from __future__ import annotations

import time
from typing import Any

from ..chunk_reader import iter_endpoint_records
from ..collection_gaps import REASON_FANOUT_LIMIT, REASON_INPUT_LIMITED, section_was_cut
from ..graph import GraphClient, GraphError
from .base import Collector, CollectorResult, _classify_graph_error, run_graph_endpoints

_MICROSOFT_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
_SERVICE_PRINCIPAL_FANOUT_LIMIT = 10


class AppConsentCollector(Collector):
    name = "app_consent"
    description = "Enterprise application consent, service principal ownership, and app role assignments."
    required_permissions = [
        "Directory.Read.All",
        "DelegatedPermissionGrant.Read.All",
        "Application.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top")
        page_size = context.get("page_size")
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            {
                "servicePrincipals": {
                    "endpoint": "/servicePrincipals",
                    "params": {
                        "$select": "id,displayName,appId,servicePrincipalType,appOwnerOrganizationId,verifiedPublisher,accountEnabled",
                    },
                },
                "oauth2PermissionGrants": {
                    "endpoint": "/oauth2PermissionGrants",
                    "params": {
                        "$select": "id,clientId,resourceId,scope,consentType,principalId",
                    },
                },
            },
            top=top,
            page_size=page_size,
            chunk_writer=context.get("chunk_writer"),
            log_event=context.get("audit_logger"),
        )

        owner_rows: list[dict[str, Any]] = []
        assignment_rows: list[dict[str, Any]] = []
        fanout_specs: list[dict[str, Any]] = []

        # Fan out over the first 10 service principals, plus Microsoft Graph so
        # application permissions granted on Graph (appRoleAssignedTo) are read.
        section = payload.get("servicePrincipals", {})
        input_issues: list[dict[str, Any]] = []
        input_count = 0
        fanout_by_id: dict[str, dict[str, Any]] = {}
        graph_found = False
        for index, item in enumerate(iter_endpoint_records(section, context.get("run_dir"), issues=input_issues)):
            input_count += 1
            is_graph = str(item.get("appId") or "").lower() == _MICROSOFT_GRAPH_APP_ID
            graph_found = graph_found or is_graph
            sp_id = item.get("id")
            if isinstance(sp_id, str) and sp_id and (index < _SERVICE_PRINCIPAL_FANOUT_LIMIT or is_graph):
                fanout_by_id.setdefault(sp_id, item)
        # Count/missing-file failures can occur at iterator exhaustion. Schedule
        # only after that validation, preserving the intended first-ten scope.
        fanout_principals = list(fanout_by_id.values()) if not input_issues else []
        for service_principal in fanout_principals:
            sp_id = service_principal.get("id")
            if not isinstance(sp_id, str) or not sp_id:
                continue
            fanout_specs.extend(
                [
                    {
                        "name": "servicePrincipalOwners",
                        "endpoint": f"/servicePrincipals/{sp_id}/owners",
                        "service_principal_id": sp_id,
                        "displayName": service_principal.get("displayName"),
                        "property_name": "owners",
                        "target_list": owner_rows,
                    },
                    {
                        "name": "servicePrincipalAppRoleAssignments",
                        "endpoint": f"/servicePrincipals/{sp_id}/appRoleAssignedTo",
                        "service_principal_id": sp_id,
                        "displayName": service_principal.get("displayName"),
                        "property_name": "assignments",
                        "target_list": assignment_rows,
                    },
                ]
            )

        batch_results: list[dict[str, Any]] | None = None
        if fanout_specs and hasattr(client, "get_batch"):
            batch_start = time.perf_counter()
            try:
                batch_results = client.get_batch(
                    [
                        {
                            "path": spec["endpoint"],
                            "params": {"$top": "50"},
                        }
                        for spec in fanout_specs
                    ]
                )
            except Exception:  # noqa: BLE001
                batch_results = None

        if batch_results is not None and len(batch_results) == len(fanout_specs):
            for spec, result in zip(fanout_specs, batch_results):
                endpoint = spec["endpoint"]
                target_list = spec["target_list"]
                status = result.get("status") if isinstance(result, dict) else None
                body = result.get("body") if isinstance(result, dict) else None
                if status == 200 and isinstance(body, dict):
                    rows = body.get("value", [])
                    if not isinstance(rows, list):
                        rows = []
                    next_link = body.get("@odata.nextLink")
                    if isinstance(next_link, str) and next_link:
                        rows = rows + list(client.iter_items(next_link))
                    target_list.append(
                        {
                            "servicePrincipalId": spec["service_principal_id"],
                            "displayName": spec["displayName"],
                            spec["property_name"]: rows,
                        }
                    )
                    coverage.append(
                        {
                            "collector": self.name,
                            "type": "graph",
                            "name": spec["name"],
                            "endpoint": endpoint,
                            "service_principal_id": spec["service_principal_id"],
                            "status": "ok",
                            "item_count": len(rows),
                            "duration_ms": round((time.perf_counter() - batch_start) * 1000, 2),
                            "error_class": None,
                            "error": None,
                        }
                    )
                    continue

                error_code = result.get("error_code") if isinstance(result, dict) else None
                error_message = result.get("error") if isinstance(result, dict) else None
                if isinstance(body, dict):
                    error = body.get("error")
                    if isinstance(error, dict):
                        error_code = error_code or error.get("code")
                        error_message = error_message or error.get("message")
                    elif isinstance(error, str):
                        error_message = error_message or error
                error_text = str(error_message or "Graph batch request failed.")
                error_status = status if isinstance(status, int) else None
                error_exc = GraphError(
                    error_text,
                    status=error_status,
                    request=endpoint,
                    error_code=error_code if isinstance(error_code, str) else None,
                )
                error_class, error = _classify_graph_error(error_exc)
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "graph",
                        "name": spec["name"],
                        "endpoint": endpoint,
                        "service_principal_id": spec["service_principal_id"],
                        "status": "failed",
                        "item_count": 0,
                        "duration_ms": round((time.perf_counter() - batch_start) * 1000, 2),
                        "error_class": error_class,
                        "error": error,
                    }
                )
        else:
            for spec in fanout_specs:
                start = time.perf_counter()
                endpoint = spec["endpoint"]
                target_list = spec["target_list"]
                try:
                    rows = client.get_all(endpoint, params={"$top": "50"})
                    if not isinstance(rows, list):
                        rows = []
                    target_list.append(
                        {
                            "servicePrincipalId": spec["service_principal_id"],
                            "displayName": spec["displayName"],
                            spec["property_name"]: rows,
                        }
                    )
                    coverage.append(
                        {
                            "collector": self.name,
                            "type": "graph",
                            "name": spec["name"],
                            "endpoint": endpoint,
                            "service_principal_id": spec["service_principal_id"],
                            "status": "ok",
                            "item_count": len(rows),
                            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                            "error_class": None,
                            "error": None,
                        }
                    )
                except Exception as exc:  # noqa: BLE001
                    error_class, error = _classify_graph_error(exc)
                    coverage.append(
                        {
                            "collector": self.name,
                            "type": "graph",
                            "name": spec["name"],
                            "endpoint": endpoint,
                            "service_principal_id": spec["service_principal_id"],
                            "status": "failed",
                            "item_count": 0,
                            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                            "error_class": error_class,
                            "error": error,
                        }
                    )

        omitted = max(input_count - len(fanout_principals), 0)
        input_failed = bool(section.get("error")) if isinstance(section, dict) else True
        input_limited = section_was_cut(section)
        failed_operations = sum(1 for row in coverage if row.get("name") in {"servicePrincipalOwners", "servicePrincipalAppRoleAssignments"} and row.get("status") != "ok")
        limited = bool(omitted or input_limited)
        incomplete = bool(input_issues or input_failed or failed_operations)
        fanout = {
            "fanout_scope": "first_10_service_principals_plus_microsoft_graph",
            "fanout_limit": _SERVICE_PRINCIPAL_FANOUT_LIMIT,
            "input_record_count": input_count,
            "input_complete": not (input_issues or input_failed or input_limited),
            "input_issues": input_issues,
            "input_collection_limited": input_limited,
            "fanout_target_count": len(fanout_principals),
            "fanout_omitted_count": omitted,
            "microsoft_graph_found": graph_found,
            "requested_operation_count": len(fanout_specs),
            "failed_operation_count": failed_operations,
            "collection_truncated": limited,
            "fanout_complete": not (limited or incomplete),
        }
        coverage.append({
            "collector": self.name, "type": "derived", "name": "servicePrincipalFanout",
            "status": "partial" if limited or incomplete else "ok", "item_count": 0,
            # The objects this fan-out expanded, so the gap reads "11 rows", not "0 rows".
            "rows_collected": len(fanout_principals),
            "error_class": "incomplete_evidence" if incomplete else "collection_limit" if limited else None,
            "error": "Service-principal fan-out inputs or relationships are incomplete." if incomplete else
                     "Service-principal relationships cover only the first ten principals plus Microsoft Graph." if limited else None,
            "truncation_reason": (REASON_FANOUT_LIMIT if omitted else REASON_INPUT_LIMITED) if limited else None,
            **fanout,
        })
        payload["servicePrincipalOwners"] = {"value": owner_rows, "fanout": fanout, "collection_truncated": limited}
        payload["servicePrincipalAppRoleAssignments"] = {"value": assignment_rows, "fanout": fanout, "collection_truncated": limited}
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="App consent collector partially completed" if partial else "",
            coverage=coverage,
        )
