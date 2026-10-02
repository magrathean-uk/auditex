from __future__ import annotations

import time
from typing import Any

from ..graph import GraphClient, GraphError
from .base import Collector, CollectorResult, _classify_graph_error, run_graph_endpoints

# deviceManagementScripts returns ``scriptContent`` (the base64 script body) unless
# $select excludes it. Script bodies are file content and must never be collected,
# so this select list is fixed and must not include scriptContent.
DEVICE_MANAGEMENT_SCRIPT_SELECT = (
    "id,displayName,description,runAsAccount,enforceSignatureCheck,fileName,"
    "createdDateTime,lastModifiedDateTime"
)


class IntuneDepthCollector(Collector):
    name = "intune_depth"
    description = "Deeper Intune policy, script, protection, and sampled assignment inventory."
    required_permissions = [
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementApps.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top", 250)
        page_size = context.get("page_size")
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            {
                "deviceConfigurations": {
                    "endpoint": "/deviceManagement/deviceConfigurations",
                    "params": {},
                },
                # groupPolicyConfigurations and deviceManagementScripts exist only on
                # the Graph beta API; v1.0 returns 404 for both.
                "groupPolicyConfigurations": {
                    "endpoint": "/deviceManagement/groupPolicyConfigurations",
                    "api_version": "beta",
                    "params": {},
                },
                "deviceManagementScripts": {
                    "endpoint": "/deviceManagement/deviceManagementScripts",
                    "api_version": "beta",
                    "params": {"$select": DEVICE_MANAGEMENT_SCRIPT_SELECT},
                },
                "androidManagedAppProtections": {
                    "endpoint": "/deviceAppManagement/androidManagedAppProtections",
                    "params": {},
                },
                "iosManagedAppProtections": {
                    "endpoint": "/deviceAppManagement/iosManagedAppProtections",
                    "params": {},
                },
            },
            top=top,
            page_size=page_size,
            chunk_writer=context.get("chunk_writer"),
            log_event=context.get("audit_logger"),
        )

        configuration_rows = payload.get("deviceConfigurations", {}).get("value", [])
        if not isinstance(configuration_rows, list):
            configuration_rows = []
        assignment_rows: list[dict[str, Any]] = []
        fanout_specs: list[dict[str, Any]] = []
        for policy in configuration_rows[:10]:
            policy_id = policy.get("id")
            if not isinstance(policy_id, str) or not policy_id:
                continue
            fanout_specs.append(
                {
                    "policy": policy,
                    "policy_id": policy_id,
                    "endpoint": f"/deviceManagement/deviceConfigurations/{policy_id}/assignments",
                }
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
                policy = spec["policy"]
                policy_id = spec["policy_id"]
                status = result.get("status") if isinstance(result, dict) else None
                body = result.get("body") if isinstance(result, dict) else None
                if status == 200 and isinstance(body, dict):
                    assignments = body.get("value", [])
                    if not isinstance(assignments, list):
                        assignments = []
                    next_link = body.get("@odata.nextLink")
                    if isinstance(next_link, str) and next_link:
                        assignments = assignments + list(client.iter_items(next_link))
                    assignment_rows.append(
                        {
                            "policyId": policy_id,
                            "displayName": policy.get("displayName"),
                            "assignments": assignments,
                        }
                    )
                    coverage.append(
                        {
                            "collector": self.name,
                            "type": "graph",
                            "name": "deviceConfigurationAssignments",
                            "endpoint": endpoint,
                            "policy_id": policy_id,
                            "status": "ok",
                            "item_count": len(assignments),
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
                error_exc = GraphError(
                    str(error_message or "Graph batch request failed."),
                    status=status if isinstance(status, int) else None,
                    request=endpoint,
                    error_code=error_code if isinstance(error_code, str) else None,
                )
                error_class, error = _classify_graph_error(error_exc)
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "graph",
                        "name": "deviceConfigurationAssignments",
                        "endpoint": endpoint,
                        "policy_id": policy_id,
                        "status": "failed",
                        "item_count": 0,
                        "duration_ms": round((time.perf_counter() - batch_start) * 1000, 2),
                        "error_class": error_class,
                        "error": error,
                    }
                )
        else:
            for policy in configuration_rows[:10]:
                policy_id = policy.get("id")
                if not isinstance(policy_id, str) or not policy_id:
                    continue
                endpoint = f"/deviceManagement/deviceConfigurations/{policy_id}/assignments"
                start = time.perf_counter()
                try:
                    assignments = client.get_all(endpoint, params={"$top": "50"})
                    if not isinstance(assignments, list):
                        assignments = []
                    assignment_rows.append(
                        {
                            "policyId": policy_id,
                            "displayName": policy.get("displayName"),
                            "assignments": assignments,
                        }
                    )
                    coverage.append(
                        {
                            "collector": self.name,
                            "type": "graph",
                            "name": "deviceConfigurationAssignments",
                            "endpoint": endpoint,
                            "policy_id": policy_id,
                            "status": "ok",
                            "item_count": len(assignments),
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
                            "name": "deviceConfigurationAssignments",
                            "endpoint": endpoint,
                            "policy_id": policy_id,
                            "status": "failed",
                            "item_count": 0,
                            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                            "error_class": error_class,
                            "error": error,
                        }
                    )

        payload["deviceConfigurationAssignments"] = {"value": assignment_rows}
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Intune depth collector partially completed" if partial else "",
            coverage=coverage,
        )
