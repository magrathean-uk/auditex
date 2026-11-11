from __future__ import annotations

import time
from typing import Any

from ..collection_gaps import (
    REASON_INPUT_LIMITED,
    fanout_gap_row,
    section_total,
    section_was_cut,
)
from ..graph import NEXT_LINK_REFUSED, GraphClient, GraphError, graph_host_url
from .base import Collector, CollectorResult, _classify_graph_error, run_graph_endpoints

_POLICY_LIMIT = 100
_TARGET_LIMIT = 50


class _InvalidPolicyTargets(ValueError):
    pass


def _minimise_directory_settings(payload: dict[str, Any]) -> None:
    section = payload.get("directorySettings", {})
    if section.get("status") == "failed":
        # Strict reads withhold failed sections before minimisation.
        if "value" not in section:
            return
    groups = section.get("value")
    if not isinstance(groups, list) or any(
        not isinstance(group, dict) or not isinstance(group.get("values", []), list)
        or any(not isinstance(entry, dict) for entry in group.get("values", []))
        for group in groups
    ):
        section.clear()
        section.update(status="failed", error_class="incomplete_evidence", error="Invalid directory settings response; values withheld.")
        return
    section["value"] = [
        {
            **{key: group[key] for key in ("id", "displayName", "templateId") if key in group},
            "values": [
                {"name": entry["name"], "value": entry.get("value")}
                for entry in group.get("values", [])
                if isinstance(entry, dict) and entry.get("name") == "EnableAdminConsentRequests"
            ] if isinstance(group.get("values"), list) else [],
        }
        for group in groups
    ]
    envelope_keys = {
        "value", "status", "result_limit", "collection_limit_reached", "collection_truncated",
        "truncation_reason", "bounded_sample", "error", "error_class",
    }
    for key in tuple(section):
        if key not in envelope_keys:
            del section[key]


def _applies_to_fanout(client: GraphClient, policies: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    name = "appManagementPolicyAppliesTo"
    rows: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    inputs = policies.get("value")
    input_failed = policies.get("status") != "ok" or not isinstance(inputs, list)
    inputs = inputs if isinstance(inputs, list) else []
    total = section_total(policies, inputs)
    input_cut = section_was_cut(policies)
    invalid = any(not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"] for item in inputs)
    ids = [item["id"] for item in inputs if isinstance(item, dict) and isinstance(item.get("id"), str)]
    invalid |= len(ids) != len(set(ids))
    if not (input_failed or invalid):
        for policy in inputs[:_POLICY_LIMIT]:
            policy_id = policy["id"]
            endpoint = f"/policies/appManagementPolicies/{policy_id}/appliesTo"
            start = time.perf_counter()
            row = {
                "collector": "consent_policy", "type": "graph", "name": name,
                "endpoint": endpoint, "api_version": "v1.0", "policy_id": policy_id,
                "status": "ok", "item_count": 0, "error_class": None, "error": None,
            }
            try:
                result = client.get_json(endpoint, params={"$select": "id", "$top": str(_TARGET_LIMIT)})
                targets = result.get("value") if isinstance(result, dict) else None
                if not isinstance(targets, list) or any(
                    not isinstance(target, dict) or not isinstance(target.get("id"), str) or not target["id"]
                    for target in targets
                ):
                    raise _InvalidPolicyTargets("Invalid app management policy targets response; evidence withheld.")
                next_link = result.get("@odata.nextLink")
                # Match GraphClient: null ends the list; other links must be non-empty strings.
                if next_link is not None and (not isinstance(next_link, str) or not next_link):
                    raise _InvalidPolicyTargets("Invalid app management policy targets next link; evidence withheld.")
                if next_link is not None and not graph_host_url(next_link):
                    raise GraphError("Refusing an unsafe policy targets next link; evidence withheld.",
                                     error_code=NEXT_LINK_REFUSED)
                truncated = len(targets) > _TARGET_LIMIT or bool(next_link)
                targets = [{"id": target["id"]} for target in targets[:_TARGET_LIMIT]]
                rows.append({"policyId": policy_id, "appliesTo": targets, "appliesToTruncated": truncated})
                row["item_count"] = len(targets)
                if truncated:
                    row.update(fanout_gap_row("consent_policy", name, total=len(result["value"]),
                                              expanded=len(targets), limit=_TARGET_LIMIT, scope="Policy targets"))
                    row.update(type="graph", item_count=len(targets))
                    if result.get("@odata.nextLink"):
                        # A next link proves there are more targets, not their total.
                        row.pop("fanout_total")
                        row["error"] = (
                            f"Policy targets: only the first {len(targets)} were expanded (fan-out limit {_TARGET_LIMIT}); "
                            "a next-page link indicates additional unread targets."
                        )
            except Exception as exc:  # noqa: BLE001
                error_class, error = (
                    ("incomplete_evidence", str(exc)) if isinstance(exc, _InvalidPolicyTargets) else _classify_graph_error(exc)
                )
                row.update(status="failed", error_class=error_class, error=error)
            row["duration_ms"] = round((time.perf_counter() - start) * 1000, 2)
            coverage.append(row)
    capped = total > _POLICY_LIMIT
    incomplete = input_failed or invalid or input_cut or total != len(inputs)
    partial = incomplete or capped or any(row["status"] != "ok" for row in coverage)
    summary = {
        "collector": "consent_policy", "type": "derived", "name": name,
        "status": "partial" if partial else "ok", "item_count": 0,
        "rows_collected": len(rows), "duration_ms": 0,
        "error_class": "incomplete_evidence" if partial else None,
        "error": "Application management policy targets are incomplete." if partial else None,
        "input_complete": not incomplete, "fanout_limit": _POLICY_LIMIT,
        "fanout_total": total, "fanout_complete": not partial,
    }
    if capped:
        summary.update(fanout_gap_row("consent_policy", name, total=total, expanded=len(rows),
                                      limit=_POLICY_LIMIT, scope="Application management policies"))
    elif input_cut:
        summary.update(collection_truncated=True, truncation_reason=REASON_INPUT_LIMITED)
    coverage.append(summary)
    section = {"status": summary["status"], "item_count": len(rows), "fanout": summary.copy()}
    # No empty value on an error: absence and a successfully read empty list differ.
    if rows or not partial:
        section["value"] = rows
    if partial:
        section["error"] = summary["error"]
    return section, coverage


class ConsentPolicyCollector(Collector):
    name = "consent_policy"
    description = "Admin consent workflow, user consent, permission grant and application management policy posture."
    required_permissions = [
        "Policy.Read.All",
        "Directory.Read.All",
        "Policy.Read.PermissionGrant",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            {
                "adminConsentRequestPolicy": {"endpoint": "/policies/adminConsentRequestPolicy", "page": False, "params": {}},
                "permissionGrantPolicies": {"endpoint": "/policies/permissionGrantPolicies", "params": {}},
                "authorizationPolicy": {"endpoint": "/policies/authorizationPolicy", "page": False, "params": {}},
                "directorySettings": {"endpoint": "/settings", "api_version": "beta", "apply_top": False, "inline": True,
                                      "validate_collection": True, "params": {}},
                "defaultAppManagementPolicy": {"endpoint": "/policies/defaultAppManagementPolicy", "page": False,
                                               "validate_object": True, "required_key": "id", "params": {}},
                "appManagementPolicies": {"endpoint": "/policies/appManagementPolicies", "apply_top": False, "inline": True,
                                          "validate_collection": True, "params": {}},
            },
            top=context.get("top"),
            page_size=context.get("page_size"),
            chunk_writer=context.get("chunk_writer"),
            log_event=context.get("audit_logger"),
        )
        for row in coverage:
            if row["name"] in {"directorySettings", "defaultAppManagementPolicy", "appManagementPolicies"}:
                payload[row["name"]]["status"] = row["status"]
        _minimise_directory_settings(payload)
        if payload["directorySettings"].get("error_class") == "incomplete_evidence":
            row = next(row for row in coverage if row["name"] == "directorySettings")
            row.update(status="failed", item_count=0, error_class="incomplete_evidence", error=payload["directorySettings"]["error"])
        payload["appManagementPolicyAppliesTo"], fanout_coverage = _applies_to_fanout(client, payload["appManagementPolicies"])
        coverage.extend(fanout_coverage)
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Consent policy collector partially completed" if partial else "",
            coverage=coverage,
        )
