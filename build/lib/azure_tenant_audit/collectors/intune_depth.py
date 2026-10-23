from __future__ import annotations

import time
from typing import Any

from ..collection_gaps import (
    FANOUT_OBJECT_LIMIT,
    REASON_INPUT_LIMITED,
    TRUNCATION_ERROR_CLASS,
    fanout_gap_row,
    section_total,
)
from ..endpoint_posture import UPDATE_RING_FIELDS, is_update_ring, project
from ..graph import GraphClient, GraphError
from ._endpoint_reads import assignment_fanout, collector_partial, input_rows, mark_section_scoped, scoped_gap_message
from .base import Collector, CollectorResult, _classify_graph_error, run_graph_endpoints

# deviceManagementScripts returns ``scriptContent`` (the base64 script body) unless
# $select excludes it. Script bodies are file content and must never be collected,
# so this select list is fixed and must not include scriptContent.
DEVICE_MANAGEMENT_SCRIPT_SELECT = (
    "id,displayName,description,runAsAccount,enforceSignatureCheck,fileName,"
    "createdDateTime,lastModifiedDateTime"
)


# Windows quality and feature update profiles exist only on the Graph beta API; v1.0 returns 404 for both.
# Update rings are ordinary deviceConfigurations of the windowsUpdateForBusinessConfiguration type, so they
# are taken from the deviceConfigurations list already read (no further call), and only their assignments
# are read one ring at a time.
_UPDATE_PROFILES = (
    ("windowsQualityUpdateProfiles", "windowsQualityUpdateProfileAssignments", "quality_update_profiles"),
    ("windowsFeatureUpdateProfiles", "windowsFeatureUpdateProfileAssignments", "feature_update_profiles"),
)
_UPDATE_PROFILE_LISTS = frozenset(list_name for list_name, _assignments, _scope in _UPDATE_PROFILES)
# The per-policy assignment reads of the first device configuration profiles (and the fan-out gap past them) belong to the
# unassigned-policy rule alone: a tenant with more than ten profiles must not lose its update ring rules over them.
_POLICY_ASSIGNMENT_SECTIONS = frozenset({"deviceConfigurationAssignments", "deviceConfigurationAssignmentsFanout"})


class IntuneDepthCollector(Collector):
    name = "intune_depth"
    description = "Deeper Intune policy, script, protection, update ring and update profile inventory, with sampled assignments."
    required_permissions = [
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementApps.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top")
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
                "windowsQualityUpdateProfiles": {
                    "endpoint": "/deviceManagement/windowsQualityUpdateProfiles",
                    "api_version": "beta",
                    "params": {},
                },
                "windowsFeatureUpdateProfiles": {
                    "endpoint": "/deviceManagement/windowsFeatureUpdateProfiles",
                    "api_version": "beta",
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
        for policy in configuration_rows[:FANOUT_OBJECT_LIMIT]:
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
            for policy in configuration_rows[:FANOUT_OBJECT_LIMIT]:
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

        configuration_total = section_total(payload.get("deviceConfigurations"), configuration_rows)
        if configuration_total > FANOUT_OBJECT_LIMIT:
            # The unassigned-policy finding reads these assignments, so the remaining policies are a gap.
            coverage.append(
                fanout_gap_row(
                    self.name,
                    "deviceConfigurationAssignmentsFanout",
                    total=configuration_total,
                    expanded=FANOUT_OBJECT_LIMIT,
                    scope="Device configuration assignments",
                )
            )
        payload["deviceConfigurationAssignments"] = {"value": assignment_rows}
        # The beta update profile lists and everything derived from the update rings are evidence of their own:
        # a failed or cut one stays in its section (the update rules and the summary read it) and does not make
        # the rest of the collector, such as the unassigned-policy rule, not assessed. The converse holds for the
        # policy assignment reads: they feed the unassigned-policy rule only, which reports their gap itself.
        mark_section_scoped(
            [row for row in coverage if row.get("name") in _UPDATE_PROFILE_LISTS | _POLICY_ASSIGNMENT_SECTIONS]
        )
        coverage.extend(self._update_management(client, context.get("run_dir"), payload))
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = collector_partial(coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Intune depth collector partially completed" if partial else scoped_gap_message("Intune depth collector", coverage),
            coverage=coverage,
        )

    def _update_management(self, client: GraphClient, run_dir: Any, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Windows Update for Business rings and update profiles, each with its assignments."""
        coverage: list[dict[str, Any]] = []
        source = payload.get("deviceConfigurations")
        rows, issues, failed, cut = input_rows(source, run_dir)
        rings = [project(row, UPDATE_RING_FIELDS) for row in rows if is_update_ring(row)]
        if failed or issues:
            payload["windowsUpdateRings"] = {
                "error": "The device configuration list could not be read in full, so update rings were not identified.",
                "error_class": "incomplete_evidence",
            }
        else:
            payload["windowsUpdateRings"] = {"value": rings, "collection_truncated": cut}
            if cut:
                payload["windowsUpdateRings"]["truncation_reason"] = REASON_INPUT_LIMITED
        incomplete = bool(failed or issues)
        coverage.append(
            {
                "section_scoped": True,
                "collector": self.name,
                "type": "derived",
                "name": "windowsUpdateRings",
                "status": "partial" if cut or incomplete else "ok",
                "item_count": len(rings),
                "error_class": "incomplete_evidence" if incomplete else TRUNCATION_ERROR_CLASS if cut else None,
                "error": (
                    "Update rings come from the device configuration list, which was not read in full."
                    if incomplete or cut
                    else None
                ),
                # The section carries ``collection_truncated`` (normalization lists the gap from it); a row that
                # flagged it would have to be named in the manifest's coverage gaps.
                **({"truncation_reason": REASON_INPUT_LIMITED} if cut and not incomplete else {}),
            }
        )
        section, rows_coverage = assignment_fanout(
            collector=self.name,
            client=client,
            name="windowsUpdateRingAssignments",
            source=source,
            run_dir=run_dir,
            endpoint_for=lambda policy_id: f"/deviceManagement/deviceConfigurations/{policy_id}/assignments",
            endpoint_template="/deviceManagement/deviceConfigurations/{id}/assignments",
            scope="windows_update_rings",
            rows_filter=is_update_ring,
        )
        payload["windowsUpdateRingAssignments"] = section
        coverage.extend(rows_coverage)
        for list_name, assignments_name, scope in _UPDATE_PROFILES:
            section, rows_coverage = assignment_fanout(
                collector=self.name,
                client=client,
                name=assignments_name,
                source=payload.get(list_name),
                run_dir=run_dir,
                endpoint_for=lambda profile_id, path=list_name: f"/deviceManagement/{path}/{profile_id}/assignments",
                endpoint_template=f"/deviceManagement/{list_name}/{{id}}/assignments",
                scope=scope,
                api_version="beta",
            )
            payload[assignments_name] = section
            coverage.extend(rows_coverage)
        return coverage
