"""The Intune collector's device posture, compliance assignment and Defender state reads (no network)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from azure_tenant_audit.baselines import build_baseline_alignment
from azure_tenant_audit.collection_gaps import list_truncations, truncations_from_payloads
from azure_tenant_audit.collectors import _endpoint_reads
from azure_tenant_audit.collectors.intune import MANAGED_DEVICE_SELECT, IntuneCollector
from azure_tenant_audit.graph import GraphClient, GraphError, graph_url, read_only_violation
from azure_tenant_audit.normalize import build_normalized_snapshot
from azure_tenant_audit.run import build_coverage_ledger

WINDOWS = "00000000-0000-4000-8000-00000000{:04d}"


def _device(number: int, system: str = "Windows") -> dict[str, Any]:
    return {"id": WINDOWS.format(number), "deviceName": f"PC{number:04d}", "operatingSystem": system, "osVersion": "10.0.26200.1",
            "isEncrypted": True, "lastSyncDateTime": "2026-10-20T07:30:00Z", "complianceState": "compliant"}


class _Client:
    """A Graph client double that answers GET only and records every path it is asked for."""

    def __init__(self, devices: list[dict[str, Any]], *, batch: bool = True, protection: dict[str, Any] | None = None,
                 policies: list[dict[str, Any]] | None = None, assignments: dict[str, Any] | None = None) -> None:
        self.devices = devices
        self.policies = policies if policies is not None else [{"id": "p1", "displayName": "Windows", "@odata.type": "#microsoft.graph.windows10CompliancePolicy"}]
        self.assignments = assignments if assignments is not None else {"p1": [{"id": "a1", "target": {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}}]}
        self.protection = protection or {}
        self.requests: list[tuple[str, dict[str, Any]]] = []
        self.batches: list[list[str]] = []
        if not batch:
            self.get_batch = None  # type: ignore[assignment]

    def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        self.requests.append((path, dict(params or {})))
        if path == "/deviceManagement/managedDevices":
            return list(self.devices)
        if path == "/deviceManagement/deviceCompliancePolicies":
            return list(self.policies)
        if path == "/deviceManagement/deviceConfigurations":
            return []
        if path.startswith("/deviceManagement/deviceCompliancePolicies/") and path.endswith("/assignments"):
            return list(self.assignments.get(path.split("/")[3], []))
        raise AssertionError(f"unexpected list path {path}")

    def get_json(self, path: str, params: dict[str, Any] | None = None, full_url: bool = False) -> dict[str, Any]:
        self.requests.append((path, dict(params or {})))
        return self._protection(path)

    def get_batch(self, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        self.batches.append([item["path"] for item in requests])
        results = []
        for item in requests:
            path = item["path"]
            self.requests.append((path, dict(item.get("params") or {})))
            try:
                if path.endswith("/assignments"):
                    body: dict[str, Any] = {"value": list(self.assignments.get(path.split("/")[3], []))}
                else:
                    body = self._protection(path)
                results.append({"request": item, "status": 200, "body": body})
            except GraphError as exc:
                results.append({"request": item, "status": exc.status, "body": {"error": {"code": exc.error_code or "Error", "message": str(exc)}}})
        return results

    def _protection(self, path: str) -> dict[str, Any]:
        device_id = path.split("/")[3]
        outcome = self.protection.get(device_id, {"malwareProtectionEnabled": True})
        if isinstance(outcome, int):
            raise GraphError(f"status {outcome}", status=outcome, request=path, error_code="ResourceNotFound" if outcome == 404 else "Forbidden")
        return dict(outcome)


def _run(client: _Client, **context: Any):
    return IntuneCollector().run({"client": client, "top": None, "audit_logger": None, **context})


def _device_paths(client: _Client) -> list[str]:
    return [path for path, _ in client.requests if path.endswith("/windowsProtectionState")]


# ---- managed devices --------------------------------------------------------------------------------------


def test_managed_devices_select_the_posture_fields_under_their_v1_names() -> None:
    client = _Client([_device(1)])
    _run(client)

    params = next(params for path, params in client.requests if path == "/deviceManagement/managedDevices")
    selected = params["$select"].split(",")
    assert params["$select"] == MANAGED_DEVICE_SELECT
    for field in ("isEncrypted", "jailBroken", "managedDeviceOwnerType", "enrolledDateTime", "lastSyncDateTime", "complianceState",
                  "osVersion", "operatingSystem", "deviceEnrollmentType"):
        assert field in selected, field
    assert "ownerType" not in selected, "ownerType exists on Graph beta only; selecting it on v1.0 returns 400"
    # Nothing that identifies the user or reads content is requested.
    assert not {"userPrincipalName", "emailAddress", "phoneNumber", "imei", "serialNumber"} & set(selected)


# ---- compliance policy assignments ------------------------------------------------------------------------


def test_compliance_policy_assignments_are_read_with_get_for_every_policy() -> None:
    client = _Client([_device(1)], policies=[{"id": "p1", "displayName": "A"}, {"id": "p2", "displayName": "B"}],
                     assignments={"p1": [{"id": "a1", "target": {"groupId": "g"}}], "p2": []})
    result = _run(client)

    section = result.payload["deviceCompliancePolicyAssignments"]
    assert [(row["policyId"], len(row["assignments"])) for row in section["value"]] == [("p1", 1), ("p2", 0)]
    assert section["collection_truncated"] is False and section["fanout"]["fanout_complete"] is True
    assert client.batches[0] == [
        "/deviceManagement/deviceCompliancePolicies/p1/assignments",
        "/deviceManagement/deviceCompliancePolicies/p2/assignments",
    ]
    by_name = {row["name"]: row for row in result.coverage}
    assert by_name["deviceCompliancePolicyAssignments"]["endpoint"] == "/deviceManagement/deviceCompliancePolicies/{id}/assignments"
    assert by_name["deviceCompliancePolicyAssignments"]["status"] == "ok" and by_name["deviceCompliancePolicyAssignmentsFanout"]["type"] == "derived"


def test_a_failed_assignment_read_leaves_that_policy_out_without_making_the_collector_partial() -> None:
    class _OnePolicyDenied(_Client):
        def get_batch(self, requests):  # noqa: ANN001
            results = super().get_batch(requests)
            for item, result in zip(requests, results):
                if item["path"].endswith("/p2/assignments"):
                    results[results.index(result)] = {"request": item, "status": 403, "body": {"error": {"code": "Forbidden", "message": "denied"}}}
            return results

    client = _OnePolicyDenied([_device(1)], policies=[{"id": "p1"}, {"id": "p2"}], assignments={"p1": [], "p2": []})
    result = _run(client)

    assert [row["policyId"] for row in result.payload["deviceCompliancePolicyAssignments"]["value"]] == ["p1"]
    # The base lists were read in full, so every other Intune rule keeps its evidence; the gap stays in the section.
    assert result.status == "ok" and "deviceCompliancePolicyAssignmentsFanout" in result.message
    row = next(row for row in result.coverage if row["name"] == "deviceCompliancePolicyAssignments")
    assert row["status"] == "partial" and row["error_class"] == "insufficient_permissions" and row["section_scoped"] is True
    assert result.payload["deviceCompliancePolicyAssignments"]["fanout"]["failed_operation_count"] == 1


def test_policy_assignments_are_not_requested_when_the_policy_list_failed() -> None:
    class _NoPolicies(_Client):
        def get_all(self, path, params=None):  # noqa: ANN001
            if path == "/deviceManagement/deviceCompliancePolicies":
                raise GraphError("denied", status=403, request=path)
            return super().get_all(path, params)

    client = _NoPolicies([_device(1)])
    result = _run(client)

    section = result.payload["deviceCompliancePolicyAssignments"]
    assert section["error_class"] == "incomplete_evidence" and "value" not in section
    assert not [path for path, _ in client.requests if path.endswith("/assignments")]


# ---- Defender antivirus state -----------------------------------------------------------------------------


def test_defender_state_is_read_with_get_for_windows_devices_only() -> None:
    client = _Client(
        [_device(1), _device(2, "iOS"), _device(3), _device(4, "macOS")],
        protection={WINDOWS.format(1): {"malwareProtectionEnabled": True, "realTimeProtectionEnabled": False, "productStatus": "noStatus",
                                         "userPrincipalName": "must-not-be-kept@example.com", "detectedMalwareState": [{"name": "x"}]},
                    WINDOWS.format(3): {}},
    )
    result = _run(client)

    assert _device_paths(client) == [f"/deviceManagement/managedDevices/{WINDOWS.format(n)}/windowsProtectionState" for n in (1, 3)]
    rows = {row["deviceId"]: row for row in result.payload["windowsProtectionStates"]["value"]}
    assert set(rows) == {WINDOWS.format(1), WINDOWS.format(3)}
    first = rows[WINDOWS.format(1)]
    assert first["read_status"] == "ok" and first["deviceName"] == "PC0001" and first["realTimeProtectionEnabled"] is False
    # Only the named state fields are kept from the response.
    assert "userPrincipalName" not in first and "detectedMalwareState" not in first
    assert rows[WINDOWS.format(3)]["read_status"] == "ok" and "malwareProtectionEnabled" not in rows[WINDOWS.format(3)]
    assert result.status == "ok"
    row = next(row for row in result.coverage if row["name"] == "windowsProtectionStates")
    assert row["endpoint"] == "/deviceManagement/managedDevices/{id}/windowsProtectionState" and row["item_count"] == 2


def test_a_device_with_no_protection_state_is_not_reported_and_other_failures_are_failed_reads() -> None:
    client = _Client([_device(1), _device(2), _device(3)], protection={WINDOWS.format(1): 404, WINDOWS.format(2): 403})
    result = _run(client)

    statuses = {row["deviceId"]: row["read_status"] for row in result.payload["windowsProtectionStates"]["value"]}
    assert statuses == {WINDOWS.format(1): "not_reported", WINDOWS.format(2): "failed", WINDOWS.format(3): "ok"}
    row = next(row for row in result.coverage if row["name"] == "windowsProtectionStates")
    # A 404 is a fact about the device; the 403 is a failed read, so that read is partial: in its own section only.
    assert row["status"] == "partial" and row["error_class"] == "insufficient_permissions" and row["section_scoped"] is True
    assert result.status == "ok"


def test_denied_defender_state_for_every_device_is_a_failed_read_in_its_own_section() -> None:
    client = _Client([_device(1), _device(2)], protection={WINDOWS.format(1): 403, WINDOWS.format(2): 403})
    result = _run(client)
    row = next(row for row in result.coverage if row["name"] == "windowsProtectionStates")
    assert row["status"] == "failed" and row["section_scoped"] is True
    assert result.status == "ok", "the device and policy lists were read in full"


def test_only_not_reported_devices_do_not_make_the_collector_partial() -> None:
    result = _run(_Client([_device(1)], protection={WINDOWS.format(1): 404}))
    assert result.status == "ok"
    assert result.payload["windowsProtectionStates"]["value"][0]["read_status"] == "not_reported"


def test_defender_state_stops_at_the_fanout_limit_and_says_so() -> None:
    client = _Client([_device(n) for n in range(1, 6)])
    section, coverage = _endpoint_reads.protection_state_fanout(
        collector="intune", client=client, name="windowsProtectionStates", source={"value": client.devices}, run_dir=None,
        endpoint_template="/x/{id}", windows_only=lambda device: True, limit=2,
    )
    assert len(section["value"]) == 2 and section["collection_truncated"] is True and section["truncation_reason"] == "fanout_limit"
    assert section["fanout"]["fanout_omitted_count"] == 3 and section["fanout"]["fanout_limit"] == 2
    derived = next(row for row in coverage if row["type"] == "derived")
    assert derived["status"] == "partial" and derived["truncation_reason"] == "fanout_limit" and derived["section_scoped"] is True
    # The coverage row does not flag the cut: a flagged row makes the run partial and the collector incomplete.
    assert "collection_truncated" not in derived and list_truncations(coverage) == []
    assert derived["rows_collected"] == 2 and derived["fanout_total"] == 5 and "only 2 objects were expanded" in derived["error"]
    # The section is what records the gap, under collection_gaps.
    assert truncations_from_payloads({"intune": {"windowsProtectionStates": section}}) == [
        {"collector": "intune", "list": "windowsProtectionStates", "rows_collected": 2, "reason": "fanout_limit"}
    ]


def test_defender_state_is_not_requested_when_the_device_list_failed() -> None:
    class _NoDevices(_Client):
        def get_all(self, path, params=None):  # noqa: ANN001
            if path == "/deviceManagement/managedDevices":
                raise GraphError("denied", status=403, request=path)
            return super().get_all(path, params)

    client = _NoDevices([_device(1)])
    result = _run(client)

    section = result.payload["windowsProtectionStates"]
    assert section["error_class"] == "incomplete_evidence" and "value" not in section
    assert not _device_paths(client)
    assert result.status == "partial"


def test_an_operator_row_limit_makes_the_defender_read_a_limited_one() -> None:
    client = _Client([_device(n) for n in range(1, 6)])
    result = _run(client, top=3)

    section = result.payload["windowsProtectionStates"]
    assert len(section["value"]) == 3 and section["collection_truncated"] is True and section["truncation_reason"] == "input_limited"
    assert next(row for row in result.coverage if row["name"] == "windowsProtectionStatesFanout")["truncation_reason"] == "input_limited"


def test_without_batch_support_each_object_is_read_with_one_get() -> None:
    client = _Client([_device(1), _device(2)], batch=False, protection={WINDOWS.format(2): 404})
    result = _run(client)

    assert [row["read_status"] for row in result.payload["windowsProtectionStates"]["value"]] == ["ok", "not_reported"]
    assert _device_paths(client) and not client.batches
    assert [row["policyId"] for row in result.payload["deviceCompliancePolicyAssignments"]["value"]] == ["p1"]


def test_every_device_is_expanded_from_chunk_files_not_just_the_inline_sample(tmp_path: Path) -> None:
    """A streamed list keeps only a small sample inline; the fan-out must read the chunk files for the rest."""

    class _Paged(_Client):
        def iter_pages(self, path: str, params: dict[str, Any] | None = None):  # noqa: ANN001
            self.requests.append((path, dict(params or {})))
            rows = {"/deviceManagement/managedDevices": self.devices, "/deviceManagement/deviceCompliancePolicies": self.policies}.get(path, [])
            for start in range(0, len(rows), 10):
                yield {"value": rows[start : start + 10]}

    def writer(collector: str, name: str, page: int, records: list[dict[str, Any]], _meta: Any) -> str:
        relative = f"chunks/{collector}/{name}-{page:05d}.jsonl"
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
        return relative

    client = _Paged([_device(n) for n in range(1, 46)])
    result = _run(client, chunk_writer=writer, run_dir=tmp_path)

    assert "chunk_files" in result.payload["managedDevices"]
    assert len(result.payload["managedDevices"]["value"]) < 45, "only a sample is inline"
    assert len(result.payload["windowsProtectionStates"]["value"]) == 45
    assert len(_device_paths(client)) == 45


# ---- read-only --------------------------------------------------------------------------------------------


def test_the_new_requests_pass_the_graph_read_guard() -> None:
    inner = [
        {"id": "0", "method": "GET", "url": GraphClient._batch_request_url(f"/deviceManagement/managedDevices/{WINDOWS.format(1)}/windowsProtectionState")},
        {"id": "1", "method": "GET", "url": GraphClient._batch_request_url("/deviceManagement/deviceCompliancePolicies/p1/assignments", {"$top": "50"})},
        {"id": "2", "method": "GET", "url": GraphClient._batch_request_url("/deviceManagement/deviceConfigurations/r1/assignments", {"$top": "50"})},
    ]
    assert read_only_violation("POST", "https://graph.microsoft.com/v1.0/$batch", {"json": {"requests": inner}}) is None
    for url in (
        graph_url("/deviceManagement/windowsQualityUpdateProfiles", "beta"),
        graph_url("/deviceManagement/windowsFeatureUpdateProfiles/f1/assignments", "beta"),
        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices",
    ):
        assert read_only_violation("GET", url, {}) is None, url
    # The reports API that returns Defender state for every device starts an export job with POST: refused.
    assert read_only_violation("POST", "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs", {"json": {"reportName": "DefenderAgents"}})


def test_the_collector_never_asks_for_the_reports_export_api() -> None:
    client = _Client([_device(1)])
    _run(client)
    assert not [path for path, _ in client.requests if "reports" in path or "exportJobs" in path]


# ---- update rings from a streamed configuration list --------------------------------------------------------


def test_update_rings_are_found_in_the_chunk_files_of_a_long_configuration_list(tmp_path: Path) -> None:
    """The ring is the 28th of 30 profiles: past the inline sample and past the first-ten assignment fan-out."""
    from azure_tenant_audit.collectors.intune_depth import IntuneDepthCollector

    configurations = [{"id": f"cfg-{n:02d}", "displayName": f"Profile {n}", "@odata.type": "#microsoft.graph.windows10GeneralConfiguration"} for n in range(30)]
    configurations[27] = {"id": "ring-late", "displayName": "Late ring", "@odata.type": "#microsoft.graph.windowsUpdateForBusinessConfiguration",
                          "qualityUpdatesDeferralPeriodInDays": 21, "qualityUpdatesPaused": False}

    class _Client:
        def __init__(self) -> None:
            self.batches: list[list[str]] = []

        def iter_pages(self, path: str, params: dict[str, Any] | None = None):  # noqa: ANN001, ARG002
            rows = configurations if path == "/deviceManagement/deviceConfigurations" else []
            for start in range(0, len(rows), 10):
                yield {"value": rows[start : start + 10]}

        def get_batch(self, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
            self.batches.append([item["path"] for item in requests])
            return [{"request": item, "status": 200, "body": {"value": [{"id": "a", "target": {"groupId": "g"}}]}} for item in requests]

    def writer(collector: str, name: str, page: int, records: list[dict[str, Any]], _meta: Any) -> str:
        relative = f"chunks/{collector}/{name}-{page:05d}.jsonl"
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
        return relative

    client = _Client()
    result = IntuneDepthCollector().run({"client": client, "top": None, "audit_logger": None, "chunk_writer": writer, "run_dir": tmp_path})

    (ring,) = result.payload["windowsUpdateRings"]["value"]
    assert ring["id"] == "ring-late" and ring["qualityUpdatesDeferralPeriodInDays"] == 21
    assignments = result.payload["windowsUpdateRingAssignments"]["value"]
    assert [row["policyId"] for row in assignments] == ["ring-late"]
    assert ["/deviceManagement/deviceConfigurations/ring-late/assignments"] in client.batches


# ---- a gap in a per-object read stays in its own section ---------------------------------------------------


def _pipeline(result: Any, collector: str = "intune") -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Normalize what a collector returned and evaluate every mapped rule the way a run would."""
    result_row = {"name": collector, "status": result.status, "item_count": result.item_count, "message": result.message}
    snapshot = build_normalized_snapshot(
        tenant_name="acme", run_id="run-1", collector_payloads={collector: result.payload}, coverage_rows=result.coverage, result_rows=[result_row]
    )
    capability = [{"collector": collector, "status": "supported_exact_scope"}]
    ledger = build_coverage_ledger(capability_rows=capability, result_rows=[result_row], diagnostics=[])
    alignment = build_baseline_alignment([], normalized_snapshot=snapshot, coverage_ledger=ledger)
    rules = {
        status["rule_id"]: status
        for framework in alignment["frameworks"].values()
        for control in framework["controls"]
        for status in control["rule_statuses"]
    }
    return snapshot, rules


def test_more_than_100_windows_devices_cut_only_the_defender_read() -> None:
    client = _Client([_device(number) for number in range(1, 102)])
    result = _run(client)

    section = result.payload["windowsProtectionStates"]
    assert len(section["value"]) == 100 and section["collection_truncated"] is True
    assert section["fanout"]["fanout_total"] == 101 and section["fanout"]["fanout_omitted_count"] == 1
    assert len(_device_paths(client)) == 100
    # The device and policy lists were read in full: the collector is ok, no collector issue is raised, and no
    # coverage row names a cut list (which would make the run partial).
    assert result.status == "ok" and result.message.startswith("Intune collector read in full")
    assert list_truncations(result.coverage) == []
    derived = next(row for row in result.coverage if row["name"] == "windowsProtectionStatesFanout")
    assert derived["status"] == "partial" and derived["truncation_reason"] == "fanout_limit" and derived["section_scoped"] is True
    # The gap is listed under collection_gaps from the section.
    snapshot, rules = _pipeline(result)
    gaps = [row for row in snapshot["collection_gaps"]["records"] if row["list"] == "windowsProtectionStates"]
    assert [(row["collector"], row["reason"], row["rows_collected"]) for row in gaps] == [("intune", "fanout_limit", 100)]
    assert snapshot["device_posture"]["records"][0]["read_state"] == "collected"

    # Every Intune rule outside the Defender read keeps its evidence; the Defender rules say why they cannot judge.
    assert rules["intune.device_noncompliant"]["status"] == "pass" and rules["intune.device_stale_sync"]["evaluated"] is True
    assert rules["intune.device_encryption_off"]["evaluated"] is True
    for rule in ("intune.defender_av_off", "intune.defender_realtime_protection_off", "intune.defender_signatures_stale"):
        assert {key: rules[rule][key] for key in ("status", "evaluated", "reason")} == {
            "status": "not_assessed", "evaluated": False, "reason": "defender_state_truncated"}, rule


def test_a_failed_assignment_read_leaves_every_other_intune_rule_assessed() -> None:
    class _OneDenied(_Client):
        def get_batch(self, requests):  # noqa: ANN001
            results = super().get_batch(requests)
            return [
                {"request": item, "status": 403, "body": {"error": {"code": "Forbidden", "message": "denied"}}}
                if item["path"].endswith("/p2/assignments")
                else result
                for item, result in zip(requests, results)
            ]

    client = _OneDenied([_device(1)], policies=[{"id": "p1", "@odata.type": "#microsoft.graph.windows10CompliancePolicy"}, {"id": "p2", "@odata.type": "#microsoft.graph.windows10CompliancePolicy"}],
                        assignments={"p1": [], "p2": []})
    result = _run(client)
    snapshot, rules = _pipeline(result)

    assert result.status == "ok"
    assert rules["intune.device_noncompliant"]["status"] == "pass"
    # Only the rule that reads the assignments is not assessed, with its own reason.
    assert rules["intune.compliance_policy_missing_platform"]["status"] == "not_assessed"
    assert rules["intune.compliance_policy_missing_platform"]["reason"] == "policy_assignments_not_read_for_every_policy"
    # The refused read is no truncation, but it is a section-scoped gap and the run names it (section gap, not collector gap).
    (gap,) = [row for row in snapshot.get("collection_gaps", {}).get("records", []) if row["collector"] == "intune"]
    assert gap["list"] == "deviceCompliancePolicyAssignments" and gap["section_scoped"] is True and gap["reason"] == "read_failed"


def test_a_failed_base_list_still_makes_the_collector_partial() -> None:
    class _NoPolicies(_Client):
        def get_all(self, path, params=None):  # noqa: ANN001
            if path == "/deviceManagement/deviceCompliancePolicies":
                raise GraphError("denied", status=403, request=path)
            return super().get_all(path, params)

    result = _run(_NoPolicies([_device(1)]))
    assert result.status == "partial", "a base read that failed is still an incomplete collector"
    _snapshot, rules = _pipeline(result)
    assert rules["intune.device_noncompliant"]["reason"] == "collector_not_complete:intune"
