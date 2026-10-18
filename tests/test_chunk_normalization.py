from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tracemalloc
from typing import Any

import pytest

from azure_tenant_audit.attack_graph import analyze_attack_graph
from azure_tenant_audit.chunk_reader import EndpointEvidenceError, iter_endpoint_records
from azure_tenant_audit.collectors.base import run_graph_endpoints
from azure_tenant_audit.diffing import diff_run_directories
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.graph import GraphError
from azure_tenant_audit.normalize import build_ai_safe_summary, build_normalization_diagnostics, build_normalized_snapshot
from azure_tenant_audit.perf_runtime import EndpointAccumulator


def _write_chunk(root: Path, relative: str, rows: list[dict[str, Any]]) -> str:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    return relative


def _endpoint(root: Path, name: str, rows: list[dict[str, Any]], page_size: int = 17) -> dict[str, Any]:
    accumulator = EndpointAccumulator()
    for start in range(0, len(rows), page_size):
        page = rows[start:start + page_size]
        relative = _write_chunk(root, f"chunks/{name}-{start // page_size:05d}.jsonl", page)
        accumulator.add_page(page, chunk_file=relative)
    return accumulator.payload()


def _snapshot(root: Path | None, payloads: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    return build_normalized_snapshot(
        tenant_name="synthetic", run_id="run", collector_payloads=payloads, run_dir=root, **kwargs
    )


def _report(snapshot: dict[str, Any], source: str = "identity.users") -> dict[str, Any]:
    return next(row for row in snapshot["normalization_coverage"]["records"] if row["source"] == source)


def _graph_payloads(root: Path, *, remediated: bool = False) -> dict[str, Any]:
    users = [
        {"id": f"u-{i}", "userPrincipalName": f"owner{i}@synthetic.example", "displayName": f"User {i}",
         "userType": "Member", "accountEnabled": True}
        for i in range(31)
    ]
    principals = [
        {"id": f"sp-{i}", "appId": f"app-{i}", "displayName": f"Service {i}"}
        for i in range(367)
    ]
    principals[-1]["appId"] = "00000003-0000-0000-c000-000000000000"
    principals[-1]["displayName"] = "Microsoft Graph"
    if remediated:
        principals[-2]["displayName"] = "Reviewed service"
    owners = [{"servicePrincipalId": f"sp-{i}", "owners": []} for i in range(30)]
    owners.append({"servicePrincipalId": "sp-365", "owners": [] if remediated else [{"id": "u-30"}]})
    assignments = [{"servicePrincipalId": f"sp-{i}", "assignments": []} for i in range(30)]
    assignments.append({"servicePrincipalId": "sp-366", "assignments": [
        {"id": "grant-tail", "principalId": "sp-365", "principalType": "ServicePrincipal",
         "resourceId": "sp-366", "appRoleId": "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"}
    ]})
    return {
        "identity": {
            "users": _endpoint(root, "identity/users", users),
            "servicePrincipals": _endpoint(root, "identity/servicePrincipals", principals),
        },
        "app_consent": {
            "servicePrincipals": _endpoint(root, "app_consent/servicePrincipals", principals),
            "servicePrincipalOwners": _endpoint(root, "app_consent/owners", owners),
            "servicePrincipalAppRoleAssignments": _endpoint(root, "app_consent/assignments", assignments),
        },
    }


def test_beyond_sample_rows_change_findings_graph_and_normalized_comparison(tmp_path: Path) -> None:
    before_root, after_root = tmp_path / "before", tmp_path / "after"
    before_payload = _graph_payloads(before_root)
    after_payload = _graph_payloads(after_root, remediated=True)
    raw_before = deepcopy(before_payload)
    before = _snapshot(before_root, before_payload)
    after = _snapshot(after_root, after_payload)

    assert before_payload == raw_before
    assert len(before_payload["identity"]["servicePrincipals"]["value"]) == 20
    assert before_payload["identity"]["servicePrincipals"]["value"] == after_payload["identity"]["servicePrincipals"]["value"]
    assert before["snapshot"]["object_counts"]["service_principals"] == 367
    assert before["snapshot"]["object_counts"]["users"] == 31
    assert before["snapshot"]["normalization_complete"] is True
    assert before["snapshot"]["sample_truncated"] is True
    assert _report(before, "identity.servicePrincipals")["record_count"] == 367

    paths = analyze_attack_graph(before)["paths"]
    assert any(path["source"] == "owner30@synthetic.example" for path in paths)
    assert not analyze_attack_graph(after)["paths"]
    findings = build_findings([], normalized_snapshot=before)
    assert any(row["rule_id"] == "attack_path.app_owner_to_tier0" for row in findings)
    assert not any(row["rule_id"].startswith("attack_path.") for row in build_findings([], normalized_snapshot=after))

    for root, snapshot in ((before_root, before), (after_root, after)):
        (root / "normalized").mkdir()
        (root / "run-manifest.json").write_text(json.dumps({"tenant_name": "synthetic", "platform": "m365"}))
        for section, payload in snapshot.items():
            (root / "normalized" / f"{section}.json").write_text(json.dumps(payload))
    changes = diff_run_directories(before_root, after_root)["changes"]
    assert len(changes["service_principals"]["changed"]) == 1
    assert changes["app_owner_edges"]["removed"][0]["owner_id"] == "u-30"


def test_complete_chunked_policy_and_identity_rows_feed_detection_and_ca_graph(tmp_path: Path) -> None:
    users = [{"id": f"u-{i}", "displayName": f"User {i}"} for i in range(31)]
    policies = [{"id": f"ca-{i}", "state": "disabled"} for i in range(31)]
    policies[-1] = {"id": "ca-30", "state": "enabled", "conditions": {
        "userRiskLevels": ["high"], "users": {"includeUsers": ["u-30"]}
    }}
    payload = {"identity": {"users": _endpoint(tmp_path, "users", users)},
               "conditional_access": {"conditionalAccessPolicies": _endpoint(tmp_path, "ca", policies)}}
    snapshot = _snapshot(tmp_path, payload)
    signal = next(row for row in snapshot["detection_signal_objects"]["records"] if row["name"] == "risk_based_conditional_access")
    assert signal["status"] == "on"
    assert snapshot["relationships"]["records"][0]["resolution"] == "resolved"
    assert snapshot["relationships"]["records"][0]["target_name"] == "User 30"


def test_full_raw_sample_flag_does_not_hide_verified_absence(tmp_path: Path) -> None:
    rows = [{"id": f"ca-{i}", "state": "disabled"} for i in range(31)]
    snapshot = _snapshot(tmp_path, {"conditional_access": {"conditionalAccessPolicies": _endpoint(tmp_path, "ca", rows)}})
    signal = next(row for row in snapshot["detection_signal_objects"]["records"] if row["name"] == "risk_based_conditional_access")
    assert signal["status"] == "off"
    assert snapshot["snapshot"]["normalization_complete"] is True


def test_large_collection_remains_sampled_while_all_rows_are_normalized(tmp_path: Path) -> None:
    class Client:
        def iter_pages(self, _endpoint: str, params: Any = None):
            for start in range(0, 10_000, 100):
                yield {"value": [{"id": f"u-{i}", "displayName": f"User {i}"} for i in range(start, start + 100)]}

    def writer(collector: str, name: str, page: int, records: list[dict[str, Any]], metadata: Any = None) -> str:
        return _write_chunk(tmp_path, f"chunks/{collector}/{name}-{page:05d}.jsonl", records)

    payload, coverage = run_graph_endpoints("identity", Client(), {"users": {"endpoint": "/users"}},
                                            top=None, page_size=100, chunk_writer=writer)
    snapshot = _snapshot(tmp_path, {"identity": payload}, coverage_rows=coverage)
    assert len(payload["users"]["value"]) == 20
    assert len(payload["users"]["chunk_files"]) == 100
    assert len(snapshot["users"]["records"]) == 10_000
    assert any(row["id"] == "u-9999" for row in snapshot["users"]["records"])
    assert snapshot["snapshot"]["normalization_complete"] is True


def test_chunk_iterator_memory_is_independent_of_total_rows(tmp_path: Path) -> None:
    relative = "chunks/large.jsonl"
    path = tmp_path / relative
    path.parent.mkdir()
    with path.open("w", encoding="utf-8") as handle:
        for index in range(50_000):
            handle.write(json.dumps({"id": f"u-{index}", "metadata": "x" * 1024}) + "\n")
    section = {"chunk_files": [relative], "item_count": 50_000, "value": [{"id": "u-0"}], "sample_truncated": True}
    tracemalloc.start()
    try:
        count = sum(1 for _ in iter_endpoint_records(section, tmp_path))
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert count == 50_000
    assert peak < 2_000_000


def test_persisted_payload_resume_uses_explicit_run_dir_not_working_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "run"
    section = _endpoint(root, "users", [{"id": f"u-{i}"} for i in range(31)])
    raw = root / "raw.json"
    raw.write_text(json.dumps({"identity": {"users": section}}))
    monkeypatch.chdir(tmp_path)
    snapshot = _snapshot(root, json.loads(raw.read_text()))
    assert len(snapshot["users"]["records"]) == 31
    assert snapshot["snapshot"]["normalization_complete"] is True


def test_inline_offline_rows_need_no_run_dir() -> None:
    rows = [{"id": f"u-{i}"} for i in range(31)]
    snapshot = _snapshot(None, {"identity": {"users": {"value": rows}}})
    assert len(snapshot["users"]["records"]) == 31
    assert snapshot["snapshot"]["normalization_complete"] is True


def test_missing_chunk_finalizes_partial_bundle_with_resolvable_blocker(tmp_path: Path) -> None:
    from azure_tenant_audit.cli import run_offline

    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps({"identity": {"users": {
        "value": [{"id": "sample-only"}], "chunk_files": ["chunks/missing.jsonl"],
        "item_count": 50, "sample_truncated": True,
    }}}))
    output = tmp_path / "output"
    assert run_offline(sample, output, "synthetic", "missing-chunk") == 1
    run = next(output.iterdir())
    manifest = json.loads((run / "run-manifest.json").read_text())
    assert manifest["overall_status"] == "partial"
    assert manifest["contract_status"] == "valid"
    blockers = json.loads((run / "blockers/blockers.json").read_text())
    assert any(row["error_class"] == "incomplete_evidence" for row in blockers)
    ledger = json.loads((run / "normalized/coverage_ledger.json").read_text())["records"]
    assert ledger[0]["coverage_status"] == "partial_success"
    assert ledger[0]["coverage_reason"] == "normalization_incomplete"
    assert not (run / "normalized/users.json").exists()


def test_portable_chunk_reader_still_rejects_symlink_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("azure_tenant_audit.chunk_reader.os.supports_dir_fd", set())
    section = _endpoint(tmp_path, "users", [{"id": "u-1"}])
    assert list(iter_endpoint_records(section, tmp_path)) == [{"id": "u-1"}]
    (tmp_path / "alias").symlink_to(tmp_path.parent, target_is_directory=True)
    section["chunk_files"] = ["alias/outside.jsonl"]
    with pytest.raises(EndpointEvidenceError) as exc:
        list(iter_endpoint_records(section, tmp_path))
    assert exc.value.issue["code"] == "unsafe_chunk_path"


@pytest.mark.parametrize("case,code", [
    ("missing", "missing_chunk"),
    ("corrupt", "invalid_chunk_json"),
    ("unicode", "invalid_chunk_json"),
    ("nonobject", "invalid_chunk_record"),
    ("parent", "unsafe_chunk_path"),
    ("absolute", "unsafe_chunk_path"),
    ("file_symlink", "unsafe_chunk_path"),
    ("directory_symlink", "unsafe_chunk_path"),
    ("directory", "invalid_chunk_file"),
    ("duplicate", "duplicate_chunk"),
    ("hardlink", "duplicate_chunk"),
    ("bad_path", "invalid_chunk_path"),
    ("bad_manifest", "invalid_chunk_manifest"),
    ("count_high", "item_count_mismatch"),
    ("count_low", "item_count_mismatch"),
    ("chunk_count", "chunk_count_mismatch"),
    ("bad_count", "invalid_item_count"),
])
def test_invalid_chunk_evidence_is_explicit_and_never_falls_back_to_sample(tmp_path: Path, case: str, code: str) -> None:
    root = tmp_path / "run"
    relative = _write_chunk(root, "chunks/users.jsonl", [{"id": "chunk-row"}])
    outside = tmp_path / "outside.jsonl"
    outside.write_text('{"id":"outside-row","displayName":"Outside evidence"}\n')
    section: dict[str, Any] = {"value": [{"id": "inline-only", "displayName": "Inline only"}],
                               "chunk_files": [relative], "item_count": 1}
    if case == "missing":
        (root / relative).unlink()
    elif case == "corrupt":
        (root / relative).write_text('{"id":"chunk-row"}\n{"invalid":\n{"id":"later-row"}\n')
        section["item_count"] = 3
    elif case == "unicode":
        (root / relative).write_bytes(b'\xff\n')
    elif case == "nonobject":
        (root / relative).write_text('[]\n')
    elif case == "parent":
        section["chunk_files"] = ["../outside.jsonl"]
    elif case == "absolute":
        section["chunk_files"] = [str(outside)]
    elif case == "file_symlink":
        (root / relative).unlink()
        (root / relative).symlink_to(outside)
    elif case == "directory_symlink":
        (root / "linked").symlink_to(tmp_path, target_is_directory=True)
        section["chunk_files"] = ["linked/outside.jsonl"]
    elif case == "directory":
        section["chunk_files"] = ["chunks"]
    elif case == "duplicate":
        section["chunk_files"] *= 2
    elif case == "hardlink":
        (root / "alias.jsonl").hardlink_to(root / relative)
        section["chunk_files"].append("alias.jsonl")
    elif case == "bad_path":
        section["chunk_files"] = [None]
    elif case == "bad_manifest":
        section["chunk_files"] = relative
    elif case == "count_high":
        section["item_count"] = 2
    elif case == "count_low":
        section["item_count"] = 0
    elif case == "chunk_count":
        section["chunk_count"] = 2
    elif case == "bad_count":
        section["item_count"] = "many"

    with pytest.raises(EndpointEvidenceError) as exc:
        list(iter_endpoint_records(section, root))
    assert exc.value.issue["code"] == code
    issues: list[dict[str, Any]] = []
    rows = list(iter_endpoint_records(section, root, issues=issues))
    assert code in {issue["code"] for issue in issues}
    assert all(row["id"] not in {"inline-only", "outside-row"} for row in rows)
    if case == "corrupt":
        assert [row["id"] for row in rows] == ["chunk-row", "later-row"]
    if case in {"duplicate", "hardlink"}:
        assert len(rows) == 1

    snapshot = _snapshot(root, {"identity": {"users": section}})
    assert snapshot["snapshot"]["normalization_complete"] is False
    assert snapshot["snapshot"]["normalization_incomplete_sections"] == ["identity.users"]
    assert _report(snapshot)["complete"] is False
    assert code in {issue["code"] for issue in _report(snapshot)["issues"]}
    assert "outside-row" not in json.dumps(snapshot)
    assert "inline-only" not in json.dumps(snapshot)
    diagnostics = build_normalization_diagnostics(snapshot)
    assert len(diagnostics) == 1
    assert diagnostics[0]["evidence_refs"][0]["record_key"] == "normalization:identity.users"
    assert snapshot["snapshot"]["blocker_count"] == 1
    ai_safe = build_ai_safe_summary(snapshot)
    assert ai_safe["normalization_complete"] is False
    assert "chunk_file" not in json.dumps(ai_safe)


@pytest.mark.parametrize("with_manifest", [False, True])
def test_missing_chunk_context_never_claims_complete(with_manifest: bool) -> None:
    section: dict[str, Any] = {"value": [{"id": f"u-{i}"} for i in range(20)], "item_count": 367, "sample_truncated": True}
    if with_manifest:
        section["chunk_files"] = ["chunks/users.jsonl"]
    with pytest.raises(EndpointEvidenceError):
        list(iter_endpoint_records(section))
    snapshot = _snapshot(None, {"identity": {"users": section}})
    assert snapshot["snapshot"]["normalization_complete"] is False
    assert _report(snapshot)["record_count"] == (0 if with_manifest else 20)
    assert _report(snapshot)["issues"][0]["code"] == ("run_dir_required" if with_manifest else "missing_chunks")


def test_coverage_count_mismatch_is_not_hidden_by_valid_manifest(tmp_path: Path) -> None:
    section = _endpoint(tmp_path, "users", [{"id": f"u-{i}"} for i in range(31)])
    snapshot = _snapshot(tmp_path, {"identity": {"users": section}}, coverage_rows=[
        {"collector": "identity", "name": "users", "item_count": 35, "status": "ok"}
    ])
    assert _report(snapshot)["record_count"] == 31
    assert _report(snapshot)["issues"] == [{"code": "coverage_count_mismatch", "expected_count": 35, "observed_count": 31}]


def test_resumed_coverage_uses_latest_endpoint_observation(tmp_path: Path) -> None:
    section = _endpoint(tmp_path, "users", [{"id": f"u-{i}"} for i in range(31)])
    snapshot = _snapshot(tmp_path, {"identity": {"users": section}}, coverage_rows=[
        {"collector": "identity", "name": "users", "endpoint": "/users", "item_count": 35, "status": "failed"},
        {"collector": "identity", "name": "users", "endpoint": "/users", "item_count": 31, "status": "ok"},
    ])
    assert snapshot["snapshot"]["full_counts"]["users"] == 31
    assert _report(snapshot)["collection_status"] == "collected"
    assert _report(snapshot)["complete"] is True


def test_duplicate_inventory_sources_are_not_counted_as_unique_objects(tmp_path: Path) -> None:
    rows = [{"id": f"sp-{i}"} for i in range(367)]
    payloads = {name: {"servicePrincipals": _endpoint(tmp_path, name, rows)} for name in ("identity", "app_consent")}
    coverage = [{"collector": name, "name": "servicePrincipals", "item_count": 367} for name in payloads]
    snapshot = _snapshot(tmp_path, payloads, coverage_rows=coverage)
    assert snapshot["snapshot"]["full_counts"]["service_principals"] == 367
    assert snapshot["snapshot"]["full_counts_basis"] == "maximum_per_source_not_unique_union"
    assert snapshot["snapshot"]["sample_counts"]["service_principals"] == 20
    assert _report(snapshot, "identity.servicePrincipals")["record_count"] == 367
    assert _report(snapshot, "app_consent.servicePrincipals")["record_count"] == 367


@pytest.mark.parametrize("coverage_only", [False, True])
def test_collection_limit_is_distinct_from_successful_full_evidence_read(tmp_path: Path, coverage_only: bool) -> None:
    rows = [{"id": f"ca-{i}", "state": "disabled"} for i in range(31)]
    section = _endpoint(tmp_path, "ca", rows)
    coverage = []
    if coverage_only:
        coverage = [{"collector": "conditional_access", "name": "conditionalAccessPolicies", "result_limit": 31, "item_count": 31}]
    else:
        section["result_limit"] = 31
        section["collection_limit_reached"] = True
    snapshot = _snapshot(tmp_path, {"conditional_access": {"conditionalAccessPolicies": section}}, coverage_rows=coverage)
    assert snapshot["snapshot"]["normalization_complete"] is True
    assert snapshot["snapshot"]["collection_limited_sections"] == ["conditional_access.conditionalAccessPolicies"]
    signal = next(row for row in snapshot["detection_signal_objects"]["records"] if row["name"] == "risk_based_conditional_access")
    assert signal["status"] == "unknown"


def test_collector_persists_caps_and_completed_chunks_after_later_page_failure(tmp_path: Path) -> None:
    class Client:
        def iter_pages(self, _endpoint: str, params: Any = None):
            yield {"value": [{"id": f"u-{i}"} for i in range(31)], "@odata.nextLink": "unused"}
            raise GraphError("Synthetic later-page failure", status=503)

    def writer(collector: str, name: str, page: int, rows: list[dict[str, Any]], metadata: Any = None) -> str:
        return _write_chunk(tmp_path, f"chunks/{collector}/{name}-{page}.jsonl", rows)

    capped, _coverage = run_graph_endpoints("identity", Client(), {"users": {"endpoint": "/users"}}, top=25, chunk_writer=writer)
    assert capped["users"]["collection_limit_reached"] is True
    assert capped["users"]["collection_truncated"] is True
    assert capped["users"]["result_limit"] == 25
    assert len(list(iter_endpoint_records(capped["users"], tmp_path))) == 25

    partial, coverage = run_graph_endpoints("identity", Client(), {"users": {"endpoint": "/users"}}, top=None, chunk_writer=writer)
    assert coverage[0]["status"] == "failed"
    assert partial["users"]["item_count"] == 31
    assert partial["users"]["error"]
    snapshot = _snapshot(tmp_path, {"identity": partial}, coverage_rows=coverage)
    assert len(snapshot["users"]["records"]) == 31
    assert _report(snapshot)["collection_status"] == "failed"
