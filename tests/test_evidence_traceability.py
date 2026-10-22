"""Evidence is traceable: every reference resolves, is hashed, and the bundle can be re-checked.

Covers the evidence reference resolver, the validator that uses it, the finding builders that used
to cite record keys that did not exist, the proof status and confidence derived from resolved
references, and the bundle hash manifest that handoff, the explorer and customer-pack creation check.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit import evidence_refs
from azure_tenant_audit.autopilot import build_proof_table, enrich_findings_for_autopilot
from azure_tenant_audit.bundle_integrity import BUNDLE_HASHES_PATH, build_bundle_hash_manifest, verify_bundle_hashes
from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.contracts import build_validation_report
from azure_tenant_audit.evidence_refs import (
    EvidenceIndex,
    confined_file,
    confidence_for,
    resolve_json_pointer,
    seal_findings,
)
from azure_tenant_audit.findings import build_findings, build_report_pack
from auditex.reporting import BundleIntegrityError, enterprise_handoff, write_enterprise_handoff_pack

REPO_ROOT = Path(__file__).resolve().parents[1]


# --- the resolver ----------------------------------------------------------------------------


def _write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    root = tmp_path / "run"
    _write(
        root / "normalized" / "users.json",
        {
            "kind": "users",
            "records": [
                {"key": "user:1", "id": "1", "display_name": "Ada", "observed_at": "2026-10-01T00:00:00Z"},
                {"id": "2", "name": "Grace"},
                {"surface": "mail"},
            ],
        },
    )
    _write(root / "blockers" / "blockers.json", [{"collector": "identity", "item": "users"}, {"id": "b2"}])
    _write(root / "raw" / "identity.json", {"users": {"value": [1, 2], "error": None}, "a/b": {"x": 1}})
    _write(root / "index" / "coverage.jsonl", '{"key": "c1", "collected_at": "2026-10-02T00:00:00Z"}\n\nnot json\n{"id": "c3"}\n')
    _write(root / "notes.md", "# notes\n")
    return root


def _ref(artifact: str, key: str = "k", **extra: Any) -> dict[str, Any]:
    return {"artifact_path": artifact, "artifact_kind": "x", "collector": "c", "record_key": key, **extra}


def test_a_record_resolves_by_its_key_its_id_or_the_evidence_index_key(run_dir: Path) -> None:
    index = EvidenceIndex(run_dir)

    for key in ("user:1", "1", "users:1", "users:Ada", "users:0", "2", "users:Grace", "users:mail", "users:2"):
        assert index.resolve(_ref("normalized/users.json", key)).resolved, key
    for key in ("user:9", "Ada", "Grace", "", "users:9"):
        result = index.resolve(_ref("normalized/users.json", key))
        assert not result.resolved and result.reason == "record_not_found", key


def test_a_list_artifact_is_addressed_by_its_rows(run_dir: Path) -> None:
    index = EvidenceIndex(run_dir)

    assert index.resolve(_ref("blockers/blockers.json", "b2")).resolved
    assert index.resolve(_ref("blockers/blockers.json", "blockers:identity")).resolved
    assert not index.resolve(_ref("blockers/blockers.json", "b3")).resolved


def test_a_json_pointer_must_exist_and_takes_precedence_over_the_record_key(run_dir: Path) -> None:
    index = EvidenceIndex(run_dir)

    assert index.resolve(_ref("raw/identity.json", "invented", json_pointer="/users")).resolved
    assert index.resolve(_ref("raw/identity.json", json_pointer="/users/value/1")).resolved
    assert index.resolve(_ref("raw/identity.json", json_pointer="/a~1b/x")).resolved
    missing = index.resolve(_ref("raw/identity.json", "user:1", json_pointer="/nope"))
    assert not missing.resolved and missing.reason == "json_pointer_not_found"
    assert not index.resolve(_ref("raw/identity.json", json_pointer="/users/value/2")).resolved
    assert not index.resolve(_ref("raw/identity.json", json_pointer="/users/value/01")).resolved
    assert not index.resolve(_ref("raw/identity.json", json_pointer="users")).resolved
    assert resolve_json_pointer({"a": [1]}, "") == (True, {"a": [1]})


def test_a_jsonl_row_is_addressed_by_one_based_line_or_by_key(run_dir: Path) -> None:
    index = EvidenceIndex(run_dir)

    assert index.resolve(_ref("index/coverage.jsonl", jsonl_line=1)).resolved
    assert index.resolve(_ref("index/coverage.jsonl", jsonl_line=4)).resolved
    for line in (0, 2, 3, 5):
        assert index.resolve(_ref("index/coverage.jsonl", jsonl_line=line)).reason == "jsonl_line_not_found", line
    assert index.resolve(_ref("index/coverage.jsonl", "c3")).resolved
    assert not index.resolve(_ref("index/coverage.jsonl", "c2")).resolved


def test_an_artifact_that_is_not_json_cannot_be_addressed_but_is_hashed(run_dir: Path) -> None:
    result = EvidenceIndex(run_dir).resolve(_ref("notes.md", "anything"))

    assert not result.resolved and result.reason == "artifact_not_addressable"
    assert result.content_hash == hashlib.sha256(b"# notes\n").hexdigest()


def test_an_artifact_outside_the_run_directory_is_refused(run_dir: Path, tmp_path: Path) -> None:
    _write(tmp_path / "secret.json", {"records": [{"key": "k"}]})
    (run_dir / "link.json").symlink_to(tmp_path / "secret.json")
    (run_dir / "linkdir").symlink_to(tmp_path)
    index = EvidenceIndex(run_dir)

    for artifact in ("../secret.json", str(tmp_path / "secret.json"), "normalized/../../secret.json", "link.json", "linkdir/secret.json"):
        result = index.resolve(_ref(artifact, "k"))
        assert not result.resolved and result.reason == "artifact_outside_run_dir", artifact
        assert result.content_hash is None
    assert confined_file(run_dir, "normalized/users.json")[0] is not None
    assert index.resolve(_ref("normalized/absent.json")).reason == "artifact_missing"
    assert index.resolve(_ref("normalized")).reason == "artifact_missing"
    assert index.resolve(_ref("")).reason == "artifact_missing"


def test_an_unreadable_json_artifact_is_reported_not_raised(run_dir: Path) -> None:
    _write(run_dir / "normalized" / "bad.json", "{not json")

    result = EvidenceIndex(run_dir).resolve(_ref("normalized/bad.json", "k"))

    assert not result.resolved and result.reason == "artifact_unreadable"


def test_each_artifact_is_read_once_however_many_references_cite_it(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    loads: list[int] = []
    real_loads = evidence_refs.json.loads

    def counting_loads(text: str, *args: Any, **kwargs: Any) -> Any:
        loads.append(len(text))
        return real_loads(text, *args, **kwargs)

    monkeypatch.setattr(evidence_refs.json, "loads", counting_loads)
    refs = [_ref("normalized/users.json", key) for key in ("user:1", "2", "users:mail", "nope")] * 50
    refs += [_ref("raw/identity.json", json_pointer="/users")] * 20
    index = EvidenceIndex(run_dir)
    index.prime(refs)
    results = [index.resolve(ref) for ref in refs]

    assert len(loads) == 2
    assert sum(1 for item in results if item.resolved) == 150 + 20


def test_collected_at_is_the_records_own_time_when_it_has_one(run_dir: Path) -> None:
    index = EvidenceIndex(run_dir)

    assert index.resolve(_ref("normalized/users.json", "user:1")).collected_at == "2026-10-01T00:00:00Z"
    assert index.resolve(_ref("normalized/users.json", "2")).collected_at is None
    assert index.resolve(_ref("index/coverage.jsonl", jsonl_line=1)).collected_at == "2026-10-02T00:00:00Z"


def test_sealing_marks_hashes_and_dates_every_reference_and_derives_confidence(run_dir: Path) -> None:
    findings = [
        {
            "id": "f1",
            "confidence": "high",  # the builder's assertion, which must not survive a failed resolution
            "evidence_refs": [_ref("normalized/users.json", "user:1"), _ref("normalized/users.json", "user:404")],
        },
        {"id": "f2", "confidence": "low", "evidence_refs": [_ref("normalized/users.json", "2")]},
        {"id": "f3", "evidence_refs": [_ref("normalized/users.json", "nope")]},
        {"id": "f4", "evidence_refs": []},
    ]

    sealed = {item["id"]: item for item in seal_findings(run_dir, findings, created_utc="2026-10-22T09:00:00Z")}

    digest = hashlib.sha256((run_dir / "normalized" / "users.json").read_bytes()).hexdigest()
    first, second = sealed["f1"]["evidence_refs"]
    assert (first["resolved"], first["content_hash"], first["collected_at"]) == (True, digest, "2026-10-01T00:00:00Z")
    assert (second["resolved"], second["unresolved_reason"], second["content_hash"]) == (False, "record_not_found", digest)
    assert sealed["f2"]["evidence_refs"][0]["collected_at"] == "2026-10-22T09:00:00Z"
    assert {key: item["confidence"] for key, item in sealed.items()} == {
        "f1": "medium",
        "f2": "high",
        "f3": "low",
        "f4": "low",
    }
    assert "resolved" not in findings[0]["evidence_refs"][0]  # the input is not modified


def test_sealing_keeps_a_collected_at_the_builder_set_and_refreshes_a_stale_hash(run_dir: Path) -> None:
    ref = _ref("normalized/users.json", "2", collected_at="2026-01-01T00:00:00Z", content_hash="0" * 64)

    (sealed,) = seal_findings(run_dir, [{"id": "f", "evidence_refs": [ref]}], created_utc="2026-10-22T09:00:00Z")

    assert sealed["evidence_refs"][0]["collected_at"] == "2026-01-01T00:00:00Z"
    assert sealed["evidence_refs"][0]["content_hash"] != "0" * 64


def test_sealing_leaves_malformed_references_alone(run_dir: Path) -> None:
    findings = [
        {"id": "a", "evidence_refs": {"x": 1}},
        {"id": "b", "evidence_refs": "text"},
        {"id": "c"},
        {"id": "d", "evidence_refs": ["not a mapping", _ref("normalized/users.json", "2")]},
    ]

    sealed = {item["id"]: item for item in seal_findings(run_dir, findings)}

    assert sealed["a"]["evidence_refs"] == {"x": 1} and sealed["b"]["evidence_refs"] == "text"
    assert "evidence_refs" not in sealed["c"]
    assert [item["confidence"] for item in (sealed["a"], sealed["b"], sealed["c"])] == ["low", "low", "low"]
    assert sealed["d"]["evidence_refs"][0] == "not a mapping" and sealed["d"]["evidence_refs"][1]["resolved"] is True


def test_confidence_is_high_only_when_every_reference_resolved() -> None:
    assert confidence_for([{"resolved": True}, {"resolved": True}]) == "high"
    assert confidence_for([{"resolved": True}, {"resolved": False}]) == "medium"
    assert confidence_for([{"resolved": False}]) == "low"
    assert confidence_for([]) == "low"


# --- proof status and confidence in the report pack ------------------------------------------


def _finding(finding_id: str, *refs: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "id": finding_id,
        "rule_id": "rule.test",
        "severity": "high",
        "title": finding_id,
        "status": "open",
        "category": "identity",
        "collector": "identity",
        "evidence_refs": list(refs),
        **extra,
    }


def test_proof_rows_are_supported_when_resolved_and_unsupported_when_not() -> None:
    findings = [
        _finding(
            "mixed",
            {**_ref("a.json"), "resolved": True},
            {**_ref("b.json"), "resolved": False, "unresolved_reason": "record_not_found", "content_hash": "ab" * 32},
        ),
        _finding("none", {**_ref("c.json"), "resolved": False}),
        _finding("unchecked", _ref("d.json")),
        _finding("empty"),
    ]

    rows = build_proof_table(findings)

    by_ref = [(row["finding_id"], row.get("evidence_ref_index"), row["proof_status"]) for row in rows]
    assert by_ref == [
        ("mixed", 0, "supported"),
        ("mixed", 1, "unsupported"),
        ("none", 0, "unsupported"),
        ("unchecked", 0, "supported"),  # nothing has checked it; the validator resolves it independently
        ("empty", None, "missing_evidence"),
    ]
    unsupported = rows[1]
    assert unsupported["unresolved_reason"] == "record_not_found" and unsupported["content_hash"] == "ab" * 32


def test_a_finding_confidence_comes_from_its_resolved_references_not_the_builder() -> None:
    findings = [
        _finding("all", {**_ref("a.json"), "resolved": True}, confidence="low"),
        _finding("some", {**_ref("a.json"), "resolved": True}, {**_ref("b.json"), "resolved": False}, confidence="high"),
        _finding("none", {**_ref("b.json"), "resolved": False}, confidence="high"),
        _finding("unchecked", _ref("a.json"), confidence="medium"),
        _finding("legacy", _ref("a.json")),
    ]

    enriched = {item["id"]: item for item in enrich_findings_for_autopilot(findings)}

    assert {key: item["confidence"] for key, item in enriched.items()} == {
        "all": "high",
        "some": "medium",
        "none": "low",
        "unchecked": "medium",  # unchecked references leave a builder's own value alone
        "legacy": "high",
    }
    assert enriched["some"]["proof"]["supported_count"] == 1


def test_report_qa_counts_a_finding_with_no_resolved_reference_as_unsupported() -> None:
    findings = [
        _finding("good", {**_ref("a.json"), "resolved": True}),
        _finding("bad", {**_ref("b.json"), "resolved": False}),
    ]

    pack = build_report_pack(tenant_name="t", overall_status="ok", findings=findings, evidence_paths=[])

    assert pack["report_qa"]["status"] == "fail"
    assert pack["report_qa"]["unsupported_claims"] == ["bad"]
    prove = {row["finding_id"]: row["proof_status"] for row in pack["reviewer_index"]["prove_this"]}
    assert prove == {"good": "supported", "bad": "unsupported"}


# --- real bundles ----------------------------------------------------------------------------


def _bundle(root: Path, sample: str, label: str) -> Path:
    rc = run_offline(
        REPO_ROOT / "examples" / sample, root, "halcyon", label, auditor_profile="global-reader", plane="inventory"
    )
    assert rc in (0, 1)
    return root / f"halcyon-{label}"


@pytest.fixture(scope="module")
def demo_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _bundle(tmp_path_factory.mktemp("traceability-demo"), "demo_tenant/demo_tenant.json", "demo")


@pytest.fixture
def bundle(demo_bundle: Path, tmp_path: Path) -> Path:
    """A private copy of the demo bundle that a test may damage."""
    target = tmp_path / "halcyon-demo"
    shutil.copytree(demo_bundle, target)
    return target


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _edit_manifest(run_dir: Path, edit) -> None:
    path = run_dir / "run-manifest.json"
    manifest = _json(path)
    edit(manifest)
    path.write_text(json.dumps(manifest), encoding="utf-8")


def _as_finalized_before_the_hash_manifest(run_dir: Path) -> None:
    """What a bundle from before bundle-hashes.json looks like: no file, and no entry for it in the run manifest."""
    (run_dir / BUNDLE_HASHES_PATH).unlink()
    _edit_manifest(run_dir, lambda manifest: manifest["artifacts"].remove(BUNDLE_HASHES_PATH))


def _rehash(run_dir: Path) -> None:
    """Rewrite bundle-hashes.json for the files as they stand, as someone covering an edit would."""
    original = _json(run_dir / BUNDLE_HASHES_PATH)
    manifest = build_bundle_hash_manifest(run_dir, run_id=original["run_id"], created_utc=original["created_utc"])
    (run_dir / BUNDLE_HASHES_PATH).write_text(json.dumps(manifest), encoding="utf-8")


def _drop_role_assignments(run_dir: Path) -> None:
    path = run_dir / "normalized" / "role_assignments.json"
    payload = _json(path)
    payload["records"] = []
    path.write_text(json.dumps(payload), encoding="utf-8")


def _as_a_legacy_bundle(run_dir: Path) -> None:
    """A bundle finalized under the previous contract, citing a raw payload for a fan-out that has no row there."""
    _edit_manifest(run_dir, lambda manifest: manifest.update(schema_contract_version="2026-10-20"))
    path = run_dir / "findings" / "findings.json"
    findings = _json(path)
    ref = findings[0]["evidence_refs"][0]
    ref.clear()
    ref.update(
        artifact_path="raw/sample_input.json",
        artifact_kind="raw_json",
        collector="identity",
        record_key="identity:privilegedGroupFanout",
        json_pointer="/identity/privilegedGroupFanout",
    )
    path.write_text(json.dumps(findings), encoding="utf-8")


def _issues(run_dir: Path, *codes: str) -> list[dict[str, Any]]:
    report = build_validation_report(run_dir=run_dir, read_only=True)
    return [item for item in report["issues"] if item["code"] in codes]


@pytest.mark.parametrize(
    ("sample", "label"),
    [
        ("demo_tenant/demo_tenant.json", "demo"),
        ("demo_tenant/demo_tenant_remediated.json", "remediated"),
        ("sample_audit_bundle/known_bad_result.json", "known-bad"),
        ("sample_audit_bundle/identity_controls_result.json", "identity-controls"),
        ("sample_audit_bundle/sample_result.json", "sample"),
    ],
)
def test_every_evidence_reference_of_an_offline_bundle_resolves(tmp_path: Path, sample: str, label: str) -> None:
    run_dir = _bundle(tmp_path, sample, label)
    findings_path = run_dir / "findings" / "findings.json"
    findings = _json(findings_path) if findings_path.exists() else []  # the sample raises no finding
    index = EvidenceIndex(run_dir)
    refs = [ref for finding in findings for ref in finding["evidence_refs"]]
    index.prime(refs)

    unresolved = [(ref["artifact_path"], ref["record_key"], index.resolve(ref).reason) for ref in refs if not index.resolve(ref).resolved]

    assert unresolved == []
    assert _json(run_dir / "validation.json")["valid"] is True
    assert _issues(run_dir, "unresolved_evidence_ref", "broken_evidence_ref", "evidence_ref_hash_mismatch") == []
    assert all(ref["resolved"] is True for ref in refs)


def test_the_google_offline_bundle_resolves_every_reference(tmp_path: Path) -> None:
    from auditex.google_workspace.run import run_google_offline

    rc = run_google_offline(
        sample_path=REPO_ROOT / "examples" / "google_workspace_sample.json",
        out=tmp_path,
        tenant_name="acme",
        run_name="google",
        domain="example.com",
        customer_id=None,
    )
    run_dir = tmp_path / "acme-google"
    findings = _json(run_dir / "findings" / "findings.json")

    assert rc in (0, 1) and findings
    assert all(ref["resolved"] is True for finding in findings for ref in finding["evidence_refs"])
    assert _json(run_dir / "validation.json")["valid"] is True


def test_the_global_admin_findings_cite_the_assignment_and_user_records_that_exist(demo_bundle: Path) -> None:
    findings = {item["rule_id"]: item for item in _json(demo_bundle / "findings" / "findings.json")}
    assignments = {row["key"]: row for row in _json(demo_bundle / "normalized" / "role_assignments.json")["records"]}
    users = {row["key"] for row in _json(demo_bundle / "normalized" / "users.json")["records"]}

    disabled = findings["identity.global_admin_disabled"]
    kinds = {ref["artifact_path"]: ref["record_key"] for ref in disabled["evidence_refs"]}
    assert kinds["normalized/role_assignments.json"] in assignments
    assert kinds["normalized/users.json"] in users
    # The cited assignment is the one that belongs to the disabled principal.
    principal = disabled["returned_value"]["principal_id"]
    assert assignments[kinds["normalized/role_assignments.json"]]["principal_id"] == principal
    assert not any(ref["record_key"] == "identity:global_admin_resilience" for item in findings.values() for ref in item["evidence_refs"])


def test_the_governance_and_intune_findings_cite_records_that_exist(demo_bundle: Path) -> None:
    findings = {item["rule_id"]: item for item in _json(demo_bundle / "findings" / "findings.json")}

    standing = findings["identity_governance.standing_privilege_only"]
    keys = {ref["record_key"] for ref in standing["evidence_refs"]}
    assert "normalization:identity_governance.roleEligibilitySchedules" in keys
    assert any(key.startswith("role_assignment_schedule:") for key in keys)

    intune = findings["intune_depth.policies_without_assignments"]
    rows = {row["key"]: row for row in _json(demo_bundle / "normalized" / "intune_policy_assignment_objects.json")["records"]}
    cited = {ref["record_key"] for ref in intune["evidence_refs"]}
    # The policy count comes from the policy read; "no assignments" from one row per policy, each empty.
    # The assignment read's own coverage row (record_count 2 for two policies) is not cited beside them.
    assert cited == {"normalization:intune_depth.deviceConfigurations", *rows}
    assert len(rows) == intune["returned_value"]["policy_count"] == 2
    assert all(row["assignment_count"] == 0 for row in rows.values())
    assert intune["returned_value"]["assignment_count"] == 0
    assert all(ref["resolved"] for item in (standing, intune) for ref in item["evidence_refs"])


def test_a_sealed_bundle_carries_the_hash_and_time_of_every_cited_artifact(demo_bundle: Path) -> None:
    manifest = _json(demo_bundle / "run-manifest.json")
    findings = _json(demo_bundle / "findings" / "findings.json")
    pack = _json(demo_bundle / "reports" / "report-pack.json")

    for finding in findings:
        assert finding["confidence"] == "high"
        for ref in finding["evidence_refs"]:
            artifact = demo_bundle / ref["artifact_path"]
            assert ref["content_hash"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
            assert ref["collected_at"] == manifest["created_utc"]
    assert {row["proof_status"] for row in pack["proof_table"]} == {"supported"}
    assert all(row["content_hash"] and row["collected_at"] for row in pack["proof_table"])
    assert pack["report_qa"]["status"] == "pass"


def test_a_missing_record_is_a_validation_issue_that_names_the_finding(bundle: Path) -> None:
    path = bundle / "normalized" / "role_assignments.json"
    payload = _json(path)
    payload["records"] = [row for row in payload["records"] if row["key"] != "role_assignment:ra-005"]
    path.write_text(json.dumps(payload), encoding="utf-8")

    issues = _issues(bundle, "unresolved_evidence_ref")

    assert issues and all(item["severity"] == "error" for item in issues)
    disabled = [item for item in issues if item["details"]["finding_id"].startswith("identity:global_admin_disabled:")]
    assert disabled and disabled[0]["details"]["record_key"] == "role_assignment:ra-005"
    assert disabled[0]["details"]["reason"] == "record_not_found"
    assert build_validation_report(run_dir=bundle, read_only=True)["valid"] is False
    # The proof table says the same thing, row by row.
    assert _issues(bundle, "unresolved_report_proof_table_ref")


def test_a_missing_artifact_is_still_a_broken_reference(bundle: Path) -> None:
    (bundle / "normalized" / "users.json").unlink()

    issues = _issues(bundle, "broken_evidence_ref")

    assert issues and {item["details"]["reason"] for item in issues} == {"artifact_missing"}
    assert all(item["details"]["finding_id"] for item in issues)


def test_an_artifact_outside_the_run_directory_is_a_broken_reference(bundle: Path, tmp_path: Path) -> None:
    findings_path = bundle / "findings" / "findings.json"
    findings = _json(findings_path)
    outside = tmp_path / "elsewhere.json"
    outside.write_text(json.dumps({"records": [{"key": "k"}]}), encoding="utf-8")
    findings[0]["evidence_refs"].append(
        {"artifact_path": "../elsewhere.json", "artifact_kind": "x", "collector": "identity", "record_key": "k"}
    )
    findings_path.write_text(json.dumps(findings), encoding="utf-8")

    issues = _issues(bundle, "broken_evidence_ref")

    assert [item["details"]["reason"] for item in issues] == ["artifact_outside_run_dir"]
    assert issues[0]["details"]["finding_id"] == findings[0]["id"]


def test_an_artifact_edited_after_sealing_fails_its_content_hash(bundle: Path) -> None:
    path = bundle / "normalized" / "users.json"
    path.write_bytes(path.read_bytes() + b"\n")

    issues = _issues(bundle, "evidence_ref_hash_mismatch")

    assert issues
    for item in issues:
        assert item["details"]["artifact_path"] == "normalized/users.json"
        assert item["details"]["expected"] != item["details"]["actual"]


def test_a_bad_json_pointer_is_unresolved(bundle: Path) -> None:
    findings_path = bundle / "findings" / "findings.json"
    findings = _json(findings_path)
    findings[0]["evidence_refs"][0]["json_pointer"] = "/records/9999"
    findings_path.write_text(json.dumps(findings), encoding="utf-8")

    issues = _issues(bundle, "unresolved_evidence_ref")

    assert [item["details"]["reason"] for item in issues] == ["json_pointer_not_found"]


def test_validation_reads_each_cited_artifact_once(bundle: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit import contracts

    reads: list[str] = []
    real = evidence_refs.EvidenceIndex._resolve_artifact

    def counting(self: EvidenceIndex, artifact: str, items: dict) -> None:
        reads.append(artifact)
        return real(self, artifact, items)

    monkeypatch.setattr(evidence_refs.EvidenceIndex, "_resolve_artifact", counting)
    report = contracts.build_validation_report(run_dir=bundle, read_only=True)

    assert report["valid"] is True
    assert reads and len(reads) == len(set(reads))


def test_a_citation_that_does_not_resolve_in_a_legacy_bundle_is_labelled_legacy(bundle: Path) -> None:
    _as_a_legacy_bundle(bundle)
    findings = _json(bundle / "findings" / "findings.json")

    issues = _issues(bundle, "legacy_unresolved_ref", "unresolved_evidence_ref")

    assert [item["code"] for item in issues] == ["legacy_unresolved_ref"]
    assert issues[0]["severity"] == "error"  # still fails validation, so the gate still fails closed
    assert issues[0]["details"]["finding_id"] == findings[0]["id"]
    assert issues[0]["details"]["reason"] == "json_pointer_not_found"
    assert issues[0]["details"]["json_pointer"] == "/identity/privilegedGroupFanout"
    assert build_validation_report(run_dir=bundle, read_only=True)["valid"] is False


def test_the_same_citation_in_a_current_bundle_is_not_legacy(bundle: Path) -> None:
    _as_a_legacy_bundle(bundle)
    _edit_manifest(bundle, lambda manifest: manifest.update(schema_contract_version="2026-10-22"))

    assert [item["code"] for item in _issues(bundle, "legacy_unresolved_ref", "unresolved_evidence_ref")] == [
        "unresolved_evidence_ref"
    ]


def test_a_missing_artifact_is_broken_not_legacy_whatever_the_bundle_age(bundle: Path) -> None:
    _as_a_legacy_bundle(bundle)
    (bundle / "normalized" / "users.json").unlink()

    codes = {item["code"] for item in _issues(bundle, "legacy_unresolved_ref", "broken_evidence_ref")}

    assert "broken_evidence_ref" in codes


def test_handoff_and_gate_name_legacy_citations_rather_than_tampering(bundle: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from auditex.cli import main

    _as_a_legacy_bundle(bundle)
    _rehash(bundle)

    handoff = enterprise_handoff(bundle)

    assert handoff["integrity"]["status"] == "verified"
    assert handoff["handoff_status"] == "unusable" and handoff["status_reasons"] == ["legacy_unresolved_refs"]
    recomputed = handoff["contract"]["recomputed"]
    assert recomputed["legacy_unresolved_ref_count"] >= 1 and recomputed["only_legacy_unresolved_refs"] is True
    assert "legacy bundle, not a sign of editing" in recomputed["summary"]
    assert any(row["surface"] == "contract_validation" and row["status"] == "legacy_unresolved_refs" for row in handoff["limitations"])
    with pytest.raises(BundleIntegrityError):
        write_enterprise_handoff_pack(bundle, tmp_path / "pack")

    assert main(["gate", str(bundle), "--fail-on", "high"]) == 2
    out = capsys.readouterr()
    assert "legacy_unresolved_ref" in out.err and "not evidence of editing" in out.err
    payload = json.loads(out.out)
    assert payload["contract"]["legacy_unresolved_ref_count"] >= 1
    assert payload["contract"]["only_legacy_unresolved_refs"] is True


def test_a_proof_table_content_hash_is_rechecked(bundle: Path) -> None:
    pack_path = bundle / "reports" / "report-pack.json"
    pack = _json(pack_path)
    row = next(item for item in pack["proof_table"] if item.get("content_hash"))
    good = row["content_hash"]
    row["content_hash"] = "0" * 64
    pack_path.write_text(json.dumps(pack), encoding="utf-8")

    issues = [item for item in _issues(bundle, "evidence_ref_hash_mismatch") if item["path"] == "reports/report-pack.json"]

    assert issues
    assert issues[0]["details"]["expected"] == "0" * 64 and issues[0]["details"]["actual"] == good
    assert issues[0]["details"]["finding_id"] == row["finding_id"]


# --- the bundle hash manifest ----------------------------------------------------------------


def _all_files(run_dir: Path) -> set[str]:
    return {
        path.relative_to(run_dir).as_posix()
        for path in run_dir.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def test_finalize_writes_a_hash_for_every_artifact(demo_bundle: Path) -> None:
    manifest = _json(demo_bundle / BUNDLE_HASHES_PATH)
    listed = {row["path"]: row for row in manifest["artifacts"]}

    assert manifest["algorithm"] == "sha256"
    assert manifest["created_utc"] == _json(demo_bundle / "run-manifest.json")["created_utc"]
    assert manifest["artifact_count"] == len(listed)
    excluded = {row["path"] for row in manifest["excluded"]}
    assert excluded == {"audit-log.jsonl", "audit-command-log.jsonl", "audit-debug.log"}
    assert set(listed) == _all_files(demo_bundle) - excluded - {BUNDLE_HASHES_PATH}
    for relative, row in listed.items():
        data = (demo_bundle / relative).read_bytes()
        assert row["sha256"] == hashlib.sha256(data).hexdigest() and row["bytes"] == len(data), relative
    assert BUNDLE_HASHES_PATH in _json(demo_bundle / "run-manifest.json")["artifacts"]


def test_the_hash_manifest_matches_its_shipped_schema(demo_bundle: Path) -> None:
    try:
        import jsonschema
    except ImportError:  # pragma: no cover
        pytest.fail("jsonschema is required: python -m pip install -e '.[test]'", pytrace=False)
    schema = _json(REPO_ROOT / "schemas" / "bundle_hashes.schema.json")

    jsonschema.Draft202012Validator(schema).validate(_json(demo_bundle / BUNDLE_HASHES_PATH))
    jsonschema.Draft202012Validator(_json(REPO_ROOT / "schemas" / "finding.schema.json")).validate(
        _json(demo_bundle / "findings" / "findings.json")[0]
    )


def test_a_fresh_bundle_verifies_and_reading_it_does_not_change_it(demo_bundle: Path) -> None:
    before = verify_bundle_hashes(demo_bundle)
    build_validation_report(run_dir=demo_bundle, read_only=True)
    enterprise_handoff(demo_bundle)
    after = verify_bundle_hashes(demo_bundle)

    assert before["status"] == after["status"] == "verified"
    assert before["checked_count"] == after["checked_count"] > 20
    assert (before["modified"], before["missing"], before["unlisted"]) == ([], [], [])


def test_an_edited_artifact_is_a_mismatch_that_names_it(bundle: Path) -> None:
    path = bundle / "summary.json"
    path.write_text(path.read_text(encoding="utf-8").replace("halcyon", "someone-else", 1), encoding="utf-8")

    result = verify_bundle_hashes(bundle)

    assert result["status"] == "mismatch"
    assert [row["path"] for row in result["modified"]] == ["summary.json"]
    assert result["modified"][0]["expected"] != result["modified"][0]["actual"]


def test_a_removed_artifact_is_a_mismatch(bundle: Path) -> None:
    (bundle / "normalized" / "devices.json").unlink()

    result = verify_bundle_hashes(bundle)

    assert result["status"] == "mismatch" and result["missing"] == ["normalized/devices.json"]


def test_a_file_added_later_is_reported_but_does_not_fail_the_check(bundle: Path) -> None:
    (bundle / "reports" / "explorer.html").write_text("<html></html>", encoding="utf-8")
    with (bundle / "audit-log.jsonl").open("a", encoding="utf-8") as handle:
        handle.write('{"event": "later"}\n')

    result = verify_bundle_hashes(bundle)

    assert result["status"] == "verified"
    assert result["unlisted"] == ["reports/explorer.html"]


def test_a_bundle_finalized_before_the_hash_manifest_cannot_be_checked(bundle: Path) -> None:
    _as_finalized_before_the_hash_manifest(bundle)

    assert verify_bundle_hashes(bundle)["status"] == "absent"


def test_a_hash_manifest_that_the_run_manifest_lists_but_is_gone_is_invalid_not_absent(bundle: Path) -> None:
    """Deleting bundle-hashes.json must not turn a failed check into "nothing to check"."""
    (bundle / BUNDLE_HASHES_PATH).unlink()

    result = verify_bundle_hashes(bundle)

    assert result["status"] == "invalid"
    assert "lists bundle-hashes.json" in result["message"]


@pytest.mark.parametrize("content", ["not json", "[]", '{"artifacts": [{"path": 1}]}', '{"artifacts": [], "algorithm": "md5"}'])
def test_an_unreadable_hash_manifest_is_invalid(bundle: Path, content: str) -> None:
    (bundle / BUNDLE_HASHES_PATH).write_text(content, encoding="utf-8")

    assert verify_bundle_hashes(bundle)["status"] == "invalid"


def test_a_hash_manifest_row_that_escapes_the_run_directory_is_missing_not_followed(bundle: Path, tmp_path: Path) -> None:
    (tmp_path / "outside.txt").write_text("x", encoding="utf-8")
    manifest = _json(bundle / BUNDLE_HASHES_PATH)
    manifest["artifacts"].append(
        {"path": "../outside.txt", "sha256": hashlib.sha256(b"x").hexdigest(), "bytes": 1}
    )
    (bundle / BUNDLE_HASHES_PATH).write_text(json.dumps(manifest), encoding="utf-8")

    result = verify_bundle_hashes(bundle)

    assert result["status"] == "mismatch" and result["missing"] == ["../outside.txt"]


def test_the_hash_manifest_is_a_function_of_the_files(bundle: Path) -> None:
    assert build_bundle_hash_manifest(bundle, run_id="r", created_utc="t") == build_bundle_hash_manifest(bundle, run_id="r", created_utc="t")
    original = _json(bundle / BUNDLE_HASHES_PATH)
    rebuilt = build_bundle_hash_manifest(bundle, run_id=original["run_id"], created_utc=original["created_utc"])
    # The only files that differ from finalization are the ones finalization could not have hashed.
    assert rebuilt["artifacts"] == original["artifacts"]


# --- handoff, explorer and customer pack ------------------------------------------------------


def test_handoff_reports_integrity_and_a_recomputed_validation(demo_bundle: Path) -> None:
    handoff = enterprise_handoff(demo_bundle)

    assert handoff["integrity"]["status"] == "verified"
    assert handoff["integrity"]["checked_count"] > 20
    assert handoff["integrity"]["manifest_sha256"] == hashlib.sha256((demo_bundle / BUNDLE_HASHES_PATH).read_bytes()).hexdigest()
    assert handoff["contract"]["recomputed"]["valid"] is True
    assert handoff["contract"]["recomputed"]["matches_validation_json"] is True
    assert handoff["handoff_status"] != "unusable"
    assert not [row for row in handoff["limitations"] if row.get("surface") == "bundle_integrity"]


def test_handoff_reports_a_changed_bundle_as_unusable(bundle: Path) -> None:
    path = bundle / "ai_safe" / "run_summary.json"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    handoff = enterprise_handoff(bundle)

    assert handoff["integrity"]["status"] == "mismatch"
    assert handoff["integrity"]["modified_paths"] == ["ai_safe/run_summary.json"]
    limits = [row for row in handoff["limitations"] if row.get("surface") == "bundle_integrity"]
    assert limits and limits[0]["paths"] == ["ai_safe/run_summary.json"]
    assert handoff["handoff_status"] == "unusable"
    assert handoff["status_reasons"] == ["bundle_integrity_mismatch"]


def test_handoff_is_unusable_when_the_recomputed_validation_fails_though_validation_json_says_valid(bundle: Path) -> None:
    _drop_role_assignments(bundle)

    handoff = enterprise_handoff(bundle)

    assert _json(bundle / "validation.json")["valid"] is True  # what the finalizer recorded
    assert handoff["contract"]["valid"] is True
    assert handoff["contract"]["recomputed"]["valid"] is False
    assert handoff["contract"]["recomputed"]["matches_validation_json"] is False
    assert handoff["contract"]["recomputed"]["error_count"] >= 1
    # The edit is also what the hash check names.
    assert handoff["integrity"]["modified_paths"] == ["normalized/role_assignments.json"]
    assert handoff["handoff_status"] == "unusable"
    assert handoff["status_reasons"] == ["recomputed_validation_failed", "bundle_integrity_mismatch"]


def test_a_customer_pack_records_the_bundle_check(demo_bundle: Path, tmp_path: Path) -> None:
    from auditex.reporting import verify_enterprise_handoff_pack

    pack = tmp_path / "pack"

    manifest = write_enterprise_handoff_pack(demo_bundle, pack)

    assert manifest["source"]["integrity"]["status"] == "verified"
    assert (pack / "source-artifacts" / BUNDLE_HASHES_PATH).read_bytes() == (demo_bundle / BUNDLE_HASHES_PATH).read_bytes()
    assert "Bundle integrity: verified" in (pack / "README.md").read_text(encoding="utf-8")
    assert verify_enterprise_handoff_pack(pack)["valid"] is True


def test_a_customer_pack_is_refused_for_a_changed_bundle(bundle: Path, tmp_path: Path) -> None:
    path = bundle / "data-handling.json"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    pack = tmp_path / "pack"

    with pytest.raises(BundleIntegrityError) as caught:
        write_enterprise_handoff_pack(bundle, pack)

    assert caught.value.integrity["modified_paths"] == ["data-handling.json"]
    assert "refusing to create a customer pack" in str(caught.value)
    assert not pack.exists()


def test_a_customer_pack_is_refused_for_an_unreadable_hash_manifest(bundle: Path, tmp_path: Path) -> None:
    (bundle / BUNDLE_HASHES_PATH).write_text("garbage", encoding="utf-8")

    with pytest.raises(BundleIntegrityError):
        write_enterprise_handoff_pack(bundle, tmp_path / "pack")


def test_a_customer_pack_can_still_be_made_from_a_bundle_finalized_before_the_manifest(bundle: Path, tmp_path: Path) -> None:
    _as_finalized_before_the_hash_manifest(bundle)

    manifest = write_enterprise_handoff_pack(bundle, tmp_path / "pack")

    assert manifest["source"]["integrity"]["status"] == "absent"


def test_a_customer_pack_is_refused_when_the_hash_manifest_was_deleted(bundle: Path, tmp_path: Path) -> None:
    """Even with a real edit hidden behind the deletion: the run manifest still lists the file."""
    path = bundle / "normalized" / "users.json"
    path.write_bytes(path.read_bytes() + b"\n")
    (bundle / BUNDLE_HASHES_PATH).unlink()

    with pytest.raises(BundleIntegrityError) as caught:
        write_enterprise_handoff_pack(bundle, tmp_path / "pack")

    assert caught.value.integrity["status"] == "invalid"
    assert not (tmp_path / "pack").exists()


def test_a_customer_pack_is_refused_when_revalidation_fails_even_if_the_hashes_were_rewritten(bundle: Path, tmp_path: Path) -> None:
    _drop_role_assignments(bundle)
    _rehash(bundle)  # the hash check now passes: only revalidation can catch this

    assert verify_bundle_hashes(bundle)["status"] == "verified"
    with pytest.raises(BundleIntegrityError) as caught:
        write_enterprise_handoff_pack(bundle, tmp_path / "pack")

    assert caught.value.integrity["status"] == "verified"
    assert caught.value.validation["valid"] is False and "unresolved_evidence_ref" in caught.value.validation["issue_codes"]
    assert "does not validate" in str(caught.value)
    assert not (tmp_path / "pack").exists()
    handoff = enterprise_handoff(bundle)
    assert handoff["handoff_status"] == "unusable" and handoff["status_reasons"] == ["recomputed_validation_failed"]


def test_a_changed_bundle_is_rejected_by_the_gate_as_it_was_before(bundle: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from auditex.cli import main

    _drop_role_assignments(bundle)

    assert main(["gate", str(bundle), "--fail-on", "high"]) == 2
    assert "contract_invalid" in capsys.readouterr().err


def test_the_customer_pack_command_refuses_a_changed_bundle(bundle: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from auditex.cli import main

    path = bundle / "summary.json"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    code = main(["report", "customer-pack", str(bundle), "--output-dir", str(tmp_path / "pack")])

    assert code == 2
    assert "refusing to create a customer pack" in capsys.readouterr().err
    assert not (tmp_path / "pack").exists()


def test_the_explorer_flags_a_changed_bundle_and_recomputes_the_contract(demo_bundle: Path, bundle: Path) -> None:
    from auditex.explorer import build_explorer_data

    clean = build_explorer_data(demo_bundle)
    assert clean["integrity"]["status"] == "verified" and clean["contract_valid"] is True
    assert not [banner for banner in clean["banners"] if banner["kind"] == "integrity"]

    path = bundle / "normalized" / "role_assignments.json"
    payload = _json(path)
    payload["records"] = []
    path.write_text(json.dumps(payload), encoding="utf-8")

    changed = build_explorer_data(bundle)

    assert changed["integrity"]["status"] == "mismatch" and changed["integrity"]["modified_count"] == 1
    assert changed["contract_valid"] is False  # validation.json still says valid; the recomputed one does not
    assert [banner["title"] for banner in changed["banners"] if banner["kind"] == "integrity"] == [
        "Bundle does not validate",
        "Bundle changed since it was finalized",
    ]


def test_the_explorer_flags_a_failed_revalidation_even_when_the_hashes_were_rewritten(bundle: Path) -> None:
    from auditex.explorer import build_explorer_data

    _drop_role_assignments(bundle)
    _rehash(bundle)

    data = build_explorer_data(bundle)

    assert data["integrity"]["status"] == "verified" and data["contract_valid"] is False
    (banner,) = [item for item in data["banners"] if item["kind"] == "integrity"]
    assert banner["title"] == "Bundle does not validate" and "unresolved_evidence_ref" in banner["text"]


def test_the_explorer_says_so_when_the_only_failures_are_legacy_citations(bundle: Path) -> None:
    from auditex.explorer import build_explorer_data

    _as_a_legacy_bundle(bundle)
    _rehash(bundle)

    (banner,) = [item for item in build_explorer_data(bundle)["banners"] if item["kind"] == "integrity"]

    assert banner["title"] == "Legacy evidence references do not resolve"
    assert "not a sign that the bundle was edited" in banner["text"]


def test_the_explorer_page_is_the_same_when_it_is_written_into_the_run_twice(bundle: Path) -> None:
    from auditex.explorer import write_explorer

    page = bundle / "reports" / "explorer.html"
    write_explorer([bundle], page)
    first = page.read_bytes()

    write_explorer([bundle], page)  # the first page is now an unlisted file in the run

    assert page.read_bytes() == first
    assert verify_bundle_hashes(bundle)["status"] == "verified"


def test_the_explorer_does_not_call_a_partly_unsupported_finding_proven() -> None:
    from auditex.explorer import _finding_rows

    findings = [{"id": "f", "severity": "high", "title": "t", "evidence_refs": []}]
    proof = [
        {"finding_id": "f", "proof_status": "unsupported"},
        {"finding_id": "f", "proof_status": "supported"},
    ]

    assert _finding_rows(findings, proof)[0]["proof"] == "partial"
    assert _finding_rows(findings, list(reversed(proof)))[0]["proof"] == "partial"
    assert _finding_rows(findings, proof[1:])[0]["proof"] == "supported"


# --- builders with nothing of their own to cite -----------------------------------------------


def test_a_collector_issue_cites_the_blocker_row_it_was_built_from(tmp_path: Path) -> None:
    diagnostics = [
        {"collector": "security", "item": "alerts", "endpoint": "/security/alerts", "status": "failed", "error_class": "insufficient_permissions"},
        {"collector": "intune", "status": "failed", "error_class": "unknown"},
        {"collector": "sharepoint_access", "item": "sites", "endpoint": "/sites/a", "status": "failed", "error_class": "forbidden"},
        {"collector": "sharepoint_access", "item": "sites", "endpoint": "/sites/b", "status": "failed", "error_class": "forbidden"},
    ]
    run_dir = tmp_path / "run"
    _write(run_dir / "blockers" / "blockers.json", diagnostics)

    findings = {item["id"]: item for item in build_findings(diagnostics)}
    sealed = seal_findings(run_dir, list(findings.values()))

    assert {item["id"]: [ref["json_pointer"] for ref in item["evidence_refs"]] for item in sealed} == {
        "security:alerts": ["/0"],
        "intune:intune": ["/1"],
        "sharepoint_access:sites": ["/2", "/3"],
    }
    assert all(ref["resolved"] for item in sealed for ref in item["evidence_refs"])
    assert findings["security:alerts"]["evidence_refs"][0]["endpoint"] == "/security/alerts"


def test_a_finding_with_no_citation_of_its_own_gets_a_ledger_stand_in_marked_as_generated() -> None:
    from azure_tenant_audit.findings import _finalize_finding

    finding = _finalize_finding({"id": "x", "rule_id": "r.x", "severity": "low", "collector": "identity"})

    assert finding["evidence_ref_generated"] is True
    assert finding["evidence_refs"][0]["artifact_path"] == "normalized/coverage_ledger.json"
    assert finding["evidence_refs"][0]["record_key"] == "coverage_ledger:identity"


def test_a_google_collector_issue_cites_the_collectors_ledger_row() -> None:
    from auditex.google_workspace.findings import build_google_findings

    findings = build_google_findings(
        {"snapshot": {"workspace_domain": "example.com"}},
        diagnostics=[{"collector": "google_directory", "name": "users", "status": "failed", "error_class": "client_error"}],
    )

    (issue,) = [item for item in findings if item["rule_id"] == "google.collector_issue"]
    assert issue["id"] == "google.collector_issue:google_directory:users"
    assert issue["evidence_refs"][0]["artifact_path"] == "normalized/coverage_ledger.json"
    assert issue["evidence_refs"][0]["record_key"] == "coverage_ledger:google_directory"

