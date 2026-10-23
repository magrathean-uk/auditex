"""Follow-ups to the third CE+ product review, integrity-gate lens (2026-10-22).

Nine findings whose refuters did not run, each reproduced before it was fixed:

a. ``verify-pack`` skipped its source-artifact check when the pack's own manifest claimed the run was not verified;
b. a planted SQLite ``-wal`` sidecar was excluded from hashing but replayed by every consumer of the evidence index;
c. the emergency-access list was an unrecorded rule input, so listing a staff group later made findings "resolved";
d. an offline replay presented its safety flags as observed in the transport audit log;
e. a current-contract bundle stripped of ``bundle-hashes.json`` was called pre-hashing by the handoff, and a pack built;
f. a ``closed`` status on an expired waiver passed the gate while ``accepted_risk`` on it failed;
g. nothing but the editable contract version stood behind the absent-manifest block, and no gate took a digest;
h. a pack for a run written with an absolute ``--out`` carried the operator's path in ``run-manifest.json``;
i. reports written into a run after it was finalized were unhashed and raised no limitation.
"""
from __future__ import annotations

import hashlib
import io
import json
import shutil
import sqlite3
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from auditex import cli as auditex_cli
from auditex.compare import build_finding_delta, compare_runs
from auditex.run_bundle import RunBundle
from auditex.reporting import (
    BundleIntegrityError,
    enterprise_handoff,
    render_enterprise_handoff_markdown,
    verify_enterprise_handoff_pack,
    write_enterprise_handoff_pack,
)
from azure_tenant_audit.bundle_integrity import BUNDLE_HASHES_PATH, verify_bundle_hashes
from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.contracts import build_validation_report
from azure_tenant_audit.evidence_db import load_run_index_summary
from azure_tenant_audit.rule_parameters import effective_rule_parameters, rule_parameter_gap

from gate_support import finding, offline_run, read_json, rehash, write_findings

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO = REPO_ROOT / "examples" / "demo_tenant" / "demo_tenant.json"
EXPIRED = {"owner": "ciso", "reason": "approved", "expires_on": "2020-01-01"}
CURRENT = {"owner": "ciso", "reason": "approved", "expires_on": "2999-01-01"}


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _main(argv: list[str]) -> tuple[int, dict[str, Any]]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        rc = auditex_cli.main(argv)
    return rc, json.loads(buffer.getvalue())


def _digest(run_dir: Path) -> str:
    return verify_bundle_hashes(run_dir)["manifest_sha256"]


@pytest.fixture(scope="module")
def demo_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("followups-demo")
    assert run_offline(DEMO, root, "halcyon", "demo", auditor_profile="global-reader", plane="inventory") in (0, 1)
    return root / "halcyon-demo"


@pytest.fixture
def bundle(demo_bundle: Path, tmp_path: Path) -> Path:
    """A private copy of the demo bundle that a test may damage."""
    target = tmp_path / "work" / "halcyon-demo"
    shutil.copytree(demo_bundle, target)
    return target


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    return offline_run(tmp_path)


@pytest.fixture
def pair(tmp_path: Path) -> tuple[Path, Path]:
    return offline_run(tmp_path / "baseline", "baseline"), offline_run(tmp_path / "current", "current")


def _write_pack(bundle: Path, tmp_path: Path, name: str = "pack") -> Path:
    pack = tmp_path / name
    write_enterprise_handoff_pack(bundle, pack)
    assert verify_enterprise_handoff_pack(pack)["valid"] is True
    return pack


def _rehash_pack(pack: Path, *relatives: str) -> None:
    """Re-hash pack files the way someone who can write to the whole pack would: rows, checksums and the manifest."""
    def sha(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    manifest_path = pack / "pack-manifest.json"
    manifest = _json(manifest_path)
    rows = {row["path"]: row for row in [*manifest["generated_files"], *manifest["source_artifacts"]] if row.get("path")}
    for relative in relatives:
        rows[relative]["sha256"] = sha(pack / relative)
    lines = []
    for line in (pack / "checksums.sha256").read_text(encoding="utf-8").splitlines():
        digest, path = line.split(None, 1)
        lines.append(f"{sha(pack / path.strip())}  {path.strip()}" if path.strip() in relatives else line)
    (pack / "checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rows["checksums.sha256"]["sha256"] = sha(pack / "checksums.sha256")
    _write_json(manifest_path, manifest)


# ---- a. verify-pack re-hashes every copied source artifact, whatever the pack claims ---------------------------


def _claim_the_run_was_not_verified(pack: Path, status: str = "absent") -> None:
    """Edit the two places that carry the claimed status (the pack manifest and handoff.json), then re-hash both."""
    manifest_path = pack / "pack-manifest.json"
    manifest = _json(manifest_path)
    manifest["source"]["integrity"]["status"] = status
    _write_json(manifest_path, manifest)
    handoff_path = pack / "handoff.json"
    handoff = _json(handoff_path)
    handoff["integrity"]["status"] = status
    _write_json(handoff_path, handoff)
    _rehash_pack(pack, "handoff.json")


def _rewrite_the_copied_report_pack(pack: Path) -> None:
    target = pack / "source-artifacts" / "reports" / "report-pack.json"
    document = _json(target)
    for row in document.get("findings") or []:
        row["severity"] = "low"
    _write_json(target, document)
    _rehash_pack(pack, "source-artifacts/reports/report-pack.json")


def test_verify_pack_rejects_a_rewritten_report_pack_even_when_the_pack_claims_the_run_was_not_verified(
    bundle: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pack = _write_pack(bundle, tmp_path)
    genuine = _digest(bundle)
    _rewrite_the_copied_report_pack(pack)
    _claim_the_run_was_not_verified(pack)

    result = verify_enterprise_handoff_pack(pack, expect_manifest_sha256=genuine)

    assert result["valid"] is False
    codes = {issue["code"] for issue in result["issues"]}
    assert "source_artifact_bundle_hash_mismatch" in codes
    assert "source_integrity_status_inconsistent" in codes
    mismatch = next(issue for issue in result["issues"] if issue["code"] == "source_artifact_bundle_hash_mismatch")
    assert mismatch["path"] == "source-artifacts/reports/report-pack.json" and mismatch["source_path"] == "reports/report-pack.json"
    # The digest of the copied manifest is the genuine one: only the artifact differs from what it lists.
    assert "expected_manifest_sha256_mismatch" not in codes
    assert auditex_cli.main(["report", "verify-pack", str(pack), "--expect-manifest-sha256", genuine]) == 1
    capsys.readouterr()


def test_verify_pack_checks_a_copied_artifact_found_by_where_it_sits_not_by_the_row_that_names_it(
    bundle: Path, tmp_path: Path
) -> None:
    pack = _write_pack(bundle, tmp_path)
    _rewrite_the_copied_report_pack(pack)
    manifest_path = pack / "pack-manifest.json"
    manifest = _json(manifest_path)
    row = next(row for row in manifest["source_artifacts"] if row.get("source_path") == "reports/report-pack.json")
    row["source_path"] = "something/else.json"  # the editable row no longer says which run artifact this is
    _write_json(manifest_path, manifest)

    result = verify_enterprise_handoff_pack(pack)

    assert "source_artifact_bundle_hash_mismatch" in {issue["code"] for issue in result["issues"]}


def test_a_pack_that_claims_no_hash_manifest_for_a_current_run_is_incomplete(bundle: Path, tmp_path: Path) -> None:
    pack = _write_pack(bundle, tmp_path)
    genuine = _digest(bundle)
    (pack / "source-artifacts" / BUNDLE_HASHES_PATH).unlink()
    manifest_path = pack / "pack-manifest.json"
    manifest = _json(manifest_path)
    row = next(row for row in manifest["source_artifacts"] if row.get("source_path") == BUNDLE_HASHES_PATH)
    row.update(present=False)
    row.pop("path", None)
    manifest["source"]["integrity"]["status"] = "absent"
    _write_json(manifest_path, manifest)
    handoff = _json(pack / "handoff.json")
    handoff["integrity"]["status"] = "absent"
    _write_json(pack / "handoff.json", handoff)
    _rehash_pack(pack, "handoff.json")
    lines = [
        line for line in (pack / "checksums.sha256").read_text(encoding="utf-8").splitlines() if BUNDLE_HASHES_PATH not in line
    ]
    (pack / "checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    _rehash_pack(pack)

    without_digest = verify_enterprise_handoff_pack(pack)
    with_digest = verify_enterprise_handoff_pack(pack, expect_manifest_sha256=genuine)

    # The run manifest copy says it was finalized under a contract that writes the file.
    assert "missing_bundle_hashes" in {issue["code"] for issue in without_digest["issues"]}
    assert {"missing_bundle_hashes", "expected_manifest_sha256_mismatch"} <= {issue["code"] for issue in with_digest["issues"]}


def test_a_legacy_pack_without_a_hash_manifest_still_verifies(bundle: Path, tmp_path: Path) -> None:
    (bundle / BUNDLE_HASHES_PATH).unlink()
    manifest = _json(bundle / "run-manifest.json")
    manifest["artifacts"].remove(BUNDLE_HASHES_PATH)
    manifest["schema_contract_version"] = "2026-10-20"
    _write_json(bundle / "run-manifest.json", manifest)

    pack = _write_pack(bundle, tmp_path)

    assert _json(pack / "pack-manifest.json")["source"]["integrity"]["status"] == "absent"
    assert verify_enterprise_handoff_pack(pack)["valid"] is True


# ---- b. a planted SQLite sidecar is never read ---------------------------------------------------------------


def _plant_wal(run_dir: Path, sql: str) -> Path:
    """Put a ``-wal`` file beside the hashed evidence index that changes it, without touching the main file."""
    database = run_dir / "index" / "evidence.sqlite"
    work = run_dir.parent / "wal-work"
    work.mkdir()
    shutil.copy(database, work / database.name)
    connection = sqlite3.connect(work / database.name)
    try:
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute(sql)
        connection.commit()
        planted = run_dir / "index" / (database.name + "-wal")
        shutil.copy(work / (database.name + "-wal"), planted)
    finally:
        connection.close()
    return planted


_PLANTED_DATE = "29991231T235959Z"
_REWRITE_DATE = f"UPDATE run_meta SET value = '{_PLANTED_DATE}' WHERE key = 'created_utc'"


def test_a_planted_wal_sidecar_is_not_read_and_fails_the_hash_check(bundle: Path) -> None:
    honest = load_run_index_summary(bundle)["created_utc"]
    planted = _plant_wal(bundle, _REWRITE_DATE)
    before = (bundle / "index" / "evidence.sqlite").read_bytes()

    assert load_run_index_summary(bundle) == {}
    assert RunBundle(bundle).metadata()["created_utc"] == read_json(bundle / "run-manifest.json")["created_utc"] != _PLANTED_DATE
    assert honest != _PLANTED_DATE
    integrity = verify_bundle_hashes(bundle)
    assert integrity["status"] == "mismatch"
    assert integrity["unexpected"] == ["index/evidence.sqlite-wal"] and integrity["modified"] == []
    # Reading changed nothing: the sidecar is still there, unreplayed, and the hashed file is byte for byte as it was.
    assert planted.exists() and (bundle / "index" / "evidence.sqlite").read_bytes() == before
    assert enterprise_handoff(bundle)["handoff_status"] == "unusable"


def test_a_planted_wal_sidecar_cannot_reverse_a_comparison(pair: tuple[Path, Path]) -> None:
    baseline, current = pair
    write_findings(baseline, [finding("f1", "high")])
    write_findings(current, [finding("f1", "high"), finding("f2", "critical")])
    _plant_wal(baseline, _REWRITE_DATE)  # makes the baseline look like the newest run

    result = compare_runs([baseline, current])

    assert [Path(run["path"]).name for run in result["runs"]] == [baseline.name, current.name]
    assert result["baseline_diff"]["status"] == "blocked"
    assert result["baseline_diff"]["reason"].startswith("run_unverified:baseline:bundle_integrity_mismatch")
    delta = build_finding_delta({"path": str(baseline)}, {"path": str(current)})
    assert delta["resolved"] == [] and delta["verification"]["baseline"]["problem"] == "bundle_integrity_mismatch"


def test_an_evidence_index_is_read_without_creating_a_sidecar_or_write_access(bundle: Path) -> None:
    index = bundle / "index"
    expected = load_run_index_summary(bundle)
    assert expected["section_stats"]
    before = sorted(path.name for path in index.iterdir())
    index.chmod(0o500)
    (index / "evidence.sqlite").chmod(0o400)
    try:
        # A WAL-mode index cannot be opened by a plain connection on read-only media; the consumers can.
        assert load_run_index_summary(bundle) == expected
        assert RunBundle(bundle).metadata()["item_count"] == expected["item_count"]
    finally:
        index.chmod(0o700)
        (index / "evidence.sqlite").chmod(0o600)
    assert sorted(path.name for path in index.iterdir()) == before == ["evidence.sqlite"]


def test_read_only_validation_does_not_read_a_sidecar_beside_a_hashed_index(bundle: Path) -> None:
    expected = build_validation_report(run_dir=bundle, read_only=True)
    assert expected["valid"] is True
    # A sidecar that swaps the run's tenant identity for another one, which validation would flag as a conflict.
    _plant_wal(bundle, "UPDATE run_meta SET value = '11111111-2222-3333-4444-555555555555' WHERE key = 'tenant_id'")

    report = build_validation_report(run_dir=bundle, read_only=True)

    assert report == expected
    assert verify_bundle_hashes(bundle)["status"] == "mismatch"


def test_a_sidecar_beside_an_index_no_hash_manifest_covers_is_still_read(bundle: Path) -> None:
    """A bundle from before the hash manifest may hold committed data in its WAL; that stays readable."""
    (bundle / BUNDLE_HASHES_PATH).unlink()
    _plant_wal(bundle, _REWRITE_DATE)

    assert load_run_index_summary(bundle)["created_utc"] == _PLANTED_DATE


def test_a_gate_blocks_a_run_with_a_planted_sidecar(run_dir: Path) -> None:
    _plant_wal(run_dir, _REWRITE_DATE)

    rc, payload = _main(["gate", str(run_dir), "--fail-on", "low"])

    assert rc == 2 and payload["status"] == "blocked"
    assert payload["code"] in {"bundle_integrity_mismatch", "contract_invalid"}


# ---- c. the emergency-access list is a recorded rule input ----------------------------------------------------


def _staff_group_sample(path: Path) -> Path:
    """A tenant whose only MFA policy covers everyone except the "All Staff" group."""
    sample = json.loads((REPO_ROOT / "examples" / "sample_audit_bundle" / "identity_controls_result.json").read_text(encoding="utf-8"))
    sample["identity"]["groups"]["value"].append({"id": "g-all-staff", "displayName": "All Staff", "groupTypes": []})
    sample["conditional_access"]["conditionalAccessPolicies"]["value"] = [
        {
            "id": "ca-all",
            "displayName": "Require MFA for all users",
            "state": "enabled",
            "conditions": {
                "users": {"includeUsers": ["All"], "excludeGroups": ["g-all-staff"]},
                "applications": {"includeApplications": ["All"]},
                "clientAppTypes": ["all"],
            },
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
        }
    ]
    path.write_text(json.dumps(sample), encoding="utf-8")
    return path


def _break_glass_run(root: Path, name: str, accounts: list[str] | None) -> Path:
    sample = root / "staff-sample.json"
    if not sample.exists():
        _staff_group_sample(sample)
    assert run_offline(sample, root / name, "ci", name, break_glass_accounts=accounts) in (0, 1)
    return root / name / f"ci-{name}"


def test_the_run_manifest_records_the_emergency_access_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUDITEX_BREAK_GLASS_ACCOUNTS", raising=False)
    listed = _break_glass_run(tmp_path, "listed", ["bg2@example.test", "All Staff", "bg2@example.test"])
    unlisted = _break_glass_run(tmp_path, "unlisted", None)

    assert read_json(listed / "run-manifest.json")["rule_parameters"]["break_glass_accounts"] == ["All Staff", "bg2@example.test"]
    assert read_json(unlisted / "run-manifest.json")["rule_parameters"]["break_glass_accounts"] == []
    monkeypatch.setenv("AUDITEX_BREAK_GLASS_ACCOUNTS", "bg1@example.test;All Staff")
    assert effective_rule_parameters()["break_glass_accounts"] == ["All Staff", "bg1@example.test"]
    assert effective_rule_parameters(break_glass_accounts=["z@example.test"])["break_glass_accounts"] == ["z@example.test"]


def test_listing_the_excluded_staff_group_later_does_not_resolve_the_mfa_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AUDITEX_BREAK_GLASS_ACCOUNTS", raising=False)
    before = _break_glass_run(tmp_path, "before", None)
    after = _break_glass_run(tmp_path, "after", ["All Staff"])
    vanished = {"ca.mfa_not_enforced", "ca.admin_mfa_not_enforced"}
    assert vanished <= {row["rule_id"] for row in read_json(before / "findings" / "findings.json")}
    assert not vanished & {row["rule_id"] for row in read_json(after / "findings" / "findings.json")}

    rc, payload = _main(["gate-drift", "--baseline", str(before), "--current", str(after), "--fail-on", "high"])

    assert payload["status"] in {"pass", "fail"}, payload
    assert not vanished & {row["rule_id"] for row in payload["resolved"]}
    reasons = {row["rule_id"]: row["reason"] for row in payload["not_reassessed"]}
    assert {reasons[rule] for rule in vanished} == {"rule_parameters_changed:break_glass_accounts"}
    assert payload["rule_parameters"]["changed"] == [
        {"parameter": "break_glass_accounts", "baseline": [], "current": ["All Staff"]}
    ]
    assert any("emergency-access list" in warning for warning in payload["warnings"])

    delta = build_finding_delta({"path": str(before)}, {"path": str(after)})
    assert not vanished & {row["rule_id"] for row in delta["resolved"]}
    assert {row["rule_id"] for row in delta["not_reassessed"] if row["rule_id"] in vanished} == vanished


def _fixed_sample(path: Path) -> Path:
    """The same tenant after its MFA policy was fixed: it covers everyone, with no exclusion."""
    sample = json.loads(_staff_group_sample(path).read_text(encoding="utf-8"))
    policy = sample["conditional_access"]["conditionalAccessPolicies"]["value"][0]
    policy["conditions"]["users"].pop("excludeGroups")
    path.write_text(json.dumps(sample), encoding="utf-8")
    return path


def test_a_finding_that_was_really_fixed_still_resolves_when_the_list_did_not_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AUDITEX_BREAK_GLASS_ACCOUNTS", raising=False)
    before = _break_glass_run(tmp_path, "before", ["bg@example.test"])
    fixed = _fixed_sample(tmp_path / "fixed-sample.json")
    assert run_offline(fixed, tmp_path / "same", "ci", "same", break_glass_accounts=["BG@example.test"]) in (0, 1)
    assert run_offline(fixed, tmp_path / "other", "ci", "other", break_glass_accounts=["bg@example.test", "All Staff"]) in (0, 1)
    same, other = tmp_path / "same" / "ci-same", tmp_path / "other" / "ci-other"
    mfa = {"ca.mfa_not_enforced", "ca.admin_mfa_not_enforced"}
    assert mfa <= {row["rule_id"] for row in read_json(before / "findings" / "findings.json")}

    resolved = build_finding_delta({"path": str(before)}, {"path": str(same)})
    listed_more = build_finding_delta({"path": str(before)}, {"path": str(other)})

    assert mfa <= {row["rule_id"] for row in resolved["resolved"]}
    assert not mfa & {row["rule_id"] for row in listed_more["resolved"]}
    assert {row["reason"] for row in listed_more["not_reassessed"] if row["rule_id"] in mfa} == {
        "rule_parameters_changed:break_glass_accounts"
    }


@pytest.mark.parametrize(
    ("baseline", "current", "expected"),
    [
        ({"break_glass_accounts": []}, {"break_glass_accounts": ["a"]}, "rule_parameters_changed:break_glass_accounts"),
        ({"break_glass_accounts": ["a"]}, {"break_glass_accounts": []}, "rule_parameters_changed:break_glass_accounts"),
        ({"break_glass_accounts": ["A "]}, {"break_glass_accounts": ["a"]}, None),
        ({"stale_sync_days": 14}, {"break_glass_accounts": []}, "rule_parameters_unrecorded:break_glass_accounts"),
        (None, {"break_glass_accounts": []}, "rule_parameters_unrecorded:break_glass_accounts"),
        ({"break_glass_accounts": []}, {"break_glass_accounts": []}, None),
    ],
)
def test_the_emergency_access_parameter_decides_the_rules_that_read_it(baseline: Any, current: Any, expected: str | None) -> None:
    for rule in (
        "ca.mfa_not_enforced",
        "ca.admin_mfa_not_enforced",
        "ca.admin_mfa_role_set_incomplete",
        "ca.legacy_auth_not_blocked",
        "ca.break_glass_exclusion_missing",
    ):
        assert rule_parameter_gap(rule, baseline, current) == expected
    # A rule outside Conditional Access never reads the list and is unaffected.
    assert rule_parameter_gap("teams.external_federation_open", baseline, current) is None
    assert rule_parameter_gap("identity.global_admin_singleton", baseline, current) is None


# ---- d. an offline replay says it was replayed ------------------------------------------------------------------


def test_a_replay_records_what_it_was_replayed_from(bundle: Path, demo_bundle: Path) -> None:
    manifest = read_json(demo_bundle / "run-manifest.json")
    inventory = read_json(demo_bundle / "api-inventory.json")

    assert manifest["mode"] == "offline"
    assert manifest["replay_source"]["file"] == "demo_tenant.json"
    assert manifest["replay_source"]["sha256"] == hashlib.sha256(DEMO.read_bytes()).hexdigest()
    assert "/" not in manifest["replay_source"]["file"]
    assert inventory["safety"]["observation_basis"] == "offline_replay"
    assert inventory["observed_ledger"]["basis"] == "offline_replay"
    assert inventory["observed_ledger"]["replay"] == {"source_file": "demo_tenant.json", "tenant_contact": False}


def test_a_replay_written_before_the_basis_was_recorded_is_still_called_a_replay(bundle: Path) -> None:
    """Older bundles say ``transport_audit_log`` for a replay; the report never repeats that."""
    inventory = read_json(bundle / "api-inventory.json")
    inventory["safety"]["observation_basis"] = "transport_audit_log"
    inventory["safety"].pop("replay_source", None)
    inventory["observed_ledger"]["basis"] = "transport_audit_log"
    _write_json(bundle / "api-inventory.json", inventory)
    manifest = read_json(bundle / "run-manifest.json")
    manifest.pop("replay_source")
    _write_json(bundle / "run-manifest.json", manifest)
    rehash(bundle)

    text = render_enterprise_handoff_markdown(enterprise_handoff(bundle))

    assert "Read-only: True (replayed from demo_tenant.json, no tenant contact)" in text
    assert "transport audit log" not in text


# ---- e. a current-contract bundle without its hash manifest is missing it, not pre-hashing ---------------------


def _strip_the_hash_manifest(run_dir: Path, *, version: str | None = None) -> None:
    (run_dir / BUNDLE_HASHES_PATH).unlink()
    manifest = _json(run_dir / "run-manifest.json")
    manifest["artifacts"] = [item for item in manifest["artifacts"] if item != BUNDLE_HASHES_PATH]
    if version is not None:
        manifest["schema_contract_version"] = version
    _write_json(run_dir / "run-manifest.json", manifest)


def test_a_current_contract_bundle_without_its_hash_manifest_is_missing_and_unusable(bundle: Path, tmp_path: Path) -> None:
    _strip_the_hash_manifest(bundle)

    integrity = verify_bundle_hashes(bundle)
    handoff = enterprise_handoff(bundle)

    assert integrity["status"] == "invalid" and integrity["manifest_missing"] is True
    assert integrity["manifest_missing_reason"] == "required_by_contract"
    assert "bundle-hashes.json is missing" in integrity["message"] and "2026-10-22" in integrity["message"]
    assert handoff["handoff_status"] == "unusable" and handoff["status_reasons"] == ["bundle_integrity_invalid"]
    assert handoff["integrity"]["manifest_missing"] is True
    assert "finalized before one was written" not in handoff["integrity"]["summary"]
    limit = next(row for row in handoff["limitations"] if row["surface"] == "bundle_integrity")
    assert "is missing" in limit["message"]
    with pytest.raises(BundleIntegrityError) as caught:
        write_enterprise_handoff_pack(bundle, tmp_path / "pack")
    assert caught.value.integrity["status"] == "invalid" and not (tmp_path / "pack").exists()
    assert auditex_cli.main(["report", "customer-pack", str(bundle), "--output-dir", str(tmp_path / "pack")]) == 2


def test_a_bundle_finalized_before_the_hash_manifest_is_still_absent_and_builds_a_pack(bundle: Path, tmp_path: Path) -> None:
    _strip_the_hash_manifest(bundle, version="2026-10-20")

    integrity = verify_bundle_hashes(bundle)

    assert integrity["status"] == "absent" and integrity["manifest_missing"] is False
    assert enterprise_handoff(bundle)["handoff_status"] != "unusable"
    assert write_enterprise_handoff_pack(bundle, tmp_path / "pack")["source"]["integrity"]["status"] == "absent"


def test_compare_does_not_call_a_finding_resolved_in_a_bundle_stripped_of_its_manifest(pair: tuple[Path, Path]) -> None:
    baseline, current = pair
    write_findings(baseline, [finding("f1", "high")])
    write_findings(current, [])
    _strip_the_hash_manifest(current)

    delta = build_finding_delta({"path": str(baseline)}, {"path": str(current)})

    assert delta["resolved"] == []
    assert delta["not_reassessed"][0]["reason"] == "run_unverified:current:bundle_integrity_invalid"


# ---- f. an expired waiver reopens every accepted or closed status ------------------------------------------------


@pytest.mark.parametrize("status", ["closed", "resolved", "accepted_risk", "accepted", "waived"])
def test_an_expired_waiver_fails_the_gate_for_every_accepted_or_closed_status(run_dir: Path, status: str) -> None:
    write_findings(run_dir, [finding("f1", "critical", status=status, waiver=EXPIRED)])

    rc, payload = _main(["gate", str(run_dir), "--fail-on", "high"])

    assert rc == 2 and payload["status"] == "fail"
    assert payload["counts_by_severity"]["critical"] == 1
    assert payload["accepted_count"] == 0 and payload["closed_count"] == 0
    assert payload["expired_waiver_status_count"] == 1 and payload["unbacked_status_count"] == 0
    entry = payload["threshold_findings"][0]
    assert entry["reason"] == ("expired_waiver" if status in {"closed", "resolved"} else "stale_accepted_risk")
    assert entry["expires_on"] == "2020-01-01"
    assert payload["stale_accepted_risk_count_at_or_above_threshold"] == 1
    assert any("waiver that has expired" in warning for warning in payload["warnings"])


def test_a_current_or_undated_waiver_still_closes_and_accepts(run_dir: Path) -> None:
    write_findings(
        run_dir,
        [
            finding("f1", "critical", status="closed", waiver=CURRENT),
            finding("f2", "critical", status="resolved", waiver={"owner": "ciso"}),
            finding("f3", "critical", status="accepted_risk", waiver=CURRENT),
        ],
    )

    rc, payload = _main(["gate", str(run_dir), "--fail-on", "high"])

    assert rc == 0 and payload["closed_count"] == 2 and payload["accepted_count"] == 1
    assert payload["expired_waiver_status_count"] == 0


def test_an_expired_waiver_below_the_threshold_counts_as_open_but_does_not_fail(run_dir: Path) -> None:
    write_findings(run_dir, [finding("f1", "low", status="closed", waiver=EXPIRED)])

    rc, payload = _main(["gate", str(run_dir), "--fail-on", "high"])

    assert rc == 0
    assert payload["counts_by_severity"]["low"] == 1 and payload["closed_count"] == 0


def test_gate_drift_reports_a_closed_status_on_an_expired_waiver_as_open(pair: tuple[Path, Path]) -> None:
    baseline, current = pair
    write_findings(baseline, [])
    write_findings(current, [finding("f1", "critical", status="closed", waiver=EXPIRED)])

    rc, payload = _main(["gate-drift", "--baseline", str(baseline), "--current", str(current), "--fail-on", "high"])

    assert rc == 2 and payload["pass"] is False
    assert payload["new_accepted_count"] == 0
    assert payload["stale_accepted_risk_count_at_or_above_threshold"] == 1
    stale = payload["stale_accepted_risks_at_or_above_threshold"][0]
    assert stale["id"] == "f1" and stale["reason"] == "expired_waiver" and stale["expires_on"] == "2020-01-01"
    assert payload["new_count_at_or_above_threshold"] == 0  # reported once, as a lapsed waiver


def test_gate_drift_reports_an_accepted_risk_whose_waiver_lapsed_once(pair: tuple[Path, Path]) -> None:
    baseline, current = pair
    write_findings(baseline, [finding("f1", "critical", status="accepted_risk", waiver=CURRENT)])
    write_findings(current, [finding("f1", "critical", status="accepted_risk", waiver=EXPIRED)])

    rc, payload = _main(["gate-drift", "--baseline", str(baseline), "--current", str(current), "--fail-on", "high"])

    assert rc == 2
    assert payload["stale_accepted_risk_count_at_or_above_threshold"] == 1
    assert payload["reactivated_count_at_or_above_threshold"] == 0


# ---- g. an expected digest for the gates and compare ---------------------------------------------------------------


def test_the_gate_accepts_the_digest_the_run_was_sent_with(run_dir: Path) -> None:
    digest = _digest(run_dir)

    rc, payload = _main(["gate", str(run_dir), "--fail-on", "low", "--expect-manifest-sha256", digest])
    rc_named, named = _main(["gate", str(run_dir), "--fail-on", "low", "--expect-manifest-sha256", f"{run_dir}={digest.upper()}"])

    assert rc == rc_named == 0
    integrity = payload["contract"]["integrity"]
    assert integrity["expected_manifest_sha256"] == digest and integrity["expected_manifest_sha256_matched"] is True
    assert named["contract"]["integrity"]["expected_manifest_sha256"] == digest


def test_the_gate_blocks_a_run_rewritten_together_with_its_manifest(run_dir: Path) -> None:
    digest = _digest(run_dir)
    write_findings(run_dir, [finding("f1", "critical", status="closed", waiver=CURRENT)])  # rewritten and re-hashed
    assert _main(["gate", str(run_dir), "--fail-on", "low"])[0] == 0  # the editable manifest agrees with the edit

    rc, payload = _main(["gate", str(run_dir), "--fail-on", "low", "--expect-manifest-sha256", digest])

    assert rc == 2 and payload["status"] == "blocked" and payload["code"] == "expected_manifest_sha256_mismatch"
    assert payload["integrity"]["expected_manifest_sha256"] == digest and payload["integrity"]["manifest_sha256"] != digest


def test_the_gate_blocks_a_run_whose_manifest_was_removed_and_whose_contract_version_was_lowered(run_dir: Path) -> None:
    digest = _digest(run_dir)
    _strip_the_hash_manifest(run_dir, version="2026-10-20")  # looks like a bundle from before the manifest existed
    assert _main(["gate", str(run_dir), "--fail-on", "low"])[0] == 0  # only a warning without the digest

    rc, payload = _main(["gate", str(run_dir), "--fail-on", "low", "--expect-manifest-sha256", digest])

    assert rc == 2 and payload["code"] == "expected_manifest_sha256_mismatch"
    assert "missing" in payload["reason"]


def test_gate_drift_checks_the_digest_of_each_run(pair: tuple[Path, Path]) -> None:
    baseline, current = pair
    digests = [f"{run}={_digest(run)}" for run in (baseline, current)]
    argv = ["gate-drift", "--baseline", str(baseline), "--current", str(current), "--fail-on", "high"]

    rc, payload = _main([*argv, "--expect-manifest-sha256", digests[0], "--expect-manifest-sha256", digests[1]])
    assert rc == 0
    assert payload["contract"]["current"]["integrity"]["expected_manifest_sha256_matched"] is True

    write_findings(current, [finding("f1", "low")])  # rewritten with its manifest
    rc, payload = _main([*argv, "--expect-manifest-sha256", digests[0], "--expect-manifest-sha256", digests[1]])
    assert rc == 2 and payload["code"] == "expected_manifest_sha256_mismatch" and "current run" in payload["reason"]

    rc, payload = _main([*argv, "--expect-manifest-sha256", digests[0]])  # only the baseline was pinned
    assert rc == 0


def test_compare_blocks_a_run_that_is_not_the_one_the_digest_names(pair: tuple[Path, Path]) -> None:
    baseline, current = pair
    write_findings(baseline, [finding("f1", "high")])
    write_findings(current, [finding("f1", "high")])
    digests = {str(baseline): _digest(baseline), str(current): _digest(current)}
    assert compare_runs([baseline, current], expect_manifest_sha256=digests)["baseline_diff"]["status"] == "ok"
    write_findings(current, [])  # the later run now lists nothing, and its manifest was re-hashed to say so

    result = compare_runs([baseline, current], expect_manifest_sha256=digests)

    assert result["baseline_diff"]["status"] == "blocked"
    assert result["baseline_diff"]["reason"] == "run_unverified:current:expected_manifest_sha256_mismatch"
    verification = next(run for run in result["runs"] if run["path"] == str(current))["verification"]
    assert verification["problem"] == "expected_manifest_sha256_mismatch" and verification["expected_manifest_sha256_matched"] is False
    delta = build_finding_delta(
        next(run for run in result["runs"] if run["path"] == str(baseline)),
        next(run for run in result["runs"] if run["path"] == str(current)),
    )
    assert delta["resolved"] == [] and delta["not_reassessed"][0]["reason"].startswith("run_unverified:current")


def test_compare_takes_the_digests_on_the_command_line(pair: tuple[Path, Path], capsys: pytest.CaptureFixture[str]) -> None:
    baseline, current = pair
    argv = ["compare", "--run-dir", str(baseline), "--run-dir", str(current)]
    good = [item for run in (baseline, current) for item in ("--expect-manifest-sha256", f"{run}={_digest(run)}")]

    assert auditex_cli.main([*argv, *good]) == 0
    assert json.loads(capsys.readouterr().out)["baseline_diff"]["status"] == "ok"
    bad = ["--expect-manifest-sha256", f"{current}={'0' * 64}"]
    assert auditex_cli.main([*argv, *bad]) == 0
    assert json.loads(capsys.readouterr().out)["baseline_diff"]["reason"] == "run_unverified:current:expected_manifest_sha256_mismatch"


@pytest.mark.parametrize(
    "argv_tail",
    [
        ["--expect-manifest-sha256", "not-a-digest"],
        ["--expect-manifest-sha256", "0" * 63],
        ["--expect-manifest-sha256", "/nowhere/else=" + "0" * 64],
        ["--expect-manifest-sha256", "0" * 64, "--expect-manifest-sha256", "1" * 64],
    ],
)
def test_a_malformed_or_misdirected_digest_is_a_usage_error_never_a_skipped_check(
    run_dir: Path, argv_tail: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as raised:
        auditex_cli.main(["gate", str(run_dir), "--fail-on", "low", *argv_tail])

    assert raised.value.code == 2
    assert "--expect-manifest-sha256" in capsys.readouterr().err


def test_gate_drift_and_compare_need_the_run_named_with_each_digest(pair: tuple[Path, Path], capsys: pytest.CaptureFixture[str]) -> None:
    baseline, current = pair
    for argv in (
        ["gate-drift", "--baseline", str(baseline), "--current", str(current), "--fail-on", "low"],
        ["compare", "--run-dir", str(baseline), "--run-dir", str(current)],
    ):
        with pytest.raises(SystemExit) as raised:
            auditex_cli.main([*argv, "--expect-manifest-sha256", "0" * 64])
        assert raised.value.code == 2
        assert "RUN_DIR=DIGEST" in capsys.readouterr().err


# ---- h. a pack carries no absolute path of the operator's machine, in the run manifest either -----------------------


def test_a_pack_from_a_run_written_with_an_absolute_out_carries_no_local_path(tmp_path: Path) -> None:
    out = tmp_path / "operator" / "outputs"
    assert run_offline(DEMO, out, "halcyon", "abs", auditor_profile="global-reader", plane="inventory") in (0, 1)
    run = out / "halcyon-abs"
    assert str(run) in _json(run / "run-manifest.json")["run_dir"]
    manifest = _json(run / "run-manifest.json")
    manifest["waiver_path"] = str(tmp_path / "operator" / "waivers.json")
    manifest["command_line"] = ["azure-tenant-audit", "--offline", "--out", str(out), "--tenant-name", "halcyon"]
    _write_json(run / "run-manifest.json", manifest)
    rehash(run)

    pack = _write_pack(run, tmp_path)

    for path in pack.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert str(tmp_path) not in text and str(tmp_path.resolve()) not in text, str(path.relative_to(pack))
    copied = _json(pack / "source-artifacts" / "run-manifest.json")
    assert copied["run_dir"] == "halcyon-abs"
    assert copied["waiver_path"] == "<local-path>/waivers.json"
    assert copied["command_line"] == ["azure-tenant-audit", "--offline", "--out", "<local-path>/outputs", "--tenant-name", "halcyon"]
    # Everything else in the run manifest is as the run wrote it.
    assert {key: value for key, value in copied.items() if key not in {"run_dir", "waiver_path", "command_line"}} == {
        key: value for key, value in manifest.items() if key not in {"run_dir", "waiver_path", "command_line"}
    }


def test_the_pack_copy_of_the_run_manifest_is_tied_to_the_run_file_the_manifest_lists(bundle: Path, tmp_path: Path) -> None:
    pack = _write_pack(bundle, tmp_path)
    row = next(
        row for row in _json(pack / "pack-manifest.json")["source_artifacts"] if row.get("source_path") == "run-manifest.json"
    )
    listed = {row["path"]: row["sha256"] for row in _json(bundle / BUNDLE_HASHES_PATH)["artifacts"]}

    assert row["transformed"] == "pack_relative_paths" and row["source_sha256"] == listed["run-manifest.json"]
    assert row["sha256"] != row["source_sha256"]
    result = verify_enterprise_handoff_pack(pack)
    assert result["valid"] is True and result["transformed_source_artifacts"] == ["run-manifest.json"]
    # The other artifacts are copied byte for byte and none claims a transformation.
    others = [item for item in _json(pack / "pack-manifest.json")["source_artifacts"] if item.get("source_path") != "run-manifest.json"]
    assert all("transformed" not in item for item in others)


def test_a_rewritten_run_manifest_copy_that_names_another_source_digest_is_caught(bundle: Path, tmp_path: Path) -> None:
    pack = _write_pack(bundle, tmp_path)
    target = pack / "source-artifacts" / "run-manifest.json"
    document = _json(target)
    document["overall_status"] = "edited"
    _write_json(target, document)
    _rehash_pack(pack, "source-artifacts/run-manifest.json")
    # A copy that does not say it was transformed must match the run's own file.
    manifest_path = pack / "pack-manifest.json"
    manifest = _json(manifest_path)
    row = next(row for row in manifest["source_artifacts"] if row.get("source_path") == "run-manifest.json")
    row.pop("transformed")
    _write_json(manifest_path, manifest)

    result = verify_enterprise_handoff_pack(pack)

    assert "source_artifact_bundle_hash_mismatch" in {issue["code"] for issue in result["issues"]}
    row["transformed"] = "pack_relative_paths"
    row["source_sha256"] = "0" * 64
    _write_json(manifest_path, manifest)
    assert "source_artifact_bundle_hash_mismatch" in {
        issue["code"] for issue in verify_enterprise_handoff_pack(pack)["issues"]
    }


# ---- i. reports placed inside a run are unhashed and say so ---------------------------------------------------------


@pytest.mark.parametrize(
    "relative",
    ["reports/handoff.md", "reports/explorer.html", "reports/rendered-report.md", "reports/rendered-report.sarif.json"],
)
def test_a_report_written_into_the_run_is_listed_as_unhashed_in_the_handoff(bundle: Path, tmp_path: Path, relative: str) -> None:
    baseline = enterprise_handoff(bundle)
    assert not [row for row in baseline["limitations"] if row.get("status") == "unhashed_outputs"]
    (bundle / relative).write_text("assessor-readable report", encoding="utf-8")

    handoff = enterprise_handoff(bundle)

    limit = next(row for row in handoff["limitations"] if row.get("status") == "unhashed_outputs")
    assert limit["surface"] == "bundle_integrity" and limit["paths"] == [relative]
    assert "not in bundle-hashes.json" in limit["message"] and relative in limit["message"]
    assert "not copied into a customer pack" in limit["message"]
    assert handoff["handoff_status"] == "ready_with_limitations" and handoff["integrity"]["status"] == "verified"
    assert f"- bundle_integrity: {limit['message']}" in render_enterprise_handoff_markdown(handoff)
    # The manifest the run was handed over with is untouched, and the pack neither copies nor lists the report.
    assert verify_bundle_hashes(bundle)["manifest_sha256"] == baseline["integrity"]["manifest_sha256"]
    pack = _write_pack(bundle, tmp_path)
    assert not (pack / "source-artifacts" / relative).exists()
    assert relative not in (pack / "checksums.sha256").read_text(encoding="utf-8")


def test_a_run_that_was_never_given_a_report_has_no_unhashed_output_limitation(run_dir: Path) -> None:
    assert not [row for row in enterprise_handoff(run_dir)["limitations"] if row.get("status") == "unhashed_outputs"]


def test_the_gate_still_only_warns_about_a_report_written_into_the_run(run_dir: Path) -> None:
    (run_dir / "reports" / "explorer.html").write_text("<html></html>", encoding="utf-8")

    rc, payload = _main(["gate", str(run_dir), "--fail-on", "low"])

    assert rc == 0 and any("added after finalization" in warning for warning in payload["warnings"])
