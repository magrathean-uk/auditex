"""SS 2.1 run projection of TargetedUsersCoverage v1 through the real private SensitiveUsers pair.

The bundle's private files and manifest are written by the real writer with the public fixture key, so the real
verifier supplies the snapshot; nothing stubs verification. Synthetic data only.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path

import pytest

from auditex.rule_assessment import canonical
from auditex.scuba_projection import NOT_COLLECTED, Bundle, PrivateSnapshot, project_run, rule_policy_section
from azure_tenant_audit.sensitive_users import BUNDLE_PATH, KEY_PATH, SensitiveUsers
from azure_tenant_audit.value_rules import assess
from azure_tenant_audit.value_rules.defender_targeted_users import BINDING_KEY, COVERAGE_KEY, SensitiveUsersBinding

SS21 = "MS.SECURITYSUITE.2.1v1"
FIXTURES = json.loads(Path("tests/fixtures/targeted-users-coverage-v1.json").read_text())
ADDRESSES = tuple(FIXTURES["addresses"])
KEY = bytes.fromhex(FIXTURES["key_hex"])
DIGEST = FIXTURES["fixture_hmac_sha256"]
CASES = {case["case"]: case for case in FIXTURES["cases"]}
UNUSABLE = {"version": 1, "state": "unusable"}
PRIVATE_ROW = {
    "met_path": "same", "missing_member": "same", "empty_list": "same", "unusable": "same", "over_limit": "same",
    "not_collected": "same", "absent_summary": {"version": 1, "state": "not_collected"},
    "unknown_shape_nonobject": UNUSABLE, "unknown_shape_version": UNUSABLE, "unknown_shape_bad_invariant": UNUSABLE,
    "hmac_mismatch": UNUSABLE, "false_flag_with_unknown_membership": "same",
}


def coverage_bundle(tmp_path, monkeypatch, rows, *, addresses=ADDRESSES, key=KEY, supply=True):
    """Writer-made private pair and manifest, plus healthy constructed Exchange operation envelopes."""
    import secrets
    from azure_tenant_audit.output import AuditWriter

    tmp_path.mkdir(parents=True, exist_ok=True)
    with monkeypatch.context() as patch:
        patch.setattr(secrets, "token_bytes", lambda n: key[:n])
        writer = AuditWriter(tmp_path, "mocktenant", "ss21-coverage")
        if supply:
            writer.write_sensitive_users(SensitiveUsers(addresses))
        writer.write_bundle({"collectors": [], "overall_status": "ok"})
    root = writer.run_dir
    (root / "raw").mkdir(exist_ok=True)
    operations = {"acceptedDomains": [], "antiPhishRules": [], "eopProtectionPolicyRules": [],
                  "atpProtectionPolicyRules": [], "atpPolicyForO365": [], "antiPhishPolicies": deepcopy(rows)}
    (root / "raw/exchange_policy.json").write_text(json.dumps(
        {name: {"value": value, "status": "ok"} for name, value in operations.items()}))
    return root


def private_config(projection):
    return rule_policy_section(projection, SS21, "scuba_config")


def rule_record(projection):
    sections = deepcopy(projection.rule_sections)
    sections["scuba_config"] = private_config(projection)
    return assess(SS21, sections)


def public_text(projection):
    return canonical(projection) + json.dumps([projection.views, projection.report], default=str)


def met_row():
    return deepcopy(CASES["met_path"]["policy_row"])


@pytest.mark.parametrize("name", list(CASES))
def test_fixture_rows_reach_their_cells_through_the_real_private_pair(tmp_path, monkeypatch, name):
    case = CASES[name]
    root = coverage_bundle(tmp_path, monkeypatch, [case["policy_row"]])
    manifest = json.loads((root / "run-manifest.json").read_text())
    assert manifest["operator_inputs"]["sensitive_users"] == {"supplied": True, "count": 2, "hmac_sha256": DIGEST}
    projection = project_run(root)
    (row,) = projection.rule_sections["anti_phish_policies"]
    expected = PRIVATE_ROW[name]
    assert row[COVERAGE_KEY] == (case["policy_row"][COVERAGE_KEY] if expected == "same" else expected)
    assert "TargetedUsersToProtect" not in row
    assert private_config(projection) == {"SecuritySuite": {SS21: {
        "SensitiveUsers": list(ADDRESSES), BINDING_KEY: {"input_count": 2, "input_hmac_sha256": DIGEST}}}}
    record = rule_record(projection)
    assert (record["verdict"], record["cell"]) == (case["expected"]["verdict"], case["expected"]["cell"])
    public = public_text(projection)
    assert DIGEST not in public and COVERAGE_KEY not in public and BINDING_KEY not in public
    if projection["anti_phish_policies"] != NOT_COLLECTED:
        assert all(COVERAGE_KEY not in item for item in projection["anti_phish_policies"])


@pytest.mark.parametrize("variant", ["literal_only", "literal_with_invalid_summary"])
def test_run_projection_never_falls_back_to_literal_targets(tmp_path, monkeypatch, variant):
    literal = {k: v for k, v in met_row().items() if k != COVERAGE_KEY}
    literal["TargetedUsersToProtect"] = [*ADDRESSES, "Target Canary Name", "canary-domain.invalid"]
    if variant == "literal_with_invalid_summary":
        literal[COVERAGE_KEY] = {"version": 2, "state": "known"}
    root = coverage_bundle(tmp_path, monkeypatch, [literal])
    projection = project_run(root)
    (row,) = projection.rule_sections["anti_phish_policies"]
    assert "TargetedUsersToProtect" not in row
    assert row[COVERAGE_KEY] == ({"version": 1, "state": "not_collected"} if variant == "literal_only" else UNUSABLE)
    assert rule_record(projection)["cell"] == "policy_field_unusable"
    public = public_text(projection)
    assert all(value not in public for value in (*ADDRESSES, "Target Canary Name", "canary-domain.invalid"))


def test_missing_private_input_withholds_config_and_unbinds_a_passing_summary(tmp_path, monkeypatch):
    root = coverage_bundle(tmp_path, monkeypatch, [met_row()], supply=False)
    projection = project_run(root)
    assert private_config(projection) == NOT_COLLECTED
    assert projection.rule_sections["anti_phish_policies"][0][COVERAGE_KEY] == UNUSABLE
    record = rule_record(projection)
    assert (record["verdict"], record["cell"]) == ("not_assessed", "section_not_collected")
    assert projection.report["sections"]["scuba_config"]["synthesis"]["policies"][SS21] == "operator_input_required"


@pytest.mark.parametrize("key,addresses", [
    (bytes(range(1, 33)), ADDRESSES),                                        # same list, another run's key
    (KEY, ("carol@example.invalid", "dave@example.invalid")),                 # same size, changed list
    (KEY, ("alice@example.invalid", "bob@example.invalid", "carol@example.invalid")),
], ids=["other-key", "same-size-other-list", "changed-count"])
def test_a_summary_bound_to_other_input_is_unusable(tmp_path, monkeypatch, key, addresses):
    root = coverage_bundle(tmp_path, monkeypatch, [met_row()], key=key, addresses=addresses)
    projection = project_run(root)
    assert projection.rule_sections["anti_phish_policies"][0][COVERAGE_KEY] == UNUSABLE
    assert rule_record(projection)["cell"] == "policy_field_unusable"


def test_private_pair_is_read_once_and_captured_once_for_config_and_coverage(tmp_path, monkeypatch):
    from auditex import scuba_projection as module

    root = coverage_bundle(tmp_path, monkeypatch, [met_row()])
    captures = []
    original_capture = module._capture_sensitive_users
    monkeypatch.setattr(module, "_capture_sensitive_users", lambda run: captures.append(run) or original_capture(run))
    original_open = os.open
    opens = []

    def capture_open(path, flags, *args, **kwargs):
        if Path(path).name in {"sensitive-users.txt", "sensitive-users.key"}:
            opens.append(Path(path).name)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", capture_open)
    projection = module.project_run(root)
    assert opens == ["sensitive-users.txt", "sensitive-users.key"]
    assert len(captures) == 1
    assert projection.rule_sections["anti_phish_policies"][0][COVERAGE_KEY] == CASES["met_path"]["policy_row"][COVERAGE_KEY]
    assert rule_record(projection)["cell"] == "default_qualifies"


@pytest.mark.parametrize("reason", ["oversize", "operator_input_required"])
def test_failed_verification_is_cached_and_shared_by_both_readers(tmp_path, monkeypatch, reason):
    from auditex import scuba_projection as module

    root = coverage_bundle(tmp_path, monkeypatch, [met_row()])
    captures = []
    monkeypatch.setattr(module, "_capture_sensitive_users",
                        lambda run: captures.append(run) or PrivateSnapshot(reason=reason))
    projection = module.project_run(root)
    assert len(captures) == 1
    assert private_config(projection) == NOT_COLLECTED
    assert projection.report["sections"]["scuba_config"]["synthesis"]["policies"][SS21] == reason
    assert projection.rule_sections["anti_phish_policies"][0][COVERAGE_KEY] == UNUSABLE
    assert rule_record(projection)["cell"] == "section_not_collected"


def test_snapshot_survives_bundle_reset_and_is_never_displayed(tmp_path):
    bundle = Bundle(tmp_path, 100, 10_000, 10)
    assert bundle.sensitive_users.binding is None and bundle.sensitive_users.reason == "operator_input_required"
    snapshot = PrivateSnapshot(ADDRESSES, SensitiveUsersBinding(2, DIGEST), None)
    bundle.sensitive_users = snapshot
    bundle.reset()
    assert bundle.sensitive_users is snapshot
    for text in (repr(snapshot), str(snapshot), repr(snapshot.binding), repr(bundle.__dict__)):
        assert DIGEST not in text and all(address not in text for address in ADDRESSES)


@pytest.mark.parametrize("redact", [True, False])
def test_summary_is_stripped_before_shape_budget_and_redaction(tmp_path, monkeypatch, redact):
    from auditex import scuba_projection as module

    root = coverage_bundle(tmp_path, monkeypatch, [met_row(), {**met_row(), "Identity": "Second", "IsDefault": False}])
    seen = []
    for name in ("_seen_shape", "_oversize", "_redact"):
        original = getattr(module, name)

        def guarded(*args, _original=original, **kwargs):
            seen.append(repr(args))
            assert DIGEST not in repr(args) and "'TargetedUsersCoverage'" not in repr(args)
            return _original(*args, **kwargs)

        monkeypatch.setattr(module, name, guarded)
    projection = module.project_run(root, redact=redact)
    assert seen
    rule_rows = projection.rule_sections["anti_phish_policies"]
    assert [row[COVERAGE_KEY]["state"] for row in rule_rows] == ["known", "known"]
    assert DIGEST not in public_text(projection)


def test_assessment_dry_run_and_new_files_never_carry_the_proof(tmp_path, monkeypatch, capsys, caplog):
    from auditex.model_serving import assess_run
    from azure_tenant_audit.scuba_assessment import validate_assessment

    caplog.set_level("DEBUG")
    root = coverage_bundle(tmp_path, monkeypatch, [met_row()])
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = assess_run(root, policies=[SS21])
    validate_assessment(result)
    assert result["policies"][0]["rule_precheck"]["cell"] == "default_qualifies"
    dry = assess_run(root, policies=[SS21], dry_run=True)
    captured = capsys.readouterr()
    text = json.dumps([result, dry], default=str) + captured.out + captured.err + caplog.text
    for token in (DIGEST, COVERAGE_KEY, BINDING_KEY, *ADDRESSES):
        assert token not in text
    for artifact in root.rglob("*"):
        if artifact.is_file() and before.get(artifact) != artifact.read_bytes():
            data = artifact.read_bytes()
            assert DIGEST.encode() not in data and COVERAGE_KEY.encode() not in data, artifact
    for relative in (BUNDLE_PATH, KEY_PATH, "run-manifest.json", "raw/exchange_policy.json"):
        assert before[root / relative] == (root / relative).read_bytes()
