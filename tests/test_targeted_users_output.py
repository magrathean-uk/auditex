"""Shareable boundaries drop TargetedUsersCoverage, its binding and the operator count/HMAC (SS 2.1 section 6).

Field and digest canaries: small counts occur legitimately elsewhere, so count exclusion is checked by field, the
HMAC by exact digest. Local outputs and the local manifest are unchanged.
"""
from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from azure_tenant_audit.output_redaction import (
    PROFILE_CUSTOMER_PACK,
    PROFILE_EXPLAINER,
    PROFILE_LOCAL,
    PROFILE_SHAREABLE,
    redact_output,
    redact_payload,
)

FIXTURES = json.loads(Path("tests/fixtures/targeted-users-coverage-v1.json").read_text())
ADDRESSES = tuple(FIXTURES["addresses"])
KEY = bytes.fromhex(FIXTURES["key_hex"])
DIGEST = FIXTURES["fixture_hmac_sha256"]
CANARY = "c0ffee" + "0" * 57 + "1"
PARTNER = "abcdef" + "1" * 58
KNOWN = {"version": 1, "state": "known", "input_hmac_sha256": CANARY, "input_count": 7,
         "protected_nonempty": True, "missing_count": 3}
SENSITIVE = {"supplied": True, "count": 7, "hmac_sha256": CANARY}
SHAREABLE_PROFILES = (PROFILE_SHAREABLE, PROFILE_CUSTOMER_PACK, PROFILE_EXPLAINER)


def structure():
    return {
        "policies": [{"Identity": "Default", "TargetedUsersCoverage": KNOWN},
                     {"Identity": "Other", "targeted_users_coverage": KNOWN},
                     {"Identity": "Third", "targetedUsersCoverage": [KNOWN, {"version": 1, "state": "unusable"}]}],
        "nested": {"deep": [{"x": {"TARGETED-USERS-COVERAGE": KNOWN, "kept": 1}}]},
        "TargetedUsersCoverageBinding": {"input_count": 7, "input_hmac_sha256": CANARY},
        "scuba_config": {"SecuritySuite": {"MS.SECURITYSUITE.2.1v1": {
            "targeted_users_coverage_binding": {"input_count": 7, "input_hmac_sha256": CANARY}}}},
        "embedded": json.dumps({"rows": [{"TargetedUsersCoverage": KNOWN}],
                                "operator_inputs": {"sensitive_users": SENSITIVE}}),
        "manifest": {"operator_inputs": {"sensitive_users": dict(SENSITIVE),
                                         "partner_domains": {"supplied": True, "count": 4, "hmac_sha256": PARTNER}}},
        "embedded_operator_inputs": {"operator_inputs": json.dumps({"sensitive_users": SENSITIVE}, indent=2)},
        "embedded_sensitive_users": {"OperatorInputs": {"SensitiveUsers": json.dumps(SENSITIVE)}},
        "unrelated": {"count": 7, "sensitive_users": {"count": 7, "supplied": True}, "input_count": 7},
    }


def assert_clean(out):
    text = json.dumps(out)
    assert CANARY not in text
    for name in ("TargetedUsersCoverage", "targeted_users_coverage", "targetedUsersCoverage", "TARGETED-USERS-COVERAGE",
                 "TargetedUsersCoverageBinding", "targeted_users_coverage_binding", "hmac_sha256\": \"c0ffee"):
        assert name not in text
    assert [set(policy) for policy in out["policies"]] == [{"Identity"}, {"Identity"}, {"Identity"}]
    assert out["nested"]["deep"][0]["x"] == {"kept": 1}
    assert "TargetedUsersCoverageBinding" not in out
    assert out["scuba_config"]["SecuritySuite"]["MS.SECURITYSUITE.2.1v1"] == {}
    embedded = json.loads(out["embedded"])
    assert embedded["rows"] == [{}] and embedded["operator_inputs"]["sensitive_users"] == {"supplied": True}
    assert out["manifest"]["operator_inputs"]["sensitive_users"] == {"supplied": True}
    assert out["manifest"]["operator_inputs"]["partner_domains"]["count"] == 4       # outside SS 2.1 scope
    assert json.loads(out["embedded_operator_inputs"]["operator_inputs"])["sensitive_users"] == {"supplied": True}
    assert json.loads(out["embedded_sensitive_users"]["OperatorInputs"]["SensitiveUsers"]) == {"supplied": True}
    assert out["unrelated"] == {"count": 7, "sensitive_users": {"count": 7, "supplied": True}, "input_count": 7}


@pytest.mark.parametrize("profile", SHAREABLE_PROFILES)
def test_structured_and_embedded_exclusions_for_every_redacting_profile(profile):
    value = structure()
    original = deepcopy(value)
    out = redact_output(value, profile=profile)
    assert value == original                     # the input is not mutated
    assert_clean(out)
    assert redact_output(out, profile=profile) == out   # idempotent


def test_local_profile_is_passthrough():
    value = structure()
    assert redact_output(value, profile=PROFILE_LOCAL) is value


def test_rendered_json_text_and_mcp_payloads_are_excluded():
    text = redact_output(json.dumps(structure()), profile=PROFILE_SHAREABLE, markup=True)
    assert CANARY not in text and "TargetedUsersCoverage" not in text
    assert_clean(json.loads(text))
    assert_clean(redact_payload(structure()))


# -- end to end: reports, built-in exports and customer packs ----------------------------------------------
def _private_pair(run_dir):
    private = run_dir / "operator-inputs"
    private.mkdir(mode=0o700, exist_ok=True)
    os.chmod(private, 0o700)
    for name, data in (("sensitive-users.txt", ("\n".join(ADDRESSES) + "\n").encode()), ("sensitive-users.key", KEY)):
        descriptor = os.open(private / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, data)
        finally:
            os.close(descriptor)
    manifest_path = run_dir / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest.setdefault("operator_inputs", {})["sensitive_users"] = {"supplied": True, "count": 2, "hmac_sha256": DIGEST}
    manifest_path.write_text(json.dumps(manifest, indent=2))


def _run(tmp_path):
    from support import RunBundleBuilder, make_contract_valid, write_json

    run_dir = (
        RunBundleBuilder(tmp_path)
        .data_handling({"schema_version": "2026-04-21", "platform": "m365", "read_only": True, "content_reads": False,
                        "write_actions": False, "provider_assertions": {}})
        .api_inventory({"schema_version": "2026-04-21", "platform": "m365",
                        "declared_collectors": [{"collector": "identity"}],
                        "observed_calls": [{"collector": "identity", "endpoint": "/users", "method": "GET"}],
                        "counts": {"observed_calls": 1},
                        "safety": {"read_only": True, "no_content_reads": True, "write_actions": False}})
        .report_pack(
            summary={"tenant_name": "acme", "overall_status": "ok"}, findings=[], evidence_paths=[],
            citations=[{"artifact_path": "summary.json", "reason": "Synthetic summary artifact for pack verification."}],
            citation_summary={"citation_count": 1, "artifact_count": 1, "artifacts": ["summary.json"],
                              "record_key_count": 0, "json_pointer_count": 0, "evidence_missing": False})
        .build()
    )
    _private_pair(run_dir)
    write_json(run_dir / "validation.json", {"schema_version": "2026-04-21", "contract_version": "2026-04-21",
                                             "valid": True, "issue_count": 0, "error_count": 0, "warning_count": 0})
    return make_contract_valid(run_dir)


def _assert_no_digest(paths):
    for path in paths:
        if path.is_file():
            assert DIGEST.encode() not in path.read_bytes(), path


def test_customer_pack_reports_and_exports_drop_the_operator_count_and_hmac(tmp_path, capsys):
    from auditex import cli as auditex_cli
    from auditex.cli import verify_customer_pack
    from auditex.exporters import BUILTIN_EXPORTERS, run_exporter
    from auditex.reporting import render_report

    run_dir = _run(tmp_path)
    local_manifest = (run_dir / "run-manifest.json").read_bytes()
    assert json.loads(local_manifest)["operator_inputs"]["sensitive_users"]["hmac_sha256"] == DIGEST
    pack = tmp_path / "customer-pack"
    assert auditex_cli.main(["report", "customer-pack", str(run_dir), "--output-dir", str(pack)]) == 0
    capsys.readouterr()
    assert verify_customer_pack(str(pack))["valid"] is True
    copied = json.loads((pack / "source-artifacts" / "run-manifest.json").read_text())
    assert copied["operator_inputs"]["sensitive_users"] == {"supplied": True}
    _assert_no_digest(pack.rglob("*"))
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    render_report(run_dir=str(run_dir), format_name="json", output_path=str(outputs / "report.json"), profile=PROFILE_SHAREABLE)
    for name in BUILTIN_EXPORTERS:
        run_exporter(name=name, run_dir=str(run_dir), output_path=str(outputs / f"export.{name}"))
    _assert_no_digest(outputs.rglob("*"))
    assert (run_dir / "run-manifest.json").read_bytes() == local_manifest      # local evidence unchanged
