"""Finding and policy ids that contain a credential word survive every redaction profile.

Reproduces the demo-bundle failure: the report-pack profile read ``password:`` inside
``identity:global_admin_stale_password:<guid>`` as a ``password: <value>`` assignment and wrote
``identity:global_admin_stale_password:***redacted***``, so ``findings.json`` and ``report-pack.json`` disagreed.
Real credentials in the same text are still redacted. Every identifier is synthetic.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditex.reporting import FORMAT_EXTENSIONS, render_report
from azure_tenant_audit import output_redaction as orx
from azure_tenant_audit.output import AuditWriter
from azure_tenant_audit.output_redaction import (
    PROFILE_CUSTOMER_PACK,
    PROFILE_EXPLAINER,
    PROFILE_REPORT_PACK,
    PROFILE_SHAREABLE,
    RedactionContext,
    redact_output,
)

PLACEHOLDER = orx.SECRET_PLACEHOLDER
GUID = "3f2b8c1e-5a6d-4e7f-9a1b-2c3d4e5f6a7b"
PROFILES = [PROFILE_REPORT_PACK, PROFILE_SHAREABLE, PROFILE_CUSTOMER_PACK, PROFILE_EXPLAINER]
CONTEXT = RedactionContext(salt="s")
# Ids with a credential word in the name part: the GUID suffix the findings engine appends, a hex digest, none.
# Only a known finding namespace with a GUID, hex digest or number suffix is exempt (see the third-round tests).
HEX = "ab" * 16
IDS = [
    f"identity:global_admin_stale_password:{GUID}",
    f"identity:app_secret_expiring:{GUID}",
    f"identity:service_principal_token_lifetime:{GUID}",
    f"identity:api_key_without_rotation:{GUID}",
    "intune:compliance_policy:windows10",
    "identity:stale_password_policy",
    f"identity:global_admin_stale_password:{HEX}",
]
REAL = [
    ("password: hunter2", "hunter2"),
    ("password=hunter2", "hunter2"),
    ("db_password=hunter2", "hunter2"),
    ('"client_secret": "hunter2"', "hunter2"),
    ("secret:hunter_2", "hunter_2"),
    ("password:hunter_2", "hunter_2"),
    ("identity:db_password:Hunter2", "Hunter2"),
    ("identity:db_password:hunter", "hunter"),
    ("identity:global_admin_stale_password:windows", "windows"),
    ("access_token=abc.def", "abc.def"),
    ("password=identity:global_admin_stale_password:" + GUID, GUID),
]


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("finding_id", IDS)
def test_an_id_with_a_credential_word_survives_as_a_value_a_key_and_in_free_text(profile: str, finding_id: str) -> None:
    out = redact_output(
        {"id": finding_id, "title": f"See {finding_id}, then {finding_id}.", "refs": [finding_id], finding_id: 1},
        profile=profile,
        context=CONTEXT,
    )
    keeps_guid = profile == PROFILE_REPORT_PACK
    expected = finding_id if keeps_guid or GUID not in finding_id else finding_id.replace(GUID, "")
    for text in (out["id"], out["title"], out["refs"][0], next(k for k in out if k not in {"id", "title", "refs"})):
        assert PLACEHOLDER not in text and "redacted" not in text
        assert finding_id.split(GUID)[0] in text or expected in text
    if keeps_guid or GUID not in finding_id:
        assert out["id"] == finding_id and out["refs"] == [finding_id] and finding_id in out
        assert out["title"] == f"See {finding_id}, then {finding_id}."
    assert redact_output(out, profile=profile, context=CONTEXT) == out  # idempotent


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("markup", [False, True])
def test_the_report_pack_ids_survive_the_serialised_text_pass_too(profile: str, markup: bool) -> None:
    text = json.dumps({"findings": [{"id": IDS[0], "rule_id": "identity.global_admin_stale_password"}]}, indent=2)
    out = redact_output(text, profile=profile, context=CONTEXT, markup=markup)
    assert "stale_password" in out and PLACEHOLDER not in out
    assert json.loads(out)["findings"][0]["rule_id"] == "identity.global_admin_stale_password"


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize(("text", "secret"), REAL)
def test_real_credentials_are_still_redacted(profile: str, text: str, secret: str) -> None:
    out = redact_output(f"note {text} end", profile=profile, context=CONTEXT)
    assert secret not in out, (profile, text, out)
    assert PLACEHOLDER in out


@pytest.mark.parametrize("profile", PROFILES)
def test_an_id_and_a_credential_in_the_same_sentence_are_handled_independently(profile: str) -> None:
    out = redact_output(f"{IDS[4]} and {IDS[6]} but password: hunter2, and ({IDS[2]}) token=ok", profile=profile, context=CONTEXT)
    assert "hunter2" not in out and "intune:compliance_policy:windows10" in out
    assert IDS[6] in out and PLACEHOLDER not in out.replace("password: " + PLACEHOLDER, "")
    # a credential that follows an id inside one whitespace-free run is still found
    tail = redact_output(f"{IDS[6]}&client_secret=hunter2", profile=profile, context=CONTEXT)
    assert "hunter2" not in tail and IDS[6] in tail


def test_the_report_pack_writer_keeps_the_finding_id_so_the_files_agree(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, "ids", "w")
    findings = [
        {"id": finding_id, "rule_id": "identity.global_admin_stale_password", "evidence": f"password: hunter2 {finding_id}", "verdict": "fail"}
        for finding_id in IDS
    ]
    findings_path = writer.write_findings(findings)
    pack_path = writer.write_report_pack({"findings": findings, "action_plan": [{"id": IDS[0], "title": "rotate"}]})
    written_findings = json.loads(findings_path.read_text(encoding="utf-8"))
    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    assert [row["id"] for row in pack["findings"]] == [row["id"] for row in written_findings] == IDS
    assert json.loads((pack_path.parent / "action-plan.json").read_text(encoding="utf-8"))[0]["id"] == IDS[0]
    assert "hunter2" not in pack_path.read_text(encoding="utf-8")


@pytest.fixture
def run_with_ids(tmp_path: Path) -> Path:
    run = tmp_path / "ids-run"
    (run / "reports").mkdir(parents=True)
    (run / "normalized").mkdir()
    (run / "run-manifest.json").write_text(json.dumps({"run_id": "run", "tenant_name": "t", "run_dir": str(run)}), encoding="utf-8")
    (run / "summary.json").write_text(json.dumps({"tenant_name": "t", "overall_status": "ok"}), encoding="utf-8")
    findings = [
        {
            "id": finding_id,
            "title": f"Check {finding_id}",
            "severity": "high",
            "status": "open",
            "rule_id": "identity.global_admin_stale_password",
            "collector": "identity",
            "verdict": "fail",
            "reason_code": "not_collected",
            "affected_objects": [finding_id],
            "impact": "The stale credential is weak; password: hunter2",
            "remediation": "Rotate it.",
            "expected_value": "rotated",
            "evidence": {"setting": "PasswordPolicy"},
        }
        for finding_id in IDS
    ]
    pack = {"findings": findings, "summary": {"tenant_name": "t", "overall_status": "ok", "finding_count": len(findings)}, "action_plan": [], "proof_table": []}
    (run / "reports" / "report-pack.json").write_text(json.dumps(pack), encoding="utf-8")
    return run


@pytest.mark.parametrize("format_name", sorted(FORMAT_EXTENSIONS))
def test_every_report_format_keeps_ids_with_a_credential_word(run_with_ids: Path, tmp_path: Path, format_name: str) -> None:
    target = tmp_path / f"out{FORMAT_EXTENSIONS[format_name]}"
    render_report(run_dir=str(run_with_ids), format_name=format_name, output_path=str(target))
    written = target.read_text(encoding="utf-8")
    assert "hunter2" not in written
    for finding_id in IDS:
        if GUID in finding_id:
            # the shareable profiles pseudonymise the GUID; the readable part of the id must stay
            assert finding_id.split(GUID)[0] in written, (format_name, finding_id)
        else:
            assert finding_id in written, (format_name, finding_id)
    assert f"stale_password:{PLACEHOLDER}" not in written and f"password:{PLACEHOLDER}" not in written
