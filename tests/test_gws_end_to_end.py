"""Replay the shipped synthetic Workspace sample through the public CLI and SCuBA rules."""
from __future__ import annotations

import json
from pathlib import Path

from auditex import local_answer
from auditex.cli import main
from auditex.reporting import preview_report
from auditex.rule_assessment import assess_run
from azure_tenant_audit.bundle_integrity import verify_bundle_hashes
from azure_tenant_audit.scuba_assessment import validate_assessment, value_rule_verdict

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "google_workspace_sample.json"


def _replay(out: Path, sample: Path = SAMPLE) -> Path:
    assert main(["google", "run", "--offline", "--as-of", "2026-11-11", "--sample", str(sample),
                 "--domain", "example.com", "--tenant-name", "ci", "--run-name", "google", "--out", str(out)]) == 0
    return out / "ci-google"


def test_shipped_google_sample_exercises_every_rule_kind(tmp_path, monkeypatch):
    run = _replay(tmp_path / "runs")
    assert json.loads((run / "validation.json").read_text())["valid"] is True
    assessment = assess_run(run)
    validate_assessment(assessment)
    assert assessment == json.loads((run / "model_assessment.json").read_text())
    by_policy = {row["policy_id"]: row for row in assessment["policies"]}
    assert len(assessment["policies"]) == len(by_policy) == assessment["totals"]["rule_answered"] == 138
    assert {row["reason"] for row in by_policy.values()} == {"rule_precheck"}
    assert all(row["rule_precheck"]["cell"] is not None for row in by_policy.values())
    assert {value_rule_verdict(row) for row in by_policy.values()} == {"met", "not_met", "not_assessed", "not_applicable"}
    assert (assessment["baseline"], assessment["endpoint_host"], assessment["model_name"]) == (
        "cisa-scubagoggles-v1.1.0", "none", "rules-only")
    sections = assessment["projection"]["sections"]
    assert set(sections) == {"gws_tenant", "gws_policies", "gws_setting_events", "gws_dns", "gws_admins", "gws_sso"}
    for section in sections.values():
        assert section["status"] == "projected"
        assert set(section) == {"status", "reason", "source"}

    # One literal answer from each kind, with extra coverage of the disabled service gate.
    for policy, verdict in {
        "GWS.GMAIL.1.1v1": "met",                 # setting
        "GWS.CHAT.1.1v1": "not_applicable",      # setting with a service gate
        "GWS.GMAIL.5.5v1": "met",               # settings_multi
        "GWS.COMMONCONTROLS.1.2v1": "not_met",  # twosv
        "GWS.COMMONCONTROLS.6.1v1": "met",      # admin_sso
        "GWS.COMMONCONTROLS.6.2v1": "not_met",  # super_admin_count
        "GWS.GMAIL.14.1v1": "met",              # gws_list_settings
        "GWS.COMMONCONTROLS.2.1v1": "met",      # setting_event
        "GWS.GMAIL.4.1v1": "not_met",          # gws_dns
        "GWS.CALENDAR.3.2v1": "not_assessed",    # manual_only
    }.items():
        assert value_rule_verdict(by_policy[policy]) == verdict, (policy, by_policy[policy]["rule_precheck"])

    assert verify_bundle_hashes(run)["status"] == "verified"
    report = preview_report(run_dir=str(run), format_name="md", profile="shareable")
    assert "## CISA SCuBA Google Workspace (ScubaGoggles v1.1.0)" in report["content"]
    monkeypatch.setattr(local_answer, "runtime_version", lambda: None)
    assert main(["explain", str(run)]) == 0
    answer = json.loads((run / "local_answer.json").read_text())
    assert answer["status"] == "fixed_text"
    assert verify_bundle_hashes(run)["status"] == "verified"

    for path in run.rglob("*"):
        if path.is_file():
            content = path.read_bytes()
            for needle in (b"discarded-list-entry@example.net", b"v=DMARC1", str(tmp_path).encode()):
                assert needle not in content, path.relative_to(run)


def test_offline_dns_needs_an_explicit_successful_read(tmp_path):
    sample = json.loads(SAMPLE.read_text())
    for domain in sample["google_dns_posture"]["domainPosture"]["value"]:
        del domain["resolver_error"]
    legacy = tmp_path / "sample.json"
    legacy.write_text(json.dumps(sample))
    run = _replay(tmp_path / "runs", legacy)
    [row] = assess_run(run, policies=["GWS.GMAIL.4.1v1"])["policies"]
    assert value_rule_verdict(row) == "not_assessed"
    assert row["rule_precheck"]["reason_code"] == "data_unavailable_dns_read_incomplete"
