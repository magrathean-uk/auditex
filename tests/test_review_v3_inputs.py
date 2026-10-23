"""Rules that passed on missing inputs (review v3 defects 1, 4, 5, 7 and 8).

Each rule here used to read ``pass`` because nothing it reads was there to fail: an empty MFA registration report, an
attack-path graph built from collectors that were partial, a SharePoint rule with no domain list, a sample in which
every sign-in hid its risk, an offline sample that held nothing for a collector. Each now reads ``not_assessed`` with
the reason, and a complete input still reads ``pass`` or ``fail`` as before.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from auditex.compare import reassessment_gap
from auditex.gate import gate_findings
from auditex.google_workspace.run import run_google_offline
from azure_tenant_audit import baselines, cli
from azure_tenant_audit.baselines import rule_inputs_gap
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot
from azure_tenant_audit.offline_replay import absent_section_rows, planned_sections, replay_coverage_rows

from scripted_collectors import (
    REPO_ROOT,
    Scripted,
    control_statuses,
    load,
    ok_step,
    rule_statuses,
    run_scripted,
    sample,
)

AS_OF = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
MFA_RULES = (
    "identity.global_admin_mfa_not_registered",
    "identity.privileged_mfa_not_registered",
    "identity.user_mfa_not_registered",
)


def _admin_set_registry(registration: dict[str, Any]) -> dict[str, Scripted]:
    fixture = sample("admin_set_result.json")
    registry = {name: Scripted(name, ok_step(name, fixture[name])) for name in ("identity", "identity_governance", "licensing")}
    registry["auth_methods"] = Scripted("auth_methods", ok_step("auth_methods", registration))
    return registry


def _reasons(run_dir: Path, rule: str) -> set[str]:
    return {reason for _status, reason in rule_statuses(run_dir)[rule]}


# ---- 1. MFA registration rules judge the directory, not only the rows the report returned ------------------------


@pytest.mark.parametrize("rows", [0, 1], ids=["empty report", "one row"])
def test_a_registration_report_that_does_not_cover_the_directory_does_not_pass_the_mfa_rules(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, rows: int
) -> None:
    fixture = sample("admin_set_result.json")
    registered = fixture["auth_methods"]["userRegistrationDetails"]["value"][:rows]
    registry = _admin_set_registry({"userRegistrationDetails": {"value": registered, "item_count": rows}})

    rc = run_scripted(monkeypatch, tmp_path, registry, "identity,identity_governance,auth_methods,licensing")

    run_dir = tmp_path / "acme-probe"
    assert rc == 0 and load(run_dir / "run-manifest.json")["overall_status"] == "ok"
    # Five Global Administrators, one more administrator and every member user the report has no answer for.
    expected_global_admins = 5 - rows
    assert _reasons(run_dir, "identity.global_admin_mfa_not_registered") == {f"registration_report_incomplete:{expected_global_admins}"}
    for rule in ("identity.privileged_mfa_not_registered", "identity.user_mfa_not_registered", "attack_path.no_mfa_to_tier0"):
        assert all(reason.startswith("registration_report_incomplete:") for reason in _reasons(run_dir, rule)), rule
    for rule in MFA_RULES:
        assert {status for status, _reason in rule_statuses(run_dir)[rule]} == {"not_assessed"}, rule
    # CIS 5.2.3.4 and the Cyber Essentials MFA requirements no longer pass on an empty or partial report.
    assert control_statuses(run_dir, "cis_m365_v7")["5.2.3.4"] == "not_assessed"
    cyber_essentials = control_statuses(run_dir, "cyber_essentials")
    assert cyber_essentials["ce.uac.mfa_cloud_services"] != "pass" and cyber_essentials["ce.uac.mfa_admin_accounts"] != "pass"


def test_a_registration_report_that_covers_everyone_is_judged_as_before(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fixture = sample("admin_set_result.json")
    report = fixture["auth_methods"]["userRegistrationDetails"]["value"]
    # The sample's report omits its two guests, one of whom is an administrator: the report here covers everyone.
    report += [
        {"id": guest, "userPrincipalName": f"{guest}@fabrikam.example", "userType": "guest", "isMfaRegistered": True}
        for guest in ("effadm-guest-01", "effadm-guest-02")
    ]

    rc = run_scripted(
        monkeypatch, tmp_path, _admin_set_registry(fixture["auth_methods"]), "identity,identity_governance,auth_methods,licensing"
    )

    run_dir = tmp_path / "acme-probe"
    assert rc == 0
    for rule in MFA_RULES:
        assert not any(reason.startswith("registration_report_incomplete") for reason in _reasons(run_dir, rule)), rule
    findings = {item["rule_id"] for item in load(run_dir / "findings" / "findings.json")}
    assert "identity.global_admin_mfa_not_registered" in findings


def test_a_row_without_an_mfa_answer_does_not_cover_its_user() -> None:
    snapshot = {
        "users": {"records": [{"id": "u1", "principal_name": "a@x.test", "enabled": True, "user_type": "member"}]},
        "auth_method_registration_objects": {"records": [{"id": "u1", "user_principal_name": "a@x.test", "is_mfa_registered": None}]},
    }

    assert rule_inputs_gap("identity.user_mfa_not_registered", snapshot) == "registration_report_incomplete:1"
    snapshot["auth_method_registration_objects"]["records"][0]["is_mfa_registered"] = True
    assert rule_inputs_gap("identity.user_mfa_not_registered", snapshot) is None
    # A disabled account and a guest are not people the user rule judges.
    snapshot["auth_method_registration_objects"]["records"] = []
    snapshot["users"]["records"] = [
        {"id": "u2", "enabled": False, "user_type": "member"},
        {"id": "u3", "enabled": True, "user_type": "guest"},
    ]
    assert rule_inputs_gap("identity.user_mfa_not_registered", snapshot) is None


def _replay(tmp_path: Path, sample_payload: dict[str, Any], name: str) -> tuple[int, Path]:
    logging.disable(logging.CRITICAL)
    try:
        path = tmp_path / f"{name}-sample.json"
        path.write_text(json.dumps(sample_payload), encoding="utf-8")
        rc = cli.run_offline(path, tmp_path / "out", "ci", name, as_of=AS_OF)
    finally:
        logging.disable(logging.NOTSET)
    return rc, tmp_path / "out" / f"ci-{name}"


@pytest.mark.parametrize("held", [{}, None, []], ids=["empty object", "null", "empty list"])
def test_an_offline_replay_of_an_empty_auth_methods_collector_is_partial_and_not_assessed(tmp_path: Path, held: Any) -> None:
    fixture = sample("admin_set_result.json")
    fixture["auth_methods"] = held

    rc, run_dir = _replay(tmp_path, fixture, "empty")

    assert rc == 1
    assert load(run_dir / "run-manifest.json")["overall_status"] == "partial"
    ledger = {row["collector"]: row["coverage_status"] for row in load(run_dir / "normalized" / "coverage_ledger.json")["records"]}
    assert ledger["auth_methods"] == "partial_success"
    rows = [row for row in load(run_dir / "coverage.json") if row["collector"] == "auth_methods"]
    assert {row["name"] for row in rows} == set(planned_sections("auth_methods"))
    assert {(row["status"], row["error_class"]) for row in rows} == {("failed", "section_absent")}
    assert load(run_dir / "validation.json")["valid"] is True
    for rule in MFA_RULES:
        assert {status for status, _reason in rule_statuses(run_dir)[rule]} == {"not_assessed"}, rule
    assert gate_findings(run_dir=str(run_dir), fail_on="critical")["status"] == "blocked"


def test_an_offline_replay_whose_registration_report_holds_no_rows_covers_nobody(tmp_path: Path) -> None:
    fixture = sample("admin_set_result.json")
    fixture["auth_methods"] = {"userRegistrationDetails": {"value": [], "item_count": 0}}

    rc, run_dir = _replay(tmp_path, fixture, "norows")

    assert rc == 0
    assert _reasons(run_dir, "identity.global_admin_mfa_not_registered") == {"registration_report_incomplete:5"}
    assert control_statuses(run_dir, "cis_m365_v7")["5.2.3.4"] == "not_assessed"


# ---- 4. the attack-path rules need the collectors their graph is built from ---------------------------------------

ATTACK_RULES = ("attack_path.app_owner_to_tier0", "attack_path.privilege_escalation")
GRAPH_COLLECTORS = {"identity", "app_consent", "directory_relationships", "identity_governance"}


def _evaluate(rule: str, complete: set[str], not_applicable: set[str] | None = None) -> dict[str, Any]:
    return baselines._rule_evaluation(rule, {}, {}, complete, None, not_applicable)


@pytest.mark.parametrize("rule", ATTACK_RULES)
def test_an_attack_path_rule_needs_every_collector_its_graph_reads(rule: str) -> None:
    assert _evaluate(rule, set(GRAPH_COLLECTORS))["status"] == "pass"
    for missing in ("identity", "app_consent", "directory_relationships", "identity_governance"):
        result = _evaluate(rule, GRAPH_COLLECTORS - {missing})
        assert result["status"] == "not_assessed" and result["reason"] == f"collector_not_complete:{missing}", (rule, missing)
    # A skipped identity governance collector (no licence for PIM) means no eligibility to read, and is tolerated.
    assert _evaluate(rule, GRAPH_COLLECTORS - {"identity_governance"}, {"identity_governance"})["status"] == "pass"
    # A finding is a failure whatever the inputs.
    assert baselines._rule_evaluation(rule, {rule: ["f1"]}, {}, set())["status"] == "fail"


def test_dropping_a_graph_collector_from_the_demo_tenant_no_longer_turns_its_attack_paths_into_passes(tmp_path: Path) -> None:
    demo = json.loads((REPO_ROOT / "examples" / "demo_tenant" / "demo_tenant.json").read_text(encoding="utf-8"))
    _rc, base = _replay(tmp_path, demo, "demo")
    assert {status for status, _reason in rule_statuses(base)["attack_path.app_owner_to_tier0"]} == {"fail"}

    without = {name: value for name, value in demo.items() if name != "app_consent"}
    _rc, run_dir = _replay(tmp_path, without, "demo-no-consent")

    for rule in ATTACK_RULES:
        ((status, reason),) = rule_statuses(run_dir)[rule]
        assert status == "not_assessed" and "app_consent" in reason.removeprefix("collector_not_complete:").split(","), rule


# ---- 5. sharepoint.external_principal needs the tenant's own domain list -----------------------------------------


def _permission_edge() -> dict[str, Any]:
    return {
        "id": "site-1:perm-2:user", "site_id": "site-1", "site_name": "Executive", "target_type": "user",
        "target_name": "consultant@external.test", "roles": ["write"],
    }


def _sharepoint_snapshot(*domains: dict[str, Any], tenant_name: str = "acme") -> dict[str, Any]:
    return {
        "sharepoint_permission_edges": {"records": [_permission_edge()]},
        "domain_hybrid_objects": {"records": list(domains)},
        "snapshot": {"tenant_name": tenant_name, "run_id": "r", "object_counts": {}},
    }


def test_the_external_principal_rule_is_not_assessed_without_a_domain_list() -> None:
    rule = "sharepoint.external_principal"
    assert rule_inputs_gap(rule, _sharepoint_snapshot()) == "tenant_domains_unknown"
    assert rule_inputs_gap(rule, _sharepoint_snapshot({"id": "contoso.example", "is_verified": False})) == "tenant_domains_unknown"
    assert rule_inputs_gap(rule, _sharepoint_snapshot({"id": "contoso.example", "is_verified": True})) is None
    assert rule_inputs_gap(rule, None) == "inputs_not_available"
    # The rule is gated on the collector that reads the domain list.
    assert baselines.rule_evidence_collectors(rule) == ("sharepoint_access", "domains_hybrid")
    result = baselines._rule_evaluation(rule, {}, {}, {"sharepoint_access"}, _sharepoint_snapshot())
    assert result["status"] == "not_assessed" and result["reason"] == "collector_not_complete:domains_hybrid"
    result = baselines._rule_evaluation(rule, {}, {}, {"sharepoint_access", "domains_hybrid"}, _sharepoint_snapshot())
    assert result["status"] == "not_assessed" and result["reason"] == "tenant_domains_unknown"


def test_the_tenant_name_alone_is_not_a_domain_list() -> None:
    """With no verified domain read, a tenant name that looks like a domain must not make every other domain external."""
    no_list = build_findings([], normalized_snapshot=_sharepoint_snapshot(tenant_name="contoso.example"))
    assert all(item["rule_id"] != "sharepoint.external_principal" for item in no_list)

    with_list = build_findings(
        [], normalized_snapshot=_sharepoint_snapshot({"id": "contoso.example", "is_verified": True}, tenant_name="contoso.example")
    )
    assert [item["rule_id"] for item in with_list if item["rule_id"] == "sharepoint.external_principal"]


def test_a_later_run_whose_domain_read_failed_does_not_resolve_an_external_principal_finding() -> None:
    finding = {"collector": "sharepoint_access", "rule_id": "sharepoint.external_principal"}
    complete = {"complete": True, "status": "complete_exact_scope"}
    with_domains = _sharepoint_snapshot({"id": "contoso.example", "is_verified": True})

    assert reassessment_gap(finding, {"sharepoint_access": complete, "domains_hybrid": complete}, with_domains) is None
    failed = {"complete": False, "status": "partial_success"}
    assert reassessment_gap(finding, {"sharepoint_access": complete, "domains_hybrid": failed}, _sharepoint_snapshot()) == (
        "rule_collector_partial_success:domains_hybrid"
    )
    assert reassessment_gap(finding, {"sharepoint_access": complete, "domains_hybrid": complete}, _sharepoint_snapshot()) == (
        "rule_inputs:tenant_domains_unknown"
    )
    assert reassessment_gap(finding, {"sharepoint_access": complete}, with_domains) == "rule_collector_not_run:domains_hybrid"


def test_dropping_the_domain_read_from_the_demo_tenant_no_longer_flips_the_sharepoint_controls_to_pass(tmp_path: Path) -> None:
    demo = json.loads((REPO_ROOT / "examples" / "demo_tenant" / "demo_tenant.json").read_text(encoding="utf-8"))
    _rc, base = _replay(tmp_path, demo, "demo")
    assert control_statuses(base, "cis_m365_v7")["7.2.3"] == "fail"

    _rc, run_dir = _replay(tmp_path, {name: value for name, value in demo.items() if name != "domains_hybrid"}, "demo-no-domains")

    assert rule_statuses(run_dir)["sharepoint.external_principal"] == {("not_assessed", "collector_not_complete:domains_hybrid")}
    assert control_statuses(run_dir, "cis_m365_v7")["7.2.3"] != "pass"


# ---- 7. a sample in which every sign-in hides its risk judges nothing --------------------------------------------


def _signins(*levels: str) -> dict[str, Any]:
    rows = [
        {"id": f"s{index}", "userPrincipalName": f"u{index}@x.test", "createdDateTime": "2026-10-01T00:00:00Z",
         "riskLevelAggregated": level, "riskLevelDuringSignIn": level, "riskState": "none"}
        for index, level in enumerate(levels)
    ]
    return build_normalized_snapshot(
        tenant_name="acme", run_id="r", collector_payloads={"security": {"signIns": {"value": rows}, "directoryAudits": {"value": []}}}
    )


def test_a_sign_in_sample_in_which_every_risk_is_hidden_is_not_assessed() -> None:
    snapshot = _signins(*["hidden"] * 40)

    assert rule_inputs_gap("security.risky_signin", snapshot) == "risk_detail_hidden"
    result = baselines._rule_evaluation("security.risky_signin", {}, {}, {"security"}, snapshot)
    assert result["status"] == "not_assessed" and result["reason"] == "risk_detail_hidden"
    assert all(item["rule_id"] != "security.risky_signin" for item in build_findings([], normalized_snapshot=snapshot))


def test_a_sign_in_sample_with_visible_risk_is_judged_and_a_finding_still_fails() -> None:
    visible = _signins("hidden", "none", "hidden")
    assert rule_inputs_gap("security.risky_signin", visible) is None
    assert baselines._rule_evaluation("security.risky_signin", {}, {}, {"security"}, visible)["status"] == "pass"
    risky = _signins("hidden", "high")
    assert [item for item in build_findings([], normalized_snapshot=risky) if item["rule_id"] == "security.risky_signin"]
    assert baselines._rule_evaluation("security.risky_signin", {"security.risky_signin": ["f"]}, {}, {"security"}, _signins("hidden"))[
        "status"
    ] == "fail"
    # No sign-in at all is not "hidden risk": the sign-in log rule says so.
    assert rule_inputs_gap("security.risky_signin", _signins()) is None


# ---- 8. an offline replay does not treat a collector that holds nothing as complete -------------------------------


def _google_replay(tmp_path: Path, payload: dict[str, Any], name: str) -> tuple[int, Path]:
    logging.disable(logging.CRITICAL)
    try:
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        rc = run_google_offline(
            sample_path=path, out=tmp_path / "out", tenant_name="g", run_name=name, domain="example.com", customer_id=None
        )
    finally:
        logging.disable(logging.NOTSET)
    return rc, tmp_path / "out" / f"g-{name}"


def _google_sample() -> dict[str, Any]:
    return json.loads((REPO_ROOT / "examples" / "google_workspace_sample.json").read_text(encoding="utf-8"))


def test_a_google_replay_of_an_empty_devices_collector_is_partial_and_does_not_pass_the_aue_rule(tmp_path: Path) -> None:
    _rc, base = _google_replay(tmp_path, _google_sample(), "base")
    assert {status for status, _reason in rule_statuses(base)["google.chromeos_device_past_aue"]} == {"fail"}
    ledger = {row["collector"]: row["coverage_status"] for row in load(base / "normalized" / "coverage_ledger.json")["records"]}
    assert set(ledger.values()) == {"complete_offline_sample"}, "a replay is an offline sample, not an exact-scope read"

    payload = _google_sample()
    payload["google_devices"] = {}
    rc, run_dir = _google_replay(tmp_path, payload, "devices-empty")

    assert rc == 1
    assert load(run_dir / "run-manifest.json")["overall_status"] == "partial"
    ledger = {row["collector"]: row["coverage_status"] for row in load(run_dir / "normalized" / "coverage_ledger.json")["records"]}
    assert ledger["google_devices"] == "partial_success" and ledger["google_devices"] != "complete_exact_scope"
    rows = [row for row in load(run_dir / "coverage.json") if row["collector"] == "google_devices"]
    assert {row["name"] for row in rows} == {"mobileDevices", "chromeosDevices"}
    assert {row["error_class"] for row in rows} == {"section_absent"}
    assert {status for status, _reason in rule_statuses(run_dir)["google.chromeos_device_past_aue"]} == {"not_assessed"}


def test_a_dns_record_with_a_resolver_error_replays_as_a_failed_read(tmp_path: Path) -> None:
    good = {"domain": "good.example", "managed_by_microsoft": False, "resolver_error": None,
            "spf": {"present": True, "all_qualifier": "-", "mechanisms": ["-all"], "multiple_records": False},
            "dmarc": {"present": True, "policy": "reject", "pct": 100, "pct_partial": False,
                      "aggregate_addresses": ["mailto:d@good.example"], "aggregate_addresses_invalid": []},
            "dkim": {"selectors_present": ["selector1"], "selectors_missing": ["selector2"]},
            "mta_sts": {"dns_present": False}, "tls_rpt": {"present": True, "rua": ["mailto:t@good.example"]}, "bimi": {"present": False}}
    bad = {"domain": "bad.example", "managed_by_microsoft": False,
           "resolver_error": "DoH resolver could not answer TXT _dmarc.bad.example: SERVFAIL",
           "spf": {"present": None}, "dmarc": {"present": None},
           "dkim": {"selectors_present": [], "selectors_missing": [], "selectors_unresolved": ["selector1", "selector2"]},
           "mta_sts": {"dns_present": None}, "tls_rpt": {"present": None}, "bimi": {"present": None}}

    def dns(*records: dict[str, Any]) -> dict[str, Any]:
        return {"dns_posture": {"domains": {"value": [{"id": r["domain"], "isVerified": True} for r in records]}, "domainPosture": {"value": list(records)}}}

    rc_good, good_dir = _replay(tmp_path, dns(good), "dns-good")
    rc, run_dir = _replay(tmp_path, dns(good, bad), "dns-bad")

    assert rc_good == 0 and rc == 1
    rows = [row for row in load(run_dir / "coverage.json") if row["collector"] == "dns_posture"]
    assert [(row["name"], row["status"], row["error_class"]) for row in rows] == [("posture:bad.example", "failed", "dns_resolver_error")]
    assert "SERVFAIL" in rows[0]["error"]
    assert load(run_dir / "run-manifest.json")["overall_status"] == "partial"
    assert gate_findings(run_dir=str(good_dir), fail_on="critical")["status"] == "pass"
    assert gate_findings(run_dir=str(run_dir), fail_on="critical")["status"] == "blocked"


def test_absent_section_rows_name_every_planned_section_of_a_collector_that_holds_nothing() -> None:
    planned = planned_sections("auth_methods")
    assert planned, "collector-definitions.json plans the sections of auth_methods"
    for held in ({}, None, [], "x"):
        rows = absent_section_rows("auth_methods", held, planned)
        assert [row["name"] for row in rows] == list(planned)
        assert {(row["status"], row["error_class"], row["type"]) for row in rows} == {("failed", "section_absent", "offline_sample")}
    # Any key is a delivery, including a section that is empty or failed and the older flat shape: not second-guessed.
    for held in ({"userRegistrationDetails": {"value": []}}, {"authenticationMethodsPolicy": {"error": "403"}}, {"value": []}, {"other": 1}):
        assert absent_section_rows("auth_methods", held, planned) == []
    # A collector the definitions do not know is left alone, and so is an offline sample with a resolver-free payload.
    assert absent_section_rows("not_a_collector", {}, planned_sections("not_a_collector")) == []
    assert replay_coverage_rows("dns_posture", {"domainPosture": {"value": [{"domain": "a.example", "resolver_error": None}]}}) == []
