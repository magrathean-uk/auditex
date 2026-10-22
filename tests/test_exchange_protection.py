"""Mail protection rules: default malware policy, tenant-wide SMTP AUTH and DKIM signing (no tenant, no PowerShell)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from azure_tenant_audit import exchange_protection as xp
from azure_tenant_audit.adapters.read_guard import check_command, classify_command
from azure_tenant_audit.baselines import build_baseline_alignment, rule_inputs_gap
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot

BLOCKED = {"error": "command_failed:1", "error_class": "command_not_authenticated", "command": "Get-X"}


def _exchange(**sections: Any) -> dict[str, Any]:
    return {"exchange_policy": sections}


def _domains(*names: tuple[str, str]) -> dict[str, Any]:
    return {"value": [{"Name": name.split(".")[0], "DomainName": name, "DomainType": kind, "Default": False} for name, kind in names]}


def _dkim(**states: Any) -> dict[str, Any]:
    return {"value": [{"Domain": domain, "Enabled": enabled, "Status": "Valid"} for domain, enabled in states.items()]}


def _malware(*policies: dict[str, Any]) -> dict[str, Any]:
    return {"value": list(policies)}


DEFAULT_OK = {"Identity": "Default", "Name": "Default", "IsDefault": True, "EnableFileFilter": True, "ZapEnabled": True}


def _snapshot(collectors: dict[str, Any]) -> dict[str, Any]:
    return build_normalized_snapshot(tenant_name="acme", run_id="run-1", collector_payloads=collectors)


def _rules(snapshot: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for item in build_findings([], normalized_snapshot=snapshot):
        result.setdefault(item["rule_id"], []).append(item)
    return result


def _dns(domain: str, selectors: list[str], *, managed: bool = False) -> dict[str, Any]:
    return {"dns_posture": {"domains": {"value": []}, "domainPosture": {"value": [
        {"domain": domain, "managed_by_microsoft": managed, "spf": {"present": True, "all_qualifier": "-"}, "dmarc": {"present": True, "policy": "reject"},
         "dkim": {"selectors_present": selectors, "selectors_missing": [] if selectors else ["selector1", "selector2"]},
         "mta_sts": {"dns_present": True}, "bimi": {"present": False}}]}}}


# ---- the commands -----------------------------------------------------------------------------------------


def test_the_three_commands_are_read_only_get_cmdlets_that_pass_the_shared_guard() -> None:
    commands = dict(ExchangePolicyCollector.command_collectors)
    for name in ("malwareFilterPolicy", "transportConfig", "dkimSigningConfig"):
        classification = classify_command("powershell_graph", commands[name])
        assert classification.read_only, (name, classification.reason)
        assert check_command("powershell_graph", commands[name])[0].startswith("Get-")
    assert commands["malwareFilterPolicy"].startswith("Get-MalwareFilterPolicy |")
    assert commands["transportConfig"].startswith("Get-TransportConfig |")
    assert commands["dkimSigningConfig"].startswith("Get-DkimSigningConfig |")
    # A write cmdlet the remediation text names is refused by the same guard.
    assert not classify_command("powershell_graph", "Set-TransportConfig -SmtpClientAuthenticationDisabled $true").read_only
    assert not classify_command("powershell_graph", "Get-DkimSigningConfig | Set-DkimSigningConfig -Enabled $true").read_only


def test_every_declared_command_is_in_the_collector_definitions_and_the_permission_notes() -> None:
    root = Path(__file__).resolve().parent.parent / "configs"
    definition = json.loads((root / "collector-definitions.json").read_text(encoding="utf-8"))["collectors"]["exchange_policy"]
    permissions = json.loads((root / "collector-permissions.json").read_text(encoding="utf-8"))["collector_permissions"]["exchange_policy"]
    declared = {row["name"]: row["commands"] for row in definition["command_collectors"]}
    for name, command in ExchangePolicyCollector.command_collectors:
        assert name in definition["query_plan"], name
        if name in {"malwareFilterPolicy", "transportConfig", "dkimSigningConfig"}:
            assert declared[name] == [command], name
    for cmdlet in ("Get-MalwareFilterPolicy", "Get-TransportConfig", "Get-DkimSigningConfig"):
        assert cmdlet in permissions["optional_commands"]


# ---- parsing ----------------------------------------------------------------------------------------------


def test_protection_fields_read_booleans_from_their_text_and_leave_other_values_unknown() -> None:
    assert xp.protection_fields("malwareFilterPolicy", {"IsDefault": "True", "EnableFileFilter": False, "ZapEnabled": "maybe"}) == {
        "is_default": True, "enable_file_filter": False, "zap_enabled": None}
    assert xp.protection_fields("transportConfig", {"SmtpClientAuthenticationDisabled": "False"}) == {"smtp_client_auth_disabled": False}
    assert xp.protection_fields("dkimSigningConfig", {"Enabled": True, "Status": "CnameMissing"}) == {"dkim_enabled": True, "dkim_status": "CnameMissing"}
    assert xp.protection_fields("acceptedDomains", {"DomainType": "Authoritative", "Default": True}) == {"domain_type": "Authoritative", "default_domain": True}
    assert xp.protection_fields("transportRules", {"Name": "x"}) == {}


# ---- default malware policy -------------------------------------------------------------------------------


def test_a_default_malware_policy_with_protections_off_is_a_finding() -> None:
    both = _rules(_snapshot(_exchange(malwareFilterPolicy=_malware({**DEFAULT_OK, "EnableFileFilter": False, "ZapEnabled": False}))))
    (item,) = both["exchange.malware_filter_weakened"]
    assert item["id"] == "exchange_policy:malware_filter:default_weakened" and item["severity"] == "high"
    assert item["evidence"]["weaknesses"] == ["common_attachment_filter_off", "zero_hour_auto_purge_off"]
    assert item["collector"] == "exchange_policy" and item["evidence_refs"][0]["artifact_path"] == "normalized/exchange_policy_objects.json"

    one = _rules(_snapshot(_exchange(malwareFilterPolicy=_malware({**DEFAULT_OK, "ZapEnabled": False}))))
    assert one["exchange.malware_filter_weakened"][0]["severity"] == "medium"
    assert one["exchange.malware_filter_weakened"][0]["evidence"]["weaknesses"] == ["zero_hour_auto_purge_off"]


def test_only_the_default_policy_is_judged_and_a_clean_default_is_not_a_finding() -> None:
    custom_weak = {"Identity": "Contractors", "Name": "Contractors", "IsDefault": False, "EnableFileFilter": False, "ZapEnabled": False}
    snapshot = _snapshot(_exchange(malwareFilterPolicy=_malware(DEFAULT_OK, custom_weak)))
    assert "exchange.malware_filter_weakened" not in _rules(snapshot)
    assert rule_inputs_gap("exchange.malware_filter_weakened", snapshot) is None


def test_a_malware_policy_that_cannot_be_judged_is_not_assessed_never_clean() -> None:
    for payload, gap in (
        (BLOCKED, "malwareFilterPolicy_not_read_in_full"),
        (_malware({**DEFAULT_OK, "IsDefault": None}), "default_malware_policy_not_identified"),
        (_malware({"Identity": "Default", "IsDefault": True, "EnableFileFilter": True}), "malware_filter_settings_not_returned"),
    ):
        snapshot = _snapshot(_exchange(malwareFilterPolicy=payload))
        assert "exchange.malware_filter_weakened" not in _rules(snapshot)
        assert rule_inputs_gap("exchange.malware_filter_weakened", snapshot) == gap
    assert rule_inputs_gap("exchange.malware_filter_weakened", _snapshot({})) == "malwareFilterPolicy_not_read_in_full"
    assert rule_inputs_gap("exchange.malware_filter_weakened", None) == "inputs_not_available"
    # One setting known to be off is a finding even when the other was not returned.
    partial = _snapshot(_exchange(malwareFilterPolicy=_malware({"Identity": "Default", "IsDefault": True, "EnableFileFilter": False})))
    assert "exchange.malware_filter_weakened" in _rules(partial)
    assert rule_inputs_gap("exchange.malware_filter_weakened", partial) == "malware_filter_settings_not_returned"


# ---- SMTP AUTH --------------------------------------------------------------------------------------------


def test_smtp_auth_enabled_for_the_tenant_is_a_finding() -> None:
    snapshot = _snapshot(_exchange(transportConfig={"value": [{"SmtpClientAuthenticationDisabled": False}]}))
    (item,) = _rules(snapshot)["exchange.smtp_auth_enabled_tenant_wide"]
    assert item["id"] == "exchange_policy:transport_config:smtp_auth_enabled" and item["severity"] == "medium"
    assert item["returned_value"] is False
    assert rule_inputs_gap("exchange.smtp_auth_enabled_tenant_wide", snapshot) is None

    disabled = _snapshot(_exchange(transportConfig={"value": [{"SmtpClientAuthenticationDisabled": True}]}))
    assert "exchange.smtp_auth_enabled_tenant_wide" not in _rules(disabled)
    assert rule_inputs_gap("exchange.smtp_auth_enabled_tenant_wide", disabled) is None


def test_an_smtp_auth_setting_that_was_not_returned_is_unknown() -> None:
    for payload, gap in (
        (BLOCKED, "transportConfig_not_read_in_full"),
        ({"value": [{}]}, "smtp_auth_setting_not_returned"),
        ({"value": [{"SmtpClientAuthenticationDisabled": None}]}, "smtp_auth_setting_not_returned"),
    ):
        snapshot = _snapshot(_exchange(transportConfig=payload))
        assert "exchange.smtp_auth_enabled_tenant_wide" not in _rules(snapshot)
        assert rule_inputs_gap("exchange.smtp_auth_enabled_tenant_wide", snapshot) == gap


# ---- DKIM signing -----------------------------------------------------------------------------------------


def test_dkim_signing_disabled_for_a_verified_custom_domain_is_a_finding() -> None:
    snapshot = _snapshot(_exchange(
        acceptedDomains=_domains(("contoso.example", "Authoritative"), ("contoso.onmicrosoft.com", "Authoritative"),
                                 ("relay.example", "InternalRelay"), ("ok.example", "Authoritative")),
        dkimSigningConfig=_dkim(**{"contoso.example": False, "contoso.onmicrosoft.com": False, "relay.example": False, "ok.example": True}),
    ))
    items = _rules(snapshot)["exchange.dkim_signing_disabled"]

    # The initial *.onmicrosoft.com domain and a relay domain that Exchange does not own are not judged.
    assert [item["id"] for item in items] == ["exchange_policy:contoso.example:dkim_signing_disabled"]
    assert items[0]["affected_objects"] == ["contoso.example"] and items[0]["severity"] == "medium"
    assert rule_inputs_gap("exchange.dkim_signing_disabled", snapshot) is None


def test_a_domain_the_dns_rule_already_reports_is_left_to_it_and_the_exchange_rule_is_not_assessed() -> None:
    collectors = {
        **_exchange(acceptedDomains=_domains(("contoso.example", "Authoritative")), dkimSigningConfig=_dkim(**{"contoso.example": False})),
        **_dns("contoso.example", []),
    }
    snapshot = _snapshot(collectors)
    rules = _rules(snapshot)

    assert [item["id"] for item in rules["dns_posture.dkim_missing"]] == ["dns_posture:contoso.example:dkim_missing"]
    assert "exchange.dkim_signing_disabled" not in rules, "one gap, one finding"
    # The Exchange rule must not read pass for a domain that has signing off; it defers to the DNS finding.
    assert rule_inputs_gap("exchange.dkim_signing_disabled", snapshot) == "reported_by:dns_posture.dkim_missing"


def test_signing_off_with_selectors_published_is_reported_by_exchange_not_dns() -> None:
    collectors = {
        **_exchange(acceptedDomains=_domains(("contoso.example", "Authoritative")), dkimSigningConfig=_dkim(**{"contoso.example": False})),
        **_dns("contoso.example", ["selector1", "selector2"]),
    }
    rules = _rules(_snapshot(collectors))
    assert "dns_posture.dkim_missing" not in rules
    assert [item["id"] for item in rules["exchange.dkim_signing_disabled"]] == ["exchange_policy:contoso.example:dkim_signing_disabled"]


def test_the_dns_predicate_in_this_module_matches_the_finding_it_mirrors() -> None:
    for domain, selectors, managed in (("a.example", [], False), ("b.example", ["selector1"], False), ("c.example", [], True)):
        collectors = _dns(domain, selectors, managed=managed)
        snapshot = _snapshot(collectors)
        fires = any(item["rule_id"] == "dns_posture.dkim_missing" for item in build_findings([], normalized_snapshot=snapshot))
        (record,) = snapshot["dns_posture_objects"]["records"]
        assert xp.dns_reports_dkim_missing(record) is fires, domain
        assert (domain in xp.dns_dkim_domains(snapshot)) is fires, domain


def test_dkim_state_that_was_not_returned_or_read_is_unknown() -> None:
    domains = _domains(("contoso.example", "Authoritative"))
    cases = {
        "blocked": (_exchange(acceptedDomains=domains, dkimSigningConfig=BLOCKED), "dkimSigningConfig_not_read_in_full"),
        "domains blocked": (_exchange(acceptedDomains=BLOCKED, dkimSigningConfig=_dkim(**{"contoso.example": False})), "acceptedDomains_not_read_in_full"),
        "only the initial domain": (_exchange(acceptedDomains=_domains(("contoso.onmicrosoft.com", "Authoritative")), dkimSigningConfig=_dkim(**{"contoso.onmicrosoft.com": True})), "no_custom_domains"),
        "no signing row for the domain": (_exchange(acceptedDomains=domains, dkimSigningConfig=_dkim(**{"other.example": True})), "dkim_state_not_returned_for_domain"),
        "enabled flag missing": (_exchange(acceptedDomains=domains, dkimSigningConfig={"value": [{"Domain": "contoso.example", "Status": "Valid"}]}), "dkim_state_not_returned_for_domain"),
    }
    for label, (collectors, gap) in cases.items():
        snapshot = _snapshot(collectors)
        assert "exchange.dkim_signing_disabled" not in _rules(snapshot), label
        assert rule_inputs_gap("exchange.dkim_signing_disabled", snapshot) == gap, label


def test_the_rules_are_attributed_to_the_exchange_policy_collector_and_the_cyber_essentials_requirements() -> None:
    complete = _snapshot(_exchange(
        malwareFilterPolicy=_malware(DEFAULT_OK),
        transportConfig={"value": [{"SmtpClientAuthenticationDisabled": True}]},
        acceptedDomains=_domains(("contoso.example", "Authoritative")),
        dkimSigningConfig=_dkim(**{"contoso.example": True}),
    ))
    ledger = [{"collector": "exchange_policy", "coverage_status": "complete_exact_scope"}]
    alignment = build_baseline_alignment([], normalized_snapshot=complete, coverage_ledger=ledger)
    ce = {row["control_id"]: row for row in alignment["frameworks"]["cyber_essentials"]["controls"]}

    antimalware = {item["rule_id"]: item for item in ce["ce.mp.antimalware"]["rule_statuses"]}
    assert antimalware["exchange.malware_filter_weakened"]["status"] == "pass"
    # The requirement is partial: a passing mail rule never lends it a pass.
    assert ce["ce.mp.antimalware"]["requirement_status"] == "partial" and ce["ce.mp.antimalware"]["status"] == "not_assessed"
    smtp = {item["rule_id"]: item for item in ce["ce.sc.saas_configuration"]["rule_statuses"]}
    assert smtp["exchange.smtp_auth_enabled_tenant_wide"]["status"] == "pass"
    assert "exchange.dkim_signing_disabled" in {rule for control in alignment["frameworks"]["cis_m365_v7"]["controls"] for rule in control["rule_ids"]}
    # A run that never collected the commands has no rows to judge: the same rules are not assessed.
    cold = build_baseline_alignment([], normalized_snapshot=_snapshot({}), coverage_ledger=[])
    cold_rows = {row["rule_id"]: row for control in cold["frameworks"]["cis_m365_v7"]["controls"] for row in control["rule_statuses"]}
    assert cold_rows["exchange.dkim_signing_disabled"]["status"] == "not_assessed"
    assert cold_rows["exchange.dkim_signing_disabled"]["reason"] == "dkimSigningConfig_not_read_in_full"


# ---- judged on their own command rows --------------------------------------------------------------------


def _complete_mail_protection() -> dict[str, Any]:
    return _exchange(
        malwareFilterPolicy=_malware(DEFAULT_OK),
        transportConfig={"value": [{"SmtpClientAuthenticationDisabled": True}]},
        acceptedDomains=_domains(("contoso.example", "Authoritative")),
        dkimSigningConfig=_dkim(**{"contoso.example": True}),
    )


def _ledger(**statuses: str) -> list[dict[str, str]]:
    return [{"collector": name, "coverage_status": status} for name, status in statuses.items()]


def test_the_mail_rules_are_judged_even_when_another_exchange_command_was_not_available() -> None:
    # App-only runs never open a Security & Compliance session, so Get-ProtectionAlert always fails and the
    # exchange_policy collector is partial. The three mail protection commands were read in full.
    collectors = {**_complete_mail_protection(), **_dns("contoso.example", ["selector1", "selector2"])}
    collectors["exchange_policy"]["protectionAlerts"] = BLOCKED
    snapshot = _snapshot(collectors)
    ledger = _ledger(exchange_policy="partial_success", dns_posture="complete_exact_scope")
    alignment = build_baseline_alignment([], normalized_snapshot=snapshot, coverage_ledger=ledger)

    rows = {row["rule_id"]: row for framework in alignment["frameworks"].values() for control in framework["controls"] for row in control["rule_statuses"]}
    for rule in ("exchange.malware_filter_weakened", "exchange.smtp_auth_enabled_tenant_wide", "exchange.dkim_signing_disabled"):
        assert rows[rule]["status"] == "pass" and rows[rule]["evaluated"] is True, rule
    # A rule that reads the alert policies is still gated on the collector, which is partial.
    assert rows["detection.no_alert_policies"]["status"] == "not_assessed"
    assert rows["detection.no_alert_policies"]["reason"] == "collector_not_complete:exchange_policy"
    # CIS 2.1.9 and SCuBA MS.EXO.3.1v1 can pass on DNS and Exchange evidence together.
    cis = {control["control_id"]: control for control in alignment["frameworks"]["cis_m365_v7"]["controls"]}["2.1.9"]
    scuba = {control["control_id"]: control for control in alignment["frameworks"]["cisa_scuba"]["controls"]}["MS.EXO.3.1v1"]
    assert cis["status"] == "pass" and scuba["status"] == "pass"
    assert {item["rule_id"] for item in cis["rule_statuses"]} == {"dns_posture.dkim_missing", "exchange.dkim_signing_disabled"}


def test_cis_dkim_no_longer_passes_on_dns_evidence_alone() -> None:
    snapshot = _snapshot(_dns("contoso.example", ["selector1", "selector2"]))
    alignment = build_baseline_alignment([], normalized_snapshot=snapshot, coverage_ledger=_ledger(dns_posture="complete_exact_scope"))
    cis = {control["control_id"]: control for control in alignment["frameworks"]["cis_m365_v7"]["controls"]}["2.1.9"]
    statuses = {item["rule_id"]: item for item in cis["rule_statuses"]}
    assert statuses["dns_posture.dkim_missing"]["status"] == "pass"
    assert statuses["exchange.dkim_signing_disabled"]["status"] == "not_assessed"
    assert statuses["exchange.dkim_signing_disabled"]["reason"] == "dkimSigningConfig_not_read_in_full"
    assert cis["status"] == "not_assessed", "selectors in DNS do not show that Exchange Online signs mail"


def test_a_mail_rule_whose_commands_were_not_read_is_not_assessed_whatever_the_collector_says() -> None:
    snapshot = _snapshot(_exchange(transportConfig=BLOCKED))
    alignment = build_baseline_alignment([], normalized_snapshot=snapshot, coverage_ledger=_ledger(exchange_policy="complete_exact_scope"))
    row = next(
        status
        for control in alignment["frameworks"]["ms_zero_trust"]["controls"]
        for status in control["rule_statuses"]
        if status["rule_id"] == "exchange.smtp_auth_enabled_tenant_wide"
    )
    assert row["status"] == "not_assessed" and row["reason"] == "transportConfig_not_read_in_full"


def test_comparison_reassesses_a_mail_finding_when_its_rows_were_read_in_the_later_run() -> None:
    from auditex.compare import reassessment_gap

    finding = {"collector": "exchange_policy", "rule_id": "exchange.smtp_auth_enabled_tenant_wide"}
    partial = {"exchange_policy": {"complete": False, "status": "partial"}}
    fixed = _snapshot(_exchange(transportConfig={"value": [{"SmtpClientAuthenticationDisabled": True}]}))
    assert reassessment_gap(finding, partial, fixed) is None, "the setting was read and is now off, so the finding is resolved"
    unread = _snapshot(_exchange(transportConfig=BLOCKED))
    assert reassessment_gap(finding, partial, unread) == "rule_inputs:transportConfig_not_read_in_full"
    assert reassessment_gap(finding, {}, fixed) == "collector_not_run"
    # Any other rule of the same collector still needs the collector to have completed.
    other = {"collector": "exchange_policy", "rule_id": "detection.no_alert_policies"}
    assert reassessment_gap(other, partial, fixed) == "collector_partial"


# ---- enumerations and domain objects ---------------------------------------------------------------------


def test_an_accepted_domain_written_with_an_integer_enumeration_is_still_judged() -> None:
    """Exchange Online v3 returns DomainType as an integer and DomainName as an object unless PowerShell is told otherwise."""
    domains = {"value": [
        {"Name": "contoso", "DomainName": {"Domain": "contoso.example", "IncludeSubDomains": False}, "DomainType": 0, "Default": True},
        {"Name": "relay", "DomainName": {"Address": "relay.example"}, "DomainType": 1, "Default": False},
        {"Name": "wrapped", "DomainName": "wrapped.example", "DomainType": {"value": 0, "Value": "Authoritative"}, "Default": False},
        {"Name": "text", "DomainName": "text.example", "DomainType": "0", "Default": False},
        {"Name": "initial", "DomainName": "contoso.onmicrosoft.com", "DomainType": 0, "Default": False},
        {"Name": "unknown", "DomainName": "unknown.example", "DomainType": 7, "Default": False},
    ]}
    snapshot = _snapshot(_exchange(
        acceptedDomains=domains,
        dkimSigningConfig=_dkim(**{"contoso.example": False, "relay.example": False, "wrapped.example": True, "text.example": False,
                                   "contoso.onmicrosoft.com": False, "unknown.example": False}),
    ))
    records = {row["id"]: row for row in snapshot["exchange_policy_objects"]["records"] if row["source_name"] == "acceptedDomains"}

    assert records["contoso"]["domain_name"] == "contoso.example" and records["contoso"]["domain_type"] == "Authoritative"
    assert records["relay"]["domain_type"] == "InternalRelay" and records["relay"]["domain_name"] == "relay.example"
    assert records["wrapped"]["domain_type"] == "Authoritative"
    assert "domain_type" not in records["unknown"], "an enumeration value this tool cannot name is unknown, not Authoritative"
    assert xp.custom_domains(snapshot) == ["contoso.example", "text.example", "wrapped.example"]
    assert [item["id"] for item in _rules(snapshot)["exchange.dkim_signing_disabled"]] == [
        "exchange_policy:contoso.example:dkim_signing_disabled", "exchange_policy:text.example:dkim_signing_disabled"]


def test_the_helpers_read_both_the_integer_and_the_named_form() -> None:
    assert [xp.domain_type_text(value) for value in (0, 1, 2, "Authoritative", " InternalRelay ", {"Value": 2}, 9, True, None, {})] == [
        "Authoritative", "InternalRelay", "ExternalRelay", "Authoritative", "InternalRelay", "ExternalRelay", None, None, None, None]
    assert [xp.domain_text(value) for value in ("a.example", " b.example ", {"Domain": "c.example"}, {"SmtpDomain": {"Address": "d.example"}}, {}, None, 5)] == [
        "a.example", "b.example", "c.example", "d.example", None, None, None]
    assert xp.protection_fields("dkimSigningConfig", {"Enabled": True, "Status": {"Value": "Valid"}})["dkim_status"] == "Valid"


def test_the_json_conversion_asks_for_enumerations_as_strings_where_powershell_can(monkeypatch) -> None:  # noqa: ANN001
    import subprocess
    from types import SimpleNamespace

    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):  # noqa: ANN001, ARG001
        calls.append(list(argv))
        return SimpleNamespace(returncode=0, stdout='[{"DomainType":"Authoritative"}]', stderr="")

    monkeypatch.setattr("azure_tenant_audit.adapters.powershell_graph.shutil.which", lambda name: "/usr/bin/pwsh")
    monkeypatch.setattr(subprocess, "run", fake_run)
    from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter

    command = "Get-AcceptedDomain | Select-Object Name,DomainName,DomainType,Default"
    result = PowerShellGraphAdapter().run(command)

    prepared = calls[0][-1]
    assert result["value"] == [{"DomainType": "Authoritative"}]
    # The switch exists from PowerShell 7.3; the same script falls back to plain ConvertTo-Json where it does not.
    assert prepared == (
        "if ((Get-Command ConvertTo-Json).Parameters.ContainsKey('EnumsAsStrings')) "
        f"{{ {command} | ConvertTo-Json -Depth 20 -Compress -EnumsAsStrings }} else {{ {command} | ConvertTo-Json -Depth 20 -Compress }}"
    )
    # The read guard ran on the caller's command, not on the wrapper, and a write verb is still refused before it runs.
    refused = PowerShellGraphAdapter().run("Set-TransportConfig -SmtpClientAuthenticationDisabled $true")
    assert refused["error_class"] == "command_refused" and len(calls) == 1
