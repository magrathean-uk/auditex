"""GWS ``gws_list_settings`` kind (design M13 8.2, lane L11): Gmail lists and rule states, API controls, system alert rules.

Synthetic data only; every expected value is a literal. The generic replay of ``lists.jsonl`` runs in
``test_gws_value_rules_replay.py``; this file pins the params transcribed from ScubaGoggles v1.1.0 and the cases the
lane names.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from azure_tenant_audit.value_rules import gws
from azure_tenant_audit.value_rules.gws.catalogue import catalogue

ROOT = Path(__file__).resolve().parents[1]
VECTORS = [json.loads(line) for line in
           (ROOT / "tests/fixtures/gws-value-rules/lists.jsonl").read_text(encoding="utf-8").splitlines() if line]
BY_ID = {vector["vector_id"]: vector for vector in VECTORS}
TENANT = {"as_of": "2026-11-25T12:00:00Z", "top_unit": "ou:root", "org_units": {"ou:root": None}, "complete": True}

CHECKS = {
    "GWS.GMAIL.14.1v1": "gmail_ip_allowlist",
    "GWS.GMAIL.17.1v1": "gmail_mail_storage",
    "GWS.GMAIL.18.1v1": "gmail_bypass_domains",
    "GWS.GMAIL.18.2v1": "gmail_warning_domains",
    "GWS.GMAIL.18.3v1": "gmail_hide_warning_all",
    "GWS.COMMONCONTROLS.10.1v1": "api_services_restricted",
    "GWS.COMMONCONTROLS.10.2v1": "api_no_high_risk",
    "GWS.COMMONCONTROLS.13.1v1": "system_alerts_active",
}
# SG:scubagoggles/rego/Commoncontrols.rego:1345-1364 at 08a08ce1.
SERVICE_TO_SCOPE = [
    ["Drive", ["DRIVE_ALL", "DRIVE_HIGH_RISK"]], ["Gmail", ["GMAIL_ALL", "GMAIL_HIGH_RISK"]],
    ["Calendar", ["CALENDAR_ALL"]], ["Contacts", ["CONTACTS_ALL"]], ["Google Workspace Admin", ["GSUITE_ADMIN_ALL"]],
    ["Vault", ["VAULT_ALL"]], ["Cloud Platform", ["CLOUD_PLATFORM"]], ["Cloud Billing", ["CLOUD_BILLING"]],
    ["Cloud Machine Learning", ["CLOUD_ML"]], ["Apps Script API", ["APPS_SCRIPT_API"]],
    ["Apps Script Runtime", ["APPS_SCRIPT_RUNTIME"]], ["Classroom", ["CLASSROOM_ALL", "CLASSROOM_HIGH_RISK"]],
    ["Tasks", ["TASKS"]], ["Groups", ["GROUPS"]], ["Chat", ["CHAT", "CHAT_HIGH_RISK"]], ["Google Sign-in", ["SIGN_IN"]],
    ["Meet", ["MEET"]], ["Cloud Search", ["CLOUD_SEARCH"]]]
# SG:scubagoggles/parsers/system_rules_parser.py:16-114 at 08a08ce1.
ACTIVE_DEFAULTS = [
    "Account suspension warning", "Device compromised", "Domain data export initiated",
    "Gmail potential employee spoofing", "Google Operations", "Government-backed attacks", "Leaked password",
    "Malware message detected post-delivery", "Phishing in inboxes due to bad whitelist",
    "Phishing message detected post-delivery", "Spike in user-reported spam", "SSO profile added",
    "SSO profile updated", "Super admin password reset", "Suspicious device activity", "Suspicious login",
    "Suspicious message reported", "Suspicious programmatic login", "User suspended (Google identity alert)",
    "User suspended due to suspicious activity", "User suspended for spamming through relay",
    "User suspended for spamming", "User-reported phishing"]
INACTIVE_DEFAULTS = [
    "Calendar settings changed", "Drive settings changed", "Email settings changed", "Mobile settings changed",
    "Rate limited recipient", "User granted Admin privilege", "User's Admin privilege revoked"]


def _row(policy_id: str) -> dict:
    return catalogue()["policies"][policy_id]


def _answer(policy_id: str, sections: dict) -> tuple[str, str]:
    record = gws.assess(policy_id, sections)
    return record["verdict"], record["cell"]


def test_rows_name_the_kind_and_check():
    assert {pid: (row["kind"], row["sections"], row["params"]["check"])
            for pid, row in catalogue()["policies"].items() if row["kind"] == "gws_list_settings"} == {
        pid: ("gws_list_settings", ["gws_tenant", "gws_policies"], check) for pid, check in CHECKS.items()}


def test_the_kind_name_is_compound_and_lists_is_not_a_product_field_name():
    # Lead ruling (M13-L11-repair): a single common word such as ``lists`` must not become a product field name
    # that the shareable redaction keeps when a person or group has that name.
    from azure_tenant_audit import output_redaction
    from azure_tenant_audit.value_rules.gws import lists
    assert set(lists.KINDS) == {"gws_list_settings"}
    assert "lists" not in output_redaction._D5_FIELD_NAMES
    assert "gwslistsettings" in output_redaction._D5_FIELD_NAMES


def test_service_to_scope_mapping_is_pinned_with_its_cite():
    params = _row("GWS.COMMONCONTROLS.10.1v1")["params"]
    assert [[entry["name"], entry["scopes"]] for entry in params["values"]] == SERVICE_TO_SCOPE
    assert params["source"] == ["SG:scubagoggles/rego/Commoncontrols.rego:1343-1400"]
    high = _row("GWS.COMMONCONTROLS.10.2v1")["params"]
    assert high["scopes"] == ["DRIVE_HIGH_RISK", "GMAIL_HIGH_RISK", "CLASSROOM_HIGH_RISK", "CHAT_HIGH_RISK"]
    assert [[entry["name"], entry["scopes"]] for entry in high["values"]] == SERVICE_TO_SCOPE
    assert high["source"] == ["SG:scubagoggles/rego/Commoncontrols.rego:1407-1436"]


def test_thirty_system_alert_rules_are_pinned_with_their_defaults_and_cite():
    params = _row("GWS.COMMONCONTROLS.13.1v1")["params"]
    assert [(rule["name"], rule["value"]) for rule in params["rules"]] == (
        [(name, "ACTIVE") for name in ACTIVE_DEFAULTS] + [(name, "INACTIVE") for name in INACTIVE_DEFAULTS])
    assert len(params["rules"]) == 30
    assert params["source"] == ["SG:scubagoggles/rego/Commoncontrols.rego:1706-1741",
                                "SG:scubagoggles/parsers/system_rules_parser.py:16-114"]


@pytest.mark.parametrize(("vector_id", "expected"), [
    # an enabled versus a disabled override rule
    ("lists-g181-not-met", ("not_met", "unit_violates")),
    ("lists-g181-override-disabled", ("met", "no_unit_violates")),
    ("lists-g183-not-met", ("not_met", "unit_violates")),
    ("lists-g183-override-disabled", ("met", "no_unit_violates")),
    # a list with domain entries, enabled and disabled
    ("lists-g182-not-met", ("not_met", "unit_violates")),
    ("lists-g181-list-disabled", ("met", "no_unit_violates")),
    # a missing rule-state entry
    ("lists-g17-rule-state-missing", ("not_assessed", "setting_value_unusable")),
    ("lists-g181-override-state-missing", ("not_assessed", "setting_value_unusable")),
    ("lists-g181-list-state-missing", ("not_assessed", "setting_value_unusable")),
    # 29 of 30 alerts ACTIVE
    ("lists-c131-29-of-30", ("not_met", "unit_violates")),
    # an explicit null flag and an unknown scope group are unknown, never met (lens 2)
    ("lists-g183-null-flag", ("not_assessed", "setting_value_unusable")),
    ("lists-c102-unknown-scope-group", ("not_assessed", "setting_value_unusable")),
    # rule states are the unit's own (lens 3)
    ("lists-g183-sub-ou-state-not-borrowed", ("not_assessed", "setting_value_unusable")),
    # an absent section
    ("lists-g17-absent", ("not_assessed", "setting_absent")),
    ("lists-g181-absent", ("not_assessed", "setting_absent")),
    ("lists-c101-absent", ("not_assessed", "setting_absent")),
    ("lists-c102-absent", ("not_assessed", "setting_absent")),
    ("lists-c131-absent-section", ("not_met", "unit_violates")),
])
def test_named_cases(vector_id, expected):
    vector = BY_ID[vector_id]
    assert _answer(vector["policy"], json.loads(json.dumps(vector["sections"]))) == expected


def test_every_lists_policy_has_the_l07_vector_set():
    cells: dict[str, set[str]] = {}
    for vector in VECTORS:
        cells.setdefault(vector["policy"], set()).add(vector["cell"])
    base = {"no_unit_violates", "unit_violates", "section_not_collected", "policy_read_incomplete",
            "setting_value_unusable"}
    for policy_id, check in CHECKS.items():
        need = set(base)
        if check not in {"gmail_ip_allowlist", "system_alerts_active"}:  # these two have pinned defaults
            need.add("setting_absent")
        if check.startswith("gmail_"):
            need.add("service_off_everywhere")
        assert need <= cells[policy_id], (policy_id, sorted(need - cells[policy_id]))


@pytest.mark.parametrize("vector", [v for v in VECTORS if isinstance(v["sections"].get("gws_policies"), dict)
                                    and isinstance(v["sections"]["gws_policies"].get("policies"), list)],
                         ids=lambda vector: vector["vector_id"])
def test_read_order_never_changes_the_answer(vector):
    sections = json.loads(json.dumps(vector["sections"]))
    sections["gws_policies"]["policies"].reverse()
    assert _answer(vector["policy"], sections) == (vector["verdict"], vector["cell"])


def test_only_the_domain_count_is_read_never_an_address():
    # A list entry carrying an unminimised address payload is judged by its count alone.
    def sections(count):
        return {"gws_tenant": TENANT, "gws_policies": {"complete": True, "policies": [
            {"unit": "ou:root", "unit_kind": "org_unit", "section": section, "sort_order": 1, "value": value}
            for section, value in (
                ("gmail_service_status", {"serviceState": "ENABLED"}),
                ("gmail_rule_states", {"ruleStates": [{"ruleId": "o1", "enabled": True},
                                                      {"ruleId": "l1", "enabled": True}]}),
                ("gmail_email_address_lists", {"emailAddressList": [
                    {"id": "l1", "entry_count": 1, "domain_entry_count": count,
                     "addressList": {"address": [{"address": "example.com"}]}}]}),
                ("gmail_spam_override_lists", {"spamOverride": [
                    {"ruleId": "o1", "bypassSelectedSenders": True, "bypassSenderAllowlist": ["l1"]}]}))]}}
    assert _answer("GWS.GMAIL.18.1v1", sections(0)) == ("met", "no_unit_violates")
    assert _answer("GWS.GMAIL.18.1v1", sections(1)) == ("not_met", "unit_violates")


def test_an_unknown_check_is_a_catalogue_fault():
    from azure_tenant_audit.value_rules.gws import lists
    row = {**_row("GWS.GMAIL.14.1v1"), "params": {"check": "gmail_unknown"}}
    with pytest.raises(ValueError, match="Unknown gws_list_settings check"):
        lists.gws_list_settings("GWS.GMAIL.14.1v1", row, {"gws_tenant": TENANT, "gws_policies": {"complete": True,
                                                                                      "policies": []}})


# Repair round (M13-L11-repair): each case below answered met or not_met on 8ad39720. Malformed, blank,
# inconsistent or unrecognised input never confirms met or not_met.
UNUSABLE = ("not_assessed", "setting_value_unusable")
TWO_OUS = {**TENANT, "org_units": {"ou:root": None, "ou:a": "ou:root"}}


def _sections(rows, tenant=TENANT) -> dict:
    return {"gws_tenant": tenant, "gws_policies": {"complete": True, "policies": [
        {"unit": unit, "unit_kind": "org_unit", "section": section, "sort_order": 1, "value": value}
        for unit, section, value in rows]}}


def _root_off_child_on(*rows) -> dict:
    return _sections([("ou:root", "gmail_service_status", {"serviceState": "DISABLED"}),
                      ("ou:a", "gmail_service_status", {"serviceState": "ENABLED"}), *rows], TWO_OUS)


def test_b1_an_unreadable_root_storage_rule_inherited_by_an_enabled_child_is_unknown():
    assert _answer("GWS.GMAIL.17.1v1", _root_off_child_on(
        ("ou:root", "gmail_comprehensive_mail_storage", None))) == UNUSABLE


@pytest.mark.parametrize("policy_id", ["GWS.GMAIL.18.1v1", "GWS.GMAIL.18.2v1", "GWS.GMAIL.18.3v1"])
def test_b1_an_unreadable_root_override_list_inherited_by_an_enabled_child_is_unknown(policy_id):
    assert _answer(policy_id, _root_off_child_on(("ou:root", "gmail_spam_override_lists", None))) == UNUSABLE


@pytest.mark.parametrize(("enabled", "expected"), [(False, ("not_met", "unit_violates")),
                                                   (True, ("met", "no_unit_violates"))])
def test_b1_the_root_storage_rule_is_judged_for_the_enabled_child_that_inherits_it(enabled, expected):
    assert _answer("GWS.GMAIL.17.1v1", _root_off_child_on(
        ("ou:root", "gmail_comprehensive_mail_storage", {"ruleId": "s1"}),
        ("ou:root", "gmail_rule_states", {"ruleStates": [{"ruleId": "s1", "enabled": enabled}]}))) == expected


def _list_case(policy_id: str, address_list: dict, list_id: str = "l1", override_id: str = "o1") -> dict:
    flags = {"GWS.GMAIL.18.1v1": ("bypassSelectedSenders", "bypassSenderAllowlist"),
             "GWS.GMAIL.18.2v1": ("hideWarningBannerFromSelectedSenders", "hideWarningBannerSenderAllowlist")}
    enable, allow = flags[policy_id]
    return _sections([
        ("ou:root", "gmail_service_status", {"serviceState": "ENABLED"}),
        ("ou:root", "gmail_rule_states", {"ruleStates": [{"ruleId": override_id, "enabled": True},
                                                         {"ruleId": list_id, "enabled": True}]}),
        ("ou:root", "gmail_email_address_lists", {"emailAddressList": [address_list]}),
        ("ou:root", "gmail_spam_override_lists", {"spamOverride": [
            {"ruleId": override_id, enable: True, allow: [list_id]}]})])


@pytest.mark.parametrize("policy_id", ["GWS.GMAIL.18.1v1", "GWS.GMAIL.18.2v1"])
@pytest.mark.parametrize(("entry_count", "domain_entry_count"), [(0, 1), (None, 0), (None, 1), (1, None), (-1, 0)])
def test_b2_impossible_or_unreadable_list_counts_are_unknown(policy_id, entry_count, domain_entry_count):
    entry = {"id": "l1", "entry_count": entry_count, "domain_entry_count": domain_entry_count}
    assert _answer(policy_id, _list_case(policy_id, entry)) == UNUSABLE


@pytest.mark.parametrize("policy_id", ["GWS.GMAIL.18.1v1", "GWS.GMAIL.18.2v1"])
def test_b2_consistent_counts_still_answer(policy_id):
    assert _answer(policy_id, _list_case(policy_id, {"id": "l1", "entry_count": 1, "domain_entry_count": 1})) == (
        "not_met", "unit_violates")
    assert _answer(policy_id, _list_case(policy_id, {"id": "l1", "entry_count": 1, "domain_entry_count": 0})) == (
        "met", "no_unit_violates")


def test_b3_a_blank_override_id_never_joins_a_blank_rule_state():
    assert _answer("GWS.GMAIL.18.3v1", _sections([
        ("ou:root", "gmail_service_status", {"serviceState": "ENABLED"}),
        ("ou:root", "gmail_rule_states", {"ruleStates": [{"ruleId": "", "enabled": True}]}),
        ("ou:root", "gmail_spam_override_lists", {"spamOverride": [
            {"ruleId": "", "hideWarningBannerForAll": True}]})])) == UNUSABLE


@pytest.mark.parametrize("policy_id", ["GWS.GMAIL.18.1v1", "GWS.GMAIL.18.2v1"])
def test_b3_a_blank_list_reference_never_joins_a_blank_list(policy_id):
    sections = _list_case(policy_id, {"id": "", "entry_count": 2, "domain_entry_count": 1}, list_id="")
    assert _answer(policy_id, sections) == UNUSABLE


@pytest.mark.parametrize("policy_id", ["GWS.GMAIL.18.1v1", "GWS.GMAIL.18.2v1"])
def test_b3_a_blank_override_id_is_unknown(policy_id):
    sections = _list_case(policy_id, {"id": "l1", "entry_count": 2, "domain_entry_count": 1}, override_id="")
    assert _answer(policy_id, sections) == UNUSABLE


def _c101(services: list) -> dict:
    return _sections([("ou:root", "api_controls_google_services", {"services": services})])


C101_MET = [{"scopesGroup": scope} for scope in (
    "DRIVE_ALL", "GMAIL_ALL", "CALENDAR_ALL", "CONTACTS_ALL", "GSUITE_ADMIN_ALL", "VAULT_ALL", "CLOUD_PLATFORM",
    "CLOUD_BILLING", "CLOUD_ML", "APPS_SCRIPT_API", "APPS_SCRIPT_RUNTIME", "CLASSROOM_ALL", "TASKS", "GROUPS", "CHAT",
    "SIGN_IN", "MEET", "CLOUD_SEARCH")]


def test_b4_a_malformed_scope_entry_never_confirms_met():
    assert _answer("GWS.COMMONCONTROLS.10.1v1", _c101(C101_MET)) == ("met", "no_unit_violates")
    assert _answer("GWS.COMMONCONTROLS.10.1v1", _c101([*C101_MET, {"scopesGroup": None}])) == UNUSABLE


def test_b4_an_unrecognised_scope_group_never_confirms_not_met():
    services = [{"scopesGroup": "FUTURE_SCOPE"}, *C101_MET[1:]]
    assert _answer("GWS.COMMONCONTROLS.10.1v1", _c101(services)) == UNUSABLE
    # The same uncovered Drive without the unknown spelling stays a readable violation.
    assert _answer("GWS.COMMONCONTROLS.10.1v1", _c101(C101_MET[1:])) == ("not_met", "unit_violates")


def _alerts(rows: list) -> dict:
    return _sections([("ou:root", "rule_system_defined_alerts", row) for row in rows])


ALL_ACTIVE = [{"displayName": name, "state": "ACTIVE"} for name in ACTIVE_DEFAULTS + INACTIVE_DEFAULTS]


@pytest.mark.parametrize("anonymous", [{"displayName": "", "state": "ACTIVE"},
                                       {"displayName": None, "state": "INACTIVE"},
                                       {"state": "ACTIVE"}, "not-an-object"])
def test_b5_an_unidentifiable_alert_row_never_confirms_met(anonymous):
    assert _answer("GWS.COMMONCONTROLS.13.1v1", _alerts(ALL_ACTIVE)) == ("met", "no_unit_violates")
    assert _answer("GWS.COMMONCONTROLS.13.1v1", _alerts([*ALL_ACTIVE, anonymous])) == UNUSABLE


def test_b5_an_unidentifiable_alert_row_alone_never_confirms_not_met():
    assert _answer("GWS.COMMONCONTROLS.13.1v1", _alerts([{"displayName": "", "state": "ACTIVE"}])) == UNUSABLE


def _ip(value) -> dict:
    return _sections([("ou:root", "gmail_service_status", {"serviceState": "ENABLED"}),
                      ("ou:root", "gmail_email_spam_filter_ip_allowlist", value)])


@pytest.mark.parametrize("addresses", [[""], ["invalid"], [" 192.0.2.1"], ["192.0.2.0/33"], ["192.0.2.1", ""]])
def test_b6_a_malformed_ip_address_is_unknown(addresses):
    assert _answer("GWS.GMAIL.14.1v1", _ip({"allowedIpAddresses": addresses})) == UNUSABLE


@pytest.mark.parametrize(("addresses", "expected"), [
    (["192.0.2.1"], ("not_met", "unit_violates")), (["198.51.100.0/24"], ("not_met", "unit_violates")),
    (["2001:db8::/32"], ("not_met", "unit_violates")), ([], ("met", "no_unit_violates"))])
def test_b6_readable_addresses_and_ranges_still_answer(addresses, expected):
    assert _answer("GWS.GMAIL.14.1v1", _ip({"allowedIpAddresses": addresses})) == expected


def test_b6_the_pinned_empty_default_still_satisfies_the_policy():
    assert _answer("GWS.GMAIL.14.1v1", _sections([
        ("ou:root", "gmail_service_status", {"serviceState": "ENABLED"})])) == ("met", "no_unit_violates")


def test_m1_an_unplaceable_address_list_row_never_hides_the_hide_warning_for_all_verdict():
    sections = json.loads(json.dumps(BY_ID["lists-g183-not-met"]["sections"]))
    sections["gws_policies"]["policies"].append(
        {"unit": None, "unit_kind": "org_unit", "section": "gmail_email_address_lists", "sort_order": 1, "value": {}})
    assert _answer("GWS.GMAIL.18.3v1", sections) == ("not_met", "unit_violates")
