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


# Review round 2 (M13-L11-repair 2). Each B-test below failed on 97222383.
MET = ("met", "no_unit_violates")
NOT_MET = ("not_met", "unit_violates")
ABSENT = ("not_assessed", "setting_absent")
DROP = object()  # leaves the section, field or entry out
KEEP = object()  # the clean baseline value


def _gmail(*extra, **values) -> dict:
    """Gmail on at the top unit plus the named ``gmail_*`` sections at the top unit; ``DROP`` leaves one out."""
    rows = [("ou:root", "gmail_service_status", {"serviceState": "ENABLED"})]
    rows += [("ou:root", f"gmail_{name}", value) for name, value in values.items() if value is not DROP]
    return _sections([*rows, *extra])


def _states(*entries) -> dict:
    return {"ruleStates": [entry for entry in entries if entry is not DROP]}


def _state(rule_id, enabled=True) -> dict:
    return {"ruleId": rule_id} if enabled is DROP else {"ruleId": rule_id, "enabled": enabled}


def _g17(violating, *, storage=KEEP, states=KEEP, extra=()) -> dict:
    storage = {"ruleId": "s1"} if storage is KEEP else storage
    states = _states(_state("s1", not violating)) if states is KEEP else states
    return _gmail(*extra, comprehensive_mail_storage=storage, rule_states=states)


def _g183(violating, *, override=KEEP, overrides=KEEP, states=KEEP) -> dict:
    override = {"ruleId": "o1", "hideWarningBannerForAll": violating} if override is KEEP else override
    overrides = {"spamOverride": [override]} if overrides is KEEP else overrides
    states = _states(_state("o1")) if states is KEEP else states
    return _gmail(spam_override_lists=overrides, rule_states=states)


_LIST_FIELDS = {"GWS.GMAIL.18.1v1": ("bypassSelectedSenders", "bypassSenderAllowlist"),
                "GWS.GMAIL.18.2v1": ("hideWarningBannerFromSelectedSenders", "hideWarningBannerSenderAllowlist")}


def _g18l(policy_id, violating, *, entry=KEEP, lists=KEEP, override=KEEP, overrides=KEEP, states=KEEP,
          extra=()) -> dict:
    """An enabled override ``o1`` with its flag on, naming the enabled list ``l1``; ``violating`` puts a domain
    entry in ``l1``. Each keyword replaces one input."""
    enable, allow = _LIST_FIELDS[policy_id]
    entry = {"id": "l1", "entry_count": 1, "domain_entry_count": 1 if violating else 0} if entry is KEEP else entry
    lists = {"emailAddressList": [entry]} if lists is KEEP else lists
    override = {"ruleId": "o1", enable: True, allow: ["l1"]} if override is KEEP else override
    overrides = {"spamOverride": [override]} if overrides is KEEP else overrides
    states = _states(_state("o1"), _state("l1")) if states is KEEP else states
    return _gmail(*extra, email_address_lists=lists, spam_override_lists=overrides, rule_states=states)


def _without(mapping: dict, key: str) -> dict:
    return {name: value for name, value in mapping.items() if name != key}


@pytest.mark.parametrize("violating", [False, True])
@pytest.mark.parametrize("enabled", [1, 0, 1.0, 0.0, [], {}])
def test_round2_b1_a_wrong_typed_storage_rule_state_is_unknown(enabled, violating):
    assert _answer("GWS.GMAIL.17.1v1", _g17(violating, states=_states(_state("s1", enabled)))) == UNUSABLE


@pytest.mark.parametrize("policy_id", ["GWS.GMAIL.18.1v1", "GWS.GMAIL.18.2v1"])
@pytest.mark.parametrize("enabled", [1, 0, 1.0, 0.0, [], {}])
def test_round2_b1_a_wrong_typed_list_or_override_state_is_unknown(policy_id, enabled):
    assert _answer(policy_id, _g18l(policy_id, True, states=_states(_state("o1"), _state("l1", enabled)))) == UNUSABLE
    assert _answer(policy_id, _g18l(policy_id, True, states=_states(_state("o1", enabled), _state("l1")))) == UNUSABLE


def test_round2_b2_a_child_only_storage_rule_with_no_root_setting_is_absent():
    assert _answer("GWS.GMAIL.17.1v1", _root_off_child_on(
        ("ou:a", "gmail_comprehensive_mail_storage", {"ruleId": "s1"}),
        ("ou:a", "gmail_rule_states", {"ruleStates": [{"ruleId": "s1", "enabled": True}]}))) == ABSENT


@pytest.mark.parametrize("policy_id", ["GWS.GMAIL.18.1v1", "GWS.GMAIL.18.2v1", "GWS.GMAIL.18.3v1"])
def test_round2_b2_a_child_only_override_list_with_no_root_setting_is_absent(policy_id):
    assert _answer(policy_id, _root_off_child_on(
        ("ou:a", "gmail_spam_override_lists", {"spamOverride": []}))) == ABSENT


def test_round2_b2_a_child_violation_still_wins_over_an_absent_root_setting():
    assert _answer("GWS.GMAIL.17.1v1", _root_off_child_on(
        ("ou:a", "gmail_comprehensive_mail_storage", {"ruleId": "s1"}),
        ("ou:a", "gmail_rule_states", {"ruleStates": [{"ruleId": "s1", "enabled": False}]}))) == NOT_MET


@pytest.mark.parametrize("policy_id", ["GWS.GMAIL.18.1v1", "GWS.GMAIL.18.2v1"])
@pytest.mark.parametrize(("violating", "expected"), [(True, NOT_MET), (False, MET)])
def test_round2_b3_integer_list_ids_keep_their_verdict(policy_id, violating, expected):
    enable, allow = _LIST_FIELDS[policy_id]
    sections = _g18l(policy_id, violating,
                     entry={"id": 42, "entry_count": 1, "domain_entry_count": 1 if violating else 0},
                     override={"ruleId": "o1", enable: True, allow: [42]},
                     states=_states(_state("o1"), _state(42)))
    assert _answer(policy_id, sections) == expected


@pytest.mark.parametrize(("violating", "expected"), [(True, NOT_MET), (False, MET)])
def test_round2_b3_an_integer_keyed_state_never_hides_an_unrelated_override(violating, expected):
    assert _answer("GWS.GMAIL.18.3v1", _g183(violating, states=_states(_state("o1"), _state(42)))) == expected


@pytest.mark.parametrize("violating", [False, True])
def test_round3_m2_a_numeric_storage_or_override_rule_id_confirms_nothing(violating):
    assert _answer("GWS.GMAIL.17.1v1", _g17(violating, storage={"ruleId": 7},
                                            states=_states(_state(7, not violating)))) == UNUSABLE
    assert _answer("GWS.GMAIL.18.3v1", _g183(violating, override={"ruleId": 5, "hideWarningBannerForAll": violating},
                                             states=_states(_state(5)))) == UNUSABLE


@pytest.mark.parametrize("policy_id", ["GWS.GMAIL.18.1v1", "GWS.GMAIL.18.2v1"])
@pytest.mark.parametrize("violating", [False, True])
def test_round3_m2_a_numeric_override_rule_id_on_a_list_check_confirms_nothing(policy_id, violating):
    enable, allow = _LIST_FIELDS[policy_id]
    sections = _g18l(policy_id, violating, override={"ruleId": 5, enable: True, allow: ["l1"]},
                     states=_states(_state(5), _state("l1")))
    assert _answer(policy_id, sections) == UNUSABLE


@pytest.mark.parametrize("storage_bad", [{}, {"ruleId": None}])
def test_round3_m1_an_unusable_root_storage_record_never_lets_a_readable_child_pass(storage_bad):
    assert _answer("GWS.GMAIL.17.1v1", _root_off_child_on(
        ("ou:root", "gmail_comprehensive_mail_storage", storage_bad),
        ("ou:a", "gmail_comprehensive_mail_storage", {"ruleId": "s1"}),
        ("ou:a", "gmail_rule_states", {"ruleStates": [{"ruleId": "s1", "enabled": True}]}))) == UNUSABLE


@pytest.mark.parametrize("policy_id", ["GWS.GMAIL.18.1v1", "GWS.GMAIL.18.2v1", "GWS.GMAIL.18.3v1"])
@pytest.mark.parametrize("root_bad", [{}, {"spamOverride": None}])
def test_round3_m1_an_unusable_root_override_record_never_lets_a_readable_child_pass(policy_id, root_bad):
    assert _answer(policy_id, _root_off_child_on(
        ("ou:root", "gmail_spam_override_lists", root_bad),
        ("ou:a", "gmail_spam_override_lists", {"spamOverride": []}))) == UNUSABLE


def test_round3_m1_a_readable_root_record_with_the_service_off_still_lets_a_readable_child_answer():
    assert _answer("GWS.GMAIL.17.1v1", _root_off_child_on(
        ("ou:root", "gmail_comprehensive_mail_storage", {"ruleId": "s1"}),
        ("ou:root", "gmail_rule_states", {"ruleStates": [{"ruleId": "s1", "enabled": True}]}),
        ("ou:a", "gmail_comprehensive_mail_storage", {"ruleId": "s2"}),
        ("ou:a", "gmail_rule_states", {"ruleStates": [{"ruleId": "s2", "enabled": True}]}))) == MET


def test_round3_m1_a_readable_child_violation_still_wins_over_an_unusable_root_record():
    assert _answer("GWS.GMAIL.17.1v1", _root_off_child_on(
        ("ou:root", "gmail_comprehensive_mail_storage", {}),
        ("ou:a", "gmail_comprehensive_mail_storage", {"ruleId": "s1"}),
        ("ou:a", "gmail_rule_states", {"ruleStates": [{"ruleId": "s1", "enabled": False}]}))) == NOT_MET


@pytest.mark.parametrize("violating", [False, True])
@pytest.mark.parametrize("rule_id", ["", "  ", None, 1.5, True, [], DROP])
def test_round2_b4_an_override_without_a_usable_primary_key_is_unknown(rule_id, violating):
    override = {"hideWarningBannerForAll": violating}
    if rule_id is not DROP:
        override["ruleId"] = rule_id
    states = _states(_state(rule_id)) if isinstance(rule_id, str) else _states()
    assert _answer("GWS.GMAIL.18.3v1", _g183(violating, override=override, states=states)) == UNUSABLE


def test_round2_the_baselines_of_the_matrix_answer():
    for violating, expected in ((False, MET), (True, NOT_MET)):
        assert _answer("GWS.GMAIL.17.1v1", _g17(violating)) == expected
        assert _answer("GWS.GMAIL.18.3v1", _g183(violating)) == expected
        for policy_id in _LIST_FIELDS:
            assert _answer(policy_id, _g18l(policy_id, violating)) == expected


def _tie(section: str, *values) -> tuple:
    """Two equal-ranked top-unit rows for one section that disagree (D11)."""
    return tuple(("ou:root", section, value) for value in values)


# Every input field the kind reads, walked through absent, null, wrong type (int for string and the reverse), blank,
# duplicate and contradictory values. ``violating`` is the baseline the corruption lands on: False reads met and True
# reads not_met when the field is clean, so a literal UNUSABLE or ABSENT for both proves the field never confirms
# either answer.
MATRIX = [
    # GMAIL.17.1: the storage section (a root setting) and its ruleId.
    ("g17-storage-absent", "GWS.GMAIL.17.1v1", lambda v: _g17(v, storage=DROP), ABSENT),
    ("g17-storage-null", "GWS.GMAIL.17.1v1", lambda v: _g17(v, storage=None), UNUSABLE),
    ("g17-storage-list", "GWS.GMAIL.17.1v1", lambda v: _g17(v, storage=["s1"]), UNUSABLE),
    ("g17-storage-empty", "GWS.GMAIL.17.1v1", lambda v: _g17(v, storage={}), UNUSABLE),
    *[(f"g17-ruleid-{name}", "GWS.GMAIL.17.1v1", lambda v, bad=bad: _g17(v, storage={"ruleId": bad}), UNUSABLE)
      for name, bad in (("null", None), ("blank", ""), ("spaces", "  "), ("float", 1.5), ("bool", True),
                        ("list", ["s1"]), ("dict", {"id": "s1"}))],
    ("g17-ruleid-int-vs-str-state", "GWS.GMAIL.17.1v1",
     lambda v: _g17(v, storage={"ruleId": 7}, states=_states(_state("7", not v))), UNUSABLE),
    ("g17-ruleid-str-vs-int-state", "GWS.GMAIL.17.1v1",
     lambda v: _g17(v, storage={"ruleId": "7"}, states=_states(_state(7, not v))), UNUSABLE),
    ("g17-ruleid-padded-state", "GWS.GMAIL.17.1v1",
     lambda v: _g17(v, states=_states(_state(" s1", not v))), UNUSABLE),
    # GMAIL.17.1: the rule-state section, its entries and ``enabled``.
    ("g17-states-absent", "GWS.GMAIL.17.1v1", lambda v: _g17(v, states=DROP), UNUSABLE),
    ("g17-states-null", "GWS.GMAIL.17.1v1", lambda v: _g17(v, states={"ruleStates": None}), UNUSABLE),
    ("g17-states-wrong-type", "GWS.GMAIL.17.1v1", lambda v: _g17(v, states={"ruleStates": "s1"}), UNUSABLE),
    ("g17-states-empty", "GWS.GMAIL.17.1v1", lambda v: _g17(v, states=_states()), UNUSABLE),
    ("g17-states-entry-null", "GWS.GMAIL.17.1v1",
     lambda v: _g17(v, states={"ruleStates": [_state("s1", not v), None]}), UNUSABLE),
    *[(f"g17-states-other-id-{name}", "GWS.GMAIL.17.1v1",
       lambda v, bad=bad: _g17(v, states=_states(_state("s1", not v), _state(bad))), UNUSABLE)
      for name, bad in (("null", None), ("blank", ""), ("float", 1.5), ("bool", False))],
    *[(f"g17-enabled-{name}", "GWS.GMAIL.17.1v1", lambda v, bad=bad: _g17(v, states=_states(_state("s1", bad))),
       UNUSABLE)
      for name, bad in (("absent", DROP), ("null", None), ("int-1", 1), ("int-0", 0), ("float-1", 1.0),
                        ("float-0", 0.0), ("str-true", "true"), ("str-false", "false"), ("list", []), ("dict", {}))],
    ("g17-states-duplicate-key", "GWS.GMAIL.17.1v1",
     lambda v: _g17(v, states=_states(_state("s1", not v), _state("s1", not v))), UNUSABLE),
    ("g17-states-contradictory-spelling", "GWS.GMAIL.17.1v1",
     lambda v: _g17(v, states=_states(_state("s1", True), _state(" s1", False))), UNUSABLE),
    ("g17-states-contradictory-rows", "GWS.GMAIL.17.1v1",
     lambda v: _g17(v, states=DROP, extra=_tie("gmail_rule_states", _states(_state("s1", True)),
                                                _states(_state("s1", False)))), UNUSABLE),
    # GMAIL.18.3: the override section, its ruleId, the flag and the override's rule state.
    ("g183-overrides-absent", "GWS.GMAIL.18.3v1", lambda v: _g183(v, overrides=DROP), ABSENT),
    ("g183-overrides-empty", "GWS.GMAIL.18.3v1", lambda v: _g183(v, overrides={}), UNUSABLE),
    ("g183-overrides-null", "GWS.GMAIL.18.3v1", lambda v: _g183(v, overrides={"spamOverride": None}), UNUSABLE),
    ("g183-overrides-wrong-type", "GWS.GMAIL.18.3v1", lambda v: _g183(v, overrides={"spamOverride": "o1"}),
     UNUSABLE),
    *[(f"g183-ruleid-{name}", "GWS.GMAIL.18.3v1",
       lambda v, bad=bad: _g183(v, override={"ruleId": bad, "hideWarningBannerForAll": v}), UNUSABLE)
      for name, bad in (("null", None), ("blank", ""), ("spaces", "  "), ("float", 1.5), ("bool", True))],
    ("g183-ruleid-absent", "GWS.GMAIL.18.3v1", lambda v: _g183(v, override={"hideWarningBannerForAll": v}),
     UNUSABLE),
    ("g183-ruleid-int-vs-str-state", "GWS.GMAIL.18.3v1",
     lambda v: _g183(v, override={"ruleId": 5, "hideWarningBannerForAll": v}, states=_states(_state("5"))),
     UNUSABLE),
    ("g183-ruleid-str-vs-int-state", "GWS.GMAIL.18.3v1",
     lambda v: _g183(v, override={"ruleId": "5", "hideWarningBannerForAll": v}, states=_states(_state(5))),
     UNUSABLE),
    *[(f"g183-flag-{name}", "GWS.GMAIL.18.3v1",
       lambda v, bad=bad: _g183(v, override={"ruleId": "o1", "hideWarningBannerForAll": bad}), UNUSABLE)
      for name, bad in (("null", None), ("int-1", 1), ("int-0", 0), ("str", "true"), ("list", []))],
    ("g183-state-missing", "GWS.GMAIL.18.3v1", lambda v: _g183(v, states=_states()), UNUSABLE),
    ("g183-states-absent", "GWS.GMAIL.18.3v1", lambda v: _g183(v, states=DROP), UNUSABLE),
    *[(f"g183-enabled-{name}", "GWS.GMAIL.18.3v1",
       lambda v, bad=bad: _g183(v, states=_states(_state("o1", bad))), UNUSABLE)
      for name, bad in (("absent", DROP), ("null", None), ("int-1", 1), ("int-0", 0), ("float-1", 1.0),
                        ("str", "true"))],
    ("g183-states-contradictory-spelling", "GWS.GMAIL.18.3v1",
     lambda v: _g183(v, states=_states(_state("o1", True), _state("o1 ", False))), UNUSABLE),
]
for _policy in _LIST_FIELDS:
    _short = "g181" if _policy.endswith("18.1v1") else "g182"
    _enable, _allow = _LIST_FIELDS[_policy]
    MATRIX += [
        # GMAIL.18.1 and 18.2: the address-list section, list id, counts and list state.
        (f"{_short}-lists-absent", _policy, lambda v, p=_policy: _g18l(p, v, lists=DROP), UNUSABLE),
        (f"{_short}-lists-empty", _policy, lambda v, p=_policy: _g18l(p, v, lists={}), UNUSABLE),
        (f"{_short}-lists-null", _policy, lambda v, p=_policy: _g18l(p, v, lists={"emailAddressList": None}),
         UNUSABLE),
        (f"{_short}-list-unread", _policy,
         lambda v, p=_policy: _g18l(p, v, lists={"emailAddressList": []}), UNUSABLE),
        *[(f"{_short}-list-id-{name}", _policy,
           lambda v, p=_policy, bad=bad: _g18l(p, v, entry={"id": bad, "entry_count": 1,
                                                            "domain_entry_count": int(v)}), UNUSABLE)
          for name, bad in (("null", None), ("blank", ""), ("spaces", "  "), ("float", 1.5), ("bool", True),
                            ("int-other", 1))],
        (f"{_short}-list-id-absent", _policy,
         lambda v, p=_policy: _g18l(p, v, entry={"entry_count": 1, "domain_entry_count": int(v)}), UNUSABLE),
        (f"{_short}-list-id-int-vs-str-ref", _policy,
         lambda v, p=_policy: _g18l(p, v, entry={"id": 42, "entry_count": 1, "domain_entry_count": int(v)},
                                    override={"ruleId": "o1", _LIST_FIELDS[p][0]: True, _LIST_FIELDS[p][1]: ["42"]},
                                    states=_states(_state("o1"), _state(42))), UNUSABLE),
        (f"{_short}-list-id-str-vs-int-ref", _policy,
         lambda v, p=_policy: _g18l(p, v, entry={"id": "42", "entry_count": 1, "domain_entry_count": int(v)},
                                    override={"ruleId": "o1", _LIST_FIELDS[p][0]: True, _LIST_FIELDS[p][1]: [42]},
                                    states=_states(_state("o1"), _state(42))), UNUSABLE),
        (f"{_short}-list-id-padded", _policy,
         lambda v, p=_policy: _g18l(p, v, entry={"id": " l1", "entry_count": 1, "domain_entry_count": int(v)}),
         UNUSABLE),
        *[(f"{_short}-{field}-{name}", _policy,
           lambda v, p=_policy, field=field, bad=bad: _g18l(p, v, entry={
               "id": "l1", "entry_count": 1, "domain_entry_count": int(v), field: bad}), UNUSABLE)
          for field in ("entry_count", "domain_entry_count")
          for name, bad in (("null", None), ("float", 1.0), ("bool", True), ("str", "1"), ("negative", -1))],
        *[(f"{_short}-{field}-absent", _policy,
           lambda v, p=_policy, field=field: _g18l(p, v, entry=_without(
               {"id": "l1", "entry_count": 1, "domain_entry_count": int(v)}, field)), UNUSABLE)
          for field in ("entry_count", "domain_entry_count")],
        (f"{_short}-counts-contradictory", _policy,
         lambda v, p=_policy: _g18l(p, v, entry={"id": "l1", "entry_count": 0, "domain_entry_count": 1}), UNUSABLE),
        (f"{_short}-list-rows-contradictory", _policy,
         lambda v, p=_policy: _g18l(p, v, lists=DROP, extra=_tie(
             "gmail_email_address_lists",
             {"emailAddressList": [{"id": "l1", "entry_count": 1, "domain_entry_count": 0}]},
             {"emailAddressList": [{"id": "l1", "entry_count": 1, "domain_entry_count": 1}]})), UNUSABLE),
        (f"{_short}-list-duplicate-spelling", _policy,
         lambda v, p=_policy: _g18l(p, v, lists={"emailAddressList": [
             {"id": "l1", "entry_count": 1, "domain_entry_count": 0},
             {"id": "l1 ", "entry_count": 1, "domain_entry_count": 1}]}), UNUSABLE),
        (f"{_short}-list-state-missing", _policy,
         lambda v, p=_policy: _g18l(p, v, states=_states(_state("o1"))), UNUSABLE),
        *[(f"{_short}-list-enabled-{name}", _policy,
           lambda v, p=_policy, bad=bad: _g18l(p, v, states=_states(_state("o1"), _state("l1", bad))), UNUSABLE)
          for name, bad in (("absent", DROP), ("null", None), ("int-1", 1), ("int-0", 0), ("float-0", 0.0),
                            ("str", "true"))],
        # The override: its ruleId, flag, address-list field and rule state.
        (f"{_short}-overrides-absent", _policy, lambda v, p=_policy: _g18l(p, v, overrides=DROP), ABSENT),
        (f"{_short}-overrides-null", _policy,
         lambda v, p=_policy: _g18l(p, v, overrides={"spamOverride": None}), UNUSABLE),
        *[(f"{_short}-override-ruleid-{name}", _policy,
           lambda v, p=_policy, bad=bad: _g18l(p, v, override={
               "ruleId": bad, _LIST_FIELDS[p][0]: True, _LIST_FIELDS[p][1]: ["l1"]}), UNUSABLE)
          for name, bad in (("null", None), ("blank", ""), ("float", 1.5), ("bool", True))],
        *[(f"{_short}-flag-{name}", _policy,
           lambda v, p=_policy, bad=bad: _g18l(p, v, override={
               "ruleId": "o1", _LIST_FIELDS[p][0]: bad, _LIST_FIELDS[p][1]: ["l1"]}), UNUSABLE)
          for name, bad in (("null", None), ("int-1", 1), ("int-0", 0), ("str", "true"))],
        *[(f"{_short}-allowlist-{name}", _policy,
           lambda v, p=_policy, bad=bad: _g18l(p, v, override={
               "ruleId": "o1", _LIST_FIELDS[p][0]: True, _LIST_FIELDS[p][1]: bad}), UNUSABLE)
          for name, bad in (("null", None), ("str", "l1"), ("entry-null", ["l1", None]), ("entry-blank", ["l1", ""]),
                            ("entry-float", ["l1", 1.5]), ("entry-bool", ["l1", True]), ("entry-list", [["l1"]]),
                            ("unread-list", ["l9"]))],
        (f"{_short}-override-state-missing", _policy,
         lambda v, p=_policy: _g18l(p, v, states=_states(_state("l1"))), UNUSABLE),
        *[(f"{_short}-override-enabled-{name}", _policy,
           lambda v, p=_policy, bad=bad: _g18l(p, v, states=_states(_state("o1", bad), _state("l1"))), UNUSABLE)
          for name, bad in (("null", None), ("int-1", 1), ("float-1", 1.0), ("str", "true"))],
    ]


@pytest.mark.parametrize("violating", [False, True], ids=["clean-reads-met", "clean-reads-not-met"])
@pytest.mark.parametrize(("policy_id", "build", "expected"), [case[1:] for case in MATRIX],
                         ids=[case[0] for case in MATRIX])
def test_round2_no_unreadable_input_confirms_met_or_not_met(policy_id, build, expected, violating):
    assert _answer(policy_id, build(violating)) == expected
