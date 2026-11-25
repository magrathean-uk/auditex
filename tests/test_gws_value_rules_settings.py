"""``setting`` kind and its 38 Gmail and Common Controls rows (design M13 sections 8.2 and 14; lane L07).

Synthetic data only; every expected value is a literal. The 343 vectors in ``fixtures/gws-value-rules/setting-core.jsonl``
replay through ``test_gws_value_rules_replay.py``; this file pins the rows against a second literal copy of the design
table, the operators, the parameter checks and the unknown-is-not-safe paths.
"""
from __future__ import annotations

import copy

import pytest

from azure_tenant_audit import value_rules
from azure_tenant_audit.value_rules import gws
from azure_tenant_audit.value_rules.gws import settings as S
from azure_tenant_audit.value_rules.gws.catalogue import catalogue

ALL, EXPLICIT = "all_units", "explicit_only"
# policy -> (section, field(s), op, pinned value, service, scope): the design section 14 rows and their Rego cites.
ROWS = {
    "GMAIL.1.1": ("gmail_mail_delegation", "enableMailDelegation", "eq", True, "gmail", ALL),
    "GMAIL.5.1": ("gmail_email_attachment_safety", "enableEncryptedAttachmentProtection", "ne", True, "gmail", ALL),
    "GMAIL.5.2": ("gmail_email_attachment_safety", "enableAttachmentWithScriptsProtection", "ne", True, "gmail", ALL),
    "GMAIL.5.3": ("gmail_email_attachment_safety", "enableAnomalousAttachmentProtection", "ne", True, "gmail", ALL),
    "GMAIL.5.4": ("gmail_email_attachment_safety", "applyFutureRecommendedSettingsAutomatically", "ne", True, "gmail", ALL),
    "GMAIL.6.1": ("gmail_links_and_external_images", "enableShortenerScanning", "ne", True, "gmail", ALL),
    "GMAIL.6.2": ("gmail_links_and_external_images", "enableExternalImageScanning", "ne", True, "gmail", ALL),
    "GMAIL.6.3": ("gmail_links_and_external_images", "enableAggressiveWarningsOnUntrustedLinks", "ne", True, "gmail", ALL),
    "GMAIL.6.4": ("gmail_links_and_external_images", "applyFutureSettingsAutomatically", "ne", True, "gmail", ALL),
    "GMAIL.7.1": ("gmail_spoofing_and_authentication", "detectDomainNameSpoofing", "ne", True, "gmail", ALL),
    "GMAIL.7.2": ("gmail_spoofing_and_authentication", "detectEmployeeNameSpoofing", "ne", True, "gmail", ALL),
    "GMAIL.7.3": ("gmail_spoofing_and_authentication", "detectDomainSpoofingFromUnauthenticatedSenders", "ne", True, "gmail", ALL),
    "GMAIL.7.4": ("gmail_spoofing_and_authentication", "detectUnauthenticatedEmails", "ne", True, "gmail", ALL),
    "GMAIL.7.5": ("gmail_spoofing_and_authentication", "detectGroupsSpoofing", "ne", True, "gmail", ALL),
    "GMAIL.7.7": ("gmail_spoofing_and_authentication", "applyFutureSettingsAutomatically", "ne", True, "gmail", ALL),
    "GMAIL.8.1": ("gmail_user_email_uploads", "enableMailAndContactsImport", "eq", True, "gmail", ALL),
    "GMAIL.10.1": ("gmail_workspace_sync_for_outlook", "enableGoogleWorkspaceSyncForMicrosoftOutlook", "eq", True, "gmail", ALL),
    "GMAIL.11.1": ("gmail_auto_forwarding", "enableAutoForwarding", "ne", False, "gmail", ALL),
    "GMAIL.12.1": ("gmail_per_user_outbound_gateway", "allowUsersToUseExternalSmtpServers", "eq", True, "gmail", ALL),
    "GMAIL.15.1": ("gmail_enhanced_pre_delivery_message_scanning", "enableImprovedSuspiciousContentDetection", "ne", True, "gmail", ALL),
    "COMMONCONTROLS.4.1": ("security_session_controls", "webSessionDuration", "duration_gt", "12h", None, ALL),
    "COMMONCONTROLS.5.1": ("security_password", "allowedStrength", "ne", "STRONG", None, ALL),
    "COMMONCONTROLS.5.2": ("security_password", "minimumLength", "lt", 12, None, ALL),
    "COMMONCONTROLS.5.3": ("security_password", "minimumLength", "lt", 16, None, ALL),
    "COMMONCONTROLS.5.4": ("security_password", "enforceRequirementsAtLogin", "ne", True, None, ALL),
    "COMMONCONTROLS.5.5": ("security_password", "allowReuse", "eq", True, None, ALL),
    "COMMONCONTROLS.5.6": ("security_password", "expirationDuration", "duration_ne", "0s", None, ALL),
    "COMMONCONTROLS.7.1": ("provisioning_conflicting_accounts_management",
                           ["option", "conflictingAccountsManagement"], "ne", "REPLACE_CONFLICTING_ACCOUNT", None, ALL),
    "COMMONCONTROLS.8.1": ("security_super_admin_account_recovery", "enableAccountRecovery", "eq", True, None, ALL),
    "COMMONCONTROLS.8.2": ("security_user_account_recovery", "enableAccountRecovery", "eq", True, None, ALL),
    "COMMONCONTROLS.10.3": ("api_controls_internal_apps", "trustInternalApps", "eq", True, None, ALL),
    "COMMONCONTROLS.10.4": ("api_controls_unconfigured_third_party_apps", "accessLevel", "not_in",
                            ["BLOCK_ALL", "BLOCK_ALL_SCOPES"], None, ALL),
    "COMMONCONTROLS.10.5": ("security_less_secure_apps", "allowLessSecureApps", "ne", False, None, ALL),
    "COMMONCONTROLS.15.1": ("data_regions_data_at_rest_region", "region", "ne", "US", None, ALL),
    "COMMONCONTROLS.15.2": ("data_regions_data_processing_region", "limitToStorageRegion", "ne", True, None, ALL),
    "COMMONCONTROLS.16.1": ("enterprise_service_restrictions_service_status", "serviceState", "ne", "ENABLED", None, EXPLICIT),
    "COMMONCONTROLS.16.2": ("early_access_apps_service_status", "serviceState", "eq", "ENABLED", None, EXPLICIT),
    "COMMONCONTROLS.17.1": ("multi_party_approval_require_approvals", "multiPartyApprovalState", "ne", "ENABLED", None, ALL),
}
IDS = {f"GWS.{key}v1": value for key, value in ROWS.items()}
TENANT = {"as_of": "2026-11-25T12:00:00Z", "top_unit": "ou:root",
          "org_units": {"ou:root": None, "ou:a": "ou:root"}, "complete": True}


def _p(unit, section, value, sort_order=1):
    return {"unit": unit, "unit_kind": "org_unit", "section": section, "sort_order": sort_order, "value": value}


def _sections(policies, complete=True, tenant=TENANT):
    return {"gws_tenant": copy.deepcopy(tenant), "gws_policies": {"complete": complete, "policies": policies}}


ON = _p("ou:root", "gmail_service_status", {"serviceState": "ENABLED"})
SE = "gmail_email_attachment_safety"
FIELD = "enableEncryptedAttachmentProtection"
GOOD = _p("ou:root", SE, {FIELD: True})


def _answer(policy_id, sections):
    record = gws.assess(policy_id, sections)
    return record["verdict"], record["cell"]


def test_the_38_rows_use_the_setting_kind_and_the_design_parameters():
    rows = {pid: row for pid, row in catalogue()["policies"].items() if row["kind"] == "setting"}
    assert sorted(rows) == sorted(IDS)
    for pid, (section, field, op, value, service, scope) in IDS.items():
        row = rows[pid]
        params = dict(row["params"])
        assert params.pop("fields" if isinstance(field, list) else "field") == field, pid
        # The string vocabularies and case folding are pinned by test_m1_every_shipped_string_row_pins_its_vocabulary.
        for name in ("known", "source", "case"):
            params.pop(name, None)
        assert params == {"section": section, "op": op, "value": value, "service": service, "scope": scope}, pid
        assert row["sections"] == ["gws_tenant", "gws_policies"] and row["rule_id"] == f"{pid}.setting"


def test_every_row_reads_a_pinned_section_and_field_and_gates_on_its_status_section():
    semantics = catalogue()["section_semantics"]
    for pid, row in catalogue()["policies"].items():
        if row["kind"] != "setting":
            continue
        params = row["params"]
        assert params["section"] in semantics, pid
        names = params.get("fields") or [params["field"]]
        known = set(semantics[params["section"]]["fields"])
        # D7 alone reads a field the pinned table does not list (``option``).
        assert [name for name in names if name not in known] == (
            ["option"] if pid == "GWS.COMMONCONTROLS.7.1v1" else []), pid
        if params["service"] is not None:
            assert f"{params['service']}_service_status" in semantics, pid


def test_only_the_gmail_rows_are_gated_and_only_the_status_rows_are_explicit_only():
    rows = {pid: row["params"] for pid, row in catalogue()["policies"].items() if row["kind"] == "setting"}
    assert {pid for pid, params in rows.items() if params["service"] == "gmail"} == {
        pid for pid in rows if ".GMAIL." in pid}
    assert {pid for pid, params in rows.items() if params["scope"] == "explicit_only"} == {
        "GWS.COMMONCONTROLS.16.1v1", "GWS.COMMONCONTROLS.16.2v1"}


def test_the_kind_is_registered_once_and_never_reaches_a_microsoft_policy():
    assert "setting" in gws._registry() and "setting" not in value_rules._registry()
    assert value_rules.assess("GWS.GMAIL.1.1v1", {}) is None
    assert gws.assess("MS.AAD.1.1v1", {}) is None


# --- parameters -----------------------------------------------------------------------------------------------------

def _good(**change):
    params = {"section": "gmail_mail_delegation", "field": "enableMailDelegation", "op": "eq", "value": True,
              "service": "gmail", "scope": ALL}
    params.update(change)
    return params


@pytest.mark.parametrize("params", [
    None, [], {}, _good(extra=1), _good(field=None), _good(field=None, fields=[]), _good(fields=["a"]),
    _good(fields=["a", "a"], field=None), _good(fields=[1], field=None), _good(fields="ab", field=None),
    _good(field=""), _good(field=1), _good(section=1), _good(op="ge"), _good(op="eq", value=1),
    _good(op="eq", value=None), _good(op="eq", value=""), _good(op="in", value="A"), _good(op="in", value=[]),
    _good(op="not_in", value=[1]), _good(op="lt", value=True), _good(op="lt", value="12"), _good(op="gt", value=1.5),
    _good(op="duration_gt", value="12"), _good(op="duration_ne", value="1w"), _good(op="duration_gt", value=3600),
    _good(service=1), _good(scope="everywhere"), _good(scope=None),
])
def test_malformed_parameters_are_a_programming_error(params):
    with pytest.raises(ValueError, match="Invalid GWS setting parameters"):
        S._params(params)


def test_parameters_default_the_scope_and_accept_the_design_shapes():
    params = _good()
    del params["scope"]
    assert S._params(params) == ("gmail_mail_delegation", ("enableMailDelegation",), "eq", True, "gmail", ALL, None,
                                 False)
    assert S._params({"section": "s", "fields": ["a", "b"], "op": "not_in", "value": ["X"], "service": None,
                      "scope": EXPLICIT, "known": ["X", "Y"], "source": "c"}) == (
        "s", ("a", "b"), "not_in", ["X"], None, EXPLICIT, frozenset({"X", "Y"}), False)


# --- operators ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("op, actual, pinned, expected", [
    ("eq", True, True, True), ("eq", False, True, False), ("ne", True, True, False), ("ne", False, True, True),
    ("eq", 1, True, None), ("ne", "true", True, None), ("eq", None, False, None), ("ne", [], False, None),
    ("eq", "ENABLED", "ENABLED", True), ("eq", "enabled", "ENABLED", False), ("ne", "DISABLED", "ENABLED", True),
    ("ne", "", "ENABLED", None), ("ne", 5, "STRONG", None), ("ne", True, "STRONG", None),
    ("ne", "ſTRONG", "STRONG", None), ("eq", "dısabled", "DISABLED", None), ("not_in", "uſ", ["US"], None),
    ("in", "BLOCK_ALL", ["BLOCK_ALL", "X"], True), ("not_in", "block_all", ["BLOCK_ALL"], True),
    ("not_in", "ALLOW_ALL", ["BLOCK_ALL", "BLOCK_ALL_SCOPES"], True), ("not_in", 1, ["BLOCK_ALL"], None),
    ("lt", 11, 12, True), ("lt", 12, 12, False), ("lt", 12.0, 12, False), ("lt", 12.5, 12, None),
    ("lt", "11", 12, None), ("lt", True, 12, None), ("lt", float("nan"), 12, None), ("lt", float("inf"), 12, None),
    ("gt", 13, 12, True), ("gt", 12, 12, False),
    ("duration_gt", "43201s", "12h", True), ("duration_gt", "43200s", "12h", False), ("duration_gt", "12H", "12h", False),
    ("duration_gt", "1d", "12h", True), ("duration_gt", "719m", "12h", False), ("duration_gt", "721m", "12h", True),
    ("duration_gt", "43200", "12h", None), ("duration_gt", "-1s", "12h", None), ("duration_gt", 43200, "12h", None),
    ("duration_gt", "3600.5s", "12h", None), ("duration_gt", "", "12h", None), ("duration_gt", "٤s", "12h", None),
    ("duration_gt", "1" * 40 + "s", "12h", True), ("duration_gt", None, "12h", None),
    ("duration_ne", "0s", "0s", False), ("duration_ne", "7776000s", "0s", True), ("duration_ne", "0d", "0s", False),
    ("duration_ne", "0", "0s", None),
])
def test_operators(op, actual, pinned, expected):
    assert S._violates(op, actual, pinned) is expected


# --- unknown is not safe --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("sections", [
    None, [], "x", {}, {"gws_tenant": None, "gws_policies": None},
    {"gws_tenant": TENANT, "gws_policies": None}, {"gws_tenant": TENANT, "gws_policies": []},
    {"gws_tenant": TENANT, "gws_policies": {"complete": True}},
    {"gws_tenant": TENANT, "gws_policies": {"complete": True, "policies": None}},
    {"gws_tenant": TENANT, "gws_policies": {"complete": True, "policies": [None]}},
    {"gws_tenant": TENANT, "gws_policies": {"complete": True, "policies": [{"section": 1}]}},
    {"gws_tenant": TENANT, "gws_policies": {"complete": True, "policies": [
        {"unit": "ou:root", "unit_kind": "group", "section": SE, "sort_order": 1, "value": {FIELD: True}}]}},
    {"gws_tenant": {"top_unit": "ou:root", "org_units": "x", "complete": True},
     "gws_policies": {"complete": True, "policies": []}},
    {"gws_tenant": {"top_unit": "ou:root", "org_units": {"ou:a": "ou:root"}, "complete": True},
     "gws_policies": {"complete": True, "policies": []}},
])
def test_malformed_envelopes_never_answer_met(sections):
    if sections is None:
        # The shared section gate (not this lane) cannot look inside None; the caller never passes it.
        with pytest.raises(TypeError):
            gws.assess("GWS.GMAIL.5.1v1", sections)
        return
    record = gws.assess("GWS.GMAIL.5.1v1", sections)
    assert record["verdict"] == "not_assessed"


@pytest.mark.parametrize("value", [None, "", [], {}, "true", 1, 0, "enabled", {"x": 1}])
def test_a_bad_value_is_unusable_never_met(value):
    for policy_id, field in (("GWS.GMAIL.5.1v1", FIELD),):
        sections = _sections([ON, _p("ou:root", SE, {field: value})])
        assert _answer(policy_id, sections) == ("not_assessed", "setting_value_unusable")


@pytest.mark.parametrize("entry", [
    {"unit": "ou:root", "unit_kind": "org_unit", "section": SE, "sort_order": "1", "value": {FIELD: True}},
    {"unit": "ou:root", "unit_kind": "org_unit", "section": SE, "sort_order": True, "value": {FIELD: True}},
    {"unit": "ou:root", "unit_kind": "org_unit", "section": SE, "value": {FIELD: True}},
    {"unit": "ou:root", "unit_kind": "org_unit", "section": SE, "sort_order": 1},
    {"unit": "ou:root", "unit_kind": "org_unit", "section": SE, "sort_order": 1, "value": None},
    {"unit": "ou:root", "unit_kind": "org_unit", "section": SE, "sort_order": 1, "value": [FIELD]},
])
def test_an_unrankable_or_valueless_entry_is_unusable_never_met(entry):
    assert _answer("GWS.GMAIL.5.1v1", _sections([ON, entry])) == ("not_assessed", "setting_value_unusable")


def test_an_unrelated_malformed_section_never_reaches_the_rule():
    junk = _p("ou:root", "gmail_pop_access", "x")
    assert _answer("GWS.GMAIL.5.1v1", _sections([ON, GOOD, junk])) == ("met", "no_unit_violates")


def test_a_malformed_status_record_is_unknown_not_off_and_not_on():
    for status in ({}, {"other": 1}, {"serviceState": None}, {"serviceState": "UNSPECIFIED"}):
        sections = _sections([_p("ou:root", "gmail_service_status", status), GOOD])
        assert _answer("GWS.GMAIL.5.1v1", sections) == ("not_assessed", "service_status_absent"), status


def test_a_service_off_only_in_one_unit_is_not_applicable_nowhere():
    sections = _sections([ON, _p("ou:a", "gmail_service_status", {"serviceState": "DISABLED"}), GOOD])
    assert _answer("GWS.GMAIL.5.1v1", sections) == ("met", "no_unit_violates")
    sections = _sections([_p("ou:root", "gmail_service_status", {"serviceState": "DISABLED"}), GOOD,
                          _p("ou:a", SE, {FIELD: False})])
    assert _answer("GWS.GMAIL.5.1v1", sections) == ("not_applicable", "service_off_everywhere")


def test_a_group_unit_inherits_the_top_service_state():
    group = {"unit": "ou:root/group:g1", "unit_kind": "group", "section": SE, "sort_order": 1,
             "value": {FIELD: False}}
    assert _answer("GWS.GMAIL.5.1v1", _sections([ON, GOOD, group])) == ("not_met", "unit_violates")
    off = {"unit": "ou:root/group:g1", "unit_kind": "group", "section": "gmail_service_status", "sort_order": 1,
           "value": {"serviceState": "DISABLED"}}
    assert _answer("GWS.GMAIL.5.1v1", _sections([ON, GOOD, group, off])) == ("met", "no_unit_violates")


def test_an_incomplete_read_is_never_a_verdict_even_with_a_violation_in_it():
    sections = _sections([ON, GOOD, _p("ou:a", SE, {FIELD: False})], complete=False)
    assert _answer("GWS.GMAIL.5.1v1", sections) == ("not_assessed", "policy_read_incomplete")


def test_defaults_need_a_complete_read():
    # GMAIL.1.1 has a pinned default (false); with an incomplete read it is not applied and the read gate answers first.
    sections = _sections([ON], complete=False)
    assert _answer("GWS.GMAIL.1.1v1", sections) == ("not_assessed", "policy_read_incomplete")
    assert _answer("GWS.GMAIL.1.1v1", _sections([ON])) == ("met", "no_unit_violates")


def test_explicit_only_never_uses_a_default_or_the_top_unit():
    section = "early_access_apps_service_status"
    assert _answer("GWS.COMMONCONTROLS.16.2v1", _sections([])) == ("not_assessed", "setting_absent")
    assert _answer("GWS.COMMONCONTROLS.16.2v1", _sections([_p("ou:a", section, {"serviceState": "DISABLED"})])) == (
        "met", "no_unit_violates")
    assert _answer("GWS.COMMONCONTROLS.16.2v1", _sections([_p("ou:a", section, {"serviceState": "ENABLED"})])) == (
        "not_met", "unit_violates")
    assert _answer("GWS.COMMONCONTROLS.16.2v1", _sections([_p("ou:a", section, {"serviceState": "x"}),
                                                            _p("ou:root", section, {"serviceState": "ENABLED"})])) == (
        "not_met", "unit_violates")
    assert _answer("GWS.COMMONCONTROLS.16.2v1", _sections([_p("ou:a", section, {"other": 1})])) == (
        "not_assessed", "setting_value_unusable")


def test_a_tie_in_an_unrelated_field_of_the_section_makes_the_unit_unusable_not_compliant():
    ties = [_p("ou:a", SE, {FIELD: True}, 4), _p("ou:a", SE, {FIELD: False}, 4)]
    assert _answer("GWS.GMAIL.5.1v1", _sections([ON, GOOD, *ties])) == ("not_assessed", "setting_value_unusable")


def test_answers_hold_no_input_value_and_cite_the_row_sections():
    secret = "ZZ-VALUE-FROM-THE-TENANT"
    sections = _sections([_p("ou:root", "security_password", {"allowedStrength": secret})])
    record = gws.assess("GWS.COMMONCONTROLS.5.1v1", sections)
    assert (record["verdict"], record["cell"], record["detail"]) == ("not_assessed", "setting_value_unusable", {})
    assert secret not in repr(record)
    record = gws.assess("GWS.COMMONCONTROLS.5.1v1", _sections([_p("ou:root", "security_password",
                                                                   {"allowedStrength": "WEAK"})]))
    assert (record["verdict"], record["cell"], record["detail"]) == ("not_met", "unit_violates", {})
    assert secret not in repr(record) and "ou:" not in record["reason_text"]
    assert record["cited_sections"] == ["gws_tenant", "gws_policies"]


def test_the_texts_are_the_kind_constants():
    row = catalogue()["policies"]["GWS.GMAIL.1.1v1"]
    assert {name: entry["reason_texts"] for name, entry in row["cells"].items() if name != "section_not_collected"} == {
        "section_shape_unusable": ["Data unusable: the Google Workspace policy evidence has an unexpected shape; "
                                   "the policy was not assessed."],
        "policy_read_incomplete": ["Data unavailable: the Google Workspace policy read is incomplete; the policy was "
                                   "not assessed."],
        "service_off_everywhere": ["Not applicable: the Google Workspace service this policy covers is turned off in "
                                   "every organisational unit."],
        "service_status_absent": ["Data unavailable: the status of the Google Workspace service this policy covers is "
                                  "absent or unreadable; the policy was not assessed."],
        "unit_violates": ["Requirement not met: at least one organisational unit or group holds a value that "
                          "violates the setting."],
        "setting_value_unusable": ["Data unusable: a unit holds a value for the setting that cannot be read as the "
                                   "expected type; the policy was not assessed."],
        "setting_absent": ["Data unavailable: the setting is absent from the collected policies and has no pinned "
                           "default; the policy was not assessed."],
        "no_unit_violates": ["Requirement met: no organisational unit or group holds a value that violates the "
                             "setting."]}
    assert {name: entry["verdict"] for name, entry in row["cells"].items()} == {
        "section_not_collected": "not_assessed", "section_shape_unusable": "not_assessed",
        "policy_read_incomplete": "not_assessed", "service_off_everywhere": "not_applicable",
        "service_status_absent": "not_assessed", "unit_violates": "not_met", "setting_value_unusable": "not_assessed",
        "setting_absent": "not_assessed", "no_unit_violates": "met"}


def test_ungated_rows_never_answer_a_service_cell():
    sections = _sections([_p("ou:root", "security_password", {"minimumLength": 12})])
    assert _answer("GWS.COMMONCONTROLS.5.2v1", sections) == ("met", "no_unit_violates")
    sections = _sections([_p("ou:root", "gmail_service_status", {"serviceState": "DISABLED"}),
                          _p("ou:root", "security_password", {"minimumLength": 11})])
    assert _answer("GWS.COMMONCONTROLS.5.2v1", sections) == ("not_met", "unit_violates")


def test_a_sub_ou_value_is_judged_on_its_own_even_when_the_top_unit_complies():
    sections = _sections([_p("ou:root", "security_password", {"minimumLength": 16}),
                          _p("ou:a", "security_password", {"minimumLength": 12})])
    assert _answer("GWS.COMMONCONTROLS.5.3v1", sections) == ("not_met", "unit_violates")
    assert _answer("GWS.COMMONCONTROLS.5.2v1", sections) == ("met", "no_unit_violates")


@pytest.mark.parametrize("policy_id, section", [
    ("GWS.COMMONCONTROLS.16.1v1", "enterprise_service_restrictions_service_status"),
    ("GWS.COMMONCONTROLS.16.2v1", "early_access_apps_service_status")])
@pytest.mark.parametrize("state", ["x", "true", "STRONG", "ENABLEDX", "ſ", 1, True, None, ""])
def test_an_unrecognised_service_state_is_unusable_on_the_status_rows(policy_id, section, state):
    sections = _sections([_p("ou:root", section, {"serviceState": state})])
    assert _answer(policy_id, sections) == ("not_assessed", "setting_value_unusable")


def test_unicode_case_folding_never_makes_an_unknown_value_compliant():
    for policy_id, section, field, value in (
            ("GWS.COMMONCONTROLS.5.1v1", "security_password", "allowedStrength", "ſTRONG"),
            ("GWS.COMMONCONTROLS.15.1v1", "data_regions_data_at_rest_region", "region", "uſ"),
            ("GWS.COMMONCONTROLS.7.1v1", "provisioning_conflicting_accounts_management", "option",
             "REPLACE_CONFLıCTING_ACCOUNT")):
        sections = _sections([_p("ou:root", section, {field: value})])
        assert _answer(policy_id, sections) == ("not_assessed", "setting_value_unusable"), policy_id


# --- a unit with the service on and no value of its own is judged on its effective value (design 8.1) ---------------------

OFF_TOP = _p("ou:root", "gmail_service_status", {"serviceState": "DISABLED"})
ON_SUB = _p("ou:a", "gmail_service_status", {"serviceState": "ENABLED"})


def test_a_sub_ou_switching_the_service_on_inherits_a_violating_top_value():
    sections = _sections([OFF_TOP, _p("ou:root", SE, {FIELD: False}), ON_SUB])
    assert _answer("GWS.GMAIL.5.1v1", sections) == ("not_met", "unit_violates")


def test_a_sub_ou_switching_the_service_on_inherits_a_compliant_top_value():
    sections = _sections([OFF_TOP, GOOD, ON_SUB])
    assert _answer("GWS.GMAIL.5.1v1", sections) == ("met", "no_unit_violates")


def test_a_sub_ou_switching_the_service_on_with_a_broken_topology_is_not_assessed():
    tenant = dict(TENANT, org_units={"ou:root": None, "ou:a": "ou:gone"})
    sections = _sections([OFF_TOP, _p("ou:root", SE, {FIELD: False}), ON_SUB], tenant=tenant)
    assert _answer("GWS.GMAIL.5.1v1", sections) == ("not_assessed", "policy_read_incomplete")


def test_a_sub_ou_with_the_service_on_inherits_the_pinned_default_when_the_top_value_is_absent():
    # GMAIL.1.1 pins a default of false for enableMailDelegation (eq true violates).
    off_ok = _sections([OFF_TOP, ON_SUB])
    assert _answer("GWS.GMAIL.1.1v1", off_ok) == ("met", "no_unit_violates")


# --- review repair M13-L07-repair (B1 to B4, M1, L1): each fails on 961acdfc ------------------------------------------

UNREADABLE_SUB = _p("ou:a", "gmail_service_status", {"serviceState": None})


def test_b1_an_unreadable_sub_unit_service_state_never_confirms_met_through_a_compliant_inherited_value():
    assert _answer("GWS.GMAIL.5.1v1", _sections([ON, GOOD, UNREADABLE_SUB])) == (
        "not_assessed", "service_status_absent")


def test_b1_an_absent_top_service_state_never_confirms_met_beside_an_enabled_sub_unit():
    assert _answer("GWS.GMAIL.5.1v1", _sections([GOOD, ON_SUB])) == ("not_assessed", "service_status_absent")


def test_b1_a_violation_in_a_service_on_unit_still_wins_over_an_unknown_state_elsewhere():
    sections = _sections([ON, _p("ou:root", SE, {FIELD: False}), UNREADABLE_SUB])
    assert _answer("GWS.GMAIL.5.1v1", sections) == ("not_met", "unit_violates")


@pytest.mark.parametrize("policy_id, section, field, value", [
    ("GWS.COMMONCONTROLS.15.1v1", "data_regions_data_at_rest_region", "region", "us"),
    ("GWS.COMMONCONTROLS.10.4v1", "api_controls_unconfigured_third_party_apps", "accessLevel", "block_all"),
    ("GWS.COMMONCONTROLS.10.4v1", "api_controls_unconfigured_third_party_apps", "accessLevel", "Block_All_Scopes"),
    ("GWS.COMMONCONTROLS.17.1v1", "multi_party_approval_require_approvals", "multiPartyApprovalState", "enabled"),
    ("GWS.COMMONCONTROLS.7.1v1", "provisioning_conflicting_accounts_management", "option",
     "replace_conflicting_account"),
])
def test_b2_strings_compare_exactly_as_the_rego_does(policy_id, section, field, value):
    sections = _sections([_p("ou:root", section, {field: value})])
    assert _answer(policy_id, sections) == ("not_assessed", "setting_value_unusable")


def test_b2_the_rego_folds_ascii_case_only_for_cc_5_1_and_the_explicit_service_states():
    assert _answer("GWS.COMMONCONTROLS.5.1v1", _sections([_p("ou:root", "security_password",
                                                             {"allowedStrength": "strong"})])) == (
        "met", "no_unit_violates")
    assert _answer("GWS.COMMONCONTROLS.5.1v1", _sections([_p("ou:root", "security_password",
                                                             {"allowedStrength": "weak"})])) == (
        "not_met", "unit_violates")
    section = "early_access_apps_service_status"
    assert _answer("GWS.COMMONCONTROLS.16.2v1", _sections([_p("ou:a", section, {"serviceState": "enabled"})])) == (
        "not_met", "unit_violates")
    assert _answer("GWS.COMMONCONTROLS.16.2v1", _sections([_p("ou:a", section, {"serviceState": "disabled"})])) == (
        "met", "no_unit_violates")


def test_b2_a_unicode_folded_service_state_is_unknown_not_disabled():
    folded = _p("ou:a", "gmail_service_status", {"serviceState": "dıſabled"})
    sections = _sections([ON, GOOD, folded, _p("ou:a", SE, {FIELD: False})])
    assert _answer("GWS.GMAIL.5.1v1", sections) == ("not_assessed", "service_status_absent")
    top = _p("ou:root", "gmail_service_status", {"serviceState": "еNABLED"})
    assert _answer("GWS.GMAIL.5.1v1", _sections([top, GOOD])) == ("not_assessed", "service_status_absent")


@pytest.mark.parametrize("policy_id, section", [
    ("GWS.COMMONCONTROLS.16.1v1", "enterprise_service_restrictions_service_status"),
    ("GWS.COMMONCONTROLS.16.2v1", "early_access_apps_service_status")])
@pytest.mark.parametrize("record", [{}, {"other": 1}])
def test_b3_a_supplied_status_record_without_a_state_is_unusable_not_absent(policy_id, section, record):
    good = "DISABLED" if policy_id.endswith("16.2v1") else "ENABLED"
    sections = _sections([_p("ou:root", section, record), _p("ou:a", section, {"serviceState": good})])
    assert _answer(policy_id, sections) == ("not_assessed", "setting_value_unusable")
    assert _answer(policy_id, _sections([_p("ou:a", section, record)])) == ("not_assessed", "setting_value_unusable")


@pytest.mark.parametrize("unit, kind", [
    ("not-an-ou", "org_unit"), ("ou:", "org_unit"), ("ou:a/b", "org_unit"), ("ou:a b", "org_unit"),
    ("ou:a/group:", "group"), ("ou:/group:g1", "group"), ("ou:a/group:g1/x", "group"), ("x/group:g1", "group"),
])
def test_b4_a_policy_record_on_an_unplaceable_unit_is_a_shape_error_never_met(unit, kind):
    stray = {"unit": unit, "unit_kind": kind, "section": SE, "sort_order": 1, "value": {FIELD: True}}
    assert _answer("GWS.GMAIL.5.1v1", _sections([ON, GOOD, stray])) == ("not_assessed", "section_shape_unusable")


def test_b4_an_unplaceable_record_in_an_unrelated_section_never_reaches_the_rule():
    stray = {"unit": "not-an-ou", "unit_kind": "org_unit", "section": "gmail_pop_access", "sort_order": 1,
             "value": {"enablePopAccess": True}}
    assert _answer("GWS.GMAIL.5.1v1", _sections([ON, GOOD, stray])) == ("met", "no_unit_violates")


def _region_row(**change):
    row = copy.deepcopy(catalogue()["policies"]["GWS.COMMONCONTROLS.15.1v1"])
    row["params"].update(change)
    return row


REGION = "data_regions_data_at_rest_region"


@pytest.mark.parametrize("change", [{"op": "eq", "value": "US"}, {"op": "in", "value": ["US"]},
                                    {"op": "ne", "value": "US"}, {"op": "not_in", "value": ["US"]}])
def test_m1_a_value_outside_the_pinned_vocabulary_never_answers_met_on_any_string_operator(change):
    sections = _sections([_p("ou:root", REGION, {"region": "UNKNOWN"})])
    record = S.setting("GWS.COMMONCONTROLS.15.1v1", _region_row(**change), sections)
    assert (record["verdict"], record["cell"]) == ("not_assessed", "setting_value_unusable")


@pytest.mark.parametrize("change", [{"op": "eq", "value": "US"}, {"op": "in", "value": ["US"]},
                                    {"op": "ne", "value": "US"}, {"op": "not_in", "value": ["US"]}])
def test_m1_a_string_row_without_a_vocabulary_is_a_programming_error(change):
    params = dict(_region_row(**change)["params"])
    del params["known"], params["source"]
    with pytest.raises(ValueError, match="Invalid GWS setting parameters"):
        S._params(params)


def test_m1_every_shipped_string_row_pins_its_vocabulary_with_a_cite():
    vocabularies = {
        "GWS.COMMONCONTROLS.5.1v1": ["STRONG", "WEAK"],
        "GWS.COMMONCONTROLS.7.1v1": ["AUTOMATICALLY_SEND_INVITATIONS", "PRESERVE_CONFLICTING_ACCOUNT",
                                     "REPLACE_CONFLICTING_ACCOUNT"],
        "GWS.COMMONCONTROLS.10.4v1": ["ACCESS_LEVEL_UNSPECIFIED", "ALLOW_SIGN_IN_ONLY", "ALLOW_SIGN_IN_SCOPES_ONLY",
                                      "BLOCK_ALL", "BLOCK_ALL_SCOPES", "UNSPECIFIED_UBER_BLOCK"],
        "GWS.COMMONCONTROLS.15.1v1": ["ANY_REGION", "EUROPE", "REGION_UNSPECIFIED", "US"],
        "GWS.COMMONCONTROLS.16.1v1": ["DISABLED", "ENABLED"],
        "GWS.COMMONCONTROLS.16.2v1": ["DISABLED", "ENABLED"],
        "GWS.COMMONCONTROLS.17.1v1": ["DISABLED", "ENABLED"],
    }
    folded = {"GWS.COMMONCONTROLS.5.1v1", "GWS.COMMONCONTROLS.16.1v1", "GWS.COMMONCONTROLS.16.2v1"}
    rows = {pid: row["params"] for pid, row in catalogue()["policies"].items() if row["kind"] == "setting"}
    assert {pid for pid, params in rows.items() if "known" in params} == set(vocabularies)
    for pid, known in vocabularies.items():
        assert rows[pid]["known"] == known, pid
        assert rows[pid]["source"].startswith("SG:scubagoggles/"), pid
        assert rows[pid].get("case", "exact") == ("fold" if pid in folded else "exact"), pid


@pytest.mark.parametrize("change", [
    {"known": ["US"]}, {"known": []}, {"known": "US"}, {"known": ["US", "US"]}, {"known": ["US", 1]},
    {"known": ["US", ""]}, {"known": ["EUROPE"]}, {"source": None}, {"source": ""}, {"case": True}, {"case": "FOLD"},
    {"case": "fold"}, {"known": ["US", "еU"]},
])
def test_m1_malformed_vocabulary_parameters_are_a_programming_error(change):
    params = dict(_region_row()["params"])
    if change.get("known") == ["US"]:
        params.update(op="eq", value=True, known=["US"])
    else:
        params.update(change)
    if change.get("source", 0) is None:
        del params["source"]
    if change.get("case") == "fold":
        params.update(known=["US", "Europe"], value="US")
    with pytest.raises(ValueError, match="Invalid GWS setting parameters"):
        S._params(params)


def test_l1_the_duration_grammar_takes_any_digit_count():
    assert S._violates("duration_gt", "1000000000000000s", "12h") is True
    assert S._violates("duration_gt", "0000000000000000000043200s", "12h") is False
