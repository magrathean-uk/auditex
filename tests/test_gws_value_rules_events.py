"""``setting_event`` (design M13 8.2, lane L12): the 12 log-based ScubaGoggles v1.1.0 policies.

Synthetic data only (ou:root, ou:a, group:g1); every expected verdict, cell and text is a literal.
"""
from __future__ import annotations

import copy

import pytest

from azure_tenant_audit.value_rules import gws
from azure_tenant_audit.value_rules.gws import events
from azure_tenant_audit.value_rules.gws.catalogue import catalogue

TENANT = {"as_of": "2026-11-25T12:00:00Z", "top_unit": "ou:root",
          "org_units": {"ou:root": None, "ou:a": "ou:root", "ou:b": "ou:a"}, "complete": True}
T1, T2, T3 = "2026-09-01T10:00:00Z", "2026-10-01T10:00:00Z", "2026-11-01T10:00:00+00:00"
DELETE = "DELETE_APPLICATION_SETTING"
CR_ON, CR_OFF = "CONTENT_REPORTING_STATE_ENABLED", "CONTENT_REPORTING_STATE_DISABLED"
ALL_CATEGORIES = ("[system_violation: HARASSMENT, system_violation: DISCRIMINATION, system_violation: EXPLICIT_CONTENT, "
                  "system_violation: SPAM, system_violation: CONFIDENTIAL_INFORMATION, "
                  "system_violation: SENSITIVE_INFORMATION, system_violation: OTHER]")
SIX_CATEGORIES = ("system_violation: HARASSMENT,system_violation: DISCRIMINATION,system_violation: EXPLICIT_CONTENT,"
                  "system_violation: SPAM,system_violation: CONFIDENTIAL_INFORMATION,system_violation: OTHER")

# policy: ([(setting name, compliant value, non-compliant value)], group-scoped, top-level delete violates)
ROWS = {
    "GWS.GMAIL.13.1v1": ([("OutOfDomainWarningProto disable_untrusted_recipient_warning", "false", "true")],
                         False, False),
    "GWS.GMAIL.16.1v1": ([("AttachmentDeepScanningSettingsProto deep_scanning_enabled", "true", "false")],
                         False, False),
    "GWS.COMMONCONTROLS.3.1v1": ([("SsoPolicyProto challenge_selection_behavior", "PERFORM_CHALLENGE_SELECTION",
                                   "BYPASS_ADDITIONAL_CHALLENGES")], False, False),
    "GWS.COMMONCONTROLS.3.2v1": ([("SsoPolicyProto sso_profile_challenge_selection_behavior",
                                   "SSO_PROFILES_PERFORM_CHALLENGE_SELECTION",
                                   "SSO_PROFILES_BYPASS_ADDITIONAL_CHALLENGES")], False, False),
    "GWS.CHAT.5.1v1": ([("ContentReportingProto one_on_one_reporting", CR_ON, CR_OFF),
                        ("ContentReportingProto group_chat_reporting", CR_ON, CR_OFF),
                        ("ContentReportingProto room_reporting", CR_ON, CR_OFF),
                        ("ContentReportingProto room_restrictions", "SPACE_RESTRICTIONS_NO_RESTRICTIONS",
                         "SPACE_RESTRICTIONS_DISCOVERABLE_SPACES_ONLY")], False, True),
    "GWS.CHAT.5.2v1": ([("ContentReportingProto report_types", ALL_CATEGORIES, SIX_CATEGORIES)], False, True),
    "GWS.MEET.6.1v1": ([("MeetGenAiSmartNotesDocAccessProto manage_smart_notes_doc_access", "false", "true")],
                       True, False),
    "GWS.MEET.6.2v1": ([("MeetGenAiSmartNotesDocAccessProto default_smart_notes_doc_access", "IN_DOMAIN",
                         "EVERYONE")], True, False),
    "GWS.GEMINI.1.1v1": ([("BardNonDuetEnablementProto enable_bard_non_duet_access", "false", "true")],
                         True, False),
    "GWS.GEMINI.2.1v1": ([("GenAiAlphaSettingsProto alpha_enabled", "false", "true")], True, False),
    "GWS.ASSUREDCONTROLS.2.1v1": ([(f"{app}NonRegionalizedFunctionalityStateSettingsProto state", "DISABLED",
                                    "ENABLED") for app in ("Calendar", "Docs", "Gmail", "Chat", "Meet", "Gemini")],
                                  True, False),
}
UNIT_ROWS = sorted(ROWS)
GEMINI_ON = {"complete": True, "policies": [
    {"unit": "ou:root", "unit_kind": "org_unit", "section": "gemini_app_service_status", "sort_order": 1,
     "value": {"serviceState": "ENABLED"}}]}

TEXT = {
    "no_unit_violates": "Requirement met: the top-level unit has a logged setting change for every setting this "
                        "policy reads, and the last change for every unit is compliant.",
    "unit_violates": "Requirement not met: the last logged setting change for at least one unit sets a "
                     "non-compliant value.",
    "no_setting_event": "Data unavailable: the admin logs hold no current setting change at the top-level unit for "
                        "every setting this policy reads; logs are kept about six months, and a reset to the default "
                        "is not logged as a value.",
    "event_value_unusable": "Data unusable: a relevant setting-change event has a missing, unknown or unreadable "
                            "value, time or unit, or two latest events disagree.",
    "event_read_incomplete": "Data unavailable: the admin setting-change event read was cut or incomplete, so the "
                             "last change per unit is not known.",
    "section_shape_unusable": "Data unusable: the tenant topology is cut, broken or of the wrong shape, or the "
                              "setting-change events, their log window or the policy section has the wrong shape.",
}


def _event(setting, value, unit="ou:root", time=T2, name="CHANGE_APPLICATION_SETTING"):
    return {"time": time, "event": name, "setting": setting, "new_value": value, "unit": unit, "application": None}


def _delete(setting, unit="ou:root", time=T3):
    return {"time": time, "event": DELETE, "setting": setting, "new_value": None, "unit": unit, "application": None}


def _sections(evs, policy="GWS.GMAIL.13.1v1", complete=True, tenant=None):
    sections = {"gws_tenant": copy.deepcopy(tenant or TENANT),
                "gws_setting_events": {"complete": complete, "window_start": "2026-05-25T00:00:00Z",
                                       "window_end": "2026-11-25T00:00:00Z", "events": evs}}
    if policy == "GWS.GEMINI.1.1v1":
        sections["gws_policies"] = copy.deepcopy(GEMINI_ON)
    return sections


def _good_top(policy, time=T2):
    return [_event(setting, good, time=time) for setting, good, _ in ROWS[policy][0]]


def _answer(policy, evs, **kwargs):
    record = gws.assess(policy, _sections(evs, policy, **kwargs))
    return record["verdict"], record["cell"]


MET = ("met", "no_unit_violates")
NOT_MET = ("not_met", "unit_violates")
NO_EVENT = ("not_assessed", "no_setting_event")
UNUSABLE = ("not_assessed", "event_value_unusable")
SHAPE = ("not_assessed", "section_shape_unusable")
TOPOLOGY = SHAPE  # a cut or broken topology (review M13-L12 B1)


def test_rows_are_the_twelve_log_based_policies():
    rows = {pid for pid, row in catalogue()["policies"].items() if row["kind"] == "setting_event"}
    assert rows == set(ROWS) | {"GWS.COMMONCONTROLS.2.1v1"}
    assert len(rows) == 12
    for pid in rows:
        events._slots(catalogue()["policies"][pid]["params"])  # every shipped row's params parse


def test_kind_texts_are_the_catalogued_constants():
    record = gws.assess("GWS.GMAIL.13.1v1", _sections(_good_top("GWS.GMAIL.13.1v1")))
    assert record == {"policy_id": "GWS.GMAIL.13.1v1", "verdict": "met", "reason_code": "no_unit_violates",
                      "reason_text": TEXT["no_unit_violates"], "cell": "no_unit_violates",
                      "cited_sections": ["gws_tenant", "gws_setting_events"], "detail": {}}
    cells = catalogue()["kinds"]["setting_event"]["cells"]
    for cell, text in TEXT.items():
        assert cells[cell]["reason_texts"] == [text]


# --- per row ----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("policy", UNIT_ROWS)
def test_met_when_every_top_level_setting_is_compliant(policy):
    assert _answer(policy, _good_top(policy)) == MET


@pytest.mark.parametrize("policy", UNIT_ROWS)
def test_not_met_when_a_child_unit_is_non_compliant(policy):
    settings = ROWS[policy][0]
    evs = _good_top(policy) + [_event(settings[-1][0], settings[-1][2], unit="ou:a")]
    assert _answer(policy, evs) == NOT_MET


@pytest.mark.parametrize("policy", UNIT_ROWS)
def test_no_top_level_event_is_not_assessed_d1(policy):
    assert _answer(policy, []) == NO_EVENT
    settings = ROWS[policy][0]
    # A compliant child alone says nothing about the top unit.
    assert _answer(policy, [_event(settings[0][0], settings[0][1], unit="ou:a")]) == NO_EVENT


@pytest.mark.parametrize("policy", UNIT_ROWS)
def test_violation_without_a_top_level_event_is_not_met(policy):
    settings = ROWS[policy][0]
    assert _answer(policy, [_event(settings[0][0], settings[0][2], unit="ou:b")]) == NOT_MET


@pytest.mark.parametrize("policy", UNIT_ROWS)
def test_read_incomplete_is_not_assessed(policy):
    assert _answer(policy, _good_top(policy), complete=False) == ("not_assessed", "event_read_incomplete")
    assert _answer(policy, _good_top(policy), complete=None) == ("not_assessed", "event_read_incomplete")


@pytest.mark.parametrize("policy", UNIT_ROWS)
@pytest.mark.parametrize("value", [None, 1, "", "UNKNOWN_ENUM_VALUE"])
def test_unusable_value_is_not_assessed(policy, value):
    evs = _good_top(policy, time=T1) + [_event(ROWS[policy][0][0][0], value, time=T2)]
    assert _answer(policy, evs) == UNUSABLE


@pytest.mark.parametrize("policy", UNIT_ROWS)
def test_later_event_overrides_an_earlier_one(policy):
    setting, good, bad = ROWS[policy][0][0]
    rest = _good_top(policy)[1:]
    assert _answer(policy, [_event(setting, bad, time=T1), _event(setting, good, time=T3)] + rest) == MET
    # Read order never matters: the latest time decides.
    assert _answer(policy, [_event(setting, good, time=T3), _event(setting, bad, time=T1)] + rest) == MET
    assert _answer(policy, [_event(setting, good, time=T1), _event(setting, bad, time=T3)] + rest) == NOT_MET


@pytest.mark.parametrize("policy", UNIT_ROWS)
def test_group_unit(policy):
    setting, good, bad = ROWS[policy][0][0]
    evs = _good_top(policy) + [_event(setting, bad, unit="group:g1")]
    # Group-scoped where the Rego reads groups; otherwise a group event is dropped (FilterEventsOU).
    assert _answer(policy, evs) == (NOT_MET if ROWS[policy][1] else MET)
    assert _answer(policy, _good_top(policy) + [_event(setting, good, unit="group:g1")]) == MET


@pytest.mark.parametrize("policy", UNIT_ROWS)
def test_delete_setting(policy):
    setting, _, bad = ROWS[policy][0][0]
    # Below the top unit a delete hands the setting back to the parent.
    evs = _good_top(policy) + [_event(setting, bad, unit="ou:a", time=T1), _delete(setting, unit="ou:a")]
    assert _answer(policy, evs) == MET
    # At the top unit it returns the setting to a default no log shows (D1), unless the Rego counts it as off.
    evs = _good_top(policy) + [_delete(setting)]
    assert _answer(policy, evs) == (NOT_MET if ROWS[policy][2] else NO_EVENT)
    # A later change after the delete decides again.
    evs = _good_top(policy, time=T1) + [_delete(setting, time=T2), _event(setting, ROWS[policy][0][0][1], time=T3)]
    assert _answer(policy, evs) == MET


# --- shared edges -----------------------------------------------------------------------------------------------------

S13 = "OutOfDomainWarningProto disable_untrusted_recipient_warning"


def test_tie_at_the_latest_time_is_unusable_but_agreement_is_not():
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false"), _event(S13, "true")]) == UNUSABLE
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false"), _event(S13, "false")]) == MET
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false"), _delete(S13, time=T2)]) == UNUSABLE


@pytest.mark.parametrize("time", [None, "", "yesterday", "2026-10-01T10:00:00", "2026-10-01", 5])
def test_unreadable_time_is_unusable(time):
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false", time=T1), _event(S13, "false", time=time)]) == UNUSABLE


@pytest.mark.parametrize("unit", [None, "", "root", "ou:", "ou:a/group:g1", 7])
def test_an_event_that_cannot_be_placed_never_answers_met(unit):
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false"), _event(S13, "true", unit=unit)]) == UNUSABLE
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false"), _event(S13, None, unit=unit)]) == UNUSABLE
    # Even a compliant value there leaves the stream ambiguous (review M13-L12 B2).
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false"), _event(S13, "false", unit=unit)]) == UNUSABLE
    # A delete there might be the top unit's (lens review): never met, whichever way the row counts it.
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false"), _delete(S13, unit=unit)]) == UNUSABLE
    chat = _good_top("GWS.CHAT.5.2v1") + [_delete("ContentReportingProto report_types", unit=unit)]
    assert _answer("GWS.CHAT.5.2v1", chat) == UNUSABLE


def test_deleted_ou_is_skipped_only_on_a_complete_topology():
    evs = [_event(S13, "false"), _event(S13, "true", unit="ou:gone")]
    assert _answer("GWS.GMAIL.13.1v1", evs) == MET
    assert _answer("GWS.GMAIL.13.1v1", evs, tenant={**TENANT, "complete": False}) == TOPOLOGY


def test_violation_wins_over_unusable_values():
    evs = [_event(S13, "false"), _event(S13, "maybe", unit="ou:a"), _event(S13, "true", unit="ou:b")]
    assert _answer("GWS.GMAIL.13.1v1", evs) == NOT_MET


def test_unusable_wins_over_no_top_level_event():
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "maybe", unit="ou:a")]) == UNUSABLE


def test_other_settings_never_reach_the_rule():
    evs = [_event(S13, "false"), _event("SomeOtherProto field", None, unit=None, time="bad")]
    assert _answer("GWS.GMAIL.13.1v1", evs) == MET


@pytest.mark.parametrize("change", [
    lambda s: s.update(gws_setting_events={"complete": True}),
    lambda s: s.update(gws_setting_events={"complete": True, "events": {}}),
    lambda s: s.update(gws_setting_events=[]),
    lambda s: s["gws_setting_events"]["events"].append("event"),
    lambda s: s["gws_setting_events"]["events"].append({"setting": S13}),
    lambda s: s["gws_setting_events"]["events"].append({"event": "X", "setting": 3}),
    lambda s: s.update(gws_tenant={"top_unit": "root", "org_units": {}}),
    lambda s: s.update(gws_tenant={"top_unit": "ou:root"}),
])
def test_wrong_section_shape_is_unusable(change):
    sections = _sections([_event(S13, "false")])
    change(sections)
    record = gws.assess("GWS.GMAIL.13.1v1", sections)
    assert (record["verdict"], record["cell"], record["reason_text"]) == (
        "not_assessed", "section_shape_unusable", TEXT["section_shape_unusable"])


def test_missing_section_is_the_shared_gate():
    record = gws.assess("GWS.GMAIL.13.1v1", {"gws_tenant": TENANT,
                                             "gws_setting_events": {"collection_status": "not_collected"}})
    assert (record["cell"], record["cited_sections"]) == ("section_not_collected", ["gws_setting_events"])


# --- row specifics ----------------------------------------------------------------------------------------------------

def test_commoncontrols_2_1_reads_the_event_name_with_no_unit():
    caa = "TOGGLE_CAA_ENABLEMENT"
    assert _answer("GWS.COMMONCONTROLS.2.1v1", [_event(None, "ENABLED", unit=None, name=caa)]) == MET
    assert _answer("GWS.COMMONCONTROLS.2.1v1", [_event(None, "DISABLED", unit="ou:a", name=caa)]) == NOT_MET
    assert _answer("GWS.COMMONCONTROLS.2.1v1", [_event(None, "ENABLED", time=T1, name=caa),
                                                _event(None, "DISABLED", time=T3, name=caa)]) == NOT_MET
    assert _answer("GWS.COMMONCONTROLS.2.1v1", [_event(None, "DISABLED", time=T1, name=caa),
                                                _event(None, "ENABLED", time=T3, name=caa)]) == MET
    assert _answer("GWS.COMMONCONTROLS.2.1v1", [_event(None, "PAUSED", name=caa)]) == UNUSABLE
    assert _answer("GWS.COMMONCONTROLS.2.1v1", [_event(caa, "ENABLED")]) == NO_EVENT
    assert _answer("GWS.COMMONCONTROLS.2.1v1", []) == NO_EVENT
    assert _answer("GWS.COMMONCONTROLS.2.1v1", [_event(None, "ENABLED", unit=None, name=caa)],
                   complete=False) == ("not_assessed", "event_read_incomplete")


def test_chat_5_1_needs_all_four_settings_at_the_top_unit():
    evs = _good_top("GWS.CHAT.5.1v1")
    assert _answer("GWS.CHAT.5.1v1", evs[:3]) == NO_EVENT
    assert _answer("GWS.CHAT.5.1v1", evs[1:]) == NO_EVENT
    restriction = "ContentReportingProto room_restrictions"
    assert _answer("GWS.CHAT.5.1v1", evs + [_delete(restriction)]) == NOT_MET
    assert _answer("GWS.CHAT.5.1v1", evs + [_event(restriction, "SPACE_RESTRICTIONS_DISCOVERABLE_SPACES_ONLY",
                                                   unit="ou:a")]) == NOT_MET


@pytest.mark.parametrize(("value", "expected"), [
    (ALL_CATEGORIES, MET),
    (ALL_CATEGORIES.replace(", ", ",   ").strip("[]"), MET),
    ("system_violation:   HARASSMENT, system_violation: DISCRIMINATION, system_violation: EXPLICIT_CONTENT, "
     "system_violation: SPAM, system_violation: CONFIDENTIAL_INFORMATION, system_violation: SENSITIVE_INFORMATION, "
     "system_violation: OTHER, system_violation: NEW_CATEGORY", MET),
    (SIX_CATEGORIES, NOT_MET),
    ("[]", NOT_MET),
    ("[ ]", NOT_MET),
    (None, UNUSABLE),
    # Not a category list: never a read value (review M13-L12 B4).
    ("", UNUSABLE),
    ("UNKNOWN", UNUSABLE),
    (ALL_CATEGORIES + "[,,", UNUSABLE),
    (ALL_CATEGORIES.replace("SPAM, ", "SPAM,, "), UNUSABLE),
    (ALL_CATEGORIES.rstrip("]"), UNUSABLE),
    ("[", UNUSABLE),
    (ALL_CATEGORIES.replace("system_violation: SPAM", "system_violation:\u00a0SPAM"), UNUSABLE),
])
def test_chat_5_2_needs_the_seven_categories(value, expected):
    assert _answer("GWS.CHAT.5.2v1", [_event("ContentReportingProto report_types", value)]) == expected


def test_meet_6_2_known_compliant_values():
    setting = "MeetGenAiSmartNotesDocAccessProto default_smart_notes_doc_access"
    assert _answer("GWS.MEET.6.2v1", [_event(setting, "HOSTS_AND_COHOSTS_ONLY")]) == MET
    assert _answer("GWS.MEET.6.2v1", [_event(setting, "IN_DOMAIN")]) == MET
    assert _answer("GWS.MEET.6.2v1", [_event(setting, "EVERYONE", unit="group:g1")]) == NOT_MET


def test_gemini_2_1_merges_both_setting_names_into_one_stream():
    alpha, beta = "GenAiAlphaSettingsProto alpha_enabled", "Beta Gemini Features Beta Features enabled"
    assert _answer("GWS.GEMINI.2.1v1", [_event(beta, "false")]) == MET
    assert _answer("GWS.GEMINI.2.1v1", [_event(alpha, "true", time=T1), _event(beta, "false", time=T3)]) == MET
    assert _answer("GWS.GEMINI.2.1v1", [_event(alpha, "false", time=T1), _event(beta, "true", time=T3)]) == NOT_MET


def test_assured_2_1_needs_all_six_products_at_the_top_unit():
    evs = _good_top("GWS.ASSUREDCONTROLS.2.1v1")
    assert len(evs) == 6
    assert _answer("GWS.ASSUREDCONTROLS.2.1v1", evs) == MET
    for index in range(6):
        assert _answer("GWS.ASSUREDCONTROLS.2.1v1", evs[:index] + evs[index + 1:]) == NO_EVENT


# --- GEMINI.1.1 service gate ------------------------------------------------------------------------------------------

BARD = "BardNonDuetEnablementProto enable_bard_non_duet_access"


def _status(unit, state, unit_kind="org_unit", sort_order=1):
    return {"unit": unit, "unit_kind": unit_kind, "section": "gemini_app_service_status", "sort_order": sort_order,
            "value": {"serviceState": state} if state is not None else {}}


def _gemini(evs, statuses, complete=True):
    sections = _sections(evs, "GWS.GEMINI.1.1v1")
    sections["gws_policies"] = {"complete": complete, "policies": statuses}
    record = gws.assess("GWS.GEMINI.1.1v1", sections)
    return record["verdict"], record["cell"]


def test_gemini_1_1_cites_its_three_sections():
    record = gws.assess("GWS.GEMINI.1.1v1", _sections([_event(BARD, "false")], "GWS.GEMINI.1.1v1"))
    assert record["cited_sections"] == ["gws_tenant", "gws_policies", "gws_setting_events"]
    assert record["cell"] == "no_unit_violates"


def test_gemini_1_1_service_gate():
    on, off = _status("ou:root", "ENABLED"), _status("ou:root", "DISABLED")
    bad_top = [_event(BARD, "true")]
    assert _gemini(bad_top, [on]) == NOT_MET
    assert _gemini(bad_top, [off]) == ("not_applicable", "service_off_everywhere")
    assert _gemini([], [off]) == ("not_applicable", "service_off_everywhere")
    assert _gemini(bad_top, []) == ("not_assessed", "service_status_absent")
    assert _gemini(bad_top, [_status("ou:root", "SUSPENDED")]) == ("not_assessed", "service_status_absent")
    assert _gemini(bad_top, [_status("ou:root", None)]) == ("not_assessed", "service_status_absent")
    assert _gemini(bad_top, [on], complete=False) == ("not_assessed", "policy_read_incomplete")
    assert _gemini(bad_top, [{"unit": "ou:root"}]) == ("not_assessed", "section_shape_unusable")
    # Off at a child: its own bad value is skipped when nothing below it has the service on. A unit without its own
    # status takes the top unit's (AppEnabled has no parent walk), so ou:b needs its own here.
    child = [_event(BARD, "false"), _event(BARD, "true", unit="ou:a")]
    assert _gemini(child, [on, _status("ou:a", "DISABLED"), _status("ou:b", "DISABLED")]) == MET
    assert _gemini(child, [on, _status("ou:a", "DISABLED")]) == UNUSABLE
    # ... but not when a unit below it could inherit the value with the service on.
    assert _gemini(child, [on, _status("ou:a", "DISABLED"), _status("ou:b", "ENABLED")]) == UNUSABLE
    # An incomplete topology may hide a unit below the off child that takes the top unit's service state (lens review).
    partial = {**TENANT, "complete": False}
    sections = _sections(child, "GWS.GEMINI.1.1v1", tenant=partial)
    sections["gws_policies"] = {"complete": True, "policies": [on, _status("ou:a", "DISABLED"),
                                                               _status("ou:b", "DISABLED")]}
    record = gws.assess("GWS.GEMINI.1.1v1", sections)
    assert (record["verdict"], record["cell"]) == TOPOLOGY
    # Off at the top, on at a child that could inherit the top's bad value.
    assert _gemini(bad_top, [off, _status("ou:a", "ENABLED")]) == UNUSABLE
    # Unknown at the top with a unit explicitly on: the top's bad value is unusable, the child's is a violation.
    assert _gemini(bad_top, [_status("ou:a", "ENABLED")]) == UNUSABLE
    assert _gemini([_event(BARD, "false"), _event(BARD, "true", unit="ou:a")],
                   [_status("ou:a", "ENABLED")]) == NOT_MET
    # A tie at the deciding rank is unknown (D11), never on.
    assert _gemini(bad_top, [on, _status("ou:root", "DISABLED")]) == ("not_assessed", "service_status_absent")


def test_gemini_1_1_group_event_needs_the_service_on_everywhere():
    evs = [_event(BARD, "false"), _event(BARD, "true", unit="group:g1")]
    assert _gemini(evs, [_status("ou:root", "ENABLED")]) == NOT_MET
    assert _gemini(evs, [_status("ou:root", "ENABLED"), _status("ou:a", "DISABLED")]) == UNUSABLE


# --- params -----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("params", [
    {}, {"setting_slots": []}, {"setting_slots": [{}]},
    {"setting_slots": [{"setting_names": ["x"], "event_names": ["x"], "good_values": ["a"], "bad_values": ["b"]}]},
    {"setting_slots": [{"setting_names": ["x"], "good_values": ["a"]}]},
    {"setting_slots": [{"setting_names": ["x"], "good_values": ["a"], "bad_values": ["a"]}]},
    {"setting_slots": [{"setting_names": [], "good_values": ["a"], "bad_values": ["b"]}]},
    {"setting_slots": [{"setting_names": ["x"], "required_values": ["a"], "good_values": ["a"]}]},
    {"setting_slots": [{"setting_names": ["x"], "good_values": ["a"], "bad_values": ["b"]}], "top_delete": "good"},
    {"setting_slots": [{"setting_names": ["x"], "good_values": ["a"], "bad_values": ["b"]}], "groups": "yes"},
])
def test_malformed_params_are_a_product_fault(params):
    with pytest.raises(ValueError):
        events._slots(params)


# --- review M13-L12 repair --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("tenant", [
    {**TENANT, "complete": False},
    {key: value for key, value in TENANT.items() if key != "complete"},
    {**TENANT, "org_units": {"ou:root": None, "ou:a": "ou:a"}},
])
def test_b1_a_cut_or_broken_topology_concludes_nothing(tenant):
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false")], tenant=tenant) == TOPOLOGY
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "true")], tenant=tenant) == TOPOLOGY


def test_b1_gemini_universal_service_states_need_a_complete_topology():
    partial = {**TENANT, "org_units": {"ou:root": None, "ou:a": "ou:root"}, "complete": False}

    def run(evs, state):
        sections = _sections(evs, "GWS.GEMINI.1.1v1", tenant=partial)
        sections["gws_policies"] = {"complete": True, "policies": [_status("ou:root", state)]}
        record = gws.assess("GWS.GEMINI.1.1v1", sections)
        return record["verdict"], record["cell"]

    assert run([_event(BARD, "false"), _event(BARD, "true", unit="group:g1")], "ENABLED") == TOPOLOGY
    assert run([_event(BARD, "false")], "DISABLED") == TOPOLOGY


def test_b2_an_unreadable_event_identity_never_confirms():
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false", name="")]) == UNUSABLE
    reset = {**_delete(S13), "setting": None}
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false", time=T1), reset]) == UNUSABLE
    assert _answer("GWS.COMMONCONTROLS.2.1v1", [_event(None, "ENABLED", unit=None, name="TOGGLE_CAA_ENABLEMENT"),
                                                _event(None, "DISABLED", unit=None, name="", time=T3)]) == UNUSABLE
    # A later unplaced change might have superseded the child violation.
    evs = [_event(S13, "false", time=T1), _event(S13, "true", unit="ou:a", time=T2),
           _event(S13, "false", unit=None, time=T3)]
    assert _answer("GWS.GMAIL.13.1v1", evs) == UNUSABLE
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false"), _event(S13, "false", unit=None,
                                                                      time="broken time")]) == UNUSABLE


def test_b2_isolation_and_proven_older_ambiguity_are_kept():
    # A known other setting and a setting-less non-setting event never reach the rule.
    toggle = _event(None, "DISABLED", unit=None, name="TOGGLE_CAA_ENABLEMENT", time=T3)
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false"), toggle]) == MET
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false"), _delete("SomeOtherProto field", unit=None)]) == MET
    # An ambiguous change proven older than the violation cannot have superseded it.
    evs = [_event(S13, "false", time=T2), _event(S13, "true", unit="ou:a", time=T3),
           _event(S13, "false", unit=None, time=T1)]
    assert _answer("GWS.GMAIL.13.1v1", evs) == NOT_MET


def _windowed(evs, start, end):
    sections = _sections(evs)
    sections["gws_setting_events"].update(window_start=start, window_end=end)
    for key in ("window_start", "window_end"):
        if sections["gws_setting_events"][key] is None:
            del sections["gws_setting_events"][key]
    record = gws.assess("GWS.GMAIL.13.1v1", sections)
    return record["verdict"], record["cell"]


@pytest.mark.parametrize(("start", "end"), [
    (None, None), ("2026-05-25T00:00:00Z", None), (None, "2026-11-25T00:00:00Z"),
    ("2026-12-01T00:00:00Z", "2026-11-25T00:00:00Z"), ("2026-11-25T00:00:00Z", "2026-11-25T00:00:00Z"),
    ("2026-05-25", "2026-11-25T00:00:00Z"), ("2026-05-25T00:00:00Z", "2026-11-25x00:00:00Z"),
])
def test_b3_a_missing_or_invalid_window_concludes_nothing(start, end):
    assert _windowed([_event(S13, "false")], start, end) == SHAPE


@pytest.mark.parametrize("time", ["2026-12-01T10:00:00Z", "2026-05-24T23:59:59Z", "2026-10-01x10:00:00+00:00",
                                  "2026-10-01 10:00:00+00:00", "2026-10-01T10:00:00+0000", "2026-10-01T10:00:00.Z",
                                  "2026-10-01T10:00:60Z", "\u0662026-10-01T10:00:00Z"])
def test_b3_an_event_time_outside_the_window_or_not_rfc3339_is_unusable(time):
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false", time=time)]) == UNUSABLE


@pytest.mark.parametrize("time", ["2026-05-25T00:00:00Z", "2026-11-25T00:00:00Z", "2026-10-01t10:00:00z",
                                  "2026-10-01T12:00:00+02:00", "2026-10-01T10:00:00.123456789123Z"])
def test_b3_rfc3339_times_inside_the_window_are_read(time):
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false", time=time)]) == MET


def test_b5_chat_5_1_top_violation_needs_all_four_top_settings():
    one = [_event("ContentReportingProto one_on_one_reporting", CR_OFF)]
    assert _answer("GWS.CHAT.5.1v1", one) == NO_EVENT
    assured = [_event("GmailNonRegionalizedFunctionalityStateSettingsProto state", "ENABLED")]
    assert _answer("GWS.ASSUREDCONTROLS.2.1v1", assured) == NO_EVENT
    # With all four present the top violation counts; a child violation counts on its own (D17, D19).
    evs = _good_top("GWS.CHAT.5.1v1")
    assert _answer("GWS.CHAT.5.1v1", evs[1:] + [_event("ContentReportingProto one_on_one_reporting", CR_OFF)]) \
        == NOT_MET
    assert _answer("GWS.CHAT.5.1v1", one + [_event("ContentReportingProto room_reporting", CR_OFF,
                                                   unit="ou:a")]) == NOT_MET


def test_m1_event_order_keeps_nanoseconds():
    first, second = "2026-10-01T10:00:00.000000001Z", "2026-10-01T10:00:00.000000002Z"
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false", time=first), _event(S13, "true", time=second)]) \
        == NOT_MET
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "true", time=first), _event(S13, "false", time=second)]) == MET
    # Same instant in two spellings is still a tie.
    assert _answer("GWS.GMAIL.13.1v1", [_event(S13, "false", time="2026-10-01T10:00:00.5Z"),
                                        _event(S13, "true", time="2026-10-01T11:00:00.500+01:00")]) == UNUSABLE


def test_m2_unreadable_value_in_a_proven_off_leaf_is_out_of_scope():
    leaf = {**TENANT, "org_units": {"ou:root": None, "ou:a": "ou:root"}}
    evs = [_event(BARD, "false"), _event(BARD, None, unit="ou:a", time=T3)]
    sections = _sections(evs, "GWS.GEMINI.1.1v1", tenant=leaf)
    sections["gws_policies"] = {"complete": True, "policies": [_status("ou:root", "ENABLED"),
                                                               _status("ou:a", "DISABLED")]}
    record = gws.assess("GWS.GEMINI.1.1v1", sections)
    assert (record["verdict"], record["cell"]) == MET
    # On, or off with a unit below that could inherit, it still weakens the answer.
    sections["gws_policies"]["policies"][1] = _status("ou:a", "ENABLED")
    record = gws.assess("GWS.GEMINI.1.1v1", sections)
    assert (record["verdict"], record["cell"]) == UNUSABLE
    assert _gemini(evs, [_status("ou:root", "ENABLED"), _status("ou:a", "DISABLED")]) == UNUSABLE
