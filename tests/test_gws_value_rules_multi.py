"""``settings_multi`` (M13-L09): the 14 multi-field and mode-dependent GWS policies, synthetic data only.

The vectors in ``tests/fixtures/gws-value-rules/multi.jsonl`` replay through ``test_gws_value_rules_replay.py``; this
file pins the rows, the params contract, the per-row vector coverage and the unknown-is-not-safe rule (design 8.4).
Every expected value is a literal.
"""
from __future__ import annotations

import copy
import json
from collections import defaultdict
from pathlib import Path

import pytest

from azure_tenant_audit.value_rules import gws
from azure_tenant_audit.value_rules.gws import multi
from azure_tenant_audit.value_rules.gws.catalogue import catalogue

VECTORS = [json.loads(line) for line in
           (Path(__file__).parent / "fixtures" / "gws-value-rules" / "multi.jsonl").read_text().splitlines() if line]

ROWS = {
    "GWS.GMAIL.5.5v1": ("own_any_bad", "gmail"),
    "GWS.GMAIL.7.6v1": ("own_any_bad", "gmail"),
    "GWS.GMAIL.9.1v1": ("own_any_bad", "gmail"),
    "GWS.DRIVEDOCS.1.2v1": ("mode_branch", "drive_and_docs"),
    "GWS.DRIVEDOCS.1.3v1": ("mode_branch", "drive_and_docs"),
    "GWS.DRIVEDOCS.1.4v1": ("mode_branch", "drive_and_docs"),
    "GWS.DRIVEDOCS.1.5v1": ("mode_branch", "drive_and_docs"),
    "GWS.DRIVEDOCS.1.7v1": ("mode_branch", "drive_and_docs"),
    "GWS.DRIVEDOCS.3.1v1": ("effective_any_bad", "drive_and_docs"),
    "GWS.DRIVEDOCS.5.1v1": ("effective_all_bad", "drive_and_docs"),
    "GWS.GROUPS.4.1v1": ("own_any_bad", "groups_for_business"),
    "GWS.CHAT.4.1v1": ("effective_all_bad", "chat"),
    "GWS.COMMONCONTROLS.11.1v1": ("mode_branch", None),
    "GWS.COMMONCONTROLS.12.1v1": ("own_any_bad", None),
}
# Rows whose fields all have a pinned default, so the top unit can never lack a value.
DEFAULTED = {"GWS.DRIVEDOCS.1.2v1", "GWS.DRIVEDOCS.1.3v1", "GWS.DRIVEDOCS.1.4v1", "GWS.DRIVEDOCS.1.5v1",
             "GWS.DRIVEDOCS.1.7v1", "GWS.GROUPS.4.1v1", "GWS.CHAT.4.1v1", "GWS.COMMONCONTROLS.11.1v1"}
TENANT = {"as_of": "2026-11-25T12:00:00Z", "top_unit": "ou:root", "org_units": {"ou:root": None, "ou:a": "ou:root"},
          "complete": True}


def _rows() -> dict[str, dict]:
    return {pid: row for pid, row in catalogue()["policies"].items() if row["kind"] == "settings_multi"}


def test_the_fourteen_rows_and_their_sub_kinds():
    rows = _rows()
    assert sorted(rows) == sorted(ROWS)
    for policy_id, row in rows.items():
        assert row["sections"] == ["gws_tenant", "gws_policies"]
        assert (row["params"]["kind"], row["params"]["service"]) == ROWS[policy_id]
    assert multi.KINDS == {"settings_multi": multi.settings_multi}
    assert gws._registry()["settings_multi"] is multi.settings_multi


def test_every_shipped_row_has_valid_params():
    for row in _rows().values():
        multi._params(row["params"])


def test_drive_rows_branch_on_the_documented_modes():
    for policy_id in ("GWS.DRIVEDOCS.1.2v1", "GWS.DRIVEDOCS.1.3v1", "GWS.DRIVEDOCS.1.4v1", "GWS.DRIVEDOCS.1.5v1",
                      "GWS.DRIVEDOCS.1.7v1"):
        params = _rows()[policy_id]["params"]
        assert params["mode"] == {"section": "drive_and_docs_external_sharing", "field": "externalSharingMode",
                                  "values": ["ALLOWED", "ALLOWLISTED_DOMAINS", "DISALLOWED"]}
    branches = {policy_id: sorted((check["mode"], check["field"], check["scope"])
                                  for check in _rows()[policy_id]["params"]["checks"])
                for policy_id in ("GWS.DRIVEDOCS.1.2v1", "GWS.DRIVEDOCS.1.5v1")}
    assert branches == {
        "GWS.DRIVEDOCS.1.2v1": [("ALLOWLISTED_DOMAINS", "allowReceivingFilesOutsideAllowlistedDomains", "effective"),
                                ("DISALLOWED", "allowReceivingExternalFiles", "own")],
        "GWS.DRIVEDOCS.1.5v1": [("ALLOWED", "allowPublishingFiles", "effective"),
                                ("ALLOWLISTED_DOMAINS", "allowPublishingFiles", "effective")]}


def test_takeout_reads_the_status_and_the_nine_app_sections():
    sections = [check["section"] for check in _rows()["GWS.COMMONCONTROLS.12.1v1"]["params"]["checks"]]
    assert sections == ["takeout_service_status", "blogger_user_takeout", "books_user_takeout",
                        "location_history_user_takeout", "maps_user_takeout", "pay_user_takeout",
                        "photos_user_takeout", "play_user_takeout", "play_console_user_takeout",
                        "youtube_user_takeout"]


GOOD = {"kind": "effective_any_bad", "service": None, "checks": [
    {"section": "drive_and_docs_file_security_update", "field": "allowUsersToManageUpdate", "good": [False]}]}


@pytest.mark.parametrize("change", [
    lambda p: p.update(kind="setting"),
    lambda p: p.pop("service"),
    lambda p: p.update(service=""),
    lambda p: p.update(service="nosuchservice"),
    lambda p: p.update(checks=[]),
    lambda p: p.update(extra=1),
    lambda p: p.update(required="any"),  # only own_any_bad takes it
    lambda p: p["checks"][0].update(field="noSuchField"),
    lambda p: p["checks"][0].update(section="no_such_section"),
    lambda p: p["checks"][0].update(good=[]),
    lambda p: p["checks"][0].update(good=["false"]),
    lambda p: p["checks"][0].update(values=["A"]),  # a bool field has no value list
    lambda p: p["checks"][0].update(mode="ALLOWED"),  # only mode_branch checks carry a mode
    lambda p: p["checks"].append(copy.deepcopy(p["checks"][0])),
    lambda p: p["checks"].append({"section": "drive_and_docs_file_security_update", "field": "securityUpdate",
                                  "good": ["APPLY_TO_IMPACTED_FILES"]}),  # an enum needs its value list
    lambda p: p["checks"].append({"section": "drive_and_docs_file_security_update", "field": "securityUpdate",
                                  "good": ["OTHER"], "values": ["APPLY_TO_IMPACTED_FILES"]}),
    lambda p: p.update(kind="own_any_bad"),  # without ``required``
    lambda p: p.update(kind="mode_branch"),  # without ``mode``
])
def test_malformed_params_are_refused(change):
    params = copy.deepcopy(GOOD)
    multi._params(params)
    change(params)
    with pytest.raises(ValueError):
        multi._params(params)


def test_every_row_has_the_lane_vector_set():
    cells = defaultdict(set)
    for vector in VECTORS:
        cells[vector["policy"]].add(vector["cell"])
    for policy_id, (_, service) in ROWS.items():
        need = {"no_unit_violates", "unit_violates", "section_not_collected", "policy_read_incomplete",
                "section_shape_unusable", "setting_value_unusable"}
        if service:
            need |= {"service_off_everywhere", "service_status_absent"}
        if policy_id not in DEFAULTED:
            need.add("setting_absent")
        assert need <= cells[policy_id], (policy_id, sorted(need - cells[policy_id]))


def test_the_kind_specific_cases_are_present():
    notes = {vector["vector_id"] for vector in VECTORS}
    assert {"multi-gmail55-group", "multi-gmail55-sub-ou", "multi-gmail55-bad-wins", "multi-gmail91-merge",
            "multi-drive12-sub-mode-from-top", "multi-drive12-sub-field-from-top", "multi-drive13-other-branch",
            "multi-drive13-sub-wrong-branch", "multi-drive51-sub-effective", "multi-chat41-sub-effective",
            "multi-groups41-other-field", "multi-cc121-status-absent", "multi-gmail91-tie",
            "multi-drive31-top-off-inherit", "multi-groups41-top-off-inherit"} <= notes
    assert {vector["divergence"] for vector in VECTORS if "divergence" in vector} == {"D3", "D11", "D12"}


@pytest.mark.parametrize("vector", VECTORS, ids=[vector["vector_id"] for vector in VECTORS])
def test_read_order_never_changes_the_answer(vector):
    sections = copy.deepcopy(vector["sections"])
    policies = sections.get("gws_policies", {}).get("policies")
    if not isinstance(policies, list):
        pytest.skip("no policy list to reorder")
    policies.reverse()
    record = gws.assess(vector["policy"], sections)
    assert (record["verdict"], record["cell"]) == (vector["verdict"], vector["cell"])


def _assess(policy_id: str, policies: list) -> dict:
    return gws.assess(policy_id, {"gws_tenant": TENANT, "gws_policies": {"complete": True, "policies": policies}})


@pytest.mark.parametrize("policy_id", sorted(ROWS))
@pytest.mark.parametrize("junk", [None, "", 0, "true", [], {}, 1.5])
def test_junk_values_never_answer_met(policy_id, junk):
    """Unknown is not safe: every participating field at junk, at the top unit and in a sub-unit."""
    row = _rows()[policy_id]
    params = row["params"]
    checks = params["checks"] + ([params["mode"]] if "mode" in params else [])
    values: dict[str, dict] = defaultdict(dict)
    for check in checks:
        values[check["section"]][check["field"]] = junk
    status = [{"unit": "ou:root", "unit_kind": "org_unit", "section": f"{params['service']}_service_status",
               "sort_order": 1, "value": {"serviceState": "ENABLED"}}] if params["service"] else []
    for unit in ("ou:root", "ou:a"):
        policies = status + [{"unit": unit, "unit_kind": "org_unit", "section": section, "sort_order": 1,
                              "value": dict(fields)} for section, fields in values.items()]
        record = _assess(policy_id, policies)
        # In a sub-unit a defaulted top unit may still violate on its own (DRIVEDOCS 1.4); it never answers met.
        assert record["verdict"] != "met", (unit, record["cell"])
        if unit == "ou:root":
            assert record["cell"] == "setting_value_unusable"


@pytest.mark.parametrize("policy_id", sorted(ROWS))
def test_answers_carry_only_constant_texts(policy_id):
    texts = {(vector["cell"], gws.assess(vector["policy"], copy.deepcopy(vector["sections"]))["reason_text"])
             for vector in VECTORS if vector["policy"] == policy_id}
    for _, text in texts:
        assert "ou:" not in text and "group:" not in text and "example." not in text
    assert len({cell for cell, _ in texts}) == len(texts)


def test_a_non_mapping_unit_section_is_unusable_not_absent():
    status = {"unit": "ou:root", "unit_kind": "org_unit", "section": "drive_and_docs_service_status",
              "sort_order": 1, "value": {"serviceState": "ENABLED"}}
    good = {"unit": "ou:root", "unit_kind": "org_unit", "section": "drive_and_docs_file_security_update",
            "sort_order": 1, "value": {"allowUsersToManageUpdate": False, "securityUpdate": "APPLY_TO_IMPACTED_FILES"}}
    tied = [{"unit": "ou:a", "unit_kind": "org_unit", "section": "drive_and_docs_file_security_update",
             "sort_order": 1, "value": {"allowUsersToManageUpdate": flag}} for flag in (True, False)]
    record = _assess("GWS.DRIVEDOCS.3.1v1", [status, good, *tied])
    assert record["cell"] == "setting_value_unusable"


# Repair round (M13-L09 review, 25 Nov 2026): mixed evidence. Unreadable never confirms met or not_met unless a
# violation is positively read on readable data for that unit. Every expected cell is a literal.
TENANT_AB = {"as_of": "2026-11-25T12:00:00Z", "top_unit": "ou:root",
             "org_units": {"ou:root": None, "ou:a": "ou:root", "ou:b": "ou:root"}, "complete": True}


def _p(unit: str, section: str, value) -> dict:
    return {"unit": unit, "unit_kind": "org_unit", "section": section, "sort_order": 1, "value": value}


def _cell(policy_id: str, policies: list) -> tuple[str, str]:
    record = gws.assess(policy_id, {"gws_tenant": TENANT_AB, "gws_policies": {"complete": True, "policies": policies}})
    return record["verdict"], record["cell"]


UNUSABLE_CELL = ("not_assessed", "setting_value_unusable")


@pytest.mark.parametrize(("policy_id", "policies", "expected"), [
    # B1: one field read as compliant must not hide an unreadable or absent partner field.
    ("GWS.DRIVEDOCS.5.1v1", [_p("ou:root", "drive_and_docs_service_status", {"serviceState": "ENABLED"}),
                             _p("ou:root", "drive_and_docs_drive_for_desktop",
                                {"allowDriveForDesktop": None, "restrictToAuthorizedDevices": True})], UNUSABLE_CELL),
    ("GWS.DRIVEDOCS.5.1v1", [_p("ou:root", "drive_and_docs_service_status", {"serviceState": "ENABLED"}),
                             _p("ou:root", "drive_and_docs_drive_for_desktop", {"restrictToAuthorizedDevices": True})],
     ("not_assessed", "setting_absent")),
    ("GWS.CHAT.4.1v1", [_p("ou:root", "chat_service_status", {"serviceState": "ENABLED"}),
                        _p("ou:root", "chat_external_chat_restriction",
                           {"allowExternalChat": None, "externalChatRestriction": "TRUSTED_DOMAINS"})], UNUSABLE_CELL),
    # Both fields readable: the compliant one still decides (no regression).
    ("GWS.CHAT.4.1v1", [_p("ou:root", "chat_service_status", {"serviceState": "ENABLED"}),
                        _p("ou:root", "chat_external_chat_restriction",
                           {"allowExternalChat": True, "externalChatRestriction": "TRUSTED_DOMAINS"})],
     ("met", "no_unit_violates")),
    # A malformed dependent field blocks too; an omitted one under a compliant activation does not.
    ("GWS.DRIVEDOCS.5.1v1", [_p("ou:root", "drive_and_docs_service_status", {"serviceState": "ENABLED"}),
                             _p("ou:root", "drive_and_docs_drive_for_desktop",
                                {"allowDriveForDesktop": False, "restrictToAuthorizedDevices": "no"})], UNUSABLE_CELL),
    ("GWS.DRIVEDOCS.5.1v1", [_p("ou:root", "drive_and_docs_service_status", {"serviceState": "ENABLED"}),
                             _p("ou:root", "drive_and_docs_drive_for_desktop", {"allowDriveForDesktop": True})],
     ("not_assessed", "setting_absent")),
    ("GWS.DRIVEDOCS.5.1v1", [_p("ou:root", "drive_and_docs_service_status", {"serviceState": "ENABLED"}),
                             _p("ou:root", "drive_and_docs_drive_for_desktop", {"allowDriveForDesktop": False})],
     ("met", "no_unit_violates")),
], ids=["b1-drive51-null", "b1-drive51-absent", "b1-chat41-null", "b1-chat41-readable", "b1-drive51-bad-dependent",
        "b1-drive51-on-dependent-absent", "b1-drive51-off-dependent-absent"])
def test_b1_all_bad_needs_every_field_readable(policy_id, policies, expected):
    assert _cell(policy_id, policies) == expected


_DRIVE31_B2 = [
    _p("ou:root", "drive_and_docs_service_status", {"serviceState": "DISABLED"}),
    _p("ou:root", "drive_and_docs_file_security_update",
       {"allowUsersToManageUpdate": True, "securityUpdate": "APPLY_TO_IMPACTED_FILES"}),
    _p("ou:a", "drive_and_docs_service_status", {"serviceState": "ENABLED"}),
    _p("ou:a", "drive_and_docs_file_security_update",
       {"allowUsersToManageUpdate": False, "securityUpdate": "APPLY_TO_IMPACTED_FILES"}),
]


@pytest.mark.parametrize(("status", "expected"), [
    ({}, ("not_assessed", "service_status_absent")),
    ({"serviceState": None}, ("not_assessed", "service_status_absent")),
    ({"serviceState": "ENABLED"}, ("not_met", "unit_violates")),
    ({"serviceState": "DISABLED"}, ("met", "no_unit_violates")),
], ids=["b2-empty", "b2-null", "b2-enabled", "b2-disabled"])
def test_b2_unreadable_child_status_never_hides_an_inherited_violation(status, expected):
    assert _cell("GWS.DRIVEDOCS.3.1v1", [*_DRIVE31_B2, _p("ou:b", "drive_and_docs_service_status", status)]) == expected


@pytest.mark.parametrize(("child", "expected"), [
    ([], ("not_met", "unit_violates")),
    ([_p("ou:a", "gmail_imap_access", {"enableImapAccess": False})], ("not_met", "unit_violates")),
    ([_p("ou:a", "gmail_imap_access", {"enableImapAccess": False}),
      _p("ou:a", "gmail_pop_access", {"enablePopAccess": False})], ("met", "no_unit_violates")),
], ids=["b3-inherits-both", "b3-restates-imap", "b3-overrides-both"])
def test_b3_a_restated_field_keeps_the_other_inherited_one(child, expected):
    policies = [_p("ou:root", "gmail_service_status", {"serviceState": "DISABLED"}),
                _p("ou:root", "gmail_imap_access", {"enableImapAccess": False}),
                _p("ou:root", "gmail_pop_access", {"enablePopAccess": True}),
                _p("ou:a", "gmail_service_status", {"serviceState": "ENABLED"}), *child]
    assert _cell("GWS.GMAIL.9.1v1", policies) == expected


@pytest.mark.parametrize(("value", "expected"), [
    ({"accessLevel": None, "allowAllInternalApps": True}, UNUSABLE_CELL),
    ({"accessLevel": "OTHER", "allowAllInternalApps": True}, UNUSABLE_CELL),
    ({"accessLevel": "ALLOW_ALL", "allowAllInternalApps": None}, ("not_met", "unit_violates")),
    ({"accessLevel": "ALLOW_NONE", "allowAllInternalApps": None}, UNUSABLE_CELL),
    ({"accessLevel": "ALLOW_NONE", "allowAllInternalApps": True}, ("not_met", "unit_violates")),
    ({"accessLevel": "ALLOW_LISTED_APPS", "allowAllInternalApps": True}, ("not_met", "unit_violates")),
    ({"accessLevel": "ALLOW_LISTED_APPS", "allowAllInternalApps": False}, ("met", "no_unit_violates")),
], ids=["b4-null-level", "b4-unknown-level", "b4-all-null-flag", "b4-none-null-flag", "b4-none-internal",
        "b4-listed-internal", "b4-listed-ok"])
def test_b4_marketplace_internal_flag_needs_a_known_access_level(value, expected):
    assert _cell("GWS.COMMONCONTROLS.11.1v1",
                 [_p("ou:root", "workspace_marketplace_apps_access_options", value)]) == expected


_CC121_ROOT = [_p("ou:root", "takeout_service_status", {"serviceState": "DISABLED"})] + [
    _p("ou:root", f"{app}_user_takeout", {"takeoutStatus": "DISABLED"})
    for app in ("blogger", "books", "location_history", "maps", "pay", "photos", "play", "play_console", "youtube")]


@pytest.mark.parametrize(("child", "expected"), [
    ([_p("ou:a", "takeout_service_status", {}), _p("ou:a", "youtube_user_takeout", {"takeoutStatus": "DISABLED"})],
     UNUSABLE_CELL),
    ([_p("ou:a", "takeout_service_status", {"serviceState": "DISABLED"}), _p("ou:a", "youtube_user_takeout", {})],
     UNUSABLE_CELL),
    ([_p("ou:a", "takeout_service_status", {})], UNUSABLE_CELL),
    ([_p("ou:a", "youtube_user_takeout", {"takeoutStatus": "DISABLED"})], ("met", "no_unit_violates")),
    ([], ("met", "no_unit_violates")),
], ids=["b5-empty-status", "b5-empty-youtube", "b5-only-empty-status", "b5-status-omitted", "b5-no-child"])
def test_b5_an_empty_one_field_record_is_unreadable(child, expected):
    assert _cell("GWS.COMMONCONTROLS.12.1v1", [*_CC121_ROOT, *child]) == expected


# Repair round 2 (M13-L09 review, 25 Nov 2026). An empty settings record, at the top unit or below, is not a value: it
# never takes a pinned default and never hides another section's readable inherited value; a unit with no effective
# value for a field the row needs is never met. Every expected cell is a literal.
@pytest.mark.parametrize(("policy_id", "policies", "expected"), [
    ("GWS.CHAT.4.1v1", [_p("ou:root", "chat_service_status", {"serviceState": "ENABLED"}),
                        _p("ou:root", "chat_external_chat_restriction", {})], UNUSABLE_CELL),
    ("GWS.COMMONCONTROLS.11.1v1", [_p("ou:root", "workspace_marketplace_apps_access_options", {})], UNUSABLE_CELL),
    ("GWS.GROUPS.4.1v1", [_p("ou:root", "groups_for_business_service_status", {"serviceState": "ENABLED"}),
                          _p("ou:root", "groups_for_business_groups_sharing", {"unknownKey": True})], UNUSABLE_CELL),
    # Omitting the record still lets the pinned default answer.
    ("GWS.CHAT.4.1v1", [_p("ou:root", "chat_service_status", {"serviceState": "ENABLED"})], ("met", "no_unit_violates")),
    ("GWS.COMMONCONTROLS.11.1v1", [], ("not_met", "unit_violates")),
], ids=["r2b1-chat-empty", "r2b1-cc111-empty", "r2b1-groups-unknown-key", "r2b1-chat-omitted", "r2b1-cc111-omitted"])
def test_r2_b1_an_empty_top_record_takes_no_default(policy_id, policies, expected):
    assert _cell(policy_id, policies) == expected


_GMAIL91_ROOT_OFF = [_p("ou:root", "gmail_service_status", {"serviceState": "DISABLED"}),
                     _p("ou:a", "gmail_service_status", {"serviceState": "ENABLED"})]


@pytest.mark.parametrize(("child", "expected"), [
    ({}, ("not_met", "unit_violates")),
    ({"enableImapAccess": None}, ("not_met", "unit_violates")),
    ({"enableImapAccess": False}, ("not_met", "unit_violates")),
], ids=["r2b2-empty-imap", "r2b2-null-imap", "r2b2-readable-imap"])
def test_r2_b2_an_empty_child_record_never_hides_an_inherited_violation(child, expected):
    policies = [*_GMAIL91_ROOT_OFF, _p("ou:root", "gmail_imap_access", {"enableImapAccess": False}),
                _p("ou:root", "gmail_pop_access", {"enablePopAccess": True}), _p("ou:a", "gmail_imap_access", child)]
    assert _cell("GWS.GMAIL.9.1v1", policies) == expected


@pytest.mark.parametrize(("policies", "expected"), [
    ([_p("ou:a", "gmail_imap_access", {"enableImapAccess": False})], ("not_assessed", "setting_absent")),
    ([_p("ou:a", "gmail_pop_access", {"enablePopAccess": False})], ("not_assessed", "setting_absent")),
    ([_p("ou:a", "gmail_imap_access", {"enableImapAccess": True})], ("not_met", "unit_violates")),
    ([_p("ou:a", "gmail_imap_access", {"enableImapAccess": False}),
      _p("ou:a", "gmail_pop_access", {"enablePopAccess": False})], ("met", "no_unit_violates")),
    ([_p("ou:a", "gmail_imap_access", {"enableImapAccess": False}),
      _p("ou:root", "gmail_pop_access", {"enablePopAccess": False})], ("met", "no_unit_violates")),
], ids=["r2b3-pop-nowhere", "r2b3-imap-nowhere", "r2b3-bad-wins", "r2b3-both-own", "r2b3-pop-from-top"])
def test_r2_b3_a_reactivated_child_needs_every_required_field(policies, expected):
    assert _cell("GWS.GMAIL.9.1v1", [*_GMAIL91_ROOT_OFF, *policies]) == expected


def _takeout() -> dict:
    return {"takeout_service_status": {"serviceState": "DISABLED"}} | {
        f"{app}_user_takeout": {"takeoutStatus": "DISABLED"}
        for app in ("blogger", "books", "location_history", "maps", "pay", "photos", "play", "play_console", "youtube")}


_EXT = "drive_and_docs_external_sharing"
_MARKET = "workspace_marketplace_apps_access_options"
# Compliant top-unit records per baseline; every field of each participating section is stated.
_BASE = {
    "gmail55": {"gmail_email_attachment_safety": {
        "anomalousAttachmentProtectionConsequence": "SPAM_FOLDER", "encryptedAttachmentProtectionConsequence": "QUARANTINE",
        "attachmentWithScriptsProtectionConsequence": "QUARANTINE"}},
    "gmail76": {"gmail_spoofing_and_authentication": {
        "domainSpoofingConsequence": "SPAM_FOLDER", "domainNameSpoofingConsequence": "QUARANTINE",
        "employeeNameSpoofingConsequence": "SPAM_FOLDER", "groupsSpoofingConsequence": "QUARANTINE",
        "unauthenticatedEmailConsequence": "SPAM_FOLDER"}},
    "gmail91": {"gmail_imap_access": {"enableImapAccess": False}, "gmail_pop_access": {"enablePopAccess": False}},
    "drive-disallowed": {_EXT: {"externalSharingMode": "DISALLOWED", "allowReceivingExternalFiles": False,
                                "allowReceivingFilesOutsideAllowlistedDomains": False}},
    "drive-allowlisted": {_EXT: {"externalSharingMode": "ALLOWLISTED_DOMAINS", "allowReceivingExternalFiles": False,
                                 "allowReceivingFilesOutsideAllowlistedDomains": False,
                                 "warnForSharingOutsideAllowlistedDomains": True, "warnForExternalSharing": True,
                                 "allowNonGoogleInvitesInAllowlistedDomains": False, "allowNonGoogleInvites": False,
                                 "allowPublishingFiles": False, "allowedPartiesForDistributingContent": "NONE"}},
    "drive-allowed": {_EXT: {"externalSharingMode": "ALLOWED", "warnForSharingOutsideAllowlistedDomains": True,
                             "warnForExternalSharing": True, "allowNonGoogleInvitesInAllowlistedDomains": False,
                             "allowNonGoogleInvites": False, "allowPublishingFiles": False,
                             "allowedPartiesForDistributingContent": "NONE"}},
    "drive31": {"drive_and_docs_file_security_update": {"allowUsersToManageUpdate": False,
                                                        "securityUpdate": "APPLY_TO_IMPACTED_FILES"}},
    # Both fields participate: the activation is on and the dependent field makes the unit compliant.
    "drive51": {"drive_and_docs_drive_for_desktop": {"allowDriveForDesktop": True, "restrictToAuthorizedDevices": True}},
    "groups41": {"groups_for_business_groups_sharing": {"ownersCanHideGroups": False, "newGroupsAreHidden": False}},
    "chat41": {"chat_external_chat_restriction": {"allowExternalChat": True,
                                                  "externalChatRestriction": "TRUSTED_DOMAINS"}},
    "cc111": {_MARKET: {"accessLevel": "ALLOW_LISTED_APPS", "allowAllInternalApps": False}},
    "cc121": _takeout(),
}
MET, BAD, ABSENT = ("met", "no_unit_violates"), ("not_met", "unit_violates"), ("not_assessed", "setting_absent")
STATUS_ABSENT = ("not_assessed", "service_status_absent")
_APPS = ("blogger", "books", "location_history", "maps", "pay", "photos", "play", "play_console", "youtube")
# (policy, baseline, section, field, a known value other than the baseline's, the top unit's answer when the field
# is absent there). Absent fields at the top unit take the pinned default when the section has one.
WALK = [
    *[("GWS.GMAIL.5.5v1", "gmail55", "gmail_email_attachment_safety", field, "WARNING", MET) for field in (
        "anomalousAttachmentProtectionConsequence", "encryptedAttachmentProtectionConsequence",
        "attachmentWithScriptsProtectionConsequence")],
    *[("GWS.GMAIL.7.6v1", "gmail76", "gmail_spoofing_and_authentication", field, "NO_ACTION", MET) for field in (
        "domainSpoofingConsequence", "domainNameSpoofingConsequence", "employeeNameSpoofingConsequence",
        "groupsSpoofingConsequence", "unauthenticatedEmailConsequence")],
    ("GWS.GMAIL.9.1v1", "gmail91", "gmail_imap_access", "enableImapAccess", True, ABSENT),
    ("GWS.GMAIL.9.1v1", "gmail91", "gmail_pop_access", "enablePopAccess", True, ABSENT),
    ("GWS.DRIVEDOCS.1.2v1", "drive-disallowed", _EXT, "externalSharingMode", "ALLOWED", MET),
    ("GWS.DRIVEDOCS.1.2v1", "drive-disallowed", _EXT, "allowReceivingExternalFiles", True, BAD),
    ("GWS.DRIVEDOCS.1.2v1", "drive-allowlisted", _EXT, "allowReceivingFilesOutsideAllowlistedDomains", True, BAD),
    ("GWS.DRIVEDOCS.1.3v1", "drive-allowlisted", _EXT, "externalSharingMode", "ALLOWED", MET),
    ("GWS.DRIVEDOCS.1.3v1", "drive-allowlisted", _EXT, "warnForSharingOutsideAllowlistedDomains", False, MET),
    ("GWS.DRIVEDOCS.1.3v1", "drive-allowed", _EXT, "warnForExternalSharing", False, MET),
    ("GWS.DRIVEDOCS.1.4v1", "drive-allowlisted", _EXT, "externalSharingMode", "ALLOWED", MET),
    ("GWS.DRIVEDOCS.1.4v1", "drive-allowlisted", _EXT, "allowNonGoogleInvitesInAllowlistedDomains", True, MET),
    ("GWS.DRIVEDOCS.1.4v1", "drive-allowed", _EXT, "allowNonGoogleInvites", True, BAD),
    ("GWS.DRIVEDOCS.1.5v1", "drive-allowed", _EXT, "externalSharingMode", "DISALLOWED", MET),
    ("GWS.DRIVEDOCS.1.5v1", "drive-allowed", _EXT, "allowPublishingFiles", True, BAD),
    ("GWS.DRIVEDOCS.1.5v1", "drive-allowlisted", _EXT, "allowPublishingFiles", True, BAD),
    ("GWS.DRIVEDOCS.1.7v1", "drive-allowed", _EXT, "externalSharingMode", "DISALLOWED", MET),
    ("GWS.DRIVEDOCS.1.7v1", "drive-allowed", _EXT, "allowedPartiesForDistributingContent", "ALL_ELIGIBLE_USERS", BAD),
    ("GWS.DRIVEDOCS.1.7v1", "drive-allowlisted", _EXT, "allowedPartiesForDistributingContent",
     "ELIGIBLE_INTERNAL_USERS", BAD),
    ("GWS.DRIVEDOCS.3.1v1", "drive31", "drive_and_docs_file_security_update", "allowUsersToManageUpdate", True, ABSENT),
    ("GWS.DRIVEDOCS.3.1v1", "drive31", "drive_and_docs_file_security_update", "securityUpdate",
     "REMOVE_FROM_IMPACTED_FILES", ABSENT),
    ("GWS.DRIVEDOCS.5.1v1", "drive51", "drive_and_docs_drive_for_desktop", "allowDriveForDesktop", False, ABSENT),
    ("GWS.DRIVEDOCS.5.1v1", "drive51", "drive_and_docs_drive_for_desktop", "restrictToAuthorizedDevices", False,
     ABSENT),
    ("GWS.GROUPS.4.1v1", "groups41", "groups_for_business_groups_sharing", "ownersCanHideGroups", True, MET),
    ("GWS.GROUPS.4.1v1", "groups41", "groups_for_business_groups_sharing", "newGroupsAreHidden", True, MET),
    ("GWS.CHAT.4.1v1", "chat41", "chat_external_chat_restriction", "allowExternalChat", False, MET),
    ("GWS.CHAT.4.1v1", "chat41", "chat_external_chat_restriction", "externalChatRestriction", "NO_RESTRICTION", BAD),
    ("GWS.COMMONCONTROLS.11.1v1", "cc111", _MARKET, "accessLevel", "ALLOW_NONE", BAD),
    ("GWS.COMMONCONTROLS.11.1v1", "cc111", _MARKET, "allowAllInternalApps", True, MET),
    ("GWS.COMMONCONTROLS.12.1v1", "cc121", "takeout_service_status", "serviceState", "ENABLED", STATUS_ABSENT),
    *[("GWS.COMMONCONTROLS.12.1v1", "cc121", f"{app}_user_takeout", "takeoutStatus", "ENABLED", ABSENT)
      for app in _APPS],
]
VARIANTS = ("absent", "null", "wrong_type", "blank", "empty_record", "contradictory")


def _variant_records(unit: str, records: dict, section: str, field: str, other, variant: str) -> list[dict]:
    records = copy.deepcopy(records)
    extra = []
    if variant == "absent":
        records[section].pop(field)
        if not records[section]:
            records.pop(section)
    elif variant == "null":
        records[section][field] = None
    elif variant == "wrong_type":
        records[section][field] = 1 if isinstance(records[section][field], bool) else True
    elif variant == "blank":
        records[section][field] = ""
    elif variant == "empty_record":
        records[section] = {}
    else:  # two equal-ranked records that disagree on the field (D11)
        extra = [_p(unit, section, {**records[section], field: other})]
    return [_p(unit, name, value) for name, value in records.items()] + extra


def _walk_status(policy_id: str) -> list[dict]:
    service = ROWS[policy_id][1]
    return [_p("ou:root", f"{service}_service_status", {"serviceState": "ENABLED"})] if service else []


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize(("policy_id", "base", "section", "field", "other", "top_absent"), WALK,
                         ids=[f"{case[0]}:{case[1]}:{case[2]}.{case[3]}" for case in WALK])
def test_r2_every_participating_field_at_the_top_unit(policy_id, base, section, field, other, top_absent, variant):
    """Absent takes the pinned default, else setting_absent (consequence lists ignore it); every other variant is
    unreadable, an empty record included."""
    expected = top_absent if variant == "absent" else UNUSABLE_CELL
    assert _cell(policy_id, [*_walk_status(policy_id), *_variant_records(
        "ou:root", _BASE[base], section, field, other, variant)]) == expected
    # The untouched baseline is compliant.
    assert _cell(policy_id, [*_walk_status(policy_id), *[_p("ou:root", name, value)
                                                          for name, value in _BASE[base].items()]]) == MET


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize(("policy_id", "base", "section", "field", "other", "top_absent"), WALK,
                         ids=[f"{case[0]}:{case[1]}:{case[2]}.{case[3]}" for case in WALK])
def test_r2_every_participating_field_in_a_child_unit(policy_id, base, section, field, other, top_absent, variant):
    """The top unit is compliant; the child restates every record, then one variant. An absent field is inherited;
    every other variant, an empty record included, is unreadable and never inherits."""
    top = [_p("ou:root", name, value) for name, value in _BASE[base].items()]
    expected = MET if variant == "absent" else UNUSABLE_CELL
    assert _cell(policy_id, [*_walk_status(policy_id), *top, *_variant_records(
        "ou:a", _BASE[base], section, field, other, variant)]) == expected
