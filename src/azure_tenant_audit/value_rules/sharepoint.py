"""SharePoint singleton settings (spec v3.9 section 3.5).

Closed applicability is decided by the shared config gate before these readers.
Absent checked fields precede violations; otherwise a known violation wins over
an unusable companion field. Text interpolations use catalogue names only.
"""
from __future__ import annotations

from .helpers import _int
from .record import BAD_SECTION_LIST, EMPTY_SECTION, ITEM_VALUE, _A, _rec

SPO = "SPO_tenant"
SLIDER_NAMES = {0: "Only people in your organization", 1: "New and existing guests",
                2: "Anyone", 3: "Existing guests"}
SP_GATE_APPLIES = {
    "MS.SHAREPOINT.1.3v1": "the external sharing slider is not set to Only people in your organization or Existing guests",
    "MS.SHAREPOINT.3.1v1": "the external sharing slider is set to Anyone",
    "MS.SHAREPOINT.3.2v1": "the external sharing slider is set to Anyone",
    "MS.SHAREPOINT.3.3v2": "the external sharing slider is not set to Only people in your organization",
}


def _spo_shape(policy_id: str, sections: dict) -> tuple[dict | None, dict | None]:
    """Require exactly one object; a closed gate may already have answered a map."""
    value = sections[SPO]
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        return _A(policy_id, BAD_SECTION_LIST,
                  f"Data unusable: {SPO} is not a list of objects; the policy was not assessed.",
                  "spo_shape_unusable", [SPO]), None
    if not value:
        return _A(policy_id, EMPTY_SECTION,
                  f"Data unavailable: {SPO} is empty; the policy was not assessed.", "spo_empty", [SPO]), None
    if len(value) > 1:
        return _A(policy_id, "data_unusable_section_not_singleton",
                  f"Data unusable: {SPO} holds more than one object; the tenant settings are a single object, "
                  "so the policy was not assessed.", "spo_not_singleton", [SPO]), None
    return None, value[0]


def _sp_field(policy_id: str, item: dict, field: str, enum=None, *, is_int: bool = True) -> tuple:
    """Typed field: absent, unusable and outside-set are separate cells."""
    if field not in item:
        return "A", _A(policy_id, "data_unusable_field_absent",
                        f"Data unusable: {field} is absent from {SPO}; the policy was not assessed.",
                        "field_absent", [SPO])
    value = item[field]
    if is_int:
        number = _int(value)
        if number is None:
            return "A", _A(policy_id, ITEM_VALUE,
                            f"Data unusable: {field} in {SPO} is null or not a number; the policy was not assessed.",
                            "field_unusable", [SPO])
        if enum is not None and number not in enum:
            return "A", _A(policy_id, ITEM_VALUE,
                            f"Data unusable: {field} in {SPO} holds a value outside the known settings; "
                            "the policy was not assessed.", "value_outside_set", [SPO])
        return "ok", number
    if type(value) is not bool:
        return "A", _A(policy_id, ITEM_VALUE,
                        f"Data unusable: {field} in {SPO} is null or not a boolean; the policy was not assessed.",
                        "field_unusable", [SPO])
    return "ok", value


def _sp_done(policy_id: str, met: bool, text_met: str, text_bad: str) -> dict:
    if met:
        return _rec(policy_id, "met", "setting_compliant", f"Requirement met: {text_met}.", "value_compliant")
    return _rec(policy_id, "not_met", "setting_noncompliant", f"Requirement not met: {text_bad}.", "value_noncompliant")


def sharepoint(policy_id: str, row: dict, sections: dict) -> dict:
    record, item = _spo_shape(policy_id, sections)
    if record:
        return record
    params = row["params"]
    if row["kind"] == "sp_scalar":
        state, value = _sp_field(policy_id, item, params["field"], params["enum"])
        if state == "A":
            return value
        return _sp_done(policy_id, value in params["good"], f"{params['field']} holds a compliant setting", params["what"])
    slider = _int(item.get("SharingCapability"))
    if slider not in SLIDER_NAMES:
        return _A(policy_id, "data_unusable_sharing_capability",
                  f"Data unusable: SharingCapability in {SPO} is absent, null or outside the known settings, "
                  "so it is unknown whether the policy applies; the policy was not assessed.", "slider_unusable", [SPO])
    # The reference requires every checked key before deciding even a known violation.
    fields = params["fields"]
    for field in fields:
        if field not in item:
            return _A(policy_id, "data_unusable_field_absent",
                      f"Data unusable: {field} is absent from {SPO}; the policy was not assessed.", "field_absent", [SPO])
    if policy_id == "MS.SHAREPOINT.1.3v1":
        state, value = _sp_field(policy_id, item, "SharingDomainRestrictionMode", (0, 1, 2))
        return value if state == "A" else _sp_done(
            policy_id, value == 1, "external sharing is restricted to approved domains", params["what"])
    if policy_id == "MS.SHAREPOINT.3.1v1":
        state, value = _sp_field(policy_id, item, "RequireAnonymousLinksExpireInDays")
        return value if state == "A" else _sp_done(
            policy_id, 1 <= value <= 30, "Anyone links expire within 30 days", params["what"])
    if policy_id == "MS.SHAREPOINT.3.2v1":
        results = [_sp_field(policy_id, item, field, (0, 1, 2)) for field in fields]
        if any(state == "ok" and value != 1 for state, value in results):
            return _sp_done(policy_id, False, "", params["what"])
        for state, value in results:
            if state == "A":
                return value
        return _sp_done(policy_id, True, "Anyone links are limited to view permission", "")
    if policy_id == "MS.SHAREPOINT.3.3v2":
        flag_state, flag = _sp_field(policy_id, item, "EmailAttestationRequired", is_int=False)
        days_state, days = _sp_field(policy_id, item, "EmailAttestationReAuthDays")
        if (flag_state == "ok" and flag is False) or (days_state == "ok" and days >= 31):
            return _sp_done(policy_id, False, "", params["what"])
        if flag_state == "A":
            return flag
        if days_state == "A":
            return days
        if days < 1:
            return _A(policy_id, ITEM_VALUE,
                      f"Data unusable: EmailAttestationReAuthDays in {SPO} is below one day; the policy was not assessed.",
                      "value_outside_set", [SPO])
        return _sp_done(policy_id, True, "verification-code reauthentication is on and at most 30 days", "")
    raise ValueError("Unknown SharePoint value rule")


KINDS = {"sp_scalar": sharepoint, "sp_gated": sharepoint}
