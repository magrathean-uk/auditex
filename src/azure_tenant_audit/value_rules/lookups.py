"""Lookup kinds (spec v3.9 section 3): Teams, Exchange Online and Defender settings read from one list section.

Every kind runs after the closed gate and section_not_collected (``value_rules.assess``). Parameters come from the
policy's row in ``configs/scuba-value-rules.json``; the deciding conjuncts of EXO 7.1 and the required alert names of
SS 4.1 are code (spec section 2).
"""
from __future__ import annotations

from typing import Any, Callable

from .helpers import _env_cell, _flag, _label, _list_state, _scan_bad_wins, _scan_good_wins
from .record import BAD_SECTION_LIST, EMPTY_SECTION, ITEM_LABEL, ITEM_VALUE, _A, _rec


# ---- violation evaluators: per object 'bad', 'clear' or 'unusable' ----
def _ev_any_flag(params: dict) -> Callable[[dict], str]:
    """any_flag (one field) and two_flag (both fields must be bad; clear when any is explicitly the other boolean)."""
    def evaluate(item: dict) -> str:
        states = [_flag(item, field, params["bad"]) for field in params["fields"]]
        if all(state == "bad" for state in states):
            return "bad"
        return "clear" if any(state == "clear" for state in states) else "unusable"
    return evaluate


def _ev_flag_and_list(params: dict) -> Callable[[dict], str]:
    """TEAMS 2.1: flag false is clear; flag true with an empty list is bad, with a non-empty list clear."""
    def evaluate(item: dict) -> str:
        state = _flag(item, params["flag"], True)
        if state != "bad":
            return state
        value = item.get(params["list_field"])
        if not isinstance(value, list):
            return "unusable"
        return "bad" if not value else "clear"
    return evaluate


def _ev_list_count(params: dict) -> Callable[[dict], str]:
    """SS 8.1: a non-empty list is bad, [] is clear, anything else unusable."""
    def evaluate(item: dict) -> str:
        value = item.get(params["list_field"])
        if not isinstance(value, list):
            return "unusable"
        return "bad" if value else "clear"
    return evaluate


def _ev_bool_list(params: dict) -> Callable[[dict], str]:
    """EXO 2.2: the upstream ``compliant`` flag; false is bad, true clear, null or absent unusable."""
    def evaluate(item: dict) -> str:
        return _flag(item, params["flag"], False)
    return evaluate


def _ev_substring(params: dict) -> Callable[[dict], str]:
    """EXO 6.x: a Domains string holding both '*' and the token (case-sensitive plain substring) is bad; every
    element a string otherwise clear; Domains not a list or a non-string element unusable (Q6)."""
    def evaluate(item: dict) -> str:
        domains = item.get("Domains")
        if not isinstance(domains, list):
            return "unusable"
        if any(isinstance(domain, str) and "*" in domain and params["token"] in domain for domain in domains):
            return "bad"
        return "clear" if all(isinstance(domain, str) for domain in domains) else "unusable"
    return evaluate


EVALUATORS = {"any_flag": _ev_any_flag, "two_flag": _ev_any_flag, "flag_and_empty_list": _ev_flag_and_list,
              "list_count": _ev_list_count, "bool_list": _ev_bool_list, "substring_pair": _ev_substring}


def _all_labels(keys: list[str]) -> Callable[[dict], bool]:
    return lambda item: all(type(item.get(key)) is str for key in keys)


def violation_scan(policy_id: str, row: dict[str, Any], sections: dict[str, Any]) -> dict:
    params = row["params"]
    if params.get("environment_gate"):
        out = _env_cell(policy_id, sections)
        if out:
            return out
    label_ok = (_all_labels(params["labels"]) if "labels" in params
                else _label(params["label"], params.get("label_null_ok", False)))
    return _scan_bad_wins(policy_id, params, sections, EVALUATORS[row["kind"]](params), label_ok)


def any_true_is_met(policy_id: str, row: dict[str, Any], sections: dict[str, Any]) -> dict:
    return _scan_good_wins(policy_id, row["params"], sections)


# ---- global_record: the single Identity Global object (TEAMS 1.3 1.4 1.6 1.7) ----
def _check_item(item: dict, check: dict) -> str:
    field = check["field"]
    if field not in item:
        return "absent"
    value = item[field]
    if check["how"] == "flag_false":
        return "unusable" if type(value) is not bool else ("good" if value is False else "bad")
    if check["how"] != "enum":
        raise ValueError("Unknown global_record check")
    if type(value) is not str:
        return "unusable"
    return "good" if value in check["good"] else ("bad" if value in check["bad"] else "unusable")


def global_record(policy_id: str, row: dict[str, Any], sections: dict[str, Any]) -> dict:
    params = row["params"]
    name = params["section"]
    out, items = _list_state(policy_id, sections, name)
    if out:
        return out
    globals_ = [item for item in items if item.get("Identity") == "Global"]
    if not globals_:
        return _A(policy_id, "data_unavailable_global_policy_absent",
                  f"Data unavailable: {name} has no policy with Identity Global; the policy was not assessed.",
                  "no_global_policy", [name])
    if len(globals_) > 1:
        return _A(policy_id, "data_unusable_global_duplicated",
                  f"Data unusable: {name} has 2 policies with Identity Global; the policy was not assessed." if len(globals_) == 2
                  else f"Data unusable: {name} has more than one policy with Identity Global; the policy was not assessed.",
                  "global_duplicated", [name])
    states = [_check_item(globals_[0], check) for check in params["checks"]]
    if "absent" in states:              # one absent checked field gives the Rego no result at all
        return _A(policy_id, ITEM_VALUE,
                  f"Data unusable: the Global policy in {name} lacks a field the policy reads; the policy was not assessed.",
                  "global_unusable", [name])
    if "bad" in states:
        return _rec(policy_id, "not_met", "global_policy_noncompliant", f"Requirement not met: {params['unmet']}.", "global_bad")
    if "unusable" in states:
        return _A(policy_id, ITEM_VALUE,
                  f"Data unusable: the Global policy in {name} lacks a usable value for a field the policy reads; the policy was not assessed.",
                  "global_unusable", [name])
    return _rec(policy_id, "met", "global_policy_compliant", f"Requirement met: {params['what']}.", "global_good")


# ---- setting_cascade: the org-wide app setting first, the legacy per-policy field after (TEAMS 5.x) ----
LEGACY_VALUES = ("BlockedAppList", "AllowedAppList")


def setting_cascade(policy_id: str, row: dict[str, Any], sections: dict[str, Any]) -> dict:
    params = row["params"]
    setting, legacy_field, label = params["setting"], params["legacy"], params["label"]
    settings = sections["tenant_app_settings"]
    cite_settings = ["tenant_app_settings"]
    entries: list[dict] = []
    certificate: list[dict] = []
    if settings is not None:
        if not isinstance(settings, list):
            return _A(policy_id, "data_unusable_tenant_app_settings_shape",
                      "Data unusable: tenant_app_settings is neither null nor a list of setting objects; the policy was not assessed.",
                      "settings_shape_unusable", cite_settings)
        objects = [item for item in settings if isinstance(item, dict)]
        entries = [item for item in objects if item.get("SettingName") == setting]
        certificate = [item for item in objects if item.get("CertificateBasedAuth") is True]
    if len(entries) > 1:
        return _A(policy_id, "data_unusable_setting_duplicated",
                  f"Data unusable: org-wide app setting {setting} appears 2 times; the policy was not assessed." if len(entries) == 2
                  else f"Data unusable: org-wide app setting {setting} appears more than once; the policy was not assessed.",
                  "setting_duplicated", cite_settings)
    if entries and certificate:
        return _A(policy_id, "data_unusable_setting_and_certificate_auth",
                  f"Data unusable: org-wide app setting {setting} and a certificate-authentication entry appear together; "
                  "the policy was not assessed.", "setting_and_cert_conflict", cite_settings)
    if entries:
        if type(entries[0].get("SettingValue")) is not str:
            return _A(policy_id, "data_unusable_setting_value",
                      f"Data unusable: org-wide app setting {setting} has no string value; the policy was not assessed.",
                      "org_setting_value_unusable", cite_settings)
        if entries[0]["SettingValue"] == "None":
            return _rec(policy_id, "met", "org_setting_none", f"Requirement met: org-wide app setting {setting} is None.",
                        "org_setting_none")
        return _rec(policy_id, "not_met", "org_setting_not_none",
                    f"Requirement not met: org-wide app setting {setting} is not None.", "org_setting_not_none")
    # Legacy per-policy check: the setting absent, tenant_app_settings null or empty, or certificate authentication in use.
    legacy = sections["app_policies"]
    cite_legacy = ["app_policies"]
    if not isinstance(legacy, list):
        return _A(policy_id, BAD_SECTION_LIST, "Data unusable: app_policies is not a list of objects; the policy was not assessed.",
                  "legacy_section_not_a_list", cite_legacy)
    items = [item for item in legacy if isinstance(item, dict)]
    if not items:
        return _A(policy_id, EMPTY_SECTION, "Data unavailable: app_policies holds no objects; the policy was not assessed.",
                  "legacy_no_policies", cite_legacy)
    blocked_labelled = blocked_unlabelled = unusable = 0
    for item in items:
        value = item.get(legacy_field)
        if type(value) is not str or value not in LEGACY_VALUES:
            unusable += 1
        elif value == "BlockedAppList":
            if type(item.get(label)) is str:
                blocked_labelled += 1
            else:
                blocked_unlabelled += 1
    if blocked_labelled:
        return _rec(policy_id, "not_met", "legacy_policy_blocked_list",
                    f"Requirement not met: an app permission policy uses {legacy_field} BlockedAppList.", "legacy_blocked")
    if blocked_unlabelled:
        return _A(policy_id, ITEM_LABEL,
                  "Data unusable: an app permission policy uses a blocked-app list but carries no identity; the policy was not assessed.",
                  "legacy_blocked_unlabelled", cite_legacy)
    if unusable:
        return _A(policy_id, ITEM_VALUE,
                  f"Data unusable: an app permission policy lacks a recognised {legacy_field}; the policy was not assessed.",
                  "legacy_unusable", cite_legacy)
    return _rec(policy_id, "met", "legacy_policies_allowed_list",
                f"Requirement met: every app permission policy uses {legacy_field} AllowedAppList.", "legacy_allowed")


# ---- list_exists: EXO 7.1 (transport_rule) and SS 4.1 (alerts) ----
TRANSPORT_CONJUNCTS = (("State", "Enabled"), ("Mode", "Enforce"), ("FromScope", "NotInOrganization"))


def _transport_rule(rule: dict) -> str:
    """'q' qualifies, 'x' excluded (a listed field present and different; PrependSubject null, "" or []), 'u' unusable."""
    checks = ["u" if key not in rule else ("q" if rule[key] == want else "x") for key, want in TRANSPORT_CONJUNCTS]
    if "PrependSubject" not in rule:
        checks.append("u")
    else:
        prepend = rule["PrependSubject"]
        if prepend is None or prepend == "" or prepend == []:
            checks.append("x")
        elif isinstance(prepend, (str, list)):
            checks.append("q")
        else:
            checks.append("u")
    return "q" if all(check == "q" for check in checks) else ("x" if "x" in checks else "u")


def _exo71(policy_id: str, name: str, items: list[dict]) -> dict:
    states = [_transport_rule(rule) for rule in items]
    if "q" in states:
        return _rec(policy_id, "met", "qualifying_rule_found",
                    "Requirement met: an enabled enforcing transport rule prepends a subject warning to mail from outside the organisation.",
                    "qualifying_rule")
    if "u" in states:
        return _A(policy_id, ITEM_VALUE,
                  "Data unusable: a transport rule lacks a field needed to tell whether it warns on external mail; the policy was not assessed.",
                  "rule_unusable", [name])
    return _rec(policy_id, "not_met", "no_qualifying_rule",
                "Requirement not met: no enabled enforcing transport rule prepends a subject warning to mail from outside the organisation.",
                "no_qualifying_rule")


# R6: exact alert names, compared case-sensitively. The seventh is a baseline SHALL (v3.7, D103).
REQUIRED_ALERTS = ("Suspicious email sending patterns detected", "Suspicious connector activity",
                   "Suspicious Email Forwarding Activity", "Messages have been delayed",
                   "Tenant restricted from sending unprovisioned email", "Tenant restricted from sending email",
                   "A potentially malicious URL click was detected")
ALERTS_MISSING_PREFIX = "Requirement not met: required alert(s) absent or disabled: "


def alert_text(names) -> str:
    """The not-met text names the missing or disabled alerts in REQUIRED_ALERTS order: a closed set of 127 texts."""
    return ALERTS_MISSING_PREFIX + "; ".join(names) + "."


def _alerts(policy_id: str, name: str, items: list[dict]) -> dict:
    named = [alert for alert in items if type(alert.get("Name")) is str]
    bad, unusable = [], []
    for required in REQUIRED_ALERTS:
        entries = [alert for alert in named if alert["Name"] == required]
        if not entries:
            bad.append(required)
            continue
        states = ["unusable" if type(alert.get("Disabled")) is not bool else ("on" if alert["Disabled"] is False else "off")
                  for alert in entries]
        if "on" in states and "off" in states:
            unusable.append(required)
        elif "on" in states:
            continue
        elif "off" in states:
            bad.append(required)
        else:
            unusable.append(required)
    if bad:
        return _rec(policy_id, "not_met", "required_alert_absent_or_disabled",
                    alert_text(bad), "alert_missing_or_disabled")
    if unusable:
        return _A(policy_id, ITEM_VALUE,
                  "Data unusable: a required alert has no usable Disabled flag or conflicting duplicate entries; the policy was not assessed.",
                  "alert_state_unusable", [name])
    return _rec(policy_id, "met", "required_alerts_enabled", "Requirement met: every required alert is present and enabled.",
                "all_alerts_enabled")


def list_exists(policy_id: str, row: dict[str, Any], sections: dict[str, Any]) -> dict:
    params = row["params"]
    name = params["section"]
    out, items = _list_state(policy_id, sections, name)
    if out:
        return out
    if params["variant"] == "transport_rule":
        return _exo71(policy_id, name, items)
    if params["variant"] == "alerts":
        return _alerts(policy_id, name, items)
    raise ValueError("Unknown list_exists variant")


KINDS = {"any_flag": violation_scan, "two_flag": violation_scan, "flag_and_empty_list": violation_scan,
         "list_count": violation_scan, "bool_list": violation_scan, "substring_pair": violation_scan,
         "any_true_is_met": any_true_is_met, "global_record": global_record, "setting_cascade": setting_cascade,
         "list_exists": list_exists}
