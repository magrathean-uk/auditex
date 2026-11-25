"""Identity kinds for Google Workspace (M13-L10): ``twosv``, ``super_admin_count`` and ``admin_sso``.

The policy vectors live in ``tests/fixtures/gws-value-rules/identity.jsonl`` and replay through
``tests/test_gws_value_rules_replay.py``. This file pins the rows, the parsers and the edges the vectors depend on.
Synthetic data only; every expectation is a literal.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from azure_tenant_audit.value_rules import gws
from azure_tenant_audit.value_rules.gws import identity
from azure_tenant_audit.value_rules.gws.catalogue import catalogue

VECTORS = Path(__file__).parent / "fixtures" / "gws-value-rules" / "identity.jsonl"
TENANT = {"as_of": "2026-11-25T12:00:00Z", "top_unit": "ou:root", "org_units": {"ou:root": None, "ou:a": "ou:root"},
          "complete": True}


def test_identity_rows_and_kinds():
    rows = {pid: (row["kind"], row["params"], row["sections"]) for pid, row in catalogue()["policies"].items()
            if row["kind"] in {"twosv", "super_admin_count", "admin_sso"}}
    twosv = ["gws_tenant", "gws_policies"]
    assert rows == {
        "GWS.COMMONCONTROLS.1.1v1": ("twosv", {"check": "passkey_only"}, twosv),
        "GWS.COMMONCONTROLS.1.2v1": ("twosv", {"check": "enrolled_and_enforced"}, twosv),
        "GWS.COMMONCONTROLS.1.3v1": ("twosv", {"check": "no_telephony"}, twosv),
        "GWS.COMMONCONTROLS.1.4v1": ("twosv", {"check": "grace_period_one_to_seven_days"}, twosv),
        "GWS.COMMONCONTROLS.1.5v1": ("twosv", {"check": "device_trust_off"}, twosv),
        "GWS.COMMONCONTROLS.6.1v1": ("admin_sso", {}, ["gws_tenant", "gws_admins", "gws_sso"]),
        "GWS.COMMONCONTROLS.6.2v1": ("super_admin_count", {}, ["gws_admins"]),
    }
    assert set(identity.KINDS) == {"twosv", "super_admin_count", "admin_sso"}
    assert {name: gws._registry()[name] for name in identity.KINDS} == identity.KINDS


def test_identity_vectors_cover_every_policy_and_divergence():
    vectors = [json.loads(line) for line in VECTORS.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_policy: dict[str, set[str]] = {}
    for vector in vectors:
        by_policy.setdefault(vector["policy"], set()).add(vector["verdict"])
    assert by_policy == {f"GWS.COMMONCONTROLS.{n}v1": {"met", "not_met", "not_assessed"}
                         for n in ("1.1", "1.2", "1.3", "1.4", "1.5", "6.1", "6.2")}
    assert {vector.get("divergence") for vector in vectors} - {None} == {"D5", "D8", "D9", "D11", "D14"}


@pytest.mark.parametrize(("text", "seconds"), [
    ("0s", 0), ("86399s", 86399), ("86400s", 86400), ("1d", 86400), ("7D", 604800), ("168h", 604800),
    ("604800s", 604800), ("604801s", 604801), ("10m", 600), ("1440M", 86400),
    ("999999999999999999s", 999_999_999_999_999_999),
])
def test_duration_seconds(text, seconds):
    assert identity.duration_seconds(text) == seconds


@pytest.mark.parametrize("text", ["", "1w", "-1d", "1.5d", "d", "1 d", " 1d", "1d\n", "١d", 86400, None, True,
                                  "9" * 19 + "s", "9" * 4301 + "s", "0" * 4300 + "1d"])
def test_duration_unreadable(text):
    assert identity.duration_seconds(text) is None


@pytest.mark.parametrize(("text", "ns"), [
    ("1970-01-01T00:00:00Z", 0),
    ("1970-01-01T00:00:00.000Z", 0),
    ("1970-01-01T00:00:01Z", 1_000_000_000),
    ("1970-01-01T00:00:00.5Z", 500_000_000),
    ("1970-01-01T00:00:00.000000001Z", 1),
    ("1970-01-01T01:00:00+01:00", 0),
    ("1969-12-31T23:00:00-01:00", 0),
    ("2026-11-25T12:00:00Z", 1_795_608_000_000_000_000),
    ("0001-01-01T00:00:00+23:59", -62_135_683_140_000_000_000),
    ("9999-12-31T23:59:59-23:59", 253_402_387_139_000_000_000),
])
def test_instant_ns(text, ns):
    assert identity.instant_ns(text) == ns


@pytest.mark.parametrize("text", ["2026-11-25", "2026-11-25T12:00:00", "2026-11-25 12:00:00Z", "2026-02-30T00:00:00Z",
                                  "2026-11-25T24:00:00Z", "2026-11-25T12:00:60Z", "2026-11-25T12:00:00.0000000001Z",
                                  "2026-11-25t12:00:00z", "2026-11-25T12:00:00+00:99", "2026-11-25T12:00:00+24:00",
                                  "", None, 0, 1795608000])
def test_instant_unreadable(text):
    assert identity.instant_ns(text) is None


def _twosv(policy: str, enforced_from: str, as_of: str) -> str:
    sections = {"gws_tenant": {**TENANT, "as_of": as_of},
                "gws_policies": {"complete": True, "policies": [
                    {"unit": "ou:root", "unit_kind": "org_unit", "sort_order": 1,
                     "section": "security_two_step_verification_enforcement", "value": {"enforcedFrom": enforced_from}},
                    {"unit": "ou:root", "unit_kind": "org_unit", "sort_order": 1,
                     "section": "security_two_step_verification_enforcement_factor",
                     "value": {"allowedSignInFactorSet": "PASSKEY_ONLY"}}]}}
    return gws.assess(policy, sections)["verdict"]


def test_enforced_from_is_compared_with_as_of_not_the_clock():
    # D8: the same bundle gives the same answer; only as_of moves the verdict.
    assert _twosv("GWS.COMMONCONTROLS.1.2v1", "2030-01-01T00:00:00Z", "2026-11-25T12:00:00Z") == "not_met"
    assert _twosv("GWS.COMMONCONTROLS.1.2v1", "2030-01-01T00:00:00Z", "2030-01-01T00:00:00Z") == "met"
    assert _twosv("GWS.COMMONCONTROLS.1.2v1", "2030-01-01T00:00:00Z", "2031-06-01T00:00:00+02:00") == "met"


def test_unknown_twosv_check_is_a_programming_error():
    with pytest.raises(ValueError, match="Unknown twosv check"):
        identity.twosv("GWS.COMMONCONTROLS.1.1v1", {"params": {"check": "passkey"}, "sections": ["gws_tenant"]}, {})


def test_answers_carry_no_input_value():
    sections = {"gws_tenant": TENANT,
                "gws_admins": {"complete": True, "super_admin_count": 1, "memberships_complete": True,
                               "privileged": [{"user": "pseudonym-p1", "org_unit": "ou:a", "groups": ["group:g9"]}]},
                "gws_sso": {"complete": True, "assignments": [{"target": "group:g9", "sso_mode": "SAML_SSO"}]}}
    record = gws.assess("GWS.COMMONCONTROLS.6.1v1", sections)
    assert (record["verdict"], record["cell"]) == ("not_met", "admin_uses_external_sso")
    assert record["detail"] == {}
    text = json.dumps(record)
    assert "pseudonym-p1" not in text and "g9" not in text and "ou:a" not in text


def _sso(mode: str, target: str = "ou:a") -> tuple[str, str]:
    sections = {"gws_tenant": TENANT,
                "gws_admins": {"complete": True, "super_admin_count": 1, "memberships_complete": True,
                               "privileged": [{"user": "p1", "org_unit": "ou:a", "groups": ["group:g1"]}]},
                "gws_sso": {"complete": True, "assignments": [{"target": target, "sso_mode": mode}]}}
    record = gws.assess("GWS.COMMONCONTROLS.6.1v1", sections)
    return record["verdict"], record["cell"]


@pytest.mark.parametrize(("mode", "answer"), [
    # Google Cloud Identity v1 ``InboundSsoAssignment.SsoMode`` (review B3); an undocumented value stays unusable (D14).
    ("SSO_OFF", ("met", "admins_use_google_sign_in")),
    ("SSO_MODE_UNSPECIFIED", ("met", "admins_use_google_sign_in")),
    ("", ("met", "admins_use_google_sign_in")),
    ("SAML_SSO", ("not_met", "admin_uses_external_sso")),
    ("OIDC_SSO", ("not_met", "admin_uses_external_sso")),
    # Review round 3 B2: the domain-wide provider applies only when one is enabled, and no read shows that it is.
    ("DOMAIN_WIDE_SAML_IF_ENABLED", ("not_assessed", "sso_read_incomplete")),
    ("domain_wide_saml_if_enabled", ("not_assessed", "sso_read_incomplete")),
    ("PASSWORDLESS_SSO", ("not_assessed", "assignment_unusable")),
])
@pytest.mark.parametrize("target", ["ou:root", "ou:a", "group:g1"])
def test_sso_modes(mode, answer, target):
    assert _sso(mode, target) == answer


def test_oversized_grace_period_is_unusable_not_an_error():
    # Review M1: 4,301 digits passed the old pattern and int() raised through gws.assess.
    sections = {"gws_tenant": TENANT,
                "gws_policies": {"complete": True, "policies": [
                    {"unit": "ou:root", "unit_kind": "org_unit", "sort_order": 1,
                     "section": "security_two_step_verification_enforcement",
                     "value": {"enforcedFrom": "2026-01-01T00:00:00Z"}},
                    {"unit": "ou:root", "unit_kind": "org_unit", "sort_order": 1,
                     "section": "security_two_step_verification_grace_period",
                     "value": {"enrollmentGracePeriod": "1d"}},
                    {"unit": "ou:a", "unit_kind": "org_unit", "sort_order": 1,
                     "section": "security_two_step_verification_grace_period",
                     "value": {"enrollmentGracePeriod": "9" * 4301 + "s"}}]}}
    record = gws.assess("GWS.COMMONCONTROLS.1.4v1", sections)
    assert (record["verdict"], record["cell"]) == ("not_assessed", "setting_value_unusable")


# --- CC.6.1 input walk (review round 3) -------------------------------------------------------------------------
# Every input admin_sso reads, set absent, null, to the wrong type, blank, duplicated and contradictory. The base
# answers met; no mutation of a read value may confirm met or not_met unless the mutated value is itself evidence.
_DROP = object()
_P1 = {"user": "p1", "org_unit": "ou:b", "groups": ["group:g1"]}


def _cc61_base() -> dict:
    return {"gws_tenant": {"as_of": "2026-11-25T12:00:00Z", "top_unit": "ou:root", "complete": True,
                           "org_units": {"ou:root": None, "ou:a": "ou:root", "ou:b": "ou:a"}},
            "gws_admins": {"complete": True, "super_admin_count": 1, "memberships_complete": True,
                           "privileged": [dict(_P1)]},
            "gws_sso": {"complete": True, "assignments": [{"target": "ou:a", "sso_mode": "SSO_OFF"}]}}


_SHAPE = ("not_assessed", "section_shape_unusable")
_NOT_COLLECTED = ("not_assessed", "section_not_collected")
_USERS = ("not_assessed", "user_read_incomplete")
_SSO_READ = ("not_assessed", "sso_read_incomplete")
_LINEAGE = ("not_assessed", "lineage_unresolved")
_ASSIGNMENT = ("not_assessed", "assignment_unusable")
_MET = ("met", "admins_use_google_sign_in")

_CC61_WALK = [
    # gws_tenant
    ("tenant-absent", ("gws_tenant",), _DROP, _NOT_COLLECTED),
    ("tenant-null", ("gws_tenant",), None, _SHAPE),
    ("tenant-wrong-type", ("gws_tenant",), [], _SHAPE),
    ("top-unit-absent", ("gws_tenant", "top_unit"), _DROP, _SHAPE),
    ("top-unit-null", ("gws_tenant", "top_unit"), None, _SHAPE),
    ("top-unit-wrong-type", ("gws_tenant", "top_unit"), 1, _SHAPE),
    ("top-unit-blank", ("gws_tenant", "top_unit"), "", _SHAPE),
    ("top-unit-not-the-root", ("gws_tenant", "top_unit"), "ou:a", _SHAPE),
    ("org-units-absent", ("gws_tenant", "org_units"), _DROP, _SHAPE),
    ("org-units-null", ("gws_tenant", "org_units"), None, _SHAPE),
    ("org-units-wrong-type", ("gws_tenant", "org_units"), [], _SHAPE),
    ("org-units-blank", ("gws_tenant", "org_units"), {}, _SHAPE),
    ("org-units-two-roots", ("gws_tenant", "org_units"), {"ou:root": None, "ou:a": None, "ou:b": "ou:a"}, _SHAPE),
    ("org-units-cycle", ("gws_tenant", "org_units"),
     {"ou:root": None, "ou:a": "ou:b", "ou:b": "ou:a"}, _LINEAGE),
    ("org-units-dangling", ("gws_tenant", "org_units"), {"ou:root": None, "ou:b": "ou:a"}, _LINEAGE),
    ("tenant-complete-absent", ("gws_tenant", "complete"), _DROP, _LINEAGE),
    ("tenant-complete-null", ("gws_tenant", "complete"), None, _LINEAGE),
    ("tenant-complete-wrong-type", ("gws_tenant", "complete"), "true", _LINEAGE),
    ("tenant-complete-false", ("gws_tenant", "complete"), False, _LINEAGE),
    # gws_admins
    ("admins-absent", ("gws_admins",), _DROP, _NOT_COLLECTED),
    ("admins-null", ("gws_admins",), None, _SHAPE),
    ("admins-wrong-type", ("gws_admins",), [], _SHAPE),
    ("admins-complete-absent", ("gws_admins", "complete"), _DROP, _USERS),
    ("admins-complete-null", ("gws_admins", "complete"), None, _USERS),
    ("admins-complete-wrong-type", ("gws_admins", "complete"), "true", _USERS),
    ("admins-complete-false", ("gws_admins", "complete"), False, _USERS),
    ("count-absent", ("gws_admins", "super_admin_count"), _DROP, _SHAPE),
    ("count-null", ("gws_admins", "super_admin_count"), None, _SHAPE),
    ("count-wrong-type", ("gws_admins", "super_admin_count"), "1", _SHAPE),
    ("count-bool", ("gws_admins", "super_admin_count"), True, _SHAPE),
    ("count-float", ("gws_admins", "super_admin_count"), 1.0, _SHAPE),
    ("count-negative", ("gws_admins", "super_admin_count"), -1, _SHAPE),
    ("count-zero", ("gws_admins", "super_admin_count"), 0, _USERS),
    ("count-above-distinct-users", ("gws_admins", "super_admin_count"), 2, _USERS),
    ("memberships-absent", ("gws_admins", "memberships_complete"), _DROP, _SHAPE),
    ("memberships-null", ("gws_admins", "memberships_complete"), None, _SHAPE),
    ("memberships-wrong-type", ("gws_admins", "memberships_complete"), "false", _SHAPE),
    # No assignment targets a group, so an unseen membership cannot change the answer (design 8.2).
    ("memberships-false-no-group-target", ("gws_admins", "memberships_complete"), False, _MET),
    ("privileged-absent", ("gws_admins", "privileged"), _DROP, _SHAPE),
    ("privileged-null", ("gws_admins", "privileged"), None, _SHAPE),
    ("privileged-wrong-type", ("gws_admins", "privileged"), {"p1": _P1}, _SHAPE),
    ("privileged-blank", ("gws_admins", "privileged"), [], _USERS),
    ("privileged-entry-null", ("gws_admins", "privileged"), [None], _SHAPE),
    ("privileged-entry-wrong-type", ("gws_admins", "privileged"), ["p1"], _SHAPE),
    ("privileged-duplicate", ("gws_admins", "privileged"), [_P1, _P1], _USERS),
    ("privileged-contradictory-groups", ("gws_admins", "privileged"),
     [_P1, {"user": "p1", "org_unit": "ou:b", "groups": []}], _USERS),
    ("privileged-contradictory-org-unit", ("gws_admins", "privileged"),
     [_P1, {"user": "p1", "org_unit": "ou:root", "groups": ["group:g1"]}], _USERS),
    ("user-absent", ("gws_admins", "privileged", 0, "user"), _DROP, _SHAPE),
    ("user-null", ("gws_admins", "privileged", 0, "user"), None, _SHAPE),
    ("user-wrong-type", ("gws_admins", "privileged", 0, "user"), 1, _SHAPE),
    ("user-blank", ("gws_admins", "privileged", 0, "user"), "", _SHAPE),
    ("user-whitespace-only", ("gws_admins", "privileged", 0, "user"), " \t\n", _SHAPE),
    ("user-padded-is-the-same-account", ("gws_admins", "privileged", 0, "user"), " p1\t", _MET),
    ("org-unit-absent", ("gws_admins", "privileged", 0, "org_unit"), _DROP, _SHAPE),
    ("org-unit-null", ("gws_admins", "privileged", 0, "org_unit"), None, _SHAPE),
    ("org-unit-wrong-type", ("gws_admins", "privileged", 0, "org_unit"), 1, _SHAPE),
    ("org-unit-blank", ("gws_admins", "privileged", 0, "org_unit"), "", _SHAPE),
    ("org-unit-a-group", ("gws_admins", "privileged", 0, "org_unit"), "group:g1", _SHAPE),
    ("org-unit-outside-the-map", ("gws_admins", "privileged", 0, "org_unit"), "ou:zz", _LINEAGE),
    ("groups-absent", ("gws_admins", "privileged", 0, "groups"), _DROP, _SHAPE),
    ("groups-null", ("gws_admins", "privileged", 0, "groups"), None, _SHAPE),
    ("groups-wrong-type", ("gws_admins", "privileged", 0, "groups"), "group:g1", _SHAPE),
    ("groups-entry-null", ("gws_admins", "privileged", 0, "groups"), [None], _SHAPE),
    ("groups-entry-blank", ("gws_admins", "privileged", 0, "groups"), [""], _SHAPE),
    ("groups-entry-an-ou", ("gws_admins", "privileged", 0, "groups"), ["ou:a"], _SHAPE),
    # A group listed twice is the same membership; the OU assignment still decides.
    ("groups-duplicate", ("gws_admins", "privileged", 0, "groups"), ["group:g1", "group:g1"], _MET),
    # gws_sso
    ("sso-absent", ("gws_sso",), _DROP, _NOT_COLLECTED),
    ("sso-null", ("gws_sso",), None, _SHAPE),
    ("sso-wrong-type", ("gws_sso",), [], _SHAPE),
    ("sso-complete-absent", ("gws_sso", "complete"), _DROP, _SSO_READ),
    ("sso-complete-null", ("gws_sso", "complete"), None, _SSO_READ),
    ("sso-complete-wrong-type", ("gws_sso", "complete"), "true", _SSO_READ),
    ("sso-complete-false", ("gws_sso", "complete"), False, _SSO_READ),
    ("assignments-absent", ("gws_sso", "assignments"), _DROP, _SHAPE),
    ("assignments-null", ("gws_sso", "assignments"), None, _SHAPE),
    ("assignments-wrong-type", ("gws_sso", "assignments"), {"ou:a": "SSO_OFF"}, _SHAPE),
    # A complete read with no assignment: every account signs in with Google (Commoncontrols.rego:1006).
    ("assignments-blank", ("gws_sso", "assignments"), [], _MET),
    ("assignment-entry-null", ("gws_sso", "assignments"), [None], _SHAPE),
    ("assignment-entry-wrong-type", ("gws_sso", "assignments"), ["ou:a"], _SHAPE),
    ("assignments-duplicate", ("gws_sso", "assignments"),
     [{"target": "ou:a", "sso_mode": "SSO_OFF"}, {"target": "ou:a", "sso_mode": "SSO_OFF"}], _MET),
    ("assignments-contradictory-ou", ("gws_sso", "assignments"),
     [{"target": "ou:a", "sso_mode": "SSO_OFF"}, {"target": "ou:a", "sso_mode": "SAML_SSO"}], _ASSIGNMENT),
    ("assignments-contradictory-group", ("gws_sso", "assignments"),
     [{"target": "group:g1", "sso_mode": "SSO_OFF"}, {"target": "group:g1", "sso_mode": "SAML_SSO"}], _ASSIGNMENT),
    ("target-absent", ("gws_sso", "assignments", 0, "target"), _DROP, _SHAPE),
    ("target-null", ("gws_sso", "assignments", 0, "target"), None, _SHAPE),
    ("target-wrong-type", ("gws_sso", "assignments", 0, "target"), 1, _SHAPE),
    ("target-blank", ("gws_sso", "assignments", 0, "target"), "", _SHAPE),
    ("target-unplaceable", ("gws_sso", "assignments", 0, "target"), "customers/x", _SHAPE),
    ("mode-absent", ("gws_sso", "assignments", 0, "sso_mode"), _DROP, _SHAPE),
    ("mode-null", ("gws_sso", "assignments", 0, "sso_mode"), None, _SHAPE),
    ("mode-wrong-type", ("gws_sso", "assignments", 0, "sso_mode"), 0, _SHAPE),
    # Design 5 (admin_sso row) and Commoncontrols.rego:1031-1044 list "" as Google sign-in.
    ("mode-blank", ("gws_sso", "assignments", 0, "sso_mode"), "", _MET),
    ("mode-unknown", ("gws_sso", "assignments", 0, "sso_mode"), "PASSWORDLESS_SSO", _ASSIGNMENT),
    ("mode-conditional-domain-wide", ("gws_sso", "assignments", 0, "sso_mode"), "DOMAIN_WIDE_SAML_IF_ENABLED",
     _SSO_READ),
]


@pytest.mark.parametrize(("path", "value", "answer"), [case[1:] for case in _CC61_WALK],
                         ids=[case[0] for case in _CC61_WALK])
def test_cc61_input_walk(path, value, answer):
    sections = copy.deepcopy(_cc61_base())
    *parents, last = path
    node = sections
    for key in parents:
        node = node[key]
    if value is _DROP:
        del node[last]
    else:
        node[last] = copy.deepcopy(value)
    record = gws.assess("GWS.COMMONCONTROLS.6.1v1", sections)
    assert (record["verdict"], record["cell"]) == answer


def test_cc61_walk_base_is_met():
    record = gws.assess("GWS.COMMONCONTROLS.6.1v1", _cc61_base())
    assert (record["verdict"], record["cell"]) == _MET


def _blank_second_admin(user: str, mode: str) -> dict:
    sections = _cc61_base()
    sections["gws_admins"]["super_admin_count"] = 2
    sections["gws_admins"]["privileged"].append({"user": user, "org_unit": "ou:b", "groups": ["group:g2"]})
    sections["gws_sso"]["assignments"].append({"target": "group:g2", "sso_mode": mode})
    return sections


@pytest.mark.parametrize("mode", ["SSO_OFF", "SAML_SSO"])
@pytest.mark.parametrize("user", [" ", "\t\n", "   "])
def test_cc61_whitespace_user_id_never_fills_the_super_admin_count(user, mode):
    record = gws.assess("GWS.COMMONCONTROLS.6.1v1", _blank_second_admin(user, mode))
    assert (record["verdict"], record["cell"]) == _SHAPE


@pytest.mark.parametrize("mode", ["SSO_OFF", "SAML_SSO"])
def test_cc61_padded_user_id_is_the_same_account_not_a_second_one(mode):
    # " p1 " is "p1" read twice with different groups, so the read contradicts itself and no row is trusted.
    record = gws.assess("GWS.COMMONCONTROLS.6.1v1", _blank_second_admin(" p1 ", mode))
    assert (record["verdict"], record["cell"]) == _USERS
