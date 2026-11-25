"""Identity kinds for Google Workspace (M13-L10): ``twosv``, ``super_admin_count`` and ``admin_sso``.

The policy vectors live in ``tests/fixtures/gws-value-rules/identity.jsonl`` and replay through
``tests/test_gws_value_rules_replay.py``. This file pins the rows, the parsers and the edges the vectors depend on.
Synthetic data only; every expectation is a literal.
"""
from __future__ import annotations

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
    assert {vector.get("divergence") for vector in vectors} - {None} == {"D5", "D8", "D9", "D11"}


@pytest.mark.parametrize(("text", "seconds"), [
    ("0s", 0), ("86399s", 86399), ("86400s", 86400), ("1d", 86400), ("7D", 604800), ("168h", 604800),
    ("604800s", 604800), ("604801s", 604801), ("10m", 600), ("1440M", 86400),
])
def test_duration_seconds(text, seconds):
    assert identity.duration_seconds(text) == seconds


@pytest.mark.parametrize("text", ["", "1w", "-1d", "1.5d", "d", "1 d", " 1d", "1d\n", "١d", 86400, None, True])
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
                "gws_admins": {"complete": True, "super_admin_count": 2, "memberships_complete": True,
                               "privileged": [{"user": "pseudonym-p1", "org_unit": "ou:a", "groups": ["group:g9"]}]},
                "gws_sso": {"complete": True, "assignments": [{"target": "group:g9", "sso_mode": "SAML_SSO"}]}}
    record = gws.assess("GWS.COMMONCONTROLS.6.1v1", sections)
    assert (record["verdict"], record["cell"]) == ("not_met", "admin_uses_external_sso")
    assert record["detail"] == {}
    text = json.dumps(record)
    assert "pseudonym-p1" not in text and "g9" not in text and "ou:a" not in text
