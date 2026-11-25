"""GWS SCuBA projection (M13 L06): synthetic Google bundles only; expected values are literals."""
from __future__ import annotations

import json
import os
import re
import socket
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest

from auditex.google_workspace.run import run_google_offline
from auditex.google_workspace.scuba_projection import SECTIONS, project_gws_run
from azure_tenant_audit.collection_markers import NOT_COLLECTED
from azure_tenant_audit.value_rules import gws

KEY = bytes(range(32))
# HMAC-SHA256 under KEY, first 16 hex digits, worked out independently of the code under test.
U100, U200, U300, U500 = "user:a3da8ecfe18ba66b", "user:3cd262199099fc36", "user:c53758839d880a20", "user:95072140579b78b2"
G1, G2 = "group:1f28b0e409ce3330", "group:3b8c6f8c6686cfef"
G9_EMAIL = "group:f89b76e9cadfed92"
UNRESOLVED = {"user": "user:unresolved", "org_unit": None, "groups": []}
CUSTOMER = "C0synth9x"
SETTING = "OutOfDomainWarningProto disable_untrusted_recipient_warning"  # GMAIL.13.1: good "false", bad "true"
DMARC = ("v=DMARC1; p=reject; pct=100; rua=mailto:reports@dmarc.cyber.dhs.gov,mailto:dmarc.ops@example.com!10m;"
         " ruf=mailto:forensic.ops@example.com")
DMARC_OUT = ("v=DMARC1; p=reject; rua=mailto:reports@dmarc.cyber.dhs.gov,mailto:contact@example.invalid;"
             " ruf=mailto:contact@example.invalid")
AS_OF = "2026-11-20T10:01:30.500000Z"


def write(root: Path, path: str, payload) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload) + "\n")


def load(root: Path, path: str):
    return json.loads((root / path).read_text())


def seed_key(root: Path) -> None:
    folder = root / "operator-inputs"
    folder.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(folder / "pseudonym.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.write(fd, KEY)
    os.close(fd)


def normalised(root: Path, name: str, records: list, **envelope) -> None:
    write(root, f"normalized/{name}.json", {"kind": name, "records": records, **envelope})


def rows(root: Path, name: str) -> list:
    return load(root, f"normalized/{name}.json")["records"]


def state(section: str, count: int, complete: bool = True, **extra) -> dict:
    return {"kind": f"{section}_read_state", "id": "read_state", "complete": complete, "record_count": count, **extra}


def event(when: str, name: str, **fields) -> dict:
    return {"kind": "google_setting_event", "event_time": when, "event": name, **fields}


def raw_directory(root: Path, change) -> None:
    raw = load(root, "raw/google_directory.json")
    change(raw)
    write(root, "raw/google_directory.json", raw)


USERS = [  # raw Directory users; the normalised copy below keeps the same five
    {"id": "u100", "primaryEmail": "ada.admin@example.com", "isAdmin": True, "orgUnitPath": "/"},
    {"id": "u200", "primaryEmail": "bo.admin@example.com", "isAdmin": True, "orgUnitPath": "/Sales"},
    {"id": "u300", "primaryEmail": "cy.groups@example.com", "isAdmin": False, "orgUnitPath": "/Sales"},
    {"id": "u400", "primaryEmail": "di.helpdesk@example.com", "isAdmin": False, "orgUnitPath": "/"},
    {"id": "u500", "primaryEmail": "ed.custom@example.com", "isAdmin": False, "orgUnitPath": "/Unknown"},
]


@pytest.fixture()
def bundle(tmp_path: Path) -> Path:
    root = tmp_path / "run"
    write(root, "run-manifest.json", {
        "run_id": "synthetic", "platform": "google_workspace", "customer_id": CUSTOMER, "tenant_id": CUSTOMER,
        "mode": "service_account", "created_utc": "2026-11-20T10:00:00.000000Z", "duration_seconds": 90.5,
        "coverage_path": "coverage.json", "run_dir": "/home/example/runs/synthetic",
    })
    seed_key(root)
    write(root, "coverage.json", [
        *({"collector": "google_directory", "name": name, "status": "ok", "item_count": 1}
          for name in ("users", "groups", "orgUnits", "roles", "roleAssignments", "groupMembers:g1@example.com",
                       "groupMembers:g2@example.org")),
        {"collector": "google_dns_posture", "name": "domains", "status": "ok", "item_count": 1},
        {"collector": "google_policies", "name": "policySettings", "status": "ok", "item_count": 2},
    ])
    write(root, "raw/google_directory.json", {
        "users": {"value": [{**user, "isDelegatedAdmin": False} for user in USERS]},
        "groups": {"value": [{"id": "g1grp01", "email": "g1@example.com"}, {"id": "g2grp02", "email": "g2@example.org"}]},
        "groupMembers": {"value": [
            {"groupEmail": "g1@example.com", "id": "u100", "email": "Ada.Admin@example.com", "type": "USER"},
            {"groupEmail": "g2@example.org", "id": "u100", "email": "ada.admin@example.com", "type": "USER"},
            {"groupEmail": "g2@example.org", "id": "x999", "email": "guest@example.net", "type": "USER"}]},
        "groupMembersErrors": {"value": []},
        "orgUnits": {"value": [
            {"orgUnitId": "id:root01", "orgUnitPath": "/", "name": "Example Org"},
            {"orgUnitId": "id:ou0a1", "orgUnitPath": "/Sales", "name": "Sales", "parentOrgUnitId": "id:root01",
             "parentOrgUnitPath": "/"},
        ]},
        "roles": {"value": [
            {"roleId": "1", "roleName": "_SEED_ADMIN_ROLE", "isSuperAdminRole": True},
            {"roleId": "2", "roleName": "Groups Admin", "isSuperAdminRole": False},
            {"roleId": "4", "roleName": "Help Desk", "rolePrivileges": [{"privilegeName": "USERS_RETRIEVE"}]},
            {"roleId": 5, "roleName": "Custom", "rolePrivileges": [{"privilegeName": "USERS_ALL", "serviceId": "s1"}]},
        ]},
        "roleAssignments": {"value": [{"roleId": "1"}, {"roleId": "2"}, {"roleId": "4"}, {"roleId": 5}]},
    })
    normalised(root, "google_users", [
        {"kind": "google_user", "id": u["id"], "primary_email": u["primaryEmail"], "display_name": "Synthetic Person",
         "is_admin": u["isAdmin"], "is_delegated_admin": False, "org_unit_path": u["orgUnitPath"]} for u in USERS])
    normalised(root, "google_role_assignments", [
        {"kind": "google_role_assignment", "role_id": "1", "assigned_to": "u100"},
        {"kind": "google_role_assignment", "role_id": "2", "assigned_to": "u300"},
        {"kind": "google_role_assignment", "role_id": "4", "assigned_to": "u400"},
        {"kind": "google_role_assignment", "role_id": 5, "assigned_to": "u500"},
    ])
    # Written as the normaliser does; the projection joins memberships on the raw rows, which keep member ids.
    normalised(root, "google_groups", [{"kind": "google_group", "id": "g1grp01", "email": "g1@example.com"},
                                       {"kind": "google_group", "id": "g2grp02", "email": "g2@example.org"}])
    normalised(root, "google_group_members", [
        {"kind": "google_group_member", "group_email": "g1@example.com", "email": "Ada.Admin@example.com", "type": "USER"},
        {"kind": "google_group_member", "group_email": "g2@example.org", "email": "ada.admin@example.com", "type": "USER"},
        {"kind": "google_group_member", "group_email": "g2@example.org", "email": "guest@example.net", "type": "USER"}])
    normalised(root, "google_org_units", [
        {"kind": "google_org_unit", "id": "ou0a1", "parent_id": "root01", "is_root": False},
        {"kind": "google_org_unit", "id": "root01", "parent_id": None, "is_root": True},
        state("google_org_units", 2, root_id_known=True, malformed_count=0)])
    write(root, "raw/google_policies.json", {"policySettings": {"value": [
        {"policyQuery": {"orgUnit": "orgUnits/root01", "sortOrder": 1},
         "setting": {"type": "settings/gmail.auto_forwarding", "value": {"enableAutoForwarding": False}}, "type": "ADMIN"},
        {"policyQuery": {"orgUnit": "orgUnits/root01", "group": "groups/g1grp01", "sortOrder": 2.5},
         "setting": {"type": "settings/drive_and_docs.external_sharing", "value": {"externalSharingMode": "DISALLOWED"}},
         "type": "ADMIN"}]}})
    normalised(root, "google_policy_settings", [
        {"kind": "google_policy_setting", "section": "gmail_auto_forwarding", "unit_kind": "org_unit",
         "org_unit": "root01", "sort_order": 1, "value": {"enableAutoForwarding": False}},
        {"kind": "google_policy_setting", "section": "drive_and_docs_external_sharing", "unit_kind": "group",
         "org_unit": "root01", "group": "g1grp01", "sort_order": 2.5, "value": {"externalSharingMode": "DISALLOWED"}},
        state("google_policy_settings", 2)])
    normalised(root, "google_setting_events", [
        event("2026-10-01T10:00:00.123456789Z", "CHANGE_APPLICATION_SETTING", setting=SETTING, new_value="false",
              org_unit="ou0a1", application="Gmail"),
        event("2026-10-02T10:00:00Z", "TOGGLE_CAA_ENABLEMENT", new_value="ENABLED"),
        event("2026-10-03T10:00:00Z", "DELETE_APPLICATION_SETTING", setting=SETTING, org_unit="root01"),
        event("2026-10-04T10:00:00Z", "CHANGE_APPLICATION_SETTING", setting=SETTING, new_value="true",
              group_email="G1@example.com"),
        event("2026-10-05T10:00:00Z", "CHANGE_GMAIL_SETTING", setting=SETTING, new_value="true",
              group_email="g9@example.com"),
        state("google_setting_events", 5, window_start="2026-05-25T00:00:00Z", window_end="2026-11-20T10:01:30Z")])
    normalised(root, "google_sso_assignments", [
        {"kind": "google_sso_assignment", "target_org_unit": "orgUnits/ou0a1", "sso_mode": "SSO_OFF"},
        {"kind": "google_sso_assignment", "target_group": "groups/g1grp01", "sso_mode": "SAML_SSO"},
        state("google_sso_assignments", 2)])
    normalised(root, "google_domains", [
        {"kind": "google_domain", "domain_name": "example.com", "domain_kind": "primary"},
        {"kind": "google_domain", "domain_name": "example.net", "domain_kind": "alias"}])
    normalised(root, "google_dns_posture", [
        {"kind": "google_domain_posture", "domain": "example.com", "alias": False,
         "spf": {"records": ["v=spf1 include:_spf.google.com -all"]},
         "dkim": {"selectors": {"google": ["v=DKIM1; k=rsa; p=AAAA"], "selector1": [], "selector2": [], "s1": ["x"]}},
         "dmarc": {"query_name": "_dmarc.example.com", "inherited": False, "records": [DMARC, "google-site-verification=x"]}},
        {"kind": "google_domain_posture", "domain": "example.net", "resolver_error": "timeout via https://resolver.example/dns-query",
         "dmarc": {"query_name": "_dmarc.example.net"}},
    ])
    write(root, "raw/google_dns_posture.json", {"domains": {"value": [{"domainName": "example.com"}]},
                                                "domainPosture": {"value": [{}, {}]}})
    return root


EXPECTED = {
    "gws_tenant": {"as_of": AS_OF, "top_unit": "ou:root01",
                   "org_units": {"ou:ou0a1": "ou:root01", "ou:root01": None}, "complete": True},
    "gws_policies": {"complete": True, "policies": [
        {"unit": "ou:root01", "unit_kind": "org_unit", "section": "gmail_auto_forwarding", "sort_order": 1,
         "value": {"enableAutoForwarding": False}},
        {"unit": f"ou:root01/{G1}", "unit_kind": "group", "section": "drive_and_docs_external_sharing",
         "sort_order": 2.5, "value": {"externalSharingMode": "DISALLOWED"}}]},
    "gws_setting_events": {"complete": True, "window_start": "2026-05-25T00:00:00Z",
                           "window_end": "2026-11-20T10:01:30Z", "events": [
        {"time": "2026-10-01T10:00:00.123456789Z", "event": "CHANGE_APPLICATION_SETTING", "setting": SETTING,
         "new_value": "false", "unit": "ou:ou0a1", "application": "Gmail"},
        {"time": "2026-10-02T10:00:00Z", "event": "TOGGLE_CAA_ENABLEMENT", "setting": None, "new_value": "ENABLED",
         "unit": None, "application": None},
        {"time": "2026-10-03T10:00:00Z", "event": "DELETE_APPLICATION_SETTING", "setting": SETTING,
         "new_value": None, "unit": "ou:root01", "application": None},
        {"time": "2026-10-04T10:00:00Z", "event": "CHANGE_APPLICATION_SETTING", "setting": SETTING,
         "new_value": "true", "unit": G1, "application": None},
        {"time": "2026-10-05T10:00:00Z", "event": "CHANGE_GMAIL_SETTING", "setting": SETTING,
         "new_value": "true", "unit": G9_EMAIL, "application": None}]},
    "gws_dns": {"complete": True, "domains": [
        {"domain": "example.com", "alias": False, "resolver_error": False,
         "spf": {"records": ["v=spf1 -all"]},
         "dkim": {"selectors": {"google": ["v=DKIM1;"], "selector1": [], "selector2": []}},
         "dmarc": {"query_name": "_dmarc.example.com", "inherited": False, "records": [DMARC_OUT, "unrecognised"]}},
        {"domain": "example.net", "alias": True, "resolver_error": True, "spf": {"records": None},
         "dkim": {"selectors": {"google": None, "selector1": None, "selector2": None}},
         "dmarc": {"query_name": "_dmarc.example.net", "inherited": None, "records": None}}]},
    "gws_admins": {"complete": True, "super_admin_count": 2, "memberships_complete": True, "privileged": [
        {"user": U100, "org_unit": "ou:root01", "groups": sorted([G1, G2])},
        {"user": U200, "org_unit": "ou:ou0a1", "groups": []},
        {"user": U300, "org_unit": "ou:ou0a1", "groups": []},
        {"user": U500, "org_unit": None, "groups": []}]},
    "gws_sso": {"complete": True, "assignments": [{"target": "ou:ou0a1", "sso_mode": "SSO_OFF"},
                                                  {"target": G1, "sso_mode": "SAML_SSO"}]},
}


def verdict(projection, policy_id: str) -> tuple[str, str]:
    answer = gws.assess(policy_id, dict(projection))
    return answer["verdict"], answer["reason_code"]


def test_each_section_from_a_synthetic_bundle(bundle: Path) -> None:
    projection = project_gws_run(bundle)
    assert dict(projection) == EXPECTED
    sections = projection.report["sections"]
    assert {name: entry["status"] for name, entry in sections.items()} == {name: "projected" for name in SECTIONS}
    assert set(sections["gws_admins"]["source"]) == {
        "run-manifest.json", "normalized/google_users.json", "normalized/google_role_assignments.json",
        "raw/google_directory.json", "coverage.json", "normalized/google_org_units.json"}
    assert projection.report["redaction"] == {"enabled": True, "strategy": "keyed-hmac-sha256-v1", "user_ids": 4,
                                              "group_ids": 3, "email_addresses": 2}
    assert projection.report["schema_version"] == "2026-11-25.2"


# --- B1: only allow-listed vocabulary, pseudonyms, ids, counts and verdict-relevant values --------------------------


def test_no_address_customer_id_group_id_path_or_name_in_the_output(bundle: Path) -> None:
    events = rows(bundle, "google_setting_events")
    events[0]["new_value"] = f"customers/{CUSTOMER} /home/example/x https://resolver.example/dns-query?profile=p1"
    events[0]["application"] = "Ada Admin"
    events.insert(1, event("2026-10-01T11:00:00Z", "CHANGE_APPLICATION_SETTING", setting="Ops ops@example.com"))
    normalised(bundle, "google_setting_events", events[:-1] + [{**events[-1], "record_count": 6}])
    policies = rows(bundle, "google_policy_settings")
    policies[0]["value"] = {"enableAutoForwarding": False, "ops@example.com": True}
    normalised(bundle, "google_policy_settings", policies)
    projection = project_gws_run(bundle)
    text = json.dumps([dict(projection), projection.report])
    for needle in ("ada.admin", "bo.admin", "cy.groups", "ed.custom", "g1@example.com", "g9@example.com", "ops@",
                   "dmarc.ops", "forensic.ops", "guest@", CUSTOMER, "g1grp01", "g2grp02", "/Sales", "Sales",
                   "Example Org", "Synthetic Person", "Ada Admin", "/home/example", "resolver.example", "timeout",
                   "u100", "u500", "x999", "Ops", "google-site-verification", "k=rsa", "pct=100"):
        assert needle not in text, needle
    assert projection["gws_setting_events"]["events"][0]["new_value"] == "unrecognised"
    assert projection["gws_setting_events"]["events"][0]["application"] == ""
    assert projection["gws_setting_events"]["events"][1] == {
        "time": "2026-10-01T11:00:00Z", "event": "", "setting": None, "new_value": None, "unit": None,
        "application": None}
    assert projection["gws_policies"]["policies"][0] == {
        "unit": "ou:root01", "unit_kind": "org_unit", "section": "gmail_auto_forwarding", "sort_order": 1}


def dns_only(bundle: Path, *records: dict) -> None:
    normalised(bundle, "google_dns_posture", list(records))
    write(bundle, "raw/google_dns_posture.json", {"domains": {"value": [{"domainName": "example.com"}]},
                                                  "domainPosture": {"value": [{} for _ in records]}})


def good_domain(name: str = "example.com", **change) -> dict:
    return {"kind": "google_domain_posture", "domain": name, "alias": False,
            "spf": {"records": ["v=spf1 include:_spf.google.com -all"]},
            "dkim": {"selectors": {"google": ["v=DKIM1; p=AAAA"], "selector1": [], "selector2": []}},
            "dmarc": {"query_name": f"_dmarc.{name}", "inherited": False, "records": [DMARC]}, **change}


@pytest.mark.parametrize("record,expected", [
    (DMARC, {"GWS.GMAIL.4.1v1": "met", "GWS.GMAIL.4.2v1": "met", "GWS.GMAIL.4.3v1": "met", "GWS.GMAIL.4.4v1": "met"}),
    ("v=DMARC1; p=reject; rua=mailto:reports@dmarc.example.com,mailto:a@example.com; ruf=mailto:b@example.com",
     {"GWS.GMAIL.4.3v1": "not_met", "GWS.GMAIL.4.4v1": "met"}),
    ("v=DMARC1; p=quarantine; rua=mailto:REPORTS@dmarc.cyber.dhs.gov", {"GWS.GMAIL.4.2v1": "not_met",
                                                                       "GWS.GMAIL.4.3v1": "not_met",
                                                                       "GWS.GMAIL.4.4v1": "not_met"}),
    ("v=DMARC1; p=bogus; rua=mailto:reports@dmarc.cyber.dhs.gov%2Cx@example.com", {"GWS.GMAIL.4.1v1": "met",
                                                                                  "GWS.GMAIL.4.2v1": "not_met",
                                                                                  "GWS.GMAIL.4.3v1": "met"}),
    ("v=DMARC1; p=reject; p=none", {"GWS.GMAIL.4.1v1": "not_met"}),
])
def test_dmarc_contacts_leave_the_bundle_and_the_dns_answers_stay(bundle: Path, record, expected) -> None:
    dns_only(bundle, good_domain(dmarc={"query_name": "_dmarc.example.com", "inherited": False, "records": [record]}))
    projection = project_gws_run(bundle)
    text = json.dumps(projection["gws_dns"])
    assert "@example.com" not in text and "dmarc.example.com," not in text
    assert {policy: verdict(projection, policy)[0] for policy in expected} == expected


# --- B3: the evaluation instant ---------------------------------------------------------------------------------


def _policy(setting: str, value: dict, *, org_unit: str | None = "root01", group: str | None = None,
            order: int = 1) -> dict:
    query = {"sortOrder": order, **({"orgUnit": f"orgUnits/{org_unit}"} if org_unit else {}),
             **({"group": f"groups/{group}"} if group else {})}
    return {"name": f"policies/{setting}-{org_unit}-{group}", "customer": f"customers/{CUSTOMER}", "policyQuery": query,
            "setting": {"type": f"settings/{setting}", "value": value}, "type": "ADMIN"}


def replay(tmp_path: Path, policies: list[dict], *, as_of: datetime | None = None, users=None, org_units=None,
           sso=None, groups=None, members=None) -> Path:
    two_step = [row for row in policies if row["setting"]["type"].startswith("settings/security.two_step")]
    sample = {
        "google_directory": {
            "users": {"value": users or [
                {"id": "u100", "primaryEmail": "ada.admin@example.com", "isAdmin": True, "isDelegatedAdmin": False,
                 "orgUnitPath": "/"},
                {"id": "u200", "primaryEmail": "bo.admin@example.com", "isAdmin": True, "isDelegatedAdmin": False,
                 "orgUnitPath": "/Sales"}]},
            "groups": {"value": groups or []},
            "groupMembers": {"value": members or []},
            "roles": {"value": [{"roleId": "1", "roleName": "_SEED_ADMIN_ROLE", "isSuperAdminRole": True}]},
            "roleAssignments": {"value": [{"roleId": "1", "assignedTo": "u100"}]},
            "orgUnits": {"value": org_units or [
                {"orgUnitId": "id:ou0a1", "name": "Sales", "orgUnitPath": "/Sales", "parentOrgUnitPath": "/",
                 "parentOrgUnitId": "id:root01"}]},
        },
        "google_policies": {"twoStepVerificationPolicies": {"value": two_step}, "policySettings": {"value": policies}},
        **({"google_sso_assignments": {"inboundSsoAssignments": {"value": sso}}} if sso is not None else {}),
    }
    path = tmp_path / "sample.json"
    path.write_text(json.dumps(sample))
    assert run_google_offline(sample_path=path, out=tmp_path / "out", tenant_name="E", run_name="g",
                              domain="example.com", customer_id=CUSTOMER, as_of=as_of) == 0
    return tmp_path / "out" / "E-g"


ENROLLED = _policy("security.two_step_verification_enrollment", {"allowEnrollment": True})


def test_an_offline_replay_has_no_collection_end_and_no_2sv_answer(tmp_path: Path) -> None:
    # B3: the replay was judged at --as-of 2024-01-01, which the manifest does not record; enforcement from 2025 was not
    # in force then, so the bundle's creation time must not stand in for it.
    run_dir = replay(tmp_path, [ENROLLED, _policy("security.two_step_verification_enforcement",
                                                  {"enforcedFrom": "2025-01-01T00:00:00Z"})],
                     as_of=datetime(2024, 1, 1, tzinfo=UTC))
    projection = project_gws_run(run_dir)
    assert projection["gws_tenant"]["as_of"] is None
    assert verdict(projection, "GWS.COMMONCONTROLS.1.2v1") == ("not_assessed", "data_unusable_section_shape")


@pytest.mark.parametrize("manifest,expected", [({"mode": "offline"}, None), ({"replay_source": {"kind": "x"}}, None),
                                               ({"mode": "service_account"}, AS_OF), ({}, AS_OF)])
def test_the_collection_end_is_only_a_live_runs(bundle: Path, manifest, expected) -> None:
    data = load(bundle, "run-manifest.json")
    data.pop("mode")
    write(bundle, "run-manifest.json", {**data, **manifest})
    assert project_gws_run(bundle)["gws_tenant"]["as_of"] == expected


# --- B4: group-only policies ------------------------------------------------------------------------------------


def test_a_group_only_policy_is_kept_under_the_top_unit(tmp_path: Path) -> None:
    run_dir = replay(tmp_path, [
        ENROLLED, _policy("security.two_step_verification_enforcement", {"enforcedFrom": "2020-01-01T00:00:00Z"}),
        _policy("security.two_step_verification_enrollment", {"allowEnrollment": False}, org_unit=None,
                group="g1grp01", order=2)], groups=[{"id": "g1grp01", "email": "g1@example.com"}])
    projection = project_gws_run(run_dir)
    policies = projection["gws_policies"]
    assert policies["complete"] is True
    # The replay writes its own pseudonym key, so the group's pseudonym is checked by shape.
    assert [(re.sub(r"group:[0-9a-f]{16}\Z", "group:G", entry["unit"]), entry["unit_kind"], entry["section"])
            for entry in policies["policies"]] == [
        ("ou:root01", "org_unit", "security_two_step_verification_enrollment"),
        ("ou:root01", "org_unit", "security_two_step_verification_enforcement"),
        ("ou:root01/group:G", "group", "security_two_step_verification_enrollment")]
    assert "g1grp01" not in json.dumps(dict(projection))
    sections = {**projection, "gws_tenant": {**projection["gws_tenant"], "as_of": "2026-11-20T00:00:00Z"}}
    assert verdict(sections, "GWS.COMMONCONTROLS.1.2v1") == ("not_met", "unit_violates")


# --- B5: the super admin count ------------------------------------------------------------------------------------


def test_a_cut_user_envelope_proves_no_count(bundle: Path) -> None:
    normalised(bundle, "google_users", rows(bundle, "google_users"), collection_truncated=True)
    projection = project_gws_run(bundle)
    assert projection["gws_admins"]["complete"] is False
    assert verdict(projection, "GWS.COMMONCONTROLS.6.2v1") == ("not_assessed", "data_unavailable_user_read_incomplete")


def test_a_duplicated_user_row_proves_no_count(bundle: Path) -> None:
    users = rows(bundle, "google_users")
    users[1] = dict(users[0])
    normalised(bundle, "google_users", users)
    projection = project_gws_run(bundle)
    assert projection["gws_admins"]["complete"] is False
    assert verdict(projection, "GWS.COMMONCONTROLS.6.2v1") == ("not_assessed", "data_unavailable_user_read_incomplete")


@pytest.mark.parametrize("flag", ["true", 1, None, "missing"])
def test_a_raw_admin_flag_that_is_not_a_boolean_proves_no_count(bundle: Path, flag) -> None:
    def change(raw):
        if flag == "missing":
            del raw["users"]["value"][1]["isAdmin"]
        else:
            raw["users"]["value"][1]["isAdmin"] = flag
    raw_directory(bundle, change)
    projection = project_gws_run(bundle)
    assert projection["gws_admins"]["complete"] is False
    assert verdict(projection, "GWS.COMMONCONTROLS.6.2v1")[0] == "not_assessed"


# --- B6: memberships ----------------------------------------------------------------------------------------------


def test_a_member_is_joined_by_its_stable_id(bundle: Path) -> None:
    raw_directory(bundle, lambda raw: raw["groupMembers"]["value"].append(
        {"groupEmail": "g1@example.com", "id": "u200", "email": "bo.old.address@example.com", "type": "USER"}))
    projection = project_gws_run(bundle)
    assert projection["gws_admins"]["privileged"][1] == {"user": U200, "org_unit": "ou:ou0a1", "groups": [G1]}
    assert projection["gws_admins"]["memberships_complete"] is True


@pytest.mark.parametrize("change", ["no_fanout_coverage", "fanout_failed", "member_by_unknown_address"])
def test_memberships_need_proof_for_every_group(bundle: Path, change) -> None:
    if change == "member_by_unknown_address":
        raw_directory(bundle, lambda raw: raw["groupMembers"]["value"].append(
            {"groupEmail": "g1@example.com", "email": "someone@example.com", "type": "USER"}))
    else:
        coverage = load(bundle, "coverage.json")
        if change == "no_fanout_coverage":
            # The review's case: groups kept, their member reads gone, an empty raw list and no normalised one.
            coverage = [row for row in coverage if not row["name"].startswith("groupMembers:")]
            raw_directory(bundle, lambda raw: raw["groupMembers"].update(value=[]))
            (bundle / "normalized/google_group_members.json").unlink(missing_ok=True)
        else:
            coverage = [{**row, "status": "failed"} if row["name"] == "groupMembers:g2@example.org" else row
                        for row in coverage]
        write(bundle, "coverage.json", coverage)
    admins = project_gws_run(bundle)["gws_admins"]
    assert admins["memberships_complete"] is False and admins["complete"] is True


# --- B7: event fields ---------------------------------------------------------------------------------------------


def caa(bundle: Path, **fields) -> None:
    normalised(bundle, "google_setting_events", [
        event("2026-10-02T10:00:00Z", "TOGGLE_CAA_ENABLEMENT", new_value="ENABLED", **fields),
        state("google_setting_events", 1, window_start="2026-05-25T00:00:00Z", window_end="2026-11-20T10:01:30Z")])


def test_a_present_but_malformed_application_is_ambiguous(bundle: Path) -> None:
    caa(bundle)
    assert verdict(project_gws_run(bundle), "GWS.COMMONCONTROLS.2.1v1") == ("met", "no_unit_violates")
    caa(bundle, application=False)
    projection = project_gws_run(bundle)
    assert projection["gws_setting_events"]["events"][0]["application"] == ""
    assert verdict(projection, "GWS.COMMONCONTROLS.2.1v1") == ("not_assessed", "data_unusable_event_value")


@pytest.mark.parametrize("newer", [{"org_unit": "root01", "group_email": "bogus"}, {"group_email": "bogus"},
                                   {"org_unit": "zz999"}, {"org_unit": "a b"}, {}])
def test_a_newer_event_whose_unit_cannot_be_told_voids_the_older_one(bundle: Path, newer) -> None:
    normalised(bundle, "google_setting_events", [
        event("2026-10-01T10:00:00Z", "CHANGE_APPLICATION_SETTING", setting=SETTING, new_value="false",
              org_unit="root01"),
        event("2026-10-02T10:00:00Z", "CHANGE_APPLICATION_SETTING", setting=SETTING, new_value="true", **newer),
        state("google_setting_events", 2, window_start="2026-05-25T00:00:00Z", window_end="2026-11-20T10:01:30Z")])
    projection = project_gws_run(bundle)
    assert projection["gws_setting_events"]["events"][1]["unit"] is None
    assert verdict(projection, "GWS.GMAIL.13.1v1") == ("not_assessed", "data_unusable_event_value")


@pytest.mark.parametrize("change,field,expected", [
    ({"event": "LOGIN"}, "event", ""), ({"event": 4}, "event", ""), ({"setting": ["x"]}, "event", ""),
    ({"new_value": {"v": 1}}, "new_value", None), ({"new_value": "maybe"}, "new_value", "unrecognised"),
    ({"application": "Ada Admin"}, "application", ""), ({"event_time": "yesterday"}, "time", None),
    ({"event_time": 5}, "time", None)])
def test_event_fields_outside_the_vocabulary(bundle: Path, change, field, expected) -> None:
    events = rows(bundle, "google_setting_events")
    events[0].update(change)
    normalised(bundle, "google_setting_events", events)
    section = project_gws_run(bundle)["gws_setting_events"]
    assert section["complete"] is True and section["events"][0][field] == expected


# --- B8: DNS scope and read health --------------------------------------------------------------------------------


def test_a_malformed_alias_flag_leaves_the_domain_unusable(bundle: Path) -> None:
    dns_only(bundle, good_domain(), good_domain("example.net", alias="no", spf={"records": []}))
    projection = project_gws_run(bundle)
    assert projection["gws_dns"]["domains"][1]["alias"] is None
    assert verdict(projection, "GWS.GMAIL.3.1v1") == ("not_assessed", "data_unusable_domain_record")


def test_an_alias_flag_contradicting_the_directory_is_unusable(bundle: Path) -> None:
    dns_only(bundle, good_domain(), good_domain("example.net", alias=False))
    assert project_gws_run(bundle)["gws_dns"]["domains"][1]["alias"] is None


@pytest.mark.parametrize("read_state", [False, True])
def test_a_partial_posture_read_is_incomplete(bundle: Path, read_state) -> None:
    domains = [good_domain(), good_domain("example.net", alias=True)]
    dns_only(bundle, *domains, *([state("google_dns_posture", 2)] if read_state else []))
    write(bundle, "raw/google_dns_posture.json", {"domains": {"value": [{"domainName": "example.com"}]},
                                                  "domainPosture": {"value": [{}, {}], "partial": True,
                                                                    "error_class": "denied"}})
    projection = project_gws_run(bundle)
    assert projection["gws_dns"]["complete"] is False
    assert verdict(projection, "GWS.GMAIL.3.1v1") == ("not_assessed", "data_unavailable_dns_read_incomplete")


# --- M1: attributed failures weaken only what they name -----------------------------------------------------------


TWO_STEP = [
    {"kind": "google_policy_setting", "section": "security_two_step_verification_enrollment", "unit_kind": "org_unit",
     "org_unit": "root01", "sort_order": 1, "value": {"allowEnrollment": True}},
    {"kind": "google_policy_setting", "section": "security_two_step_verification_enforcement",
     "unit_kind": "org_unit", "org_unit": "root01", "sort_order": 1, "value": {"enforcedFrom": "2020-01-01T00:00:00Z"}}]


def attributed(bundle: Path, raw_type: str = "settings/gmail.auto_forwarding") -> None:
    normalised(bundle, "google_policy_settings", [*TWO_STEP, state(
        "google_policy_settings", 2, complete=False, malformed_count=1, unusable_sections=[],
        unusable_scopes=[{"section": "gmail_auto_forwarding", "org_unit": "root01", "group": None}])])
    write(bundle, "raw/google_policies.json", {"policySettings": {"value": [
        {"policyQuery": {"orgUnit": "orgUnits/root01", "sortOrder": 1},
         "setting": {"type": "settings/security.two_step_verification_enrollment", "value": {"allowEnrollment": True}}},
        {"policyQuery": {"orgUnit": "orgUnits/root01", "sortOrder": 1},
         "setting": {"type": "settings/security.two_step_verification_enforcement",
                     "value": {"enforcedFrom": "2020-01-01T00:00:00Z"}}},
        {"policyQuery": {"orgUnit": "orgUnits/root01", "sortOrder": 1},
         "setting": {"type": raw_type, "value": {"enableAutoForwarding": None}}, "type": "ADMIN"}]}})
    coverage = load(bundle, "coverage.json")
    write(bundle, "coverage.json", [*coverage, {"collector": "google_policies", "name": "policySettings",
                                                "status": "partial", "error_class": "malformed_response",
                                                "policy_row_validation": True}])


def test_an_attributed_policy_failure_leaves_other_settings_answerable(bundle: Path) -> None:
    attributed(bundle)
    projection = project_gws_run(bundle)
    assert projection["gws_policies"]["complete"] is True
    assert projection["gws_policies"]["policies"][-1] == {
        "unit": "ou:root01", "unit_kind": "org_unit", "section": "gmail_auto_forwarding", "sort_order": None}
    assert verdict(projection, "GWS.COMMONCONTROLS.1.2v1") == ("met", "no_unit_violates")
    assert verdict(projection, "GWS.GMAIL.11.1v1")[0] == "not_assessed"


def test_an_unattributed_policy_failure_leaves_the_read_incomplete(bundle: Path) -> None:
    attributed(bundle, raw_type="settings/not_a_service.thing")
    projection = project_gws_run(bundle)
    assert projection["gws_policies"]["complete"] is False
    assert verdict(projection, "GWS.COMMONCONTROLS.1.2v1") == ("not_assessed", "data_unavailable_policy_read_incomplete")


def test_a_refused_role_list_leaves_the_super_admin_count_answerable(bundle: Path) -> None:
    raw_directory(bundle, lambda raw: raw["roles"].update(value=[], error_class="insufficient_permissions"))
    projection = project_gws_run(bundle)
    admins = projection["gws_admins"]
    assert admins["complete"] is True and admins["super_admin_count"] == 2
    assert admins["privileged"] == [{"user": U100, "org_unit": "ou:root01", "groups": sorted([G1, G2])},
                                    {"user": U200, "org_unit": "ou:ou0a1", "groups": []}, UNRESOLVED]
    assert verdict(projection, "GWS.COMMONCONTROLS.6.2v1") == ("met", "count_in_range")
    assert verdict(projection, "GWS.COMMONCONTROLS.6.1v1")[0] == "not_assessed"


# --- M2: legacy unit lists ----------------------------------------------------------------------------------------


def test_a_legacy_unit_list_without_a_root_row_still_places_admins(tmp_path: Path) -> None:
    run_dir = replay(tmp_path, [ENROLLED], users=[
        {"id": "u100", "primaryEmail": "ada.admin@example.com", "isAdmin": True, "isDelegatedAdmin": False,
         "orgUnitPath": "/"},
        {"id": "u200", "primaryEmail": "bo.admin@example.com", "isAdmin": True, "isDelegatedAdmin": False,
         "orgUnitPath": "/Sales"}], sso=[{"targetOrgUnit": "orgUnits/root01", "ssoMode": "SAML_SSO"}])
    projection = project_gws_run(run_dir)
    assert [entry["org_unit"] for entry in projection["gws_admins"]["privileged"]] == ["ou:root01", "ou:ou0a1"]
    assert verdict(projection, "GWS.COMMONCONTROLS.6.1v1") == ("not_met", "admin_uses_external_sso")


# --- M3: every row a section uses counts against the bound ----------------------------------------------------------


def test_raw_and_supporting_rows_count_against_the_bound(bundle: Path) -> None:
    normalised(bundle, "google_setting_events", [
        event("2026-10-01T10:00:00Z", "CHANGE_APPLICATION_SETTING", setting=SETTING, new_value="false",
              org_unit="ou0a1"),
        state("google_setting_events", 1, window_start="2026-05-25T00:00:00Z", window_end="2026-11-20T10:01:30Z")])
    report = project_gws_run(bundle, scan_max_rows=2).report["sections"]["gws_setting_events"]
    assert (report["reason"], report["detail"]) == ("oversize", {"field": "scan_max_rows", "kind": "scan_bound"})
    # gws_admins: 5 + 4 normalised rows, 5 + 4 + 4 + 2 + 3 + 2 raw Directory rows, 9 coverage rows, 3 unit rows.
    assert project_gws_run(bundle, scan_max_rows=41).report["sections"]["gws_admins"]["reason"] is None
    assert project_gws_run(bundle, scan_max_rows=40).report["sections"]["gws_admins"]["reason"] == "oversize"


# --- M4: the tenant topology ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("parent", ["zz999", "ou0a1"])
def test_a_dangling_or_looping_unit_is_not_a_complete_topology(bundle: Path, parent) -> None:
    units = rows(bundle, "google_org_units")
    units[0]["parent_id"] = parent
    normalised(bundle, "google_org_units", units)
    tenant = project_gws_run(bundle)["gws_tenant"]
    assert tenant["complete"] is False and tenant["org_units"]["ou:ou0a1"] == f"ou:{parent}"


# --- shape, markers, bounds -----------------------------------------------------------------------------------------


def test_old_google_bundle_gives_markers(bundle: Path) -> None:
    for name in ("google_org_units", "google_policy_settings", "google_setting_events", "google_sso_assignments"):
        (bundle / f"normalized/{name}.json").unlink()
    normalised(bundle, "google_dns_posture", [{"kind": "google_domain_posture", "domain": "example.com",
                                               "dmarc": {"present": True, "policy": "reject"}}])
    projection = project_gws_run(bundle)
    for name in ("gws_tenant", "gws_policies", "gws_setting_events", "gws_sso", "gws_dns"):
        assert projection[name] == NOT_COLLECTED
    reasons = {name: entry["reason"] for name, entry in projection.report["sections"].items()}
    assert reasons == {"gws_tenant": "missing_artifact", "gws_policies": "missing_artifact",
                       "gws_setting_events": "missing_artifact", "gws_dns": "incomplete_shape",
                       "gws_admins": None, "gws_sso": "missing_artifact"}
    assert projection.report["sections"]["gws_dns"]["detail"] == {"field": "dmarc.query_name", "kind": "missing_field"}
    assert projection["gws_admins"]["complete"] is True
    assert [entry["org_unit"] for entry in projection["gws_admins"]["privileged"]] == [None, None, None, None]


@pytest.mark.parametrize("manifest", [{"run_id": "m", "platform": "m365"}, {"run_id": "m"}])
def test_m365_bundle_is_not_applicable(tmp_path: Path, manifest: dict) -> None:
    write(tmp_path, "run-manifest.json", manifest)
    projection = project_gws_run(tmp_path)
    assert dict(projection) == {name: {"collection_status": "not_collected"} for name in SECTIONS}
    assert {entry["reason"] for entry in projection.report["sections"].values()} == {"not_applicable_to_platform"}


def test_missing_or_unreadable_manifest_gives_markers(tmp_path: Path) -> None:
    assert {e["reason"] for e in project_gws_run(tmp_path).report["sections"].values()} == {"missing_artifact"}
    (tmp_path / "run-manifest.json").write_text('{"platform": "google_workspace", "platform": "m365"}')
    assert {e["reason"] for e in project_gws_run(tmp_path).report["sections"].values()} == {"incomplete_shape"}


def test_read_only_and_no_network(bundle: Path, monkeypatch) -> None:
    def tree() -> dict:
        return {str(p.relative_to(bundle)): (p.stat().st_mode, sha256(p.read_bytes()).hexdigest())
                for p in bundle.rglob("*") if p.is_file()}
    before = tree()
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: pytest.fail("projection opened a socket"))
    project_gws_run(bundle)
    assert tree() == before


def test_bounds_give_oversize(bundle: Path) -> None:
    small = project_gws_run(bundle, max_items=4)
    assert {name: e["reason"] for name, e in small.report["sections"].items()} == {
        "gws_tenant": None, "gws_policies": None, "gws_setting_events": "oversize", "gws_dns": None,
        "gws_admins": None, "gws_sso": None}
    assert small["gws_setting_events"] == NOT_COLLECTED
    tiny = project_gws_run(bundle, scan_max_bytes=64).report["sections"]
    assert {e["reason"] for e in tiny.values()} == {"oversize"}
    assert project_gws_run(bundle, max_chars=100).report["sections"]["gws_policies"]["reason"] == "oversize"
    with pytest.raises(ValueError):
        project_gws_run(bundle, max_items=0)


@pytest.mark.parametrize("section,name", [("gws_policies", "google_policy_settings"),
                                          ("gws_setting_events", "google_setting_events"),
                                          ("gws_sso", "google_sso_assignments"),
                                          ("gws_tenant", "google_org_units")])
@pytest.mark.parametrize("bad", [{"complete": False}, {"complete": None}, {"complete": "true"}, {"record_count": 9},
                                 {"record_count": True}, {"record_count": None}, "missing", "twice", "cut"])
def test_read_state_not_proving_a_complete_read_is_incomplete(bundle: Path, section, name, bad) -> None:
    data = rows(bundle, name)
    records, read_state = data[:-1], data[-1]
    envelope = {}
    if bad == "twice":
        records = [*records, read_state, read_state]
    elif bad == "cut":
        records, envelope = data, {"collection_truncated": True}
    elif bad != "missing":
        records = [*records, {**read_state, **bad}]
    normalised(bundle, name, records, **envelope)
    assert project_gws_run(bundle)[section]["complete"] is False


@pytest.mark.parametrize("change", [
    {"org_unit": 7}, {"org_unit": "bad id"}, {"org_unit": "a/b"}, {"group": ""}, {"unit_kind": "org_unit"},
    {"unit_kind": None}, {"section": None}, {"section": ""}, {"section": "not_a_section"}])
def test_a_policy_that_cannot_be_placed_is_left_out(bundle: Path, change) -> None:
    policies = rows(bundle, "google_policy_settings")
    policies[1].update(change)
    normalised(bundle, "google_policy_settings", policies)
    section = project_gws_run(bundle)["gws_policies"]
    assert section["complete"] is False
    assert [entry["section"] for entry in section["policies"]] == ["gmail_auto_forwarding"]


@pytest.mark.parametrize("value", [{"enableAutoForwarding": "broken"}, {"note": "x"}, [], "on"])
def test_a_value_outside_its_schema_passes_without_its_value(bundle: Path, value) -> None:
    policies = rows(bundle, "google_policy_settings")
    policies[0]["value"] = value
    normalised(bundle, "google_policy_settings", policies)
    section = project_gws_run(bundle)["gws_policies"]
    assert section["complete"] is True and "value" not in section["policies"][0]


def test_policy_without_value_or_rank_passes_on_for_the_reducer(bundle: Path) -> None:
    policies = rows(bundle, "google_policy_settings")
    del policies[0]["value"]
    policies[0]["sort_order"] = 10 ** 400
    normalised(bundle, "google_policy_settings", policies)
    section = project_gws_run(bundle)["gws_policies"]
    assert section["complete"] is True
    assert section["policies"][0] == {"unit": "ou:root01", "unit_kind": "org_unit", "section": "gmail_auto_forwarding",
                                      "sort_order": None}


@pytest.mark.parametrize("change", [{"id": None}, {"id": "a b"}, {"is_root": "yes"}, {"parent_id": None},
                                    {"parent_id": "x/y"}])
def test_a_unit_that_cannot_be_placed_makes_the_topology_incomplete(bundle: Path, change) -> None:
    units = rows(bundle, "google_org_units")
    units[0].update(change)
    normalised(bundle, "google_org_units", units)
    tenant = project_gws_run(bundle)["gws_tenant"]
    assert tenant["complete"] is False and tenant["top_unit"] == "ou:root01"
    assert "ou:ou0a1" not in tenant["org_units"]


def test_no_root_withholds_the_tenant(bundle: Path) -> None:
    normalised(bundle, "google_org_units", [{"kind": "google_org_unit", "id": "ou0a1", "parent_id": "root01",
                                             "is_root": False}, state("google_org_units", 1, root_id_known=False)])
    projection = project_gws_run(bundle)
    assert projection["gws_tenant"] == NOT_COLLECTED
    assert projection.report["sections"]["gws_tenant"]["detail"] == {"field": "top_unit", "kind": "missing_field"}


@pytest.mark.parametrize("manifest", [{"created_utc": None}, {"duration_seconds": -1}, {"duration_seconds": True},
                                      {"duration_seconds": 10 ** 400}, {"duration_seconds": 10 ** 12},
                                      {"created_utc": "2026-11-20T10:00:00"}, {"created_utc": "soon"}])
def test_unusable_collection_end_gives_no_as_of(bundle: Path, manifest) -> None:
    write(bundle, "run-manifest.json", {**load(bundle, "run-manifest.json"), **manifest})
    assert project_gws_run(bundle)["gws_tenant"]["as_of"] is None


@pytest.mark.parametrize("payload", [[], {"records": "x"}, {"records": [1]}, {"records": [], "error": "denied"},
                                     {"records": [], "collection_status": "failed"}])
def test_a_malformed_envelope_withholds_the_section(bundle: Path, payload) -> None:
    write(bundle, "normalized/google_sso_assignments.json", payload)
    projection = project_gws_run(bundle)
    assert projection["gws_sso"] == NOT_COLLECTED
    assert projection.report["sections"]["gws_sso"]["reason"] in {"incomplete_shape", "collector_error"}


@pytest.mark.parametrize("record", [
    {"target_org_unit": "orgUnits/ou0a1"}, {"target_org_unit": "orgUnits/ou0a1", "sso_mode": 3},
    {"target_org_unit": "orgUnits/ou0a1", "target_group": "groups/g1grp01", "sso_mode": "SSO_OFF"},
    {"sso_mode": "SSO_OFF"}, {"target_org_unit": "ou0a1", "sso_mode": "SSO_OFF"},
    {"target_group": "groups/", "sso_mode": "SSO_OFF"}, {"target_group": 5, "sso_mode": "SSO_OFF"},
    {"target_group": "groups/g7@example.com", "sso_mode": "SSO_OFF"}])
def test_an_sso_assignment_that_cannot_be_placed_is_left_out(bundle: Path, record) -> None:
    normalised(bundle, "google_sso_assignments", [{"kind": "google_sso_assignment", **record},
                                                  state("google_sso_assignments", 1)])
    assert project_gws_run(bundle)["gws_sso"] == {"complete": False, "assignments": []}


def test_sso_targets_by_group_address_and_unknown_modes(bundle: Path) -> None:
    normalised(bundle, "google_sso_assignments", [
        {"kind": "google_sso_assignment", "target_group": "groups/G1@example.com", "sso_mode": "SAML_SSO"},
        {"kind": "google_sso_assignment", "target_org_unit": "orgUnits/root01", "sso_mode": "ops@example.com"},
        state("google_sso_assignments", 2)])
    assert project_gws_run(bundle)["gws_sso"] == {"complete": True, "assignments": [
        {"target": G1, "sso_mode": "SAML_SSO"}, {"target": "ou:root01", "sso_mode": "unrecognised"}]}


@pytest.mark.parametrize("name", ["users"])
@pytest.mark.parametrize("cut", ["coverage", "gap", "raw", "count"])
def test_a_cut_user_read_is_incomplete(bundle: Path, name, cut) -> None:
    if cut == "coverage":
        write(bundle, "coverage.json", [{**r, "status": "partial"} if r["name"] == name else r
                                        for r in load(bundle, "coverage.json")])
    elif cut == "gap":
        normalised(bundle, "collection_gaps", [{"kind": "collection_gap", "collector": "google_directory", "list": name}])
    elif cut == "raw":
        raw_directory(bundle, lambda raw: raw[name].update(collection_truncated=True))
    else:
        raw_directory(bundle, lambda raw: raw[name]["value"].append({**raw[name]["value"][0], "id": "u900"}))
    assert project_gws_run(bundle)["gws_admins"]["complete"] is False


@pytest.mark.parametrize("name", ["roles", "roleAssignments"])
@pytest.mark.parametrize("cut", ["coverage", "gap", "raw"])
def test_a_cut_role_read_leaves_the_inventory_unresolved(bundle: Path, name, cut) -> None:
    if cut == "coverage":
        write(bundle, "coverage.json", [{**r, "status": "partial"} if r["name"] == name else r
                                        for r in load(bundle, "coverage.json")])
    elif cut == "gap":
        normalised(bundle, "collection_gaps", [{"kind": "collection_gap", "collector": "google_directory", "list": name}])
    else:
        raw_directory(bundle, lambda raw: raw[name].update(collection_truncated=True))
    admins = project_gws_run(bundle)["gws_admins"]
    assert admins["complete"] is True and admins["privileged"][-1] == UNRESOLVED


def test_coverage_file_named_but_missing_is_unknown(bundle: Path) -> None:
    (bundle / "coverage.json").unlink()
    admins = project_gws_run(bundle)["gws_admins"]
    assert admins["complete"] is False and admins["memberships_complete"] is False


@pytest.mark.parametrize("role", [{"roleId": "2", "isSuperAdminRole": "no"}, {"roleId": "2", "roleName": 4},
                                  {"roleId": "2", "rolePrivileges": [{"privilegeName": None}]},
                                  {"roleId": "2", "rolePrivileges": "USERS_ALL"}])
def test_an_assigned_role_that_cannot_be_read_leaves_the_inventory_unresolved(bundle: Path, role) -> None:
    raw_directory(bundle, lambda raw: raw["roles"]["value"].__setitem__(1, role))
    admins = project_gws_run(bundle)["gws_admins"]
    assert admins["complete"] is True and admins["privileged"][-1] == UNRESOLVED
    assert U300 not in [entry["user"] for entry in admins["privileged"]]


@pytest.mark.parametrize("change", ["member_error", "raw_member_error", "unknown_group"])
def test_partial_memberships_are_not_complete(bundle: Path, change) -> None:
    if change == "member_error":
        normalised(bundle, "google_group_member_errors", [{"kind": "google_group_member_error", "group_email": "g"}])
    elif change == "raw_member_error":
        raw_directory(bundle, lambda raw: raw["groupMembersErrors"]["value"].append({"groupEmail": "g1@example.com"}))
    else:
        raw_directory(bundle, lambda raw: raw["groupMembers"]["value"][0].update(groupEmail="g7@example.com"))
    admins = project_gws_run(bundle)["gws_admins"]
    assert admins["memberships_complete"] is False and admins["complete"] is True


@pytest.mark.parametrize("member_type", ["GROUP", "CUSTOMER", None])
def test_a_member_that_is_not_a_user_leaves_memberships_unresolved(bundle: Path, member_type) -> None:
    raw_directory(bundle, lambda raw: raw["groupMembers"]["value"][1].update(type=member_type))
    assert project_gws_run(bundle)["gws_admins"]["memberships_complete"] is False


def test_delegated_admin_flags_that_cannot_be_proven_leave_the_inventory_unresolved(bundle: Path) -> None:
    raw_directory(bundle, lambda raw: raw["users"]["value"][3].pop("isDelegatedAdmin"))
    admins = project_gws_run(bundle)["gws_admins"]
    assert admins["complete"] is True and admins["privileged"][-1] == UNRESOLVED


def test_a_privileged_role_held_by_a_group_leaves_the_inventory_unresolved(bundle: Path) -> None:
    assignments = rows(bundle, "google_role_assignments")
    assignments[3]["assigned_to"] = "g1grp01"
    normalised(bundle, "google_role_assignments", assignments)
    admins = project_gws_run(bundle)["gws_admins"]
    assert [entry["user"] for entry in admins["privileged"]] == [U100, U200, U300, "user:unresolved"]


@pytest.mark.parametrize("role,privileged", [({"roleId": 5}, None), ({"roleId": 5, "rolePrivileges": []}, False),
                                             ({"roleId": 5, "roleName": "Services Admin"}, True),
                                             ({"roleId": 5, "isSuperAdminRole": True}, True)])
def test_a_role_without_its_privilege_list_is_unknown(bundle: Path, role, privileged) -> None:
    raw_directory(bundle, lambda raw: raw["roles"]["value"].__setitem__(3, role))
    users = [entry["user"] for entry in project_gws_run(bundle)["gws_admins"]["privileged"]]
    assert ("user:unresolved" in users) is (privileged is None)
    assert (U500 in users) is bool(privileged)


def test_an_incomplete_unit_list_places_no_admin(bundle: Path) -> None:
    raw_directory(bundle, lambda raw: raw["orgUnits"].update(collection_truncated=True))
    projection = project_gws_run(bundle)
    assert [entry["org_unit"] for entry in projection["gws_admins"]["privileged"]] == [None, None, None, None]


def test_a_shared_path_is_unplaceable(bundle: Path) -> None:
    raw_directory(bundle, lambda raw: raw["orgUnits"]["value"].append(
        {"orgUnitId": "id:ou0a1", "orgUnitPath": "/Sales", "parentOrgUnitId": "id:root01", "parentOrgUnitPath": "/"}))
    assert [entry["org_unit"] for entry in project_gws_run(bundle)["gws_admins"]["privileged"]] == [
        "ou:root01", None, None, None]


def test_customer_id_shaped_unit_ids_are_not_placed(bundle: Path) -> None:
    raw_directory(bundle, lambda raw: raw["orgUnits"]["value"][1].update(orgUnitId="id:" + CUSTOMER))
    projection = project_gws_run(bundle)
    assert CUSTOMER not in json.dumps(dict(projection))
    assert projection["gws_admins"]["privileged"][1]["org_unit"] is None


def test_event_window_comes_only_from_the_read(bundle: Path) -> None:
    events = rows(bundle, "google_setting_events")
    events[-1] = state("google_setting_events", 5, window_start=7, window_end="2026-11-20")
    normalised(bundle, "google_setting_events", events)
    section = project_gws_run(bundle)["gws_setting_events"]
    assert (section["window_start"], section["window_end"]) == (None, None)


@pytest.mark.parametrize("value,expected", [(None, False), (False, False), (True, True), ("x", True), ({}, True),
                                            (0, True)])
def test_resolver_error_is_unknown_unless_absent_or_false(bundle: Path, value, expected) -> None:
    posture = rows(bundle, "google_dns_posture")
    posture[0]["resolver_error"] = value
    normalised(bundle, "google_dns_posture", posture)
    assert project_gws_run(bundle)["gws_dns"]["domains"][0]["resolver_error"] is expected


@pytest.mark.parametrize("change,field,expected", [
    ({"domain": "example.org", "alias": None}, "alias", None),
    ({"domain": "exa mple.com"}, "domain", ""),
    ({"spf": {"records": ["v=spf1", 3]}}, "spf", {"records": None}),
    ({"spf": {"records": ["v=spf1 include:_spf.google.com ~all", "ops@example.com"]}}, "spf",
     {"records": ["v=spf1 ?all", "unrecognised"]}),
    ({"dmarc": {"query_name": 1, "inherited": "no", "records": "v=DMARC1"}}, "dmarc",
     {"query_name": None, "inherited": None, "records": None}),
    ({"dmarc": {"query_name": "_dmarc.other.example", "inherited": True, "records": []}}, "dmarc",
     {"query_name": "unrecognised", "inherited": True, "records": []}),
])
def test_dns_fields_of_the_wrong_type_pass_as_null(bundle: Path, change, field, expected) -> None:
    posture = rows(bundle, "google_dns_posture")
    posture[0].update(change)
    normalised(bundle, "google_dns_posture", posture)
    assert project_gws_run(bundle)["gws_dns"]["domains"][0][field] == expected


def test_a_lone_surrogate_never_reaches_a_section(bundle: Path) -> None:
    for name, old in (("google_dns_posture", "include:_spf.google.com"), ("google_setting_events", "Gmail"),
                      ("google_sso_assignments", "SAML_SSO")):
        path = bundle / f"normalized/{name}.json"
        path.write_text(path.read_text().replace(old, "\\ud800"))
    projection = project_gws_run(bundle)
    json.dumps(dict(projection), ensure_ascii=False).encode()
    assert projection["gws_dns"]["domains"][0]["spf"] == {"records": ["v=spf1 ?all"]}
    assert projection["gws_setting_events"]["events"][0]["application"] == ""
    assert projection["gws_sso"]["assignments"][1]["sso_mode"] == "unrecognised"
