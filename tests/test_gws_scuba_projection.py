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
ROOT, SALES = "ou:b7fc69fe6d4526fb", "ou:cb36f2dcd7411d30"
D_COM, D_NET = "domain:0f1b91af965ab2e1.invalid", "domain:bf4ddaa84e70a66f.invalid"
UNRESOLVED = {"user": "user:unresolved", "org_unit": None, "groups": []}
CUSTOMER = "C0synth9x"
SETTING = "OutOfDomainWarningProto disable_untrusted_recipient_warning"  # GMAIL.13.1: good "false", bad "true"
DMARC = ("v=DMARC1; p=reject; pct=100; rua=mailto:reports@dmarc.cyber.dhs.gov,mailto:dmarc.ops@example.com!10m;"
         " ruf=mailto:forensic.ops@example.com")
DMARC_OUT = ("v=DMARC1; p=reject; rua=mailto:%72eports@%64marc.cyber.dhs.gov,mailto:contact@example.invalid;"
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
    details = {"malformed_count": 0, "unusable_sections": [], "unusable_scopes": []} \
        if section == "google_policy_settings" else {}
    return {"kind": f"{section}_read_state", "id": "read_state", "complete": complete, "record_count": count,
            **details, **extra}


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
        *({"collector": "google_directory", "name": name, "status": "ok", "item_count": count}
          for name, count in (("users", 5), ("groups", 2), ("orgUnits", 2), ("roles", 4), ("roleAssignments", 4),
                              ("groupMembers:g1@example.com", 1), ("groupMembers:g2@example.org", 2))),
        {"collector": "google_dns_posture", "name": "domains", "status": "ok", "item_count": 1},
        {"collector": "google_dns_posture", "name": "posture:example.com", "status": "ok", "item_count": 1},
        {"collector": "google_dns_posture", "name": "posture:example.net", "status": "failed", "item_count": 1,
         "error_class": "dns_resolver_error"},
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
        "roleAssignments": {"value": [{"roleId": "1", "assignedTo": "u100"}, {"roleId": "2", "assignedTo": "u300"},
                                      {"roleId": "4", "assignedTo": "u400"}, {"roleId": 5, "assignedTo": "u500"}]},
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
        {"kind": "google_group_member", "id": "g1@example.com:u100", "group_email": "g1@example.com", "email": "Ada.Admin@example.com", "type": "USER"},
        {"kind": "google_group_member", "id": "g2@example.org:u100", "group_email": "g2@example.org", "email": "ada.admin@example.com", "type": "USER"},
        {"kind": "google_group_member", "id": "g2@example.org:x999", "group_email": "g2@example.org", "email": "guest@example.net", "type": "USER"}])
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
    recorded_events(root, [
        event("2026-10-01T10:00:00.123456789Z", "CHANGE_APPLICATION_SETTING", setting=SETTING, new_value="false",
              org_unit="ou0a1", application="Gmail"),
        event("2026-10-02T10:00:00Z", "TOGGLE_CAA_ENABLEMENT", new_value="ENABLED"),
        event("2026-10-03T10:00:00Z", "DELETE_APPLICATION_SETTING", setting=SETTING, org_unit="root01"),
        event("2026-10-04T10:00:00Z", "CHANGE_APPLICATION_SETTING", setting=SETTING, new_value="true",
              group_email="G1@example.com"),
        event("2026-10-05T10:00:00Z", "CHANGE_GMAIL_SETTING", setting=SETTING, new_value="true",
              group_email="g9@example.com"),
        state("google_setting_events", 5, window_start="2026-05-25T00:00:00Z", window_end="2026-11-20T10:01:30Z")])
    sso(root, {"target_org_unit": "orgUnits/ou0a1", "sso_mode": "SSO_OFF"},
        {"target_group": "groups/g1grp01", "sso_mode": "SAML_SSO"})
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
    write(root, "raw/google_dns_posture.json", {
        "domains": {"value": [{"domainName": "example.com", "verified": True, "isPrimary": True,
                               "domainAliases": [{"domainAliasName": "example.net", "verified": True}]}]},
        "domainPosture": {"value": rows(root, "google_dns_posture")}})
    return root


EXPECTED = {
    "gws_tenant": {"as_of": AS_OF, "top_unit": ROOT,
                   "org_units": {SALES: ROOT, ROOT: None}, "complete": True},
    "gws_policies": {"complete": True, "policies": [
        {"unit": ROOT, "unit_kind": "org_unit", "section": "gmail_auto_forwarding", "sort_order": 1,
         "value": {"enableAutoForwarding": False}},
        {"unit": f"{ROOT}/{G1}", "unit_kind": "group", "section": "drive_and_docs_external_sharing",
         "sort_order": 2.5, "value": {"externalSharingMode": "DISALLOWED"}}]},
    "gws_setting_events": {"complete": True, "window_start": "2026-05-25T00:00:00Z",
                           "window_end": "2026-11-20T10:01:30Z", "events": [
        {"time": "2026-10-01T10:00:00.123456789Z", "event": "CHANGE_APPLICATION_SETTING", "setting": SETTING,
         "new_value": "false", "unit": SALES, "application": "Gmail"},
        {"time": "2026-10-02T10:00:00Z", "event": "TOGGLE_CAA_ENABLEMENT", "setting": None, "new_value": "ENABLED",
         "unit": None, "application": None},
        {"time": "2026-10-03T10:00:00Z", "event": "DELETE_APPLICATION_SETTING", "setting": SETTING,
         "new_value": None, "unit": ROOT, "application": None},
        {"time": "2026-10-04T10:00:00Z", "event": "CHANGE_APPLICATION_SETTING", "setting": SETTING,
         "new_value": "true", "unit": G1, "application": None},
        {"time": "2026-10-05T10:00:00Z", "event": "CHANGE_GMAIL_SETTING", "setting": SETTING,
         "new_value": "true", "unit": G9_EMAIL, "application": None}]},
    "gws_dns": {"complete": True, "domains": [
        {"domain": D_COM, "alias": False, "resolver_error": False,
         "spf": {"records": ["v=spf1 include:example.invalid -all"]},
         "dkim": {"selectors": {"google": ["v=DKIM1;"], "selector1": [], "selector2": []}},
         "dmarc": {"query_name": "_dmarc." + D_COM, "inherited": False, "records": [DMARC_OUT, "unrecognised"]}},
        {"domain": D_NET, "alias": True, "resolver_error": True, "spf": {"records": None},
         "dkim": {"selectors": {"google": None, "selector1": None, "selector2": None}},
         "dmarc": {"query_name": "_dmarc." + D_NET, "inherited": None, "records": None}}]},
    "gws_admins": {"complete": True, "super_admin_count": 2, "memberships_complete": True, "privileged": [
        {"user": U100, "org_unit": ROOT, "groups": sorted([G1, G2])},
        {"user": U200, "org_unit": SALES, "groups": []},
        {"user": U300, "org_unit": SALES, "groups": []},
        {"user": U500, "org_unit": None, "groups": []}]},
    "gws_sso": {"complete": True, "assignments": [{"target": SALES, "sso_mode": "SSO_OFF"},
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
        "raw/google_directory.json", "coverage.json", "normalized/google_org_units.json",
        "normalized/google_group_members.json", "normalized/google_groups.json"}
    assert projection.report["redaction"] == {"enabled": True, "strategy": "keyed-hmac-sha256-v1", "user_ids": 4,
                                              "group_ids": 3, "email_addresses": 2, "domain_names": 2}
    assert projection.report["schema_version"] == "2026-11-25.4"


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
                   "u100", "u500", "x999", "root01", "ou0a1", "Ops", "google-site-verification", "k=rsa", "pct=100", "example.com",
                   "example.net", "_dmarc.example", "reports@dmarc.cyber.dhs.gov"):
        assert needle not in text, needle
    assert projection["gws_setting_events"]["events"][0]["new_value"] == "unrecognised"
    assert projection["gws_setting_events"]["events"][0]["application"] == ""
    assert projection["gws_setting_events"]["events"][1] == {
        "time": "2026-10-01T11:00:00Z", "event": "", "setting": None, "new_value": None, "unit": None,
        "application": None}
    assert projection["gws_policies"]["policies"][0] == {
        "unit": ROOT, "unit_kind": "org_unit", "section": "gmail_auto_forwarding", "sort_order": 1}


def dns_only(bundle: Path, *records: dict, listed: list[str] | None = None) -> None:
    """The posture records, a raw read listing and proving each of them (or the ``listed`` names) and their coverage."""
    normalised(bundle, "google_dns_posture", list(records))
    data = [row for row in records if row.get("kind") == "google_domain_posture"]
    names = [row["domain"] for row in data if isinstance(row.get("domain"), str)]
    scope = names if listed is None else listed
    domains = [{"domainName": name, "verified": True} for name in scope if name != "example.net"]
    if "example.net" in scope:
        domains[0]["domainAliases"] = [{"domainAliasName": "example.net", "verified": True}]
    write(bundle, "raw/google_dns_posture.json", {"domains": {"value": domains}, "domainPosture": {"value": data}})
    normalised(bundle, "google_domains", [
        {"kind": "google_domain", "domain_name": name,
         "domain_kind": "alias" if name == "example.net" else "primary"} for name in scope])
    edit_coverage(bundle, "domains", item_count=len(domains))
    coverage = [row for row in load(bundle, "coverage.json") if not row["name"].startswith("posture:")]
    write(bundle, "coverage.json", [*coverage, *({"collector": "google_dns_posture", "name": f"posture:{name}",
                                                  "status": "ok", "item_count": 1} for name in names)])


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
    run = tmp_path / "out" / "E-g"
    (run / "operator-inputs/pseudonym.key").unlink()
    seed_key(run)
    return run


ENROLLED = _policy("security.two_step_verification_enrollment", {"allowEnrollment": True})


def test_an_offline_replay_keeps_the_evaluation_time_for_2sv(tmp_path: Path) -> None:
    # Enforcement begins in 2025, after the replay's evaluation time in 2024.
    run_dir = replay(tmp_path, [ENROLLED, _policy("security.two_step_verification_enforcement",
                                                  {"enforcedFrom": "2025-01-01T00:00:00Z"})],
                     as_of=datetime(2024, 1, 1, tzinfo=UTC))
    projection = project_gws_run(run_dir)
    assert load(run_dir, "run-manifest.json")["as_of"] == "2024-01-01T00:00:00Z"
    assert projection["gws_tenant"]["as_of"] == "2024-01-01T00:00:00Z"
    assert verdict(projection, "GWS.COMMONCONTROLS.1.2v1") == ("not_met", "unit_violates")


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
        (ROOT, "org_unit", "security_two_step_verification_enrollment"),
        (ROOT, "org_unit", "security_two_step_verification_enforcement"),
        (f"{ROOT}/group:G", "group", "security_two_step_verification_enrollment")]
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
    members = rows(bundle, "google_group_members")
    normalised(bundle, "google_group_members", [*members, {**members[0], "id": "g1@example.com:u200", "email": "bo.old.address@example.com"}])
    write(bundle, "coverage.json", [{**row, "item_count": 2} if row["name"] == "groupMembers:g1@example.com" else row
                                    for row in load(bundle, "coverage.json")])
    projection = project_gws_run(bundle)
    assert projection["gws_admins"]["privileged"][1] == {"user": U200, "org_unit": SALES, "groups": [G1]}
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
    recorded_events(bundle, [
        event("2026-10-02T10:00:00Z", "TOGGLE_CAA_ENABLEMENT", new_value="ENABLED", **fields),
        state("google_setting_events", 1, window_start="2026-05-25T00:00:00Z", window_end="2026-11-20T10:01:30Z")])


def test_a_present_but_malformed_application_is_ambiguous(bundle: Path) -> None:
    caa(bundle)
    assert verdict(project_gws_run(bundle), "GWS.COMMONCONTROLS.2.1v1") == ("met", "no_unit_violates")
    caa(bundle, application=False)
    projection = project_gws_run(bundle)
    assert projection["gws_setting_events"]["events"][0]["application"] == ""
    assert verdict(projection, "GWS.COMMONCONTROLS.2.1v1") == ("not_assessed", "data_unavailable_event_read_incomplete")


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
    assert verdict(projection, "GWS.GMAIL.13.1v1") == ("not_assessed", "data_unavailable_event_read_incomplete")


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
    assert section["complete"] is False and section["events"][0][field] == expected


# --- B8: DNS scope and read health --------------------------------------------------------------------------------


def test_a_malformed_alias_flag_leaves_the_domain_unusable(bundle: Path) -> None:
    dns_only(bundle, good_domain(), good_domain("example.net", alias="no", spf={"records": []}))
    projection = project_gws_run(bundle)
    assert projection["gws_dns"]["domains"][1]["alias"] is None
    assert verdict(projection, "GWS.GMAIL.3.1v1") == ("not_assessed", "data_unavailable_dns_read_incomplete")


def test_an_alias_flag_contradicting_the_directory_is_unusable(bundle: Path) -> None:
    dns_only(bundle, good_domain(), good_domain("example.net", alias=False))
    assert project_gws_run(bundle)["gws_dns"]["domains"][1]["alias"] is None


@pytest.mark.parametrize("read_state", [False, True])
def test_a_partial_posture_read_is_incomplete(bundle: Path, read_state) -> None:
    domains = [good_domain(), good_domain("example.net", alias=True)]
    dns_only(bundle, *domains, *([state("google_dns_posture", 2)] if read_state else []))
    raw = load(bundle, "raw/google_dns_posture.json")
    raw["domainPosture"].update(partial=True, error_class="denied")
    write(bundle, "raw/google_dns_posture.json", raw)
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
    edit_coverage(bundle, "policySettings", item_count=3, status="partial", error_class="malformed_response",
                  policy_row_validation=True)


def test_an_attributed_policy_failure_leaves_other_settings_answerable(bundle: Path) -> None:
    attributed(bundle)
    projection = project_gws_run(bundle)
    assert projection["gws_policies"]["complete"] is True
    assert projection["gws_policies"]["policies"][-1] == {
        "unit": ROOT, "unit_kind": "org_unit", "section": "gmail_auto_forwarding", "sort_order": None}
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
    assert admins["privileged"] == [{"user": U100, "org_unit": ROOT, "groups": sorted([G1, G2])},
                                    {"user": U200, "org_unit": SALES, "groups": []}, UNRESOLVED]
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
    assert [entry["org_unit"] for entry in projection["gws_admins"]["privileged"]] == [ROOT, SALES]
    assert verdict(projection, "GWS.COMMONCONTROLS.6.1v1") == ("not_met", "admin_uses_external_sso")


# --- M3: every row a section uses counts against the bound ----------------------------------------------------------


def test_raw_and_supporting_rows_count_against_the_bound(bundle: Path) -> None:
    normalised(bundle, "google_setting_events", [
        event("2026-10-01T10:00:00Z", "CHANGE_APPLICATION_SETTING", setting=SETTING, new_value="false",
              org_unit="ou0a1"),
        state("google_setting_events", 1, window_start="2026-05-25T00:00:00Z", window_end="2026-11-20T10:01:30Z")])
    report = project_gws_run(bundle, scan_max_rows=2).report["sections"]["gws_setting_events"]
    assert (report["reason"], report["detail"]) == ("oversize", {"field": "scan_max_rows", "kind": "scan_bound"})
    # 17 normalised, 20 raw Directory, and 13 coverage rows, counted once per section.
    assert project_gws_run(bundle, scan_max_rows=50).report["sections"]["gws_admins"]["reason"] is None
    assert project_gws_run(bundle, scan_max_rows=49).report["sections"]["gws_admins"]["reason"] == "oversize"


# --- M4: the tenant topology ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(("parent", "projected"), [("zz999", "ou:a0e459b4313cf158"), ("ou0a1", SALES)])
def test_a_dangling_or_looping_unit_is_not_a_complete_topology(bundle: Path, parent, projected) -> None:
    units = rows(bundle, "google_org_units")
    units[0]["parent_id"] = parent
    normalised(bundle, "google_org_units", units)
    tenant = project_gws_run(bundle)["gws_tenant"]
    assert tenant["complete"] is False and tenant["org_units"][SALES] == projected


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
    assert section["complete"] is False and "value" not in section["policies"][0]


def test_policy_without_value_or_rank_passes_on_for_the_reducer(bundle: Path) -> None:
    policies = rows(bundle, "google_policy_settings")
    del policies[0]["value"]
    policies[0]["sort_order"] = 10 ** 400
    normalised(bundle, "google_policy_settings", policies)
    section = project_gws_run(bundle)["gws_policies"]
    assert section["complete"] is False
    assert section["policies"][0] == {"unit": ROOT, "unit_kind": "org_unit", "section": "gmail_auto_forwarding",
                                      "sort_order": None}


@pytest.mark.parametrize("change", [{"id": None}, {"id": "a b"}, {"is_root": "yes"}, {"parent_id": None},
                                    {"parent_id": "x/y"}])
def test_a_unit_that_cannot_be_placed_makes_the_topology_incomplete(bundle: Path, change) -> None:
    units = rows(bundle, "google_org_units")
    units[0].update(change)
    normalised(bundle, "google_org_units", units)
    tenant = project_gws_run(bundle)["gws_tenant"]
    assert tenant["complete"] is False and tenant["top_unit"] == ROOT
    assert SALES not in tenant["org_units"]


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
    assert project_gws_run(bundle)["gws_sso"] == {"complete": False, "assignments": [
        {"target": G1, "sso_mode": "SAML_SSO"}, {"target": ROOT, "sso_mode": "unrecognised"}]}


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
    raw_directory(bundle, lambda raw: raw["roleAssignments"]["value"][3].update(assignedTo="g1grp01"))
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
        None, None, None, None]


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
    ({"domain": "example.org"}, "domain", "domain:1631ad6c226401f3.invalid"),
    ({"domain": "exa mple.com"}, "domain", ""),
    ({"spf": {"records": ["v=spf1", 3]}}, "spf", {"records": None}),
    ({"spf": {"records": ["v=spf1 include:_spf.google.com ~all", "ops@example.com"]}}, "spf",
     {"records": ["v=spf1 include:example.invalid ~all", "unrecognised"]}),
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
    assert projection["gws_dns"]["domains"][0]["spf"] == {"records": ["v=spf1 invalid"]}
    assert projection["gws_setting_events"]["events"][0]["application"] == ""
    assert projection["gws_sso"]["assignments"][1]["sso_mode"] == "unrecognised"


# --- Review round 2 (M13-L06 repair) ---------------------------------------------------------------------------------

CHAT_REPORTS = "ContentReportingProto report_types"  # CHAT.5.2: a top-level delete violates
WINDOW = {"window_start": "2026-05-25T00:00:00Z", "window_end": "2026-11-20T10:01:30Z"}


def edit_rows(bundle: Path, name: str, change, **envelope) -> None:
    data = rows(bundle, name)
    change(data)
    normalised(bundle, name, data, **envelope)


def edit_manifest(bundle: Path, **fields) -> None:
    data = load(bundle, "run-manifest.json")
    for key, value in fields.items():
        if value == "MISSING":
            data.pop(key, None)
        else:
            data[key] = value
    write(bundle, "run-manifest.json", data)


def edit_coverage(bundle: Path, name: str, **fields) -> None:
    """Change one coverage row; ``DROP=True`` removes it, a ``MISSING`` value removes that field."""
    out = []
    for row in load(bundle, "coverage.json"):
        if row["name"] == name:
            if fields.get("DROP"):
                continue
            row = {**row, **{k: v for k, v in fields.items() if v != "MISSING"}}
            for key in [k for k, v in fields.items() if v == "MISSING"]:
                row.pop(key, None)
        out.append(row)
    write(bundle, "coverage.json", out)


def edit_raw(bundle: Path, path: str, change) -> None:
    raw = load(bundle, path)
    change(raw)
    write(bundle, path, raw)


def two_step(bundle: Path, enforced: str = "2020-01-01T00:00:00Z") -> None:
    write(bundle, "raw/google_policies.json", {"policySettings": {"value": [
        ENROLLED, _policy("security.two_step_verification_enforcement", {"enforcedFrom": enforced})]}})
    normalised(bundle, "google_policy_settings", [
        TWO_STEP[0], {**TWO_STEP[1], "value": {"enforcedFrom": enforced}}, state("google_policy_settings", 2)])


def placed(bundle: Path, path: str = "/") -> None:
    """Every privileged account in a known OU: u500 moves from the unknown ``/Unknown`` to ``path``."""
    raw_directory(bundle, lambda raw: raw["users"]["value"][4].update(orgUnitPath=path))
    edit_rows(bundle, "google_users", lambda data: data[4].update(org_unit_path=path))


def coverage_row(bundle: Path, collector: str, name: str, count: int) -> None:
    rows = [row for row in load(bundle, "coverage.json") if (row["collector"], row["name"]) != (collector, name)]
    write(bundle, "coverage.json", [*rows, {"collector": collector, "name": name, "status": "ok", "item_count": count}])


def recorded_events(bundle: Path, records: list[dict]) -> None:
    collector = "google_setting_events"
    activities = []
    for row in records[:-1]:
        params = []
        for field, key in (("setting", "SETTING_NAME"), ("new_value", "NEW_VALUE"), ("org_unit", "ORG_UNIT_NAME"),
                           ("group_email", "GROUP_EMAIL"), ("application", "APPLICATION_NAME")):
            if row.get(field) is not None:
                value = row[field]
                if field == "org_unit" and isinstance(value, str):
                    value = {"root01": "/", "ou0a1": "/Sales"}.get(value, value)
                params.append({"name": key, "value": value})
        activities.append({"event_time": row["event_time"],
                           "events": [{"name": row["event"], "event_parameters": params}]})
    normalised(bundle, collector, records)
    write(bundle, f"raw/{collector}.json", {"settingEvents": {
        "value": activities, "window_start": records[-1]["window_start"], "window_end": records[-1]["window_end"]}})
    coverage_row(bundle, collector, "settingEvents", len(activities))


def sso(bundle: Path, *assignments: dict) -> None:
    collector = "google_sso_assignments"
    normalised(bundle, collector, [*({"kind": "google_sso_assignment", **row} for row in assignments),
                                   state(collector, len(assignments))])
    keys = {"target_org_unit": "targetOrgUnit", "target_group": "targetGroup", "sso_mode": "ssoMode"}
    write(bundle, f"raw/{collector}.json", {"inboundSsoAssignments": {
        "value": [{keys[key]: value for key, value in row.items()} for row in assignments]}})
    coverage_row(bundle, collector, "inboundSsoAssignments", len(assignments))


def third_ou(bundle: Path) -> None:
    """u500 (role 5, USERS_ALL) in a third OU whose SAML assignment is the only external one."""
    raw_directory(bundle, lambda raw: raw["orgUnits"]["value"].append(
        {"orgUnitId": "id:ou0b2", "orgUnitPath": "/Ops", "name": "Ops", "parentOrgUnitId": "id:root01",
         "parentOrgUnitPath": "/"}))
    normalised(bundle, "google_org_units", [
        {"kind": "google_org_unit", "id": "ou0a1", "parent_id": "root01", "is_root": False},
        {"kind": "google_org_unit", "id": "ou0b2", "parent_id": "root01", "is_root": False},
        {"kind": "google_org_unit", "id": "root01", "parent_id": None, "is_root": True},
        state("google_org_units", 3, root_id_known=True, malformed_count=0)])
    edit_coverage(bundle, "orgUnits", item_count=3)
    placed(bundle, "/Ops")
    sso(bundle, {"target_org_unit": "orgUnits/ou0b2", "sso_mode": "SAML_SSO"})


def chat_delete(bundle: Path, **fields) -> None:
    recorded_events(bundle, [
        event("2026-10-03T10:00:00Z", "DELETE_APPLICATION_SETTING",
              **{"setting": CHAT_REPORTS, "org_unit": "root01", **fields}),
        state("google_setting_events", 1, **WINDOW)])


# B1: a DNS label never carries the customer id, whatever its shape.

def test_dns_labels_are_pseudonyms_and_keep_only_their_relation(bundle: Path) -> None:
    own, child = "C0synth9x.example.org", "mail.C0synth9x.example.org"
    dns_only(bundle, good_domain(own), good_domain(child, dmarc={
        "query_name": f"_dmarc.{own}", "inherited": True, "records": [DMARC]}))
    projection = project_gws_run(bundle)
    text = json.dumps([dict(projection), projection.report]).lower()
    assert CUSTOMER.lower() not in text and "example.org" not in text
    domains = projection["gws_dns"]["domains"]
    assert [(entry["domain"], entry["dmarc"]["query_name"]) for entry in domains] == [
        ("domain:ed29e53bc9f78521.invalid", "_dmarc.domain:ed29e53bc9f78521.invalid"),
        ("domain:6d34e6674c106194.invalid", "_dmarc.invalid")]
    assert verdict(projection, "GWS.GMAIL.4.1v1") == ("met", "no_domain_violates")
    assert verdict(projection, "GWS.GMAIL.4.2v1") == ("met", "no_domain_violates")


# B2: the collection end is a strictly parsed instant.

@pytest.mark.parametrize("created", ["2026-11-20X10:00:00Z", "2026-11-20 10:00:00Z", "2026-11-20T10:00:00",
                                     "2026-11-20T24:00:00Z", "20261120T100000Z"])
def test_a_malformed_creation_time_confirms_no_2sv_answer(bundle: Path, created) -> None:
    two_step(bundle)
    assert verdict(project_gws_run(bundle), "GWS.COMMONCONTROLS.1.2v1") == ("met", "no_unit_violates")
    edit_manifest(bundle, created_utc=created)
    projection = project_gws_run(bundle)
    assert projection["gws_tenant"]["as_of"] is None
    assert verdict(projection, "GWS.COMMONCONTROLS.1.2v1")[0] == "not_assessed"


# B3: an envelope claim or a blank identity never proves the super admin count.

@pytest.mark.parametrize("envelope", [{"complete": False}, {"status": "partial"}, {"collection_truncated": "true"},
                                      {"item_count": 6}])
def test_an_incomplete_user_envelope_proves_no_count(bundle: Path, envelope) -> None:
    edit_rows(bundle, "google_users", lambda data: None, **envelope)
    projection = project_gws_run(bundle)
    assert projection["gws_admins"]["complete"] is False
    assert verdict(projection, "GWS.COMMONCONTROLS.6.2v1") == ("not_assessed", "data_unavailable_user_read_incomplete")


def test_a_blank_admin_id_proves_no_count(bundle: Path) -> None:
    raw_directory(bundle, lambda raw: raw["users"]["value"][1].update(id=" "))
    edit_rows(bundle, "google_users", lambda data: data[1].update(id=" "))
    projection = project_gws_run(bundle)
    assert projection["gws_admins"]["complete"] is False
    assert verdict(projection, "GWS.COMMONCONTROLS.6.2v1") == ("not_assessed", "data_unavailable_user_read_incomplete")


# B4: memberships and role joins must reconcile, not merely be present.

@pytest.mark.parametrize("change", ["kept_rows_short_of_coverage", "normalised_members_cut"])
def test_a_dropped_membership_never_confirms_google_sign_in(bundle: Path, change) -> None:
    placed(bundle)
    assert verdict(project_gws_run(bundle), "GWS.COMMONCONTROLS.6.1v1") == ("not_met", "admin_uses_external_sso")
    raw_directory(bundle, lambda raw: raw["groupMembers"]["value"].pop(0))  # u100's only g1 (SAML) membership
    if change == "kept_rows_short_of_coverage":
        edit_rows(bundle, "google_group_members", lambda data: data.pop(0))  # coverage still says one member
    else:
        edit_coverage(bundle, "groupMembers:g1@example.com", item_count=0)
        edit_rows(bundle, "google_group_members", lambda data: data.pop(0), collection_truncated=True)
    projection = project_gws_run(bundle)
    assert projection["gws_admins"]["memberships_complete"] is False
    assert verdict(projection, "GWS.COMMONCONTROLS.6.1v1") == ("not_assessed", "data_unavailable_membership_incomplete")


def test_role_assignments_are_joined_by_identity_not_length(bundle: Path) -> None:
    third_ou(bundle)
    assert verdict(project_gws_run(bundle), "GWS.COMMONCONTROLS.6.1v1") == ("not_met", "admin_uses_external_sso")
    edit_rows(bundle, "google_role_assignments", lambda data: data.__setitem__(3, dict(data[2])))
    projection = project_gws_run(bundle)
    assert projection["gws_admins"]["privileged"][-1] == UNRESOLVED
    assert verdict(projection, "GWS.COMMONCONTROLS.6.1v1")[0] == "not_assessed"


# B5: a delete that carries a value is malformed, never a delete the kind can rank.

def test_a_delete_with_a_value_is_ambiguous(bundle: Path) -> None:
    chat_delete(bundle)
    assert verdict(project_gws_run(bundle), "GWS.CHAT.5.2v1") == ("not_met", "unit_violates")
    chat_delete(bundle, new_value={"invalid": True})
    projection = project_gws_run(bundle)
    assert projection["gws_setting_events"]["events"][0]["unit"] is None
    assert verdict(projection, "GWS.CHAT.5.2v1") == ("not_assessed", "data_unavailable_event_read_incomplete")


# B6: each domain's own read, and the domain list's coverage, must be proven.

def test_a_posture_read_that_misses_a_listed_domain_confirms_no_pass(bundle: Path) -> None:
    dns_only(bundle, good_domain())
    assert verdict(project_gws_run(bundle), "GWS.GMAIL.3.1v1") == ("met", "no_domain_violates")
    dns_only(bundle, good_domain(), listed=["example.com", "example.org"])
    projection = project_gws_run(bundle)
    assert projection["gws_dns"]["complete"] is False
    assert verdict(projection, "GWS.GMAIL.3.1v1") == ("not_assessed", "data_unavailable_dns_read_incomplete")


@pytest.mark.parametrize("change", ["raw_posture_partial", "coverage_failed", "coverage_missing"])
def test_an_unproven_domain_read_confirms_no_failure(bundle: Path, change) -> None:
    dns_only(bundle, good_domain(spf={"records": []}))
    assert verdict(project_gws_run(bundle), "GWS.GMAIL.3.1v1") == ("not_met", "domain_violates")
    if change == "raw_posture_partial":
        edit_raw(bundle, "raw/google_dns_posture.json",
                 lambda raw: raw["domainPosture"].update(partial=True, error_class="denied"))
    elif change == "coverage_failed":
        edit_coverage(bundle, "posture:example.com", status="failed", error_class="dns_resolver_error")
    else:
        edit_coverage(bundle, "posture:example.com", DROP=True)
    projection = project_gws_run(bundle)
    assert projection["gws_dns"]["domains"][0]["resolver_error"] is True
    assert verdict(projection, "GWS.GMAIL.3.1v1")[0] == "not_assessed"


# B7: an attribution the raw read contradicts proves nothing.

def test_an_attribution_contradicted_by_the_raw_row_leaves_the_read_incomplete(bundle: Path) -> None:
    attributed(bundle)
    edit_raw(bundle, "raw/google_policies.json", lambda raw: raw["policySettings"]["value"][2].update(
        setting={"type": "settings/security.two_step_verification_enrollment", "value": {"allowEnrollment": None}}))
    projection = project_gws_run(bundle)
    assert projection["gws_policies"]["complete"] is False
    assert verdict(projection, "GWS.COMMONCONTROLS.1.2v1") == ("not_assessed", "data_unavailable_policy_read_incomplete")


# M1: the explicit empty SSO mode is the engine's Google-only value.

def test_the_empty_sso_mode_passes_through(bundle: Path) -> None:
    placed(bundle)
    sso(bundle, {"target_org_unit": "orgUnits/root01", "sso_mode": ""})
    projection = project_gws_run(bundle)
    assert projection["gws_sso"] == {"complete": True, "assignments": [{"target": ROOT, "sso_mode": ""}]}
    assert verdict(projection, "GWS.COMMONCONTROLS.6.1v1") == ("met", "admins_use_google_sign_in")


# Every input the projection reads, through absent, null, wrong-typed, blank, malformed, partial and contradictory
# values: none may confirm met or not_met. Each row names its base (whose verdict is checked first, so the row is not
# vacuous), the policy, the base verdict and the change.

def _member(index: int, **fields):
    return lambda b: raw_directory(b, lambda raw: raw["groupMembers"]["value"][index].update(**fields))


def _raw_user(**fields):
    return lambda b: raw_directory(b, lambda raw: raw["users"]["value"][1].update(**fields))


def _raw_user_drop(field: str):
    return lambda b: raw_directory(b, lambda raw: raw["users"]["value"][1].pop(field))


def _norm_assignment(**fields):
    return lambda b: edit_rows(b, "google_role_assignments", lambda data: data[3].update(**fields))


def _raw_assignment(**fields):
    return lambda b: raw_directory(b, lambda raw: raw["roleAssignments"]["value"][3].update(**fields))


def _attribution(**fields):
    return lambda b: edit_rows(b, "google_policy_settings", lambda data: data[-1].update(**fields))


def _scope(**fields):
    return lambda b: edit_rows(b, "google_policy_settings",
                               lambda data: data[-1]["unusable_scopes"][0].update(**fields))


def _raw_domains(rows_):
    return lambda b: edit_raw(b, "raw/google_dns_posture.json", lambda raw: raw["domains"].update(value=rows_))


def _raw_posture(**fields):
    return lambda b: edit_raw(b, "raw/google_dns_posture.json",
                              lambda raw: raw["domainPosture"]["value"][0].update(**fields))


def _sso_row(**fields):
    return lambda b: sso(b, {"target_org_unit": "orgUnits/root01", **fields})


BASES = {
    "2sv": (two_step, "GWS.COMMONCONTROLS.1.2v1", "met"),
    "count": (lambda b: None, "GWS.COMMONCONTROLS.6.2v1", "met"),
    "groups": (placed, "GWS.COMMONCONTROLS.6.1v1", "not_met"),
    "roles": (third_ou, "GWS.COMMONCONTROLS.6.1v1", "not_met"),
    "delete": (chat_delete, "GWS.CHAT.5.2v1", "not_met"),
    "dns_pass": (lambda b: dns_only(b, good_domain()), "GWS.GMAIL.3.1v1", "met"),
    "dns_fail": (lambda b: dns_only(b, good_domain(spf={"records": []})), "GWS.GMAIL.3.1v1", "not_met"),
    "attributed": (attributed, "GWS.COMMONCONTROLS.1.2v1", "met"),
    "sso": (lambda b: (placed(b), sso(b, {"target_org_unit": "orgUnits/root01", "sso_mode": "SSO_OFF"})),
            "GWS.COMMONCONTROLS.6.1v1", "met"),
}

UNKNOWN_INPUTS = {
    # manifest times
    "created absent": ("2sv", lambda b: edit_manifest(b, created_utc="MISSING")),
    "created null": ("2sv", lambda b: edit_manifest(b, created_utc=None)),
    "created number": ("2sv", lambda b: edit_manifest(b, created_utc=1763632800)),
    "created blank": ("2sv", lambda b: edit_manifest(b, created_utc=" ")),
    "created malformed": ("2sv", lambda b: edit_manifest(b, created_utc="2026-11-20X10:00:00Z")),
    "created zoneless": ("2sv", lambda b: edit_manifest(b, created_utc="2026-11-20T10:00:00")),
    "duration absent": ("2sv", lambda b: edit_manifest(b, duration_seconds="MISSING")),
    "duration null": ("2sv", lambda b: edit_manifest(b, duration_seconds=None)),
    "duration text": ("2sv", lambda b: edit_manifest(b, duration_seconds="90.5")),
    "duration negative": ("2sv", lambda b: edit_manifest(b, duration_seconds=-1)),
    # user envelopes and ids
    "users envelope complete false": ("count", lambda b: edit_rows(b, "google_users", lambda d: None, complete=False)),
    "users envelope complete null": ("count", lambda b: edit_rows(b, "google_users", lambda d: None, complete=None)),
    "users envelope status": ("count", lambda b: edit_rows(b, "google_users", lambda d: None, status="partial")),
    "users envelope cut text": ("count", lambda b: edit_rows(b, "google_users", lambda d: None,
                                                             collection_truncated="true")),
    "users envelope cut number": ("count", lambda b: edit_rows(b, "google_users", lambda d: None,
                                                               collection_truncated=1)),
    "users envelope count": ("count", lambda b: edit_rows(b, "google_users", lambda d: None, item_count=6)),
    "users envelope other kind": ("count", lambda b: edit_rows(b, "google_users", lambda d: None,
                                                               kind="google_groups")),
    "raw users status": ("count", lambda b: raw_directory(b, lambda raw: raw["users"].update(status="partial"))),
    "raw users cut text": ("count", lambda b: raw_directory(
        b, lambda raw: raw["users"].update(collection_truncated="true"))),
    "raw user id absent": ("count", _raw_user_drop("id")),
    "raw user id null": ("count", _raw_user(id=None)),
    "raw user id number": ("count", _raw_user(id=200)),
    "raw user id blank": ("count", _raw_user(id=" ")),
    "raw user id padded": ("count", _raw_user(id="u200 ")),
    "user ids contradict": ("count", lambda b: edit_rows(b, "google_users", lambda d: d[1].update(id="u999"))),
    # memberships
    "members envelope cut": ("groups", lambda b: edit_rows(b, "google_group_members", lambda d: None,
                                                          collection_truncated=True)),
    "members envelope status": ("groups", lambda b: edit_rows(b, "google_group_members", lambda d: None,
                                                             status="partial")),
    "members normalised short": ("groups", lambda b: edit_rows(b, "google_group_members", lambda d: d.pop())),
    "members normalised absent": ("groups", lambda b: (b / "normalized/google_group_members.json").unlink()),
    "member coverage count absent": ("groups", lambda b: edit_coverage(b, "groupMembers:g1@example.com",
                                                                      item_count="MISSING")),
    "member coverage count null": ("groups", lambda b: edit_coverage(b, "groupMembers:g1@example.com",
                                                                    item_count=None)),
    "member coverage count text": ("groups", lambda b: edit_coverage(b, "groupMembers:g1@example.com",
                                                                    item_count="1")),
    "member coverage count contradicts": ("groups", lambda b: edit_coverage(b, "groupMembers:g1@example.com",
                                                                           item_count=2)),
    "member coverage partial": ("groups", lambda b: edit_coverage(b, "groupMembers:g1@example.com",
                                                                 status="partial")),
    "member coverage absent": ("groups", lambda b: edit_coverage(b, "groupMembers:g1@example.com", DROP=True)),
    "member id null": ("groups", _member(2, id=None)),
    "member id blank": ("groups", _member(2, id=" ")),
    "member id number": ("groups", _member(2, id=999)),
    "member type absent": ("groups", lambda b: raw_directory(b, lambda raw: raw["groupMembers"]["value"][2].pop(
        "type"))),
    "member group blank": ("groups", _member(2, groupEmail="")),
    "raw members partial": ("groups", lambda b: raw_directory(b, lambda raw: raw["groupMembers"].update(
        status="partial"))),
    # role joins
    "assignment duplicated": ("roles", lambda b: edit_rows(b, "google_role_assignments",
                                                          lambda d: d.__setitem__(3, dict(d[2])))),
    "assignee blank": ("roles", _norm_assignment(assigned_to=" ")),
    "assignee null": ("roles", _norm_assignment(assigned_to=None)),
    "assignee contradicts": ("roles", _norm_assignment(assigned_to="u400")),
    "role id boolean": ("roles", _norm_assignment(role_id=True)),
    "role id null": ("roles", _norm_assignment(role_id=None)),
    "raw assignee absent": ("roles", lambda b: raw_directory(b, lambda raw: raw["roleAssignments"]["value"][3].pop(
        "assignedTo"))),
    "raw role id blank": ("roles", _raw_assignment(roleId=" ")),
    "assignments envelope cut": ("roles", lambda b: edit_rows(b, "google_role_assignments", lambda d: None,
                                                             partial=True)),
    "assignments absent": ("roles", lambda b: (b / "normalized/google_role_assignments.json").unlink()),
    # setting deletes
    "delete value object": ("delete", lambda b: chat_delete(b, new_value={"invalid": True})),
    "delete value text": ("delete", lambda b: chat_delete(b, new_value="system_violation: SPAM")),
    "delete value blank": ("delete", lambda b: chat_delete(b, new_value="")),
    "delete value false": ("delete", lambda b: chat_delete(b, new_value=False)),
    "delete value list": ("delete", lambda b: chat_delete(b, new_value=[])),
    "delete time malformed": ("delete", lambda b: chat_delete(b, event_time="2026-10-03X10:00:00Z")),
    "delete unit blank": ("delete", lambda b: chat_delete(b, org_unit=" ")),
    # DNS coverage
    "posture coverage absent": ("dns_fail", lambda b: edit_coverage(b, "posture:example.com", DROP=True)),
    "posture coverage failed": ("dns_fail", lambda b: edit_coverage(b, "posture:example.com", status="failed")),
    "posture coverage status null": ("dns_fail", lambda b: edit_coverage(b, "posture:example.com", status=None)),
    "posture coverage cut": ("dns_fail", lambda b: edit_coverage(b, "posture:example.com",
                                                                collection_truncated="true")),
    "raw posture resolver failure": ("dns_fail", _raw_posture(resolver_error="timeout")),
    "raw posture record absent": ("dns_fail", lambda b: edit_raw(
        b, "raw/google_dns_posture.json", lambda raw: raw["domainPosture"].update(value=[]))),
    "raw posture record twice": ("dns_fail", lambda b: edit_raw(
        b, "raw/google_dns_posture.json", lambda raw: raw["domainPosture"]["value"].append(
            {"domain": "example.com", "resolver_error": False}))),
    "raw posture partial": ("dns_fail", lambda b: edit_raw(
        b, "raw/google_dns_posture.json", lambda raw: raw["domainPosture"].update(status="partial"))),
    "listed domains extra": ("dns_pass", _raw_domains([{"domainName": "example.com"}, {"domainName": "example.org"}])),
    "listed alias extra": ("dns_pass", _raw_domains([{"domainName": "example.com", "domainAliases": [
        {"domainAliasName": "example.net", "verified": True}]}])),
    "listed name null": ("dns_pass", _raw_domains([{"domainName": None}])),
    "listed name blank": ("dns_pass", _raw_domains([{"domainName": " "}])),
    "listed verified text": ("dns_pass", _raw_domains([{"domainName": "example.com", "verified": "yes"}])),
    "listed empty": ("dns_pass", _raw_domains([])),
    "listed partial": ("dns_pass", lambda b: edit_raw(b, "raw/google_dns_posture.json",
                                                      lambda raw: raw["domains"].update(status="partial"))),
    # failure attributions
    "attribution contradicts setting": ("attributed", lambda b: edit_raw(
        b, "raw/google_policies.json", lambda raw: raw["policySettings"]["value"][2].update(setting={
            "type": "settings/security.two_step_verification_enrollment", "value": {"allowEnrollment": None}}))),
    "attribution contradicts unit": ("attributed", _scope(org_unit="ou0a1")),
    "attribution contradicts group": ("attributed", _scope(group="g1grp01")),
    "attribution unit blank": ("attributed", _scope(org_unit=" ")),
    "attribution section null": ("attributed", _scope(section=None)),
    "attribution scopes absent": ("attributed", lambda b: edit_rows(
        b, "google_policy_settings", lambda data: data[-1].pop("unusable_scopes"))),
    "attribution scopes null": ("attributed", _attribution(unusable_scopes=None)),
    "attribution scopes text": ("attributed", _attribution(unusable_scopes="gmail_auto_forwarding")),
    "attribution scopes empty": ("attributed", _attribution(unusable_scopes=[])),
    # SSO modes
    "sso mode absent": ("sso", lambda b: sso(b, {"target_org_unit": "orgUnits/root01"})),
    "sso mode null": ("sso", _sso_row(sso_mode=None)),
    "sso mode number": ("sso", _sso_row(sso_mode=0)),
    "sso mode blank": ("sso", _sso_row(sso_mode=" ")),
    "sso mode padded": ("sso", _sso_row(sso_mode="SSO_OFF ")),
    "sso mode malformed": ("sso", _sso_row(sso_mode="SSO-OFF")),
    "sso modes contradict": ("sso", lambda b: sso(b, {"target_org_unit": "orgUnits/root01", "sso_mode": "SSO_OFF"},
                                                  {"target_org_unit": "orgUnits/root01", "sso_mode": "SAML_SSO"})),
    "sso envelope partial": ("sso", lambda b: edit_rows(b, "google_sso_assignments", lambda d: None,
                                                       partial=True)),
}


@pytest.mark.parametrize("case", sorted(UNKNOWN_INPUTS))
def test_unknown_input_never_confirms_a_verdict(bundle: Path, case) -> None:
    base, change = UNKNOWN_INPUTS[case]
    setup, policy, expected = BASES[base]
    setup(bundle)
    assert verdict(project_gws_run(bundle), policy)[0] == expected
    change(bundle)
    assert verdict(project_gws_run(bundle), policy)[0] == "not_assessed", case


def test_collection_end_keeps_the_decimal_boundary(bundle: Path) -> None:
    boundary = "2026-11-20T10:00:00.300000Z"
    two_step(bundle, boundary)
    edit_manifest(bundle, created_utc="2026-11-20T10:00:00Z", duration_seconds=0.3)
    projection = project_gws_run(bundle)
    assert projection["gws_tenant"]["as_of"] == boundary
    assert verdict(projection, "GWS.COMMONCONTROLS.1.2v1")[0] == "met"


def test_user_count_must_reconcile_with_coverage(bundle: Path) -> None:
    edit_coverage(bundle, "users", item_count=6)
    projection = project_gws_run(bundle)
    assert projection["gws_admins"]["complete"] is False
    assert verdict(projection, "GWS.COMMONCONTROLS.6.2v1")[0] == "not_assessed"


def test_membership_identities_must_reconcile_at_equal_counts(bundle: Path) -> None:
    placed(bundle)
    assert verdict(project_gws_run(bundle), "GWS.COMMONCONTROLS.6.1v1")[0] == "not_met"
    _member(0, id="u400", email="di.helpdesk@example.com")(bundle)
    projection = project_gws_run(bundle)
    assert projection["gws_admins"]["memberships_complete"] is False
    assert verdict(projection, "GWS.COMMONCONTROLS.6.1v1")[0] == "not_assessed"


@pytest.mark.parametrize("fault", ["wrong count", "gap", "cut envelope", "different answers"])
def test_domain_proof_requires_agreement_at_each_source(bundle: Path, fault: str) -> None:
    passing = fault == "different answers"
    dns_only(bundle, good_domain() if passing else good_domain(spf={"records": []}))
    assert verdict(project_gws_run(bundle), "GWS.GMAIL.3.1v1")[0] == ("met" if passing else "not_met")
    if fault == "wrong count":
        edit_coverage(bundle, "posture:example.com", item_count=0)
    elif fault == "gap":
        normalised(bundle, "collection_gaps", [
            {"collector": "google_dns_posture", "list": "posture:example.com", "status": "partial"}])
    elif fault == "cut envelope":
        edit_rows(bundle, "google_dns_posture", lambda data: None, collection_truncated=True)
    else:
        _raw_posture(spf={"records": []})(bundle)
    projection = project_gws_run(bundle)
    assert projection["gws_dns"]["complete"] is False
    assert projection["gws_dns"]["domains"][0]["resolver_error"] is True
    assert verdict(projection, "GWS.GMAIL.3.1v1")[0] == "not_assessed"


@pytest.mark.parametrize("fault", ["unsupported scope", "wrong-typed cut"])
def test_policy_attribution_requires_agreement_at_each_source(bundle: Path, fault: str) -> None:
    attributed(bundle)
    assert verdict(project_gws_run(bundle), "GWS.COMMONCONTROLS.1.2v1")[0] == "met"
    if fault == "unsupported scope":
        policy = _policy("security.two_step_verification_enrollment", {"allowEnrollment": False}, order=2)
        policy["policyQuery"].update(query_scope="other")
        edit_raw(bundle, "raw/google_policies.json", lambda raw: raw["policySettings"]["value"].append(policy))
        edit_coverage(bundle, "policySettings", item_count=4)
    else:
        edit_coverage(bundle, "policySettings", policy_row_validation=True, collection_truncated="true")
    projection = project_gws_run(bundle)
    assert projection["gws_policies"]["complete"] is False
    assert verdict(projection, "GWS.COMMONCONTROLS.1.2v1")[0] == "not_assessed"


def test_malformed_membership_does_not_withhold_the_admin_count(bundle: Path) -> None:
    placed(bundle)
    _member(0, groupEmail=[])(bundle)
    projection = project_gws_run(bundle)
    assert projection["gws_admins"]["memberships_complete"] is False
    assert verdict(projection, "GWS.COMMONCONTROLS.6.1v1")[0] == "not_assessed"
    assert verdict(projection, "GWS.COMMONCONTROLS.6.2v1")[0] == "met"


# Each tuple identifies a required field in the fixture whose evidence reaches the rule. Optional fields with a
# defined absence (e.g. the value on a delete and the parent of the root) have separate cases.
REQUIRED_FIELDS = [
    ("2sv", "gws_tenant", "raw/google_directory.json", ("orgUnits", "value", 1, "orgUnitId")),
    ("2sv", "gws_tenant", "raw/google_directory.json", ("orgUnits", "value", 1, "orgUnitPath")),
    ("2sv", "gws_tenant", "raw/google_directory.json", ("orgUnits", "value", 1, "parentOrgUnitPath")),
    ("2sv", "gws_tenant", "raw/google_directory.json", ("orgUnits", "value", 1, "parentOrgUnitId")),
    ("2sv", "gws_tenant", "normalized/google_org_units.json", ("records", 0, "parent_id")),
    ("2sv", "gws_tenant", "normalized/google_org_units.json", ("records", 0, "is_root")),
    ("2sv", "gws_tenant", "normalized/google_org_units.json", ("records", 2, "root_id_known")),
    ("2sv", "gws_tenant", "normalized/google_org_units.json", ("records", 2, "malformed_count")),
    ("2sv", "gws_policies", "raw/google_policies.json", ("policySettings", "value", 0, "policyQuery", "orgUnit")),
    ("2sv", "gws_policies", "raw/google_policies.json", ("policySettings", "value", 0, "setting", "type")),
    ("2sv", "gws_policies", "raw/google_policies.json", ("policySettings", "value", 0, "setting", "value")),
    ("2sv", "gws_policies", "normalized/google_policy_settings.json", ("records", 0, "sort_order")),
    ("2sv", "gws_policies", "normalized/google_policy_settings.json", ("records", 1, "value", "enforcedFrom")),
    ("2sv", "gws_policies", "normalized/google_policy_settings.json", ("records", 2, "unusable_sections")),
    ("2sv", "gws_policies", "normalized/google_policy_settings.json", ("records", 2, "unusable_scopes")),
    ("delete", "gws_setting_events", "raw/google_setting_events.json", ("settingEvents", "window_start")),
    ("delete", "gws_setting_events", "raw/google_setting_events.json", ("settingEvents", "window_end")),
    ("delete", "gws_setting_events", "raw/google_setting_events.json", ("settingEvents", "value", 0, "event_time")),
    ("delete", "gws_setting_events", "raw/google_setting_events.json", ("settingEvents", "value", 0, "events", 0, "name")),
    ("delete", "gws_setting_events", "normalized/google_setting_events.json", ("records", 0, "setting")),
    ("delete", "gws_setting_events", "normalized/google_setting_events.json", ("records", 0, "org_unit")),
    ("dns_fail", "gws_dns", "raw/google_dns_posture.json", ("domains", "value", 0, "verified")),
    ("dns_fail", "gws_dns", "raw/google_dns_posture.json", ("domainPosture", "value", 0, "domain")),
    ("dns_fail", "gws_dns", "raw/google_dns_posture.json", ("domainPosture", "value", 0, "spf", "records")),
    ("dns_fail", "gws_dns", "normalized/google_dns_posture.json", ("records", 0, "dmarc", "query_name")),
    ("dns_fail", "gws_dns", "normalized/google_dns_posture.json", ("records", 0, "dmarc", "inherited")),
    ("dns_fail", "gws_dns", "normalized/google_dns_posture.json", ("records", 0, "dkim", "selectors", "selector1")),
    ("dns_fail", "gws_dns", "normalized/google_domains.json", ("records", 0, "domain_kind")),
    ("count", "gws_admins", "raw/google_directory.json", ("users", "value", 1, "isAdmin")),
    ("count", "gws_admins", "normalized/google_users.json", ("records", 1, "is_admin")),
    ("count", "gws_admins", "normalized/google_users.json", ("records", 1, "kind")),
    ("roles", "privileged", "raw/google_directory.json", ("users", "value", 4, "orgUnitPath")),
    ("roles", "privileged", "raw/google_directory.json", ("users", "value", 4, "isDelegatedAdmin")),
    ("roles", "privileged", "raw/google_directory.json", ("roles", "value", 3, "rolePrivileges")),
    ("roles", "privileged", "raw/google_directory.json", ("roles", "value", 3, "rolePrivileges", 0, "privilegeName")),
    ("roles", "privileged", "normalized/google_users.json", ("records", 4, "org_unit_path")),
    ("groups", "memberships_complete", "raw/google_directory.json", ("groupMembers", "value", 0, "groupEmail")),
    ("groups", "memberships_complete", "raw/google_directory.json", ("groupMembers", "value", 0, "id")),
    ("groups", "memberships_complete", "raw/google_directory.json", ("groupMembers", "value", 0, "email")),
    ("groups", "memberships_complete", "normalized/google_group_members.json", ("records", 0, "id")),
    ("groups", "memberships_complete", "normalized/google_group_members.json", ("records", 0, "email")),
    ("sso", "gws_sso", "raw/google_sso_assignments.json", ("inboundSsoAssignments", "value", 0, "targetOrgUnit")),
    ("sso", "gws_sso", "raw/google_sso_assignments.json", ("inboundSsoAssignments", "value", 0, "ssoMode")),
    ("sso", "gws_sso", "normalized/google_sso_assignments.json", ("records", 0, "target_org_unit")),
]


def replace_field(payload, path: tuple, replacement) -> None:
    for key in path[:-1]:
        payload = payload[key]
    if replacement is MISSING:
        del payload[path[-1]]
    else:
        payload[path[-1]] = replacement


MISSING = object()


@pytest.mark.parametrize(
    "base,proof,source,path", REQUIRED_FIELDS,
    ids=["/".join(map(str, (source.split("/")[-1], *path))) for _, _, source, path in REQUIRED_FIELDS],
)
@pytest.mark.parametrize("replacement", [MISSING, None, 42, " ", {"partial": True}],
                         ids=["absent", "null", "wrong-type", "blank", "malformed"])
def test_required_field_matrix(bundle: Path, base, proof, source, path, replacement) -> None:
    setup, policy, expected = BASES[base]
    setup(bundle)
    assert verdict(project_gws_run(bundle), policy)[0] == expected
    edit_raw(bundle, source, lambda payload: replace_field(payload, path, replacement))
    projection = project_gws_run(bundle)
    if proof == "memberships_complete":
        assert projection["gws_admins"]["complete"] is True
        assert projection["gws_admins"]["memberships_complete"] is False
    elif proof == "privileged":
        assert projection["gws_admins"]["complete"] is True
    else:
        assert projection[proof].get("complete") is not True
    assert verdict(projection, policy)[0] == "not_assessed"


@pytest.mark.parametrize("base,source,path", [
    ("2sv", "raw/google_directory.json", ("orgUnits", "value")),
    ("2sv", "raw/google_policies.json", ("policySettings", "value")),
    ("delete", "raw/google_setting_events.json", ("settingEvents", "value")),
    ("dns_fail", "raw/google_dns_posture.json", ("domainPosture", "value")),
    ("count", "raw/google_directory.json", ("users", "value")),
    ("groups", "raw/google_directory.json", ("groupMembers", "value")),
    ("roles", "raw/google_directory.json", ("roleAssignments", "value")),
    ("sso", "raw/google_sso_assignments.json", ("inboundSsoAssignments", "value")),
])
@pytest.mark.parametrize("duplicate", [True, False], ids=["duplicate", "partial"])
def test_retained_list_must_match_the_other_sources(bundle: Path, base, source, path, duplicate: bool) -> None:
    setup, policy, expected = BASES[base]
    setup(bundle)
    assert verdict(project_gws_run(bundle), policy)[0] == expected

    def damage(payload):
        section, key = path
        retained = payload[section][key]
        if duplicate:
            retained.append(retained[0])
        else:
            retained.pop()

    edit_raw(bundle, source, damage)
    assert verdict(project_gws_run(bundle), policy)[0] == "not_assessed"


@pytest.mark.parametrize("change", [
    {"item_count": "MISSING"}, {"item_count": None}, {"item_count": True}, {"item_count": "5"},
    {"status": None}, {"status": "partial"}, {"partial": "false"}, {"collection_truncated": 0},
    {"error_class": "read_failed"}, {"DROP": True},
])
def test_present_user_coverage_must_be_readable_and_whole(bundle: Path, change: dict) -> None:
    edit_coverage(bundle, "users", **change)
    project = project_gws_run(bundle)
    assert project["gws_admins"]["complete"] is False
    assert verdict(project, "GWS.COMMONCONTROLS.6.2v1")[0] == "not_assessed"


@pytest.mark.parametrize("base,name", [
    ("2sv", "orgUnits"), ("2sv", "policySettings"), ("delete", "settingEvents"),
    ("dns_fail", "posture:example.com"), ("count", "users"), ("groups", "groupMembers:g1@example.com"),
    ("roles", "roleAssignments"), ("sso", "inboundSsoAssignments"),
])
def test_duplicate_coverage_is_ambiguous_even_when_both_rows_are_ok(bundle: Path, base: str, name: str) -> None:
    setup, policy, expected = BASES[base]
    setup(bundle)
    assert verdict(project_gws_run(bundle), policy)[0] == expected
    coverage = load(bundle, "coverage.json")
    write(bundle, "coverage.json", [*coverage, next(row for row in coverage if row["name"] == name)])
    assert verdict(project_gws_run(bundle), policy)[0] == "not_assessed"


def test_collection_end_keeps_nanoseconds_and_the_offset(bundle: Path) -> None:
    two_step(bundle, "2026-11-20T10:00:00.300000001Z")
    edit_manifest(bundle, created_utc="2026-11-20T11:00:00.299999999+01:00", duration_seconds=2e-9)
    projection = project_gws_run(bundle)
    assert projection["gws_tenant"]["as_of"] == "2026-11-20T10:00:00.300000001Z"
    assert verdict(projection, "GWS.COMMONCONTROLS.1.2v1")[0] == "met"


def test_sub_nanosecond_duration_is_withheld_without_rounding(bundle: Path) -> None:
    two_step(bundle)
    edit_manifest(bundle, duration_seconds=0.3000000001)
    projection = project_gws_run(bundle)
    assert projection["gws_tenant"]["as_of"] is None
    assert verdict(projection, "GWS.COMMONCONTROLS.1.2v1")[0] == "not_assessed"


def test_an_independently_proven_dns_violation_survives_another_domains_missing_read(bundle: Path) -> None:
    dns_only(bundle, good_domain(spf={"records": []}), listed=["example.com", "example.org"])
    projection = project_gws_run(bundle)
    assert projection["gws_dns"]["complete"] is False
    assert verdict(projection, "GWS.GMAIL.3.1v1") == ("not_met", "domain_violates")


def test_an_unsupported_policy_scope_only_weakens_the_confirmed_setting(bundle: Path) -> None:
    attributed(bundle)
    edit_raw(bundle, "raw/google_policies.json", lambda raw: raw["policySettings"]["value"][2].update({
        "setting": {"type": "settings/gmail.auto_forwarding", "value": {"enableAutoForwarding": False}},
        "policyQuery": {"orgUnit": "orgUnits/root01", "sortOrder": 1, "query_scope": "other"},
    }))
    edit_rows(bundle, "google_policy_settings", lambda records: records[-1].update(malformed_count=0))
    projection = project_gws_run(bundle)
    assert projection["gws_policies"]["complete"] is True
    assert verdict(projection, "GWS.COMMONCONTROLS.1.2v1")[0] == "met"


def test_policy_identifiers_and_ip_addresses_are_redacted_after_reconciliation(bundle: Path) -> None:
    from auditex.google_workspace.normalize import _policy_settings_read

    rule_id = "mail-storage-private-ref"
    address = "198.51.100.27/32"
    policies = {"policySettings": {"value": [
        _policy("gmail.service_status", {"serviceState": "ENABLED"}),
        _policy("gmail.comprehensive_mail_storage", {"ruleId": rule_id}),
        _policy("gmail.rule_states", {"ruleStates": [{"ruleId": rule_id, "enabled": True}]}),
        _policy("gmail.email_spam_filter_ip_allowlist", {"allowedIpAddresses": [address]}),
        _policy("gmail.email_attachment_safety", {"enableEncryptedAttachmentProtection": True,
                                                  "encryptedAttachmentProtectionQuarantineId": 908792381872}),
        _policy("security.password", {"minimumLength": 16}),
    ]}}
    normalised_rows, _ = _policy_settings_read(
        policies, [{"name": "google_policies", "status": "ok"}], [], {"root01", "ou0a1"})
    write(bundle, "raw/google_policies.json", policies)
    normalised(bundle, "google_policy_settings", normalised_rows)
    edit_coverage(bundle, "policySettings", item_count=6)
    projection = project_gws_run(bundle)
    text = json.dumps([dict(projection), projection.report])
    assert rule_id not in text and address not in text and "908792381872" not in text
    entries = {row["section"]: row["value"] for row in projection["gws_policies"]["policies"]}
    assert entries["gmail_comprehensive_mail_storage"] == {"ruleId": "ref:485a522113e0c67b"}
    assert entries["gmail_rule_states"] == {"ruleStates": [{"ruleId": "ref:485a522113e0c67b", "enabled": True}]}
    assert entries["gmail_email_spam_filter_ip_allowlist"] == {"allowedIpAddresses": ["2001:db8::8aa7:7a5d:eafd:529b"]}
    assert entries["gmail_email_attachment_safety"] == {"enableEncryptedAttachmentProtection": True}
    assert entries["security_password"] == {"minimumLength": 16}
    assert verdict(projection, "GWS.GMAIL.17.1v1")[0] == "met"
    assert verdict(projection, "GWS.GMAIL.14.1v1")[0] == "not_met"


@pytest.mark.parametrize("marker", [{"complete": False}, {"collection_status": "not_collected"},
                                    {"nextPageToken": "another-page"}, {"error": "timed out"}])
def test_matching_txt_payloads_with_a_failed_read_are_unknown(bundle: Path, marker: dict) -> None:
    dns_only(bundle, good_domain(spf={"records": [], **marker}))
    projection = project_gws_run(bundle)
    assert projection["gws_dns"]["complete"] is False
    assert verdict(projection, "GWS.GMAIL.3.1v1")[0] == "not_assessed"


@pytest.mark.parametrize("marker", [{"complete": False}, {"collection_status": "not_collected"},
                                    {"nextPageToken": "another-page"}, {"next_page_token": "another-page"}])
def test_attribution_cannot_override_unproven_transport(bundle: Path, marker: dict) -> None:
    attributed(bundle)
    assert verdict(project_gws_run(bundle), "GWS.COMMONCONTROLS.1.2v1")[0] == "met"
    edit_coverage(bundle, "policySettings", **marker)
    assert verdict(project_gws_run(bundle), "GWS.COMMONCONTROLS.1.2v1")[0] == "not_assessed"


def test_an_unreadable_gap_artifact_cannot_prove_the_absence_of_gaps(bundle: Path) -> None:
    normalised(bundle, "collection_gaps", [], collection_status="not_collected")
    assert verdict(project_gws_run(bundle), "GWS.COMMONCONTROLS.6.2v1")[0] == "not_assessed"


@pytest.mark.parametrize("base,source", [
    ("2sv", "google_org_units"), ("2sv", "google_policy_settings"), ("delete", "google_setting_events"),
    ("sso", "google_sso_assignments"),
])
@pytest.mark.parametrize("marker", [{"complete": "true"}, {"collection_truncated": True},
                                    {"nextPageToken": "another-page"}, {"error_class": "denied"}])
def test_read_state_cannot_attest_to_an_interrupted_read(bundle: Path, base: str, source: str, marker: dict) -> None:
    setup, policy, expected = BASES[base]
    setup(bundle)
    assert verdict(project_gws_run(bundle), policy)[0] == expected
    edit_rows(bundle, source, lambda data: data[-1].update(**marker))
    assert verdict(project_gws_run(bundle), policy)[0] == "not_assessed"


def test_directory_parent_fields_must_agree_with_its_path_hierarchy(bundle: Path) -> None:
    third_ou(bundle)
    def move_other_users_to_root(users: list[dict], field: str) -> None:
        for user in users[:-1]:
            user[field] = "/"

    raw_directory(bundle, lambda raw: move_other_users_to_root(raw["users"]["value"], "orgUnitPath"))
    edit_rows(bundle, "google_users", lambda data: move_other_users_to_root(data, "org_unit_path"))
    sso(bundle, {"target_org_unit": "orgUnits/ou0a1", "sso_mode": "SAML_SSO"})
    policy = "GWS.COMMONCONTROLS.6.1v1"
    assert verdict(project_gws_run(bundle), policy)[0] == "met"

    placed(bundle, "/Sales/Ops")
    raw_directory(bundle, lambda raw: raw["orgUnits"]["value"][2].update(orgUnitPath="/Sales/Ops"))
    projection = project_gws_run(bundle)
    assert projection["gws_tenant"]["complete"] is False
    assert verdict(projection, policy)[0] == "not_assessed"

    raw_directory(bundle, lambda raw: raw["orgUnits"]["value"][2].update(
        parentOrgUnitId="id:ou0a1", parentOrgUnitPath="/Sales"))
    edit_rows(bundle, "google_org_units", lambda data: data[1].update(parent_id="ou0a1"))
    assert verdict(project_gws_run(bundle), policy)[0] == "not_met"


@pytest.mark.parametrize("record_gap", [False, True])
def test_an_accounted_alias_failure_leaves_base_domain_rules_answerable(bundle: Path, record_gap: bool) -> None:
    if record_gap:
        normalised(bundle, "collection_gaps", [
            {"collector": "google_dns_posture", "list": "posture:example.net", "status": "failed",
             "reason": "read_failed", "rows_collected": 1, "error_classes": ["dns_resolver_error"]}])
    projection = project_gws_run(bundle)
    assert verdict(projection, "GWS.GMAIL.3.1v1")[0] == "met"
    assert verdict(projection, "GWS.GMAIL.4.1v1")[0] == "not_assessed"
    edit_coverage(bundle, "posture:example.net", item_count=0)
    projection = project_gws_run(bundle)
    assert projection["gws_dns"]["complete"] is False
    assert verdict(projection, "GWS.GMAIL.3.1v1")[0] == "not_assessed"


@pytest.mark.parametrize("problem", ["retired_ou", "value", "application"])
def test_unusable_event_only_withholds_its_own_setting(bundle: Path, problem: str) -> None:
    changed = event("2026-10-03T10:00:00Z", "CHANGE_APPLICATION_SETTING",
                    setting="AttachmentDeepScanningSettingsProto deep_scanning_enabled", new_value="true")
    if problem == "value":
        changed.update(org_unit="ou0a1", new_value="unrecognised")
    elif problem == "application":
        changed.update(org_unit="ou0a1", application="unrecognised")
    recorded_events(bundle, [
        event("2026-10-01T10:00:00Z", "CHANGE_APPLICATION_SETTING", setting=SETTING, new_value="false",
              org_unit="root01"),
        event("2026-10-02T10:00:00Z", "CHANGE_APPLICATION_SETTING", setting=SETTING, new_value="false",
              org_unit="ou0a1"),
        changed, state("google_setting_events", 3, **WINDOW)])
    if problem == "retired_ou":
        edit_raw(bundle, "raw/google_setting_events.json", lambda raw: (
            raw["settingEvents"]["value"][-1]["events"][0]["event_parameters"].append(
                {"name": "ORG_UNIT_NAME", "value": "/Retired"})))
    projection = project_gws_run(bundle)
    assert projection["gws_setting_events"]["complete"] is True
    assert verdict(projection, "GWS.GMAIL.13.1v1") == ("met", "no_unit_violates")
    assert verdict(projection, "GWS.GMAIL.16.1v1") == ("not_assessed", "data_unusable_event_value")


def test_dns_scope_accounts_for_unverified_directory_domains(bundle: Path) -> None:
    dns_only(bundle, good_domain(spf={"records": []}))
    edit_rows(bundle, "google_domains", lambda data: data.extend([
        {"kind": "google_domain", "domain_name": "example.org", "domain_kind": "secondary", "verified": False},
        {"kind": "google_domain", "domain_name": "example.net", "domain_kind": "alias", "verified": False,
         "parent_domain": "example.com"},
        {"kind": "google_domain", "domain_name": "mail.example.org", "domain_kind": "alias", "verified": True,
         "parent_domain": "example.org"},
    ]))
    edit_coverage(bundle, "domains", item_count=2)
    projection = project_gws_run(bundle)
    assert projection["gws_dns"]["complete"] is True
    assert [row["resolver_error"] for row in projection["gws_dns"]["domains"]] == [False]
    assert verdict(projection, "GWS.GMAIL.3.1v1") == ("not_met", "domain_violates")
    edit_coverage(bundle, "domains", item_count=3)
    assert verdict(project_gws_run(bundle), "GWS.GMAIL.3.1v1")[0] == "not_assessed"


@pytest.mark.parametrize("resolver_failed", [False, True])
def test_l05_dns_alias_has_dmarc_evidence_or_a_scoped_failure(bundle: Path, resolver_failed: bool) -> None:
    alias = {"kind": "google_domain_posture", "domain": "example.net", "alias": True,
             "resolver_error": resolver_failed}
    if not resolver_failed:
        alias["dmarc"] = {"query_name": "_dmarc.example.net", "inherited": False, "records": [DMARC]}
    dns_only(bundle, good_domain(), alias)
    if resolver_failed:
        edit_raw(bundle, "raw/google_dns_posture.json", lambda raw: raw["domainPosture"]["value"][1].update(
            resolver_error="DNS resolver could not answer."))
        edit_coverage(bundle, "posture:example.net", status="failed", error_class="dns_resolver_error")
    projection = project_gws_run(bundle)
    assert projection["gws_dns"]["complete"] is True
    assert [row["resolver_error"] for row in projection["gws_dns"]["domains"]] == [False, resolver_failed]
    for policy in ("GWS.GMAIL.2.1v1", "GWS.GMAIL.3.1v1"):
        assert verdict(projection, policy) == ("met", "no_domain_violates")
    expected = ("not_assessed", "data_unavailable_resolver_error") if resolver_failed else ("met", "no_domain_violates")
    assert verdict(projection, "GWS.GMAIL.4.1v1") == expected


def test_a_failed_resolver_configuration_withholds_apparently_readable_txt(bundle: Path) -> None:
    dns_only(bundle, good_domain(spf={"records": []}))
    coverage = load(bundle, "coverage.json")
    coverage.append({"collector": "google_dns_posture", "name": "dohEndpoint", "status": "failed",
                     "item_count": 0, "error_class": "config_error"})
    write(bundle, "coverage.json", coverage)
    projection = project_gws_run(bundle)
    assert projection["gws_dns"]["complete"] is False
    assert verdict(projection, "GWS.GMAIL.3.1v1")[0] == "not_assessed"
