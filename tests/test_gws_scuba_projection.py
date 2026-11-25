"""GWS SCuBA projection (M13 L06): synthetic Google bundles only; expected values are literals."""
from __future__ import annotations

import json
import os
import socket
from hashlib import sha256
from pathlib import Path

import pytest

from auditex.google_workspace.scuba_projection import SECTIONS, project_gws_run
from azure_tenant_audit.collection_markers import NOT_COLLECTED

KEY = bytes(range(32))
# HMAC-SHA256 under KEY, first 16 hex digits, worked out independently of the code under test.
U100, U200, U300, U500 = "user:a3da8ecfe18ba66b", "user:3cd262199099fc36", "user:c53758839d880a20", "user:95072140579b78b2"
G1, G2 = "group:1f28b0e409ce3330", "group:3b8c6f8c6686cfef"
GONE = "ou:~deleted~21cdd3c0abefedfc"
G9_EMAIL = "group:f89b76e9cadfed92"
CUSTOMER = "C0synth9x"
DMARC = "v=DMARC1; p=reject; rua=mailto:reports@dmarc.cyber.dhs.gov"


def write(root: Path, path: str, payload) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload) + "\n")


def seed_key(root: Path) -> None:
    folder = root / "operator-inputs"
    folder.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(folder / "pseudonym.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.write(fd, KEY)
    os.close(fd)


def normalised(root: Path, name: str, records: list) -> None:
    write(root, f"normalized/{name}.json", {"kind": name, "records": records})


def state(section: str, count: int, complete: bool = True, **extra) -> dict:
    return {"kind": f"{section}_read_state", "id": "read_state", "complete": complete, "record_count": count, **extra}


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
        "created_utc": "2026-11-20T10:00:00.000000Z", "duration_seconds": 90.5, "coverage_path": "coverage.json",
        "run_dir": "/home/example/runs/synthetic",
    })
    seed_key(root)
    write(root, "coverage.json", [
        *({"collector": "google_directory", "name": name, "status": "ok", "item_count": 1}
          for name in ("users", "groups", "orgUnits", "roles", "roleAssignments", "groupMembers:g1@example.com")),
        {"collector": "google_dns_posture", "name": "domains", "status": "ok", "item_count": 1},
    ])
    write(root, "raw/google_directory.json", {
        "users": {"value": USERS},
        "groups": {"value": [{"id": "g1grp01", "email": "g1@example.com"}, {"id": "g2grp02", "email": "g2@example.org"}]},
        "groupMembers": {"value": [{"groupEmail": "g1@example.com", "email": "Ada.Admin@example.com", "type": "USER"},
                                   {"groupEmail": "g2@example.org", "email": "ada.admin@example.com", "type": "USER"}]},
        "groupMembersErrors": {"value": []},
        "orgUnits": {"value": [
            {"orgUnitId": "id:root01", "orgUnitPath": "/", "name": "Example Org"},
            {"orgUnitId": "id:ou0a1", "orgUnitPath": "/Sales", "name": "Sales", "parentOrgUnitId": "id:root01"},
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
    normalised(root, "google_groups", [{"kind": "google_group", "id": "g1grp01", "email": "g1@example.com"},
                                       {"kind": "google_group", "id": "g2grp02", "email": "g2@example.org"}])
    normalised(root, "google_group_members", [
        {"kind": "google_group_member", "group_email": "g1@example.com", "email": "Ada.Admin@example.com"},
        {"kind": "google_group_member", "group_email": "G2@example.org", "email": "ada.admin@example.com"}])
    normalised(root, "google_org_units", [
        {"kind": "google_org_unit", "id": "ou0a1", "parent_id": "root01", "is_root": False},
        {"kind": "google_org_unit", "id": "root01", "parent_id": None, "is_root": True},
        state("google_org_units", 2, root_id_known=True, malformed_count=0)])
    normalised(root, "google_policy_settings", [
        {"kind": "google_policy_setting", "section": "gmail_auto_forwarding", "unit_kind": "org_unit",
         "org_unit": "root01", "sort_order": 1, "value": {"enableAutoForwarding": False}},
        {"kind": "google_policy_setting", "section": "drive_and_docs_external_sharing", "unit_kind": "group",
         "org_unit": "root01", "group": "g1grp01", "sort_order": 2.5,
         "value": {"externalSharingMode": "DISALLOWED", "note": "owner ops@example.com"}},
        state("google_policy_settings", 2)])
    normalised(root, "google_setting_events", [
        {"kind": "google_setting_event", "time": "2026-10-01T10:00:00.123456789Z", "event": "CHANGE_APPLICATION_SETTING",
         "setting": "SettingA", "new_value": "true", "org_unit_name": "Sales", "application": "Gmail"},
        {"kind": "google_setting_event", "time": "2026-10-02T10:00:00Z", "event": "TOGGLE_CAA_ENABLEMENT",
         "new_value": "ENABLED", "org_unit_name": "Example Org"},
        {"kind": "google_setting_event", "time": "2026-10-03T10:00:00Z", "event": "DELETE_APPLICATION_SETTING",
         "setting": "SettingA", "org_unit_name": "Gone"},
        {"kind": "google_setting_event", "time": "2026-10-04T10:00:00Z", "event": "CHANGE_APPLICATION_SETTING",
         "setting": "SettingB", "new_value": "false", "org_unit_name": "Sales", "group_email": "G1@example.com"},
        {"kind": "google_setting_event", "time": "2026-10-05T10:00:00Z", "event": "CHANGE_APPLICATION_SETTING",
         "setting": "SettingB", "new_value": "1", "group_email": "g9@example.com"},
        state("google_setting_events", 5)])
    normalised(root, "google_sso_assignments", [
        {"kind": "google_sso_assignment", "target_org_unit": "orgUnits/ou0a1", "sso_mode": "SSO_OFF"},
        {"kind": "google_sso_assignment", "target_group": "groups/g1grp01", "sso_mode": "SAML_SSO"},
        state("google_sso_assignments", 2)])
    normalised(root, "google_domains", [
        {"kind": "google_domain", "domain_name": "example.com", "domain_kind": "primary"},
        {"kind": "google_domain", "domain_name": "example.net", "domain_kind": "alias"}])
    normalised(root, "google_dns_posture", [
        {"kind": "google_domain_posture", "domain": "example.com", "alias": False,
         "spf": {"records": ["v=spf1 -all"]},
         "dkim": {"selectors": {"google": ["v=DKIM1; p=AAAA"], "selector1": [], "selector2": [], "s1": ["x"]}},
         "dmarc": {"query_name": "_dmarc.example.com", "inherited": False, "records": [DMARC]}},
        {"kind": "google_domain_posture", "domain": "example.net", "resolver_error": "timeout via https://resolver.example/dns-query",
         "dmarc": {"query_name": "_dmarc.example.net"}},
    ])
    write(root, "raw/google_dns_posture.json", {"domains": {"value": [{"domainName": "example.com"}]},
                                                "domainPosture": {"value": [{}, {}]}})
    return root


EXPECTED = {
    "gws_tenant": {"as_of": "2026-11-20T10:01:30.500000Z", "top_unit": "ou:root01",
                   "org_units": {"ou:ou0a1": "ou:root01", "ou:root01": None}, "complete": True},
    "gws_policies": {"complete": True, "policies": [
        {"unit": "ou:root01", "unit_kind": "org_unit", "section": "gmail_auto_forwarding", "sort_order": 1,
         "value": {"enableAutoForwarding": False}},
        {"unit": f"ou:root01/{G1}", "unit_kind": "group", "section": "drive_and_docs_external_sharing", "sort_order": 2.5,
         "value": {"externalSharingMode": "DISALLOWED", "note": "owner ***@example.com"}}]},
    "gws_setting_events": {"complete": True, "window_start": "1970-01-01T00:00:00Z",
                           "window_end": "2026-11-20T10:01:30.500000Z", "events": [
        {"time": "2026-10-01T10:00:00.123456789Z", "event": "CHANGE_APPLICATION_SETTING", "setting": "SettingA",
         "new_value": "true", "unit": "ou:ou0a1", "application": "Gmail"},
        {"time": "2026-10-02T10:00:00Z", "event": "TOGGLE_CAA_ENABLEMENT", "setting": None, "new_value": "ENABLED",
         "unit": "ou:root01", "application": None},
        {"time": "2026-10-03T10:00:00Z", "event": "DELETE_APPLICATION_SETTING", "setting": "SettingA",
         "new_value": None, "unit": GONE, "application": None},
        {"time": "2026-10-04T10:00:00Z", "event": "CHANGE_APPLICATION_SETTING", "setting": "SettingB",
         "new_value": "false", "unit": G1, "application": None},
        {"time": "2026-10-05T10:00:00Z", "event": "CHANGE_APPLICATION_SETTING", "setting": "SettingB",
         "new_value": "1", "unit": G9_EMAIL, "application": None}]},
    "gws_dns": {"complete": True, "domains": [
        {"domain": "example.com", "alias": False, "resolver_error": False, "spf": {"records": ["v=spf1 -all"]},
         "dkim": {"selectors": {"google": ["v=DKIM1; p=AAAA"], "selector1": [], "selector2": []}},
         "dmarc": {"query_name": "_dmarc.example.com", "inherited": False, "records": [DMARC]}},
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


def test_each_section_from_a_synthetic_bundle(bundle: Path) -> None:
    projection = project_gws_run(bundle)
    assert dict(projection) == EXPECTED
    sections = projection.report["sections"]
    assert {name: entry["status"] for name, entry in sections.items()} == {name: "projected" for name in SECTIONS}
    assert sections["gws_admins"]["source"] == [
        "run-manifest.json", "normalized/google_users.json", "normalized/google_role_assignments.json",
        "raw/google_directory.json", "coverage.json", "normalized/google_groups.json",
        "normalized/google_group_members.json"]
    assert projection.report["redaction"] == {"enabled": True, "strategy": "keyed-hmac-sha256-v1", "user_ids": 4,
                                              "group_ids": 2, "email_addresses": 1}
    assert projection.report["schema_version"] == "2026-11-25"


def test_no_address_customer_id_group_id_path_or_name_in_the_output(bundle: Path) -> None:
    projection = project_gws_run(bundle)
    text = json.dumps([dict(projection), projection.report])
    for needle in ("ada.admin", "bo.admin", "cy.groups", "ed.custom", "g1@example.com", "g9@example.com", "ops@",
                   CUSTOMER, "g1grp01", "g2grp02", "/Sales", "Sales", "Example Org", "Synthetic Person", "Gone",
                   "/home/example", "resolver.example", "timeout", "u100", "u500"):
        assert needle not in text, needle
    # Public DNS text stays verbatim: GMAIL 4.3 reads the DMARC reporting address.
    assert DMARC in text


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
    rows = project_gws_run(bundle, scan_max_rows=4).report["sections"]
    assert rows["gws_setting_events"]["reason"] == "oversize"
    assert rows["gws_setting_events"]["detail"] == {"field": "scan_max_rows", "kind": "scan_bound"}
    assert rows["gws_sso"]["reason"] is None
    tiny = project_gws_run(bundle, scan_max_bytes=64).report["sections"]
    assert {e["reason"] for e in tiny.values()} == {"oversize"}
    assert project_gws_run(bundle, max_chars=100).report["sections"]["gws_policies"]["reason"] == "oversize"
    with pytest.raises(ValueError):
        project_gws_run(bundle, max_items=0)


# --- unknown is not safe --------------------------------------------------------------------------------------


@pytest.mark.parametrize("section,name,count", [("gws_policies", "google_policy_settings", 2),
                                                ("gws_setting_events", "google_setting_events", 5),
                                                ("gws_sso", "google_sso_assignments", 2),
                                                ("gws_tenant", "google_org_units", 2)])
@pytest.mark.parametrize("bad", [{"complete": False}, {"complete": None}, {"complete": "true"}, {"record_count": 9},
                                 {"record_count": True}, {"record_count": None}, "missing", "twice"])
def test_read_state_not_proving_a_complete_read_is_incomplete(bundle: Path, section, name, count, bad) -> None:
    data = json.loads((bundle / f"normalized/{name}.json").read_text())["records"]
    rows, read_state = data[:-1], data[-1]
    if bad == "twice":
        rows = [*rows, read_state, read_state]
    elif bad != "missing":
        rows = [*rows, {**read_state, **bad}]
    normalised(bundle, name, rows)
    assert project_gws_run(bundle)[section]["complete"] is False


@pytest.mark.parametrize("change", [
    {"org_unit": None}, {"org_unit": 7}, {"org_unit": "bad id"}, {"org_unit": "a/b"}, {"group": ""},
    {"unit_kind": "org_unit"}, {"unit_kind": None}, {"section": None}, {"section": ""}])
def test_a_policy_that_cannot_be_placed_is_left_out(bundle: Path, change) -> None:
    rows = json.loads((bundle / "normalized/google_policy_settings.json").read_text())["records"]
    rows[1].update(change)
    normalised(bundle, "google_policy_settings", rows)
    section = project_gws_run(bundle)["gws_policies"]
    assert section["complete"] is False
    assert [entry["section"] for entry in section["policies"]] == ["gmail_auto_forwarding"]


def test_policy_without_value_or_rank_passes_on_for_the_reducer(bundle: Path) -> None:
    rows = json.loads((bundle / "normalized/google_policy_settings.json").read_text())["records"]
    del rows[0]["value"], rows[0]["sort_order"]
    normalised(bundle, "google_policy_settings", rows)
    section = project_gws_run(bundle)["gws_policies"]
    assert section["complete"] is True
    assert section["policies"][0] == {"unit": "ou:root01", "unit_kind": "org_unit", "section": "gmail_auto_forwarding",
                                      "sort_order": None}


@pytest.mark.parametrize("change", [{"id": None}, {"id": "a b"}, {"is_root": "yes"}, {"parent_id": None},
                                    {"parent_id": "x/y"}])
def test_a_unit_that_cannot_be_placed_makes_the_topology_incomplete(bundle: Path, change) -> None:
    rows = json.loads((bundle / "normalized/google_org_units.json").read_text())["records"]
    rows[0].update(change)
    normalised(bundle, "google_org_units", rows)
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
                                      {"created_utc": "2026-11-20T10:00:00"}, {"created_utc": "soon"}])
def test_unusable_collection_end_gives_no_as_of(bundle: Path, manifest) -> None:
    data = json.loads((bundle / "run-manifest.json").read_text())
    write(bundle, "run-manifest.json", {**data, **manifest})
    projection = project_gws_run(bundle)
    assert projection["gws_tenant"]["as_of"] is None
    assert projection["gws_setting_events"]["window_end"] is None


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
    {"target_group": "groups/", "sso_mode": "SSO_OFF"}, {"target_group": 5, "sso_mode": "SSO_OFF"}])
def test_an_sso_assignment_that_cannot_be_placed_is_left_out(bundle: Path, record) -> None:
    normalised(bundle, "google_sso_assignments", [{"kind": "google_sso_assignment", **record},
                                                  state("google_sso_assignments", 1)])
    assert project_gws_run(bundle)["gws_sso"] == {"complete": False, "assignments": []}


@pytest.mark.parametrize("name", ["users", "roles", "roleAssignments"])
@pytest.mark.parametrize("cut", ["coverage", "gap", "raw", "count"])
def test_a_cut_admin_read_is_incomplete(bundle: Path, name, cut) -> None:
    if cut == "coverage":
        rows = json.loads((bundle / "coverage.json").read_text())
        write(bundle, "coverage.json", [{**r, "status": "partial"} if r["name"] == name else r for r in rows])
    elif cut == "gap":
        normalised(bundle, "collection_gaps", [{"kind": "collection_gap", "collector": "google_directory", "list": name}])
    else:
        raw = json.loads((bundle / "raw/google_directory.json").read_text())
        if cut == "raw":
            raw[name]["collection_truncated"] = True
        else:
            raw[name]["value"].append(dict(raw[name]["value"][0]))
            if name == "roles":
                raw[name]["value"][-1]["roleId"] = "99"
        write(bundle, "raw/google_directory.json", raw)
    expected = cut != "count" or name != "roles"  # an extra raw role is not a cut read
    assert project_gws_run(bundle)["gws_admins"]["complete"] is (not expected)


def test_coverage_file_named_but_missing_is_unknown(bundle: Path) -> None:
    (bundle / "coverage.json").unlink()
    admins = project_gws_run(bundle)["gws_admins"]
    assert admins["complete"] is False and admins["memberships_complete"] is False


@pytest.mark.parametrize("role", [{"roleId": "2", "isSuperAdminRole": "no"}, {"roleId": "2", "roleName": 4},
                                  {"roleId": "2", "rolePrivileges": [{"privilegeName": None}]},
                                  {"roleId": "2", "rolePrivileges": "USERS_ALL"}])
def test_an_assigned_role_that_cannot_be_read_makes_admins_incomplete(bundle: Path, role) -> None:
    raw = json.loads((bundle / "raw/google_directory.json").read_text())
    raw["roles"]["value"][1] = role
    write(bundle, "raw/google_directory.json", raw)
    admins = project_gws_run(bundle)["gws_admins"]
    assert admins["complete"] is False
    assert U300 not in [entry["user"] for entry in admins["privileged"]]


@pytest.mark.parametrize("change", ["member_error", "member_cut", "unknown_group", "member_email"])
def test_partial_memberships_are_not_complete(bundle: Path, change) -> None:
    if change == "member_error":
        normalised(bundle, "google_group_member_errors", [{"kind": "google_group_member_error", "group_email": "g"}])
    elif change == "member_cut":
        rows = json.loads((bundle / "coverage.json").read_text())
        write(bundle, "coverage.json", [{**r, "collection_truncated": True} if r["name"].startswith("groupMembers:")
                                        else r for r in rows])
    else:
        rows = json.loads((bundle / "normalized/google_group_members.json").read_text())["records"]
        rows[0].update({"group_email": "g7@example.com"} if change == "unknown_group" else {"email": None})
        normalised(bundle, "google_group_members", rows)
    admins = project_gws_run(bundle)["gws_admins"]
    assert admins["memberships_complete"] is False and admins["complete"] is True


def test_admin_flags_of_the_wrong_type_make_admins_incomplete(bundle: Path) -> None:
    rows = json.loads((bundle / "normalized/google_users.json").read_text())["records"]
    rows[1]["is_admin"] = "true"
    normalised(bundle, "google_users", rows)
    admins = project_gws_run(bundle)["gws_admins"]
    assert admins["complete"] is False and admins["super_admin_count"] == 1


def test_an_incomplete_unit_list_places_no_admin_or_event(bundle: Path) -> None:
    raw = json.loads((bundle / "raw/google_directory.json").read_text())
    raw["orgUnits"]["collection_truncated"] = True
    write(bundle, "raw/google_directory.json", raw)
    projection = project_gws_run(bundle)
    assert [entry["org_unit"] for entry in projection["gws_admins"]["privileged"]] == [None, None, None, None]
    assert [event["unit"] for event in projection["gws_setting_events"]["events"]] == [None, None, None, G1, G9_EMAIL]


def test_a_shared_unit_name_is_ambiguous(bundle: Path) -> None:
    raw = json.loads((bundle / "raw/google_directory.json").read_text())
    raw["orgUnits"]["value"].append({"orgUnitId": "id:ou0b2", "orgUnitPath": "/Region/Sales", "name": "Sales"})
    write(bundle, "raw/google_directory.json", raw)
    events = project_gws_run(bundle)["gws_setting_events"]["events"]
    assert [event["unit"] for event in events] == [None, "ou:root01", GONE, G1, G9_EMAIL]


@pytest.mark.parametrize("change", [{"event": None}, {"event": ""}, {"event": 4}])
def test_an_event_without_a_name_is_left_out(bundle: Path, change) -> None:
    rows = json.loads((bundle / "normalized/google_setting_events.json").read_text())["records"]
    rows[0].update(change)
    normalised(bundle, "google_setting_events", rows)
    section = project_gws_run(bundle)["gws_setting_events"]
    assert section["complete"] is False and len(section["events"]) == 4


def test_event_fields_of_the_wrong_type_pass_as_null(bundle: Path) -> None:
    rows = json.loads((bundle / "normalized/google_setting_events.json").read_text())["records"]
    rows[0].update({"time": 5, "setting": ["x"], "new_value": {"v": 1}, "application": False})
    normalised(bundle, "google_setting_events", rows)
    assert project_gws_run(bundle)["gws_setting_events"]["events"][0] == {
        "time": None, "event": "CHANGE_APPLICATION_SETTING", "setting": None, "new_value": None, "unit": "ou:ou0a1",
        "application": None}


def test_dns_read_state_and_cut_posture_list(bundle: Path) -> None:
    raw = json.loads((bundle / "raw/google_dns_posture.json").read_text())
    raw["domainPosture"]["collection_truncated"] = True
    write(bundle, "raw/google_dns_posture.json", raw)
    assert project_gws_run(bundle)["gws_dns"]["complete"] is False
    rows = json.loads((bundle / "normalized/google_dns_posture.json").read_text())["records"]
    normalised(bundle, "google_dns_posture", [*rows, state("google_dns_posture", 2)])
    assert project_gws_run(bundle)["gws_dns"]["complete"] is True


@pytest.mark.parametrize("value,expected", [(None, False), (False, False), (True, True), ("x", True), ({}, True),
                                            (0, True)])
def test_resolver_error_is_unknown_unless_absent_or_false(bundle: Path, value, expected) -> None:
    rows = json.loads((bundle / "normalized/google_dns_posture.json").read_text())["records"]
    rows[0]["resolver_error"] = value
    normalised(bundle, "google_dns_posture", rows)
    assert project_gws_run(bundle)["gws_dns"]["domains"][0]["resolver_error"] is expected


@pytest.mark.parametrize("change,field,expected", [
    ({"alias": "no"}, "alias", False),  # falls back to the Directory domain kind (primary)
    ({"domain": "example.org", "alias": None}, "alias", None),  # no kind known
    ({"spf": {"records": ["v=spf1", 3]}}, "spf", {"records": None}),
    ({"dmarc": {"query_name": 1, "inherited": "no", "records": "v=DMARC1"}}, "dmarc",
     {"query_name": None, "inherited": None, "records": None}),
])
def test_dns_fields_of_the_wrong_type_pass_as_null(bundle: Path, change, field, expected) -> None:
    rows = json.loads((bundle / "normalized/google_dns_posture.json").read_text())["records"]
    rows[0].update(change)
    normalised(bundle, "google_dns_posture", rows)
    assert project_gws_run(bundle)["gws_dns"]["domains"][0][field] == expected
