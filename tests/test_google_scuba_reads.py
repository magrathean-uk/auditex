from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from auditex.google_workspace.auth import ISOLATED_GOOGLE_SCOPES
from auditex.google_workspace.client import GoogleWorkspaceClient
from auditex.google_workspace.collectors import PRESETS, REGISTRY
from auditex.google_workspace.normalize import build_google_normalized_snapshot
from auditex.google_workspace.run import build_google_preflight_rows, run_google_offline
from auditex.setup_guide import build_setup_guide
from azure_tenant_audit.scope_catalog import build_google_scope_catalog

EVENTS = "google_setting_events"
SSO = "google_sso_assignments"
SSO_SCOPE = "https://www.googleapis.com/auth/cloud-identity.inboundsso.readonly"
POLICY_SCOPE = "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
REPORTS_SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
TIME = "2026-11-23T00:02:28.672000091Z"
SETTING = "ContentReportingProto one_on_one_reporting"


def _activity(name, *parameters, timestamp=TIME):
    return {
        "id": {"time": timestamp, "customerId": "C0123abc", "uniqueQualifier": "ignored"},
        "actor": {"email": "actor@example.com"},
        "ipAddress": "192.0.2.25",
        "events": [{"name": name, "parameters": [{"name": key, "value": value} for key, value in parameters]}],
    }


def _enable():
    return _activity("TOGGLE_CAA_ENABLEMENT", ("NEW_VALUE", "ENABLED"), ("OLD_VALUE", "actor@example.com"))


def _delete():
    return _activity("DELETE_APPLICATION_SETTING", ("SETTING_NAME", SETTING),
                     ("ORG_UNIT_NAME", "Example Root"), ("APPLICATION_NAME", "Google Chat"))


class _Service:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def list(self, **kwargs):
        self.calls.append(kwargs)
        key = kwargs.get("eventName"), kwargs.get("pageToken")
        response = self.pages.get(key, {})

        def execute():
            if isinstance(response, Exception):
                raise response
            return response

        return SimpleNamespace(execute=execute)


def _client(service):
    client = GoogleWorkspaceClient(object(), customer_id="C0123abc")
    client._services["admin", "reports_v1"] = SimpleNamespace(activities=lambda: service)
    client._services["cloudidentity", "v1", SSO_SCOPE] = SimpleNamespace(inboundSsoAssignments=lambda: service)
    return client


def _normalise(*results, directory=None):
    payloads = {result.name: result.payload for result in results}
    if directory is not None:
        payloads["google_directory"] = directory
    return build_google_normalized_snapshot(
        tenant_name="Example", run_id="r1",
        collector_payloads=payloads,
        result_rows=[{"name": result.name, "status": result.status} for result in results],
        coverage_rows=[row for result in results for row in result.coverage],
    )


def test_request_names_retention_and_event_minimisation():
    service = _Service({
        ("TOGGLE_CAA_ENABLEMENT", None): {"items": [_enable()]},
        ("DELETE_APPLICATION_SETTING", None): {"items": [_delete()]},
    })
    result = REGISTRY[EVENTS].run({"client": _client(service), "since": "2026-11-24", "until": "2026-11-25", "top": 1})
    assert result.status == "ok"
    assert [call["eventName"] for call in service.calls] == [
        "ALLOW_SERVICE_FOR_OAUTH2_ACCESS", "BLOCK_ALL_THIRD_PARTY_API_ACCESS", "CHANGE_APPLICATION_SETTING",
        "CHANGE_DOCS_SETTING", "CHANGE_EMAIL_SETTING", "CHANGE_GMAIL_SETTING", "CREATE_APPLICATION_SETTING",
        "DELETE_APPLICATION_SETTING", "DISALLOW_SERVICE_FOR_OAUTH2_ACCESS", "SIGN_IN_ONLY_THIRD_PARTY_API_ACCESS",
        "SYSTEM_DEFINED_RULE_UPDATED", "TOGGLE_CAA_ENABLEMENT", "TOGGLE_SERVICE_ENABLED",
        "TRUST_DOMAIN_OWNED_OAUTH2_APPS", "UNBLOCK_ALL_THIRD_PARTY_API_ACCESS", "UNTRUST_DOMAIN_OWNED_OAUTH2_APPS",
    ]
    assert all(call["applicationName"] == "admin" and call["userKey"] == "all" for call in service.calls)
    assert all({"startTime", "endTime"}.isdisjoint(call) and call["maxResults"] == 100 for call in service.calls)
    values = result.payload["settingEvents"]["value"]
    assert values[1] == {"id": {"time": "2026-11-23T00:02:28.672000091Z"}, "events": [
        {"name": "TOGGLE_CAA_ENABLEMENT", "parameters": [{"name": "NEW_VALUE", "value": "ENABLED"}]},
    ]}
    records = _normalise(result, directory={"orgUnits": {"value": [
        {"orgUnitId": "id:root", "orgUnitPath": "/", "name": "Example Root"},
    ]}})[EVENTS]["records"]
    assert [(row["event"], row.get("setting"), row.get("new_value"), row.get("org_unit")) for row in records[:-1]] == [
        ("DELETE_APPLICATION_SETTING", "ContentReportingProto one_on_one_reporting", None, "root"),
        ("TOGGLE_CAA_ENABLEMENT", None, "ENABLED", None),
    ]
    assert records[-1]["complete"] is True
    assert all(text not in json.dumps([result.payload, records]) for text in (
        "actor", "192.0.2.25", "C0123abc", "OLD_VALUE", "uniqueQualifier",
    ))


@pytest.mark.parametrize("ending", ["overflow", "failure", "malformed", "cycle", "empty"])
def test_event_limit_and_page_errors_are_carried_into_read_state(monkeypatch, ending):
    monkeypatch.setattr("auditex.google_workspace.client.SCUBA_EVENT_LIMIT", 2)
    last = {
        "overflow": {"items": [_enable()]},
        "failure": ValueError("untrusted error from https://example.org/customers/C0123abc"),
        "malformed": {"items": None},
        "cycle": {"nextPageToken": "second"},
        "empty": {},
    }[ending]
    event_name = "TOGGLE_CAA_ENABLEMENT"
    service = _Service({
        (event_name, None): {"items": [_enable(), _enable()], "nextPageToken": "first"},
        (event_name, "first"): {"nextPageToken": "second"},
        (event_name, "second"): last,
    })
    result = REGISTRY[EVENTS].run({"client": _client(service)})
    assert [call["pageToken"] for call in service.calls if call["eventName"] == event_name] == [None, "first", "second"]
    assert _normalise(result)[EVENTS]["records"][-1]["complete"] is (ending == "empty")
    assert result.status == ("ok" if ending == "empty" else "partial")
    assert "C0123abc" not in json.dumps([result.payload, result.coverage])


@pytest.mark.parametrize("timestamp", [None, 1, "", "2026-02-30T00:00:00Z", "2026-11-23T00:02:28"])
def test_unreadable_event_timestamp_is_incomplete(timestamp):
    event_name = "TOGGLE_CAA_ENABLEMENT"
    service = _Service({(event_name, None): {"items": [_activity(event_name, ("NEW_VALUE", "ENABLED"), timestamp=timestamp)]}})
    result = REGISTRY[EVENTS].run({"client": _client(service)})
    assert result.payload["settingEvents"]["value"] == []
    assert _normalise(result)[EVENTS]["records"][-1]["complete"] is False


@pytest.mark.parametrize("bad", [None, True, "", " ", "unreadable", "true ", "https://example.org/private"])
def test_unreadable_event_values_are_incomplete(bad):
    event_name = "CHANGE_APPLICATION_SETTING"
    item = _activity(event_name, ("SETTING_NAME", SETTING), ("NEW_VALUE", bad), ("ORG_UNIT_NAME", "Example Root"))
    service = _Service({(event_name, None): {"items": [item]}})
    result = REGISTRY[EVENTS].run({"client": _client(service)})
    assert result.payload["settingEvents"]["value"] == []
    assert _normalise(result)[EVENTS]["records"][-1]["complete"] is False


@pytest.mark.parametrize("event_name", ["CHANGE_APPLICATION_SETTING", "CHANGE_EMAIL_SETTING"])
@pytest.mark.parametrize("new_value", ["", "x" * 2049])
def test_unrelated_setting_change_does_not_make_covered_settings_unreadable(event_name, new_value):
    item = _activity(event_name, ("SETTING_NAME", "Attachment safety Enable: a different setting"),
                     ("NEW_VALUE", new_value))
    service = _Service({(event_name, None): {"items": [item]}, ("TOGGLE_CAA_ENABLEMENT", None): {"items": [_enable()]}})
    result = REGISTRY[EVENTS].run({"client": _client(service)})
    records = _normalise(result)[EVENTS]["records"]
    assert [(record["event"], record.get("setting"), record.get("new_value")) for record in records[:-1]] == [
        (event_name, "unrecognised", None), ("TOGGLE_CAA_ENABLEMENT", None, "ENABLED"),
    ]
    assert records[-1]["complete"] is True


def test_ordinary_ou_label_with_a_colon_is_retained():
    event_name = "DELETE_APPLICATION_SETTING"
    item = _activity(event_name, ("SETTING_NAME", SETTING), ("ORG_UNIT_NAME", "Sales: EMEA"))
    service = _Service({(event_name, None): {"items": [item]}})
    result = REGISTRY[EVENTS].run({"client": _client(service)})
    directory = {"orgUnits": {"value": [{"orgUnitId": "id:root", "orgUnitPath": "/", "name": "Sales: EMEA"}]}}
    event, read_state = _normalise(result, directory=directory)[EVENTS]["records"]
    assert event["org_unit"] == "root"
    assert "Sales: EMEA" in json.dumps(result.payload) and "Sales: EMEA" not in json.dumps(event)
    assert read_state["complete"] is True


def test_ambiguous_and_cut_ou_targets_never_become_root_evidence():
    event_name = "DELETE_APPLICATION_SETTING"
    activities = [_activity(event_name, ("SETTING_NAME", SETTING), ("ORG_UNIT_NAME", label))
                  for label in ("Shared", "/A/Shared", "/")]
    service = _Service({(event_name, None): {"items": activities}})
    result = REGISTRY[EVENTS].run({"client": _client(service)})
    directory = {"orgUnits": {"value": [
        {"orgUnitId": "id:root", "orgUnitPath": "/", "name": "Example Root"},
        {"orgUnitId": "id:a", "orgUnitPath": "/A", "name": "A", "parentOrgUnitId": "id:root", "parentOrgUnitPath": "/"},
        {"orgUnitId": "id:b", "orgUnitPath": "/B", "name": "B", "parentOrgUnitId": "id:root", "parentOrgUnitPath": "/"},
        {"orgUnitId": "id:a1", "orgUnitPath": "/A/Shared", "name": "Shared", "parentOrgUnitId": "id:a"},
        {"orgUnitId": "id:b1", "orgUnitPath": "/B/Shared", "name": "Shared", "parentOrgUnitId": "id:b"},
    ]}}
    records = _normalise(result, directory=directory)[EVENTS]["records"]
    assert [record.get("org_unit") for record in records[:-1]] == [None, "a1", "root"]
    directory["orgUnits"]["value"].append({"orgUnitId": "id:root", "orgUnitPath": "/", "name": "Other Root"})
    records = _normalise(result, directory=directory)[EVENTS]["records"]
    assert [record.get("org_unit") for record in records[:-1]] == [None, None, None]
    directory["orgUnits"]["value"].pop()
    directory["orgUnits"]["collection_truncated"] = True
    records = _normalise(result, directory=directory)[EVENTS]["records"]
    assert [record.get("org_unit") for record in records[:-1]] == [None, None, None]


@pytest.mark.parametrize(("field", "label"), [
    ("ORG_UNIT_NAME", "/".join(("", "private", "tmp", "example"))),
    ("ORG_UNIT_NAME", "Example OU https://example.org/private"),
    ("ORG_UNIT_NAME", "Example OU C0123abc"),
    ("GROUP_EMAIL", "C0123abc@example.org"),
])
def test_event_targets_cannot_carry_paths_urls_or_customer_ids(field, label):
    event_name = "DELETE_APPLICATION_SETTING"
    item = _activity(event_name, ("SETTING_NAME", SETTING), (field, label))
    service = _Service({(event_name, None): {"items": [item]}})
    result = REGISTRY[EVENTS].run({"client": _client(service)})
    records = _normalise(result)[EVENTS]["records"]
    assert label not in json.dumps([result.payload, records, result.coverage])
    assert records[-1]["complete"] is False


@pytest.mark.parametrize("assignment", [
    {}, {"targetOrgUnit": "orgUnits/root"}, {"targetOrgUnit": "orgUnits/root", "ssoMode": None},
    {"targetOrgUnit": "orgUnits/root", "ssoMode": False}, {"targetOrgUnit": "orgUnits/root", "ssoMode": ""},
    {"targetOrgUnit": "orgUnits/root", "ssoMode": "SSO_MODE_UNSPECIFIED"},
    {"ssoMode": "SSO_OFF"}, {"targetOrgUnit": None, "ssoMode": "SSO_OFF"},
    {"targetOrgUnit": 7, "ssoMode": "SSO_OFF"}, {"targetOrgUnit": "", "ssoMode": "SSO_OFF"},
    {"targetOrgUnit": "ou:root", "ssoMode": "SSO_OFF"},
    {"targetGroup": "groups/C0123abc@example.org", "ssoMode": "SSO_OFF"},
    {"targetGroup": "groups/g1", "targetOrgUnit": "orgUnits/root", "ssoMode": "SSO_OFF"},
])
def test_unreadable_sso_rows_cannot_be_an_empty_complete_assignment_list(assignment):
    service = _Service({(None, None): {"inboundSsoAssignments": [assignment]}})
    result = REGISTRY[SSO].run({"client": _client(service)})
    assert result.status == "partial"
    assert _normalise(result)[SSO]["records"][-1]["complete"] is False


def test_sso_paging_filter_and_field_minimisation():
    service = _Service({
        (None, None): {"nextPageToken": "second"},
        (None, "second"): {"inboundSsoAssignments": [
            {"targetOrgUnit": "orgUnits/root", "ssoMode": "SSO_OFF", "name": "assignment-private"},
            {"targetGroup": "groups/security-admins@example.org", "ssoMode": "SAML_SSO", "samlSsoInfo": {"profile": "private"}},
        ]},
    })
    result = REGISTRY[SSO].run({"client": _client(service), "top": 1})
    assert [call["filter"] for call in service.calls] == ['customer=="customers/C0123abc"'] * 2
    assert result.payload == {"inboundSsoAssignments": {"value": [
        {"targetOrgUnit": "orgUnits/root", "ssoMode": "SSO_OFF"},
        {"targetGroup": "groups/security-admins@example.org", "ssoMode": "SAML_SSO"},
    ]}}
    records = _normalise(result)[SSO]["records"]
    assert [(row.get("target_org_unit"), row.get("target_group"), row["sso_mode"]) for row in records[:-1]] == [
        ("orgUnits/root", None, "SSO_OFF"), (None, "groups/security-admins@example.org", "SAML_SSO"),
    ]
    assert records[-1]["complete"] is True


def test_sso_scope_isolated_from_policies_and_probe_names_the_missing_scope(monkeypatch):
    built = []

    class Credentials:
        def __init__(self, scopes=()):
            self.scopes = tuple(scopes)

        def with_scopes(self, scopes):
            return Credentials(scopes)

        def refresh(self, _request):
            if self.scopes == (SSO_SCOPE,):
                raise ValueError("unauthorized_client with private response details")

    def build(api, version, *, credentials, cache_discovery):
        built.append((api, version, credentials.scopes))
        if credentials.scopes == (SSO_SCOPE,):
            service = _Service({(None, None): ValueError("unauthorized_client with private response details")})
            return SimpleNamespace(inboundSsoAssignments=lambda: service)
        if api == "admin":
            return SimpleNamespace(activities=lambda: _Service({}))
        return SimpleNamespace(policies=lambda: _Service({(None, None): {"policies": [{"setting": {}}]}}))

    monkeypatch.setattr("googleapiclient.discovery.build", build)
    client = GoogleWorkspaceClient(Credentials())
    client.list_policies()
    preflight = build_google_preflight_rows(client, [SSO, EVENTS], domain=None)
    assert [(row["name"], row["status"], row.get("missing_permissions")) for row in preflight] == [
        ("inboundSsoAssignments", "failed", [SSO_SCOPE]), ("settingEvents", "ok", None),
    ]
    assert built == [
        ("cloudidentity", "v1", (POLICY_SCOPE,)), ("cloudidentity", "v1", (SSO_SCOPE,)),
        ("admin", "reports_v1", (REPORTS_SCOPE,)),
    ]
    assert "private response details" not in json.dumps(preflight)
    assert ISOLATED_GOOGLE_SCOPES == {POLICY_SCOPE, SSO_SCOPE}


def test_scope_catalogue_setup_guide_and_presets():
    catalog = build_google_scope_catalog()
    assert catalog[SSO]["required_permissions"] == [SSO_SCOPE]
    assert catalog[SSO]["scope_warnings"][0]["risk"] == "read_only"
    assert catalog[SSO]["api_enablement"] == catalog["google_policies"]["api_enablement"] == ["Cloud Identity API"]
    for preset in ("identity", "core-security"):
        assert {SSO, EVENTS}.issubset(PRESETS[preset])
        setup = build_setup_guide(provider="google", collector_preset=preset)
        assert SSO_SCOPE in setup["scopes_csv"].split(",")
    docs = Path("docs/guides/admin-permission-guide.md").read_text()
    assert SSO_SCOPE in next(line.split(",") for line in docs.splitlines() if line.startswith("https://www.googleapis.com/auth/"))


def test_offline_bundle_reapplies_minimisation_and_records_invalid_sections(tmp_path):
    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps({
        EVENTS: {"settingEvents": {"value": [_enable(), _delete()], "actor": "actor@example.com"}},
        SSO: {"inboundSsoAssignments": {"value": [{"targetOrgUnit": "orgUnits/root", "ssoMode": None}],
                                        "error": "private failure https://example.org/customers/C0123abc"}},
    }))
    out = tmp_path / "out"
    assert run_google_offline(
        sample_path=sample, tenant_name="Example", out=out, run_name=None, domain=None, customer_id=None,
    ) == 1
    run_dir = next(out.iterdir())
    for name in (EVENTS, SSO):
        for section in ("raw", "normalized"):
            text = (run_dir / section / f"{name}.json").read_text()
            assert all(secret not in text for secret in ("actor@example.com", "192.0.2.25", "C0123abc", "private failure"))
    assert json.loads((run_dir / "normalized/google_setting_events.json").read_text())["records"][-1]["complete"] is True
    assert json.loads((run_dir / "normalized/google_sso_assignments.json").read_text())["records"][-1]["complete"] is False
