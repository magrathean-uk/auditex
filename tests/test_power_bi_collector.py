from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from azure_tenant_audit.collectors.power_bi import TENANT_SETTINGS, PowerBICollector
from azure_tenant_audit.scuba_assessment import COLLECTOR_ERROR_CLASSES
from azure_tenant_audit.power_bi import POWERBI_SCOPE, PowerBIClient, PowerBIError, power_bi_client_from
from azure_tenant_audit.profiles import PROFILES

CANARY = "synthetic-powerbi-token-canary-never-retain"
GROUP = "11111111-2222-3333-4444-555555555555"
SETTINGS = ["PublishToWeb", "AllowGuestUserToAccessSharedContent", "ExternalSharingV2", "ServicePrincipalAccessPermissionAPIs",
            "AllowServicePrincipalsCreateAndUseProfiles", "BlockResourceKeyAuthentication", "RScriptVisual", "EimInformationProtectionEdit"]


@pytest.fixture(autouse=True)
def _forbid_real_http(monkeypatch):
    attempted = []
    def blocked(*args, **kwargs):
        attempted.append(True)
        raise AssertionError("real HTTP transport forbidden in collector tests")
    monkeypatch.setattr("requests.sessions.Session.request", blocked)
    yield
    assert not attempted, "a test reached real HTTP transport"


class _FakePowerBIClient:
    token = CANARY
    last_status = 200

    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, path):
        self.calls.append(("GET", path))
        self.last_status = None
        if isinstance(self.response, Exception):
            raise self.response
        self.last_status = 200
        return self.response


def _run(client, **context):
    return PowerBICollector().run({"power_bi_client": client, **context})


def _coverage(result):
    return {row["name"]: row for row in result.coverage}


def _assert_retention(value):
    if isinstance(value, dict):
        assert not {"raw", "title", "properties", "tenantSettingGroup", "canSpecifySecurityGroups", "name"} & value.keys()
        for item in value.values():
            _assert_retention(item)
    elif isinstance(value, list):
        for item in value:
            _assert_retention(item)
    elif isinstance(value, str):
        assert not re.search(r"[^\s@]+@[^\s@]+\.[^\s@]+", value)


def test_exact_tenant_settings_for_all_eight_rule_names_and_retention():
    client = _FakePowerBIClient({"tenantSettings": [{
        "settingName": name, "enabled": False,
        "enabledSecurityGroups": [{"graphId": GROUP, "name": "drop@example.test"}],
        "title": "drop@example.test", "tenantSettingGroup": "drop@example.test",
        "properties": [{"name": "drop@example.test", "value": "drop@example.test"}],
        "canSpecifySecurityGroups": True,
    } for name in SETTINGS], "title": "drop@example.test"})
    result = _run(client)
    assert result.status == "ok"
    assert result.payload["tenantSettings"] == {"status": "ok", "value": [
        {"settingName": name, "enabled": False, "enabledSecurityGroups": [{"graphId": GROUP}]} for name in SETTINGS
    ]}
    assert result.payload["accessState"] == {"status": "ok", "value": [{"denied": False, "http_status": 200}]}
    assert client.calls == [("GET", TENANT_SETTINGS)]
    assert all(row["status"] == "ok" and row["type"] == "powerbi" for row in result.coverage)
    _assert_retention(result.payload)


@pytest.mark.parametrize("item,expected", [
    ({}, {}), ({"enabled": "false"}, {"enabled": "false"}),
    ({"settingName": None, "enabled": 0}, {"settingName": None, "enabled": 0}),
    ({"enabledSecurityGroups": [{"graphId": None, "name": "drop@example.test"}, {"name": "drop@example.test"}, None, "invalid", 1]},
     {"enabledSecurityGroups": [{"graphId": None}, {}, None, "invalid", 1]}),
    ({"enabledSecurityGroups": "invalid"}, {"enabledSecurityGroups": "invalid"}),
    ({"enabledSecurityGroups": None}, {"enabledSecurityGroups": None}),
    ({"enabledSecurityGroups": {"x": 1}}, {"enabledSecurityGroups": {"x": 1}}),
])
def test_setting_keys_types_and_group_elements_are_verbatim(item, expected):
    result = _run(_FakePowerBIClient({"tenantSettings": [item]}))
    assert result.payload["tenantSettings"]["value"] == [expected]
    _assert_retention(result.payload)


@pytest.mark.parametrize("raw", [{}, {"tenantSettings": []}, {"tenantSettings": None}, {"tenantSettings": {}},
                                {"tenantSettings": [None]}, None])
def test_missing_empty_or_unusable_list_is_failed_read(raw):
    result = _run(_FakePowerBIClient(raw))
    assert result.status == "partial"
    assert result.payload["tenantSettings"]["value"] == []
    row = _coverage(result)["tenantSettings"]
    assert row["status"] == "failed" and row["error_class"] == "incomplete_evidence"
    assert result.payload["accessState"]["value"] == [{"denied": False, "http_status": 200}]


@pytest.mark.parametrize("http,expected", [(401, "insufficient_permissions"), (403, "insufficient_permissions"),
    (404, "service_not_available"), (410, "service_not_available"), (429, "service_not_available"),
    (500, "service_not_available"), (599, "service_not_available"), (400, "client_error"), (None, "client_error")])
def test_http_and_transport_errors_with_access_state_and_canary(http, expected):
    failure = PowerBIError(CANARY, status=http) if http else RuntimeError(CANARY)
    events = []
    result = _run(_FakePowerBIClient(failure), audit_logger=lambda *args: events.append(args))
    row = _coverage(result)["tenantSettings"]
    assert row["status"] == "failed" and row["error_class"] == expected
    assert row["error_class"] in COLLECTOR_ERROR_CLASSES
    assert result.payload["tenantSettings"]["value"] == []
    assert result.payload["accessState"]["value"] == [{"denied": http in (401, 403), "http_status": http}]
    assert _coverage(result)["accessState"]["status"] == "ok"
    assert CANARY not in json.dumps([result.payload, result.coverage, events])


@pytest.mark.parametrize("context", [{}, {"power_bi_client": None}, {"power_bi_client": PowerBIClient()}])
def test_no_client_or_token_skips_both_operations(context):
    result = PowerBICollector().run(context)
    assert result.status == "partial"
    assert result.payload == {"tenantSettings": {"value": [], "status": "skipped"}, "accessState": {"value": [], "status": "skipped"}}
    assert len(result.coverage) == 2
    assert all(row["status"] == "skipped" and row["error_class"] == "service_not_available" for row in result.coverage)


class _Response:
    def __init__(self, raw=None, status=200):
        self.raw, self.status_code = raw, status

    def json(self):
        if isinstance(self.raw, Exception):
            raise self.raw
        return self.raw


class _Session:
    def __init__(self, response):
        self.response, self.calls = response, []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def test_client_get_is_header_only_and_uses_commercial_root():
    session = _Session(_Response({"tenantSettings": [{"settingName": "PublishToWeb", "enabled": False}]}))
    client = PowerBIClient(token=CANARY, session=session)
    result = _run(client)
    assert result.status == "ok"
    assert session.calls == [("GET", "https://api.powerbi.com/v1/admin/tenantsettings", {
        "headers": {"Authorization": "Bearer " + CANARY, "accept": "application/json"},
        "timeout": 15.0, "allow_redirects": False,
    })]
    assert result.payload["accessState"]["value"] == [{"denied": False, "http_status": 200}]
    assert CANARY not in repr(client)


@pytest.mark.parametrize("response,expected_status", [
    (RuntimeError("Authorization: Bearer " + CANARY), None), (_Response(ValueError(CANARY)), 200),
    (_Response({"title": CANARY}, 401), 401), (_Response({"title": CANARY}, 403), 403),
    (_Response({"title": CANARY}, 500), 500), (_Response({}, 302), 302),
])
def test_client_errors_do_not_leak_token(response, expected_status):
    client = PowerBIClient(token=CANARY, session=_Session(response))
    with pytest.raises(PowerBIError) as error:
        client.get(TENANT_SETTINGS)
    assert CANARY not in str(error.value)
    assert error.value.status == expected_status
    result = _run(client)
    assert CANARY not in json.dumps([result.payload, result.coverage])
    assert result.payload["accessState"]["value"] == [{"denied": expected_status in (401, 403), "http_status": expected_status}]


@pytest.mark.parametrize("path", ["https://untrusted.invalid/next", "//untrusted.invalid/next", "http://api.powerbi.com/next",
    "https://api.powerbi.com:444/next", "https://user@api.powerbi.com/next", "/path?token=" + CANARY])
def test_client_refuses_unsafe_url_without_sending_token(path):
    session = _Session(_Response({}))
    with pytest.raises(PowerBIError) as error:
        PowerBIClient(token=CANARY, session=session).get(path)
    assert session.calls == [] and CANARY not in str(error.value)


@pytest.mark.parametrize("token", [None, CANARY])
def test_app_token_resolution_and_collector_local_client_creation(monkeypatch, token):
    class _Graph:
        def __init__(self):
            self.scopes = []

        def app_token_for(self, scope):
            self.scopes.append(scope)
            return token
    graph = _Graph()
    session = _Session(_Response({"tenantSettings": [{"settingName": "PublishToWeb", "enabled": False}]}))
    monkeypatch.setattr("azure_tenant_audit.power_bi.PowerBIClient", lambda *, token: PowerBIClient(token=token, session=session))
    client = power_bi_client_from({"client": graph})
    assert (client is None) is (token is None)
    assert graph.scopes == [POWERBI_SCOPE]
    assert POWERBI_SCOPE == "https://analysis.windows.net/powerbi/api/.default"
    result = PowerBICollector().run({"client": graph})
    assert result.status == ("partial" if token is None else "ok")
    assert len(session.calls) == (0 if token is None else 1)
    injected = _FakePowerBIClient({"tenantSettings": [{}]})
    assert power_bi_client_from({"client": graph, "power_bi_client": injected}) is injected
    assert power_bi_client_from({"client": graph, "power_bi_client": None}) is None


def test_collectors_stay_disabled_and_absent_from_default_presets():
    definitions = json.loads(Path("configs/collector-definitions.json").read_text())["collectors"]
    optional = {"power_platform", "power_bi"}
    for name in optional:
        assert definitions[name]["enabled"] is False, name
    presets = json.loads(Path("configs/collector-presets.json").read_text())["presets"]
    assert optional <= set(presets["power-platform"]["include"])
    assert optional.isdisjoint(presets["power-platform"]["exclude"])
    assert optional.isdisjoint(presets["full"]["include"])
    for name, preset in presets.items():
        if name != "power-platform":
            assert optional.isdisjoint(preset["include"]), name
            assert optional.isdisjoint(preset["exclude"]), name
    for name, profile in PROFILES.items():
        assert optional.isdisjoint(profile.default_collectors), name
