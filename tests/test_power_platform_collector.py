from __future__ import annotations

import json
import re
from typing import Any

import pytest

from azure_tenant_audit.collectors import power_platform as module
from azure_tenant_audit.collectors.power_platform import PowerPlatformCollector
from azure_tenant_audit.normalize import build_normalized_snapshot
from azure_tenant_audit.power_platform import (
    BAP_SCOPE,
    PowerPlatformClient,
    PowerPlatformError,
    power_platform_client_from,
)
from azure_tenant_audit.scuba_assessment import COLLECTOR_ERROR_CLASSES

TENANT_ID = "11111111-2222-3333-4444-555555555555"
CANARY = "synthetic-token-canary-never-retain"


@pytest.fixture(autouse=True)
def _forbid_real_http(monkeypatch):
    attempted = []
    def blocked(*args, **kwargs):
        attempted.append(True)
        raise AssertionError("real HTTP transport forbidden in collector tests")
    monkeypatch.setattr("requests.sessions.Session.request", blocked)
    yield
    assert not attempted, "a test reached real HTTP transport"


class _Graph:
    def __init__(self, rows: Any = None, token: str | None = None):
        self.rows = [{"id": TENANT_ID}] if rows is None else rows
        self.token = token
        self.calls = []
        self.scopes = []

    def get_all(self, path, *, params):
        self.calls.append((path, params))
        return self.rows

    def app_token_for(self, scope):
        self.scopes.append(scope)
        return self.token


class _FakeBapClient:
    token = CANARY

    def __init__(self, *, environments=None, dlp_policies=None, tenant_settings=None, scopes=None, isolation=None):
        self.responses = {
            module.ENVIRONMENTS: {"value": environments or []},
            module.DLP_POLICIES: {"value": dlp_policies or []},
            module.TENANT_SETTINGS: tenant_settings if tenant_settings is not None else {},
            module.DLP_SCOPES: {"value": scopes or []},
            module.TENANT_ISOLATION.replace("{TenantId}", TENANT_ID): isolation,
        }
        self.calls = []

    def get(self, path, *, api_version=None):
        self.calls.append(("GET", path))
        response = self.responses[path]
        if isinstance(response, Exception):
            raise response
        return response

    def request(self, method, path):
        assert method == "GET"
        return self.get(path)


def _run(bap=None, **kwargs):
    return PowerPlatformCollector().run({"power_platform_client": bap, "client": _Graph(), **kwargs})


def _coverage(result):
    return {row["name"]: row for row in result.coverage}


def _assert_retention(value):
    if isinstance(value, dict):
        assert not {"linked_environment_metadata", "linkedEnvironmentMetadata", "raw", "title", "connectorGroups", "definition"} & value.keys()
        if "properties" in value:
            assert isinstance(value["properties"], dict)
            assert set(value["properties"]) <= {"isDisabled"}
        for item in value.values():
            _assert_retention(item)
    elif isinstance(value, list):
        for item in value:
            _assert_retention(item)
    elif isinstance(value, str):
        assert not re.search(r"[^\s@]+@[^\s@]+\.[^\s@]+", value)


def test_collector_returns_environments_and_dlp_policies():
    client = _FakeBapClient(
        environments=[{"name": "default", "properties": {
            "displayName": "drop@example.test", "environmentSku": "Default", "isDefault": True,
            "createdTime": "2024-01-01T00:00:00Z", "linkedEnvironmentMetadata": {"name": "drop@example.test"},
        }}],
        dlp_policies=[{"name": "policy-1", "displayName": "Tenant DLP", "environmentType": "AllEnvironments", "connectorGroups": [
            {"classification": "Business", "connectors": [{"name": "shared_office365"}]},
            {"classification": "NonBusiness", "connectors": []},
            {"classification": "Blocked", "connectors": [{"name": "shared_twitter"}]},
        ]}],
        tenant_settings={"isPowerAppsEnabled": True, "isPowerAutomateEnabled": False, "isDataverseEnabled": None,
                         "raw": "drop@example.test", "disableEnvironmentCreationByNonAdminUsers": True,
                         "disableTrialEnvironmentCreationByNonAdminUsers": "false", "disablePortalsCreationByNonAdminUsers": 1,
                         "powerPlatform": {"powerApps": {"disableShareWithEveryone": None, "title": "drop@example.test"}}},
        isolation={"properties": {"isDisabled": False, "title": "drop@example.test"}},
    )
    result = _run(client)
    assert result.status == "ok"
    assert result.payload["environments"]["value"] == [{
        "id": "default", "name": "default", "environment_sku": "Default",
        "is_default": True, "created_time": "2024-01-01T00:00:00Z",
    }]
    assert result.payload["dlpPolicies"]["value"] == [{
        "id": "policy-1", "display_name": "Tenant DLP", "environment_type": "AllEnvironments",
        "business_connector_count": 1, "non_business_connector_count": 0, "blocked_connector_count": 1,
    }]
    assert result.payload["tenantSettings"]["value"] == [{
        "is_power_apps_enabled": True, "is_power_automate_enabled": False, "is_dataverse_enabled": None,
    }]
    assert result.payload["environmentCreation"]["value"] == [{
        "disableEnvironmentCreationByNonAdminUsers": True, "disableTrialEnvironmentCreationByNonAdminUsers": "false",
        "disablePortalsCreationByNonAdminUsers": 1, "powerPlatform": {"powerApps": {"disableShareWithEveryone": None}},
    }]
    assert result.payload["dlpPolicyScopes"]["value"] == []
    assert result.payload["tenantIsolation"]["value"] == [{"properties": {"isDisabled": False}}]
    assert all(envelope["status"] == "ok" for envelope in result.payload.values())
    assert client.calls.count(("GET", module.TENANT_SETTINGS)) == 1
    assert module.TENANT_SETTINGS_METHOD == "GET"
    assert len(client.calls) == 5 and all(method == "GET" for method, _ in client.calls)
    assert all("api-version=" in row["endpoint"] for row in result.coverage)
    assert _coverage(result)["tenantIsolation"]["endpoint"] == module.TENANT_ISOLATION
    assert TENANT_ID not in json.dumps(result.coverage)
    assert ("GET", module.TENANT_ISOLATION.replace("{TenantId}", TENANT_ID)) in client.calls
    _assert_retention(result.payload)


@pytest.mark.parametrize("constraint,expected", [
    (None, {"environmentType": "AllEnvironments", "environments": []}),
    ({"parameters": {"filterType": "include", "environments": [{"name": "env", "id": "drop@example.test"}, {}, "invalid", None]}},
     {"environmentType": "OnlyEnvironments", "environments": [{"name": "env"}, {}, "invalid", None]}),
    ({"parameters": {"filterType": "exclude", "environments": []}}, {"environmentType": "ExceptEnvironments", "environments": []}),
    ({"parameters": {"filterType": "odd", "environments": [{"name": "env"}]}}, {"environmentType": None, "environments": [{"name": "env"}]}),
    ({"parameters": {}}, {"environmentType": None}),
    ({"parameters": {"filterType": []}}, {"environmentType": None}),
])
def test_dlp_scope_exact_shapes(constraint, expected):
    policy = {"name": "policy", "properties": {"displayName": "Policy", "definition": {
        "constraints": {"environmentFilter1": constraint}, "connectorGroups": "drop@example.test",
    }}}
    result = _run(_FakeBapClient(scopes=[policy, {}]))
    assert result.payload["dlpPolicyScopes"]["value"] == [
        {"name": "policy", "displayName": "Policy", **expected},
        {"environmentType": "AllEnvironments", "environments": []},
    ]
    _assert_retention(result.payload)


@pytest.mark.parametrize("filter_type", ["Include", "INCLUDE", "Exclude", "EXCLUDE"])
def test_dlp_scope_filter_type_is_case_insensitive(filter_type):
    policy = {"properties": {"definition": {"constraints": {
        "environmentFilter1": {"parameters": {"filterType": filter_type, "environments": []}},
    }}}}
    result = _run(_FakeBapClient(scopes=[policy]))
    expected = "OnlyEnvironments" if filter_type.lower() == "include" else "ExceptEnvironments"
    assert result.payload["dlpPolicyScopes"] == {
        "status": "ok", "value": [{"environmentType": expected, "environments": []}],
    }


@pytest.mark.parametrize("raw,expected", [
    ({}, {}), ({"powerPlatform": {}}, {}), ({"powerPlatform": {"powerApps": {}}}, {}),
    ({"powerPlatform": {"powerApps": {"disableShareWithEveryone": [False]}}},
     {"powerPlatform": {"powerApps": {"disableShareWithEveryone": [False]}}}),
    ({"disableEnvironmentCreationByNonAdminUsers": {"x": 1}}, {"disableEnvironmentCreationByNonAdminUsers": {"x": 1}}),
])
def test_creation_only_retains_recognised_present_paths(raw, expected):
    assert _run(_FakeBapClient(tenant_settings=raw)).payload["environmentCreation"]["value"] == [expected]


@pytest.mark.parametrize("context", [{}, {"power_platform_client": None}, {"client": _Graph()},
                                      {"power_platform_client": PowerPlatformClient()}])
def test_collector_marks_capability_unavailable_when_token_missing(context):
    result = PowerPlatformCollector().run(context)
    assert result.status == "partial"
    assert set(result.payload) == set(module.OPERATIONS)
    assert all(envelope["value"] == [] for envelope in result.payload.values())
    assert len(result.coverage) == 6
    assert all(row["status"] == "skipped" and row["error_class"] == "service_not_available" for row in result.coverage)


@pytest.mark.parametrize("http,expected", [(401, "insufficient_permissions"), (403, "insufficient_permissions"),
    (404, "service_not_available"), (410, "service_not_available"), (429, "service_not_available"),
    (500, "service_not_available"), (503, "service_not_available"), (405, "client_error"), (None, "client_error")])
@pytest.mark.parametrize("operation", list(module.OPERATIONS))
def test_failed_read_has_empty_envelope_and_honest_coverage(http, expected, operation):
    client = _FakeBapClient()
    path = module.OPERATIONS[operation].replace("{TenantId}", TENANT_ID)
    client.responses[path] = PowerPlatformError(CANARY, status=http) if http else RuntimeError(CANARY)
    events = []
    result = _run(client, audit_logger=lambda *args: events.append(args))
    row = _coverage(result)[operation]
    assert row["status"] == "failed" and row["error_class"] == expected
    assert row["error_class"] in COLLECTOR_ERROR_CLASSES
    assert result.payload[operation]["value"] == []
    assert CANARY not in json.dumps([result.payload, result.coverage, events])


def test_collector_handles_no_environments_gracefully():
    result = _run(_FakeBapClient())
    assert result.status == "ok"
    assert result.payload["environments"]["value"] == []
    assert result.payload["dlpPolicies"]["value"] == []


@pytest.mark.parametrize("operation", ["environments", "dlpPolicies", "dlpPolicyScopes"])
def test_off_host_next_link_is_refused_and_marked_cut(operation):
    client = _FakeBapClient()
    client.responses[module.OPERATIONS[operation]] = {"value": [{"name": "first"}], "nextLink": "https://untrusted.invalid/?token=" + CANARY}
    result = _run(client)
    row = _coverage(result)[operation]
    assert row["status"] == "failed" and row["error_class"] == "client_error"
    assert row["collection_truncated"] is True and row["truncation_reason"] == "pagination_failed"
    assert result.payload[operation]["collection_truncated"] is True
    assert len(result.payload[operation]["value"]) == 1
    assert not any("untrusted" in path for _, path in client.calls)
    assert CANARY not in json.dumps([result.payload, result.coverage])


@pytest.mark.parametrize("raw,expected", [
    ({"properties": {"isDisabled": "false", "title": "drop@example.test"}}, [{"properties": {"isDisabled": "false"}}]),
    ({"properties": {"isDisabled": None}}, [{"properties": {"isDisabled": None}}]),
    ({}, [{"properties": {}}]), (None, [{"never_configured": True}]),
])
def test_tenant_isolation_shapes(raw, expected):
    graph = _Graph()
    result = _run(_FakeBapClient(isolation=raw), client=graph)
    assert result.payload["tenantIsolation"]["value"] == expected
    assert graph.calls == [("/organization", {"$select": "id"})]


@pytest.mark.parametrize("rows", [[], [{}], [{"id": "not-a-guid"}], [{"id": TENANT_ID.replace('-', '')}],
                                    [{"id": TENANT_ID + '/extra'}], [{"id": TENANT_ID}, {"id": TENANT_ID}]])
def test_tenant_isolation_requires_canonical_guid(rows):
    client = _FakeBapClient()
    result = _run(client, client=_Graph(rows=rows))
    assert not any("tenantIsolationPolicy" in path for _, path in client.calls)
    assert _coverage(result)["tenantIsolation"]["error_class"] == "missing_argument"
    assert result.payload["tenantIsolation"]["value"] == []


@pytest.mark.parametrize("present,value", [(False, None), (True, None), (True, False), (True, "false"), (True, 0)])
def test_is_default_is_verbatim_in_collection_and_normalisation(present, value):
    properties = {"isDefault": value} if present else {}
    result = _run(_FakeBapClient(environments=[{"name": "env", "properties": properties}]))
    assert result.payload["environments"]["value"][0]["is_default"] == value
    snapshot = build_normalized_snapshot(tenant_name="fixture", run_id="fixture", collector_payloads={"power_platform": result.payload})
    record = snapshot["power_platform_environment_objects"]["records"][0]
    assert record["is_default"] == value
    assert type(record["is_default"]) is type(value)


def test_normalisation_drops_legacy_raw_tenant_settings():
    snapshot = build_normalized_snapshot(tenant_name="fixture", run_id="fixture", collector_payloads={"power_platform": {
        "tenantSettings": {"value": [{"is_power_apps_enabled": False, "raw": {"title": "drop@example.test"}, "title": "drop"}]},
    }})
    record = snapshot["power_platform_tenant_setting_objects"]["records"][0]
    assert record["is_power_apps_enabled"] is False
    assert "raw" not in record and "title" not in record


def test_app_token_resolution_and_injected_client_precedence():
    graph = _Graph(token=CANARY)
    client = power_platform_client_from({"client": graph})
    assert client.token == CANARY and graph.scopes == [BAP_SCOPE]
    assert BAP_SCOPE == "https://service.powerapps.com//.default"
    injected = _FakeBapClient()
    assert power_platform_client_from({"client": graph, "power_platform_client": injected}) is injected
    assert power_platform_client_from({"client": graph, "power_platform_client": None}) is None
    assert graph.scopes == [BAP_SCOPE]


class _Response:
    def __init__(self, raw=None, *, status=200, content=b"{}"):
        self.raw, self.status_code, self.content = raw, status, content

    def json(self):
        if isinstance(self.raw, Exception):
            raise self.raw
        return self.raw


class _Session:
    def __init__(self, response):
        self.response, self.calls = response, []

    def request(self, method, url, **kwargs):
        assert method == "GET"
        self.calls.append((method, url, kwargs))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def test_client_get_method_api_version_and_header_only_token():
    session = _Session(_Response({"value": []}))
    client = PowerPlatformClient(token=CANARY, session=session)
    assert client.get("/metadata", api_version="2023-06-01") == {"value": []}
    method, url, kwargs = session.calls[0]
    assert method == "GET" and url == "https://api.bap.microsoft.com/metadata"
    assert kwargs == {"params": {"api-version": "2023-06-01"}, "headers": {
        "Authorization": "Bearer " + CANARY, "accept": "application/json"}, "timeout": 15.0, "allow_redirects": False}
    client.get(module.DLP_SCOPES)
    assert session.calls[-1][2]["params"] is None
    assert CANARY not in repr(client)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "get"])
@pytest.mark.parametrize("token", [None, CANARY])
def test_client_refuses_non_get_methods_before_touching_session(method, token):
    class _UntouchedSession:
        def __getattribute__(self, name):
            raise AssertionError("refused method touched the session")

    client = PowerPlatformClient(token=token, session=_UntouchedSession())
    with pytest.raises(PowerPlatformError, match="^method refused$"):
        client.request(method, module.TENANT_SETTINGS)


@pytest.mark.parametrize("path", ["https://untrusted.invalid/next", "//untrusted.invalid/next", "http://api.bap.microsoft.com/next",
    "https://api.bap.microsoft.com:444/next", "https://user@api.bap.microsoft.com/next", "/path?token=" + CANARY])
def test_client_refuses_unsafe_urls_before_sending_token(path):
    session = _Session(_Response({}))
    with pytest.raises(PowerPlatformError) as error:
        PowerPlatformClient(token=CANARY, session=session).get(path)
    assert not session.calls and CANARY not in str(error.value)


@pytest.mark.parametrize("response", [RuntimeError("Authorization: Bearer " + CANARY), _Response(ValueError(CANARY)), _Response({}, status=302)])
def test_client_errors_never_retain_token_or_response_body(response):
    with pytest.raises(PowerPlatformError) as error:
        PowerPlatformClient(token=CANARY, session=_Session(response)).get("/metadata")
    assert CANARY not in str(error.value)
    assert error.value.__suppress_context__ or error.value.status == 302


@pytest.mark.parametrize("response", [_Response(content=b""), _Response(content=b" \n"), _Response(None, content=b"null")])
def test_empty_and_null_isolation_http_responses(response):
    session = _Session(response)
    client = PowerPlatformClient(token=CANARY, session=session)
    # Exercise the real client's empty-body handling within the collector, with fake HTTP only.
    class _IsolationClient(_FakeBapClient):
        def get(self, path, *, api_version=None):
            if "tenantIsolationPolicy" in path:
                return client.get(path, api_version=api_version)
            return super().get(path, api_version=api_version)
    result = _run(_IsolationClient())
    assert result.payload["tenantIsolation"]["value"] == [{"never_configured": True}]
    assert _coverage(result)["tenantIsolation"]["status"] == "ok"


def test_malformed_dlp_scope_does_not_retain_arbitrary_environment_object():
    client = _FakeBapClient(scopes=[{"properties": {"definition": {"constraints": {
        "environmentFilter1": {"parameters": {"filterType": "include", "environments": {"title": "drop@example.test"}}}
    }}}}])
    result = _run(client)
    assert result.payload["dlpPolicyScopes"]["value"] == []
    assert _coverage(result)["dlpPolicyScopes"]["error_class"] == "incomplete_evidence"
    _assert_retention(result.payload)


@pytest.mark.parametrize("token", [None, CANARY])
def test_collector_builds_its_own_app_client_with_fake_http(monkeypatch, token):
    graph = _Graph(token=token)
    session = _Session(_Response({"value": []}))
    monkeypatch.setattr("azure_tenant_audit.power_platform.PowerPlatformClient", lambda *, token: PowerPlatformClient(token=token, session=session))
    result = PowerPlatformCollector().run({"client": graph})
    assert graph.scopes == [BAP_SCOPE]
    if token is None:
        assert not session.calls and all(row["status"] == "skipped" for row in result.coverage)
    else:
        assert len(session.calls) == 5
        assert all(method == "GET" for method, _, _ in session.calls)
        assert _coverage(result)["tenantIsolation"]["status"] == "ok"
    assert CANARY not in json.dumps([result.payload, result.coverage])


@pytest.mark.parametrize("operation,api_version", [
    ("environments", "2023-06-01"), ("dlpPolicies", "2020-10-01"), ("dlpPolicyScopes", "2016-11-01"),
])
@pytest.mark.parametrize("next_query", ["?page=2", "?page=2&api-version=2099-01-01"])
def test_list_pagination_keeps_operation_version_when_next_link_omits_it(operation, api_version, next_query):
    next_link = "https://api.bap.microsoft.com/next" + next_query

    class _PagingSession(_Session):
        def request(self, method, url, **kwargs):
            self.response = _Response({"value": []})
            if url.endswith(module.OPERATIONS[operation]):
                self.response = _Response({"value": [{"name": "first"}], "nextLink": next_link})
            elif url == next_link:
                self.response = _Response({"value": [{"name": "second"}]})
            return super().request(method, url, **kwargs)

    session = _PagingSession(None)
    result = _run(PowerPlatformClient(token=CANARY, session=session))
    assert len(result.payload[operation]["value"]) == 2
    assert _coverage(result)[operation]["status"] == "ok"
    next_calls = [kwargs for _, url, kwargs in session.calls if url == next_link]
    assert len(next_calls) == 1
    assert next_calls[0]["params"] == (None if "api-version=" in next_query else {"api-version": api_version})


@pytest.mark.parametrize("operation", ["environments", "dlpPolicies", "dlpPolicyScopes"])
@pytest.mark.parametrize("last_page", ["ok", "denied", "bound"])
def test_each_list_pages_and_marks_a_cut(operation, last_page, monkeypatch):
    next_path = "https://api.bap.microsoft.com/next?api-version=2016-11-01"
    client = _FakeBapClient()
    client.responses[module.OPERATIONS[operation]] = {"value": [{"name": "first"}], "nextLink": next_path}
    client.responses[next_path] = PowerPlatformError(CANARY, status=403) if last_page == "denied" else {"value": [{"name": "second"}]}
    if last_page == "bound":
        monkeypatch.setattr(module, "MAX_LIST_PAGES", 1)
    result = _run(client)
    row = _coverage(result)[operation]
    assert len(result.payload[operation]["value"]) == (2 if last_page == "ok" else 1)
    if last_page == "ok":
        assert row["status"] == "ok" and not row.get("collection_truncated")
    else:
        assert row["collection_truncated"] is True
        assert result.payload[operation]["collection_truncated"] is True
        assert row["truncation_reason"] == ("pagination_failed" if last_page == "denied" else "pagination_not_followed")
        assert row["error_class"] == ("insufficient_permissions" if last_page == "denied" else "collection_limit")
        assert result.status == "partial"
    assert all(method == "GET" for method, _ in client.calls)
    assert CANARY not in json.dumps([result.payload, result.coverage])
