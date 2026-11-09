"""Offline transport contracts; real requests use only a loopback fake server."""
import ast
import base64
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import inspect
import json
import logging
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

from azure_tenant_audit.adapters import get_adapter, list_adapters
from azure_tenant_audit.adapters import teams_admin_rest as rest
from azure_tenant_audit.collectors.teams_policy import TEAMS_OPERATIONS, TeamsPolicyCollector
from azure_tenant_audit.config import CollectorConfig
from azure_tenant_audit.run import build_capability_matrix_rows


def token(**claims):
    payload = {"aud": rest.TEAMS_ADMIN_SCOPE.removesuffix("/.default"), "appidacr": "2", **claims}
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"constructed.{encoded}.signature"


TOKEN = token()


@pytest.fixture(autouse=True)
def no_token_in_any_diagnostic(caplog, capsys):
    caplog.set_level(logging.DEBUG)
    yield
    captured = capsys.readouterr()
    assert TOKEN not in caplog.text + captured.out + captured.err


# All synthetic rows are constructed; no external pack/test/pilot sample is used.
CONSTRUCTED_FIXTURE = {
    "_meta": {"provenance": "constructed rows and pack train and validation rows from v3.9.1; held-out test and pilot rows excluded"},
    "vectors": [{
        "vector_id": "constructed:teams-3d:complete-policy",
        "source_kind": "constructed",
        "row": {
            "Identity": "Global", "AllowCloudRecording": False,
            "AllowExternalParticipantGiveRequestControl": False,
            "AllowAnonymousUsersToStartMeeting": False, "AutoAdmittedUsers": "EveryoneInCompany",
            "AllowPSTNUsersToBypassLobby": False, "AllowFederatedUsers": False,
            "AllowTeamsConsumer": False, "AllowTeamsConsumerInbound": False, "AllowedDomains": [],
            "AllowEmailIntoChannel": False, "DefaultCatalogAppsType": "AllowedAppList",
            "GlobalCatalogAppsType": "AllowedAppList", "PrivateCatalogAppsType": "AllowedAppList",
            "BroadcastRecordingMode": "AlwaysDisabled",
        }
        ,
    }],
}
CONSTRUCTED_ROW = CONSTRUCTED_FIXTURE["vectors"][0]["row"]

def policy_row(operation="meetingPolicies", **extra):
    return {key: CONSTRUCTED_ROW[key] for key in rest.TEAMS_REQUIRED_FIELDS[operation]} | extra


class Response:
    def __init__(self, status=200, parsed=None, headers=None, body=None):
        self.status_code = status
        self.parsed = {"value": [CONSTRUCTED_ROW.copy()]} if parsed is None else parsed
        self.headers = {"Content-Type": "application/json"} if headers is None else headers
        self.body = body
        self.closed = False

    def iter_content(self, chunk_size):
        if isinstance(self.parsed, Exception):
            yield b"invalid JSON"
            return
        body = self.body if self.body is not None else json.dumps(self.parsed).encode()
        for offset in range(0, len(body), chunk_size):
            yield body[offset:offset + chunk_size]

    def close(self):
        self.closed = True


class GetOnlySession:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        result = next(self.responses)
        if isinstance(result, Exception):
            raise result
        return result

    def __getattr__(self, name):
        raise AssertionError(f"Only GET is allowed: {name}")


def connect(monkeypatch, responses):
    session = GetOnlySession(responses)
    monkeypatch.setattr(rest.requests, "get", session.get)
    for verb in ("post", "put", "patch", "delete", "request", "head", "options"):
        monkeypatch.setattr(rest.requests, verb, lambda *a, **k: pytest.fail("Non-GET request"))
    return session


# Deliberately independent literals: changes to production destinations must fail.
DESTINATIONS = {
    "meetingPolicies": "https://api.interfaces.records.teams.microsoft.com/Skype.Policy/configurations/TeamsMeetingPolicy",
    "tenantFederationConfiguration": "https://api.interfaces.records.teams.microsoft.com/Skype.Policy/configurations/TenantFederationSettings",
    "clientConfiguration": "https://api.interfaces.records.teams.microsoft.com/Skype.Policy/configurations/TeamsClientConfiguration",
    "appPermissionPolicies": "https://api.interfaces.records.teams.microsoft.com/Skype.Policy/configurations/TeamsAppPermissionPolicy",
    "broadcastPolicies": "https://api.interfaces.records.teams.microsoft.com/Skype.Policy/configurations/TeamsMeetingBroadcastPolicy",
}


@pytest.mark.parametrize("operation", DESTINATIONS)
@pytest.mark.parametrize("environment", ["commercial", "gcc"])
def test_only_five_get_paths(monkeypatch, operation, environment):
    assert set(rest.TEAMS_READ_PATHS) == set(DESTINATIONS)
    assert set(rest.TEAMS_ADMIN_BASE) == {"commercial", "gcc"}
    session = connect(monkeypatch, [Response()])
    response = rest.TeamsAdminRestAdapter().get(operation, TOKEN, environment)
    assert response["status"] == "ok"
    assert len(session.calls) == 1
    url, kwargs = session.calls[0]
    assert url == DESTINATIONS[operation]
    assert kwargs["headers"] == {"Authorization": f"Bearer {TOKEN}", "Accept": "application/json"}
    assert 0 < kwargs.pop("timeout") <= 30
    assert kwargs == {"headers": {"Authorization": f"Bearer {TOKEN}", "Accept": "application/json"},
                      "allow_redirects": False, "stream": True}


def test_no_method_argument_or_mutating_transport():
    tree = ast.parse(inspect.getsource(rest))
    assert not any(isinstance(node, ast.arg) and node.arg == "method" for node in ast.walk(tree))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
             and node.func.value.id == "requests"]
    assert [node.func.attr for node in calls] == ["get"]


def test_bad_operation_before_any_call(monkeypatch):
    session = connect(monkeypatch, [])
    with pytest.raises(ValueError):
        rest.TeamsAdminRestAdapter().get("messages", TOKEN, "commercial")
    assert session.calls == []


@pytest.mark.parametrize("parsed", [{"value": [policy_row()]}, policy_row()])
def test_accepted_shapes(monkeypatch, parsed):
    connect(monkeypatch, [Response(parsed=parsed)])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result["status"] == "ok"
    assert result["value"] == [policy_row()]


@pytest.mark.parametrize("operation", DESTINATIONS)
def test_empty_configuration_or_global_policy_is_withheld(monkeypatch, operation):
    response = Response(parsed={"value": []})
    connect(monkeypatch, [response])
    result = rest.TeamsAdminRestAdapter().get(operation, TOKEN, "commercial")
    assert result["error_class"] == "unexpected_shape"
    assert "value" not in result and response.closed


@pytest.mark.parametrize("parsed", [None, "bad", 1, True, [1], {"value": {}},
    {"value": [None]}, ValueError("private invalid JSON"), {}, {"error": {"message": TOKEN}},
    [], [policy_row()], {"value": [{}]}, {"Identity": "Global"},
    {"value": [policy_row()], "error": {"message": TOKEN}}])
def test_unexpected_shapes(monkeypatch, parsed):
    response = Response()
    response.parsed = parsed
    connect(monkeypatch, [response])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result["error_class"] == "unexpected_shape"
    assert "value" not in result and result.get("status") != "ok" and response.closed


@pytest.mark.parametrize("retry_after,expected", [("0", 0), ("120", 60), ("-10", 0),
                                                 ("invalid", 1), ("nan", 1), ("inf", 1)])
def test_retry_once(monkeypatch, retry_after, expected):
    responses = [Response(429, headers={"Retry-After": retry_after}), Response()]
    session = connect(monkeypatch, responses)
    sleeps = []
    monkeypatch.setattr(rest.time, "sleep", sleeps.append)
    assert rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")["status"] == "ok"
    assert len(session.calls) == 2 and sleeps == [expected]
    assert all(response.closed for response in responses)


def test_retry_http_date():
    date = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=20), usegmt=True)
    assert 18 <= rest._retry_after(date) <= 20


def test_two_429s_fail(monkeypatch):
    session = connect(monkeypatch, [Response(429), Response(429)])
    monkeypatch.setattr(rest.time, "sleep", lambda _: None)
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert len(session.calls) == 2
    assert result["error_class"] == "command_error" and "value" not in result


@pytest.mark.parametrize("status,error_class", [(401, "command_not_authenticated"),
    (403, "command_not_authenticated"), (404, "command_error"), (500, "command_error"),
    (503, "command_error"), (302, "command_error"), (204, "command_error")])
def test_http_errors_and_redirects(monkeypatch, status, error_class):
    response = Response(status, parsed={"secret": TOKEN}, headers={"Location": "https://other.invalid"})
    session = connect(monkeypatch, [response])
    events = []
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial", lambda *a: events.append(a))
    assert result["error_class"] == error_class and "value" not in result
    assert TOKEN not in json.dumps([result, events]) and response.closed
    assert len(session.calls) == 1


@pytest.mark.parametrize("exception,error_class", [(requests.Timeout(TOKEN), "timeout"),
                                                  (requests.ConnectionError(TOKEN), "command_error")])
def test_transport_errors_are_private(monkeypatch, exception, error_class):
    connect(monkeypatch, [exception])
    events = []
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial", lambda *a: events.append(a))
    assert result["error_class"] == error_class
    assert TOKEN not in json.dumps([result, events])


@pytest.mark.parametrize("environment", ["gcchigh", "dod", "unknown", None])
def test_unsupported_environment_no_request(monkeypatch, environment):
    session = connect(monkeypatch, [])
    assert rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, environment) == {
        "error": "unsupported_environment", "error_class": "unsupported_environment"}
    assert session.calls == []


def test_field_filter_and_private_logs(monkeypatch, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    connect(monkeypatch, [Response(parsed={"value": [policy_row(unlisted=TOKEN, body="private")]})])
    events = []
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial", lambda *a: events.append(a))
    assert result["value"] == [policy_row()]
    assert TOKEN not in json.dumps([result, events])
    captured = capsys.readouterr()
    assert TOKEN not in caplog.text + captured.out + captured.err
    assert set(events[0][2]) == {"method", "host", "path", "status_code", "duration_ms"}
    assert events[0][2]["method"] == "GET"


def test_token_echo_in_selected_field_is_never_stored(monkeypatch):
    connect(monkeypatch, [Response(parsed={"value": [policy_row(Identity=TOKEN)]})])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result["error_class"] == "unexpected_shape" and TOKEN not in json.dumps(result)


def test_partial_page_is_never_a_success(monkeypatch):
    connect(monkeypatch, [Response(parsed={"value": [], "@odata.nextLink": "https://other.invalid"})])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result["error_class"] == "command_error" and "value" not in result


def test_rest_retains_only_consumed_fields():
    assert set(rest.TEAMS_FIELDS["meetingPolicies"]) == {
        "Identity", "AllowCloudRecording", "AllowExternalParticipantGiveRequestControl",
        "AllowAnonymousUsersToStartMeeting", "AutoAdmittedUsers", "AllowPSTNUsersToBypassLobby",
    }
    assert {"AllowPublicUsers", "BlockedDomains"} <= set(rest.TEAMS_FIELDS["tenantFederationConfiguration"])
    command = dict(TeamsPolicyCollector.command_collectors)["meetingPolicies"]
    assert "AllowIPVideo" in command and "ScreenSharingMode" in command


@pytest.mark.parametrize("candidate", [None, "opaque", token(appidacr="1"), token(appidacr="0"),
    token(aud="wrong"), token(scp="read"), token(azpacr="1"), "header.W10.signature"])
def test_only_certificate_tokens(monkeypatch, candidate):
    session = connect(monkeypatch, [])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", candidate, "commercial")
    assert result["error"] == "teams_token_unavailable" and session.calls == []


def test_v2_certificate_token():
    assert rest.certificate_token(token(azpacr="2"))


class Client:
    graph_endpoint = "https://graph.microsoft.com/v1.0"

    def __init__(self, resource_token=TOKEN):
        self.resource_token = resource_token
        self.scopes = []

    def app_token_for(self, scope):
        self.scopes.append(scope)
        return self.resource_token


class Commands:
    def __init__(self):
        self.calls = []

    def run(self, command, **kwargs):
        self.calls.append((command, kwargs))
        return {"error": "session_not_connected", "error_class": "session_not_connected"}


def command_reader(monkeypatch):
    commands = Commands()
    monkeypatch.setattr("azure_tenant_audit.collectors.teams_policy.get_adapter",
                        lambda name: commands if name == "powershell_graph" else rest.TeamsAdminRestAdapter())
    return commands


def test_collector_certificate_reads_five_and_skips_two_commands(monkeypatch):
    commands = command_reader(monkeypatch)
    session = connect(monkeypatch, [Response() for _ in range(5)])
    client = Client()
    result = TeamsPolicyCollector().run({"client": client})
    assert len(session.calls) == 5 and commands.calls == []
    assert client.scopes == [rest.TEAMS_ADMIN_SCOPE]
    assert tuple(result.payload) == TEAMS_OPERATIONS and len(result.coverage) == 7
    assert result.status == "ok" and result.item_count == 5
    skipped = [row for row in result.coverage if row["status"] == "skipped"]
    assert {row["name"] for row in skipped} == {"messagingPolicies", "appSetupPolicies"}
    assert all(row["reason"] == row["error_class"] == "teams_powershell_not_supported" for row in skipped)
    assert all(row["section_scoped"] for row in skipped)
    for operation in rest.TEAMS_READ_PATHS:
        assert result.payload[operation]["value"] == [policy_row(operation)]
        assert result.payload[operation]["command"] == f"GET {rest.TEAMS_READ_PATHS[operation]}"
    assert TOKEN not in json.dumps([result.payload, result.coverage, commands.calls])


@pytest.mark.parametrize("resource_token", [None, "unusable", token(appidacr="1"), token(aud="other-resource")])
def test_no_token_skips_every_read(monkeypatch, resource_token):
    commands = command_reader(monkeypatch)
    session = connect(monkeypatch, [])
    result = TeamsPolicyCollector().run({"client": Client(resource_token)})
    assert result.status == "ok" and result.item_count == 0
    assert len(result.coverage) == 7
    assert all(row["reason"] == "teams_token_unavailable" and row["status"] == "skipped" for row in result.coverage)
    assert session.calls == [] and commands.calls == []


@pytest.mark.parametrize("environment", ["gcchigh", "dod", "unknown"])
def test_collector_unsupported_environment(monkeypatch, environment):
    commands = command_reader(monkeypatch)
    session = connect(monkeypatch, [])
    client = Client()
    result = TeamsPolicyCollector().run({"client": client, "environment": environment})
    assert session.calls == [] and client.scopes == [] and commands.calls == []
    for operation in rest.TEAMS_READ_PATHS:
        assert result.payload[operation]["error_class"] == "unsupported_environment"
    assert result.status == "partial"
    assert all(row["status"] == ("failed" if row["name"] in rest.TEAMS_READ_PATHS else "skipped")
               for row in result.coverage)


@pytest.mark.parametrize("endpoint", ["https://graph.microsoft.us/v1.0", "http://graph.microsoft.com/v1.0", ""])
def test_no_environment_defaults_only_for_commercial_graph(monkeypatch, endpoint):
    commands = command_reader(monkeypatch)
    session = connect(monkeypatch, [])
    client = Client()
    client.graph_endpoint = endpoint
    result = TeamsPolicyCollector().run({"client": client})
    assert session.calls == [] and client.scopes == [] and commands.calls == []
    assert all(result.payload[operation]["error_class"] == "unsupported_environment"
               for operation in rest.TEAMS_READ_PATHS)


def test_environment_from_manifest(monkeypatch):
    command_reader(monkeypatch)
    session = connect(monkeypatch, [Response() for _ in range(5)])
    result = TeamsPolicyCollector().run({"client": Client(), "manifest": {"environment": "gcc"}})
    assert len(session.calls) == 5 and result.item_count == 5


@pytest.mark.parametrize("auth", [SimpleNamespace(client_secret="constructed-secret", auth_mode="app"),
                                  SimpleNamespace(auth_mode="delegated")])
def test_collector_does_not_attempt_non_certificate_auth(monkeypatch, auth):
    commands = command_reader(monkeypatch)
    session = connect(monkeypatch, [])
    client = Client()
    client.auth = auth
    result = TeamsPolicyCollector().run({"client": client})
    assert client.scopes == [] and session.calls == [] and commands.calls == []
    assert result.status == "ok"
    assert all(row["reason"] == "teams_token_unavailable" for row in result.coverage)


def test_token_exception_never_reaches_logs_or_bundle(monkeypatch):
    commands = command_reader(monkeypatch)
    connect(monkeypatch, [])
    client = Client()
    def fail(_scope):
        raise RuntimeError(TOKEN)
    client.app_token_for = fail
    events = []
    result = TeamsPolicyCollector().run({"client": client, "audit_logger": lambda *a: events.append(a)})
    assert result.status == "ok" and commands.calls == []
    assert TOKEN not in json.dumps([result.payload, result.coverage, events])


def test_capability_gate_has_no_unused_graph_scope():
    config = CollectorConfig.from_path(Path("configs/collector-definitions.json"))
    hints = json.loads(Path("configs/collector-permissions.json").read_text())["collector_permissions"]
    rows = build_capability_matrix_rows(auth_context={"token_claims": {}}, selected_collectors=["teams_policy"],
        auditor_profile="app-readonly-full", collector_config=config, permission_hints=hints)
    assert rows[0]["status"] == "supported_effective_role"
    assert rows[0]["reason"] == "command_toolchain_required"
    assert rows[0]["required_permissions"] == [] and hints["teams_policy"]["graph_scopes"] == []


def test_adapter_metadata_and_capability():
    adapter = get_adapter("teams_admin_rest")
    assert adapter.name == "teams_admin_rest" and adapter.auth_requirements == ("app",)
    assert adapter.tool_dependencies == () and adapter.dependency_check()
    row = next(row for row in list_adapters() if row["name"] == adapter.name)
    assert row["supported_auth_modes"] == ["app"] and row["write_risk"] == "get_only_allowlist"


@pytest.mark.parametrize("operation", DESTINATIONS)
def test_every_required_policy_field_is_checked(monkeypatch, operation):
    row = {key: value for key, value in CONSTRUCTED_ROW.items()
           if key in {
               "meetingPolicies": {"Identity", "AllowCloudRecording", "AllowExternalParticipantGiveRequestControl",
                   "AllowAnonymousUsersToStartMeeting", "AutoAdmittedUsers", "AllowPSTNUsersToBypassLobby"},
               "tenantFederationConfiguration": {"Identity", "AllowFederatedUsers", "AllowTeamsConsumer",
                   "AllowTeamsConsumerInbound", "AllowedDomains"},
               "clientConfiguration": {"Identity", "AllowEmailIntoChannel"},
               "appPermissionPolicies": {"Identity", "DefaultCatalogAppsType", "GlobalCatalogAppsType", "PrivateCatalogAppsType"},
               "broadcastPolicies": {"Identity", "BroadcastRecordingMode"},
           }[operation]}
    for field in row:
        missing = row.copy()
        missing.pop(field)
        wrong_type = row | {field: 123}
        for invalid in (missing, wrong_type):
            response = Response(parsed={"value": [invalid]})
            connect(monkeypatch, [response])
            result = rest.TeamsAdminRestAdapter().get(operation, TOKEN, "commercial")
            assert result["error_class"] == "unexpected_shape", (operation, field)
            assert "value" not in result and response.closed


@pytest.mark.parametrize("media_type", [None, "text/html", "text/json", "application/problem+json", "application/jsonp"])
def test_only_json_media_type(monkeypatch, media_type):
    response = Response(headers={} if media_type is None else {"Content-Type": media_type})
    connect(monkeypatch, [response])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result["error_class"] == "unexpected_shape" and response.closed


def test_json_media_type_parameters(monkeypatch):
    connect(monkeypatch, [Response(headers={"Content-Type": "Application/JSON; charset=utf-8"})])
    assert rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")["status"] == "ok"


@pytest.mark.parametrize("status", [200, 401, 403, 429, 500, 302])
def test_size_cap_also_applies_to_error_bodies(monkeypatch, status):
    monkeypatch.setattr(rest, "TEAMS_MAX_RESPONSE_BYTES", 128)
    response = Response(status, body=b"x" * 129, headers={"Content-Length": "1", "Retry-After": "0"})
    session = connect(monkeypatch, [response])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result["error_class"] == "response_too_large" and "value" not in result
    assert response.closed and len(session.calls) == 1


def test_decoded_gzip_size_is_capped(monkeypatch):
    import gzip
    from io import BytesIO
    from urllib3.response import HTTPResponse

    monkeypatch.setattr(rest, "TEAMS_MAX_RESPONSE_BYTES", 128)
    compressed = gzip.compress(b"x" * 129)
    assert len(compressed) < 128
    response = requests.Response()
    response.status_code = 200
    response.headers["Content-Type"] = "application/json"
    response.raw = HTTPResponse(BytesIO(compressed), headers={"Content-Encoding": "gzip"}, preload_content=False)
    connect(monkeypatch, [response])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result["error_class"] == "response_too_large" and response.raw.closed


@pytest.mark.parametrize("extra", [0, 1])
def test_decoded_size_boundary(monkeypatch, extra):
    body = json.dumps({"value": [policy_row()]}).encode()
    monkeypatch.setattr(rest, "TEAMS_MAX_RESPONSE_BYTES", len(body))
    response = Response(body=body + b" " * extra)
    connect(monkeypatch, [response])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result.get("status") == (None if extra else "ok")
    if extra:
        assert result["error_class"] == "response_too_large"
    assert response.closed


@pytest.mark.parametrize("depth", [32, 33, 2000])
def test_json_depth_bound_precedes_parser(monkeypatch, depth):
    # Unknown metadata must also obey the depth bound; never recurse to scan it.
    body = (json.dumps({"value": [policy_row()]})[:-1].encode() + b', "extra":'
            + b"[" * (depth - 1) + b"0" + b"]" * (depth - 1) + b"}")
    response = Response(body=body)
    connect(monkeypatch, [response])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    if depth == 32:
        assert result["status"] == "ok"
    else:
        assert result["error_class"] == "unexpected_shape" and "value" not in result
    assert response.closed


def test_depth_scanner_respects_escaped_strings(monkeypatch):
    connect(monkeypatch, [Response(parsed={"value": [policy_row()], "extra": '\\"' + "[" * 100})])
    assert rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")["status"] == "ok"


def test_json_recursion_error_is_sanitised(monkeypatch, caplog, capsys):
    original = rest.json.loads
    def fail_body(value, *args, **kwargs):
        if isinstance(value, str):
            raise RecursionError(TOKEN)
        return original(value, *args, **kwargs)
    monkeypatch.setattr(rest.json, "loads", fail_body)
    connect(monkeypatch, [Response()])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result["error_class"] == "unexpected_shape"
    captured = capsys.readouterr()
    assert TOKEN not in json.dumps(result) + caplog.text + captured.out + captured.err


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_wall_deadline_interrupts_blocked_io_and_closes_late_response(monkeypatch, phase):
    release, entered, closed = threading.Event(), threading.Event(), threading.Event()
    response = Response()
    original_iter = response.iter_content
    def block():
        entered.set()
        assert release.wait(2), "test must release its worker"
    def stream(chunk_size):
        block()
        yield from original_iter(chunk_size)
    def close():
        response.closed = True
        closed.set()
    response.close = close
    if phase == "body":
        response.iter_content = stream
    def get(*args, **kwargs):
        if phase == "headers":
            block()
        return response
    monkeypatch.setattr(rest.requests, "get", get)
    monkeypatch.setattr(rest, "TEAMS_OPERATION_DEADLINE_SECONDS", 0.05)
    events = []
    start = time.monotonic()
    try:
        result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial", lambda *a: events.append(a))
        assert entered.is_set()
        assert time.monotonic() - start < 0.5
        assert result["error_class"] == "timeout" and "value" not in result
        assert len(events) == 1 and TOKEN not in json.dumps(events)
    finally:
        release.set()
        assert closed.wait(2)


def test_deadline_covers_retry_sleep_and_prevents_another_request(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(rest.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(rest, "TEAMS_OPERATION_DEADLINE_SECONDS", 5)
    monkeypatch.setattr(rest.time, "sleep", lambda delay: clock.__setitem__(0, clock[0] + 6))
    response = Response(429, headers={"Retry-After": "1"})
    session = connect(monkeypatch, [response])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result["error_class"] == "timeout" and response.closed and len(session.calls) == 1


def test_retry_delay_cannot_consume_remaining_budget(monkeypatch):
    monkeypatch.setattr(rest, "TEAMS_OPERATION_DEADLINE_SECONDS", 0.5)
    response = Response(429, headers={"Retry-After": "60"})
    session = connect(monkeypatch, [response])
    monkeypatch.setattr(rest.time, "sleep", lambda _: pytest.fail("sleep would exceed deadline"))
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result["error_class"] == "timeout" and len(session.calls) == 1 and response.closed


@pytest.mark.parametrize("exception", [requests.Timeout(TOKEN), requests.ConnectionError(TOKEN)])
def test_stream_failures_are_private_and_closed(monkeypatch, exception, caplog, capsys):
    response = Response()
    def fail(chunk_size):
        raise exception
        yield
    response.iter_content = fail
    connect(monkeypatch, [response])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert "value" not in result and response.closed
    captured = capsys.readouterr()
    assert TOKEN not in json.dumps(result) + caplog.text + captured.out + captured.err


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be", "latin-1"])
@pytest.mark.parametrize("depth", [0, 41])
def test_non_utf8_cannot_bypass_depth_scan(monkeypatch, encoding, depth):
    # U+2200 is 22 00 in UTF-16BE; an escaped quote also confused the old byte
    # scanner. Valid policy rows ensure empty-row validation cannot mask a bypass.
    metadata = '∀' if encoding != "latin-1" else 'é'
    text = json.dumps({"value": [policy_row()], "quote": 'escaped "' + metadata}, ensure_ascii=False)
    text = text[:-1] + ', "extra":' + '[' * depth + '0' + ']' * depth + '}'
    body = text.encode(encoding)
    response = Response(body=body)
    connect(monkeypatch, [response])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result["error_class"] == "unexpected_shape" and response.closed


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
def test_odd_quote_parity_cannot_bypass_depth_scan(monkeypatch, encoding):
    # The escaped quote gives the old byte scanner odd quote parity, hiding x's
    # 41 array levels from it while json.loads still accepts the UTF-16 body.
    text = (json.dumps({"value": [policy_row()], "q": 'a"b'}, separators=(",", ":"))[:-1]
            + ',"x":' + '[' * 41 + '0' + ']' * 41 + '}')
    response = Response(body=text.encode(encoding))
    connect(monkeypatch, [response])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result.get("error_class") == "unexpected_shape" and response.closed


@pytest.mark.parametrize("prefix", [b"", b"\xef\xbb\xbf"])
def test_scan_and_parser_receive_same_utf8_text(monkeypatch, prefix):
    text = json.dumps({"value": [policy_row()], "extra": '∀ escaped "'}, ensure_ascii=False)
    scan, loads = rest._check_json_depth, rest.json.loads
    scanned, parsed = [], []
    def record_scan(value):
        scanned.append(value)
        return scan(value)
    def record_parse(value, *args, **kwargs):
        if isinstance(value, str):
            parsed.append(value)
        return loads(value, *args, **kwargs)
    monkeypatch.setattr(rest, "_check_json_depth", record_scan)
    monkeypatch.setattr(rest.json, "loads", record_parse)
    connect(monkeypatch, [Response(body=prefix + text.encode("utf-8"))])
    assert rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")["status"] == "ok"
    assert scanned == parsed == [text]


def test_nul_body_is_rejected_before_scanning(monkeypatch):
    connect(monkeypatch, [Response(body=b'{"value": []}\x00')])
    monkeypatch.setattr(rest, "_check_json_depth", lambda _: pytest.fail("NUL reached scanner"))
    assert rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")["error_class"] == "unexpected_shape"


@pytest.mark.parametrize("phase", ["request", "body"])
def test_unexpected_transport_exception_is_private(monkeypatch, phase, capsys, caplog):
    uncaught = []
    monkeypatch.setattr(threading, "excepthook", uncaught.append)
    response = Response()
    def fail(chunk_size):
        raise RuntimeError(TOKEN)
        yield
    response.iter_content = fail
    connect(monkeypatch, [RuntimeError(TOKEN) if phase == "request" else response])
    events = []
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial", lambda *a: events.append(a))
    assert result["error_class"] == "command_error" and "value" not in result
    assert not uncaught
    if phase == "body":
        assert response.closed
    captured = capsys.readouterr()
    assert captured.err == ""
    assert TOKEN not in json.dumps([result, events]) + captured.out + captured.err + caplog.text


def test_missing_worker_body_fails_closed(monkeypatch):
    monkeypatch.setattr(rest, "_read_attempt", lambda *args: None)
    assert rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")["error_class"] == "command_error"


@pytest.mark.parametrize("path", [("connection", "sock"), ("_connection", "sock"), ("_fp", "fp", "raw", "_sock")])
def test_shutdown_socket_paths(monkeypatch, path):
    calls = []
    raw = SimpleNamespace(shutdown=calls.append)
    for name in reversed(path):
        raw = SimpleNamespace(**{name: raw})
    rest._shutdown_response(SimpleNamespace(raw=raw))
    assert calls == [socket.SHUT_RDWR]


def test_shutdown_diagnostics_never_escape(capsys):
    class Broken:
        def __getattr__(self, name):
            raise RuntimeError(TOKEN)
    rest._shutdown_response(Broken())
    assert capsys.readouterr().err == ""


def test_fake_trickle_shutdown_reaps_workers(monkeypatch):
    # Model a buffered read waiting for 1 KiB while a peer supplies a byte every
    # 0.3 s. close needs the read lock; only socket shutdown can unblock it.
    stopped = threading.Event()
    read_lock = threading.Lock()
    bytes_received, shutdowns = [], []
    response = Response()
    def shutdown(how):
        shutdowns.append(how)
        stopped.set()
    response.raw = SimpleNamespace(connection=SimpleNamespace(sock=SimpleNamespace(shutdown=shutdown)))
    def trickle(chunk_size):
        assert chunk_size == 1024
        with read_lock:
            for _ in range(chunk_size):
                if stopped.wait(0.3):
                    return
                bytes_received.append(b" ")
            yield b"".join(bytes_received)
    def close():
        with read_lock:
            response.closed = True
    response.iter_content, response.close = trickle, close
    connect(monkeypatch, [response])
    monkeypatch.setattr(rest, "TEAMS_OPERATION_DEADLINE_SECONDS", 2.0)
    before = set(threading.enumerate())
    try:
        started = time.monotonic()
        result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
        assert 1.8 <= time.monotonic() - started < 3.0
        assert result["error_class"] == "timeout" and "value" not in result
        workers = [thread for thread in threading.enumerate() if thread not in before
                   and thread.name in {"teams-policy-read", "teams-policy-close"}]
        for worker in workers:
            worker.join(1)
        assert not any(worker.is_alive() for worker in workers)
        assert not any(thread.name in {"teams-policy-read", "teams-policy-close"}
                       for thread in threading.enumerate() if thread not in before)
        assert bytes_received and shutdowns == [socket.SHUT_RDWR] and response.closed
    finally:
        stopped.set()


def test_loopback_trickle_shutdown_reaps_workers(monkeypatch, capsys):
    # Real requests/urllib3, with no external network or proxy. The peer keeps
    # sending one byte every 0.3 s until the client actually closes its socket.
    ready, stop, peer_closed = threading.Event(), threading.Event(), threading.Event()
    errors, responses = [], []
    listener = socket.socket()
    try:
        listener.bind(("127.0.0.1", 0))
    except PermissionError:
        listener.close()
        pytest.skip("sandbox denies loopback bind; fake-transport trickle probe runs separately")
    listener.listen(1)
    listener.settimeout(5)
    def serve():
        try:
            with listener.accept()[0] as peer:
                peer.settimeout(5)
                request = b""
                while b"\r\n\r\n" not in request:
                    request += peer.recv(4096)
                peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10000\r\nConnection: close\r\n\r\n")
                ready.set()
                while not stop.wait(0.3):
                    try:
                        peer.sendall(b" ")
                    except (BrokenPipeError, ConnectionResetError):
                        peer_closed.set()
                        break
        except Exception as exc:
            errors.append(type(exc).__name__)
    server = threading.Thread(target=serve, name="teams-trickle-peer", daemon=True)
    session = requests.Session()
    session.trust_env = False
    local_url = f"http://127.0.0.1:{listener.getsockname()[1]}/trickle"
    def local_get(url, **kwargs):
        assert url == DESTINATIONS["meetingPolicies"]
        response = session.get(local_url, **kwargs)
        responses.append(response)
        return response
    monkeypatch.setattr(rest.requests, "get", local_get)
    monkeypatch.setattr(rest, "TEAMS_OPERATION_DEADLINE_SECONDS", 2.0)
    before = set(threading.enumerate())
    server.start()
    try:
        started = time.monotonic()
        result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
        elapsed = time.monotonic() - started
        assert ready.is_set() and result["error_class"] == "timeout"
        assert 1.8 <= elapsed < 3.0
        workers = [thread for thread in threading.enumerate() if thread not in before
                   and thread.name in {"teams-policy-read", "teams-policy-close"}]
        for worker in workers:
            worker.join(1)
        assert not any(worker.is_alive() for worker in workers)
        assert not any(thread.name in {"teams-policy-read", "teams-policy-close"}
                       for thread in threading.enumerate() if thread not in before)
        assert responses and responses[0].raw.closed
        assert peer_closed.wait(1.5), "peer should see shutdown while still trickling"
        server.join(1)
        assert not server.is_alive() and not errors
        assert capsys.readouterr().err == ""
    finally:
        stop.set()
        listener.close()
        server.join(6)
        session.close()


def test_retry_request_timeout_uses_remaining_operation_budget(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(rest.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(rest.time, "sleep", lambda delay: clock.__setitem__(0, clock[0] + delay))
    responses = [Response(429, headers={"Retry-After": "60"}), Response()]
    session = connect(monkeypatch, responses)
    original = session.get
    def get(*args, **kwargs):
        response = original(*args, **kwargs)
        clock[0] += 25 if len(session.calls) == 1 else 1
        return response
    monkeypatch.setattr(rest.requests, "get", get)
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result["status"] == "ok"
    assert [kwargs["timeout"] for _, kwargs in session.calls] == [30, 5]
    assert result["duration_ms"] == 86000


def test_decoded_byte_budget_is_shared_across_retry(monkeypatch):
    body = json.dumps({"value": [policy_row()]}).encode()
    monkeypatch.setattr(rest, "TEAMS_MAX_RESPONSE_BYTES", len(body) + 99)
    responses = [Response(429, body=b" " * 100, headers={"Retry-After": "0"}), Response(body=body)]
    session = connect(monkeypatch, responses)
    monkeypatch.setattr(rest.time, "sleep", lambda _: None)
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    assert result["error_class"] == "response_too_large" and "value" not in result
    assert len(session.calls) == 2 and all(response.closed for response in responses)


def test_close_diagnostics_are_private(monkeypatch, caplog, capsys):
    response = Response()
    def close():
        response.closed = True
        raise OSError(TOKEN)
    response.close = close
    connect(monkeypatch, [response])
    result = rest.TeamsAdminRestAdapter().get("meetingPolicies", TOKEN, "commercial")
    captured = capsys.readouterr()
    assert response.closed
    assert TOKEN not in json.dumps(result) + caplog.text + captured.out + captured.err
