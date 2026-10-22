"""Transport and data hygiene: redirects, token events, secret redaction, ledger templating and content detection."""
from __future__ import annotations

import base64
import subprocess
from typing import Any

import pytest

from azure_tenant_audit.api_inventory import (
    endpoint_template,
    observe_audit_events,
    with_observed_ledger,
)
from azure_tenant_audit.graph import GRAPH_ROOT, REDIRECT_REFUSED, GraphClient, GraphError
from azure_tenant_audit.secret_hygiene import redact_text
from support import graph_auth, graph_response

GUID = "5f7b3a1e-0c4d-4e2b-9a6f-1d2c3b4a5e6f"
SIGNED = "https://reportsdata.office.com/data/download/abc123?sig=TOPSECRETSIGNATURE&se=2026"


class _Session:
    """A fake requests.Session answering from a script and recording what it was asked."""

    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict[str, str], dict[str, Any]]] = []

    def request(self, method: str, url: str, headers: Any = None, timeout: Any = None, **kwargs: Any) -> Any:  # noqa: ARG002
        self.calls.append((method, url, dict(headers or {}), kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        response.url = url
        return response


def _client(session: _Session, events: list[tuple[str, dict[str, Any]]]) -> GraphClient:
    return GraphClient(
        graph_auth(),
        session=session,  # type: ignore[arg-type]
        audit_event=lambda event, message, details=None: events.append((event, dict(details or {}))),
    )


def _redirect(location: str, status: int = 302) -> Any:
    return graph_response(status, "", headers={"Location": location})


# ---- redirects --------------------------------------------------------------------------------------------


def test_a_report_redirect_is_followed_without_the_token_and_logged_without_its_query() -> None:
    session = _Session(_redirect(SIGNED), graph_response(200, "a,b\n1,2\n"))
    events: list[tuple[str, dict[str, Any]]] = []

    text = _client(session, events).get_content("/reports/getMailboxUsageDetail(period='D30')")

    assert text == "a,b\n1,2\n"
    assert all(call[3].get("allow_redirects") is False for call in session.calls)
    first, second = session.calls
    assert first[2]["Authorization"] == "Bearer x"
    assert second[1] == SIGNED
    assert "Authorization" not in second[2], "the bearer token never goes to the download host"
    redirects = [details for event, details in events if event == "graph.request.redirect"]
    assert redirects == [
        {
            "method": "GET",
            "status": 302,
            "hop": 1,
            "from_path": "/v1.0/reports/getMailboxUsageDetail(period='D30')",
            "host": "reportsdata.office.com",
            "path": "/data/download/abc123",
        }
    ]
    assert "TOPSECRETSIGNATURE" not in repr(events)


def test_a_redirect_to_a_host_that_is_not_microsoft_is_refused_and_nothing_is_sent_there() -> None:
    session = _Session(_redirect("https://attacker.example.net/collect?token=abc"))
    events: list[tuple[str, dict[str, Any]]] = []

    with pytest.raises(GraphError) as caught:
        _client(session, events).get_content("/reports/getMailboxUsageDetail(period='D30')")

    assert caught.value.error_code == REDIRECT_REFUSED
    assert len(session.calls) == 1
    refused = [details for event, details in events if event == "graph.request.redirect_refused"]
    assert refused[0]["host"] == "attacker.example.net"
    assert "token=abc" not in repr(events) and "token=abc" not in str(caught.value) + repr(caught.value.request)


def test_a_redirect_downgrade_to_http_is_refused() -> None:
    session = _Session(_redirect("http://reportsdata.office.com/data/download/abc"))

    with pytest.raises(GraphError) as caught:
        _client(session, []).get_content("/reports/getMailboxUsageDetail(period='D30')")

    assert caught.value.error_code == REDIRECT_REFUSED


def test_a_redirect_back_to_graph_keeps_the_token_and_a_loop_stops() -> None:
    session = _Session(
        _redirect(f"{GRAPH_ROOT}/reports/other"),
        graph_response(200, "ok"),
    )
    client = _client(session, [])

    assert client.get_content("/reports/first") == "ok"
    assert session.calls[1][2]["Authorization"] == "Bearer x"

    loop = _Session(*[_redirect(f"{GRAPH_ROOT}/reports/again") for _ in range(6)])
    with pytest.raises(GraphError) as caught:
        _client(loop, []).get_content("/reports/first")
    assert caught.value.error_code == REDIRECT_REFUSED


def test_an_error_after_a_redirect_does_not_carry_the_download_query() -> None:
    session = _Session(_redirect(SIGNED), graph_response(403, "denied"))
    events: list[tuple[str, dict[str, Any]]] = []

    with pytest.raises(GraphError) as caught:
        _client(session, events).get_content("/reports/getMailboxUsageDetail(period='D30')")

    assert "TOPSECRETSIGNATURE" not in str(caught.value.request)
    assert caught.value.request == "https://reportsdata.office.com/data/download/abc123"


def test_a_failed_redirect_hop_is_logged_without_the_signed_url() -> None:
    from requests.exceptions import ConnectionError as RequestsConnectionError

    session = _Session(_redirect(SIGNED), RequestsConnectionError(f"could not reach {SIGNED}"))
    events: list[tuple[str, dict[str, Any]]] = []

    with pytest.raises(RequestsConnectionError):
        _client(session, events).get_content("/reports/getMailboxUsageDetail(period='D30')")

    assert "TOPSECRETSIGNATURE" not in repr(events)


def test_the_observed_ledger_lists_redirect_hops_without_a_query() -> None:
    events = [
        {"event": "graph.request.started", "details": {"method": "GET", "url": f"{GRAPH_ROOT}/reports/getMailboxUsageDetail(period='D30')", "attempt": 1, "params": {}}},
        {
            "event": "graph.request.redirect",
            "details": {"status": 302, "hop": 1, "from_path": "/v1.0/reports/getMailboxUsageDetail(period='D30')", "host": "reportsdata.office.com", "path": "/data/download/abc"},
        },
        {"event": "graph.request.redirect_refused", "details": {"host": "attacker.example.net", "path": "/x"}},
    ]

    ledger = observe_audit_events(events)

    assert ledger["graph"]["redirects"] == [
        {"from": "/reports/getMailboxUsageDetail(...)", "host": "reportsdata.office.com", "path": "/data/download/abc", "count": 1}
    ]
    assert ledger["graph"]["redirects_refused"] == 1


# ---- token events -----------------------------------------------------------------------------------------


def test_a_resource_token_request_is_counted_like_the_graph_token_request() -> None:
    class _Post:
        status_code = 200

        @staticmethod
        def json() -> dict[str, Any]:
            return {"access_token": "resource-token"}

    class _TokenSession(_Session):
        def post(self, url: str, **kwargs: Any) -> Any:  # noqa: ARG002
            return _Post()

    events: list[tuple[str, dict[str, Any]]] = []
    client = GraphClient(
        graph_auth(auth_mode="app", access_token=None, client_secret="s"),
        session=_TokenSession(),  # type: ignore[arg-type]
        audit_event=lambda event, message, details=None: events.append((event, dict(details or {}))),
    )

    assert client.app_token_for("https://outlook.office365.com/.default") == "resource-token"

    names = [event for event, _ in events]
    assert names == ["graph.token.requested", "graph.token.succeeded"]
    assert events[0][1]["scope"] == "https://outlook.office365.com/.default"
    ledger = observe_audit_events([{"event": event, "details": details} for event, details in events])
    assert ledger["auth"] == {"token_requests": 1, "token_succeeded": 1}


# ---- secret redaction -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        '{"client_secret": "DUMMYVALUE"}',
        '{"password":"DUMMYVALUE"}',
        '{"access_token":"DUMMYVALUE"}',
        '"refresh_token": "DUMMYVALUE"',
        "{'secret': 'DUMMYVALUE'}",
        "client_secret: DUMMYVALUE",
        "password=DUMMYVALUE",
    ],
)
def test_json_keyed_and_plain_secrets_are_redacted(text: str) -> None:
    assert "DUMMYVALUE" not in redact_text(text)


def test_a_quoted_secret_value_with_spaces_is_redacted_whole() -> None:
    redacted = redact_text('{"password": "two words", "name": "kept"}')

    assert "two words" not in redacted
    assert '"name": "kept"' in redacted


def test_the_command_output_sample_is_redacted_before_it_is_cut(monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter

    # Built at run time so that no token-shaped literal sits in the repository.
    segments = (b'{"alg":"HS256"}', b'{"sub":"user"}', b"signature-signature")
    jwt = ".".join(base64.urlsafe_b64encode(segment).decode().rstrip("=") for segment in segments)
    stdout = "[" + " " * 445 + f'"{jwt}"]'
    monkeypatch.setattr("subprocess.run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr=""))
    monkeypatch.setattr("shutil.which", lambda name, *a, **k: f"/usr/bin/{name}")
    events: list[dict[str, Any]] = []

    PowerShellGraphAdapter().run(
        "Get-Mailbox", log_event=lambda event, message, details=None: events.append({"event": event, **(details or {})})
    )

    sample = next(row["stdout_sample"] for row in events if row["event"] == "command.completed")
    assert jwt.split(".")[0] not in sample
    assert "eyJ" not in sample, "no header or partial payload of the token survives the cut"


# ---- ledger templating ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/deviceManagement/deviceCompliancePolicies", "/deviceManagement/deviceCompliancePolicies"),
        ("/beta/deviceManagement/windowsQualityUpdateProfiles", "/deviceManagement/windowsQualityUpdateProfiles"),
        ("/deviceManagement/windowsAutopilotDeviceIdentities", "/deviceManagement/windowsAutopilotDeviceIdentities"),
        ("/policies/identitySecurityDefaultsEnforcementPolicy", "/policies/identitySecurityDefaultsEnforcementPolicy"),
        ("/roleManagement/directory/roleEligibilitySchedules", "/roleManagement/directory/roleEligibilitySchedules"),
        (f"/users/{GUID}/mailboxSettings", "/users/{id}/mailboxSettings"),
        ("/users/AAMkAGI2THVSAAA1234567890/messages", "/users/{id}/messages"),
        ("/groups/alice@contoso.com/members", "/groups/{id}/members"),
        ("/security/secureScoreControlProfiles/MDA_Zendesk_Production_Account_01", "/security/secureScoreControlProfiles/{id}"),
    ],
)
def test_long_resource_names_are_not_collapsed_but_identifiers_are(path: str, expected: str) -> None:
    assert endpoint_template(path)[0] == expected


def test_an_undeclared_sibling_resource_with_a_long_name_is_outside_the_declared_set() -> None:
    declared = [{"method": "GET", "endpoint": "/deviceManagement/deviceCompliancePolicies", "api_version": "v1.0"}]
    events = [
        {"event": "graph.request.started", "details": {"method": "GET", "url": f"{GRAPH_ROOT}/deviceManagement/windowsAutopilotDeviceIdentities", "attempt": 1, "params": {}}},
        {"event": "graph.request.started", "details": {"method": "GET", "url": f"{GRAPH_ROOT}/deviceManagement/deviceCompliancePolicies", "attempt": 1, "params": {}}},
    ]

    ledger = observe_audit_events(events, declared_calls=declared)

    assert [row["endpoint"] for row in ledger["outside_declared"]["graph"]] == ["/deviceManagement/windowsAutopilotDeviceIdentities"]


def test_no_endpoint_a_collector_calls_is_flagged_as_a_content_read() -> None:
    """The denylist must not flag any endpoint the shipped collectors really call."""
    import re
    from pathlib import Path

    from azure_tenant_audit.api_inventory import _content_reason

    collectors = Path(__file__).resolve().parents[1] / "src" / "azure_tenant_audit" / "collectors"
    endpoints = {
        match
        for path in collectors.glob("*.py")
        for match in re.findall(r"""["']endpoint["']\s*:\s*f?["'](/[^"']+)["']""", path.read_text(encoding="utf-8"))
    }
    assert len(endpoints) > 30, "the scan must actually find the collectors' endpoints"
    for endpoint in sorted(endpoints):
        template, _ = endpoint_template(re.sub(r"\{[^}]*\}", GUID, endpoint))
        assert _content_reason(template, None) is None, endpoint


# ---- content detection ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        f"{GRAPH_ROOT}/users/{GUID}/calendarView?startDateTime=2026-01-01&endDateTime=2026-02-01",
        f"{GRAPH_ROOT}/users/{GUID}/calendars/AAMkAGI2THVSAAA1234567890=/events",
        f"{GRAPH_ROOT}/me/calendarView",
        f"{GRAPH_ROOT}/groups/{GUID}/calendar/calendarView",
        f"{GRAPH_ROOT}/groups/{GUID}/threads/AAQkADk1234567890123456789/posts",
        f"{GRAPH_ROOT}/groups/{GUID}/conversations",
        f"{GRAPH_ROOT}/chats/getAllMessages",
        f"{GRAPH_ROOT}/sites/{GUID}/lists/{GUID}/items",
        f"{GRAPH_ROOT}/users/{GUID}/todo/lists/AAMkAD1234567890123456789/tasks",
    ],
)
def test_more_content_bearing_endpoints_clear_no_content_reads(url: str) -> None:
    events = [{"event": "graph.request.started", "details": {"method": "GET", "url": url, "attempt": 1, "params": {}}}]

    inventory = with_observed_ledger(
        {"safety": {"read_only": True, "no_content_reads": True}, "counts": {}, "observed_calls": []}, events
    )

    assert inventory["safety"]["no_content_reads"] is False, url


def test_a_select_or_expand_inside_the_url_or_a_batch_inner_url_is_judged_like_a_parameter() -> None:
    inline = [
        {"event": "graph.request.started", "details": {"method": "GET", "url": f"{GRAPH_ROOT}/users?%24select=id,body", "attempt": 1, "params": {}}}
    ]
    expand = [
        {"event": "graph.request.started", "details": {"method": "GET", "url": f"{GRAPH_ROOT}/users?$expand=messages($select=id)", "attempt": 1, "params": None}}
    ]
    batch = [
        {
            "event": "graph.request.started",
            "details": {
                "method": "POST",
                "url": f"{GRAPH_ROOT}/$batch",
                "attempt": 1,
                "batch": {"size": 1, "urls": ["/users?$select=id,bodyPreview"], "methods": ["GET"]},
            },
        }
    ]
    clean = [{"event": "graph.request.started", "details": {"method": "GET", "url": f"{GRAPH_ROOT}/users?$select=id,displayName", "attempt": 1, "params": {}}}]

    for events in (inline, expand, batch):
        assert observe_audit_events(events)["graph"]["content_read_calls"], events
    assert observe_audit_events(clean)["graph"]["content_read_calls"] == []


# ---- guided setup -----------------------------------------------------------------------------------------


def test_the_exchange_module_install_does_not_change_the_psgallery_trust_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex import auth

    seen: list[list[str]] = []
    monkeypatch.setattr(auth, "_pwsh_exchange_module_status", lambda: {"status": "missing", "pwsh_path": "/usr/bin/pwsh"})
    monkeypatch.setattr(auth.subprocess, "run", lambda command, **kwargs: seen.append(list(command)) or subprocess.CompletedProcess(command, 0))

    assert auth.ensure_exchange_online_module() == 0

    assert "Install-Module ExchangeOnlineManagement" in seen[0][-1]
    assert "Set-PSRepository" not in seen[0][-1]
