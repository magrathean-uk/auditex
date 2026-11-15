"""No verb, path or body other than the one pinned read reaches the SharePoint admin host."""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from azure_tenant_audit.adapters import read_guard
from azure_tenant_audit.adapters.read_guard import (
    SHAREPOINT_ADMIN_ACCEPT,
    RequestRefused,
    check_sharepoint_admin_request,
    sharepoint_admin_host,
    sharepoint_admin_request_violation,
)
from azure_tenant_audit.collectors import sharepoint_admin as spa
from azure_tenant_audit.config import AuthConfig
from azure_tenant_audit.graph import GraphClient

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "src/azure_tenant_audit/collectors/sharepoint_admin.py"
URL = "https://contoso-admin.sharepoint.com/_api/SPO.Tenant"
HEADERS = {"Authorization": "Bearer constructed", "Accept": SHAREPOINT_ADMIN_ACCEPT, "User-Agent": "auditex/test"}


def test_the_pinned_read_passes() -> None:
    assert sharepoint_admin_request_violation("GET", URL, headers=HEADERS) is None
    assert check_sharepoint_admin_request("GET", URL, headers=HEADERS) == URL
    assert read_guard.SHAREPOINT_ADMIN_READ_PATHS == frozenset({"/_api/SPO.Tenant"})


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "MERGE", "HEAD", "OPTIONS", "get", " GET", None, b"GET"])
def test_every_other_verb_is_refused(method) -> None:  # noqa: ANN001
    with pytest.raises(RequestRefused):
        check_sharepoint_admin_request(method, URL, headers=HEADERS)


@pytest.mark.parametrize("url", [
    "https://contoso-admin.sharepoint.com/_api/SPO.Tenant/sites",
    "https://contoso-admin.sharepoint.com/_api/SPO.Tenant?$select=SharingCapability",
    "https://contoso-admin.sharepoint.com/_api/SPO.Tenant#frag",
    "https://contoso-admin.sharepoint.com/_api/SPO.Tenant;x",
    "https://contoso-admin.sharepoint.com/_api/spo.tenant",
    "https://contoso-admin.sharepoint.com/_api/SPO%2ETenant",
    "https://contoso-admin.sharepoint.com/_vti_bin/client.svc/ProcessQuery",
    "https://contoso-admin.sharepoint.com/_api/SPO.Tenant/GetSitePropertiesFromSharePointByFilters",
    "https://contoso-admin.sharepoint.com//_api/SPO.Tenant",
    "https://contoso-admin.sharepoint.com/x/../_api/SPO.Tenant",
    "http://contoso-admin.sharepoint.com/_api/SPO.Tenant",
    "https://contoso-admin.sharepoint.com:443/_api/SPO.Tenant",
    "https://user@contoso-admin.sharepoint.com/_api/SPO.Tenant",
    "https://Contoso-admin.sharepoint.com/_api/SPO.Tenant",
    "https://contoso-admin.sharepoint.com./_api/SPO.Tenant",
    "https://contoso.sharepoint.com/_api/SPO.Tenant",
    "https://contoso-my.sharepoint.com/_api/SPO.Tenant",
    "https://-admin.sharepoint.com/_api/SPO.Tenant",
    "https://con.toso-admin.sharepoint.com/_api/SPO.Tenant",
    "https://contoso-admin.sharepoint.com.evil.example/_api/SPO.Tenant",
    "https://evil.example/contoso-admin.sharepoint.com/_api/SPO.Tenant",
    "https://evil.example#-admin.sharepoint.com/_api/SPO.Tenant",
    "https://evil.example\\@contoso-admin.sharepoint.com/_api/SPO.Tenant",
    "https://contoso-admin.sharepoint.com/_api/SPO.Te\nnant",
    "https://contoso-admin.sharepoint.com/_api/SPO.Te\tnant",
    "https://contoso-admin.sharepoint.com/_api/SPO.Tenant ",
    "https://contoso-admin.sharepoint.com/_api/SPO.Ténant",
    "https://contoso-admin.sharepoint.us/_api/SPO.Tenant",
    "https://graph.microsoft.com/v1.0/admin/sharepoint/settings",
    "",
    None,
])
def test_every_other_path_or_host_is_refused(url) -> None:  # noqa: ANN001
    with pytest.raises(RequestRefused):
        check_sharepoint_admin_request("GET", url, headers=HEADERS)


@pytest.mark.parametrize("body", [{}, b"", "", {"x": 1}, b"<Request/>"])
def test_a_body_is_refused(body) -> None:  # noqa: ANN001
    with pytest.raises(RequestRefused):
        check_sharepoint_admin_request("GET", URL, headers=HEADERS, body=body)


@pytest.mark.parametrize("headers", [
    {**HEADERS, "X-HTTP-Method-Override": "DELETE"},
    {**HEADERS, "X-HTTP-Method": "MERGE"},
    {**HEADERS, "X-RequestDigest": "constructed"},
    {**HEADERS, "IF-MATCH": "*"},
    {**HEADERS, "Accept": "application/json;odata=nometadata"},
    {**HEADERS, "accept": SHAREPOINT_ADMIN_ACCEPT},
    ["Authorization"],
])
def test_only_the_three_read_headers_are_allowed(headers) -> None:  # noqa: ANN001
    with pytest.raises(RequestRefused):
        check_sharepoint_admin_request("GET", URL, headers=headers)


@pytest.mark.parametrize(("prefix", "host"), [
    ("contoso", "contoso-admin.sharepoint.com"), ("a", "a-admin.sharepoint.com"), ("a-1", "a-1-admin.sharepoint.com"),
    ("", None), ("-a", None), ("a-", None), ("A", None), ("a.b", None), ("a_b", None), ("a" * 58, None), (None, None),
])
def test_the_admin_host_is_built_only_from_a_plain_prefix(prefix, host) -> None:  # noqa: ANN001
    assert sharepoint_admin_host(prefix) == host


class RecordingSession:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(self, url, **kwargs):  # noqa: ANN001, ANN201
        self.calls.append(url)
        raise AssertionError("a refused request reached the network")


@pytest.mark.parametrize("url", [URL + "/sites", URL + "?x=1", "https://contoso.sharepoint.com/_api/SPO.Tenant"])
def test_a_refused_read_never_reaches_the_session_and_is_logged(url) -> None:  # noqa: ANN001
    session, events = RecordingSession(), []
    result = spa.read_tenant_settings(session, url, "constructed-token",
                                      log_event=lambda event, message, details=None: events.append((event, details)))
    assert result == {"reason": "request_refused"} and session.calls == []
    [(event, details)] = events
    assert event == "sharepoint_admin_rest.refused" and details["method"] == "GET"
    assert "constructed-token" not in json.dumps(events) and "contoso" not in json.dumps(events)


def _calls(tree: ast.AST) -> list[ast.Call]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


def test_the_module_has_one_network_call_and_the_guard_runs_first() -> None:
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    verbs = {"get", "post", "put", "patch", "delete", "head", "options", "request", "send", "urlopen", "open"}
    sites = [call for call in _calls(tree) if isinstance(call.func, ast.Attribute) and call.func.attr in verbs
             and ast.unparse(call.func.value) in {"session", "requests", "self.session", "urllib.request"}]
    assert [ast.unparse(site.func) for site in sites] == ["session.get"]
    functions = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    send = functions["_send"]
    assert sites[0] in list(ast.walk(send))
    first = send.body[1] if isinstance(send.body[0], ast.Expr) and isinstance(send.body[0].value, ast.Constant) else send.body[0]
    assert ast.unparse(first) == "check_sharepoint_admin_request(SHAREPOINT_ADMIN_METHOD, url, headers=headers)"
    keywords = {keyword.arg: ast.unparse(keyword.value) for keyword in sites[0].keywords}
    assert keywords["allow_redirects"] == "False" and not {"json", "data", "files", "params"} & set(keywords)
    # _send is reached only from read_tenant_settings, which builds the headers it checks.
    callers = {name for name, node in functions.items() if any(
        isinstance(call.func, ast.Name) and call.func.id == "_send" for call in _calls(node))}
    assert callers == {"read_tenant_settings"}


def test_no_other_module_talks_to_a_sharepoint_admin_host() -> None:
    allowed = {"src/azure_tenant_audit/collectors/sharepoint_admin.py", "src/azure_tenant_audit/adapters/read_guard.py"}
    pattern = re.compile(r"-admin\.sharepoint|SPO\.Tenant|ProcessQuery|_vti_bin")
    found = {str(path.relative_to(ROOT)) for path in (ROOT / "src").rglob("*.py")
             if pattern.search(path.read_text(encoding="utf-8"))}
    assert found == allowed


@pytest.mark.parametrize("scope", [
    "https://contoso-admin.sharepoint.com/.default",
    "https://contoso.sharepoint.com/.default",
    "00000003-0000-0ff1-ce00-000000000000/.default",
    "HTTPS://CONTOSO-ADMIN.SHAREPOINT.COM/.default",
])
def test_a_client_secret_never_mints_a_sharepoint_token(scope) -> None:  # noqa: ANN001
    class NoPost:
        def post(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            raise AssertionError("a SharePoint token was requested with the client secret")

    auth = AuthConfig(tenant_id="constructed.onmicrosoft.com", client_id="constructed-app", client_secret="constructed-secret")
    assert GraphClient(auth, session=NoPost()).app_token_for(scope) is None


def test_a_client_secret_still_mints_other_resource_tokens() -> None:
    posts: list[str] = []

    class Session:
        def post(self, url, data=None, **kwargs):  # noqa: ANN001, ANN201
            posts.append(data["scope"])
            response = type("R", (), {"status_code": 200, "json": lambda self: {"access_token": "t"}})()
            return response

    auth = AuthConfig(tenant_id="constructed.onmicrosoft.com", client_id="constructed-app", client_secret="constructed-secret")
    assert GraphClient(auth, session=Session()).app_token_for("https://outlook.office365.com/.default") == "t"
    assert posts == ["https://outlook.office365.com/.default"]
