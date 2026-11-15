"""The opt-in SharePoint admin read: host from Graph, certificate or one-sign-in token, one guarded GET, named skips."""
from __future__ import annotations

import base64
import json
import types
from pathlib import Path

import pytest
import requests

from azure_tenant_audit.collection_gaps import SECTION_SCOPED
from azure_tenant_audit.collectors import REGISTRY
from azure_tenant_audit.collectors import sharepoint_admin as spa
from azure_tenant_audit.graph import GraphError
from azure_tenant_audit.profiles import PROFILES
from azure_tenant_audit.selection import select_collectors

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://contoso-admin.sharepoint.com"
URL = ORIGIN + "/_api/SPO.Tenant"
SETTINGS = {
    "ODBSharingCapability": 3, "DefaultSharingLinkType": 1, "DefaultLinkPermission": 1,
    "RequireAnonymousLinksExpireInDays": 30, "FileAnonymousLinkType": 1, "FolderAnonymousLinkType": 1,
    "EmailAttestationRequired": True, "EmailAttestationReAuthDays": 30,
}
ROOT_SITE = {"id": "constructed", "siteCollection": {"hostname": "Contoso.sharepoint.com"}}


def jwt(**claims: object) -> str:
    def part(value: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return f"{part({'alg': 'none'})}.{part(claims)}.signature"


APP_TOKEN = jwt(aud=ORIGIN, appidacr="2", roles=["Sites.FullControl.All"])


class FakeResponse:
    def __init__(self, status: int = 200, payload: object = None, *, body: bytes | None = None,
                 content_type: str = "application/json;odata=verbose;charset=utf-8", headers: dict | None = None) -> None:
        self.status_code = status
        self._body = body if body is not None else json.dumps({"d": payload if payload is not None else {
            "__metadata": {"type": "Microsoft.Online.SharePoint.TenantAdministration.Tenant"},
            "SharingCapability": 2, "OneDriveStorageQuota": 1048576, **SETTINGS}}).encode()
        self.headers = {"Content-Type": content_type, **(headers or {})}
        self.closed = False

    def iter_content(self, chunk_size: int = 1024):  # noqa: ANN201
        for start in range(0, len(self._body), chunk_size):
            yield self._body[start:start + chunk_size]

    def close(self) -> None:
        self.closed = True


class FakeSession:
    def __init__(self, *answers: object) -> None:
        self.answers = list(answers) or [FakeResponse()]
        self.calls: list[tuple[str, dict, dict]] = []
        self.closed = False

    def get(self, url, headers=None, **kwargs):  # noqa: ANN001, ANN201
        self.calls.append((url, dict(headers or {}), kwargs))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def close(self) -> None:
        self.closed = True


class FakeClient:
    def __init__(self, *, mode: str = "certificate", root_site: object = ROOT_SITE, token: object = None) -> None:
        self.auth = types.SimpleNamespace(
            certificate=object() if mode == "certificate" else None,
        )
        self.root_site = root_site
        self.token = token if token is not None else APP_TOKEN
        self.graph_reads: list[tuple[str, dict | None]] = []
        self.app_scopes: list[str] = []

    def get_json(self, path, params=None):  # noqa: ANN001, ANN201
        self.graph_reads.append((path, params))
        if isinstance(self.root_site, BaseException):
            raise self.root_site
        return self.root_site

    def app_token_for(self, scope):  # noqa: ANN001, ANN201
        self.app_scopes.append(scope)
        return self.token


def collect(client: FakeClient, session: FakeSession | None = None, monkeypatch=None, **context):  # noqa: ANN001, ANN201
    session = session or FakeSession()
    events: list[tuple[str, dict]] = []
    collector = spa.SharePointAdminCollector()
    collector.session_factory = lambda: session
    if monkeypatch is not None:
        monkeypatch.setattr(spa.time, "sleep", lambda seconds: events.append(("sleep", {"seconds": seconds})))
    result = collector.run({"client": client, "audit_logger": lambda event, message, details=None: events.append(
        (event, details or {})), **context})
    return result, session, events


def section(result):  # noqa: ANN001, ANN201
    return result.payload[spa.OPERATION]


def rest_row(result):  # noqa: ANN001, ANN201
    return next(row for row in result.coverage if row["name"] == spa.OPERATION)


# Selection: opt-in only -------------------------------------------------------------------------------

def test_registered_defined_opt_in_and_in_no_profile_or_preset() -> None:
    definitions = json.loads((ROOT / "configs/collector-definitions.json").read_text())
    presets = json.loads((ROOT / "configs/collector-presets.json").read_text())["presets"]
    permissions = json.loads((ROOT / "configs/collector-permissions.json").read_text())["collector_permissions"]
    assert isinstance(REGISTRY["sharepoint_admin"], spa.SharePointAdminCollector)
    definition = definitions["collectors"]["sharepoint_admin"]
    assert definition["enabled"] is False
    # Only the read-only root site scope: the SharePoint permission never joins the Graph sign-in.
    assert definition["required_permissions"] == spa.SharePointAdminCollector.required_permissions == ["Sites.Read.All"]
    assert permissions["sharepoint_admin"]["graph_scopes"] == ["Sites.Read.All"]
    assert definition["query_plan"] == [spa.ROOT_SITE_OPERATION, spa.OPERATION]
    assert "sharepoint_admin" in definitions["default_order"]
    assert permissions["sharepoint_admin"]["sharepoint_permissions"] == {
        "application": "Sites.FullControl.All", "delegated": "AllSites.FullControl"}
    assert not any("sharepoint_admin" in (preset.get("include") or []) for preset in presets.values())
    assert not any("sharepoint_admin" in profile.default_collectors for profile in PROFILES.values())


def test_only_an_explicit_selection_runs_it() -> None:
    available = json.loads((ROOT / "configs/collector-definitions.json").read_text())["default_order"]
    for profile in PROFILES.values():
        for mode in ("app", "interactive"):
            selected = select_collectors(available=available, profile_default_collectors=profile.default_collectors,
                                         auth_mode=mode)
            assert "sharepoint_admin" not in selected
    assert select_collectors(available=available, explicit_collectors=["sharepoint_admin"]) == ["sharepoint_admin"]


# App mode ---------------------------------------------------------------------------------------------

def test_certificate_run_reads_the_eight_settings_with_one_guarded_get() -> None:
    client = FakeClient()
    result, session, events = collect(client)
    assert result.status == "ok" and result.item_count == 1
    assert section(result) == {"value": [SETTINGS], "status": "ok", "item_count": 1}
    assert client.graph_reads == [("/sites/root", {"$select": "siteCollection"})]
    assert client.app_scopes == [ORIGIN + "/.default"]
    [(url, headers, kwargs)] = session.calls
    assert url == URL
    assert headers["Authorization"] == f"Bearer {APP_TOKEN}"
    assert headers["Accept"] == "application/json;odata=verbose"
    assert set(headers) == {"Authorization", "Accept", "User-Agent"}
    assert kwargs["allow_redirects"] is False and "json" not in kwargs and "data" not in kwargs
    assert session.closed
    graph_row, row = result.coverage
    assert graph_row["type"] == "graph" and graph_row["endpoint"] == "/sites/root" and graph_row["status"] == "ok"
    assert row["type"] == "sharepoint_admin_rest" and row["method"] == "GET"
    assert row["endpoint"] == "https://{tenant}-admin.sharepoint.com/_api/SPO.Tenant" and row["status"] == "ok"
    [(event, details)] = [item for item in events if item[0].startswith("sharepoint_admin_rest")]
    assert event == "sharepoint_admin_rest.request"
    assert details["host"] == "{tenant}-admin.sharepoint.com" and details["path"] == "/_api/SPO.Tenant"
    assert details["method"] == "GET" and details["status_code"] == 200
    # Neither the token nor the tenant's real host reaches the evidence, the coverage or the audit log.
    blob = json.dumps([result.payload, result.coverage, events])
    assert APP_TOKEN not in blob and "contoso" not in blob.lower()


def test_a_run_without_a_certificate_records_a_named_skip_and_sends_nothing() -> None:
    reason = spa.REASON_CERTIFICATE_REQUIRED
    client = FakeClient(mode="none")
    result, session, events = collect(client)
    assert result.status == "ok"  # a named section gap, not a failed collector
    assert section(result)["status"] == "skipped" and section(result)["reason"] == reason
    assert section(result)[SECTION_SCOPED] is True and section(result)["error"] == spa.SKIP_TEXT[reason]
    assert rest_row(result)["reason"] == reason and rest_row(result)[SECTION_SCOPED] is True
    assert result.message == spa.SKIP_TEXT[reason]
    assert client.graph_reads == client.app_scopes == []
    assert session.calls == [] and events == []


def test_the_certificate_skip_text_names_the_certificate_limit() -> None:
    text = spa.SKIP_TEXT[spa.REASON_CERTIFICATE_REQUIRED]
    assert "certificate" in text and "no SharePoint token was requested" in text


def test_a_certificate_token_that_cannot_be_acquired_fails_without_a_request() -> None:
    client = FakeClient(token="")
    result, session, _ = collect(client)
    assert result.status == "partial"
    assert section(result)["status"] == "failed" and section(result)["reason"] == "sharepoint_admin_token_failed"
    assert section(result)["error_class"] == "unauthenticated"
    assert session.calls == []


@pytest.mark.parametrize("token", [
    jwt(aud="https://graph.microsoft.com", appidacr="2"),  # a Graph token never goes to SharePoint
    jwt(aud=ORIGIN, appidacr="1"),  # secret-minted
    jwt(aud=ORIGIN, azpacr="0"),
    jwt(aud=ORIGIN, appidacr="2", scp="AllSites.FullControl"),  # a user token in app mode
    jwt(aud="https://other-admin.sharepoint.com", appidacr="2"),
    "opaque-token",
])
def test_a_token_of_the_wrong_kind_is_never_sent(token) -> None:  # noqa: ANN001
    result, session, _ = collect(FakeClient(token=token))
    assert section(result)["reason"] == "sharepoint_admin_token_refused"
    assert session.calls == []


# The admin host comes from the tenant's own Graph answer ---------------------------------------------

@pytest.mark.parametrize(("site", "prefix"), [
    (ROOT_SITE, "contoso"),
    ({"siteCollection": {"hostname": "a-b1.sharepoint.com"}}, "a-b1"),
    ({"siteCollection": {"hostname": "contoso.onmicrosoft.com"}}, None),  # the initial domain is never a host
    ({"siteCollection": {"hostname": "contoso.sharepoint.us"}}, None),
    ({"siteCollection": {"hostname": "contoso.sharepoint.com."}}, None),
    ({"siteCollection": {"hostname": "contoso.sharepoint.com:443"}}, None),
    ({"siteCollection": {"hostname": " contoso.sharepoint.com"}}, None),
    ({"siteCollection": {"hostname": "a.b.sharepoint.com"}}, None),
    ({"siteCollection": {"hostname": "evil.example/x.sharepoint.com"}}, None),
    ({"siteCollection": {"hostname": "-x.sharepoint.com"}}, None),
    ({"siteCollection": {"hostname": "x_y.sharepoint.com"}}, None),
    ({"siteCollection": {"hostname": "contoso-admin.sharepoint.com"}}, None),
    ({"siteCollection": {"hostname": "contoso-my.sharepoint.com"}}, None),
    ({"siteCollection": {"hostname": "sharepoint.com"}}, None),
    ({"siteCollection": {"hostname": ".sharepoint.com"}}, None),
    ({"siteCollection": {"hostname": None}}, None),
    ({"siteCollection": {}}, None),
    ({"siteCollection": "contoso.sharepoint.com"}, None),
    ({"webUrl": "https://contoso.sharepoint.com"}, None),  # only the named host field counts
    ({}, None),
    ([], None),
])
def test_the_host_prefix_is_the_root_site_sharepoint_hostname(site, prefix) -> None:  # noqa: ANN001
    assert spa.root_site_prefix(site) == prefix


def test_a_renamed_tenant_reads_its_current_sharepoint_host_not_the_initial_domain() -> None:
    # The initial domain stays contoso.onmicrosoft.com after a SharePoint rename; the root site names the new host.
    renamed = "https://fabrikam-admin.sharepoint.com"
    token = jwt(aud=renamed, appidacr="2", roles=["Sites.FullControl.All"])
    client = FakeClient(root_site={"siteCollection": {"hostname": "fabrikam.sharepoint.com"}}, token=token)
    result, session, _ = collect(client)
    assert section(result)["status"] == "ok"
    assert client.app_scopes == [renamed + "/.default"]
    [(url, headers, kwargs)] = session.calls
    assert url == renamed + "/_api/SPO.Tenant" and headers["Authorization"] == f"Bearer {token}"
    assert kwargs["allow_redirects"] is False
    blob = json.dumps([client.app_scopes, session.calls, client.graph_reads])
    assert "contoso" not in blob and "onmicrosoft" not in blob


def test_a_non_object_root_site_answer_fails_the_section() -> None:
    client = FakeClient(root_site=GraphError("Non-dict response from /sites/root"))
    result, session, _ = collect(client)
    assert result.coverage[0]["status"] == "failed"
    assert section(result)["reason"] == "sharepoint_admin_host_unknown" and session.calls == []


@pytest.mark.parametrize("site", [
    {"siteCollection": {"hostname": "contoso.onmicrosoft.com"}},
    {"siteCollection": {"hostname": "contoso.sharepoint.us"}},
    {"id": "constructed"},
])
def test_an_inconclusive_host_is_a_named_skip_and_nothing_is_guessed(site) -> None:  # noqa: ANN001
    client = FakeClient(root_site=site)
    result, session, _ = collect(client)
    assert result.status == "ok"
    assert section(result)["status"] == "skipped" and section(result)["reason"] == spa.REASON_HOST_UNRESOLVED
    assert result.message == spa.SKIP_TEXT[spa.REASON_HOST_UNRESOLVED]
    assert result.coverage[0]["status"] == "ok" and result.coverage[0]["item_count"] == 0
    assert client.app_scopes == [] and session.calls == []


def test_a_failed_root_site_read_fails_the_section_without_a_token() -> None:
    client = FakeClient(root_site=GraphError("denied", status=403))
    result, session, _ = collect(client)
    assert result.status == "partial"
    graph_row = result.coverage[0]
    assert graph_row["status"] == "failed" and graph_row["error_class"] == "insufficient_permissions"
    assert section(result)["reason"] == "sharepoint_admin_host_unknown"
    assert section(result)["error_class"] == "insufficient_permissions"  # the root site read's own class
    assert client.app_scopes == [] and session.calls == []


@pytest.mark.parametrize("environment", ["gcchigh", "dod", "china"])
def test_other_clouds_are_a_named_skip(environment) -> None:  # noqa: ANN001
    client = FakeClient()
    result, session, _ = collect(client, environment=environment)
    assert section(result)["reason"] == spa.REASON_UNSUPPORTED_ENVIRONMENT
    assert client.graph_reads == [] and session.calls == []


# Answers and failures -----------------------------------------------------------------------------------

@pytest.mark.parametrize(("answers", "reason"), [
    ([FakeResponse(403, body=b"{}")], "sharepoint_admin_access_denied"),
    ([FakeResponse(401, body=b"{}")], "sharepoint_admin_unauthenticated"),
    ([FakeResponse(302, body=b"", headers={"Location": "https://evil.example/"})], "redirect_refused"),
    ([FakeResponse(404, body=b"{}")], "resource_not_found"),
    ([FakeResponse(500, body=b"{}")], "sharepoint_admin_http_error"),
    ([FakeResponse(429, body=b"", headers={"Retry-After": "2"}), FakeResponse(429, body=b"")], "sharepoint_admin_throttled"),
    ([FakeResponse(content_type="text/html")], "unexpected_shape"),
    ([FakeResponse(body=b"not json")], "unexpected_shape"),
    ([FakeResponse(body=json.dumps({"value": [SETTINGS]}).encode())], "unexpected_shape"),
    ([FakeResponse(body=json.dumps({"d": {"error": {"code": "x"}}}).encode())], "unexpected_shape"),
    ([FakeResponse(body=json.dumps({"d": {"SharingCapability": 2}}).encode())], "unexpected_shape"),
    ([FakeResponse(payload={**SETTINGS, "DefaultLinkPermission": {"nested": 1}})], "unexpected_shape"),
    ([FakeResponse(payload={**SETTINGS, "DefaultLinkPermission": 1.5})], "unexpected_shape"),
    ([FakeResponse(payload={**SETTINGS, "EmailAttestationReAuthDays": APP_TOKEN})], "unexpected_shape"),
    ([FakeResponse(body=b"\x00" + json.dumps({"d": SETTINGS}).encode())], "unexpected_shape"),
    ([FakeResponse(body=b" " * (spa.MAX_RESPONSE_BYTES + 1))], "response_too_large"),
    ([requests.ConnectionError("connection to contoso-admin.sharepoint.com refused")], "transport_error"),
    ([requests.Timeout("slow")], "timeout"),
])
def test_failures_are_named_with_fixed_text_and_keep_no_evidence(monkeypatch, answers, reason) -> None:  # noqa: ANN001
    from azure_tenant_audit.scuba_assessment import COLLECTOR_ERROR_CLASSES

    result, session, _ = collect(FakeClient(), FakeSession(*answers), monkeypatch)
    assert result.status == "partial"
    assert section(result)["status"] == "failed" and section(result)["value"] == []
    assert section(result)["reason"] == reason
    assert section(result)["error_class"] == spa.ERROR_CLASS_BY_REASON[reason] in COLLECTOR_ERROR_CLASSES
    assert section(result)["error"] == spa.FAILURE_TEXT[reason]
    assert rest_row(result)["status"] == "failed" and rest_row(result)["reason"] == reason
    assert APP_TOKEN not in json.dumps(result.payload) and "contoso" not in json.dumps(result.payload)
    assert all(call[2]["allow_redirects"] is False for call in session.calls)
    assert len(session.calls) == len(answers)  # never a request beyond the one read and its single retry


def test_a_throttled_read_is_retried_once_after_retry_after(monkeypatch) -> None:  # noqa: ANN001
    session = FakeSession(FakeResponse(429, body=b"", headers={"Retry-After": "120"}), FakeResponse())
    result, _, events = collect(FakeClient(), session, monkeypatch)
    assert section(result)["status"] == "ok" and len(session.calls) == 2
    assert ("sleep", {"seconds": spa.MAX_RETRY_AFTER_SECONDS}) in events  # Retry-After is capped
    attempts = [details["attempt"] for event, details in events if event == "sharepoint_admin_rest.request"]
    assert attempts == [1, 2]


def test_absent_fields_stay_absent_and_null_stays_null() -> None:
    payload = {"ODBSharingCapability": 0, "EmailAttestationReAuthDays": None}
    result, _, _ = collect(FakeClient(), FakeSession(FakeResponse(payload=payload)))
    assert section(result)["value"] == [payload]


def test_every_failure_has_fixed_text_and_a_known_error_class() -> None:
    from azure_tenant_audit.scuba_assessment import COLLECTOR_ERROR_CLASSES

    assert set(spa.FAILURE_TEXT) == set(spa.ERROR_CLASS_BY_REASON)
    assert set(spa.ERROR_CLASS_BY_REASON.values()) <= COLLECTOR_ERROR_CLASSES
