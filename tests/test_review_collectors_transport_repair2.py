"""Regression tests for the collectors-transport lane, repair round 2 (redirect retries, response session, folder scope)."""
from __future__ import annotations

import pytest
from support import fake_graph_client, graph_response


@pytest.mark.parametrize("error_name", ["ReadTimeout", "ConnectionError"])
def test_a_transient_failure_on_a_download_redirect_hop_is_retried(monkeypatch, error_name) -> None:
    """R033 (round 2): a timeout on an allowed download hop is retried from Graph, not raised on the first attempt."""
    from requests import exceptions

    client = fake_graph_client(throttle_mode="safe")
    client.sleep = lambda _seconds: None
    signed = "https://reports.office.com/data/download/abc123?sig=SIGNED&se=2026"
    download_failures = [getattr(exceptions, error_name)("blip")]
    sent: list[str] = []

    def _request(method, url, headers=None, timeout=None, **kwargs):  # noqa: ARG001
        sent.append(url.split("?")[0])
        if url.startswith("https://graph.microsoft.com"):
            return graph_response(302, {}, headers={"Location": signed})
        if download_failures:
            raise download_failures.pop(0)
        return graph_response(200, "Report Refresh Date,User Principal Name\n")

    monkeypatch.setattr(client.session, "request", _request)
    assert client.get_content("/reports/getMailboxUsageDetail(period='D7')").startswith("Report Refresh Date")
    # Graph, failed hop, Graph again (a fresh signed link), successful hop.
    assert len(sent) == 4 and sent[0] == sent[2] and sent[1] == sent[3]


class _NamedRecordingAdapter:
    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[str] = []

    def dependency_check(self) -> bool:
        return True

    def run(self, command, log_event=None, session=None, **kwargs):  # noqa: ANN001, ARG002
        self.calls.append(command)
        return {"command": command, "value": [], "duration_ms": 1.0}


def _lab_response(monkeypatch, adapter: _NamedRecordingAdapter) -> None:
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"lab-tenant"})
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")


@pytest.mark.parametrize("organization", [None, "", "not an organisation"])
def test_an_exchange_session_the_adapter_cannot_connect_is_refused_before_any_command(
    tmp_path, monkeypatch, organization
) -> None:
    """R086 (round 2): a session without a usable organisation would run the cmdlet unconnected, so nothing runs."""
    from test_review_collectors_transport_repair import (
        _lab_token,
        _response_blockers,
        _response_config,
    )

    from azure_tenant_audit.response import run_response

    adapter = _NamedRecordingAdapter("powershell_graph")
    _lab_response(monkeypatch, adapter)
    session = {"kind": "exchange_online", "access_token": _lab_token("lab-tenant")}
    if organization is not None:
        session["organization"] = organization
    assert run_response(_response_config(tmp_path, exchange_session=session)) == 1
    assert adapter.calls == []
    assert "session_not_connected" in {b["error_class"] for b in _response_blockers(tmp_path)}


def test_an_adapter_override_that_cannot_carry_the_exchange_session_is_refused(tmp_path, monkeypatch) -> None:
    """R086 (round 2): an allowed m365dsc override would run an Exchange action without the checked session."""
    from test_review_collectors_transport_repair import (
        _response_blockers,
        _response_config,
    )

    from azure_tenant_audit.response import run_response

    adapter = _NamedRecordingAdapter("m365dsc")
    _lab_response(monkeypatch, adapter)
    config = _response_config(tmp_path, adapter_override="m365dsc", allow_adapter_override=True)
    assert run_response(config) == 1
    assert adapter.calls == []
    assert "response_invalid_adapter_override" in {b["error_class"] for b in _response_blockers(tmp_path)}


def test_a_complete_lab_exchange_session_on_the_default_adapter_still_runs(tmp_path, monkeypatch) -> None:
    from test_review_collectors_transport_repair import _response_config

    from azure_tenant_audit.response import run_response

    adapter = _NamedRecordingAdapter("powershell_graph")
    _lab_response(monkeypatch, adapter)
    assert run_response(_response_config(tmp_path)) == 0
    assert adapter.calls


# Least-privileged application permission Microsoft documents for each folder route (Graph API reference pages
# user-list-mailfolders and mailfolder-get, v1.0; mailbox-list-folders, beta). An independent source, not the config.
_DOCUMENTED_FOLDER_GRANTS = (
    ("/users/{id}/mailFolders", "Mail.ReadBasic.All"),
    ("/admin/exchange/mailboxes/{id}/folders", "MailboxFolder.Read.All"),
)


def _documented_grant(path: str) -> str:
    import re

    for route, grant in _DOCUMENTED_FOLDER_GRANTS:
        pattern = "^" + re.escape(route).replace(r"\{id\}", "[^/]+") + "(/|$)"
        if re.search(pattern, path):
            return grant
    raise AssertionError(f"undocumented folder route {path}")


def test_the_declared_folder_scope_is_the_grant_documented_for_the_routes_the_collector_calls(monkeypatch) -> None:
    """R006 (round 2): the shipped consent instructions must name the grant Microsoft documents for the actual calls."""
    import json
    from pathlib import Path
    from urllib.parse import urlparse

    from azure_tenant_audit.collectors.mailbox_forwarding import (
        MailboxForwardingCollector,
    )

    client = fake_graph_client(throttle_mode="safe")
    client.sleep = lambda _seconds: None
    folder_paths: list[str] = []

    def _request(method, url, headers=None, timeout=None, params=None, json=None, **kwargs):  # noqa: ARG001
        path = urlparse(url).path.removeprefix("/v1.0").removeprefix("/beta")
        if path == "/$batch":
            folder_paths.extend(urlparse(item["url"]).path for item in json["requests"])
            return graph_response(200, {"responses": [
                {"id": item["id"], "status": 200, "body": {"id": "AAMkFOLDER", "value": []}} for item in json["requests"]
            ]})
        if path == "/users":
            return graph_response(200, {"value": [{"id": "u1", "mail": "u1@contoso.com", "userType": "Member"}]})
        if path == "/domains":
            return graph_response(200, {"value": [{"id": "contoso.com", "isVerified": True}]})
        if path.endswith("/messageRules"):
            return graph_response(200, {"value": [{"id": "r1", "isEnabled": True, "conditions": {},
                                                   "actions": {"moveToFolder": "AAMkFOLDER"}}]})
        if path.endswith("/mailboxSettings"):
            return graph_response(200, {})
        if "/mailFolders" in path or "/folders" in path:
            folder_paths.append(path)
            return graph_response(200, {"id": "AAMkFOLDER", "value": []})
        raise AssertionError(path)

    monkeypatch.setattr(client.session, "request", _request)
    MailboxForwardingCollector().run({"client": client})
    assert folder_paths, "the folder lookup was not exercised"
    documented = {_documented_grant(path) for path in folder_paths}

    configs = Path(__file__).resolve().parents[1] / "configs"
    entry = json.loads((configs / "collector-permissions.json").read_text(encoding="utf-8"))[
        "collector_permissions"]["mailbox_forwarding"]
    assert documented <= set(entry["optional_graph_scopes"])
    assert documented <= set(MailboxForwardingCollector.optional_permissions)
    # The consent guides name the same grant, so a reader following them can make the calls.
    docs = Path(__file__).resolve().parents[1] / "docs"
    for guide in ("guides/admin-permission-guide.md", "guides/reader-app-permissions.md"):
        text = (docs / guide).read_text(encoding="utf-8")
        assert all(f"`{grant}`" in text for grant in documented), guide


def test_a_failed_redirect_hop_error_keeps_no_signed_url_in_its_context(monkeypatch) -> None:
    """R033/R158 (round 2 review): the re-raised hop error must not hold the original error as its hidden context."""
    from requests.exceptions import ConnectionError as RequestsConnectionError

    client = fake_graph_client(throttle_mode="safe")
    client.sleep = lambda _seconds: None
    signed = "https://reports.office.com/data/download/abc123?sig=SIGNEDQUERY&se=2026"

    def _request(method, url, headers=None, timeout=None, **kwargs):  # noqa: ARG001
        if url.startswith("https://graph.microsoft.com"):
            return graph_response(302, {}, headers={"Location": signed})
        raise RequestsConnectionError(f"could not reach {url}")

    monkeypatch.setattr(client.session, "request", _request)
    with pytest.raises(RequestsConnectionError) as caught:
        client.get_content("/reports/getMailboxUsageDetail(period='D7')")
    chained, seen = caught.value, []
    while chained is not None and chained not in seen:
        seen.append(chained)
        assert "SIGNEDQUERY" not in repr(chained.args)
        chained = chained.__cause__ or chained.__context__
