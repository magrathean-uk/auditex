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
    from test_review_collectors_transport_repair import _lab_token, _response_blockers, _response_config

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
    from test_review_collectors_transport_repair import _response_blockers, _response_config

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
