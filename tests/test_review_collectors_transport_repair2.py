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
