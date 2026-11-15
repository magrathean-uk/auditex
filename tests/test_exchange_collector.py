"""The CLI for Microsoft 365 Exchange collector is retired (DEC-108 D2): it reads nothing and records named skips."""
from __future__ import annotations

import subprocess

import pytest

from azure_tenant_audit.collectors.exchange import (
    M365_CLI_NOT_USED_TEXT,
    REASON_M365_CLI_NOT_USED,
    ExchangeCollector,
)


class _NoGraph:
    def get_all(self, path, params=None):  # noqa: ARG002
        raise AssertionError("the retired Exchange collector reads nothing")


def test_exchange_collector_records_every_operation_as_a_named_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no m365 process")))

    result = ExchangeCollector().run({"audit_logger": None, "client": _NoGraph()})

    assert result.status == "ok" and result.item_count == 0
    assert result.message == M365_CLI_NOT_USED_TEXT and "exchange_policy" in result.message
    assert list(result.payload) == [
        "exchangeConnectivityCheck", "exchangeTenantInfo", "mailboxCount", "mailboxQuotaStatus",
        "mailboxStorage", "mailActivityCounts", "roomLists",
    ]
    assert result.coverage is not None and len(result.coverage) == 7
    for row in result.coverage:
        assert (row["status"], row["reason"], row["item_count"]) == ("skipped", REASON_M365_CLI_NOT_USED, 0)
        assert "command" not in row
    assert {name for name, row in result.payload.items() if row["status"] == "skipped"} == set(result.payload)
    assert {row["name"]: row["optional"] for row in result.coverage}["roomLists"] is True
