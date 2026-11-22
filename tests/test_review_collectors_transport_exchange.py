"""R047: the whole-tenant mailbox aggregates get a longer command timeout, and a timeout is a named large-tenant gap."""
from __future__ import annotations

import subprocess

from azure_tenant_audit.adapters import powershell_graph as pg
from azure_tenant_audit.collectors import exchange_policy
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector

COMMANDS = dict(ExchangePolicyCollector.command_collectors)
AGGREGATES = {"casMailboxSmtpAuth", "mailboxAuditBypass"}


def test_whole_tenant_enumerations_get_the_long_timeout(monkeypatch) -> None:
    seen: list[float] = []
    monkeypatch.setattr(pg.shutil, "which", lambda name: "synthetic-pwsh" if name == "pwsh" else None)

    def run(argv, **kwargs):
        seen.append(kwargs["timeout"])
        return subprocess.CompletedProcess(argv, 0, stdout='{"Count": 0}', stderr="")

    monkeypatch.setattr(pg.subprocess, "run", run)
    pg.PowerShellGraphAdapter().run(COMMANDS["casMailboxSmtpAuth"])
    pg.PowerShellGraphAdapter().run(COMMANDS["mailboxAuditBypass"])
    pg.PowerShellGraphAdapter().run(COMMANDS["transportConfig"])
    assert seen == [pg.UNBOUNDED_READ_TIMEOUT_SECONDS, pg.UNBOUNDED_READ_TIMEOUT_SECONDS, 120]
    assert pg.UNBOUNDED_READ_TIMEOUT_SECONDS > 180


class _Recording(pg.PowerShellGraphAdapter):
    def run(self, command, log_event=None, session=None, response_transform=None):  # noqa: ANN001
        name = next(key for key, value in COMMANDS.items() if value == command)
        if name in AGGREGATES:
            return {"error": "command_timeout", "error_class": "command_timeout", "command": command}
        return {"value": [], "command": command}


def test_an_aggregate_timeout_is_a_named_large_tenant_gap(monkeypatch) -> None:
    adapter = _Recording()
    monkeypatch.setattr(exchange_policy, "get_adapter", lambda _name: adapter)
    result = ExchangePolicyCollector().run({})
    for name in AGGREGATES:
        row = next(r for r in result.coverage if r["name"] == name)
        assert row["status"] == "failed" and row["reason"] == exchange_policy.REASON_LARGE_TENANT_AGGREGATE_TIMEOUT
    assert next(r for r in result.coverage if r["name"] == "transportRules").get("reason") is None
