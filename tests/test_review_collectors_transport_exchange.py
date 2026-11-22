"""R047: the whole-tenant mailbox aggregates get a longer command timeout, and a timeout is a named large-tenant gap."""
from __future__ import annotations

import subprocess

from azure_tenant_audit.adapters import powershell_graph as pg
from azure_tenant_audit.collectors import exchange_policy
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector

COMMANDS = dict(ExchangePolicyCollector.command_collectors)
AGGREGATES = {"casMailboxSmtpAuth", "mailboxAuditBypass"}


def test_adapter_honours_a_per_command_timeout(monkeypatch) -> None:
    seen: list[float] = []
    monkeypatch.setattr(pg.shutil, "which", lambda name: "synthetic-pwsh" if name == "pwsh" else None)

    def run(argv, **kwargs):
        seen.append(kwargs["timeout"])
        return subprocess.CompletedProcess(argv, 0, stdout='{"Count": 0}', stderr="")

    monkeypatch.setattr(pg.subprocess, "run", run)
    pg.PowerShellGraphAdapter().run(COMMANDS["casMailboxSmtpAuth"], timeout=600)
    pg.PowerShellGraphAdapter().run(COMMANDS["casMailboxSmtpAuth"])
    assert seen == [600, 120]


class _Recording(pg.PowerShellGraphAdapter):
    def __init__(self) -> None:
        self.timeouts: dict[str, float | None] = {}

    def run(self, command, log_event=None, session=None, response_transform=None, timeout=None):  # noqa: ANN001
        name = next(key for key, value in COMMANDS.items() if value == command)
        self.timeouts[name] = timeout
        if name in AGGREGATES:
            return {"error": "command_timeout", "error_class": "command_timeout", "command": command}
        return {"value": [], "command": command}


def test_aggregates_get_the_long_timeout_and_a_named_gap(monkeypatch) -> None:
    adapter = _Recording()
    monkeypatch.setattr(exchange_policy, "get_adapter", lambda _name: adapter)
    result = ExchangePolicyCollector().run({})
    for name in AGGREGATES:
        assert adapter.timeouts[name] == exchange_policy.AGGREGATE_COMMAND_TIMEOUT_SECONDS > 180
        row = next(r for r in result.coverage if r["name"] == name)
        assert row["status"] == "failed" and row["reason"] == exchange_policy.REASON_LARGE_TENANT_AGGREGATE_TIMEOUT
    assert adapter.timeouts["transportRules"] is None
