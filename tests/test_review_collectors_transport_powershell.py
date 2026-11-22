"""R020/R044: a successful PowerShell read whose JSON rows name 'unauthorized' or 'not recognized' is not a failure."""
from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from azure_tenant_audit.adapters import powershell_graph as pg
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector

ROWS = [
    {"Name": "Block unauthorized external sharing", "Disabled": False, "Mode": "Enable"},
    {"Name": "Access denied notice", "Disabled": False, "Mode": "Enable"},
    {"Name": "Sender not recognized warning", "Disabled": True, "Mode": "Enable"},
]


@pytest.fixture
def pwsh(monkeypatch):
    monkeypatch.setattr(pg.shutil, "which", lambda name: "synthetic-pwsh" if name == "pwsh" else None)


@pytest.mark.parametrize(
    "command",
    [",@(Get-DlpComplianceRule | Select-Object Name,Disabled,Mode)", ",@(Get-TransportRule | Select-Object Name,State)"],
)
def test_successful_json_naming_refusal_words_is_read(monkeypatch, pwsh, command) -> None:
    stdout = json.dumps(ROWS)
    monkeypatch.setattr(
        pg.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, stdout=stdout, stderr=""),
    )
    result = pg.PowerShellGraphAdapter().run(command)
    assert "error" not in result, result
    assert [row["Name"] for row in result["value"]] == [row["Name"] for row in ROWS]


def test_a_nonzero_exit_naming_auth_is_still_unauthenticated(monkeypatch, pwsh) -> None:
    monkeypatch.setattr(
        pg.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 1, stdout="", stderr="Unauthorized: access denied"),
    )
    result = pg.PowerShellGraphAdapter().run(",@(Get-TransportRule | Select-Object Name,State)")
    assert result["error_class"] == "command_not_authenticated"


def test_sensitive_read_with_a_policy_named_unauthorized_is_read(monkeypatch, pwsh) -> None:
    row = {"Identity": "Block unauthorized senders", "Name": "Block unauthorized senders", "IsDefault": False,
           "Enabled": True, "EnableTargetedUserProtection": False, "TargetedUserProtectionAction": "NoAction",
           "TargetedUsersToProtect": []}
    data = json.dumps([row]).encode()

    def bounded(*args, **kwargs):
        return SimpleNamespace(stdout=bytearray(data), stderr="", returncode=0, timed_out=False, overflow=False,
                               stdout_total=len(data), stderr_total=0, duration_ms=1)

    monkeypatch.setattr(pg, "_run_bounded", bounded)
    command = dict(ExchangePolicyCollector.command_collectors)["antiPhishPolicies"]
    result = pg.PowerShellGraphAdapter().run(command)
    assert result.get("error_class") is None, result
