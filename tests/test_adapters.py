from __future__ import annotations

import pytest

from azure_tenant_audit.adapters import get_adapter
from azure_tenant_audit.adapters.m365_cli import M365CLIAdapter
from azure_tenant_audit.adapters.m365dsc import M365DSCAdapter
from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter


def test_adapter_registry_keeps_the_retired_m365_cli_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """DEC-108 D2: the CLI for Microsoft 365 adapter resolves for old callers but never starts ``m365``."""
    import subprocess

    from azure_tenant_audit.adapters.m365_cli import M365_CLI_NOT_USED

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no m365 process")))
    adapter = get_adapter("m365_cli")
    assert isinstance(adapter, M365CLIAdapter)
    assert adapter.name == "m365_cli"
    assert adapter.dependency_check() is False
    assert adapter.metadata.tool_dependencies == ()
    response = adapter.run("m365 purview hold list --output json")
    assert response["error"] == M365_CLI_NOT_USED
    assert response["error_class"] == "command_not_found"  # collectors with a Graph fallback still fall back
    refused = adapter.run("m365 purview hold list --output json --secret constructed-canary")
    assert refused["error_class"] == "command_refused"  # the read guard still runs first
    assert "constructed-canary" not in str(refused)


def test_adapter_registry_exposes_powershell_graph_and_m365dsc() -> None:
    graph_adapter = get_adapter("powershell_graph")
    dsc_adapter = get_adapter("m365dsc")
    assert isinstance(graph_adapter, PowerShellGraphAdapter)
    assert isinstance(dsc_adapter, M365DSCAdapter)
    assert graph_adapter.auth_requirements
    assert dsc_adapter.auth_requirements


def test_powershell_graph_adapter_marks_missing_tool_dependency(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda *_, **__: None)

    adapter = PowerShellGraphAdapter()
    result = adapter.run("Get-Date")
    assert result["error_class"] == "command_not_found"


def test_m365dsc_adapter_executes_via_powershell(monkeypatch) -> None:
    payload = {"value": [{"name": "ok"}]}

    class _FakePowerShell:
        def run(self, command, log_event=None):  # noqa: ARG002
            if "Get-Module -ListAvailable" in command:
                return {"value": [{"module_version": "2.26.1015.1", "powershell_version": "7.4.0"}]}
            assert "Invoke-Expression" in command
            assert "-RequiredVersion '2.26.1015.1'" in command
            assert "Install-Module" not in command and "Update-Module" not in command
            return {"value": payload["value"]}

    monkeypatch.setattr("azure_tenant_audit.adapters.m365dsc.shutil.which", lambda *_: True)
    monkeypatch.setattr("azure_tenant_audit.adapters.m365dsc.PowerShellGraphAdapter", lambda: _FakePowerShell())

    adapter = M365DSCAdapter()
    result = adapter.run("Get-M365DSCResource")
    assert result["source"] == "m365dsc"
    assert result["value"] == payload["value"]
    assert result["module_compatibility"]["module_version"] == "2.26.1015.1"
    assert result["module_compatibility"]["export_semantics_verified"] is False


@pytest.mark.parametrize(
    ("version", "error_class"),
    [
        (None, "module_not_found"),
        ("2.26.930.1", "module_incompatible"),
        ("not-a-version", "module_compatibility_unverified"),
    ],
)
def test_m365dsc_blocks_missing_older_or_unverified_modules_before_export(monkeypatch, version, error_class) -> None:
    calls = []

    class _FakePowerShell:
        def run(self, command, log_event=None):  # noqa: ARG002
            calls.append(command)
            assert "Import-Module" not in command
            assert "Invoke-Expression" not in command
            return {"value": [{"module_version": version, "powershell_version": "7.4.0"}]}

    monkeypatch.setattr("azure_tenant_audit.adapters.m365dsc.PowerShellGraphAdapter", lambda: _FakePowerShell())
    result = M365DSCAdapter().run("Export-M365DSCConfiguration")

    assert result["error_class"] == error_class
    assert result["minimum_module_version"] == "2.26.1007.1"
    assert result["export_semantics_verified"] is False
    assert len(calls) == 1


def test_m365dsc_compatibility_probe_preserves_missing_powershell_diagnostic(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda *_, **__: None)
    result = M365DSCAdapter().run("Export-M365DSCConfiguration")

    assert result["error_class"] == "command_not_found"
    assert result["compatibility"] == "unverified"


def test_m365dsc_accepts_baseline_version_without_claiming_export_validation(monkeypatch) -> None:
    class _FakePowerShell:
        def run(self, command, log_event=None):  # noqa: ARG002
            return {"value": [{"module_version": "2.26.1007.1", "powershell_version": "7.4.0"}]}

    monkeypatch.setattr("azure_tenant_audit.adapters.m365dsc.PowerShellGraphAdapter", lambda: _FakePowerShell())
    result = M365DSCAdapter().compatibility_check()

    assert result["compatibility"] == "minimum_version_met"
    assert result["export_semantics_verified"] is False
    assert "error" not in result
