"""The shared read-verb allowlist the three command adapters apply before they execute anything."""
from __future__ import annotations

from typing import Any

import pytest

from azure_tenant_audit.adapters import ADAPTERS
from azure_tenant_audit.adapters.m365_cli import M365CLIAdapter
from azure_tenant_audit.adapters.m365dsc import COMPATIBILITY_SCRIPT, M365DSCAdapter
from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
from azure_tenant_audit.adapters.read_guard import (
    CommandRefused,
    VettedCommand,
    check_command,
    classify_command,
    words_are_read,
)
from azure_tenant_audit.collectors.exchange import ExchangeCollector
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
from azure_tenant_audit.collectors.teams_policy import TeamsPolicyCollector
from azure_tenant_audit.response import RESPONSE_ACTIONS


def _shipped_powershell_commands() -> list[str]:
    commands = [command for _, command in ExchangePolicyCollector.command_collectors]
    commands += [command for _, command in TeamsPolicyCollector.command_collectors]
    for action in RESPONSE_ACTIONS.values():
        if action.adapter == "powershell_graph":
            commands += [template.format(target="a@contoso.com", since="2026-01-01T00:00:00Z", until="2026-01-02T00:00:00Z") for template in action.commands]
    commands.append(COMPATIBILITY_SCRIPT)
    return commands


def _shipped_m365_commands() -> list[str]:
    from azure_tenant_audit.collectors.ediscovery import EDiscoveryCollector
    from azure_tenant_audit.collectors.purview import PurviewCollector

    commands: list[str] = []
    for collector in (PurviewCollector, EDiscoveryCollector, ExchangeCollector):
        for entry in collector.command_collectors:
            variants = entry.get("commands") if isinstance(entry, dict) else None
            commands += list(variants or [entry.get("command", "")] if isinstance(entry, dict) else [])
    for action in RESPONSE_ACTIONS.values():
        if action.adapter == "m365_cli":
            commands += list(action.commands)
    commands.append("m365 status --output json")
    commands.append("m365 connection list --output json")
    return [command for command in commands if command]


@pytest.mark.parametrize("command", _shipped_powershell_commands())
def test_every_shipped_powershell_command_is_a_read(command: str) -> None:
    assert check_command("powershell_graph", command)


@pytest.mark.parametrize("command", _shipped_m365_commands())
def test_every_shipped_m365_command_is_a_read(command: str) -> None:
    assert check_command("m365_cli", command)


@pytest.mark.parametrize(
    "command",
    [
        "Remove-Mailbox -Identity alice",
        "Set-Mailbox alice -ForwardingSmtpAddress evil@example.com",
        "New-InboxRule -Mailbox alice -Name x",
        "Add-MailboxPermission -Identity a -User b -AccessRights FullAccess",
        "Enable-Mailbox alice",
        "Disable-Mailbox alice",
        "Update-User x",
        "Invoke-MgGraphRequest -Method DELETE -Uri https://graph.microsoft.com/v1.0/users/u1",
        "Connect-MgGraph",
        "Import-Module Foo",
        "Start-Process calc",
        "Out-File x.txt",
        "Export-Csv x.csv",
        "Export-M365DSCConfiguration",  # an export is only allowed through the DSC adapter
        "Get-Mailbox; Remove-Mailbox alice",
        "Get-Mailbox | Remove-Mailbox",
        "Get-Mailbox && Set-Mailbox alice",
        "Get-Mailbox || Set-Mailbox alice",
        "Get-Mailbox\nRemove-Mailbox alice",
        "$x = Remove-Mailbox alice",
        "Get-Mailbox -Identity (Remove-Mailbox alice)",
        "Get-Mailbox -Identity $(Remove-Mailbox alice)",
        'Get-Mailbox -Identity "$(Remove-Mailbox alice)"',
        "Get-Mailbox | Where-Object { Remove-Mailbox $_ }",
        "Get-Mailbox | ForEach-Object Delete",
        "Invoke-Expression 'Remove-Mailbox alice'",
        "iex 'Remove-Mailbox alice'",
        "rm -rf /tmp/x",
        "Remove-Item x",
        "& $cmd",
        "& 'Remove-Mailbox' alice",
        ". ./other.ps1",
        "Get-Mailbox # ; Remove-Mailbox alice",
        "Get-Mailbox `\nRemove-Mailbox alice",
        "Get-Mailbox > out.txt",
        "[System.IO.File]::Delete('x')",
        "(Get-Item x).Delete()",
        "Get-Item x | Select-Object @{n='a';e={ $_.Delete() }}",
        "Get-Mailbox @'\nRemove-Mailbox x\n'@",
        "Get-Mailbox 'unterminated",
        "pwsh -Command Remove-Mailbox alice",
        "",
        "   ",
    ],
)
def test_powershell_write_or_obfuscated_commands_are_refused(command: str) -> None:
    with pytest.raises(CommandRefused):
        check_command("powershell_graph", command)


@pytest.mark.parametrize(
    "command",
    [
        "m365 login",
        "m365 logout",
        "m365 purview auditlog export create --output json --help",
        "m365 purview audit-log search --output json",
        "m365 purview auditlog search --output json",
        "m365 purview",
        "m365 request --method post --url /users",
        "m365 spo site remove --url https://x",
        "m365 aad user set --id u1",
        "m365 outlook report",
        "m365",
        "/bin/sh -c 'rm -rf /'",
        "rm -rf /",
        "m365 'unterminated",
    ],
)
def test_m365_write_or_unknown_commands_are_refused(command: str) -> None:
    with pytest.raises(CommandRefused):
        check_command("m365_cli", command)


def test_export_is_allowed_only_for_the_dsc_adapter() -> None:
    command = "Export-M365DSCConfiguration -Components @('AADUser') -Path 'C:\\export'"
    assert check_command("m365dsc", command) == ("Export-M365DSCConfiguration",)
    with pytest.raises(CommandRefused):
        check_command("powershell_graph", command)
    with pytest.raises(CommandRefused):
        check_command("m365dsc", "Export-Csv x.csv")
    with pytest.raises(CommandRefused):
        check_command("m365dsc", "Remove-M365DSCResource x")


def test_unknown_adapter_is_refused() -> None:
    with pytest.raises(CommandRefused):
        check_command("bash", "ls")


def test_classify_and_words_are_read_agree_with_the_guard() -> None:
    assert classify_command("m365_cli", "m365 purview dlp policy list --output json").read_only
    assert not classify_command("m365_cli", "m365 purview auditlog export create").read_only
    assert words_are_read("powershell_graph", ["Get-RemoteDomain", "Select-Object"])
    assert not words_are_read("powershell_graph", ["Get-RemoteDomain", "Remove-Mailbox"])
    assert words_are_read("m365dsc", ["Export-M365DSCConfiguration"])
    assert not words_are_read("powershell_graph", ["Export-M365DSCConfiguration"])
    assert words_are_read("m365_cli", ["outlook", "report", "mailboxusagedetail"])
    assert not words_are_read("m365_cli", [])


def _forbid_execution(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    started: list[Any] = []

    def _fail(*args: Any, **kwargs: Any) -> Any:  # pragma: no cover - reached only if the guard is bypassed
        started.append(args)
        raise AssertionError("a refused command must not reach subprocess")

    monkeypatch.setattr("subprocess.run", _fail)
    monkeypatch.setattr("shutil.which", lambda name, *a, **k: f"/usr/bin/{name}")
    return started


@pytest.mark.parametrize(
    ("adapter", "command"),
    [
        (M365CLIAdapter(), "m365 spo site remove --url https://x"),
        (M365CLIAdapter(), "rm -rf /"),
        (PowerShellGraphAdapter(), "Remove-Mailbox -Identity alice"),
        (PowerShellGraphAdapter(), "Get-Mailbox; Set-Mailbox alice -ForwardingSmtpAddress evil@example.com"),
        (M365DSCAdapter(), "Remove-M365DSCResource x"),
        (M365DSCAdapter(), "Get-M365DSCResource; Invoke-Expression 'x'"),
    ],
)
def test_adapters_refuse_a_write_before_execution_and_log_it(monkeypatch, adapter, command) -> None:
    started = _forbid_execution(monkeypatch)
    events: list[tuple[str, dict[str, Any]]] = []

    result = adapter.run(command, log_event=lambda event, message, details=None: events.append((event, dict(details or {}))))

    assert started == []
    assert result["error_class"] == "command_refused"
    assert result["error"].startswith("command_refused:")
    assert result["refusal_reason"]
    assert [event for event, _ in events] == ["command.refused"]
    assert events[0][1]["adapter"] == adapter.name
    assert events[0][1]["reason"] == result["refusal_reason"]


def test_every_registered_adapter_has_a_guard() -> None:
    for name, adapter in ADAPTERS.items():
        with pytest.raises(CommandRefused):
            check_command(name, "Remove-Everything" if name != "m365_cli" else "m365 spo site remove")
        assert adapter.name == name


def test_m365_adapter_runs_an_allowed_read_and_records_its_command_words(monkeypatch) -> None:
    import subprocess

    calls: list[list[str]] = []

    def _run(cmd, **kwargs):  # noqa: ANN001, ARG001
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout='{"value": [{"id": "1"}]}', stderr="")

    monkeypatch.setattr("subprocess.run", _run)
    monkeypatch.setattr("shutil.which", lambda name, *a, **k: f"/usr/bin/{name}")
    events: list[tuple[str, dict[str, Any]]] = []

    result = M365CLIAdapter().run(
        "m365 purview dlp policy list --output json",
        log_event=lambda event, message, details=None: events.append((event, dict(details or {}))),
    )

    assert result["value"] == [{"id": "1"}]
    assert calls and calls[0][1:5] == ["purview", "dlp", "policy", "list"]
    started = [details for event, details in events if event == "command.started"][0]
    assert started["adapter"] == "m365_cli"
    assert started["command_words"] == ["purview", "dlp", "policy", "list"]


def test_powershell_adapter_runs_an_allowed_read(monkeypatch) -> None:
    import subprocess

    captured: list[list[str]] = []

    def _run(cmd, **kwargs):  # noqa: ANN001, ARG001
        captured.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout='[{"Name": "r1"}]', stderr="")

    monkeypatch.setattr("subprocess.run", _run)
    monkeypatch.setattr("shutil.which", lambda name, *a, **k: f"/usr/bin/{name}")
    events: list[tuple[str, dict[str, Any]]] = []

    result = PowerShellGraphAdapter().run(
        "Get-RemoteDomain | Select-Object Name,DomainName",
        log_event=lambda event, message, details=None: events.append((event, dict(details or {}))),
    )

    assert result["value"] == [{"Name": "r1"}]
    assert "Get-RemoteDomain | Select-Object Name,DomainName | ConvertTo-Json" in captured[0][-1]
    started = [details for event, details in events if event == "command.started"][0]
    assert started["command_words"] == ["Get-RemoteDomain", "Select-Object"]


def test_dsc_wrapper_is_vetted_once_and_logged_as_the_callers_command(monkeypatch) -> None:
    import subprocess

    scripts: list[str] = []

    def _run(cmd, **kwargs):  # noqa: ANN001, ARG001
        scripts.append(cmd[-1])
        if "Get-Module -ListAvailable" in cmd[-1]:
            return subprocess.CompletedProcess(
                cmd, 0, stdout='{"module_version": "2.26.1015.1", "powershell_version": "7.4.0"}', stderr=""
            )
        return subprocess.CompletedProcess(cmd, 0, stdout='[{"Component": "AADUser"}]', stderr="")

    monkeypatch.setattr("subprocess.run", _run)
    monkeypatch.setattr("shutil.which", lambda name, *a, **k: f"/usr/bin/{name}")
    events: list[tuple[str, dict[str, Any]]] = []

    result = M365DSCAdapter().run(
        "Export-M365DSCConfiguration -Components @('AADUser')",
        log_event=lambda event, message, details=None: events.append((event, dict(details or {}))),
    )

    assert result["value"] == [{"Component": "AADUser"}]
    assert any("Invoke-Expression" in script and "-RequiredVersion '2.26.1015.1'" in script for script in scripts)
    started = [details for event, details in events if event == "command.started"]
    dsc = [details for details in started if details["adapter"] == "m365dsc"]
    assert len(dsc) == 1
    assert dsc[0]["command"].startswith("Export-M365DSCConfiguration")
    assert dsc[0]["command_words"] == ["Export-M365DSCConfiguration"]
    assert "Invoke-Expression" not in dsc[0]["command"]
    assert not [event for event, _ in events if event == "command.refused"]


def test_vetted_command_is_a_str_that_carries_what_was_checked() -> None:
    vetted = VettedCommand("Import-Module X; Invoke-Expression 'Get-Foo'", vetted_text="Get-Foo", source_adapter="m365dsc", command_words=("Get-Foo",))

    assert isinstance(vetted, str)
    assert vetted.vetted_text == "Get-Foo"
    assert vetted.command_words == ("Get-Foo",)
    # A plain string with the same text is still refused: only the adapter that vetted it can mark it.
    with pytest.raises(CommandRefused):
        check_command("powershell_graph", str(vetted))


def test_refusal_reasons_are_redacted_and_clipped() -> None:
    jwt = ".".join(["eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJ1c2VyIn0", "c2lnbmF0dXJlLXNpZ25hdHVyZQ"])  # built at runtime: not a literal token
    with pytest.raises(CommandRefused) as caught:
        check_command("powershell_graph", f"{jwt} -Foo")
    assert jwt not in caught.value.reason
    assert "redacted" in caught.value.reason

    with pytest.raises(CommandRefused) as long:
        check_command("powershell_graph", "x" * 500)
    assert len(long.value.reason) <= 160


# --- bypasses found in review ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "Get-Mailbox\rSet-Mailbox x -ForwardingSmtpAddress a@b.c",  # CR ends a statement in PowerShell
        "Get-Mailbox\r\nSet-Mailbox x -ForwardingSmtpAddress a@b.c",
        "Get-Mailbox\r\rRemove-Mailbox x",
        "$x = Get-Mailbox\rRemove-Mailbox $x",
    ],
)
def test_carriage_return_is_a_statement_separator(command: str) -> None:
    with pytest.raises(CommandRefused):
        check_command("powershell_graph", command)


def test_reads_separated_by_carriage_returns_or_crlf_are_still_allowed() -> None:
    assert check_command("powershell_graph", "Get-RemoteDomain\r\n") == ("Get-RemoteDomain",)
    assert check_command("powershell_graph", "Get-RemoteDomain\r\nGet-AcceptedDomain") == ("Get-RemoteDomain", "Get-AcceptedDomain")
    assert check_command("powershell_graph", "Get-RemoteDomain\rGet-AcceptedDomain") == ("Get-RemoteDomain", "Get-AcceptedDomain")
    assert check_command("powershell_graph", "Get-RemoteDomain |\r\n  Select-Object Name") == ("Get-RemoteDomain", "Select-Object")


@pytest.mark.parametrize(
    "command",
    [
        "Get-Mailbox -Identity 'a’; Set-Mailbox y -ForwardingSmtpAddress z@z.z; ’b'",  # right single quote closes a string
        "Get-Mailbox -Identity ‘a’; Set-Mailbox y",
        "Get-Mailbox -Identity “a”; Remove-Mailbox y",
        "Get-Mailbox -Identity „a“; Remove-Mailbox y",
        "Get-Mailbox\u0085Set-Mailbox x",  # NEL is a line break
        "Get-Mailbox Set-Mailbox x",
        "Get-Mailbox Set-Mailbox x",
        "Get-Mailbox –Identity x",  # en dash is a parameter dash in PowerShell
        "Get-Mailbox -Identity x",
        "Get-Mailbox\x00Set-Mailbox x",
        "Get-Mailbox\x0bSet-Mailbox x",
        "Get-Mailbox\x0cSet-Mailbox x",
        "Get-Mailbox\x1cSet-Mailbox x",
        "Get-Mailbox\x7fSet-Mailbox x",
    ],
)
def test_non_ascii_and_control_characters_are_refused_in_powershell(command: str) -> None:
    with pytest.raises(CommandRefused) as caught:
        check_command("powershell_graph", command)
    assert "not allowed" in caught.value.reason


@pytest.mark.parametrize(
    "command",
    [
        "m365 status --output json’",
        "m365 purview dlp policy list ––output json",
        "m365 purview dlp policy list --output json",
        "m365\x00 status",
        "m365 status\x0b--output json",
    ],
)
def test_non_ascii_and_control_characters_are_refused_in_m365(command: str) -> None:
    with pytest.raises(CommandRefused):
        check_command("m365_cli", command)
    with pytest.raises(CommandRefused):
        check_command("m365_cli", command.split(" "))  # the list form is checked too


def test_plain_ascii_with_tabs_and_newlines_is_unaffected() -> None:
    assert check_command("powershell_graph", "Get-RemoteDomain\t|\tSelect-Object Name\n")
    assert check_command("m365_cli", "m365 status\t--output json")


@pytest.mark.parametrize(
    "command",
    [
        "m365 spo list --webUrl https://x remove",  # the CLI resolves this to `spo list remove`
        "m365 spo list --webUrl=https://x remove",
        "m365 spo list -- remove",
        "m365 spo list --verbose remove",  # a flag takes no value, so `remove` is a stray word
        "m365 spo list --help remove",
        "m365 spo list --output json remove",
        "m365 purview auditlog list --output json --top 100 delete",
        "m365 status --output",  # a value option needs a value
        "m365 status --output --verbose",
        "m365 status --output=",
        "m365 status --verbose=remove",
        "m365 status --webUrl https://x",  # options outside the allowlist
        "m365 status --query value",
        "m365 status --confirm",
        "m365 status -x",
        "m365 status --",
        "m365 status -- --output json",
        "m365 status json",
        "m365 spo list/remove",
        "m365 spo$IFS list",
    ],
)
def test_m365_option_parsing_cannot_extend_the_command(command: str) -> None:
    with pytest.raises(CommandRefused):
        check_command("m365_cli", command)


@pytest.mark.parametrize(
    "command",
    [
        "m365 status --output json",
        "m365 status --output=json",
        "m365 status -o json",
        "m365 status --verbose",
        "m365 status --debug --output json",
        "m365 purview auditlog list --output json --help",
        "m365 purview auditlog list -h",
        "m365 purview auditlog list --output json --top 100",
        "m365 outlook report mailboxusagedetail --period D30 --output json",
        "m365 outlook report mailboxusagedetail --period=D30",
        "m365 tenant info get",
    ],
)
def test_m365_reads_with_known_options_are_allowed(command: str) -> None:
    assert check_command("m365_cli", command)


@pytest.mark.parametrize(
    "command",
    [
        "$m = Get-Item x; $m.'Delete'()",
        "Get-Item x | Where-Object { $_.'Delete'() }",
        "$m.\"Delete\"()",
        "$f.$n()",
        "$f.${n}()",
        "(Get-Item x).('Delete')()",
        "(Get-Item x).$name()",
        "$m.[0]",
        "$m.{x}",
        "$m.@x",
        "$m.($n)",
    ],
)
def test_dynamic_member_access_is_refused(command: str) -> None:
    with pytest.raises(CommandRefused):
        check_command("powershell_graph", command)


def test_ordinary_member_access_and_string_helpers_are_still_allowed() -> None:
    assert check_command(
        "powershell_graph",
        "Get-Mailbox | Where-Object { $_.PrimarySmtpAddress.ToString().Trim().ToLower() -eq 'a@b.test' } | Select-Object Name",
    ) == ("Get-Mailbox", "Where-Object", "Select-Object")
    assert check_command("powershell_graph", "Get-Foo | Select-Object -First 1")


def test_m365_adapter_refuses_a_stray_word_before_execution(monkeypatch) -> None:
    started = _forbid_execution(monkeypatch)

    result = M365CLIAdapter().run("m365 spo list --webUrl https://x remove")

    assert started == []
    assert result["error_class"] == "command_refused"
