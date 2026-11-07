from __future__ import annotations

import subprocess
import pytest
from types import SimpleNamespace

from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
from azure_tenant_audit.collectors.exchange_policy import EXCHANGE_ONLINE_SCOPE, ExchangePolicyCollector, _exchange_session


class _Client:
    def __init__(self, token: str | None, domains: list[dict]) -> None:
        self.token = token
        self.domains = domains
        self.scopes: list[str] = []

    def app_token_for(self, scope: str) -> str | None:
        self.scopes.append(scope)
        return self.token

    def get_all(self, path: str, params=None):  # noqa: ANN001
        assert path == "/domains"
        return self.domains


def test_exchange_session_uses_initial_domain_and_exchange_scope() -> None:
    client = _Client("token-value", [{"id": "halcyon.example", "isInitial": False}, {"id": "halcyon.onmicrosoft.com", "isInitial": True}])

    session = _exchange_session(client, None)

    assert session == {"kind": "exchange_online", "access_token": "token-value", "organization": "halcyon.onmicrosoft.com"}
    assert client.scopes == [EXCHANGE_ONLINE_SCOPE]


def test_exchange_session_absent_without_app_token() -> None:
    assert _exchange_session(_Client(None, []), None) == {"kind": "none"}
    assert _exchange_session(object(), None) == {"kind": "none"}


def _capture_run(monkeypatch, stdout: str = "[]", stderr: str = "", returncode: int = 0):  # noqa: ANN001
    calls: list[dict] = []

    def fake_run(argv, **kwargs):  # noqa: ANN001
        calls.append({"argv": argv, "env": kwargs.get("env") or {}})
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr("azure_tenant_audit.adapters.powershell_graph.shutil.which", lambda name: "/usr/bin/pwsh")
    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_session_token_travels_in_environment_not_argv(monkeypatch) -> None:  # noqa: ANN001
    calls = _capture_run(monkeypatch, stdout='[{"Name": "Default"}]')
    session = {"kind": "exchange_online", "access_token": "secret-token", "organization": "halcyon.onmicrosoft.com"}

    result = PowerShellGraphAdapter().run("Get-RemoteDomain | Select-Object Name", session=session)

    assert result["value"] == [{"Name": "Default"}]
    script = calls[0]["argv"][-1]
    assert "Connect-ExchangeOnline -AccessToken $env:AUDITEX_EXO_ACCESS_TOKEN -Organization 'halcyon.onmicrosoft.com'" in script
    assert "secret-token" not in " ".join(calls[0]["argv"])
    assert calls[0]["env"]["AUDITEX_EXO_ACCESS_TOKEN"] == "secret-token"


def test_untrusted_organization_is_never_interpolated(monkeypatch) -> None:  # noqa: ANN001
    calls = _capture_run(monkeypatch)
    session = {"kind": "exchange_online", "access_token": "t", "organization": "x.onmicrosoft.com'; Remove-Item -Recurse /"}

    PowerShellGraphAdapter().run("Get-RemoteDomain", session=session)

    assert "Connect-ExchangeOnline" not in calls[0]["argv"][-1]
    assert "AUDITEX_EXO_ACCESS_TOKEN" not in calls[0]["env"]


def test_missing_session_is_labelled_not_command_not_found(monkeypatch) -> None:  # noqa: ANN001
    _capture_run(monkeypatch, stdout="", stderr="Get-TransportRule: The term 'Get-TransportRule' is not recognized", returncode=1)

    without_session = PowerShellGraphAdapter().run("Get-TransportRule", session={"kind": "none"})
    plain = PowerShellGraphAdapter().run("Get-Unknown")

    assert without_session["error_class"] == "session_not_connected"
    assert plain["error_class"] == "command_not_found"


def test_delegated_and_token_clients_cannot_construct_an_exchange_session(monkeypatch):
    from azure_tenant_audit.config import AuthConfig
    from azure_tenant_audit.graph import GraphClient

    for mode, token in (("interactive", None), ("azure_cli", "constructed"), ("access_token", "constructed")):
        client = GraphClient(AuthConfig(tenant_id="constructed", client_id="constructed", auth_mode=mode,
                                        access_token=token, client_secret=None))
        monkeypatch.setattr(client, "get_all", lambda *args, **kwargs: pytest.fail("No domain request without an app token"))
        assert _exchange_session(client, None) == {"kind": "none"}


_LIST_COMMANDS = [(name, command) for name, command in ExchangePolicyCollector.command_collectors
                  if command.startswith(',@(')]


@pytest.mark.parametrize('name,command', _LIST_COMMANDS, ids=[name for name, _ in _LIST_COMMANDS])
@pytest.mark.parametrize('stdout', ['', '[]'])
def test_empty_exchange_lists_through_real_adapter(monkeypatch, name, command, stdout):
    calls = _capture_run(monkeypatch, stdout=stdout)
    result = PowerShellGraphAdapter().run(command)
    assert result['value'] == [] and 'error' not in result
    assert command in calls[0]['argv'][-1]
    assert "$ErrorActionPreference = 'Stop'" in calls[0]['argv'][-1]


@pytest.mark.parametrize('name,command', _LIST_COMMANDS, ids=[name for name, _ in _LIST_COMMANDS])
@pytest.mark.parametrize('returncode,stderr', [(1, ''), (0, 'Access denied'), (0, 'Get-Read: constructed read error')])
def test_empty_failed_exchange_lists_stay_failures(monkeypatch, name, command, returncode, stderr):
    _capture_run(monkeypatch, stdout='', stderr=stderr, returncode=returncode)
    result = PowerShellGraphAdapter().run(command)
    assert result['error_class'] in {'command_error', 'command_not_authenticated'}
    assert 'value' not in result


_REQUIRED_ANSWERS = {'adminAuditLogConfig', 'organizationAuditConfig', 'mailboxAuditBypass',
                     'transportConfig', 'casMailboxSmtpAuth', 'acceptedDomains', 'remoteDomains',
                     'sharingPolicy', 'malwareFilterPolicy', 'dkimSigningConfig', 'atpPolicyForO365',
                     'antiPhishPolicies', 'hostedContentFilterPolicies', 'hostedConnectionFilterPolicy'}


def test_only_legitimately_empty_exchange_collections_are_wrapped():
    for name, command in ExchangePolicyCollector.command_collectors:
        assert command.startswith(',@(') == (name not in _REQUIRED_ANSWERS)


@pytest.mark.parametrize('name', sorted(_REQUIRED_ANSWERS))
def test_empty_required_answer_is_still_an_error(monkeypatch, name):
    _capture_run(monkeypatch, stdout='')
    command = dict(ExchangePolicyCollector.command_collectors)[name]
    assert PowerShellGraphAdapter().run(command)['error_class'] == 'command_output_empty'


@pytest.mark.parametrize('wrapped', [False, True])
def test_exit_zero_json_with_stderr_warning_preserves_exchange_evidence(monkeypatch, wrapped):
    command = 'Get-InboundConnector | Select-Object Name'
    if wrapped:
        command = f',@({command})'
    _capture_run(monkeypatch, stdout='[{"Name":"constructed"}]', stderr='constructed warning')
    assert PowerShellGraphAdapter().run(command)['value'] == [{'Name': 'constructed'}]


@pytest.mark.parametrize('list_stdout,stderr', [('', ''), ('[]', ''), ('[]', 'constructed warning')])
def test_real_adapter_empty_lists_keep_exchange_collector_ok(monkeypatch, list_stdout, stderr):
    required_commands = {command for _, command in ExchangePolicyCollector.command_collectors
                         if not command.startswith(',@(')}
    calls = []

    def completed(argv, **kwargs):
        calls.append(argv[-1])
        stdout = '{"Count":0}' if any(command in argv[-1] for command in required_commands) else list_stdout
        return SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)

    monkeypatch.setattr('azure_tenant_audit.adapters.powershell_graph.shutil.which', lambda _: '/usr/bin/pwsh')
    monkeypatch.setattr(subprocess, 'run', completed)
    monkeypatch.setattr('azure_tenant_audit.collectors.exchange_policy.get_adapter', lambda _: PowerShellGraphAdapter())
    result = ExchangePolicyCollector().run({'client': _Client(
        'constructed-token', [{'id': 'constructed.onmicrosoft.com', 'isInitial': True}],
    )})
    assert result.status == 'ok'
    assert result.payload['mailboxForwarding']['value'] == []
    assert all(row['status'] == 'ok' or row.get('section_scoped') for row in result.coverage)
    assert len(calls) == len(ExchangePolicyCollector.command_collectors) - 1
