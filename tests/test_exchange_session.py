from __future__ import annotations

import subprocess
from types import SimpleNamespace

from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
from azure_tenant_audit.collectors.exchange_policy import EXCHANGE_ONLINE_SCOPE, _exchange_session


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
