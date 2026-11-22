"""Named-tenant guards: the az seeders must refuse to write outside the configured lab tenant."""
from __future__ import annotations

import base64
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
LAB_TENANT = "11111111-1111-1111-1111-111111111111"
OTHER_TENANT = "99999999-9999-9999-9999-999999999999"
ZERO_TENANT = "00000000-0000-0000-0000-000000000000"


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fake_jwt(tid: str) -> str:
    def part(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{part({'alg': 'none'})}.{part({'tid': tid, 'appid': 'lab'})}.sig"


class FakeResponse:
    def __init__(self, status: int, body: dict) -> None:
        self.status_code = status
        self.ok = 200 <= status < 300
        self._body = body
        self.text = json.dumps(body)
        self.headers: dict = {}

    def json(self) -> dict:
        return self._body


class RecordingGraph:
    def __init__(self, org_id: str) -> None:
        self.org_id = org_id
        self.calls: list[tuple[str, str]] = []

    def __call__(self, session, method, url, json=None, timeout=None, **_):  # noqa: A002
        self.calls.append((method.upper(), url))
        if method.upper() == "GET":
            if "/organization" in url:
                return FakeResponse(200, {"value": [{"id": self.org_id}]})
            return FakeResponse(200, {"value": []})
        return FakeResponse(201, {"id": "22222222-2222-2222-2222-222222222222"})

    @property
    def writes(self) -> list[tuple[str, str]]:
        return [call for call in self.calls if call[0] != "GET"]


def lab_config(tmp_path: Path, tenant_id: str) -> Path:
    cfg = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))
    cfg["tenant"]["tenantId"] = tenant_id
    path = tmp_path / "config.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return path


@pytest.fixture
def graph(monkeypatch):
    def install(org_id: str) -> RecordingGraph:
        recorder = RecordingGraph(org_id)
        monkeypatch.setattr(requests.Session, "request", lambda session, *a, **k: recorder(session, *a, **k))
        return recorder

    return install


@pytest.fixture
def az_calls(monkeypatch):
    """Record every subprocess argv; answer `az account get-access-token` with a token for the requested tenant."""
    calls: list[list[str]] = []

    def fake_run(argv, *args, **kwargs):
        calls.append(list(argv))
        if argv[:3] == ["az", "account", "get-access-token"]:
            tenant = argv[argv.index("--tenant") + 1] if "--tenant" in argv else OTHER_TENANT
            return SimpleNamespace(returncode=0, stdout=fake_jwt(tenant) + "\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    monkeypatch.delenv("AZURE_ACCESS_TOKEN", raising=False)
    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    return calls


SEEDERS = {
    "identity": ("identity_seed_az.py", [], "identity-seed-az-manifest.json"),
    "workload": ("seed-workload-az.py", ["--steps", "licenses,teams,intune,security"], "workload-seed-az-manifest.json"),
}


def run_seeder(kind: str, config: Path) -> tuple[int, dict | None]:
    script, extra, manifest_name = SEEDERS[kind]
    module = load_module(ROOT / "scripts" / script)
    result = module.main(["--config", str(config), "--run-name", "guard", *extra])
    manifest_path = config.parent / "runs" / "guard" / manifest_name
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else None
    return result, manifest


@pytest.mark.parametrize("kind", sorted(SEEDERS))
def test_env_token_from_other_tenant_stops_before_any_write(kind, tmp_path, monkeypatch, graph, az_calls):
    monkeypatch.setenv("AZURE_ACCESS_TOKEN", fake_jwt(OTHER_TENANT))
    recorder = graph(LAB_TENANT)
    result, manifest = run_seeder(kind, lab_config(tmp_path, LAB_TENANT))
    assert result != 0
    assert recorder.writes == []
    assert manifest is not None and manifest.get("error") == "tenant_mismatch"


@pytest.mark.parametrize("kind", sorted(SEEDERS))
def test_organization_of_other_tenant_stops_before_any_write(kind, tmp_path, monkeypatch, graph, az_calls):
    monkeypatch.setenv("AZURE_ACCESS_TOKEN", fake_jwt(LAB_TENANT))
    recorder = graph(OTHER_TENANT)
    result, manifest = run_seeder(kind, lab_config(tmp_path, LAB_TENANT))
    assert result != 0
    assert recorder.writes == []
    assert manifest is not None and manifest.get("error") == "tenant_mismatch"


@pytest.mark.parametrize("kind", sorted(SEEDERS))
def test_azure_cli_token_is_requested_for_the_named_tenant(kind, tmp_path, graph, az_calls):
    recorder = graph(LAB_TENANT)
    result, _ = run_seeder(kind, lab_config(tmp_path, LAB_TENANT))
    token_calls = [argv for argv in az_calls if argv[:3] == ["az", "account", "get-access-token"]]
    assert token_calls, "expected an az token request"
    assert all(argv[argv.index("--tenant") + 1] == LAB_TENANT for argv in token_calls if "--tenant" in argv)
    assert all("--tenant" in argv for argv in token_calls)
    assert result == 0
    assert recorder.writes, "a matching tenant should proceed to seeding"


@pytest.mark.parametrize("kind", sorted(SEEDERS))
@pytest.mark.parametrize("tenant_id", [ZERO_TENANT, "", "not-a-guid", "organizations"])
def test_placeholder_or_invalid_tenant_id_is_rejected_before_auth(kind, tenant_id, tmp_path, monkeypatch, graph, az_calls):
    monkeypatch.setenv("AZURE_ACCESS_TOKEN", fake_jwt(tenant_id or OTHER_TENANT))
    recorder = graph(tenant_id or OTHER_TENANT)
    result, manifest = run_seeder(kind, lab_config(tmp_path, tenant_id))
    assert result != 0
    assert recorder.calls == []
    assert [argv for argv in az_calls if argv[:1] == ["az"]] == []
    assert manifest is not None and manifest.get("error") == "tenant_id_required"


@pytest.mark.parametrize("kind", sorted(SEEDERS))
def test_dry_run_with_placeholder_tenant_still_plans(kind, tmp_path, graph, az_calls):
    recorder = graph(OTHER_TENANT)
    script, extra, _ = SEEDERS[kind]
    module = load_module(ROOT / "scripts" / script)
    config = lab_config(tmp_path, ZERO_TENANT)
    assert module.main(["--config", str(config), "--run-name", "guard", "--dry-run", *extra]) == 0
    assert recorder.calls == []


PWSH_DRIVER = r"""
$ErrorActionPreference = "Stop"
. (Join-Path $env:KIT_SCRIPTS "00-shared.ps1") -ConfigPath $env:KIT_CONFIG
function Write-BootstrapEvent { param($Message, $Status, $Details, $Step) }
function Connect-MgGraph { }
function Select-MgProfile { }
function az { $global:AzCalls += ,($args -join " "); "fake-token" }
function Invoke-MgGraphRequest {
  param($Method, $Uri, $OutputType, $ErrorAction)
  if ($Uri -like "*/me*") { return [pscustomobject]@{ userPrincipalName = "operator@lab.example" } }
  return [pscustomobject]@{ value = @([pscustomobject]@{ id = $env:ORG_ID; displayName = "Org" }) }
}
function Get-Module { param([switch]$ListAvailable, $Name) [pscustomobject]@{ Name = $Name } }
function Connect-ExchangeOnline { $global:ExoArgs = ($args | ForEach-Object { "$_" }) -join " " }
function Get-ConnectionInformation { [pscustomobject]@{ TenantID = $env:EXO_TENANT; State = "Connected" } }
function Disconnect-ExchangeOnline { $global:ExoDisconnected = $true }
$global:ExoDisconnected = $false
$global:AzCalls = @()
$global:ExoArgs = ""
$global:BootstrapSession = @{ Config = (Get-Content $env:KIT_CONFIG -Raw | ConvertFrom-Json); Context = @{} }
$result = [ordered]@{ graphError = ""; exchangeError = "" }
try { Connect-BootstrapGraph } catch { $result.graphError = $_.Exception.Message }
try { Connect-BootstrapExchange } catch { $result.exchangeError = $_.Exception.Message }
$result.azCalls = @($global:AzCalls)
$result.exchangeArgs = $global:ExoArgs
$result.exchangeDisconnected = $global:ExoDisconnected
$result | ConvertTo-Json -Compress
"""


def run_shared_ps1(tmp_path: Path, tenant_id: str, org_id: str, exo_tenant: str | None = None) -> dict:
    import os
    import subprocess

    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("pwsh is not installed")
    config = lab_config(tmp_path, tenant_id)
    driver = tmp_path / "driver.ps1"
    driver.write_text(PWSH_DRIVER, encoding="utf-8")
    env = {**os.environ, "KIT_SCRIPTS": str(ROOT / "scripts"), "KIT_CONFIG": str(config), "ORG_ID": org_id,
           "EXO_TENANT": exo_tenant or org_id}
    proc = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-File", str(driver)],
                          capture_output=True, text=True, timeout=120, env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_powershell_graph_context_refuses_another_tenant(tmp_path):
    result = run_shared_ps1(tmp_path, LAB_TENANT, OTHER_TENANT)
    assert "tenant_mismatch" in result["graphError"]


def test_powershell_graph_token_is_requested_for_the_named_tenant(tmp_path):
    result = run_shared_ps1(tmp_path, LAB_TENANT, LAB_TENANT)
    assert result["graphError"] == ""
    token_calls = [call for call in result["azCalls"] if "get-access-token" in call]
    assert token_calls and all(f"--tenant {LAB_TENANT}" in call for call in token_calls)


def test_powershell_placeholder_tenant_is_refused_before_auth(tmp_path):
    result = run_shared_ps1(tmp_path, ZERO_TENANT, ZERO_TENANT)
    assert "tenant_id_required" in result["graphError"]
    assert not [call for call in result["azCalls"] if "get-access-token" in call]


def test_powershell_exchange_session_in_another_tenant_is_refused(tmp_path):
    result = run_shared_ps1(tmp_path, LAB_TENANT, LAB_TENANT, exo_tenant=OTHER_TENANT)
    assert "tenant_mismatch" in result["exchangeError"]
    assert result["exchangeDisconnected"] is True


def test_powershell_exchange_session_in_the_lab_tenant_is_accepted(tmp_path):
    result = run_shared_ps1(tmp_path, LAB_TENANT, LAB_TENANT)
    assert result["exchangeError"] == ""
    assert result["exchangeDisconnected"] is False
