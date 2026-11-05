"""Offline IPPS contract. Shapes inferred from docs/rule fields, never observed live.

Every process is mocked, including Exchange reads alongside IPPS. No sign-in occurs.
"""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from auditex.scuba_projection import NOT_COLLECTED, project_run
from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
from azure_tenant_audit.adapters.read_guard import check_command
from azure_tenant_audit.collectors.exchange_ipps_commands import DLP_EXCEPTION_FIELDS, IPPS_COMMANDS, ipps_session, minimise_ipps
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
from azure_tenant_audit.value_rules import assess
from azure_tenant_audit.value_rules.defender_dlp import DLP_TYPES

POLICIES = [f"MS.SECURITYSUITE.3.{n}v1" for n in range(1, 5)] + ["MS.SECURITYSUITE.4.1v1"]
ALERTS = [
    "Suspicious email sending patterns detected", "Suspicious connector activity",
    "Suspicious Email Forwarding Activity", "Messages have been delayed",
    "Tenant restricted from sending unprovisioned email", "Tenant restricted from sending email",
    "A potentially malicious URL click was detected",
]
# Entirely synthetic output after the explicit Select-Object projections.
OUTPUT = {
    "protectionAlerts": [{"Name": name, "Disabled": False, "Severity": "High", "Category": "ThreatManagement", "IsSystemRule": True} for name in ALERTS],
    "dlpCompliancePolicies": [{
        "Name": "Synthetic protection", "Enabled": True, "Mode": "Enable",
        "Workload": "Exchange,SharePoint,OneDriveForBusiness,Teams,EndpointDevices",
        **{key: ["All"] for key in ("ExchangeLocation", "SharePointLocation", "OneDriveLocation", "TeamsLocation", "EndpointDlpLocation")},
        **{key: [] for key in DLP_EXCEPTION_FIELDS},
    }],
    "dlpComplianceRules": [{
        "Name": "Synthetic rule", "ParentPolicyName": "Synthetic protection", "Disabled": False,
        "IsAdvancedRule": False, "ContentContainsSensitiveInformation": [{"name": name} for name in DLP_TYPES],
        "BlockAccess": True, "BlockAccessScope": "All", "NotifyUser": ["recipient"], "NotifyUserType": "Email",
    }],
}


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    monkeypatch.delenv("AUDITEX_ENABLE_IPPS", raising=False)
    monkeypatch.setenv("AZURE_CLIENT_ID", "11111111-1111-4111-8111-111111111111")
    monkeypatch.setenv("AUDITEX_IPPS_ORGANIZATION", "synthetic.onmicrosoft.com")
    monkeypatch.setenv("AUDITEX_IPPS_CERTIFICATE_THUMBPRINT", "A" * 40)
    monkeypatch.setattr("azure_tenant_audit.adapters.powershell_graph.shutil.which", lambda _: "/mock/pwsh")
    # Default tripwire: no test may start a real subprocess, including pwsh.
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("unmocked process"))


def process(monkeypatch, *, stdout="[]", stderr="", code=0, exception=None, output=None):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if exception:
            raise exception
        value = stdout
        if output is not None:
            value = "[]"
            for name, command in IPPS_COMMANDS:
                if command in argv[-1]:
                    value = json.dumps(output[name])
        return SimpleNamespace(returncode=code, stdout=value, stderr=stderr)

    monkeypatch.setattr(subprocess, "run", run)
    return calls


def enabled(monkeypatch):
    monkeypatch.setenv("AUDITEX_ENABLE_IPPS", "true")
    return ipps_session()


def project(tmp_path, payload):
    (tmp_path / "raw").mkdir(exist_ok=True)
    (tmp_path / "raw/exchange_policy.json").write_text(json.dumps(payload))
    (tmp_path / "run-manifest.json").write_text(json.dumps({"run_id": "synthetic", "platform": "m365"}))
    return project_run(tmp_path, redact=False)


@pytest.mark.parametrize("switch", [None, "", "false", "0", "off"])
def test_off_keeps_five_original_gaps_without_ipps_process(monkeypatch, tmp_path, switch):
    if switch is not None:
        monkeypatch.setenv("AUDITEX_ENABLE_IPPS", switch)
    calls = process(monkeypatch)
    result = ExchangePolicyCollector().run({})
    assert "dlpCompliancePolicies" not in result.payload and "dlpComplianceRules" not in result.payload
    assert result.payload["protectionAlerts"]["error_class"] == "session_not_connected"
    assert all("IPPSSession" not in args[-1] and "Get-ProtectionAlert" not in args[-1] for args, _ in calls)
    p = project(tmp_path, result.payload)
    for section in ("dlp_compliance_policies", "dlp_compliance_rules", "defender_dlp_license", "protection_alerts"):
        assert p.rule_sections[section] == NOT_COLLECTED
        assert p.report["sections"][section]["reason"] == "missing_artifact"
    assert all(assess(policy, p.rule_sections)["verdict"] == "not_assessed" for policy in POLICIES)


def test_enabled_uses_existing_adapter_and_all_five_rules(monkeypatch, tmp_path):
    enabled(monkeypatch)
    calls = process(monkeypatch, output=OUTPUT)
    result = ExchangePolicyCollector().run({})
    p = project(tmp_path, result.payload)
    assert [assess(policy, p.rule_sections)["verdict"] for policy in POLICIES] == ["met"] * 5
    connections = [(args, kw) for args, kw in calls if "Connect-IPPSSession" in args[-1]]
    assert len(connections) == 3
    for args, kw in connections:
        assert "-AppId $env:AUDITEX_IPPS_APP_ID" in args[-1]
        assert "-CertificateThumbprint $env:AUDITEX_IPPS_CERTIFICATE_THUMBPRINT" in args[-1]
        assert "-Organization $env:AUDITEX_IPPS_ORGANIZATION" in args[-1]
        for value in ("A" * 40, "synthetic.onmicrosoft.com", "11111111-1111-4111-8111-111111111111"):
            assert value not in " ".join(args)
        assert "-ClientSecret" not in args[-1] and "-AccessToken" not in args[-1]
        assert kw["env"]["AUDITEX_IPPS_CERTIFICATE_THUMBPRINT"] == "A" * 40
    # Clearing all evidence and changing relevant settings produce negative judgements.
    negative = deepcopy(OUTPUT)
    negative["dlpComplianceRules"][0]["ContentContainsSensitiveInformation"] = []
    negative["protectionAlerts"][0]["Disabled"] = True
    process(monkeypatch, output=negative)
    p = project(tmp_path, ExchangePolicyCollector().run({}).payload)
    assert [assess(policy, p.rule_sections)["verdict"] for policy in POLICIES] == ["not_met"] * 5


@pytest.mark.parametrize("key", ["AZURE_CLIENT_ID", "AUDITEX_IPPS_ORGANIZATION", "AUDITEX_IPPS_CERTIFICATE_THUMBPRINT"])
@pytest.mark.parametrize("value", ["", "invalid'; Set-Thing"])
def test_missing_or_unsafe_certificate_configuration_fails_before_process(monkeypatch, key, value):
    enabled(monkeypatch)
    monkeypatch.setenv(key, value)
    result = PowerShellGraphAdapter().run(IPPS_COMMANDS[0][1], session=ipps_session())
    assert result["error_class"] == "missing_app_credentials"


@pytest.mark.parametrize("stderr,expected", [
    ("AUDITEX_IPPS_MODULE_NOT_FOUND", "module_not_found"),
    ("AUDITEX_IPPS_SESSION_NOT_CONNECTED", "session_not_connected"),
    ("Get-DlpComplianceRule: not recognized", "command_not_found"),
    ("Access denied", "command_not_authenticated"),
    ("A license required for this command", "license_required"),
    ("Generic refusal", "command_error"),
])
def test_failures_are_typed_and_no_raw_error_reaches_logs(monkeypatch, stderr, expected, tmp_path):
    session = enabled(monkeypatch)
    planted = "synthetic-sensitive-marker"
    calls = process(monkeypatch, stdout=planted, stderr=stderr + " " + planted + " " + "A" * 40, code=1)
    events = []
    result = PowerShellGraphAdapter().run(IPPS_COMMANDS[1][1], session=session, log_event=lambda *args: events.append(args))
    assert result["error_class"] == expected
    assert "stdout" not in result and "stderr" not in result
    assert planted not in json.dumps([events, result]) and "A" * 40 not in json.dumps([events, result])
    assert len(calls) == 1
    result["ipps_enabled"] = True
    p = project(tmp_path, {"dlpCompliancePolicies": result, "dlpComplianceRules": {"value": []}})
    assert p.rule_sections["defender_dlp_license"] == NOT_COLLECTED
    assert p.report["sections"]["dlp_compliance_policies"]["detail"]["error_class"] == expected
    assert all(assess(policy, p.rule_sections)["verdict"] == "not_assessed" for policy in POLICIES[:4])


@pytest.mark.parametrize("stdout", ["", "synthetic-invalid-json-with-sensitive-marker", "null", "{}", '["synthetic-sensitive-marker"]'])
def test_empty_and_invalid_output_do_not_echo_content(monkeypatch, stdout):
    session = enabled(monkeypatch)
    process(monkeypatch, stdout=stdout)
    result = PowerShellGraphAdapter().run(IPPS_COMMANDS[0][1], session=session)
    assert result["error_class"] in {"command_output_empty", "command_parse_error"}
    assert "stdout" not in result and "stderr" not in result


@pytest.mark.parametrize("exception", [RuntimeError("synthetic-sensitive-marker"), subprocess.TimeoutExpired("synthetic-sensitive-marker", 1), subprocess.CalledProcessError(1, "synthetic-sensitive-marker")])
def test_exceptions_never_echo_command_or_auth_material(monkeypatch, exception):
    session = enabled(monkeypatch)
    process(monkeypatch, exception=exception)
    events = []
    result = PowerShellGraphAdapter().run(IPPS_COMMANDS[0][1], session=session, log_event=lambda *a: events.append(a))
    assert result["error_class"] in {"command_timeout", "command_exception", "command_error"}
    assert "synthetic-sensitive-marker" not in json.dumps([events, result])


@pytest.mark.parametrize("command", ["Set-DlpCompliancePolicy -Mode Disable", "Remove-ProtectionAlert", "Connect-IPPSSession", "Get-ProtectionAlert | Set-Thing", "New-DlpComplianceRule"])
def test_non_get_tenant_cmdlets_are_refused_before_connection(monkeypatch, command):
    result = PowerShellGraphAdapter().run(command, session=enabled(monkeypatch))
    assert result["error_class"] == "command_refused"


def test_cmdlets_and_scope_minimisation(monkeypatch, tmp_path):
    for _, command in IPPS_COMMANDS:
        assert check_command("powershell_graph", command)[0].startswith("Get-")
        assert "*" not in command and ",AdvancedRule" not in command
    response = {"value": [{"Name": "synthetic", "ExchangeLocation": ["All", "synthetic-sensitive-marker"], "Unselected": "synthetic-sensitive-marker"}]}
    minimise_ipps("dlpCompliancePolicies", response)
    assert response["value"][0]["ExchangeLocation"] == ["All", "scope"]
    assert "synthetic-sensitive-marker" not in json.dumps(response)
    enabled(monkeypatch)
    output = deepcopy(OUTPUT)
    output["dlpComplianceRules"][0].update(IsAdvancedRule=True, AdvancedRule="synthetic-sensitive-marker", NotifyUser=["synthetic-sensitive-marker"])
    process(monkeypatch, output=output)
    events = []
    result = ExchangePolicyCollector().run({"audit_logger": lambda *a: events.append(a)})
    assert "synthetic-sensitive-marker" not in json.dumps([result.payload, events])
    p = project(tmp_path, result.payload)
    assert all(assess(policy, p.rule_sections)["reason_code"] == "data_unusable_dlp_rule" for policy in POLICIES[:4])


def test_config_inventory_tracks_commands_and_permissions():
    root = Path(__file__).resolve().parents[1]
    definition = json.loads((root / "configs/collector-definitions.json").read_text())["collectors"]["exchange_policy"]
    declared = {row["name"]: row["commands"][0] for row in definition["command_collectors"]}
    assert declared == dict(ExchangePolicyCollector.command_collectors)
    permissions = json.loads((root / "configs/collector-permissions.json").read_text())["collector_permissions"]["exchange_policy"]
    for name, command in IPPS_COMMANDS:
        assert command.removeprefix(",@(").split()[0] in permissions["optional_commands"]
    assert "AUDITEX_ENABLE_IPPS" in permissions["notes"]


def test_missing_powershell_is_a_typed_gap(monkeypatch):
    session = enabled(monkeypatch)
    monkeypatch.setattr("azure_tenant_audit.adapters.powershell_graph.shutil.which", lambda _: None)
    assert PowerShellGraphAdapter().run(IPPS_COMMANDS[0][1], session=session)["error_class"] == "command_not_found"


@pytest.mark.parametrize("key", DLP_EXCEPTION_FIELDS)
def test_populated_scope_exceptions_cannot_pass(monkeypatch, tmp_path, key):
    enabled(monkeypatch)
    output = deepcopy(OUTPUT)
    output["dlpCompliancePolicies"][0][key] = ["synthetic-sensitive-marker"]
    process(monkeypatch, output=output)
    result = ExchangePolicyCollector().run({})
    assert "synthetic-sensitive-marker" not in json.dumps(result.payload)
    p = project(tmp_path, result.payload)
    assert p.rule_sections["dlp_compliance_policies"] == NOT_COLLECTED
    assert all(assess(policy, p.rule_sections)["verdict"] == "not_assessed" for policy in POLICIES[:4])


@pytest.mark.parametrize("envelope", [None, [], "unreadable", {"ipps_enabled": "true"}, {"ipps_enabled": False}])
def test_malformed_or_unmarked_alert_envelope_stays_uncollected(tmp_path, envelope):
    p = project(tmp_path, {"protectionAlerts": envelope})
    assert p.rule_sections["protection_alerts"] == NOT_COLLECTED
    assert p.report["sections"]["protection_alerts"]["reason"] == "missing_artifact"
