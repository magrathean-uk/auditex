"""Offline IPPS contract. Shapes inferred from docs/rule fields, never observed live.

Every process is mocked, including Exchange reads alongside IPPS. No sign-in occurs.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

from auditex.scuba_projection import NOT_COLLECTED, project_run
from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter, _ipps_certificate_file_usable
from azure_tenant_audit.adapters.read_guard import check_command
from azure_tenant_audit.collectors.exchange_ipps_commands import DLP_EXCEPTION_FIELDS, DLP_LOCATION_FIELDS, IPPS_COMMANDS, ipps_session, minimise_ipps
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
        "AuditexExceptionPropertiesAvailable": True,
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
    for key in ("AUDITEX_IPPS_CERTIFICATE_FILE", "AUDITEX_IPPS_CERTIFICATE_PASSWORD_ENV",
                "AUDITEX_IPPS_CHILD_CERTIFICATE_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("AZURE_CLIENT_ID", "11111111-1111-4111-8111-111111111111")
    monkeypatch.setenv("AUDITEX_IPPS_ORGANIZATION", "synthetic.onmicrosoft.com")
    monkeypatch.setenv("AUDITEX_IPPS_CERTIFICATE_THUMBPRINT", "A" * 40)
    monkeypatch.setattr("azure_tenant_audit.adapters.powershell_graph.shutil.which", lambda _: "/mock/pwsh")
    monkeypatch.setattr("sys.platform", "win32")
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
        assert kw["input"] is None
        assert "AUDITEX_IPPS_CHILD_CERTIFICATE_PASSWORD" not in kw["env"]
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


@pytest.mark.parametrize("count", [0, 1, 3])
def test_real_python_projection_preserves_all_collection_cardinalities(count):
    # These are synthetic child JSON inputs, not pre-minimised collector rows.
    # The matching PowerShell comma/array syntax is pinned in the next test.
    private = "synthetic-private-scope"
    policy = deepcopy(OUTPUT["dlpCompliancePolicies"][0])
    policy.update({key: ["All", private, private][:count] for key in DLP_LOCATION_FIELDS})
    policy.update({key: [private] * count for key in DLP_EXCEPTION_FIELDS})
    rule = deepcopy(OUTPUT["dlpComplianceRules"][0])
    rule.update(NotifyUser=[private] * count,
                ContentContainsSensitiveInformation=[{"name": "Synthetic type", "Unselected": private}] * count)
    responses = {"dlpCompliancePolicies": {"value": [policy]}, "dlpComplianceRules": {"value": [rule]}}
    for name, response in responses.items():
        minimise_ipps(name, response)  # Calls the actual pure projection used in production.
        assert private not in json.dumps(response)
    for key in DLP_LOCATION_FIELDS:
        assert policy[key] == ["All", private, private][:count]  # Input was not mutated.
        assert responses["dlpCompliancePolicies"]["value"][0][key] == ["All", "scope", "scope"][:count]
    for key in DLP_EXCEPTION_FIELDS:
        assert responses["dlpCompliancePolicies"]["value"][0][key] == ["scope"] * count
    result = responses["dlpComplianceRules"]["value"][0]
    assert result["NotifyUser"] == ["scope"] * count
    assert result["ContentContainsSensitiveInformation"] == [{"name": "Synthetic type"}] * count


def test_powershell_nested_arrays_and_original_property_availability_are_explicit():
    commands = dict(IPPS_COMMANDS)
    policies = commands["dlpCompliancePolicies"]
    rules = commands["dlpComplianceRules"]
    for key in (*DLP_LOCATION_FIELDS, *DLP_EXCEPTION_FIELDS, "NotifyUser"):
        command = rules if key == "NotifyUser" else policies
        assert "@{Name='" + key + "';Expression={ if ($null -eq $_." + key + ") { $null } else { ,@(foreach ($entry in @($_." + key + "))" in command
    assert "else { ,@($_.ContentContainsSensitiveInformation | Select-Object name) }" in rules
    assert "Name='AuditexExceptionPropertiesAvailable';Expression={ " in policies
    for key in DLP_EXCEPTION_FIELDS:
        assert "($null -ne $_.PSObject.Properties['" + key + "'])" in policies
    assert policies.count(" -and ") == len(DLP_EXCEPTION_FIELDS) - 1
    for _, command in IPPS_COMMANDS:
        assert command.startswith(",@(Get-") and command.endswith(")")
        check_command("powershell_graph", command)


@pytest.mark.parametrize("key", DLP_EXCEPTION_FIELDS)
@pytest.mark.parametrize("value,available,expected", [
    ("absent", True, "not_assessed"), (None, True, "met"), ([], True, "met"),
    (["synthetic-private-scope"], True, "not_assessed"),
    (None, False, "not_assessed"), (None, None, "not_assessed"),
    (None, "absent", "not_assessed"), (None, "true", "not_assessed"),
])
def test_exception_availability_is_separate_from_selected_value(monkeypatch, tmp_path, key, value, available, expected):
    enabled(monkeypatch)
    output = deepcopy(OUTPUT)
    row = output["dlpCompliancePolicies"][0]
    if value == "absent":
        del row[key]
    else:
        row[key] = value
    if available == "absent":
        del row["AuditexExceptionPropertiesAvailable"]
    else:
        row["AuditexExceptionPropertiesAvailable"] = available
    process(monkeypatch, output=output)
    payload = ExchangePolicyCollector().run({}).payload
    assert "synthetic-private-scope" not in json.dumps(payload)
    p = project(tmp_path, payload)
    assert [assess(policy, p.rule_sections)["verdict"] for policy in POLICIES[:4]] == [expected] * 4
    if expected == "not_assessed":
        assert p.rule_sections["dlp_compliance_policies"] == NOT_COLLECTED


def pfx_configuration(monkeypatch, *, platform="darwin", mode=stat.S_IFREG | 0o600, size=2048, owner=None):
    # Only metadata is mocked. No certificate, key or password file is ever created.
    monkeypatch.setattr("sys.platform", platform)
    monkeypatch.setenv("AUDITEX_ENABLE_IPPS", "true")
    monkeypatch.delenv("AUDITEX_IPPS_CERTIFICATE_THUMBPRINT")
    monkeypatch.setenv("AUDITEX_IPPS_CERTIFICATE_FILE", "/synthetic/customer.pfx")
    monkeypatch.setenv("AUDITEX_IPPS_CERTIFICATE_PASSWORD_ENV", "SYNTHETIC_IPPS_PASSWORD")
    monkeypatch.setenv("SYNTHETIC_IPPS_PASSWORD", "synthetic-password-only-in-memory")
    original = Path.lstat

    def metadata(path, *args, **kwargs):
        if str(path) == "/synthetic":
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=os.getuid())
        if str(path) == "/synthetic/customer.pfx":
            return SimpleNamespace(st_mode=mode, st_size=size, st_uid=os.getuid() if owner is None else owner)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", metadata)


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_portable_certificate_is_child_only_and_uses_file_parameters(monkeypatch, platform):
    pfx_configuration(monkeypatch, platform=platform)
    calls = process(monkeypatch, output=OUTPUT)
    events = []
    result = ExchangePolicyCollector().run({"audit_logger": lambda *a: events.append(a)})
    connections = [(argv, kwargs) for argv, kwargs in calls if "Connect-IPPSSession" in argv[-1]]
    assert len(connections) == 3
    assert "SYNTHETIC_IPPS_PASSWORD" not in os.environ
    assert "synthetic-password-only-in-memory" not in json.dumps([events, result.payload])
    for argv, kwargs in calls:
        assert "synthetic-password-only-in-memory" not in str(argv)
        assert "/synthetic/customer.pfx" not in str(argv)
        assert "SYNTHETIC_IPPS_PASSWORD" not in kwargs["env"]
        if "Connect-IPPSSession" in argv[-1]:
            script = argv[-1]
            assert "-CertificateFilePath $env:AUDITEX_IPPS_CERTIFICATE_FILE -CertificatePassword $ippsPassword " in script
            assert "-CertificateThumbprint" not in script
            assert "[System.Net.NetworkCredential]::new('', [Console]::In.ReadLine()).SecurePassword" in script
            assert "ConvertTo-SecureString" not in script
            assert "EphemeralKeySet" not in script
            assert kwargs["input"] == "synthetic-password-only-in-memory\n"
        else:
            assert kwargs["input"] is None
        assert "AUDITEX_IPPS_CHILD_CERTIFICATE_PASSWORD" not in kwargs["env"]
        assert "synthetic-password-only-in-memory" not in str(kwargs["env"])


@pytest.mark.parametrize("mode,size,owner", [
    (stat.S_IFREG | 0o644, 2048, None), (stat.S_IFDIR | 0o700, 2048, None),
    (stat.S_IFLNK | 0o600, 2048, None), (stat.S_IFIFO | 0o600, 2048, None),
    (stat.S_IFREG | 0o600, 65537, None), (stat.S_IFREG | 0o600, 0, None),
    (stat.S_IFREG | 0o600, 2048, os.getuid() + 1),
])
def test_pfx_metadata_rejected_without_process_or_file_read(monkeypatch, mode, size, owner):
    pfx_configuration(monkeypatch, mode=mode, size=size, owner=owner)
    calls = process(monkeypatch)
    result = PowerShellGraphAdapter().run(IPPS_COMMANDS[0][1], session=ipps_session())
    assert result["error_class"] == "missing_app_credentials" and not calls


@pytest.mark.parametrize("problem", ["both", "neither", "missing_file", "missing_password", "empty_password", "invalid_env", "no_env", "provider_error", "thumbprint_on_mac", "pfx_on_windows"])
def test_certificate_selection_fails_closed_without_sensitive_diagnostics(monkeypatch, problem):
    pfx_configuration(monkeypatch)
    if problem == "both":
        monkeypatch.setenv("AUDITEX_IPPS_CERTIFICATE_THUMBPRINT", "A" * 40)
    elif problem == "neither":
        monkeypatch.delenv("AUDITEX_IPPS_CERTIFICATE_FILE")
    elif problem == "missing_file":
        monkeypatch.setenv("AUDITEX_IPPS_CERTIFICATE_FILE", "/synthetic/absent.pfx")
    elif problem in {"missing_password", "empty_password"}:
        monkeypatch.setenv("SYNTHETIC_IPPS_PASSWORD", "")
        if problem == "missing_password":
            monkeypatch.delenv("SYNTHETIC_IPPS_PASSWORD")
    elif problem == "invalid_env":
        monkeypatch.setenv("AUDITEX_IPPS_CERTIFICATE_PASSWORD_ENV", "bad;variable")
    elif problem == "no_env":
        monkeypatch.delenv("AUDITEX_IPPS_CERTIFICATE_PASSWORD_ENV")
    elif problem == "pfx_on_windows":
        monkeypatch.setattr("sys.platform", "win32")
    elif problem == "thumbprint_on_mac":
        monkeypatch.delenv("AUDITEX_IPPS_CERTIFICATE_FILE")
        monkeypatch.delenv("AUDITEX_IPPS_CERTIFICATE_PASSWORD_ENV")
        monkeypatch.setenv("AUDITEX_IPPS_CERTIFICATE_THUMBPRINT", "A" * 40)
    session = ipps_session()
    if problem == "provider_error":
        def failed_provider():
            raise ValueError("synthetic-password-only-in-memory")
        session["certificate_password_provider"] = failed_provider
    calls = process(monkeypatch)
    events = []
    result = PowerShellGraphAdapter().run(IPPS_COMMANDS[0][1], session=session, log_event=lambda *a: events.append(a))
    assert result["error_class"] == "missing_app_credentials" and not calls
    assert "synthetic-password-only-in-memory" not in str(result)
    assert "/synthetic/customer.pfx" not in str(result)
    assert (session.get("certificate_file") or "unconfigured") not in str(result)
    assert "/synthetic/customer.pfx" not in str(events)
    assert (session.get("certificate_file") or "unconfigured") not in str(events)


@pytest.mark.parametrize("kind", ["none", "exchange_online", "security_compliance"])
def test_direct_adapter_children_do_not_inherit_password_source(monkeypatch, kind):
    pfx_configuration(monkeypatch)
    monkeypatch.setenv("AUDITEX_IPPS_CHILD_CERTIFICATE_PASSWORD", "synthetic-stale-child-password")
    calls = process(monkeypatch)
    session = {"kind": kind}
    if kind == "security_compliance":
        session = ipps_session()
    PowerShellGraphAdapter().run("Get-DlpCompliancePolicy", session=session)
    assert len(calls) == 1
    assert "SYNTHETIC_IPPS_PASSWORD" not in calls[0][1]["env"]
    assert "AUDITEX_IPPS_CHILD_CERTIFICATE_PASSWORD" not in calls[0][1]["env"]
    assert calls[0][1]["input"] == ("synthetic-password-only-in-memory\n" if kind == "security_compliance" else None)


@pytest.mark.parametrize("enabled_switch", ["true", "false"])
def test_collector_consumes_password_before_any_other_child_even_when_off(monkeypatch, enabled_switch):
    pfx_configuration(monkeypatch)
    monkeypatch.setenv("AUDITEX_ENABLE_IPPS", enabled_switch)
    calls = process(monkeypatch)
    ExchangePolicyCollector().run({})
    assert "SYNTHETIC_IPPS_PASSWORD" not in os.environ
    assert all("SYNTHETIC_IPPS_PASSWORD" not in kwargs["env"] for _, kwargs in calls)


@pytest.mark.parametrize("entry", ["audit", "probe"])
def test_live_entry_captures_password_before_auth_toolchain_or_collectors(monkeypatch, tmp_path, entry):
    from azure_tenant_audit import cli, probe

    pfx_configuration(monkeypatch)

    class BoundaryReached(RuntimeError):
        pass

    def first_dependency(*args, **kwargs):
        assert "SYNTHETIC_IPPS_PASSWORD" not in os.environ
        raise BoundaryReached

    if entry == "audit":
        monkeypatch.setattr(cli, "load_break_glass_accounts", first_dependency)
        invoke = lambda: cli.run_live(SimpleNamespace(waiver_file=None, break_glass_accounts=None))
    else:
        monkeypatch.setattr(probe, "AuditWriter", first_dependency)
        invoke = lambda: probe.run_live_probe(SimpleNamespace(output_dir=tmp_path, tenant_name="Synthetic", run_name=None))
    with pytest.raises(BoundaryReached):
        invoke()


def test_prepared_session_is_reused_without_losing_consumed_password(monkeypatch):
    pfx_configuration(monkeypatch)
    session = ipps_session()
    assert "synthetic-password-only-in-memory" not in repr(session)
    monkeypatch.setattr("azure_tenant_audit.collectors.exchange_policy.ipps_session", lambda: pytest.fail("session recaptured"))
    calls = process(monkeypatch)
    ExchangePolicyCollector().run({"ipps_session": session})
    children = [kwargs for argv, kwargs in calls if "Connect-IPPSSession" in argv[-1]]
    assert len(children) == 3
    assert all(child["input"] == "synthetic-password-only-in-memory\n" for child in children)
    assert all("AUDITEX_IPPS_CHILD_CERTIFICATE_PASSWORD" not in child["env"] for child in children)


@pytest.mark.parametrize("failure", ["session", "parse", "timeout"])
def test_pfx_child_failures_never_log_password_or_provider_output(monkeypatch, failure):
    pfx_configuration(monkeypatch)
    session = ipps_session()
    private = "synthetic-password-only-in-memory"
    if failure == "timeout":
        process(monkeypatch, exception=subprocess.TimeoutExpired(private, 1))
        expected = "command_timeout"
    elif failure == "parse":
        process(monkeypatch, stdout=private)
        expected = "command_parse_error"
    else:
        process(monkeypatch, code=1, stderr="AUDITEX_IPPS_SESSION_NOT_CONNECTED " + private)
        expected = "session_not_connected"
    events = []
    result = PowerShellGraphAdapter().run(IPPS_COMMANDS[0][1], session=session, log_event=lambda *a: events.append(a))
    assert result["error_class"] == expected
    assert private not in json.dumps([events, result])
    assert "/synthetic/customer.pfx" not in json.dumps([events, result])


def test_preflight_reuses_the_prepared_pfx_session(monkeypatch, tmp_path):
    from azure_tenant_audit.config import RunConfig
    from azure_tenant_audit.run import run_preflight_probe

    pfx_configuration(monkeypatch)
    session = ipps_session()
    monkeypatch.setattr("azure_tenant_audit.collectors.exchange_policy.ipps_session", lambda: pytest.fail("session recaptured"))
    calls = process(monkeypatch)
    events = []
    artifacts = []

    class Writer:
        run_dir = tmp_path

        def log_event(self, *args):
            events.append(args)

        def write_json_artifact(self, name, payload):
            artifacts.append(payload)
            return tmp_path / name

    runnable, rows, _ = run_preflight_probe(
        selected_collectors=["exchange_policy"], completed_collectors=set(), client=None,
        run_cfg=RunConfig(tenant_name="Synthetic", output_dir=tmp_path, top_items=5, page_size=5),
        writer=Writer(), include_blocked=False, registry={"exchange_policy": ExchangePolicyCollector()},
        ipps_session=session,
    )
    assert runnable == ["exchange_policy"] and rows[0]["decision"] == "run"
    assert len([argv for argv, _ in calls if "Connect-IPPSSession" in argv[-1]]) == 3
    assert "synthetic-password-only-in-memory" not in json.dumps([events, artifacts])


@pytest.fixture
def private_pfx_test_root(monkeypatch, tmp_path):
    root = tmp_path.resolve()
    original = Path.lstat
    ancestors = set(root.parents)

    def metadata(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path in ancestors:
            # The host's external mount is 0775. Isolate that infrastructure
            # only; every file/directory under tmp_path uses real metadata.
            return SimpleNamespace(st_mode=info.st_mode & ~0o022, st_uid=info.st_uid)
        return info

    monkeypatch.setattr(Path, "lstat", metadata)
    return root


@pytest.mark.parametrize("case", ["regular", "leaf_symlink", "directory_symlink", "fifo", "public_file", "public_parent", "group_parent", "sticky_parent", "hardlink"])
def test_pfx_real_filesystem_metadata_gate(monkeypatch, private_pfx_test_root, case):
    monkeypatch.setattr("sys.platform", "darwin")
    root = private_pfx_test_root  # macOS /var may itself be a symlink.
    parent = root / "private"
    parent.mkdir(mode=0o700)
    path = parent / "metadata-only.pfx"
    # A single dummy byte, not a certificate or any key material.
    path.write_bytes(b"x")
    path.chmod(0o600)
    selected = path
    if case == "leaf_symlink":
        selected = parent / "leaf.pfx"
        selected.symlink_to(path)
    elif case == "directory_symlink":
        link = root / "linked"
        link.symlink_to(parent, target_is_directory=True)
        selected = link / path.name
    elif case == "fifo":
        path.unlink()
        os.mkfifo(path, 0o600)
    elif case == "public_file":
        path.chmod(0o644)
    elif case == "public_parent":
        parent.chmod(0o777)
    elif case == "group_parent":
        parent.chmod(0o770)
    elif case == "sticky_parent":
        parent.chmod(0o1777)
    elif case == "hardlink":
        os.link(path, parent / "other-link.pfx")
    expected = case in {"regular", "sticky_parent", "hardlink"}
    assert _ipps_certificate_file_usable(str(selected)) is expected
    monkeypatch.setenv("AUDITEX_ENABLE_IPPS", "true")
    monkeypatch.delenv("AUDITEX_IPPS_CERTIFICATE_THUMBPRINT")
    monkeypatch.setenv("AUDITEX_IPPS_CERTIFICATE_FILE", str(selected))
    monkeypatch.setenv("AUDITEX_IPPS_CERTIFICATE_PASSWORD_ENV", "SYNTHETIC_IPPS_PASSWORD")
    monkeypatch.setenv("SYNTHETIC_IPPS_PASSWORD", "synthetic-password-only-in-memory")
    calls = process(monkeypatch)
    events = []
    result = PowerShellGraphAdapter().run(IPPS_COMMANDS[0][1], session=ipps_session(), log_event=lambda *a: events.append(a))
    assert bool(calls) is expected
    if not expected:
        assert result["error_class"] == "missing_app_credentials"
    assert str(selected) not in str([result, events])


def test_pfx_rechecked_after_callback_before_launch(monkeypatch, private_pfx_test_root):
    pfx_configuration(monkeypatch)
    path = private_pfx_test_root / "metadata-only.pfx"
    path.write_bytes(b"x")
    path.chmod(0o600)
    monkeypatch.setenv("AUDITEX_IPPS_CERTIFICATE_FILE", str(path))
    events = []

    def replace_after_validation(*event):
        events.append(event)
        if event[0] == "command.started":
            path.chmod(0o644)

    calls = process(monkeypatch)
    result = PowerShellGraphAdapter().run(IPPS_COMMANDS[0][1], session=ipps_session(), log_event=replace_after_validation)
    assert result["error_class"] == "missing_app_credentials"
    assert not calls
    assert str(path) not in str([result, events])


@pytest.mark.parametrize("name", ["PATH", "HOME", "USER", "SHELL", "TMPDIR", "AZURE_CLIENT_SECRET", "AZURE_OTHER", "M365_CLI_APP_ID", "AUDITEX_ENABLE_IPPS", "AUDITEX_IPPS_CERTIFICATE_FILE", "path", "azure_client_secret"])
@pytest.mark.parametrize("switch", ["true", "false"])
def test_reserved_password_variable_refused_without_consumption(monkeypatch, name, switch):
    pfx_configuration(monkeypatch)
    monkeypatch.setenv("AUDITEX_ENABLE_IPPS", switch)
    before = os.environ.get(name)
    monkeypatch.setenv("AUDITEX_IPPS_CERTIFICATE_PASSWORD_ENV", name)
    session = ipps_session()
    assert os.environ.get(name) == before
    calls = process(monkeypatch)
    result = PowerShellGraphAdapter().run(IPPS_COMMANDS[0][1], session=session)
    assert result["error_class"] == ("missing_app_credentials" if switch == "true" else "session_not_connected")
    assert not calls
    # Also refuse a caller-supplied provider for a reserved name.
    session.update(enabled=True, certificate_password_env=name, certificate_file="/synthetic/customer.pfx",
                   app_id="11111111-1111-4111-8111-111111111111", organization="synthetic.onmicrosoft.com",
                   certificate_password_provider=lambda: "synthetic-password-only-in-memory")
    assert PowerShellGraphAdapter().run(IPPS_COMMANDS[0][1], session=session)["error_class"] == "missing_app_credentials"
    assert not calls


@pytest.mark.parametrize("name", ["AUDITEX_IPPS_PFX_PASSWORD", "AUDITEX_IPPS_PFX_PASSWORD_CUSTOMER"])
@pytest.mark.parametrize("switch", ["true", "false"])
def test_dedicated_password_variable_consumed_even_when_off(monkeypatch, name, switch):
    pfx_configuration(monkeypatch)
    monkeypatch.setenv("AUDITEX_ENABLE_IPPS", switch)
    monkeypatch.setenv("AUDITEX_IPPS_CERTIFICATE_PASSWORD_ENV", name)
    monkeypatch.setenv(name, "synthetic-password-only-in-memory")
    session = ipps_session()
    assert name not in os.environ
    calls = process(monkeypatch)
    result = PowerShellGraphAdapter().run(IPPS_COMMANDS[0][1], session=session)
    assert bool(calls) is (switch == "true")
    if calls:
        assert calls[0][1]["input"] == "synthetic-password-only-in-memory\n"
        assert name not in calls[0][1]["env"]
    else:
        assert result["error_class"] == "session_not_connected"


@pytest.mark.parametrize("password", ["synthetic\nsecond-line", "synthetic\rsecond-line", "synthetic\x00value"])
def test_line_delimited_password_rejects_control_separators(monkeypatch, password):
    pfx_configuration(monkeypatch)
    monkeypatch.setenv("SYNTHETIC_IPPS_PASSWORD", password.replace("\x00", ""))
    session = ipps_session()
    session["certificate_password_provider"] = lambda: password
    calls = process(monkeypatch)
    result = PowerShellGraphAdapter().run(IPPS_COMMANDS[0][1], session=session)
    assert result["error_class"] == "missing_app_credentials"
    assert not calls


@pytest.mark.parametrize("owner,mode", [(0, 0o1777), (os.getuid(), 0o1777), (os.getuid() + 1, 0o1777), (os.getuid(), 0o777), (os.getuid(), 0o770)])
def test_writable_ancestor_requires_sticky_and_controlled_owner(monkeypatch, owner, mode):
    pfx_configuration(monkeypatch)
    original = Path.lstat

    def metadata(path, *args, **kwargs):
        if str(path) == "/synthetic":
            return SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=owner)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", metadata)
    assert _ipps_certificate_file_usable("/synthetic/customer.pfx") is (bool(mode & stat.S_ISVTX) and owner in {0, os.getuid()})
