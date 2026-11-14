"""The Security & Compliance session (M08-T05): certificate token only, guarded prelude, a named reason on failure.

No tenant, PowerShell or network: tokens are constructed JWT-shaped strings and the subprocess and adapter are fakes.
"""
from __future__ import annotations

import base64
import json
from copy import deepcopy
from types import SimpleNamespace

import pytest

from azure_tenant_audit.adapters import powershell_graph as pg
from azure_tenant_audit.adapters.powershell_graph import (
    PowerShellGraphAdapter,
    compliance_certificate_token,
)
from azure_tenant_audit.collection_gaps import (
    DLP_LICENCE_SKIP_TEXT,
    IPPS_SKIP_TEXT,
    SECTION_GAP_REASON_TEXT,
    section_gap_records,
)
from azure_tenant_audit.collectors.exchange_policy import (
    COMPLIANCE_SCOPE,
    DLP_READS,
    EXCHANGE_ONLINE_SCOPE,
    IPPS_OPERATIONS,
    ExchangePolicyCollector,
    _compliance_session,
)
from azure_tenant_audit.offline_replay import (
    replay_collector_status,
    replay_coverage_rows,
)

ORG = "constructed.onmicrosoft.com"
COMMANDS = dict(ExchangePolicyCollector.command_collectors)


def jwt(**claims) -> str:
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"e30.{body}.c2lnbmF0dXJl"


CERT = jwt(aud="https://ps.compliance.protection.outlook.com", appidacr="2", roles=["Exchange.ManageAsApp"])
SECRET = jwt(aud="https://ps.compliance.protection.outlook.com", appidacr="1", roles=["Exchange.ManageAsApp"])
SESSION = {"kind": "security_compliance", "access_token": CERT, "organization": ORG}


# The credential gate -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("token", [
    CERT,
    jwt(aud="00000007-0000-0ff1-ce00-000000000000", azpacr="2"),
    jwt(aud="https://ps.compliance.protection.outlook.com/", appidacr="2"),
])
def test_certificate_app_token_for_the_compliance_audience_passes(token) -> None:
    assert compliance_certificate_token(token) is True


@pytest.mark.parametrize("token", [
    SECRET,  # client secret: no primary source shows Security & Compliance accepts it
    jwt(aud="https://ps.compliance.protection.outlook.com", appidacr="0"),
    jwt(aud="https://ps.compliance.protection.outlook.com", appidacr="2", scp="Exchange.Manage"),  # delegated
    jwt(aud="https://outlook.office365.com", appidacr="2"),  # the Exchange Online token
    jwt(aud="https://graph.microsoft.com", appidacr="2"),
    jwt(appidacr="2"),
    "certificate:" + COMPLIANCE_SCOPE,  # opaque
    "a.!!!.b", "", None, 7,
])
def test_any_other_token_fails_closed(token) -> None:
    assert compliance_certificate_token(token) is False


# The guarded prelude -------------------------------------------------------------------------------------------------

def test_prelude_connects_with_the_token_from_the_environment_only() -> None:
    env: dict[str, str] = {}
    prelude = PowerShellGraphAdapter._session_prelude(dict(SESSION), env)
    assert prelude.startswith("Import-Module ExchangeOnlineManagement -ErrorAction Stop; ")
    assert "try { Connect-IPPSSession -AccessToken $env:AUDITEX_IPPS_ACCESS_TOKEN " in prelude
    assert f"-Organization '{ORG}' -ShowBanner:$false -ErrorAction Stop | Out-Null }}" in prelude
    assert "catch { throw 'ipps_session_not_opened' }; " in prelude
    assert CERT not in prelude and env == {"AUDITEX_IPPS_ACCESS_TOKEN": CERT}
    for absent in ("Connect-ExchangeOnline", "-Certificate", "-Credential", "-UserPrincipalName", "-AppId"):
        assert absent not in prelude


@pytest.mark.parametrize("change", [
    {"access_token": SECRET},
    {"access_token": jwt(aud="https://outlook.office365.com", appidacr="2")},
    {"access_token": None},
    {"organization": "contoso.com"},
    {"organization": "x.onmicrosoft.com'; Remove-Mailbox -Identity y; '"},
    {"organization": None},
])
def test_prelude_refuses_anything_but_a_certificate_token_and_an_initial_domain(change) -> None:
    env: dict[str, str] = {}
    assert PowerShellGraphAdapter._session_prelude({**SESSION, **change}, env) == ""
    assert env == {}


class _Process:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _pwsh(monkeypatch, outcome: _Process | None) -> list[dict]:
    calls: list[dict] = []

    def run(argv, **kwargs):  # noqa: ANN001
        if outcome is None:
            pytest.fail("no PowerShell process may start")
        calls.append({"argv": list(argv), "env": dict(kwargs.get("env") or {})})
        return outcome

    monkeypatch.setattr(pg.shutil, "which", lambda name: "/constructed/pwsh")
    monkeypatch.setattr(pg.subprocess, "run", run)
    return calls


def test_a_session_without_a_usable_token_starts_no_process(monkeypatch) -> None:
    _pwsh(monkeypatch, None)
    events: list[tuple] = []
    response = PowerShellGraphAdapter().run(
        COMMANDS["protectionAlerts"], log_event=lambda *event: events.append(event),
        session={**SESSION, "access_token": SECRET},
    )
    assert response["error"] == response["error_class"] == "ipps_session_not_opened"
    assert [event[0] for event in events] == ["command.failed"]
    assert events[0][2]["error_class"] == "ipps_session_not_opened"


def test_a_failed_connect_is_named_and_never_a_pass(monkeypatch) -> None:
    calls = _pwsh(monkeypatch, _Process(1, "", "Exception: ipps_session_not_opened"))
    response = PowerShellGraphAdapter().run(COMMANDS["dlpComplianceRules"], session=dict(SESSION))
    assert response["error"] == response["error_class"] == "ipps_session_not_opened"
    assert "value" not in response
    (call,) = calls
    script = call["argv"][-1]
    assert call["argv"][:5] == ["/constructed/pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]
    assert script.index("Connect-IPPSSession -AccessToken") < script.index("Get-DlpComplianceRule")
    assert CERT not in " ".join(call["argv"]) and call["env"]["AUDITEX_IPPS_ACCESS_TOKEN"] == CERT


def test_the_marker_is_only_read_from_a_compliance_session(monkeypatch) -> None:
    _pwsh(monkeypatch, _Process(1, "", "Exception: ipps_session_not_opened"))
    exchange = {"kind": "exchange_online", "access_token": "exchange-token", "organization": ORG}
    response = PowerShellGraphAdapter().run(COMMANDS["transportConfig"], session=exchange)
    assert response["error_class"] == "command_error"


def test_an_opened_session_returns_rows(monkeypatch) -> None:
    _pwsh(monkeypatch, _Process(0, json.dumps({"Count": 1}), ""))
    response = PowerShellGraphAdapter().run(COMMANDS["dlpLicense"], session=dict(SESSION))
    assert response["value"] == [{"Count": 1}] and "error" not in response


# The compliance session the collector asks for -------------------------------------------------------------------------

class _Client:
    def __init__(self, *, certificate: bool = True, tokens: dict | None = None) -> None:
        self.auth = SimpleNamespace(certificate=object() if certificate else None)
        self.tokens = {EXCHANGE_ONLINE_SCOPE: "exchange-token", COMPLIANCE_SCOPE: CERT} if tokens is None else tokens
        self.requested: list[str] = []
        self.domain_reads = 0

    def app_token_for(self, scope: str):  # noqa: ANN201
        self.requested.append(scope)
        return self.tokens.get(scope)

    def get_all(self, path: str, params=None):  # noqa: ANN001, ANN201
        self.domain_reads += 1
        return [{"id": "other.example", "isInitial": False}, {"id": ORG, "isInitial": True}]


def test_certificate_mode_opens_the_session_with_the_compliance_audience() -> None:
    client = _Client()
    assert _compliance_session(client, None, None) == SESSION
    assert client.requested == [COMPLIANCE_SCOPE] and client.domain_reads == 1
    reused = _Client()
    assert _compliance_session(reused, ORG, None) == SESSION and reused.domain_reads == 0


def test_a_secret_or_delegated_run_asks_for_no_compliance_token() -> None:
    client = _Client(certificate=False)
    assert _compliance_session(client, ORG, None) == {"kind": "none"}
    assert client.requested == []
    assert _compliance_session(None, ORG, None) == {"kind": "none"}
    assert _compliance_session(SimpleNamespace(), ORG, None) == {"kind": "none"}


@pytest.mark.parametrize("token", [None, SECRET, "certificate:opaque"])
def test_an_unusable_compliance_token_opens_no_session(token) -> None:
    events: list[tuple] = []
    client = _Client(tokens={COMPLIANCE_SCOPE: token})
    assert _compliance_session(client, ORG, lambda *event: events.append(event)) == {"kind": "none"}
    assert events and events[0][2] == {"error_class": "ipps_session_not_opened"}


# The collector -------------------------------------------------------------------------------------------------------

PLANTED = "planted.person@example.invalid"
POLICY = {
    "Name": "P1", "Enabled": True, "Mode": "Enable", "Workload": "Exchange, SharePoint, OneDriveForBusiness, Teams, EndpointDevices",
    "ExchangeLocation": ["All"], "SharePointLocation": ["All"], "OneDriveLocation": ["All", PLANTED],
    "TeamsLocation": [PLANTED], "EndpointDlpLocation": [],
}
RULE = {
    "Name": "R1", "ParentPolicyName": "P1", "Disabled": False, "IsAdvancedRule": False, "AdvancedRule": None,
    "ContentContainsSensitiveInformation": {"name": "Credit Card Number"}, "BlockAccess": True,
    "BlockAccessScope": "All", "NotifyUser": [PLANTED, "SiteAdmin"], "NotifyUserType": "NotSet",
}


class _Adapter:
    def __init__(self, overrides: dict | None = None) -> None:
        self.overrides = overrides or {}
        self.calls: list[tuple[str, dict]] = []

    def run(self, command, log_event=None, session=None):  # noqa: ANN001
        name = next(name for name, text in COMMANDS.items() if text == command)
        self.calls.append((name, deepcopy(session)))
        if name in self.overrides:
            return deepcopy(self.overrides[name])
        return {"value": deepcopy({"dlpLicense": [{"Count": 1}], "dlpCompliancePolicies": [POLICY],
                                   "dlpComplianceRules": [RULE]}.get(name, []))}


def _collect(monkeypatch, adapter: _Adapter, client: _Client | None = None):
    monkeypatch.setattr("azure_tenant_audit.collectors.exchange_policy.get_adapter", lambda _name: adapter)
    return ExchangePolicyCollector().run({"client": client or _Client(), "audit_logger": None})


def _rows(result) -> dict:
    return {row["name"]: row for row in result.coverage}


def test_certificate_run_reads_compliance_in_its_own_session_and_minimises(monkeypatch) -> None:
    adapter = _Adapter()
    result = _collect(monkeypatch, adapter)
    sessions = dict(adapter.calls)
    assert {name for name in sessions if name in IPPS_OPERATIONS} == IPPS_OPERATIONS
    assert all(sessions[name] == SESSION for name in IPPS_OPERATIONS)
    assert all(sessions[name]["kind"] == "exchange_online" for name in sessions if name not in IPPS_OPERATIONS)
    assert result.status == "ok"
    rows = _rows(result)
    assert all(rows[name]["status"] == "ok" and rows[name]["section_scoped"] is True for name in IPPS_OPERATIONS)
    assert PLANTED not in json.dumps(result.payload)
    (policy,) = result.payload["dlpCompliancePolicies"]["value"]
    assert policy["OneDriveLocation"] == ["All", "location"] and policy["TeamsLocation"] == ["location"]
    assert policy["ExchangeLocation"] == ["All"] and policy["EndpointDlpLocation"] == []
    (rule,) = result.payload["dlpComplianceRules"]["value"]
    assert rule["NotifyUser"] == ["recipient", "recipient"]
    assert rule["ContentContainsSensitiveInformation"] == [{"name": "Credit Card Number"}]


def test_no_dlp_cmdlet_skips_the_dlp_reads_as_licence_not_detected(monkeypatch) -> None:
    adapter = _Adapter({"dlpLicense": {"value": [{"Count": 0}]}})
    result = _collect(monkeypatch, adapter)
    assert not set(DLP_READS) & {name for name, _ in adapter.calls}
    rows = _rows(result)
    for name in DLP_READS:
        envelope = result.payload[name]
        assert envelope["error_class"] == "license_required" and envelope["value"] == [] and envelope["item_count"] == 0
        assert rows[name]["status"] == "skipped" and rows[name]["reason"] == "dlp_licence_not_detected"
    assert rows["dlpLicense"]["status"] == rows["protectionAlerts"]["status"] == "ok"
    assert result.status == "ok"
    assert SECTION_GAP_REASON_TEXT["dlp_licence_not_detected"] == DLP_LICENCE_SKIP_TEXT


@pytest.mark.parametrize("probe", [
    {"value": [{"Count": 2}]}, {"value": [{"Count": "0"}]}, {"value": []},
    {"error": "constructed failure", "error_class": "command_error"},
])
def test_only_an_exact_zero_count_means_no_dlp_licence(monkeypatch, probe) -> None:
    adapter = _Adapter({"dlpLicense": probe})
    _collect(monkeypatch, adapter)
    assert set(DLP_READS) <= {name for name, _ in adapter.calls}


def test_a_failed_connect_stops_every_later_compliance_read(monkeypatch) -> None:
    failed = {"error": "ipps_session_not_opened", "error_class": "ipps_session_not_opened"}
    adapter = _Adapter({"protectionAlerts": failed})
    result = _collect(monkeypatch, adapter)
    assert [name for name, _ in adapter.calls if name in IPPS_OPERATIONS] == ["protectionAlerts"]
    rows = _rows(result)
    assert rows["protectionAlerts"]["status"] == "failed"
    assert all(rows[name]["status"] == "skipped" for name in IPPS_OPERATIONS - {"protectionAlerts"})
    assert all(rows[name]["reason"] == "ipps_session_not_opened" for name in IPPS_OPERATIONS)
    assert all(result.payload[name]["error"] == IPPS_SKIP_TEXT for name in IPPS_OPERATIONS - {"protectionAlerts"})
    assert result.status == "ok"
    gaps = {row["section"]: row for row in section_gap_records(result.coverage)}
    assert set(gaps) == IPPS_OPERATIONS
    assert gaps["protectionAlerts"]["status"] == "failed" and gaps["dlpLicense"]["status"] == "skipped"
    assert {row["reason"] for row in gaps.values()} == {"ipps_session_not_opened"}


def test_another_compliance_read_failure_is_a_named_gap_not_a_pass(monkeypatch) -> None:
    refused = {"error": "command_failed:1", "error_class": "command_not_authenticated", "stdout": f'[{{"NotifyUser":"{PLANTED}"'}
    adapter = _Adapter({"dlpComplianceRules": refused})
    result = _collect(monkeypatch, adapter)
    rows = _rows(result)
    assert rows["dlpComplianceRules"]["status"] == "failed" and rows["dlpComplianceRules"]["section_scoped"] is True
    assert result.status == "ok"
    (gap,) = section_gap_records(result.coverage)
    assert gap["section"] == "dlpComplianceRules" and gap["reason"] == "read_failed"
    assert gap["error_classes"] == ["command_not_authenticated"]
    assert PLANTED not in json.dumps(result.payload) and result.payload["dlpComplianceRules"]["stdout_bytes"] > 0


def test_a_secret_run_never_invokes_a_compliance_read(monkeypatch) -> None:
    adapter = _Adapter()
    client = _Client(certificate=False, tokens={EXCHANGE_ONLINE_SCOPE: "exchange-token"})
    result = _collect(monkeypatch, adapter, client)
    assert not IPPS_OPERATIONS & {name for name, _ in adapter.calls}
    assert COMPLIANCE_SCOPE not in client.requested
    assert all(_rows(result)[name]["reason"] == "ipps_session_not_opened" for name in IPPS_OPERATIONS)


def test_the_real_adapter_runs_the_collector_reads_without_a_second_sign_in(monkeypatch) -> None:
    """Driven through the real adapter: every compliance process connects with the access token, never a prompt."""
    scripts: list[str] = []

    def run(argv, **kwargs):  # noqa: ANN001
        scripts.append(argv[-1])
        return _Process(0, json.dumps({"Count": 1}) if "Get-Command" in argv[-1] else "[]", "")

    monkeypatch.setattr(pg.shutil, "which", lambda name: "/constructed/pwsh")
    monkeypatch.setattr(pg.subprocess, "run", run)
    result = ExchangePolicyCollector().run({"client": _Client(), "audit_logger": None})
    compliance = [script for script in scripts if "Connect-IPPSSession" in script]
    assert len(compliance) == len(IPPS_OPERATIONS)
    assert all("Connect-IPPSSession -AccessToken $env:AUDITEX_IPPS_ACCESS_TOKEN" in script for script in compliance)
    assert all("Connect-ExchangeOnline" not in script for script in compliance)
    assert all(_rows(result)[name]["status"] == "ok" for name in IPPS_OPERATIONS)


def _replayed(payload: dict) -> tuple[dict, str]:
    rows = replay_coverage_rows("exchange_policy", json.loads(json.dumps(payload)))
    return {row["name"]: row for row in rows}, replay_collector_status(rows)


def test_offline_replay_keeps_the_compliance_skips_as_skips(monkeypatch) -> None:
    secret = _collect(monkeypatch, _Adapter(), _Client(certificate=False, tokens={EXCHANGE_ONLINE_SCOPE: "exchange-token"}))
    rows, status = _replayed(secret.payload)
    assert set(rows) == IPPS_OPERATIONS and status == "ok"
    assert all(row["status"] == "skipped" and row["section_scoped"] is True
               and row["reason"] == "ipps_session_not_opened" for row in rows.values())
    unlicensed = _collect(monkeypatch, _Adapter({"dlpLicense": {"value": [{"Count": 0}]}}))
    rows, status = _replayed(unlicensed.payload)
    assert set(rows) == set(DLP_READS) and status == "ok"
    assert all(row["status"] == "skipped" and row["reason"] == "dlp_licence_not_detected" for row in rows.values())


@pytest.mark.parametrize(("name", "section"), [
    # The licence reason belongs to the DLP reads only; elsewhere it stays a failure.
    ("protectionAlerts", {"status": "skipped", "reason": "dlp_licence_not_detected", "error_class": "license_required"}),
    # A failed compliance read is not a skip: it keeps its failure in replay.
    ("dlpComplianceRules", {"error": "command_failed:1", "error_class": "command_not_authenticated"}),
    # Only the compliance reads carry the session reason.
    ("transportConfig", {"status": "skipped", "reason": "ipps_session_not_opened",
                         "error_class": "ipps_session_not_opened"}),
])
def test_offline_replay_keeps_other_compliance_rows_as_failures(name, section) -> None:
    rows, status = _replayed({name: {"value": [], **section}})
    assert rows[name]["status"] == "failed" and status == "partial"
