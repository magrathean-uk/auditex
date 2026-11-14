"""MS.TEAMS 5.1-5.3: the org-wide unified app settings read, its app-only named skip and the rule adapter.

Every row here is constructed; no tenant evidence is used.
"""
import base64
import json

import pytest

from auditex.scuba_adapters_teams import ADAPTERS, CERTIFICATE_AUTH_MARKER
from auditex.scuba_projection import project_run
from azure_tenant_audit.adapters import teams_admin_rest as rest
from azure_tenant_audit.collection_markers import NOT_COLLECTED
from azure_tenant_audit.collectors.teams_policy import (
    APP_SETTINGS_OPERATION,
    TeamsPolicyCollector,
)
from azure_tenant_audit.value_rules import assess

# Independent literals pinned from ScubaGear's API catalogue (Get-TeamsM365UnifiedTenantSettingsRest,
# Get-TeamsUnifiedApiEndpoint); a change to the production destination must fail here.
UNIFIED_URL = "https://substrate.office.com/AdminAppCatalog/ps/v2/admin/unifiedApp/settings"
UNIFIED_SCOPE = "08ff1ce2-4973-4b08-86a3-ebed13badc7f/.default"
POLICY_IDS = ("MS.TEAMS.5.1v2", "MS.TEAMS.5.2v2", "MS.TEAMS.5.3v2")


def token(aud, **claims):
    encoded = base64.urlsafe_b64encode(json.dumps({"aud": aud, **claims}).encode()).decode().rstrip("=")
    return f"constructed.{encoded}.signature"


UNIFIED_TOKEN = token("08ff1ce2-4973-4b08-86a3-ebed13badc7f", scp="constructed")
TEAMS_TOKEN = token("48ac35b8-9aa8-4d74-927d-1f4a14a0b239", appidacr="2")
SETTINGS = [
    {"SettingName": "DefaultApp", "SettingValue": "None"},
    {"SettingName": "GlobalApp", "SettingValue": "All"},
    {"SettingName": "EnableCopilotExtensibility", "SettingValue": "Some",
     "Users": ["constructed-user"], "Groups": ["constructed-group"]},
]


class Response:
    def __init__(self, status=200, parsed=None):
        self.status_code = status
        self.parsed = SETTINGS if parsed is None else parsed
        self.headers = {"Content-Type": "application/json"}

    def iter_content(self, chunk_size):
        body = json.dumps(self.parsed).encode()
        for offset in range(0, len(body), chunk_size):
            yield body[offset:offset + chunk_size]

    def close(self):
        pass


def connect(monkeypatch, responses):
    calls = []
    queue = iter(responses)

    def get(url, **kwargs):
        calls.append((url, kwargs))
        return next(queue)

    monkeypatch.setattr(rest.requests, "get", get)
    for verb in ("post", "put", "patch", "delete", "request", "head", "options"):
        monkeypatch.setattr(rest.requests, verb, lambda *a, **k: pytest.fail("Non-GET request"))
    return calls


def read(monkeypatch, parsed=None, status=200, environment="commercial", bearer=UNIFIED_TOKEN):
    calls = connect(monkeypatch, [Response(status, parsed)])
    return rest.TeamsAdminRestAdapter().get(APP_SETTINGS_OPERATION, bearer, environment), calls


# ---- the read: one pinned GET, its token audience and its shapes ----

def test_destination_scope_and_get_only(monkeypatch):
    assert rest.TEAMS_UNIFIED_SCOPE == UNIFIED_SCOPE
    assert {env: base + rest.TEAMS_UNIFIED_READ_PATHS[APP_SETTINGS_OPERATION]
            for env, base in rest.TEAMS_UNIFIED_BASE.items()} == {"commercial": UNIFIED_URL, "gcc": UNIFIED_URL}
    result, calls = read(monkeypatch)
    assert result["status"] == "ok" and result["command"] == "GET /AdminAppCatalog/ps/v2/admin/unifiedApp/settings"
    (url, kwargs), = calls
    assert url == UNIFIED_URL and kwargs["allow_redirects"] is False and kwargs["stream"] is True
    assert kwargs["headers"] == {"Authorization": f"Bearer {UNIFIED_TOKEN}", "Accept": "application/json"}


def test_only_consumed_fields_are_kept(monkeypatch):
    result, _ = read(monkeypatch)
    assert result["value"] == [{key: row[key] for key in ("SettingName", "SettingValue")} for row in SETTINGS]
    assert "constructed-user" not in json.dumps(result) and "constructed-group" not in json.dumps(result)


@pytest.mark.parametrize("parsed", [[], {"value": []}, {"value": SETTINGS}])
def test_accepted_shapes_include_empty(monkeypatch, parsed):
    result, _ = read(monkeypatch, parsed)
    assert result["status"] == "ok" and len(result["value"]) == len(parsed if isinstance(parsed, list) else parsed["value"])


def test_missing_value_passes_to_the_rule(monkeypatch):
    result, _ = read(monkeypatch, [{"SettingName": "DefaultApp"}])
    assert result["value"] == [{"SettingName": "DefaultApp"}]


@pytest.mark.parametrize("parsed", [
    {"SettingName": "DefaultApp", "SettingValue": "None"},  # an object is not the settings list
    [{"SettingValue": "None"}], [{"SettingName": ""}], [{"SettingName": 5}], ["DefaultApp"],
    {"error": {"code": "Forbidden"}}, {"value": "DefaultApp"},
])
def test_unexpected_shapes(monkeypatch, parsed):
    result, _ = read(monkeypatch, parsed)
    assert result["error_class"] == "unexpected_shape" and "value" not in result


def test_partial_page_is_never_a_success(monkeypatch):
    result, _ = read(monkeypatch, {"value": SETTINGS, "@odata.nextLink": "https://substrate.office.com/next"})
    assert result["error_class"] == "command_error" and "value" not in result


@pytest.mark.parametrize("status", [401, 403])
def test_refusal_is_not_authenticated(monkeypatch, status):
    result, _ = read(monkeypatch, {"error": "denied"}, status=status)
    assert result["error_class"] == "command_not_authenticated"


@pytest.mark.parametrize("bearer", [None, "opaque", TEAMS_TOKEN, token("https://graph.microsoft.com")])
def test_only_a_unified_audience_token_is_sent(monkeypatch, bearer):
    calls = connect(monkeypatch, [])
    result = rest.TeamsAdminRestAdapter().get(APP_SETTINGS_OPERATION, bearer, "commercial")
    assert result["error"] == "teams_token_unavailable" and calls == []


def test_unified_token_never_reaches_the_teams_admin_host(monkeypatch):
    calls = connect(monkeypatch, [])
    result = rest.TeamsAdminRestAdapter().get("appPermissionPolicies", UNIFIED_TOKEN, "commercial")
    assert result["error"] == "teams_token_unavailable" and calls == []


@pytest.mark.parametrize("environment", ["gcchigh", "dod", "unknown"])
def test_unsupported_environment_sends_nothing(monkeypatch, environment):
    calls = connect(monkeypatch, [])
    result = rest.TeamsAdminRestAdapter().get(APP_SETTINGS_OPERATION, UNIFIED_TOKEN, environment)
    assert result["error_class"] == "unsupported_environment" and calls == []


# ---- the collector: an app-only run names the skip and sends nothing to the unified host ----

class Client:
    graph_endpoint = "https://graph.microsoft.com/v1.0"

    def __init__(self, resource_token=TEAMS_TOKEN):
        self.resource_token = resource_token
        self.scopes = []

    def app_token_for(self, scope):
        self.scopes.append(scope)
        return self.resource_token


APP_POLICY = {"Identity": "Global", "DefaultCatalogAppsType": "AllowedAppList",
              "GlobalCatalogAppsType": "AllowedAppList", "PrivateCatalogAppsType": "BlockedAppList"}
ROWS = {
    "meetingPolicies": {"Identity": "Global", "AllowCloudRecording": False,
                        "AllowExternalParticipantGiveRequestControl": False,
                        "AllowAnonymousUsersToStartMeeting": False, "AutoAdmittedUsers": "EveryoneInCompany",
                        "AllowPSTNUsersToBypassLobby": False},
    "tenantFederationConfiguration": {"Identity": "Global", "AllowFederatedUsers": False, "AllowTeamsConsumer": False,
                                      "AllowTeamsConsumerInbound": False, "AllowedDomains": []},
    "clientConfiguration": {"Identity": "Global", "AllowEmailIntoChannel": False},
    "appPermissionPolicies": APP_POLICY,
    "broadcastPolicies": {"Identity": "Global", "BroadcastRecordingMode": "AlwaysDisabled"},
}


def collect(monkeypatch, client, responses=None):
    calls = connect(monkeypatch, responses or [])
    events = []
    result = TeamsPolicyCollector().run({"client": client, "audit_logger": lambda *args: events.append(args)})
    return result, calls, events


def certificate_run(monkeypatch):
    return collect(monkeypatch, Client(), rest_answers())


def rest_answers():
    # The five REST reads run in the collector's command order.
    return [Response(parsed={"value": [ROWS[name]]})
            for name, _ in TeamsPolicyCollector.command_collectors if name in rest.TEAMS_READ_PATHS]


def test_certificate_run_names_the_skip_and_never_calls_the_unified_host(monkeypatch):
    client = Client()
    result, calls, events = collect(monkeypatch, client, rest_answers())
    assert client.scopes == [rest.TEAMS_ADMIN_SCOPE]  # no token is requested for the unified settings
    assert len(calls) == 5 and not any("substrate.office.com" in url for url, _ in calls)
    assert not any("substrate.office.com" in json.dumps(event, default=str) for event in events)
    envelope = result.payload[APP_SETTINGS_OPERATION]
    assert envelope["status"] == "skipped" and envelope["value"] == []
    assert envelope["reason"] == envelope["error_class"] == "teams_powershell_not_supported"
    (row,) = [row for row in result.coverage if row["name"] == APP_SETTINGS_OPERATION]
    assert row["status"] == "skipped" and row["section_scoped"] is True
    assert row["reason"] == "teams_powershell_not_supported"
    assert result.status == "ok"
    assert TEAMS_TOKEN not in json.dumps([result.payload, result.coverage])


@pytest.mark.parametrize("resource_token", [None, token("48ac35b8-9aa8-4d74-927d-1f4a14a0b239", appidacr="1")])
def test_without_a_certificate_token_the_read_is_teams_token_unavailable(monkeypatch, resource_token):
    result, calls, _ = collect(monkeypatch, Client(resource_token))
    assert calls == [] and result.payload[APP_SETTINGS_OPERATION]["reason"] == "teams_token_unavailable"


# ---- the rule adapter and the three rows ----

def bundle_of(tmp_path, result, *, payload=None, coverage=None, ledger=None, gaps=None, manifest_gaps=None):
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw/teams_policy.json").write_text(json.dumps(result.payload if payload is None else payload))
    # The run writes its coverage rows to coverage.json, which the projection's health checks read.
    (tmp_path / "coverage.json").write_text(json.dumps(result.coverage if coverage is None else coverage))
    if ledger is not None or gaps is not None:
        (tmp_path / "normalized").mkdir()
    if ledger is not None:
        (tmp_path / "normalized/coverage_ledger.json").write_text(json.dumps(ledger))
    if gaps is not None:
        (tmp_path / "normalized/collection_gaps.json").write_text(json.dumps({"records": gaps}))
    (tmp_path / "run-manifest.json").write_text(json.dumps({
        "run_id": "constructed-teams-app-settings", "platform": "m365",
        "tenant_id": "11111111-1111-4111-8111-111111111111",
        "graph_endpoint": "https://graph.microsoft.com/v1.0",
        **({} if manifest_gaps is None else {"coverage_gaps": manifest_gaps}),
    }))
    (tmp_path / "collector-coverage.json").write_text(json.dumps({"coverage": result.coverage}))
    return project_run(tmp_path, redact=False)


def test_adapter_is_registered():
    assert "tenant_app_settings" in ADAPTERS


def test_certificate_run_closes_the_three_rows_from_app_permission_policies(monkeypatch, tmp_path):
    result, _, _ = certificate_run(monkeypatch)
    projection = bundle_of(tmp_path, result)
    sections = projection.rule_sections
    assert sections["tenant_app_settings"] == [CERTIFICATE_AUTH_MARKER]
    assert sections["app_policies"] == [APP_POLICY]
    verdicts = {policy: assess(policy, sections) for policy in POLICY_IDS}
    assert {policy: (row["verdict"], row["reason_code"]) for policy, row in verdicts.items()} == {
        "MS.TEAMS.5.1v2": ("met", "legacy_policies_allowed_list"),
        "MS.TEAMS.5.2v2": ("met", "legacy_policies_allowed_list"),
        "MS.TEAMS.5.3v2": ("not_met", "legacy_policy_blocked_list"),
    }


SKIP_GAP = {"kind": "collection_gap", "source": "teams_policy.tenantAppSettings", "collector": "teams_policy",
            "section": APP_SETTINGS_OPERATION, "status": "skipped", "reason": "teams_powershell_not_supported",
            "rows_collected": 0, "error_classes": ["teams_powershell_not_supported"]}
LEDGER_OK = {"collector": "teams_policy", "actual_status": "ok", "coverage_status": "complete_exact_scope",
             "diagnostics": []}


def test_certificate_run_with_its_ledger_and_skip_gap_still_closes_the_rows(monkeypatch, tmp_path):
    result, _, _ = certificate_run(monkeypatch)
    projection = bundle_of(tmp_path, result, ledger=[LEDGER_OK], gaps=[SKIP_GAP])
    assert projection.rule_sections["tenant_app_settings"] == [CERTIFICATE_AUTH_MARKER]


def _withheld(projection):
    sections = projection.rule_sections
    assert sections["tenant_app_settings"] == NOT_COLLECTED
    assert all(assess(policy, sections)["verdict"] == "not_assessed" for policy in POLICY_IDS)


def _app_settings_row(result, **changes):
    rows = [dict(row) for row in result.coverage]
    for row in rows:
        if row["name"] == APP_SETTINGS_OPERATION:
            row.update(changes)
    return rows


@pytest.mark.parametrize("changes", [
    {"status": "failed", "error_class": "command_not_authenticated", "reason": None},
    {"error_class": "command_not_authenticated"},
    {"status": "failed"},
    {"incomplete": True},
    {"item_count": 3},
    {"section_scoped": False},
])
def test_a_conflicting_coverage_row_withholds_the_certificate_input(monkeypatch, tmp_path, changes):
    result, _, _ = certificate_run(monkeypatch)
    _withheld(bundle_of(tmp_path, result, coverage=_app_settings_row(result, **changes)))


@pytest.mark.parametrize("changes", [
    {"incomplete": True, "error_class": "command_not_authenticated"},
    {"incomplete": True},
    {"partial": True},
    {"collection_truncated": True},
    {"error_class": "command_not_authenticated"},
    {"status": "failed"},
    {"value": [{"SettingName": "DefaultApp"}]},
    {"section_scoped": False},
    {"error": {"code": "Unauthorized"}},
])
def test_a_conflicting_envelope_withholds_the_certificate_input(monkeypatch, tmp_path, changes):
    result, _, _ = certificate_run(monkeypatch)
    payload = json.loads(json.dumps(result.payload))
    payload[APP_SETTINGS_OPERATION].update(changes)
    _withheld(bundle_of(tmp_path, result, payload=payload))


@pytest.mark.parametrize("ledger", [
    [{**LEDGER_OK, "actual_status": "failed", "coverage_status": "failed_runtime"}],
    [{**LEDGER_OK, "coverage_status": "blocked_permission", "diagnostics": [
        {"collector": "teams_policy", "item": APP_SETTINGS_OPERATION, "status": "failed",
         "error_class": "command_not_authenticated"}]}],
])
def test_a_failed_collector_ledger_withholds_the_certificate_input(monkeypatch, tmp_path, ledger):
    result, _, _ = certificate_run(monkeypatch)
    _withheld(bundle_of(tmp_path, result, ledger=ledger))


@pytest.mark.parametrize("changes", [
    {"status": "failed", "error_classes": ["command_not_authenticated"]},
    {"error_classes": ["teams_powershell_not_supported", "command_not_authenticated"]},
    {"reason": "read_failed"},
])
def test_a_conflicting_collection_gap_withholds_the_certificate_input(monkeypatch, tmp_path, changes):
    result, _, _ = certificate_run(monkeypatch)
    _withheld(bundle_of(tmp_path, result, ledger=[LEDGER_OK], gaps=[{**SKIP_GAP, **changes}]))


# The manifest's surface gap as the run writes it for the certificate skip (assurance.build_coverage_gap_summary).
SKIP_SECTION_GAP = {"collector": "teams_policy", "section": APP_SETTINGS_OPERATION, "status": "skipped",
                    "reason": "teams_powershell_not_supported", "rows_collected": 0,
                    "error_classes": ["teams_powershell_not_supported"]}
SURFACE_GAP = {"surface": "teams", "status": "partial", "severity": "medium", "collectors": ["teams_policy"],
               "error_classes": ["teams_powershell_not_supported"], "scope": "section",
               "section_gaps": [SKIP_SECTION_GAP]}


def test_certificate_run_with_its_manifest_section_gap_still_closes_the_rows(monkeypatch, tmp_path):
    result, _, _ = certificate_run(monkeypatch)
    projection = bundle_of(tmp_path, result, manifest_gaps=[SURFACE_GAP])
    assert projection.rule_sections["tenant_app_settings"] == [CERTIFICATE_AUTH_MARKER]


@pytest.mark.parametrize("changes", [{"read_state": "failed"}, {"collection_status": "failed"}])
def test_a_failed_health_field_on_the_coverage_row_withholds_the_certificate_input(monkeypatch, tmp_path, changes):
    result, _, _ = certificate_run(monkeypatch)
    _withheld(bundle_of(tmp_path, result, coverage=_app_settings_row(result, **changes)))


@pytest.mark.parametrize("manifest_gaps", [
    # The reviewer's probe: an authentication-failed truncation of the read.
    {"truncated_lists": [{"collector": "teams_policy", "name": APP_SETTINGS_OPERATION, "status": "failed",
                          "error_class": "command_not_authenticated", "reason": "read_failed"}]},
    [{**SURFACE_GAP, "section_gaps": [{**SKIP_SECTION_GAP, "status": "failed", "reason": "read_failed",
                                       "error_classes": ["command_not_authenticated"]}]}],
    [{**SURFACE_GAP, "section_gaps": [{**SKIP_SECTION_GAP, "read_state": "failed"}]}],
    [{**SURFACE_GAP, "notes": ["teams_policy.tenantAppSettings"]}],
])
def test_a_failed_manifest_gap_withholds_the_certificate_input(monkeypatch, tmp_path, manifest_gaps):
    result, _, _ = certificate_run(monkeypatch)
    _withheld(bundle_of(tmp_path, result, manifest_gaps=manifest_gaps))


def test_without_a_token_the_section_stays_not_collected(monkeypatch, tmp_path):
    result, _, _ = collect(monkeypatch, Client(None))
    projection = bundle_of(tmp_path, result)
    assert projection.rule_sections["tenant_app_settings"] == NOT_COLLECTED
    assert all(assess(policy, projection.rule_sections)["verdict"] == "not_assessed" for policy in POLICY_IDS)


def write_envelope(tmp_path, envelope):
    (tmp_path / "raw").mkdir(exist_ok=True)
    (tmp_path / "raw/teams_policy.json").write_text(json.dumps({
        "appPermissionPolicies": {"value": [APP_POLICY], "status": "ok"}, APP_SETTINGS_OPERATION: envelope}))
    (tmp_path / "run-manifest.json").write_text(json.dumps({
        "run_id": "constructed-teams-app-settings", "platform": "m365",
        "tenant_id": "11111111-1111-4111-8111-111111111111",
        "graph_endpoint": "https://graph.microsoft.com/v1.0",
    }))
    return project_run(tmp_path, redact=False).rule_sections["tenant_app_settings"]


@pytest.mark.parametrize("envelope", [
    {"value": [], "status": "skipped", "reason": "teams_token_unavailable", "error_class": "teams_token_unavailable"},
    {"value": [], "status": "skipped", "reason": "read_failed", "error_class": "read_failed"},
    {"value": [{"SettingName": "DefaultApp"}], "status": "skipped", "reason": "teams_powershell_not_supported",
     "error_class": "teams_powershell_not_supported"},
    {"error": "denied", "error_class": "command_not_authenticated"},
    {"error": "unsupported_environment", "error_class": "unsupported_environment"},
])
def test_no_other_gap_becomes_the_certificate_input(tmp_path, envelope):
    assert write_envelope(tmp_path, envelope) == NOT_COLLECTED


def test_a_read_answer_feeds_the_rules(tmp_path):
    rows = [{"SettingName": "DefaultApp", "SettingValue": "None"},
            {"SettingName": "GlobalApp", "SettingValue": "All"},
            {"SettingName": "PrivateApp", "SettingValue": 0}]
    sections = {"tenant_app_settings": write_envelope(tmp_path, {"value": rows, "status": "ok"}),
                "app_policies": [APP_POLICY]}
    assert sections["tenant_app_settings"] == rows
    assert [(assess(policy, sections)["verdict"], assess(policy, sections)["reason_code"]) for policy in POLICY_IDS] == [
        ("met", "org_setting_none"), ("not_met", "org_setting_not_none"),
        ("not_assessed", "data_unusable_setting_value")]


def test_an_empty_read_answer_falls_back_to_app_permission_policies(tmp_path):
    sections = {"tenant_app_settings": write_envelope(tmp_path, {"value": [], "status": "ok"}),
                "app_policies": [APP_POLICY]}
    assert sections["tenant_app_settings"] == []
    assert assess("MS.TEAMS.5.3v2", sections)["reason_code"] == "legacy_policy_blocked_list"


@pytest.mark.parametrize("row", [{"SettingValue": "None"}, {"SettingName": ""}, "DefaultApp"])
def test_an_unnamed_setting_withholds_the_section(tmp_path, row):
    assert write_envelope(tmp_path, {"value": [row], "status": "ok"}) == NOT_COLLECTED
