"""Constructed C1 evidence: real collectors -> project_run -> supported value rules.

Power Platform stage 8 rules are required: every policy checks its verdict and cell.
No pack vectors, credentials or tenant evidence are used.
"""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from auditex.model_serving import ModelConfig, assess_run
from auditex.scuba_projection import project_run
from azure_tenant_audit.collectors import power_platform as pp
from azure_tenant_audit.collectors.power_bi import PowerBICollector, TENANT_SETTINGS
from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.power_bi import PowerBIError
from azure_tenant_audit.power_platform import PowerPlatformError
from azure_tenant_audit.value_rules import assess


TENANT = "11111111-1111-4111-8111-111111111111"
DEFAULT = f"Default-{TENANT}"
SANDBOX = "constructed-sandbox"
FIXTURE_META = {
    "source_kind": "constructed",
    "spec_version": "v3.9.1",
    "note": "constructed rows and pack train and validation rows from v3.9.1; held-out test and pilot rows excluded",
}
# Explicit expectations, rather than settings inferred from the shipped rules.
BI_POLICIES = [
    ("MS.POWERBI.1.1v1", "PublishToWeb", "off"),
    ("MS.POWERBI.2.1v1", "AllowGuestUserToAccessSharedContent", "off_or_groups"),
    ("MS.POWERBI.3.1v1", "ExternalSharingV2", "off_or_groups"),
    ("MS.POWERBI.4.1v1", "ServicePrincipalAccessPermissionAPIs", "off_or_groups"),
    ("MS.POWERBI.4.2v1", "AllowServicePrincipalsCreateAndUseProfiles", "off_or_groups"),
    ("MS.POWERBI.5.1v1", "BlockResourceKeyAuthentication", "on"),
    ("MS.POWERBI.6.1v1", "RScriptVisual", "off"),
    ("MS.POWERBI.7.1v1", "EimInformationProtectionEdit", "on"),
]
PP_POLICIES = [f"MS.POWERPLATFORM.{number}v1" for number in
               ("1.1", "1.2", "2.1", "2.2", "3.1", "5.1", "6.1")]
OPTIONAL_POLICIES = [*(row[0] for row in BI_POLICIES), *PP_POLICIES, "MS.POWERPLATFORM.2.3v1"]
OPTIONAL_REASON = "optional_collection_not_enabled"
OPTIONAL_TEXT = "Not assessed: the optional Power BI / Power Platform collection was not enabled for this run."
FLAGS = {
    "MS.POWERPLATFORM.1.1v1": "disableEnvironmentCreationByNonAdminUsers",
    "MS.POWERPLATFORM.1.2v1": "disableTrialEnvironmentCreationByNonAdminUsers",
    "MS.POWERPLATFORM.5.1v1": "disablePortalsCreationByNonAdminUsers",
    "MS.POWERPLATFORM.6.1v1": "powerPlatform.powerApps.disableShareWithEveryone",
}
CREATION = {
    "disableEnvironmentCreationByNonAdminUsers": True,
    "disableTrialEnvironmentCreationByNonAdminUsers": True,
    "disablePortalsCreationByNonAdminUsers": True,
    "powerPlatform": {"powerApps": {"disableShareWithEveryone": True}},
}
ENVIRONMENTS = [
    {"EnvironmentName": DEFAULT, "IsDefault": True},
    {"EnvironmentName": SANDBOX, "IsDefault": False},
]
DLP = [{"value": [{
    "name": "constructed-dlp", "displayName": "Constructed DLP",
    "environmentType": "OnlyEnvironments",
    "environments": [{"name": DEFAULT}, {"name": SANDBOX}],
}]}]
ISOLATION = pp.TENANT_ISOLATION.replace("{TenantId}", TENANT)


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("network forbidden in end-to-end proof")

    monkeypatch.setattr("requests.sessions.Session.request", blocked)
    monkeypatch.setattr("socket.socket.connect", blocked)
    monkeypatch.setattr("socket.create_connection", blocked)
    monkeypatch.setattr("auditex.model_serving.ModelClient.assess", blocked)
    yield
    # Collectors catch transport errors, so also fail outside their exception handlers.
    assert not attempts, "a collector attempted real network access"


def write(root, path, payload):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload) + "\n")


def operation(root, collector, name, rows, **metadata):
    path = root / f"raw/{collector}.json"
    payload = json.loads(path.read_text()) if path.exists() else {}
    payload[name] = {"value": rows, "status": "ok", **metadata}
    write(root, f"raw/{collector}.json", payload)


class FakeGraph:
    def get_all(self, path, *, params):
        assert path == "/organization" and params == {"$select": "id"}
        return [{"id": TENANT}]


class FakePowerPlatform:
    def __init__(self):
        self.calls = []
        self.responses = {
            pp.ENVIRONMENTS: {"value": [
                {"name": DEFAULT, "properties": {"isDefault": True}},
                {"name": SANDBOX, "properties": {"isDefault": False}},
            ]},
            pp.DLP_POLICIES: {"value": []},
            pp.DLP_SCOPES: {"value": [{
                "name": "constructed-dlp",
                "properties": {"displayName": "Constructed DLP", "definition": {
                    "constraints": {"environmentFilter1": {"parameters": {
                        "filterType": "include", "environments": [{"name": DEFAULT}, {"name": SANDBOX}],
                    }}},
                }},
            }]},
            pp.TENANT_SETTINGS: deepcopy(CREATION),
            ISOLATION: {"properties": {"isDisabled": False}},
        }

    def get(self, path, *, api_version=None):
        self.calls.append(("GET", path))
        response = self.responses[path]
        if isinstance(response, Exception):
            raise response
        return deepcopy(response)

    def request(self, method, path, **kwargs):
        assert method == "GET", "this proof does not authorise a POST"
        return self.get(path, **kwargs)


class FakePowerBI:
    last_status = 200

    def __init__(self, settings, error):
        self.settings, self.error, self.calls = settings, error, []

    def get(self, path):
        assert path == TENANT_SETTINGS
        self.calls.append(("GET", path))
        if self.error is not None:
            raise self.error
        return {"tenantSettings": deepcopy(self.settings)}


@pytest.fixture
def collect_run(tmp_path, request):
    def run(*, pp_changes=None, settings=None, bi_error=None, licence="present", tokens=True,
            manifest_metadata=None):
        platform = FakePowerPlatform()
        platform.responses.update(pp_changes or {})
        bi = FakePowerBI(settings if settings is not None else [
            {"settingName": name, "enabled": kind == "on", "enabledSecurityGroups": []}
            for _, name, kind in BI_POLICIES
        ], bi_error)
        pp_result = pp.PowerPlatformCollector().run({
            "client": FakeGraph(), "power_platform_client": platform if tokens else None,
        })
        bi_result = PowerBICollector().run({"power_bi_client": bi if tokens else None})
        write(tmp_path, "run-manifest.json", {
            "run_id": "constructed-powerplat-run", "platform": "m365", **(manifest_metadata or {}),
        })
        write(tmp_path, "fixture-meta.json", {
            **FIXTURE_META, "vector_id": f"constructed:powerplat-e2e:{request.node.name}",
        })
        # These raw payloads and their failure/truncation metadata come from the real collectors.
        write(tmp_path, "raw/power_platform.json", pp_result.payload)
        write(tmp_path, "raw/power_bi.json", bi_result.payload)
        operation(tmp_path, "identity", "organization", [{"id": TENANT}])
        operation(tmp_path, "licensing", "subscribedSkus", [{"servicePlans": [{
            "servicePlanId": TENANT, "servicePlanName": "POWER_BI_STANDARD" if licence != "absent" else "AAD_PREMIUM",
            "provisioningStatus": "Success",
        }]}])
        write(tmp_path, "coverage.json", [*pp_result.coverage, *bi_result.coverage,
            {"collector": "identity", "name": "organization", "status": "ok", "error_class": None},
            {"collector": "licensing", "name": "subscribedSkus",
             "status": "failed" if licence == "withheld" else "ok",
             "error_class": "insufficient_permissions" if licence == "withheld" else None},
        ])
        assert all(method == "GET" for method, _ in platform.calls + bi.calls)
        assert platform.calls.count(("GET", pp.TENANT_SETTINGS)) == int(tokens)
        assert len(bi.calls) == int(tokens)
        return project_run(tmp_path, redact=False), pp_result, bi_result
    return run


def assess_pp(policy_id, sections, verdict, cell):
    result = assess(policy_id, sections)
    assert result["verdict"] == verdict
    assert result["cell"] == cell


@pytest.mark.parametrize("policy_id,name,kind", BI_POLICIES)
@pytest.mark.parametrize("verdict", ["met", "not_met", "not_assessed"])
def test_powerbi_policy_matrix(collect_run, policy_id, name, kind, verdict):
    entry = {"settingName": name, "enabledSecurityGroups": []}
    if verdict != "not_assessed":
        entry["enabled"] = (kind == "on") == (verdict == "met")
    projection, _, bi_result = collect_run(settings=[entry])
    sections = projection.rule_sections
    assert bi_result.status == "ok"
    assert sections["powerbi_tenant_settings"] == [entry]
    assert sections["powerbi_license_found"] is True
    assert sections["powerbi_access_denied_reason"] == ""
    result = assess(policy_id, sections)
    assert result["verdict"] == verdict
    cell = "enabled_missing" if verdict == "not_assessed" else {
        "on": "on.enabled" if verdict == "met" else "on.disabled",
        "off": "off.disabled" if verdict == "met" else "off.enabled",
        "off_or_groups": "og.disabled" if verdict == "met" else "og.enabled_no_groups",
    }[kind]
    assert result["cell"] == cell


@pytest.mark.parametrize("policy_id,name,kind", BI_POLICIES)
@pytest.mark.parametrize("http_status", [401, 403])
def test_powerbi_denial_withholds_settings_and_never_assesses(collect_run, policy_id, name, kind, http_status):
    projection, _, result = collect_run(bi_error=PowerBIError("constructed denial", status=http_status))
    sections = projection.rule_sections
    assert result.payload["tenantSettings"] == {"value": [], "status": "failed"}
    assert sections["powerbi_access_denied_reason"] == f"Power BI Admin API denied access (HTTP {http_status})"
    assert sections["powerbi_tenant_settings"] == NOT_COLLECTED
    assert sections["powerbi_license_found"] is True
    record = assess(policy_id, sections)
    assert record["verdict"] == "not_assessed"
    # The missing-section guard runs before the Power BI kind's denial branch.
    assert record["cell"] == "section_not_collected"


@pytest.mark.parametrize("policy_id,name,kind", BI_POLICIES)
@pytest.mark.parametrize("licence,cell", [("absent", "licence_false"), ("withheld", "section_not_collected")])
def test_powerbi_missing_and_withheld_licence_are_distinct(collect_run, policy_id, name, kind, licence, cell):
    projection, _, _ = collect_run(licence=licence)
    sections = projection.rule_sections
    if licence == "absent":
        assert sections["powerbi_license_found"] is False
    else:
        assert sections["powerbi_license_found"] == NOT_COLLECTED
        assert sections["powerbi_license_found"] is not False
    assert sections["powerbi_tenant_settings"] != NOT_COLLECTED
    result = assess(policy_id, sections)
    assert result["verdict"] == "not_assessed"
    assert result["cell"] == cell


@pytest.mark.parametrize("policy_id", PP_POLICIES)
@pytest.mark.parametrize("verdict", ["met", "not_met", "not_assessed"])
def test_powerplatform_policy_matrix(collect_run, policy_id, verdict):
    changes = {}
    if policy_id in FLAGS:
        creation = deepcopy(CREATION)
        value = {"met": True, "not_met": False, "not_assessed": None}[verdict]
        path = FLAGS[policy_id].split(".")
        parent = creation
        for key in path[:-1]:
            parent = parent[key]
        parent[path[-1]] = value
        changes[pp.TENANT_SETTINGS] = creation
        expected = {"environment_creation": [creation]}
        cell = {"met": "all_clear", "not_met": "flag_bad", "not_assessed": "flag_unusable"}[verdict]
    elif policy_id == "MS.POWERPLATFORM.3.1v1":
        changes[ISOLATION] = (PowerPlatformError("constructed denial", status=403) if verdict == "not_assessed"
                              else {"properties": {"isDisabled": verdict == "not_met"}})
        expected = {"tenant_isolation": NOT_COLLECTED if verdict == "not_assessed" else [changes[ISOLATION]]}
        cell = {"met": "all_clear", "not_met": "flag_bad", "not_assessed": "section_not_collected"}[verdict]
    else:
        if verdict == "not_met":
            changes[pp.DLP_SCOPES] = {"value": []}
        elif verdict == "not_assessed":
            changes[pp.DLP_SCOPES] = PowerPlatformError("constructed denial", status=403)
        expected = {"dlp_policies": {"met": DLP, "not_met": [{"value": []}],
                                     "not_assessed": NOT_COLLECTED}[verdict]}
        if policy_id == "MS.POWERPLATFORM.2.1v1":
            expected["tenant_id"] = TENANT
            cell = {"met": "default_environment_covered", "not_met": "no_dlp_policies",
                    "not_assessed": "section_not_collected"}[verdict]
        else:
            expected["environment_list"] = ENVIRONMENTS
            cell = {"met": "all_environments_covered", "not_met": "environment_without_policy",
                    "not_assessed": "section_not_collected"}[verdict]
    projection, _, _ = collect_run(pp_changes=changes)
    for section, value in expected.items():
        assert projection.rule_sections[section] == value
    assess_pp(policy_id, projection.rule_sections, verdict, cell)


@pytest.mark.parametrize("policy_id", ["MS.POWERPLATFORM.2.1v1", "MS.POWERPLATFORM.2.2v1"])
def test_truncated_dlp_list_is_withheld_even_with_covering_first_page(collect_run, policy_id):
    first = FakePowerPlatform().responses[pp.DLP_SCOPES]
    next_link = "https://api.bap.microsoft.com/constructed-next?api-version=2016-11-01"
    first["nextLink"] = next_link
    projection, result, _ = collect_run(pp_changes={
        pp.DLP_SCOPES: first, next_link: PowerPlatformError("constructed page denial", status=403),
    })
    assert result.payload["dlpPolicyScopes"]["value"] == DLP[0]["value"]
    assert result.payload["dlpPolicyScopes"]["collection_truncated"] is True
    row = next(row for row in result.coverage if row["name"] == "dlpPolicyScopes")
    assert row["collection_truncated"] is True
    assert projection.rule_sections["dlp_policies"] == NOT_COLLECTED
    assess_pp(policy_id, projection.rule_sections, "not_assessed", "section_not_collected")


def test_absent_is_default_stays_unusable_instead_of_false(collect_run):
    projection, result, _ = collect_run(pp_changes={pp.ENVIRONMENTS: {"value": [
        {"name": SANDBOX, "properties": {}},
    ]}})
    assert result.payload["environments"]["value"][0]["is_default"] is None
    assert projection.rule_sections["environment_list"] == [{"EnvironmentName": SANDBOX, "IsDefault": None}]
    # OnlyEnvironments avoids the rule's AllEnvironments shortcut, which needs no default flags.
    assert projection.rule_sections["dlp_policies"] == DLP
    assess_pp("MS.POWERPLATFORM.2.2v1", projection.rule_sections,
                           "not_assessed", "environment_list_unusable")


def test_no_admin_token_withholds_every_optional_section(collect_run):
    projection, pp_result, bi_result = collect_run(tokens=False)
    assert all(row["status"] == "skipped" for row in pp_result.coverage + bi_result.coverage)
    for section in ("environment_creation", "tenant_isolation", "dlp_policies", "environment_list",
                    "powerbi_tenant_settings", "powerbi_access_denied_reason"):
        assert projection.rule_sections[section] == NOT_COLLECTED
    for policy_id, _, _ in BI_POLICIES:
        result = assess(policy_id, projection.rule_sections)
        assert result["verdict"] == "not_assessed"
        assert result["cell"] == "section_not_collected"
    for policy_id in PP_POLICIES:
        assess_pp(policy_id, projection.rule_sections,
                               "not_assessed", "section_not_collected")


def assess_optional_run(root):
    # Use the same customer assessment entry point as test_optional_collection_reason.py.
    result = assess_run(root, ModelConfig(model_name="constructed-powerplat-e2e"), policies=OPTIONAL_POLICIES)
    assert len(result["policies"]) == 16
    assert {row["policy_id"] for row in result["policies"]} == set(OPTIONAL_POLICIES)
    return result


@pytest.mark.parametrize("metadata,optional_reason", [
    pytest.param({"selected_collectors": ["identity", "licensing"]}, True, id="not-enabled"),
    pytest.param({}, False, id="selection-absent"),
    pytest.param({"selected_collectors": []}, False, id="selection-empty"),
    pytest.param({"selected_collectors": None}, False, id="selection-null"),
    pytest.param({"selected_collectors": "identity"}, False, id="selection-string"),
    pytest.param({"selected_collectors": {"identity": True}}, False, id="selection-object"),
])
def test_without_optional_collection_all_16_policies_are_not_assessed(tmp_path, metadata, optional_reason):
    # Constructed run with only supporting collectors; no optional collector ran.
    write(tmp_path, "run-manifest.json", {
        "run_id": "constructed-no-opt-in", "platform": "m365", **metadata,
    })
    write(tmp_path, "fixture-meta.json", {**FIXTURE_META, "vector_id": "constructed:powerplat-e2e:no-opt-in"})
    operation(tmp_path, "identity", "organization", [{"id": TENANT}])
    operation(tmp_path, "licensing", "subscribedSkus", [{"servicePlans": [{
        "servicePlanId": TENANT, "servicePlanName": "POWER_BI_STANDARD", "provisioningStatus": "Success",
    }]}])
    write(tmp_path, "coverage.json", [
        {"collector": collector, "name": name, "status": "ok", "error_class": None}
        for collector, name in (("identity", "organization"), ("licensing", "subscribedSkus"))
    ])
    projection = project_run(tmp_path, redact=False)
    for section in ("environment_creation", "tenant_isolation", "dlp_policies", "environment_list",
                    "powerbi_tenant_settings", "powerbi_access_denied_reason"):
        assert projection[section] == NOT_COLLECTED
        assert projection.report["sections"][section]["reason"] == (
            OPTIONAL_REASON if optional_reason else "missing_artifact"
        )
    for policy_id in OPTIONAL_POLICIES:
        result = assess(policy_id, projection.rule_sections)
        assert result["verdict"] == "not_assessed"
        if not optional_reason:
            assert result["cell"] == "section_not_collected"
    result = assess_optional_run(tmp_path)
    for row in result["policies"]:
        assert row["claims"][0]["status"] == "unknown"
        detail = row["rule_precheck"]
        if optional_reason:
            assert detail["class"] == "absent_section"
            assert detail["reason_code"] == OPTIONAL_REASON
            assert detail["reason_text"] == OPTIONAL_TEXT
            assert row["limitations"] == [OPTIONAL_REASON]
            assert row["recommendations"] == []
        else:
            assert detail["cell"] == "section_not_collected"
            assert detail["reason_code"] == "required_evidence_section_not_collected"
            assert OPTIONAL_REASON not in row["limitations"]
            assert detail["reason_text"] != OPTIONAL_TEXT


def test_selected_optional_collectors_keep_read_failure_reasons(collect_run, tmp_path):
    projection, pp_result, bi_result = collect_run(
        manifest_metadata={"selected_collectors": ["identity", "licensing", "power_bi", "power_platform"]},
        bi_error=PowerBIError("constructed denial", status=403),
        pp_changes={path: PowerPlatformError("constructed denial", status=403) for path in (
            pp.ENVIRONMENTS, pp.DLP_POLICIES, pp.DLP_SCOPES, pp.TENANT_SETTINGS, ISOLATION,
        )},
    )
    assert pp_result.status == bi_result.status == "partial"
    assert all(row["status"] == "failed" for row in pp_result.coverage)
    assert bi_result.payload["tenantSettings"]["status"] == "failed"
    result = assess_optional_run(tmp_path)
    for section in ("environment_creation", "tenant_isolation", "dlp_policies", "environment_list",
                    "powerbi_tenant_settings"):
        detail = result["projection"]["sections"][section]
        assert detail["reason"] == "collector_error"
        assert detail["detail"]["error_class"] == "insufficient_permissions"
    assert projection.rule_sections["powerbi_access_denied_reason"] == "Power BI Admin API denied access (HTTP 403)"
    for row in result["policies"]:
        assert row["claims"][0]["status"] == "unknown"
        detail = row["rule_precheck"]
        assert detail["cell"] == "section_not_collected"
        assert detail["reason_code"] == "required_evidence_section_not_collected"
        assert OPTIONAL_REASON not in row["limitations"]
        assert detail["reason_text"] != OPTIONAL_TEXT
