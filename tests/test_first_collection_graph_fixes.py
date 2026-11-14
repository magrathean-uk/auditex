"""M08-T08: auth-methods inline read, withheld classifications section, app-only site permissions."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from auditex import scuba_adapters_aad as aad  # noqa: F401  (registers the adapter module)
from auditex import scuba_projection as projection
from azure_tenant_audit.collection_markers import NOT_COLLECTED
from azure_tenant_audit.collectors.auth_methods import AuthMethodsCollector
from azure_tenant_audit.collectors.sharepoint_access import SharePointAccessCollector
from azure_tenant_audit.value_rules import assess

TENANT = "11111111-1111-4111-8111-111111111111"
CONFIGS = [{"id": "Sms", "state": "disabled"}, {"id": "Fido2", "state": "enabled"}]


def _write(root: Path, path: str, payload) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload) + "\n")


def _operation(root: Path, collector: str, name: str, rows, *, singleton=False, **meta) -> None:
    path = root / f"raw/{collector}.json"
    payload = json.loads(path.read_text()) if path.exists() else {}
    payload[name] = {**(rows if singleton else {"value": rows}), "status": "ok", **meta}
    _write(root, f"raw/{collector}.json", payload)


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setattr(projection, "AREA_ADAPTER_MODULES", ("auditex.scuba_adapters_aad",))
    _write(tmp_path, "run-manifest.json", {"run_id": "synthetic-run", "platform": "m365", "tenant_id": TENANT})
    return tmp_path


# D1: collector

class _Client:
    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        assert path == "/policies/authenticationMethodsPolicy"
        return {"id": "authenticationMethodsPolicy", "policyMigrationState": None,
                "authenticationMethodConfigurations": deepcopy(CONFIGS)}

    def get_all(self, path, params=None):  # noqa: ANN001, ARG002
        assert "authenticationMethodConfigurations" not in path, "list endpoint Graph rejects must not be called"
        assert path == "/reports/authenticationMethods/userRegistrationDetails"
        return []


def test_collector_reads_configurations_inline_only():
    result = AuthMethodsCollector().run({"client": _Client(), "top": None, "audit_logger": None})
    assert result.status == "ok"
    assert "authenticationMethodConfigurations" not in result.payload
    assert result.payload["authenticationMethodsPolicy"]["authenticationMethodConfigurations"] == CONFIGS
    assert all(row["name"] != "authenticationMethodConfigurations" for row in result.coverage)


# D1: adapter

def test_null_migration_state_is_passed_through_with_inline_configurations(run):
    _operation(run, "auth_methods", "authenticationMethodsPolicy",
               {"policyMigrationState": None, "authenticationMethodConfigurations": deepcopy(CONFIGS)}, singleton=True)
    rows = projection.project_run(run).rule_sections["authentication_method"]
    assert rows[0]["authentication_method_policy"] == {"PolicyMigrationState": None}
    assert [c["Id"] for c in rows[0]["authentication_method_feature_settings"]] == ["Sms", "Fido2"]


@pytest.mark.parametrize("policy", [{}, {"policyMigrationState": 5}, {"policyMigrationState": ""}])
def test_missing_or_invalid_migration_state_still_withholds(run, policy):
    # negative case: only a string or an explicit null is accepted
    _operation(run, "auth_methods", "authenticationMethodsPolicy",
               {**policy, "authenticationMethodConfigurations": deepcopy(CONFIGS)}, singleton=True)
    assert projection.project_run(run).rule_sections["authentication_method"] == NOT_COLLECTED


# D1 and D3: decided verdicts on a first-collection-shaped fixture (key shapes only, no tenant values)

_ALL_USERS = {"includeTarget": {"id": "all_users", "targetType": "group"},
              "excludeTarget": {"id": "00000000-0000-0000-0000-000000000000", "targetType": "group"}}
_FIRST_COLLECTION_CONFIGS = [
    {"id": "MicrosoftAuthenticator", "state": "enabled", "isSoftwareOathEnabled": False,
     "featureSettings": {"displayAppInformationRequiredState": {"state": "enabled", **_ALL_USERS},
                         "displayLocationInformationRequiredState": {"state": "enabled", **_ALL_USERS}}},
    {"id": "Fido2", "state": "enabled"}, {"id": "Sms", "state": "disabled"},
    {"id": "Voice", "state": "disabled"}, {"id": "Email", "state": "disabled"},
]
_AUTHORIZATION_POLICY = {
    "id": "authorizationPolicy", "allowInvitesFrom": "adminsAndGuestInviters",
    "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3",
    "defaultUserRolePermissions": {
        "allowedToCreateApps": False,
        "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat"]},
}


def _first_collection(run) -> None:
    _operation(run, "auth_methods", "authenticationMethodsPolicy",
               {"policyMigrationState": None, "authenticationMethodConfigurations": deepcopy(_FIRST_COLLECTION_CONFIGS)},
               singleton=True)
    _operation(run, "consent_policy", "authorizationPolicy", deepcopy(_AUTHORIZATION_POLICY), singleton=True)
    _operation(run, "app_consent", "delegatedPermissionClassifications", [])


def test_first_collection_fixture_decides_aad_3_3_3_5_and_5_2_and_leaves_3_4_open(run):
    _first_collection(run)
    sections = projection.project_run(run).rule_sections
    verdicts = {policy: assess(policy, sections)["verdict"]
                for policy in ("MS.AAD.3.3v2", "MS.AAD.3.5v2", "MS.AAD.5.2v1", "MS.AAD.3.4v1")}
    assert verdicts == {"MS.AAD.3.3v2": "met", "MS.AAD.3.5v2": "met", "MS.AAD.5.2v1": "met",
                        "MS.AAD.3.4v1": "not_assessed"}


def test_an_enabled_low_security_method_is_not_met_on_the_same_fixture(run):
    # negative case: the decided verdict follows the data, it is not a constant
    _first_collection(run)
    configs = deepcopy(_FIRST_COLLECTION_CONFIGS)
    next(c for c in configs if c["id"] == "Sms")["state"] = "enabled"
    _operation(run, "auth_methods", "authenticationMethodsPolicy",
               {"policyMigrationState": None, "authenticationMethodConfigurations": configs}, singleton=True)
    assert assess("MS.AAD.3.5v2", projection.project_run(run).rule_sections)["verdict"] == "not_met"


# D3: derived fan-out names

def _bundle(run) -> projection.Bundle:
    bundle = projection.Bundle(run, 10_000, 10_000_000, 100)
    bundle.manifest = json.loads((run / "run-manifest.json").read_text())
    return bundle


def _coverage(run, *rows) -> None:
    _write(run, "coverage.json", {"records": list(rows)})


def test_unread_service_principal_fanout_gap_does_not_withhold_classifications(run):
    _operation(run, "app_consent", "delegatedPermissionClassifications", [])
    _operation(run, "app_consent", "servicePrincipalOwners", [])
    _coverage(run, {"collector": "app_consent", "type": "derived", "name": "servicePrincipalFanout",
                    "status": "partial", "error_class": "collection_limit", "collection_truncated": True})
    bundle = _bundle(run)
    assert bundle.operation("app_consent", "delegatedPermissionClassifications") == []
    assert "app_consent.servicePrincipalFanout" in bundle.ignored
    assert projection.project_run(run).rule_sections["risky_delegated_permission_classifications"] != NOT_COLLECTED


def test_truncated_classification_read_still_withholds_5_2(run):
    _first_collection(run)
    section = "risky_delegated_permission_classifications"
    # the read succeeds and 5.2 decides before the truncation is recorded
    assert projection.project_run(run).rule_sections[section] == []
    assert assess("MS.AAD.5.2v1", projection.project_run(run).rule_sections)["verdict"] == "met"
    _operation(run, "app_consent", "delegatedPermissionClassifications", [],
               collection_truncated=True, truncation_reason="result_limit")
    result = projection.project_run(run)
    assert result.rule_sections[section] == NOT_COLLECTED
    with pytest.raises(projection.Unavailable) as gap:
        _bundle(run).operation("app_consent", "delegatedPermissionClassifications")
    assert gap.value.reason != "missing_artifact"
    assert assess("MS.AAD.5.2v1", result.rule_sections)["verdict"] == "not_assessed"


def test_fanout_gap_withholds_a_section_that_reads_the_fanout(run):
    _operation(run, "app_consent", "servicePrincipalFanout", [])
    bundle = _bundle(run)
    assert bundle.operation("app_consent", "servicePrincipalFanout") == []  # reads fine before the gap
    _coverage(run, {"collector": "app_consent", "type": "derived", "name": "servicePrincipalFanout", "status": "partial",
                    "error_class": "collection_limit", "collection_truncated": True})
    with pytest.raises(projection.Unavailable) as gap:
        _bundle(run).operation("app_consent", "servicePrincipalFanout")
    assert gap.value.reason != "missing_artifact"


def test_site_permissions_fanout_ignored_by_settings_read_but_not_by_its_own(run):
    _operation(run, "sharepoint_access", "sharePointSettings", {"sharingCapability": "disabled"}, singleton=True)
    _operation(run, "sharepoint_access", "sitePermissionsFanout", [])
    _coverage(run, {"collector": "sharepoint_access", "type": "derived", "name": "sitePermissionsFanout",
                    "status": "partial", "error_class": "collection_limit", "collection_truncated": True})
    bundle = _bundle(run)
    bundle.operation("sharepoint_access", "sharePointSettings")
    assert "sharepoint_access.sitePermissionsFanout" in bundle.ignored
    with pytest.raises(projection.Unavailable) as gap:
        _bundle(run).operation("sharepoint_access", "sitePermissionsFanout")
    assert gap.value.reason != "missing_artifact"


# D7: app-only site permissions

class _Auth:
    def __init__(self, mode):
        self.auth_mode = mode


class _SiteClient:
    def __init__(self, mode):
        self.auth = _Auth(mode)
        self.permission_reads: list[str] = []

    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        return {"sharingCapability": "disabled"}

    def get_all(self, path, params=None):  # noqa: ANN001, ARG002
        if path == "/sites":
            return [{"id": "site-1", "displayName": "One", "webUrl": "https://x.invalid/sites/one"}]
        self.permission_reads.append(path)
        return []


def test_app_only_makes_no_site_permissions_read_and_records_a_skip():
    client = _SiteClient("app")
    result = SharePointAccessCollector().run({"client": client, "top": None, "audit_logger": None})
    assert client.permission_reads == []
    skip = next(row for row in result.coverage if row["name"] == "sitePermissions")
    assert skip["status"] == "skipped" and skip["reason"] == "site_permissions_app_only_not_read"
    assert "Sites.FullControl.All" in skip["error"]
    assert result.status == "ok"
    assert result.payload["sitePermissionsBySite"] == {"value": []}


@pytest.mark.parametrize("mode", ["interactive", "azure_cli", "access_token"])
def test_delegated_modes_keep_the_site_permissions_read(mode):
    client = _SiteClient(mode)
    result = SharePointAccessCollector().run({"client": client, "top": None, "audit_logger": None})
    assert client.permission_reads == ["/sites/site-1/permissions"]
    assert all(row.get("status") != "skipped" for row in result.coverage)


_SITE_PERMISSION_RULES = ("sharepoint.site_orphaned", "sharepoint.site_weak_ownership",
                          "sharepoint.broad_link", "sharepoint.external_principal")


def test_app_only_skip_keeps_site_permission_rules_not_assessed():
    """Collector, normalisation and baseline together: a skipped permission read is never a pass."""
    from azure_tenant_audit.baselines import build_baseline_alignment
    from azure_tenant_audit.collector_runner import CollectorRunContext, CollectorRunner
    from azure_tenant_audit.diagnostics import build_diagnostics
    from azure_tenant_audit.normalize import build_normalized_snapshot
    from azure_tenant_audit.run import build_coverage_ledger

    def evaluate(mode):
        output = CollectorRunner().run(SharePointAccessCollector(),
                                       CollectorRunContext(client=_SiteClient(mode), top=None, page_size=100))
        assert output.result_row["status"] == "ok"
        snapshot = build_normalized_snapshot(
            tenant_name="acme", run_id="r", collector_payloads={"sharepoint_access": output.result.payload},
            coverage_rows=output.coverage_rows, result_rows=[output.result_row])
        # the tenant's own domains are known, so the external-principal check is not withheld for that reason
        snapshot["domain_hybrid_objects"] = {"records": [{"id": "acme.invalid", "is_verified": True}]}
        # and the domain collection that reads them completed
        result_rows = [output.result_row, {**output.result_row, "name": "domains_hybrid"}]
        diagnostics = build_diagnostics(result_rows, output.coverage_rows, {}, "global-reader")
        ledger = build_coverage_ledger(
            capability_rows=[{"collector": name, "status": "supported_exact_scope"}
                             for name in ("sharepoint_access", "domains_hybrid")],
            result_rows=result_rows, diagnostics=diagnostics)
        mappings = {rule: {"cis_m365_v7": ["T.1"]} for rule in _SITE_PERMISSION_RULES}
        alignment = build_baseline_alignment([], normalized_snapshot=snapshot, coverage_ledger=ledger, mappings=mappings)
        (control,) = alignment["frameworks"]["cis_m365_v7"]["controls"]
        return {row["rule_id"]: row for row in control["rule_statuses"]}

    skipped = evaluate("app")
    assert set(skipped) == set(_SITE_PERMISSION_RULES)
    assert {row["status"] for row in skipped.values()} == {"not_assessed"}
    assert {row["reason"] for row in skipped.values()} == {"site_permissions_not_read"}
    # negative control: a delegated read of the same sites can pass all four
    delegated = evaluate("interactive")
    assert set(delegated) == set(_SITE_PERMISSION_RULES)
    assert {row["status"] for row in delegated.values()} == {"pass"}
