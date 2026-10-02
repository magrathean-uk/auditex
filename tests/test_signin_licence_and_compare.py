"""Coverage for sign-in activity, Intune licence gating, compare markdown, and offline handoff."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from auditex import cli as auditex_cli
from auditex.compare import render_compare_markdown
from auditex.reporting import enterprise_handoff, render_enterprise_handoff_markdown
from azure_tenant_audit.api_inventory import build_api_call_inventory
from azure_tenant_audit.capability_gate import (
    classify_capability_blocker,
    intune_license_state,
    relabel_intune_license_blockers,
)
from azure_tenant_audit.collectors.identity import IdentityCollector
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.graph import GraphError
from azure_tenant_audit.normalize import build_normalized_snapshot
from azure_tenant_audit.run import reconcile_capability_matrix_rows

from support import RunBundleBuilder


def _iso(days_ago: int) -> str:
    return (datetime.now(tz=timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- identity signInActivity -------------------------------------------------


class _IdentityClient:
    def __init__(self, signin: list[dict[str, Any]] | Exception) -> None:
        self.signin = signin
        self.requests: list[tuple[str, dict[str, Any]]] = []

    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        self.requests.append((path, dict(params or {})))
        return {"value": [{"id": "org"}]} if path == "/organization" else {"value": []}

    def iter_items(self, path, params=None, result_limit=None):  # noqa: ANN001, ARG002
        params = dict(params or {})
        self.requests.append((path, params))
        if path == "/users" and "signInActivity" in str(params.get("$select")):
            if isinstance(self.signin, Exception):
                raise self.signin
            return iter(self.signin)
        if path == "/users":
            return iter([{"id": "u1", "accountEnabled": True, "createdDateTime": _iso(400)}])
        return iter([])


def test_identity_collects_signin_activity_with_capped_page_size() -> None:
    client = _IdentityClient([{"id": "u1", "signInActivity": {"lastSuccessfulSignInDateTime": _iso(5)}}])
    result = IdentityCollector().run({"client": client, "top": 999, "page_size": 999})

    assert result.status == "ok"
    signin_requests = [params for path, params in client.requests if "signInActivity" in str(params.get("$select"))]
    assert signin_requests == [{"$select": "id,signInActivity", "$top": "500"}]
    assert result.payload["userSignInActivity"]["value"][0]["id"] == "u1"


def test_identity_records_coverage_gap_when_signin_activity_is_unlicensed() -> None:
    client = _IdentityClient(GraphError("Tenant does not have a premium license", status=403, request="/users"))
    result = IdentityCollector().run({"client": client, "top": 100})

    assert result.status == "partial"
    assert result.payload["users"]["value"][0]["id"] == "u1"
    row = next(item for item in result.coverage or [] if item["name"] == "userSignInActivity")
    assert row["error_class"] == "license_required"
    assert row["capability_gated"] is True
    assert "sign-in activity unavailable" in result.message
    snapshot = build_normalized_snapshot(tenant_name="t", run_id="r", collector_payloads={"identity": result.payload})
    user = snapshot["users"]["records"][0]
    assert "signin_data_available" not in user
    findings = build_findings([], normalized_snapshot=snapshot)
    assert not [item for item in findings if "stale" in str(item.get("rule_id"))]


def _identity_payload(users: list[dict[str, Any]], signin: list[dict[str, Any]] | None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "users": {"value": users},
        "roleDefinitions": {"value": [{"id": "role-ga", "displayName": "Global Administrator"}]},
        "roleAssignments": {"value": [{"id": "ra-1", "principalId": "admin-1", "roleDefinitionId": "role-ga"}]},
    }
    if signin is None:
        payload["userSignInActivity"] = {"error": "forbidden", "error_class": "insufficient_permissions"}
    else:
        payload["userSignInActivity"] = {"value": signin}
    return payload


def _stale_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    snapshot = build_normalized_snapshot(tenant_name="t", run_id="r", collector_payloads={"identity": payload})
    return [
        item
        for item in build_findings([], normalized_snapshot=snapshot)
        if item.get("rule_id") in {"identity.stale_enabled_account", "identity.privileged_stale_account"}
    ]


def test_stale_and_privileged_stale_findings_fire_from_signin_activity() -> None:
    users = [
        {"id": "user-1", "userPrincipalName": "old@contoso.test", "accountEnabled": True, "createdDateTime": _iso(400)},
        {"id": "user-2", "userPrincipalName": "never@contoso.test", "accountEnabled": True, "createdDateTime": _iso(200)},
        {"id": "user-3", "userPrincipalName": "active@contoso.test", "accountEnabled": True, "createdDateTime": _iso(400)},
        {"id": "user-4", "userPrincipalName": "new@contoso.test", "accountEnabled": True, "createdDateTime": _iso(10)},
        {"id": "user-5", "userPrincipalName": "disabled@contoso.test", "accountEnabled": False, "createdDateTime": _iso(400)},
        {"id": "admin-1", "userPrincipalName": "admin@contoso.test", "accountEnabled": True, "createdDateTime": _iso(400)},
    ]
    signin = [
        {"id": "user-1", "signInActivity": {"lastSuccessfulSignInDateTime": _iso(120), "lastSignInDateTime": _iso(3)}},
        {"id": "user-2", "signInActivity": None},
        {"id": "user-3", "signInActivity": {"lastSuccessfulSignInDateTime": _iso(2)}},
        {"id": "user-4", "signInActivity": None},
        {"id": "user-5", "signInActivity": None},
        {"id": "admin-1", "signInActivity": {"lastSuccessfulSignInDateTime": _iso(150)}},
    ]
    findings = _stale_findings(_identity_payload(users, signin))
    by_rule: dict[str, set[str]] = {}
    for item in findings:
        by_rule.setdefault(item["rule_id"], set()).update(item["affected_objects"])

    assert by_rule["identity.stale_enabled_account"] == {"old@contoso.test", "never@contoso.test"}
    assert by_rule["identity.privileged_stale_account"] == {"admin@contoso.test"}
    privileged = next(item for item in findings if item["rule_id"] == "identity.privileged_stale_account")
    assert privileged["severity"] == "high"
    assert privileged["evidence"]["privileged_roles"] == ["Global Administrator"]
    assert privileged["framework_mappings"]["mcsb"]


def test_stale_findings_stay_silent_without_signin_data() -> None:
    users = [{"id": "user-1", "accountEnabled": True, "createdDateTime": _iso(400)}]
    assert _stale_findings(_identity_payload(users, None)) == []


# --- reports_usage concealed names ------------------------------------------


def test_reports_usage_concealed_names_finding() -> None:
    payload = {"reportSettings": {"value": [{"id": "reportSettings", "displayConcealedNames": True}]}}
    snapshot = build_normalized_snapshot(tenant_name="t", run_id="r", collector_payloads={"reports_usage": payload})
    findings = [item for item in build_findings([], normalized_snapshot=snapshot) if item["rule_id"] == "reports_usage.concealed_names"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "low"
    assert "hashed" in findings[0]["description"]

    payload["reportSettings"]["value"][0]["displayConcealedNames"] = False
    snapshot = build_normalized_snapshot(tenant_name="t", run_id="r", collector_payloads={"reports_usage": payload})
    assert not [item for item in build_findings([], normalized_snapshot=snapshot) if item["rule_id"] == "reports_usage.concealed_names"]


# --- API inventory beta tracking ---------------------------------------------


def test_api_inventory_records_api_version_for_beta_and_v1_calls() -> None:
    inventory = build_api_call_inventory(
        platform="m365",
        selected_collectors=["intune_depth"],
        capability_rows=[],
        coverage_rows=[
            {"collector": "intune_depth", "type": "graph", "name": "deviceConfigurations", "endpoint": "/deviceManagement/deviceConfigurations", "status": "ok"},
            {
                "collector": "intune_depth",
                "type": "graph",
                "name": "deviceManagementScripts",
                "endpoint": "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts",
                "api_version": "beta",
                "status": "ok",
            },
        ],
        data_handling={},
    )
    versions = {call["name"]: call["api_version"] for call in inventory["observed_calls"]}
    assert versions == {"deviceConfigurations": "v1.0", "deviceManagementScripts": "beta"}
    assert inventory["counts"]["beta_calls"] == 1
    assert inventory["safety"]["read_only"] is True


# --- Intune licence vs scope -------------------------------------------------


_INTUNE_FORBIDDEN = {
    "collector": "intune",
    "type": "graph",
    "name": "managedDevices",
    "endpoint": "/deviceManagement/managedDevices",
    "status": "failed",
    "error_class": "insufficient_permissions",
    "error": '{"ErrorCode":"Forbidden","Message":"..."}',
}


def _licensing(skus: list[dict[str, Any]]) -> dict[str, Any]:
    return {"licensing": {"subscribedSkus": {"value": skus}}}


def _reconciled_blocker(collector_payloads: dict[str, Any] | None) -> str:
    coverage = relabel_intune_license_blockers([dict(_INTUNE_FORBIDDEN)], collector_payloads)
    rows = reconcile_capability_matrix_rows(
        [
            {
                "collector": "intune",
                "status": "supported_exact_scope",
                "reason": "required_permissions_present",
                "required_permissions": ["DeviceManagementManagedDevices.Read.All"],
                "missing_permissions": [],
            }
        ],
        [{"name": "intune", "status": "partial"}],
        coverage_rows=coverage,
        collector_payloads=collector_payloads,
    )
    return rows[0]["blocker_kind"]


def test_intune_forbidden_without_intune_sku_is_classified_as_license() -> None:
    payloads = _licensing(
        [{"skuPartNumber": "O365_BUSINESS_PREMIUM", "capabilityStatus": "Enabled", "servicePlans": [{"servicePlanName": "EXCHANGE_S_STANDARD"}]}]
    )
    assert intune_license_state(payloads) == "absent"
    relabelled = relabel_intune_license_blockers([dict(_INTUNE_FORBIDDEN)], payloads)
    assert relabelled[0]["error_class"] == "license_required"
    assert relabelled[0]["original_error_class"] == "insufficient_permissions"
    assert _reconciled_blocker(payloads) == "license"


def test_intune_forbidden_with_intune_sku_stays_auth_scope() -> None:
    payloads = _licensing(
        [{"skuPartNumber": "CUSTOM", "capabilityStatus": "Enabled", "servicePlans": [{"servicePlanName": "INTUNE_A", "provisioningStatus": "Success"}]}]
    )
    assert intune_license_state(payloads) == "present"
    assert relabel_intune_license_blockers([dict(_INTUNE_FORBIDDEN)], payloads)[0]["error_class"] == "insufficient_permissions"
    assert _reconciled_blocker(payloads) == "auth_scope"


def test_intune_forbidden_without_licensing_data_stays_auth_scope() -> None:
    assert intune_license_state({}) == "unknown"
    assert intune_license_state({"licensing": {"subscribedSkus": {"error": "x", "error_class": "insufficient_permissions"}}}) == "unknown"
    assert _reconciled_blocker({}) == "auth_scope"


def test_missing_scope_wins_over_licence_signal() -> None:
    row = {
        "collector": "intune",
        "status": "partial",
        "missing_permissions": ["DeviceManagementManagedDevices.Read.All"],
        "license_state": "absent",
        "endpoint_statuses": [{"name": "managedDevices", "status": "failed", "error_class": "license_required"}],
    }
    assert classify_capability_blocker(row)["blocker_kind"] == "auth_scope"


# --- compare --format md -----------------------------------------------------


def _run_with_findings(tmp_path: Path, name: str, created: str, findings: list[dict[str, Any]], grade: str) -> Path:
    return (
        RunBundleBuilder(tmp_path, name=name)
        .manifest(run_id=name, created_utc=created)
        .report_pack(
            summary={"tenant_name": "acme", "overall_status": "ok", "finding_count": len(findings), "risk": {"grade": grade, "score": 10}},
            findings=findings,
        )
        .build()
    )


def test_compare_markdown_summarises_new_resolved_and_changed_findings(tmp_path: Path, capsys) -> None:
    before = _run_with_findings(
        tmp_path,
        "run-a",
        "2026-09-01T00:00:00Z",
        [
            {"id": "f-keep", "rule_id": "x.keep", "severity": "medium", "status": "open", "title": "Kept finding"},
            {"id": "f-gone", "rule_id": "x.gone", "severity": "high", "status": "open", "title": "Fixed finding"},
        ],
        "high",
    )
    after = _run_with_findings(
        tmp_path,
        "run-b",
        "2026-09-20T00:00:00Z",
        [
            {"id": "f-keep", "rule_id": "x.keep", "severity": "high", "status": "open", "title": "Kept finding"},
            {"id": "f-new", "rule_id": "x.new", "severity": "critical", "status": "open", "title": "Brand new finding"},
        ],
        "critical",
    )

    rc = auditex_cli.main(["compare", "--run-dir", str(before), "--run-dir", str(after), "--format", "md"])
    output = capsys.readouterr().out

    assert rc == 0
    assert "# Auditex Run Comparison" in output
    assert "Risk grade: high -> critical" in output
    assert "New findings: 1 (critical 1)" in output
    assert "Resolved findings: 1 (high 1)" in output
    assert "Changed findings: 1 (high 1)" in output
    assert "| critical | Brand new finding | x.new |" in output
    assert "| high | medium | open | open | Kept finding | x.keep |" in output


def test_compare_defaults_to_json(tmp_path: Path, capsys) -> None:
    import json

    before = _run_with_findings(tmp_path, "run-a", "2026-09-01T00:00:00Z", [], "clean")
    after = _run_with_findings(tmp_path, "run-b", "2026-09-02T00:00:00Z", [], "clean")
    assert auditex_cli.main(["compare", "--run-dir", str(before), "--run-dir", str(after)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["runs"]) == 2


def test_compare_markdown_handles_blocked_and_single_run() -> None:
    assert "At least two runs" in render_compare_markdown({"runs": [{"run_id": "only"}]})
    blocked = render_compare_markdown(
        {
            "runs": [{"run_id": "a"}, {"run_id": "b"}],
            "baseline_diff": {"status": "blocked", "reason": "same_tenant_required"},
        }
    )
    assert "Status: blocked (same_tenant_required)" in blocked


# --- offline handoff -----------------------------------------------------------


def test_offline_handoff_prints_live_readiness_not_applicable(tmp_path: Path) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .manifest(mode="offline")
        .report_pack(summary={"tenant_name": "acme", "overall_status": "ok"}, findings=[], evidence_paths=[])
        .build()
    )
    payload = enterprise_handoff(run_dir)
    assert payload["quality"]["live_readiness"] == "n/a (offline)"
    assert "- Live readiness: n/a (offline)" in render_enterprise_handoff_markdown(payload)


def test_live_handoff_keeps_trust_level(tmp_path: Path) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .live_readiness({"trust_level": "partial"})
        .report_pack(summary={"tenant_name": "acme", "overall_status": "ok"}, findings=[], evidence_paths=[])
        .build()
    )
    assert "- Live readiness: partial" in render_enterprise_handoff_markdown(enterprise_handoff(run_dir))
