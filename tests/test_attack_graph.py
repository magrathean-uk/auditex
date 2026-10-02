from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from azure_tenant_audit.attack_graph import analyze_attack_graph
from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.findings import build_findings, build_report_pack
from azure_tenant_audit.normalize import build_normalized_snapshot

REPO_ROOT = Path(__file__).resolve().parents[1]
KNOWN_BAD = REPO_ROOT / "examples" / "sample_audit_bundle" / "known_bad_result.json"
DEMO_TENANT = Path(__file__).resolve().parents[1] / "examples" / "demo_tenant" / "demo_tenant.json"

GA = "62e90394-69f5-4237-9190-012177145e10"
PRA = "e8611ab8-c189-46e8-94e1-60213ab1f814"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
ROLE_MANAGEMENT_RW = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"


def _user(user_id: str, upn: str, user_type: str = "Member") -> dict[str, Any]:
    return {"id": user_id, "displayName": upn.split("@")[0], "userPrincipalName": upn, "userType": user_type, "accountEnabled": True}


def _payloads() -> dict[str, Any]:
    return {
        "identity": {
            "users": {
                "value": [
                    _user("u-admin", "admin@contoso.example"),
                    _user("u-owner", "owner@contoso.example"),
                    _user("u-nested", "nested@contoso.example"),
                    _user("u-eligible", "eligible@contoso.example"),
                    _user("u-plain", "plain@contoso.example"),
                ]
            },
            "groups": {
                "value": [
                    {"id": "g-ra", "displayName": "Tier0 Admins", "isAssignableToRole": True},
                    {"id": "g-outer", "displayName": "Ops Leads"},
                ]
            },
            "servicePrincipals": {
                "value": [
                    {"id": "sp-app", "displayName": "Payroll Export", "appId": "app-payroll"},
                    {"id": "sp-graph", "displayName": "Microsoft Graph", "appId": GRAPH_APP_ID},
                ]
            },
            "roleDefinitions": {
                "value": [
                    {"id": GA, "displayName": "Global Administrator"},
                    {"id": PRA, "displayName": "Privileged Role Administrator"},
                ]
            },
            "roleAssignments": {
                "value": [
                    {"id": "ra-admin", "principalId": "u-admin", "roleDefinitionId": GA},
                    {"id": "ra-group", "principalId": "g-ra", "roleDefinitionId": GA},
                ]
            },
            "roleAssignableGroupMembers": {
                "value": [
                    {"groupId": "g-ra", "displayName": "Tier0 Admins", "members": [{"@odata.type": "#microsoft.graph.group", "id": "g-outer", "displayName": "Ops Leads"}]},
                    {"groupId": "g-outer", "displayName": "Ops Leads", "members": [{"@odata.type": "#microsoft.graph.user", "id": "u-nested", "displayName": "nested"}]},
                ]
            },
        },
        "app_consent": {
            "servicePrincipals": {"value": [{"id": "sp-app", "displayName": "Payroll Export", "appId": "app-payroll"}]},
            "servicePrincipalOwners": {
                "value": [
                    {
                        "servicePrincipalId": "sp-app",
                        "displayName": "Payroll Export",
                        "owners": [{"@odata.type": "#microsoft.graph.user", "id": "u-owner", "displayName": "owner"}],
                    }
                ]
            },
            "servicePrincipalAppRoleAssignments": {
                "value": [
                    {
                        "servicePrincipalId": "sp-graph",
                        "displayName": "Microsoft Graph",
                        "assignments": [
                            {
                                "id": "assign-rm",
                                "appRoleId": ROLE_MANAGEMENT_RW,
                                "principalId": "sp-app",
                                "principalDisplayName": "Payroll Export",
                                "principalType": "ServicePrincipal",
                                "resourceId": "sp-graph",
                            }
                        ],
                    }
                ]
            },
        },
        "identity_governance": {
            "roleEligibilitySchedules": {
                "value": [{"id": "elig-1", "principalId": "u-eligible", "roleDefinitionId": PRA, "memberType": "Direct"}]
            }
        },
        "auth_methods": {
            "userRegistrationDetails": {
                "value": [
                    {"id": "u-owner", "userPrincipalName": "owner@contoso.example", "isMfaRegistered": True},
                    {"id": "u-eligible", "userPrincipalName": "eligible@contoso.example", "isMfaRegistered": False},
                ]
            }
        },
    }


def _snapshot(payloads: dict[str, Any] | None = None) -> dict[str, Any]:
    return build_normalized_snapshot(tenant_name="contoso", run_id="run-1", collector_payloads=payloads or _payloads())


def _path_from(analysis: dict[str, Any], source_label: str) -> dict[str, Any] | None:
    return next((path for path in analysis["paths"] if path["source"] == source_label), None)


def test_app_owner_path_to_role_management_permission() -> None:
    analysis = analyze_attack_graph(_snapshot())
    path = _path_from(analysis, "owner@contoso.example")

    assert path is not None
    assert path["target"] == "Microsoft Graph RoleManagement.ReadWrite.Directory"
    assert [hop["edge"] for hop in path["hops"]] == ["owns", "has_app_role"]
    assert path["techniques"] == ["T1098.001", "T1098.003"]
    assert [(item["from"], item["to"], item["edge"]) for item in path["breakpoints"]] == [
        ("owner@contoso.example", "Payroll Export", "owns"),
        ("Payroll Export", "Microsoft Graph RoleManagement.ReadWrite.Directory", "has_app_role"),
    ]
    assert path["severity"] == "critical"
    assert path["finding_id"] == path["id"]
    # Compatibility shape used by the explorer, demo, and Markdown report.
    assert path["chain"] == ["owns", "has_app_role"]
    assert all({"stage", "title", "severity", "finding_id"} <= set(stage) for stage in path["findings"])
    assert path["findings"][0]["title"] == "owner@contoso.example → Payroll Export"


def test_nested_group_into_role_assignable_group_reaches_global_admin() -> None:
    analysis = analyze_attack_graph(_snapshot())
    path = _path_from(analysis, "nested@contoso.example")

    assert path is not None
    assert path["target"] == "Global Administrator"
    assert [(hop["from"], hop["to"], hop["edge"]) for hop in path["hops"]] == [
        ("nested@contoso.example", "Ops Leads", "member_of"),
        ("Ops Leads", "Tier0 Admins", "member_of"),
        ("Tier0 Admins", "Global Administrator", "has_role"),
    ]
    assert len(path["breakpoints"]) == 3
    assert analysis["summary"]["tier0_principals"] >= 2  # u-admin and the role-assignable group


def test_pim_eligible_assignment_is_marked_and_no_mfa_entry_hop_is_added() -> None:
    analysis = analyze_attack_graph(_snapshot())
    path = _path_from(analysis, "eligible@contoso.example")

    assert path is not None
    assert path["eligible"] is True
    assert path["foothold"] == "no_mfa"
    assert path["hops"][0]["edge"] == "no_mfa"
    assert path["hops"][0]["technique"] == "T1078.004"
    role_hop = path["hops"][-1]
    assert role_hop["edge"] == "has_role" and role_hop["eligible"] is True
    assert role_hop["evidence_ref"]["artifact_path"] == "normalized/governance_objects.json"
    assert "PIM-eligible" in path["summary"]
    assert path["hop_count"] == 1


def test_no_path_when_owner_removed() -> None:
    payloads = _payloads()
    payloads["app_consent"]["servicePrincipalOwners"]["value"] = []
    analysis = analyze_attack_graph(_snapshot(payloads))

    assert _path_from(analysis, "owner@contoso.example") is None
    assert not any(path["target"].endswith("RoleManagement.ReadWrite.Directory") for path in analysis["paths"])


def test_privileged_principals_are_not_footholds() -> None:
    analysis = analyze_attack_graph(_snapshot())

    assert _path_from(analysis, "admin@contoso.example") is None
    assert _path_from(analysis, "plain@contoso.example") is None


def test_depth_bound() -> None:
    payloads = _payloads()
    chain = [f"g-{index}" for index in range(6)]
    payloads["identity"]["groups"]["value"].extend({"id": group_id, "displayName": group_id} for group_id in chain)
    members = payloads["identity"]["roleAssignableGroupMembers"]["value"]
    members.append({"groupId": "g-ra", "members": [{"@odata.type": "#microsoft.graph.group", "id": chain[0]}]})
    for parent, child in zip(chain, chain[1:]):
        members.append({"groupId": parent, "members": [{"@odata.type": "#microsoft.graph.group", "id": child}]})
    payloads["identity"]["users"]["value"].append(_user("u-deep", "deep@contoso.example"))
    members.append({"groupId": chain[-1], "members": [{"@odata.type": "#microsoft.graph.user", "id": "u-deep"}]})
    snapshot = _snapshot(payloads)

    # deep -> g-5 -> ... -> g-0 -> g-ra -> GA is 8 hops.
    assert _path_from(analyze_attack_graph(snapshot), "deep@contoso.example") is None
    deep = _path_from(analyze_attack_graph(snapshot, max_depth=8), "deep@contoso.example")
    assert deep is not None and deep["hop_count"] == 8
    assert all(path["hop_count"] <= 5 for path in analyze_attack_graph(snapshot)["paths"])


def test_count_bound_keeps_highest_risk_paths() -> None:
    payloads = _payloads()
    owners = payloads["app_consent"]["servicePrincipalOwners"]["value"]
    assignments = payloads["app_consent"]["servicePrincipalAppRoleAssignments"]["value"][0]["assignments"]
    for index in range(15):
        user_id = f"u-app-owner-{index}"
        sp_id = f"sp-extra-{index}"
        payloads["identity"]["users"]["value"].append(_user(user_id, f"appowner{index}@contoso.example"))
        payloads["identity"]["servicePrincipals"]["value"].append({"id": sp_id, "displayName": f"Extra {index}", "appId": f"app-{index}"})
        owners.append({"servicePrincipalId": sp_id, "owners": [{"@odata.type": "#microsoft.graph.user", "id": user_id}]})
        assignments.append({"id": f"assign-{index}", "appRoleId": ROLE_MANAGEMENT_RW, "principalId": sp_id, "principalType": "ServicePrincipal", "resourceId": "sp-graph"})
    analysis = analyze_attack_graph(_snapshot(payloads))

    assert len(analysis["paths"]) == 10
    assert analysis["summary"]["paths_found"] > 10
    scores = [path["risk_score"] for path in analysis["paths"]]
    assert scores == sorted(scores, reverse=True)
    assert len(analyze_attack_graph(_snapshot(payloads), max_paths=3)["paths"]) == 3


def test_every_hop_evidence_ref_points_at_a_normalized_record() -> None:
    snapshot = _snapshot()
    analysis = analyze_attack_graph(snapshot)

    assert analysis["paths"]
    for path in analysis["paths"]:
        for hop in path["hops"] + path["breakpoints"]:
            ref = hop["evidence_ref"]
            assert ref["artifact_kind"] == "normalized_json"
            assert ref["collector"]
            section = ref["artifact_path"].removeprefix("normalized/").removesuffix(".json")
            keys = {record.get("key") for record in snapshot[section]["records"]}
            assert ref["record_key"] in keys, (section, ref["record_key"])


def test_findings_and_report_pack_carry_graph_paths() -> None:
    snapshot = _snapshot()
    findings = build_findings([], normalized_snapshot=snapshot)
    by_rule = {item["rule_id"]: item for item in findings if str(item.get("rule_id")).startswith("attack_path.")}

    assert "attack_path.app_owner_to_tier0" in by_rule
    owner_finding = by_rule["attack_path.app_owner_to_tier0"]
    assert owner_finding["severity"] == "critical"
    assert "T1098.001" in owner_finding["framework_mappings"]["mitre_attack"]
    assert {ref["artifact_path"] for ref in owner_finding["evidence_refs"]} == {
        "normalized/app_owner_edges.json",
        "normalized/application_consents.json",
    }

    analysis = analyze_attack_graph(snapshot)
    pack = build_report_pack(
        tenant_name="contoso",
        overall_status="ok",
        findings=findings,
        evidence_paths=[],
        attack_graph=analysis,
    )
    assert pack["attack_paths"][0]["kind"] == "privilege_graph"
    assert pack["attack_graph"]["node_count"] == analysis["summary"]["node_count"]
    finding_ids = {item["id"] for item in findings}
    for path in pack["attack_paths"]:
        if path.get("finding_id"):
            assert path["finding_id"] in finding_ids


def test_keyword_path_is_kept_when_graph_has_no_path() -> None:
    findings = [
        {"id": "f-1", "rule_id": "identity.user_mfa_not_registered", "title": "MFA missing", "severity": "medium", "status": "open", "category": "identity"},
        {"id": "f-2", "rule_id": "app_consent.high_privilege", "title": "OAuth grant", "severity": "high", "status": "open", "category": "app_consent"},
    ]
    empty = analyze_attack_graph({})
    pack = build_report_pack(tenant_name="t", overall_status="ok", findings=findings, evidence_paths=[], attack_graph=empty)

    assert pack["attack_paths"][0]["id"] == "attack_path:primary"
    assert pack["attack_graph"]["path_count"] == 0


def test_long_lived_app_secret_is_a_foothold_without_sensitive_keys() -> None:
    import re

    payloads = _payloads()
    payloads["identity"]["applications"] = {"value": [{"id": "app-obj", "displayName": "Payroll Export", "signInAudience": "AzureADMyOrg"}]}
    payloads["app_credentials"] = {
        "applicationCredentials": {
            "value": [
                {
                    "id": "app-obj",
                    "display_name": "Payroll Export",
                    "app_id": "app-payroll",
                    "password_credentials": [
                        {"key_id": "k1", "start_date_time": "2024-01-01T00:00:00Z", "end_date_time": "2099-01-01T00:00:00Z"}
                    ],
                }
            ]
        }
    }
    analysis = analyze_attack_graph(_snapshot(payloads))
    path = _path_from(analysis, "Payroll Export")

    assert path is not None
    assert path["foothold"] == "long_lived_secret"
    assert [hop["edge"] for hop in path["hops"]] == ["credential", "authenticates_as", "has_app_role"]
    assert path["hops"][0]["technique"] == "T1552"
    assert path["hops"][0]["evidence_ref"]["artifact_path"] == "normalized/application_credential_objects.json"

    sensitive = re.compile(r"(secret|password|credential|token|authorization)", re.IGNORECASE)

    def keys(value: Any) -> list[str]:
        if isinstance(value, dict):
            return [str(key) for key in value] + [item for child in value.values() for item in keys(child)]
        if isinstance(value, list):
            return [item for child in value for item in keys(child)]
        return []

    assert not [key for key in keys(analysis) if sensitive.search(key)]


def test_offline_known_bad_bundle_stays_contract_valid(tmp_path: Path) -> None:
    assert run_offline(KNOWN_BAD, tmp_path, "contoso", "kb") == 0
    run_dir = tmp_path / "contoso-kb"
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    report_pack = json.loads((run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))

    assert validation["valid"] is True, validation["issues"]
    assert "attack_paths" in report_pack


def test_offline_demo_tenant_reports_graph_paths_with_valid_contract(tmp_path: Path) -> None:
    sample = json.loads(DEMO_TENANT.read_text(encoding="utf-8"))
    sample_path = tmp_path / "demo.json"
    sample_path.write_text(json.dumps(copy.deepcopy(sample)), encoding="utf-8")

    assert run_offline(sample_path, tmp_path, "halcyon", "graph") == 0
    run_dir = tmp_path / "halcyon-graph"
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    report_pack = json.loads((run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))
    findings = json.loads((run_dir / "findings" / "findings.json").read_text(encoding="utf-8"))

    assert validation["valid"] is True, validation["issues"]
    first = report_pack["attack_paths"][0]
    assert first["kind"] == "privilege_graph"
    assert first["source"] == "tom.fielding@halcyonfreight.example"
    assert first["target"].endswith("RoleManagement.ReadWrite.Directory")
    assert report_pack["attack_graph"]["edge_count"] > 0
    rules = {item.get("rule_id") for item in findings}
    assert "attack_path.app_owner_to_tier0" in rules
    for path in report_pack["attack_paths"]:
        for hop in path["hops"]:
            assert (run_dir / hop["evidence_ref"]["artifact_path"]).is_file()


class _IdentityClient:
    def __init__(self) -> None:
        self.paths: list[tuple[str, dict[str, Any]]] = []

    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        return {"value": []}

    def get_all(self, path, params=None):  # noqa: ANN001
        self.paths.append((path, dict(params or {})))
        responses = {
            "/groups": [{"id": "g-ra", "displayName": "Tier0", "isAssignableToRole": True}, {"id": "g-plain"}],
            "/roleManagement/directory/roleAssignments": [{"id": "ra-1", "principalId": "g-ra", "roleDefinitionId": GA}],
            "/groups/g-ra/members": [{"@odata.type": "#microsoft.graph.group", "id": "g-nested"}],
            "/groups/g-nested/members": [{"@odata.type": "#microsoft.graph.user", "id": "u-1"}],
            "/groups/g-ra/owners": [{"@odata.type": "#microsoft.graph.user", "id": "u-owner"}],
        }
        return responses.get(path, [])


def test_identity_collector_reads_privileged_group_members_and_owners_only() -> None:
    from azure_tenant_audit.collectors.identity import IdentityCollector

    client = _IdentityClient()
    result = IdentityCollector().run({"client": client, "top": 500, "audit_logger": None})

    fanout = [path for path, _params in client.paths if path.startswith("/groups/")]
    assert fanout == ["/groups/g-ra/members", "/groups/g-ra/owners", "/groups/g-nested/members", "/groups/g-nested/owners"]
    assert all(params == {"$select": "id,displayName,userPrincipalName"} for path, params in client.paths if path.startswith("/groups/"))
    groups_params = next(params for path, params in client.paths if path == "/groups")
    assert "isAssignableToRole" in groups_params["$select"]
    members = result.payload["roleAssignableGroupMembers"]["value"]
    assert [row["groupId"] for row in members] == ["g-ra", "g-nested"]
    assert result.payload["roleAssignableGroupOwners"]["value"][0]["owners"][0]["id"] == "u-owner"
    assert {row["name"] for row in result.coverage} >= {"roleAssignableGroupMembers", "roleAssignableGroupOwners"}


def test_app_credentials_collector_keeps_owner_ids_for_the_graph() -> None:
    from azure_tenant_audit.collectors.app_credentials import AppCredentialsCollector

    class _Client:
        def get_all(self, path, params=None):  # noqa: ANN001, ARG002
            return [{"id": "app-1", "displayName": "Bot", "appId": "a1"}] if path == "/applications" else []

        def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
            if path == "/applications/app-1/owners":
                return {"value": [{"@odata.type": "#microsoft.graph.user", "id": "owner-1"}]}
            return {"value": []}

    result = AppCredentialsCollector().run({"client": _Client(), "top": 100})
    app = result.payload["applicationCredentials"]["value"][0]
    assert app["owner_count"] == 1
    assert app["owners"] == [{"id": "owner-1", "@odata.type": "#microsoft.graph.user"}]

    snapshot = build_normalized_snapshot(
        tenant_name="t", run_id="r", collector_payloads={"app_credentials": result.payload}
    )
    edge = snapshot["app_owner_edges"]["records"][0]
    assert edge["target_type"] == "application" and edge["owner_id"] == "owner-1"


def test_app_consent_fanout_includes_microsoft_graph_beyond_first_ten() -> None:
    from azure_tenant_audit.collectors.app_consent import AppConsentCollector

    principals = [{"id": f"sp-{index}", "displayName": f"App {index}", "appId": f"app-{index}"} for index in range(12)]
    principals.append({"id": "sp-graph", "displayName": "Microsoft Graph", "appId": GRAPH_APP_ID})

    class _Client:
        def __init__(self) -> None:
            self.paths: list[str] = []

        def get_all(self, path, params=None):  # noqa: ANN001, ARG002
            self.paths.append(path)
            if path == "/servicePrincipals":
                return principals
            return []

        def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
            return {"value": self.get_all(path, params)}

    client = _Client()
    AppConsentCollector().run({"client": client, "top": 100, "audit_logger": None})
    assert "/servicePrincipals/sp-graph/appRoleAssignedTo" in client.paths
    assert "/servicePrincipals/sp-11/appRoleAssignedTo" not in client.paths
