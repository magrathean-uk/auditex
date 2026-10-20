"""Every emitted finding carries a rule_id and a template.

A finding with no rule cannot reach a framework control, a finding template or a baseline status, so
an open finding in its area would leave the matching controls reading ``pass``. This runs every
finding builder over the offline fixtures and the demo tenant, checks the builders that no fixture
reaches statically, and checks that the runtime refuses a rule-less finding.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit import findings as m365_findings
from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.findings import _finalize_finding, build_findings
from auditex.google_workspace import findings as google_findings
from auditex.google_workspace.run import run_google_offline

REPO = Path(__file__).resolve().parents[1]
TEMPLATES = json.loads((REPO / "configs" / "finding-templates.json").read_text(encoding="utf-8"))
MAPPINGS = json.loads((REPO / "configs" / "control-mappings.json").read_text(encoding="utf-8"))
TEMPLATE_FIELDS = ("risk_rating", "description", "impact", "remediation", "control_ids", "expected_value")
M365_FIXTURES = [
    *sorted(path for path in (REPO / "examples" / "sample_audit_bundle").glob("*.json") if not path.name.startswith("external_")),
    *sorted((REPO / "examples" / "demo_tenant").glob("*.json")),
]
# Findings that used to be emitted with no rule, and the rule each one reports under now.
FORMERLY_RULELESS = {
    "sharepoint.site_orphaned",
    "onedrive.external_sharing_enabled",
    "exchange.mailbox_forwarding_configured",
    "teams.external_federation_open",
    "identity_governance.standing_privilege_only",
    "intune_depth.policies_without_assignments",
    "ca.policy_report_only",
    "ca.break_glass_exclusion_missing",
}


def _read_in_full(*sources: str, **overrides: dict[str, Any]) -> dict[str, Any]:
    """A normalization_coverage section saying each source was read without error, cut or unreadable rows."""
    return {"normalization_coverage": {"records": [
        {"source": source, "collection_status": "collected", "complete": True, "record_count": 3, **overrides.get(source, {})}
        for source in sources
    ]}}


def _assert_rule_and_template(finding: dict[str, Any], *, templates: dict[str, Any] = TEMPLATES) -> None:
    rule_id = finding.get("rule_id")
    where = f"{finding.get('id')!r} ({finding.get('collector')})"
    assert isinstance(rule_id, str) and rule_id.strip(), f"finding {where} has no rule_id"
    template = templates.get(rule_id)
    assert isinstance(template, dict), f"finding {where}: rule {rule_id} has no template"
    for field in TEMPLATE_FIELDS:
        assert template.get(field), f"template for {rule_id} lacks {field}"
    assert finding.get("control_ids"), f"finding {where} carries no template control ids"
    assert finding.get("description") and finding.get("remediation"), f"finding {where} carries no template text"


def _run_findings(tmp_path: Path, fixture: Path) -> list[dict[str, Any]]:
    name = fixture.stem.replace("_", "-")
    assert run_offline(fixture, tmp_path, "inv", name, auditor_profile="global-reader", plane="inventory") in {0, 1}
    path = tmp_path / f"inv-{name}" / "findings" / "findings.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def test_every_m365_fixture_finding_has_a_rule_id_and_template(tmp_path: Path) -> None:
    seen: set[str] = set()
    for fixture in M365_FIXTURES:
        findings = _run_findings(tmp_path, fixture)
        for finding in findings:
            _assert_rule_and_template(finding)
            seen.add(finding["rule_id"])

    assert len(seen) > 30
    assert FORMERLY_RULELESS <= seen, f"fixtures no longer reach {sorted(FORMERLY_RULELESS - seen)}"


def test_demo_tenant_emits_no_finding_without_a_rule_id(tmp_path: Path) -> None:
    for fixture in sorted((REPO / "examples" / "demo_tenant").glob("*.json")):
        findings = _run_findings(tmp_path, fixture)
        assert findings
        assert [item["id"] for item in findings if not item.get("rule_id")] == []


def test_every_new_rule_has_a_control_mapping_with_a_framework_floor() -> None:
    for rule_id in FORMERLY_RULELESS | {"sharepoint.site_weak_ownership"}:
        mapping = MAPPINGS[rule_id]
        assert mapping.get("nist_800_53") or mapping.get("iso_27001"), rule_id


def _finding_dict_literals(tree: ast.AST) -> list[ast.Dict]:
    required = {"id", "severity", "category", "title", "status", "collector"}
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            keys = {key.value for key in node.keys if isinstance(key, ast.Constant) and isinstance(key.value, str)}
            if required <= keys:
                found.append(node)
    return found


def test_no_m365_finding_builder_omits_its_rule_id() -> None:
    source = Path(m365_findings.__file__).read_text(encoding="utf-8")
    literals = _finding_dict_literals(ast.parse(source))

    assert len(literals) > 40, "the scan should see every finding builder"
    missing = []
    for node in literals:
        keys = [key.value if isinstance(key, ast.Constant) else None for key in node.keys]
        if "rule_id" not in keys and None not in keys:  # None marks a ``**spread`` that supplies the rule
            missing.append(node.lineno)
    assert missing == [], f"finding dicts without a rule_id at findings.py lines {missing}"


def test_finalising_a_finding_without_a_rule_id_fails_loudly() -> None:
    body = {"id": "x:1", "severity": "low", "title": "T", "status": "open", "collector": "identity", "category": "identity"}

    with pytest.raises(ValueError, match="no rule_id"):
        _finalize_finding(body)
    with pytest.raises(ValueError, match="no rule_id"):
        _finalize_finding({**body, "rule_id": "  "})
    assert _finalize_finding({**body, "rule_id": "identity.stale_enabled_account"})["rule_id"] == "identity.stale_enabled_account"


def test_an_unmapped_conditional_access_finding_type_fails_loudly() -> None:
    snapshot = {"ca_findings": {"records": [{"id": "p", "finding_type": "ca_something_new", "severity": "low"}]}}

    with pytest.raises(ValueError, match="ca_something_new"):
        build_findings([], normalized_snapshot=snapshot)


def test_each_formerly_ruleless_builder_reports_under_its_rule() -> None:
    snapshot = {
        "ca_findings": {"records": [
            {"id": "p1", "finding_type": "ca_reporting_only", "policy_id": "p1", "severity": "medium"},
            {"id": "p2:x", "finding_type": "ca_break_glass_exclusion", "policy_id": "p2", "severity": "high"},
        ]},
        "sharepoint_site_posture_objects": {"records": [
            {"id": "s1", "site_name": "Orphan", "ownership_state": "orphaned"},
            {"id": "s2", "site_name": "Weak", "ownership_state": "weak"},
            {"id": "s3", "site_name": "Fine", "ownership_state": "sampled"},
        ]},
        "onedrive_posture_objects": {"records": [{"id": "o1", "site_kind": "personal", "sharing_capability": "ExternalUserSharingOnly"}]},
        "exchange_policy_objects": {"records": [
            {"id": "m1", "source_name": "mailboxForwarding", "forwarding_smtp_address": "x@example.net", "display_name": "Box"}
        ]},
        "teams_policy_objects": {"records": [
            {"id": "t1", "source_name": "tenantFederationConfiguration", "allow_federated_users": True}
        ]},
        "governance_objects": {"records": [{"kind": "role_assignment_schedule"}]},
        "intune_assignment_objects": {"records": []},
        **_read_in_full(
            "identity_governance.roleAssignmentSchedules",
            "identity_governance.roleEligibilitySchedules",
            "intune_depth.deviceConfigurations",
            "intune_depth.deviceConfigurationAssignments",
        ),
    }

    findings = build_findings([], normalized_snapshot=snapshot)

    by_rule = {item["rule_id"]: item for item in findings}
    assert set(by_rule) == FORMERLY_RULELESS | {"sharepoint.site_weak_ownership"}
    assert len(findings) == 9, "one finding per record that raises one"
    assert by_rule["sharepoint.site_orphaned"]["severity"] == "high"
    assert by_rule["sharepoint.site_weak_ownership"]["severity"] == "medium"
    assert by_rule["ca.break_glass_exclusion_missing"]["severity"] == "high"
    for finding in findings:
        _assert_rule_and_template(finding)


def test_collector_issue_findings_carry_a_rule_id_for_every_error_class() -> None:
    classes = ["insufficient_permissions", "resource_not_found", "collection_limit", "client_error", None]
    diagnostics = [
        {"collector": "identity", "item": f"list{i}", "status": "partial", "error_class": error_class, "error": "x"}
        for i, error_class in enumerate(classes)
    ]

    findings = build_findings(diagnostics)

    assert len(findings) == len(classes)
    for finding in findings:
        _assert_rule_and_template(finding)


# ---- Google Workspace -------------------------------------------------------------------------------


def test_google_offline_findings_all_carry_a_rule_id_and_template(tmp_path: Path) -> None:
    metadata = google_findings.google_rule_metadata()
    run_dirs = []
    for name, sample in (("sample", REPO / "examples" / "google_workspace_sample.json"),):
        assert run_google_offline(
            sample_path=sample, out=tmp_path, tenant_name="Inv", run_name=name, domain="example.com", customer_id="C1"
        ) in {0, 1}
        run_dirs.append(tmp_path / f"Inv-{name}")

    findings = [
        finding
        for run_dir in run_dirs
        for finding in json.loads((run_dir / "findings" / "findings.json").read_text(encoding="utf-8"))
    ]
    assert findings
    for finding in findings:
        rule_id = finding.get("rule_id")
        assert isinstance(rule_id, str) and rule_id.startswith("google."), finding.get("id")
        assert rule_id in metadata, f"{rule_id} has no Google rule metadata"
        for field in ("description", "impact", "remediation", "control_ids"):
            assert finding.get(field), f"{finding.get('id')} lacks {field}"


def test_google_finding_helper_requires_a_rule_id() -> None:
    source = Path(google_findings.__file__).read_text(encoding="utf-8")
    calls = [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "_finding"
    ]

    assert len(calls) > 30
    assert [node.lineno for node in calls if "rule_id" not in {keyword.arg for keyword in node.keywords}] == []
