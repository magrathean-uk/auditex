"""Impact prediction 1 for the value-rules-aad lane: a ScubaGear export whose enabled Conditional Access policy offers terms
of use beside MFA under OR must never answer met. The export path has no rule-view variant, so it withholds the section
(not assessed), as it already does for locations and the other restrictions; a bundle answers not met."""
from __future__ import annotations

import json
from pathlib import Path

from auditex.rule_assessment import policy_catalogue
from auditex.scubagear_export import load_export, project_export
from azure_tenant_audit.collection_markers import NOT_COLLECTED
from azure_tenant_audit.value_rules import assess

PROVIDER = Path(__file__).resolve().parent / "fixtures/scubagear-export/mocktenant-provider-export.json"


def test_export_terms_of_use_under_or_never_answers_met(tmp_path):
    raw = json.loads(PROVIDER.read_text())
    policy = next(p for p in raw["conditional_access_policies"] if isinstance(p, dict) and p.get("State") == "enabled")
    policy["GrantControls"] = {"BuiltInControls": ["mfa"], "Operator": "OR", "AuthenticationStrength": None, "TermsOfUse": ["synthetic"]}
    path = tmp_path / "export.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    projection, _ = project_export(load_export(path), policy_catalogue()["policies"])
    assert projection.rule_sections["conditional_access_policies"] == NOT_COLLECTED
    sections = {"conditional_access_policies": projection.rule_sections["conditional_access_policies"],
                "scuba_config": projection.rule_sections.get("scuba_config")}
    assert assess("MS.AAD.3.2v2", sections)["verdict"] != "met"
