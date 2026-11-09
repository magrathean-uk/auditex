"""Internal run-proof fields never change literal ScubaGear export inputs."""
from copy import deepcopy
import json

import pytest

from auditex.rule_assessment import policy_catalogue
from auditex.scubagear_export import load_export, project_export
from test_scubagear_export import PROVIDER


@pytest.mark.parametrize("state", ["known", "unusable", "not_collected"])
def test_provider_literal_rows_ignore_run_only_summary_fields(tmp_path, state):
    raw = json.loads(PROVIDER.read_text())
    raw["anti_phish_policies"] = [{
        "Identity": "literal-policy",
        "EnableTargetedUserProtection": True,
        "TargetedUsersToProtect": ["Literal Person;literal@example.test", "Other;other@example.test"],
    }]
    raw["securitysuite_successful_commands"] = ["Get-AntiPhishPolicy"]
    raw["securitysuite_unsuccessful_commands"] = []
    baseline = deepcopy(raw["anti_phish_policies"])
    for row in raw["anti_phish_policies"]:
        row["TargetedUsersCoverage"] = {"version": 1, "state": state}
        row["TargetedUsersCoverageBinding"] = {"input_count": 1, "input_hmac_sha256": "a" * 64}
    path = tmp_path / "provider.json"
    path.write_text(json.dumps(raw))
    before = path.read_bytes()
    projection, _ = project_export(load_export(path), policy_catalogue()["policies"])
    assert projection.rule_sections["anti_phish_policies"] == baseline
    assert path.read_bytes() == before
