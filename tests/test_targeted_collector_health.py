"""Collector health cannot disappear before offline SS 2.1 and EXO qualification."""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from auditex.scuba_projection import project_run, rule_policy_section
from azure_tenant_audit import cli
from azure_tenant_audit.sensitive_users import SensitiveUsers
from azure_tenant_audit.value_rules import assess


ADDRESS = "alice@configured-canary.invalid"
CANARY = "zq-canary@unlisted-canary.invalid"
POLICIES = ("MS.SECURITYSUITE.2.1v1", "MS.EXO.5.1v1")
REFUSALS = [
    ("error", CANARY), ("error", {"code": CANARY}), ("error_class", CANARY),
    ("status", "failed"), ("status", CANARY), ("complete", False), ("complete", None),
    ("incomplete", True), ("partial", True), ("bounded_sample", True),
    ("truncation_reason", "operator_limit"), ("collection_truncated", True),
    ("@odata.nextLink", "https://unlisted-canary.invalid/next"), ("resolver_error", CANARY),
    ("collection_status", "failed"), ("read_state", "failed"),
]


def _sample():
    healthy = {name: {"status": "ok", "value": []} for name in (
        "acceptedDomains", "antiPhishRules", "eopProtectionPolicyRules", "atpProtectionPolicyRules", "atpPolicyForO365")}
    return {"exchange_policy": {**healthy,
        "transportConfig": {"status": "ok", "value": [{"Name": "Default", "SmtpClientAuthenticationDisabled": True}]},
        "antiPhishPolicies": {"status": "ok", "value": [{
            "Identity": "Default", "Name": "Default", "IsDefault": True, "Enabled": True,
            "EnableTargetedUserProtection": True, "TargetedUserProtectionAction": "Quarantine",
            "TargetedUsersToProtect": [ADDRESS],
        }]},
    }}


def _replay(tmp_path, sample, name):
    source = tmp_path / (name + ".json")
    source.write_text(json.dumps(sample))
    original = source.read_bytes()
    cli.run_offline(source, tmp_path / "runs", "acme", name, sensitive_users=SensitiveUsers((ADDRESS,)))
    assert source.read_bytes() == original
    return tmp_path / "runs" / ("acme-" + name)


def _answers(run):
    projection = project_run(run)
    records = {}
    for policy in POLICIES:
        sections = deepcopy(projection.rule_sections)
        sections["scuba_config"] = rule_policy_section(projection, policy, "scuba_config")
        records[policy] = assess(policy, sections)
    return records


def test_healthy_collector_control_qualifies_both_rule_families(tmp_path):
    records = _answers(_replay(tmp_path, _sample(), "healthy"))
    assert {policy: row["verdict"] for policy, row in records.items()} == dict.fromkeys(POLICIES, "met")


@pytest.mark.parametrize(("key", "value"), REFUSALS, ids=[f"{k}-{i}" for i, (k, _) in enumerate(REFUSALS)])
def test_collector_refusal_survives_minimisation_and_withholds_all_exchange_rules(tmp_path, capsys, caplog, key, value):
    sample = _sample()
    sample["exchange_policy"][key] = value
    run = _replay(tmp_path, sample, "refused")
    records = _answers(run)
    assert {policy: row["verdict"] for policy, row in records.items()} == dict.fromkeys(POLICIES, "not_assessed")
    assert all(CANARY.encode() not in path.read_bytes() for path in run.rglob("*") if path.is_file())
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err + caplog.text


def test_resume_minimisation_preserves_collector_refusal_and_safe_operations():
    from azure_tenant_audit.collectors.targeted_users_coverage import resume_payload
    payload = _sample()["exchange_policy"]
    payload["complete"] = False
    cleaned, reusable = resume_payload(payload, SensitiveUsers(), None)
    assert not reusable
    assert cleaned.get("complete") is False
    assert cleaned["transportConfig"] == payload["transportConfig"]
    assert cleaned["antiPhishPolicies"]["value"][0]["TargetedUsersCoverage"] == {"version": 1, "state": "not_collected"}
    assert ADDRESS not in json.dumps(cleaned)
