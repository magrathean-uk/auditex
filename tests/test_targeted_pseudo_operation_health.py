"""Minimisation keeps collector-wide refusals from unsupported pseudo-operations."""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from auditex.scuba_projection import project_run
from azure_tenant_audit import cli
from azure_tenant_audit.collectors.targeted_users_coverage import sanitise_sample
from azure_tenant_audit.value_rules import assess


CANARY = "zq-legacy-health@unlisted.invalid"
ADMIN = "62e90394-69f5-4237-9190-012177145e10"
SAFETY_TIPS = (
    "EnableFirstContactSafetyTips", "EnableSimilarUsersSafetyTips", "EnableSimilarDomainsSafetyTips",
    "EnableUnusualCharactersSafetyTips", "EnableViaTag", "EnableUnauthenticatedSender",
)


def _success(rows):
    return {"status": "ok", "value": rows}


def _identity():
    ids = ("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
    return {"identity": {
        "users": _success([{"id": uid, "displayName": f"Admin {number}",
            "userPrincipalName": f"admin{number}@example.invalid", "accountEnabled": True,
            "userType": "Member", "onPremisesImmutableId": None} for number, uid in enumerate(ids)]),
        "groups": _success([]), "servicePrincipals": _success([]),
        "roleDefinitions": _success([{"id": ADMIN, "displayName": "Global Administrator"}]),
        "roleAssignments": _success([{"id": f"assignment-{number}", "principalId": uid,
            "roleDefinitionId": ADMIN, "directoryScopeId": "/"} for number, uid in enumerate(ids)]),
    }, "identity_governance": {"roleAssignmentSchedules": _success([]), "roleEligibilitySchedules": _success([])}}


def _exchange():
    return {"exchange_policy": {
        **{name: _success([]) for name in ("acceptedDomains", "antiPhishRules", "eopProtectionPolicyRules",
            "atpProtectionPolicyRules", "atpPolicyForO365")},
        "antiPhishPolicies": _success([{"Identity": "Default", "Name": "Default", "IsDefault": True,
            "Enabled": True, **dict.fromkeys(SAFETY_TIPS, True)}]),
    }}


def _deep_error():
    item = {"error": CANARY}
    for _ in range(70):
        item = {"nested": item}
    return [item]


def _bearing_error():
    return [{"TargetedUsersToProtect": [CANARY], "details": {"error": CANARY}}]


CASES = (
    ("identity", "legacy", _deep_error, "MS.AAD.7.1v1"),
    ("identity", "legacy", _bearing_error, "MS.AAD.7.1v1"),
    ("exchange_policy", "legacyRows", lambda: [{"details": {"error": CANARY}}], "MS.SECURITYSUITE.2.4v1"),
    ("exchange_policy", "legacy.rows", lambda: {"details": {"error": CANARY}}, "MS.SECURITYSUITE.2.4v1"),
    ("identity", "value", _bearing_error, "MS.AAD.7.1v1"),
    ("identity", "TargetedUsersToProtect", lambda: [{"error": CANARY}], "MS.AAD.7.1v1"),
    ("exchange_policy", "value", _bearing_error, "MS.SECURITYSUITE.2.4v1"),
    ("exchange_policy", "TargetedUsersToProtect", lambda: [{"error": CANARY}], "MS.SECURITYSUITE.2.4v1"),
)


def _replay(tmp_path, sample, name):
    source = tmp_path / (name + ".json")
    source.write_text(json.dumps(sample))
    before = source.read_bytes()
    cli.run_offline(source, tmp_path / "runs", "acme", name)
    assert source.read_bytes() == before
    return tmp_path / "runs" / ("acme-" + name)


def _verdict(run, policy):
    return assess(policy, deepcopy(project_run(run).rule_sections))["verdict"]


@pytest.mark.parametrize("sample,policy", [(_identity, "MS.AAD.7.1v1"), (_exchange, "MS.SECURITYSUITE.2.4v1")])
def test_supported_controls_are_met(tmp_path, sample, policy):
    assert _verdict(_replay(tmp_path, sample(), "healthy"), policy) == "met"


@pytest.mark.parametrize("collector,name,payload,policy", CASES)
def test_legacy_refusal_survives_the_entire_offline_projection(tmp_path, capsys, caplog, collector, name, payload, policy):
    sample = _identity() if collector == "identity" else _exchange()
    sample[collector][name] = payload()
    before = deepcopy(sample)
    run = _replay(tmp_path, sample, "refused")
    assert _verdict(run, policy) == "not_assessed", "a failing pseudo-operation still withholds the collector"
    assert sample == before
    assert all(CANARY.encode() not in path.read_bytes() for path in run.rglob("*") if path.is_file())
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err + caplog.text


@pytest.mark.parametrize("collector,name,payload,policy", CASES)
def test_cleaned_legacy_failure_stays_visible_without_target_values(collector, name, payload, policy):
    sample = _identity() if collector == "identity" else _exchange()
    sample[collector][name] = payload()
    before = deepcopy(sample)
    cleaned = sanitise_sample(sample, None, None)[collector]
    if name in cleaned:
        item = cleaned[name]
        assert isinstance(item, list) and item and item[0].get("error")
    else:
        assert cleaned.get("error"), "a removed target-named slot must lift its refusal to the collector"
    assert CANARY not in json.dumps(cleaned)
    assert sample == before


def test_a_known_policy_target_value_only_invalidates_membership_not_safety_tips(tmp_path):
    sample = _exchange()
    sample["exchange_policy"]["antiPhishPolicies"]["value"][0]["TargetedUsersToProtect"] = [{"error": CANARY}]
    run = _replay(tmp_path, sample, "supported")
    assert _verdict(run, "MS.SECURITYSUITE.2.4v1") == "met"
    assert all(CANARY.encode() not in path.read_bytes() for path in run.rglob("*") if path.is_file())
