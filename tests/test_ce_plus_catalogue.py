"""Content rules of the CE+ practice run action catalogue (configs/ce-plus-practice.json, DEC-146)."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from auditex.google_workspace.findings import _GOOGLE_FRAMEWORK_MAPPINGS

ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = json.loads((ROOT / "configs" / "ce-plus-practice.json").read_text(encoding="utf-8"))
FRAMEWORK = json.loads((ROOT / "configs" / "framework-catalog.json").read_text(encoding="utf-8"))["frameworks"][
    "cyber_essentials"
]
MAPPINGS = json.loads((ROOT / "configs" / "control-mappings.json").read_text(encoding="utf-8"))
CONFIDENCE = MAPPINGS["_cyber_essentials_confidence"]
NCSC_URL = (
    "https://www.ncsc.gov.uk/sites/default/files/documents/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf"
)
STATES = {
    "evidence_unknown",
    "outside_tenant_evidence",
    "gap_observed",
    "gap_accepted",
    "supporting_only",
    "evidence_observed_partial",
}
TRIGGERS = {"rule_gap", "rule_not_evaluated", "conflict", "requirement_state", "assessor_test", "stale_evidence"}
KINDS = {"resolve_gap", "recollect", "gather_proof", "provider_assurance", "prepare_assessor_test"}
PLATFORMS = ("m365", "google_workspace")
FORBIDDEN = re.compile(r"\bpass(ed|es|ing)?\b|certif|guarantee|\bcompliant\b|\bA\d\.\d+\b", re.IGNORECASE)
OUTSIDE_STATUSES = {"manual", "ce_plus_assessor_test", "provider_responsibility"}

ACTIONS = CATALOGUE["actions"]
REQUIREMENTS = FRAMEWORK["controls"]


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [text for item in value for text in _strings(item)]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _strings(item)]
    return []


def _mapped_rules(platform: str) -> dict[str, dict[str, str]]:
    """requirement id -> {rule id: confidence} for one platform, from the shipped mappings."""
    rules: dict[str, dict[str, str]] = {}
    if platform == "m365":
        source = {
            rule: entry.get("cyber_essentials") or []
            for rule, entry in MAPPINGS.items()
            if not rule.startswith("_") and isinstance(entry, dict)
        }
    else:
        source = {rule: entry.get("cyber_essentials") or [] for rule, entry in _GOOGLE_FRAMEWORK_MAPPINGS.items()}
    for rule, requirement_ids in source.items():
        for requirement_id in requirement_ids:
            rules.setdefault(requirement_id, {})[rule] = CONFIDENCE.get(rule, {}).get(requirement_id, "partial")
    return rules


def _deciding(platform: str, requirement_id: str) -> set[str]:
    return {rule for rule, level in _mapped_rules(platform).get(requirement_id, {}).items() if level != "supporting"}


def _reachable(platform: str, requirement_id: str) -> set[str]:
    status = REQUIREMENTS[requirement_id]["status"]
    if status in OUTSIDE_STATUSES:
        return {"outside_tenant_evidence", "evidence_unknown"}
    if _deciding(platform, requirement_id):
        return {"gap_observed", "gap_accepted", "evidence_unknown", "evidence_observed_partial"}
    return {"supporting_only", "evidence_unknown"}


def _for(platform: str, requirement_id: str) -> list[dict]:
    return [
        action
        for action in ACTIONS
        if requirement_id in action["requirement_ids"] and ("any" in action["platforms"] or platform in action["platforms"])
    ]


def test_versions_and_parameters() -> None:
    assert CATALOGUE["requirements_version"] == FRAMEWORK["version"] == "v3.3"
    assert CATALOGUE["test_specification_version"] == "v3.2"
    assert CATALOGUE["test_specification_version"] == FRAMEWORK["related_documents"][0]["version"]
    assert CATALOGUE["catalogue_version"] == "2026-11-23.1"
    assert CATALOGUE["verified_on"] == "2026-11-22"
    assert CATALOGUE["stale_after_days"] == 14
    assert CATALOGUE["conflict_weight"] == 1
    assert CATALOGUE["effort_bands"] == [
        {"id": "quick", "weight": 1},
        {"id": "moderate", "weight": 2},
        {"id": "extended", "weight": 4},
    ]
    assert {row["state"]: row["weight"] for row in CATALOGUE["state_weights"]} == {
        "gap_observed": 3,
        "evidence_unknown": 2,
        "gap_accepted": 1,
        "supporting_only": 1,
        "evidence_observed_partial": 1,
        "outside_tenant_evidence": 1,
    }
    assert CATALOGUE["source"] == {
        "document_title": "Cyber Essentials: Requirements for IT Infrastructure v3.3",
        "document_url": NCSC_URL,
        "licence": "Open Government Licence v3.0",
    }


def test_ids_are_unique_and_every_reference_resolves() -> None:
    ids = [row["id"] for key in ("actions", "conflicts", "assessor_tests") for row in CATALOGUE[key]]
    assert len(ids) == len(set(ids))
    action_ids = {action["id"] for action in ACTIONS}
    conflict_ids = {conflict["id"] for conflict in CATALOGUE["conflicts"]}
    bands = {band["id"] for band in CATALOGUE["effort_bands"]}
    for action in ACTIONS:
        assert action["requirement_ids"] and set(action["requirement_ids"]) <= set(REQUIREMENTS), action["id"]
        assert action["kind"] in KINDS and action["trigger"] in TRIGGERS and action["effort"] in bands, action["id"]
        assert action["platforms"] and set(action["platforms"]) <= {"any", *PLATFORMS}, action["id"]
        assert set(action["states"]) <= STATES and set(action["conflict_ids"]) <= conflict_ids, action["id"]
    for conflict in CATALOGUE["conflicts"]:
        assert conflict["requirement_id"] in REQUIREMENTS
    for test in CATALOGUE["assessor_tests"]:
        assert set(test["prepare_action_ids"]) <= action_ids and test["prepare_action_ids"], test["id"]
        assert set(test["requirement_ids"]) <= set(REQUIREMENTS)
    assert [row["requirement_id"] for row in CATALOGUE["requirement_notes"]] == list(REQUIREMENTS)
    assert all(row["evidence_limits"] for row in CATALOGUE["requirement_notes"])


def test_each_action_fills_only_the_list_its_trigger_needs() -> None:
    needs = {
        "rule_gap": "rule_ids",
        "conflict": "conflict_ids",
        "requirement_state": "states",
    }
    for action in ACTIONS:
        filled = {key for key in ("rule_ids", "states", "conflict_ids") if action[key]}
        expected = {needs[action["trigger"]]} if action["trigger"] in needs else set()
        if action["trigger"] == "rule_not_evaluated":
            assert filled <= {"rule_ids"}, action["id"]
        else:
            assert filled == expected, action["id"]


def test_action_count_is_in_the_expected_range() -> None:
    assert 45 <= len(ACTIONS) <= 60


@pytest.mark.parametrize("platform", PLATFORMS)
def test_every_reachable_state_of_every_requirement_has_an_action(platform: str) -> None:
    assert len(REQUIREMENTS) == 30
    for requirement_id in REQUIREMENTS:
        actions = _for(platform, requirement_id)
        for state in _reachable(platform, requirement_id):
            if state == "evidence_unknown":
                matched = [action for action in actions if action["trigger"] == "rule_not_evaluated"]
            elif state == "gap_observed":
                matched = [action for action in actions if action["trigger"] == "rule_gap"]
                covered = {rule for action in matched for rule in action["rule_ids"]}
                assert _deciding(platform, requirement_id) <= covered, (platform, requirement_id)
            else:
                matched = [
                    action for action in actions if action["trigger"] == "requirement_state" and state in action["states"]
                ]
            assert matched, (platform, requirement_id, state)


def test_requirement_kinds_follow_the_requirement_status() -> None:
    for requirement_id, spec in REQUIREMENTS.items():
        kinds = {action["kind"] for action in ACTIONS if requirement_id in action["requirement_ids"]}
        if spec["status"] in {"manual", "ce_plus_assessor_test"}:
            assert "gather_proof" in kinds, requirement_id
        if spec["status"] == "partial":
            assert "gather_proof" in kinds, requirement_id
            for platform in PLATFORMS:
                if _deciding(platform, requirement_id):
                    assert any(
                        action["kind"] == "resolve_gap" and action["trigger"] == "rule_gap"
                        for action in _for(platform, requirement_id)
                    ), (platform, requirement_id)
    providers = [action for action in ACTIONS if action["kind"] == "provider_assurance"]
    assert [action["requirement_ids"] for action in providers] == [
        ["ce.fw.saas_provider", "ce.sum.saas_provider", "ce.mp.saas_provider"]
    ]


def test_one_shared_recollect_action_and_one_for_a_stale_run() -> None:
    recollect = [action for action in ACTIONS if action["kind"] == "recollect"]
    assert [(action["id"], action["trigger"]) for action in recollect] == [
        ("ce.act.run.recollect_missing_evidence", "rule_not_evaluated"),
        ("ce.act.run.recollect_stale_evidence", "stale_evidence"),
    ]
    assert recollect[0]["requirement_ids"] == list(REQUIREMENTS)
    assert recollect[0]["platforms"] == ["any"]


def test_rule_ids_are_mapped_to_the_action_requirements_and_platform() -> None:
    for action in ACTIONS:
        for rule in action["rule_ids"]:
            platform = "google_workspace" if rule.startswith("google.") else "m365"
            assert platform in action["platforms"], (action["id"], rule)
            mapped = _mapped_rules(platform)
            levels = [mapped.get(requirement_id, {}).get(rule) for requirement_id in action["requirement_ids"]]
            assert any(level is not None for level in levels), (action["id"], rule)
            if action["trigger"] == "rule_gap":
                assert any(level not in (None, "supporting") for level in levels), (action["id"], rule)


def test_five_conflicts_ship_and_their_rules_decide_the_requirement() -> None:
    assert [conflict["id"] for conflict in CATALOGUE["conflicts"]] == [
        "ce.conflict.mfa_policy_vs_registration_m365",
        "ce.conflict.admin_mfa_policy_vs_registration_m365",
        "ce.conflict.2sv_policy_vs_enrolment_google",
        "ce.conflict.admin_2sv_policy_vs_enrolment_google",
        "ce.conflict.update_ring_vs_device_state_m365",
    ]
    update_ring = CATALOGUE["conflicts"][4]
    assert update_ring["policy_rule_ids"] == ["intune_depth.update_ring_not_assigned"]
    assert update_ring["state_rule_ids"] == ["intune.device_os_end_of_life", "intune.device_stale_sync"]
    for conflict in CATALOGUE["conflicts"]:
        (platform,) = conflict["platforms"]
        assert conflict["policy_rule_ids"] and conflict["state_rule_ids"] and conflict["note"]
        deciding = _deciding(platform, conflict["requirement_id"])
        assert set(conflict["policy_rule_ids"]) | set(conflict["state_rule_ids"]) <= deciding, conflict["id"]
        assert any(conflict["id"] in action["conflict_ids"] for action in ACTIONS), conflict["id"]


def test_five_assessor_tests_link_the_framework_requirements() -> None:
    tests = CATALOGUE["assessor_tests"]
    assert [(test["id"], test["number"], test["requirement_ids"]) for test in tests] == [
        ("ce_plus.test_1", 1, ["ce.fw.internet_exposure"]),
        ("ce_plus.test_2", 2, ["ce.sum.vulnerability_fixes_14_days"]),
        ("ce_plus.test_3", 3, ["ce.mp.antimalware"]),
        ("ce_plus.test_4", 4, ["ce.uac.mfa_cloud_services", "ce.uac.mfa_admin_accounts"]),
        ("ce_plus.test_5", 5, ["ce.uac.separate_admin_accounts"]),
    ]
    for test in tests:
        linked = [rid for rid, spec in REQUIREMENTS.items() if spec.get("ce_plus_test") == test["framework_label"]]
        assert linked == test["requirement_ids"], test["id"]
        assert test["title"] and test["auditex_prepares"] and test["assessor_witnesses"]


def test_the_patching_test_names_the_whole_scope_the_assessor_checks() -> None:
    witness = CATALOGUE["assessor_tests"][1]["assessor_witnesses"]
    for phrase in ("servers", "IaaS", "high or critical", "CVSS 7 or above", "without a published severity", "14 days"):
        assert phrase in witness, phrase


def test_catalogue_wording_has_no_forbidden_claims_and_only_the_ncsc_link() -> None:
    texts = _strings(CATALOGUE)
    assert [text for text in texts if FORBIDDEN.search(text)] == []
    assert [text for text in texts if "/Users/" in text or "/Volumes/" in text] == []
    links = {link for text in texts for link in re.findall(r"https?://[^\s)]+", text)}
    assert links == {NCSC_URL}
    for action in ACTIONS:
        assert action["title"] and action["proof_to_gather"], action["id"]
