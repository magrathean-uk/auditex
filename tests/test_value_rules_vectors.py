"""Value-rule vectors from constructed and train/validation cases."""
from __future__ import annotations

from collections import defaultdict
import json
import lzma
import os
from pathlib import Path

import pytest

from azure_tenant_audit.resources import open_text_resource
from azure_tenant_audit.scuba_precheck import precheck_policy, precheck_response
from azure_tenant_audit.value_rules import assess, as_pack_response, cells_for, rule_policies
from azure_tenant_audit.value_rules.catalogue import catalogue

FIXTURE = Path(__file__).parent / "fixtures/value-rules/vectors-v2.jsonl.xz"
STAGE_POLICIES = frozenset({"MS.AAD.3.4v1", "MS.POWERBI.1.1v1", "MS.POWERBI.2.1v1",
                            "MS.POWERBI.3.1v1", "MS.POWERBI.4.1v1", "MS.POWERBI.4.2v1",
                            "MS.POWERBI.5.1v1", "MS.POWERBI.6.1v1", "MS.POWERBI.7.1v1"})
PBI_COMMON = {"section_not_collected", "licence_false", "licence_flag_unusable", "access_denied",
              "settings_not_a_list", "settings_empty", "setting_entry_missing", "setting_entry_duplicated",
              "enabled_missing", "enabled_not_boolean"}
PBI_KIND = {"on": {"on.enabled", "on.disabled"}, "off": {"off.disabled", "off.enabled"},
            "off_or_groups": {"og.disabled", "og.enabled_groups_listed", "og.enabled_no_groups",
                              "og.enabled_groups_unusable"}}
AAD_CELLS = {"section_not_collected", "section_shape_unusable", "section_not_singleton",
             "policy_object_absent", "state_field_absent", "state_null", "state_not_a_string",
             "state_complete", "state_not_complete"}


def _rows(path: Path):
    reader = lzma.open(path, "rt") if path.suffix == ".xz" else path.open()
    with reader:
        for line in reader:
            yield json.loads(line)


@pytest.fixture(scope="module")
def rows_by_policy():
    grouped = defaultdict(list)
    for row in _rows(FIXTURE):
        grouped[row["policy"]].append(row)
    return grouped


def test_catalogue_is_shipped_and_stage_set_is_exact():
    assert json.loads(open_text_resource("configs/scuba-value-rules.json")) == catalogue()
    assert set(rule_policies()) == STAGE_POLICIES
    assert sum(len(cells_for(policy)) for policy in STAGE_POLICIES) == 113
    for policy, row in catalogue()["policies"].items():
        expected = AAD_CELLS if policy == "MS.AAD.3.4v1" else PBI_COMMON | PBI_KIND[row["kind"].removeprefix("powerbi.")]
        assert set(cells_for(policy)) == expected


@pytest.mark.parametrize("policy", sorted(STAGE_POLICIES))
def test_v2_vectors_through_precheck(policy, rows_by_policy):
    reached = set()
    for row in rows_by_policy[policy]:
        detail = precheck_policy(policy, row["sections"], list(row["sections"]), value_rules=True,
                                 absent_fields=True, empty_lists=True)
        assert detail["class"] == "value_rule", row["vector_id"]
        assert (detail["cell"], detail["reason_code"], detail["reason_text"]) == (
            row["rule_cell"], row["rule_reason_code"], row["rule_reason_text"]), row["vector_id"]
        assert detail["section"] == (row["rule_cited_sections"] or list(catalogue()["policies"][policy]["sections"])), row["vector_id"]
        assert catalogue()["policies"][policy]["cells"][detail["cell"]]["verdict"] == row["rule_verdict"]
        reached.add(detail["cell"])
        response = precheck_response(detail, {"policy_id": policy, "criticality": row["criticality"]},
                                     list(row["sections"]), named_limitations=False)
        expected = as_pack_response(assess(policy, row["sections"]), row["criticality"], list(row["sections"]))
        assert response == expected, row["vector_id"]
        if row.get("gold_response") is not None and row.get("disagreement") is None:
            assert response == row["gold_response"], row["vector_id"]
        assert row.get("disagreement") is None or row["disagreement"].startswith("expected:")
    assert reached == set(cells_for(policy))


def test_fixture_manifest_matches_bytes_and_counts(rows_by_policy):
    from hashlib import sha256
    manifest = json.loads((FIXTURE.parent / "manifest.json").read_text())[FIXTURE.name]
    assert sha256(FIXTURE.read_bytes()).hexdigest() == manifest["sha256"]
    assert sum(map(len, rows_by_policy.values())) == manifest["rows"] == 825
    assert {policy: len(rows) for policy, rows in rows_by_policy.items()} == manifest["by_policy"]
    assert {row["source_kind"] for rows in rows_by_policy.values() for row in rows} == {
        "constructed", "pbi-pack-train", "pbi-pack-validation", "aad-pack-train"}
    assert sum(row.get("gold_response") is not None and row.get("disagreement") is None
               for rows in rows_by_policy.values() for row in rows if row["source_kind"] != "constructed") == 426
    assert sum(manifest["by_cell"].values()) == manifest["rows"]
    assert sum(manifest["by_source"].values()) == manifest["rows"]


def test_reason_text_never_echoes_unbounded_evidence():
    pbi = {"powerbi_access_denied_reason": "", "powerbi_license_found": True,
           "powerbi_tenant_settings": [{"settingName": "PublishToWeb", "enabled": True,
                                        "owner": "canary@example.invalid"}] * 3}
    aad = {"authentication_method": [{"DisplayName": "Canary Name"}] * 3}
    for policy, sections, canary in (("MS.POWERBI.1.1v1", pbi, "canary@example.invalid"),
                                     ("MS.AAD.3.4v1", aad, "Canary Name")):
        result = assess(policy, sections)
        assert canary not in json.dumps(result)
        assert result["reason_text"] in catalogue()["policies"][policy]["cells"][result["cell"]]["reason_texts"]


def test_optional_full_source_vectors():
    path = os.getenv("AUDITEX_TEST_VALUE_RULE_VECTORS")
    if not path:
        pytest.skip("AUDITEX_TEST_VALUE_RULE_VECTORS unset")
    policy_items = json.loads(open_text_resource("configs/scuba-policy-sections.json"))["policies"]
    reached = defaultdict(set)
    for row in _rows(Path(path)):
        if row["policy"] not in STAGE_POLICIES:
            continue
        detail = precheck_policy(row["policy"], row["sections"], list(row["sections"]), value_rules=True)
        assert (detail["cell"], detail["reason_code"]) == (row["rule_cell"], row["rule_reason_code"])
        assert detail["section"] == (row["rule_cited_sections"] or catalogue()["policies"][row["policy"]]["sections"])
        assert catalogue()["policies"][row["policy"]]["cells"][detail["cell"]]["verdict"] == row["rule_verdict"]
        # The v2 source predates the v3.6 Power BI licence wording; the
        # checked-in fixture carries the new exact text.
        if detail["cell"] not in {"licence_false", "licence_flag_unusable"}:
            assert detail["reason_text"] == row["rule_reason_text"]
        criticality = policy_items[row["policy"]]["policy_item"]["criticality"]
        response = precheck_response(detail, {"policy_id": row["policy"], "criticality": criticality},
                                     list(row["sections"]), named_limitations=False)
        if row.get("gold_response") is not None and row.get("disagreement") is None:
            assert response == row["gold_response"]
        assert row.get("disagreement") is None or row["disagreement"].startswith("expected:")
        reached[row["policy"]].add(detail["cell"])
    assert all(reached[policy] == set(cells_for(policy)) for policy in STAGE_POLICIES)
