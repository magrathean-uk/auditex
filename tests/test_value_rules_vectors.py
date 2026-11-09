"""Value-rule vectors from constructed and train/validation cases.

Stage 1 (Power BI 8, AAD 3.4v1) replays ``vectors-v2.jsonl.xz``; stage 3 (the
25 Teams, Exchange Online and Defender lookups) replays ``vectors-v39.jsonl.xz``.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
import json
import lzma
import os
from pathlib import Path

import pytest

from azure_tenant_audit.resources import open_text_resource
from azure_tenant_audit.scuba_precheck import check_gate, precheck_policy, precheck_response
from azure_tenant_audit.value_rules import assess, as_pack_response, cells_for, rule_policies
from azure_tenant_audit.value_rules.catalogue import catalogue
from azure_tenant_audit.value_rules.gates import closed_gate

FIXTURE = Path(__file__).parent / "fixtures/value-rules/vectors-v2.jsonl.xz"
FIXTURE_V39 = Path(__file__).parent / "fixtures/value-rules/vectors-v39.jsonl.xz"
STAGE1_POLICIES = frozenset({"MS.AAD.3.4v1", "MS.POWERBI.1.1v1", "MS.POWERBI.2.1v1",
                             "MS.POWERBI.3.1v1", "MS.POWERBI.4.1v1", "MS.POWERBI.4.2v1",
                             "MS.POWERBI.5.1v1", "MS.POWERBI.6.1v1", "MS.POWERBI.7.1v1"})
STAGE3_POLICIES = frozenset({
    "MS.TEAMS.1.1v1", "MS.TEAMS.1.2v2", "MS.TEAMS.1.3v1", "MS.TEAMS.1.4v1", "MS.TEAMS.1.5v1",
    "MS.TEAMS.1.6v1", "MS.TEAMS.1.7v2", "MS.TEAMS.2.1v2", "MS.TEAMS.2.2v2", "MS.TEAMS.2.3v2",
    "MS.TEAMS.4.1v1", "MS.TEAMS.5.1v2", "MS.TEAMS.5.2v2", "MS.TEAMS.5.3v2",
    "MS.EXO.2.2v3", "MS.EXO.5.1v1", "MS.EXO.6.1v1", "MS.EXO.6.2v1", "MS.EXO.7.1v1", "MS.EXO.13.1v1",
    "MS.SECURITYSUITE.1.4v1", "MS.SECURITYSUITE.4.1v1", "MS.SECURITYSUITE.5.1v1",
    "MS.SECURITYSUITE.8.1v1", "MS.SECURITYSUITE.8.2v1"})
# stage 4: DNS, anti-spam and Safe Links rows, one per line; SS 6.1 and 6.2 were enabled after P4.
STAGE4_POLICIES = frozenset({
    "MS.EXO.3.1v1",
    "MS.EXO.4.1v1",
    "MS.EXO.4.2v1",
    "MS.EXO.4.3v1",
    "MS.EXO.4.4v1",
    "MS.SECURITYSUITE.6.1v1",
    "MS.SECURITYSUITE.6.2v1",
    "MS.SECURITYSUITE.7.1v1",
    "MS.SECURITYSUITE.7.2v1",
    "MS.SECURITYSUITE.7.3v1",
})
# stage 8: include the eight Power Platform policies in the exact registration gate.
STAGE8_POLICIES = frozenset(f"MS.POWERPLATFORM.{number}v1" for number in
                            ("1.1", "1.2", "2.1", "2.2", "2.3", "3.1", "5.1", "6.1"))
# stage 6: include the new kinds in the exact registry and optional full-source checks.
STAGE6_POLICIES = frozenset({
    "MS.SHAREPOINT.1.1v1", "MS.SHAREPOINT.1.2v1", "MS.SHAREPOINT.1.3v1",
    "MS.SHAREPOINT.2.1v1", "MS.SHAREPOINT.2.2v1", "MS.SHAREPOINT.3.1v1",
    "MS.SHAREPOINT.3.2v1", "MS.SHAREPOINT.3.3v2", "MS.AAD.5.1v1", "MS.AAD.7.1v1",
    "MS.AAD.7.2v1", "MS.AAD.7.3v1", "MS.AAD.8.1v1", "MS.AAD.8.2v1"})
# stage 5: SS 1.1 was enabled after P4.
STAGE5_POLICIES = frozenset({
    "MS.EXO.1.1v2",
    "MS.SECURITYSUITE.1.1v1",
    "MS.SECURITYSUITE.1.2v1",
    "MS.SECURITYSUITE.1.3v1",
    "MS.SECURITYSUITE.2.1v1",
    "MS.SECURITYSUITE.2.2v1",
    "MS.SECURITYSUITE.2.3v1",
    "MS.SECURITYSUITE.2.4v1",
    "MS.SECURITYSUITE.3.1v1",
    "MS.SECURITYSUITE.3.2v1",
    "MS.SECURITYSUITE.3.3v1",
    "MS.SECURITYSUITE.3.4v1",
})
# stage 9: the eight AAD pilot policies, one per line.
STAGE9_POLICIES = frozenset({
    "MS.AAD.3.3v2",
    "MS.AAD.3.5v2",
    "MS.AAD.5.2v1",
    "MS.AAD.5.3v1",
    "MS.AAD.5.5v1",
    "MS.AAD.5.6v1",
    "MS.AAD.5.7v1",
    "MS.AAD.6.1v1",
})
# stage 7: include the privileged-role and Conditional Access registrations.
STAGE7_POLICIES = frozenset({
    "MS.AAD.1.1v1",
    "MS.AAD.2.1v1",
    "MS.AAD.2.3v1",
    "MS.AAD.3.1v1",
    "MS.AAD.3.2v2",
    "MS.AAD.3.6v1",
    "MS.AAD.3.7v1",
    "MS.AAD.3.8v1",
    "MS.AAD.3.9v1",
    "MS.AAD.7.4v1",
    "MS.AAD.7.5v1",
    "MS.AAD.7.6v1",
    "MS.AAD.7.7v1",
    "MS.AAD.7.8v1",
    "MS.AAD.7.9v1",
    "MS.AAD.9.1v1",
})
# v3.9.1: the three policies that were held for the P4 projection review are registered with the rest.
STAGE_V391_POLICIES = frozenset({"MS.SECURITYSUITE.1.1v1", "MS.SECURITYSUITE.6.1v1", "MS.SECURITYSUITE.6.2v1"})
STAGE_POLICIES = (STAGE1_POLICIES | STAGE_V391_POLICIES | STAGE3_POLICIES | STAGE4_POLICIES | STAGE5_POLICIES
                  | STAGE6_POLICIES | STAGE7_POLICIES | STAGE8_POLICIES | STAGE9_POLICIES)
GATE_POLICIES = frozenset(policy for policy, row in catalogue()["policies"].items()
                          if row["params"].get("environment_gate"))
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


def _grouped(path: Path):
    grouped = defaultdict(list)
    for row in _rows(path):
        grouped[row["policy"]].append(row)
    return grouped


@pytest.fixture(scope="module")
def rows_by_policy():
    return _grouped(FIXTURE)


@pytest.fixture(scope="module")
def rows_v39():
    return _grouped(FIXTURE_V39)


def test_catalogue_is_shipped_and_stage_set_is_exact():
    text = open_text_resource("configs/scuba-value-rules.json")
    assert json.loads(text) == catalogue()
    assert text == json.dumps(catalogue(), indent=2, ensure_ascii=False) + "\n"
    assert catalogue()["spec_version"] == "v3.9.1"
    assert set(rule_policies()) == STAGE_POLICIES and len(STAGE_POLICIES) == 102
    assert sum(len(cells_for(policy)) for policy in STAGE1_POLICIES) == 113
    assert sum(len(cells_for(policy)) for policy in STAGE3_POLICIES) == 201
    for policy in STAGE1_POLICIES:
        row = catalogue()["policies"][policy]
        expected = AAD_CELLS if policy == "MS.AAD.3.4v1" else PBI_COMMON | PBI_KIND[row["kind"].removeprefix("powerbi.")]
        assert set(cells_for(policy)) == expected


def test_catalogue_texts_are_closed_and_free_of_evidence():
    """Every text is a constant of at most 400 characters; the closed lists (cited
    sections, SS 4.1 alert names) are complete, so no reachable answer is missing."""
    from itertools import combinations
    from azure_tenant_audit.value_rules.lookups import REQUIRED_ALERTS, alert_text
    for policy, row in catalogue()["policies"].items():
        names = row["sections"]
        expected = {"Data unavailable: required evidence section(s) not collected: " + ", ".join(subset) + "."
                    for size in range(1, len(names) + 1) for subset in combinations(names, size)}
        if policy in STAGE3_POLICIES:
            assert set(row["cells"]["section_not_collected"]["reason_texts"]) == expected
        for cell, entry in row["cells"].items():
            assert all("@" not in text and len(text) <= 400 for text in entry["reason_texts"]), (policy, cell)
    alerts = catalogue()["policies"]["MS.SECURITYSUITE.4.1v1"]["cells"]["alert_missing_or_disabled"]["reason_texts"]
    assert set(alerts) == {alert_text(subset) for size in range(1, 8) for subset in combinations(REQUIRED_ALERTS, size)}


@pytest.mark.parametrize("policy", sorted(STAGE1_POLICIES))
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
        expected = as_pack_response(assess(policy, row["sections"]), row["criticality"], list(row["sections"]), legacy=True)
        assert response == expected, row["vector_id"]
        if row.get("gold_response") is not None and row.get("disagreement") is None:
            assert response == row["gold_response"], row["vector_id"]
        assert row.get("disagreement") is None or row["disagreement"].startswith("expected:")
    assert reached == set(cells_for(policy))


def _strip_names(value):
    if isinstance(value, dict):
        return {key: _strip_names(item) for key, item in value.items() if not key.endswith("_name")}
    if isinstance(value, list):
        return [_strip_names(item) for item in value]
    return value


@pytest.mark.parametrize("policy", sorted(STAGE3_POLICIES))
def test_v39_vectors_through_precheck(policy, rows_v39):
    """Whole precheck order: closed gate, absent section, environment, value rule."""
    rule = catalogue()["policies"][policy]
    reached = set()
    for row in rows_v39[policy]:
        sections = row["sections"]
        detail = precheck_policy(policy, sections, list(sections), value_rules=True,
                                 absent_fields=True, empty_lists=True)
        record = assess(policy, sections)
        expected = (row["rule_verdict"], row["rule_cell"], row["rule_reason_code"], row["rule_reason_text"],
                    row["rule_cited_sections"] or list(rule["sections"]))
        assert (record["verdict"], record["cell"], record["reason_code"], record["reason_text"],
                record["cited_sections"] or list(rule["sections"])) == expected, row["vector_id"]
        # The closed gate too is rendered as the rule's closed_gate cell (gates.py, decided by check_gate).
        assert detail["class"] == "value_rule" and detail["rule_id"] == rule["rule_id"], row["vector_id"]
        assert (detail["cell"], detail["reason_code"], detail["reason_text"], detail["section"]) == (
            record["cell"], record["reason_code"], record["reason_text"],
            record["cited_sections"] or list(rule["sections"])), row["vector_id"]
        assert rule["cells"][record["cell"]]["verdict"] == row["rule_verdict"]
        reached.add(record["cell"])
        response = precheck_response(detail, {"policy_id": policy, "criticality": row["criticality"]},
                                     list(sections), named_limitations=False)
        assert response == as_pack_response(record, row["criticality"], list(sections), legacy=True), row["vector_id"]
        if row.get("gold_response") is not None and row.get("disagreement") is None:
            assert response == row["gold_response"], row["vector_id"]
        assert row.get("disagreement") is None or row["disagreement"].startswith("expected:")
        assert (row.get("disagreement") is None) is (row["rule_verdict"] == row["gold_verdict"]), row["vector_id"]
        assert assess(policy, _strip_names(sections)) == record, row["vector_id"]
    assert reached == set(cells_for(policy))


def test_gates_agree_with_the_config_gate_on_every_gate_vector(rows_v39):
    checked = 0
    for policy in sorted(GATE_POLICIES):
        for row in rows_v39[policy]:
            gate = check_gate(policy, row["sections"])
            rendered = closed_gate(policy, row["sections"])
            assert (rendered is not None) is bool(gate and gate["class"] == "closed_gate"), row["vector_id"]
            assert (rendered is not None) is (row["rule_cell"] == "closed_gate"), row["vector_id"]
            checked += 1
    assert checked == sum(len(rows_v39[policy]) for policy in GATE_POLICIES) == 230
    for value in ("gcc", "gcchigh", "dod", "commercial", "GCC", None, 0, "other"):
        for config in ({"M365Environment": value}, [{"M365Environment": value}]):
            for policy in GATE_POLICIES:
                gate = check_gate(policy, {"scuba_config": config})
                # Value rules require the reference's object-shaped environment section;
                # the legacy config gate also accepts a singleton list.
                assert (closed_gate(policy, {"scuba_config": config}) is not None) is bool(
                    isinstance(config, dict) and gate and gate["class"] == "closed_gate")


def test_v39_fixture_manifest_matches_bytes_and_counts(rows_v39):
    from hashlib import sha256
    manifest = json.loads((FIXTURE_V39.parent / "manifest.json").read_text())[FIXTURE_V39.name]
    rows = [row for group in rows_v39.values() for row in group]
    assert sha256(FIXTURE_V39.read_bytes()).hexdigest() == manifest["sha256"]
    assert len(rows) == manifest["rows"] == 1100
    assert manifest["spec_version"] == catalogue()["spec_version"] == "v3.9.1"
    assert set(rows_v39) == STAGE3_POLICIES
    assert {policy: len(group) for policy, group in rows_v39.items()} == manifest["by_policy"]
    assert {row["source_kind"] for row in rows} == {"constructed", "pack-train", "pack-validation"}
    assert not any(row["source_kind"].endswith("test") for row in rows)
    assert sum(row.get("gold_response") is not None and row.get("disagreement") is None for row in rows) == 374
    assert len(manifest["by_cell"]) == 201
    assert sum(manifest["by_cell"].values()) == sum(manifest["by_source"].values()) == manifest["rows"]


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


CANARY = "canary.person@example.invalid"
CANARY_NAME = "Canary Display Name"
COMMERCIAL = {"M365Environment": "commercial", "Owner": CANARY}
STAGE3_CANARY_CASES = [
    ("MS.TEAMS.1.1v1", {"meeting_policies": [{"Identity": CANARY, "AllowExternalParticipantGiveRequestControl": True},
                                             {"Identity": CANARY_NAME, "AllowExternalParticipantGiveRequestControl": "x"}]}),
    ("MS.TEAMS.1.3v1", {"meeting_policies": [{"Identity": "Global", "AutoAdmittedUsers": CANARY,
                                              "AllowPSTNUsersToBypassLobby": False, "Description": CANARY_NAME}]}),
    ("MS.TEAMS.1.2v2", {"meeting_policies": [{"Identity": CANARY, "AllowAnonymousUsersToStartMeeting": False},
                                             {"Identity": CANARY_NAME, "AllowAnonymousUsersToStartMeeting": None}]}),
    ("MS.TEAMS.1.4v1", {"meeting_policies": [{"Identity": "Global", "AutoAdmittedUsers": "Everyone", "Owner": CANARY},
                                             {"Identity": CANARY_NAME, "AutoAdmittedUsers": CANARY}]}),
    ("MS.TEAMS.1.5v1", {"meeting_policies": [{"Description": CANARY, "AllowPSTNUsersToBypassLobby": True}]}),
    ("MS.TEAMS.1.6v1", {"meeting_policies": [{"Identity": "Global", "AllowCloudRecording": False, "Owner": CANARY},
                                             {"Identity": "Global", "AllowCloudRecording": CANARY_NAME}]}),
    ("MS.TEAMS.1.7v2", {"broadcast_policies": [{"Identity": "Global", "BroadcastRecordingMode": "AlwaysEnabled",
                                                "Owner": CANARY}]}),
    ("MS.TEAMS.2.1v2", {"federation_configuration": [{"Identity": CANARY, "AllowFederatedUsers": True,
                                                      "AllowedDomains": []}]}),
    ("MS.TEAMS.2.2v2", {"federation_configuration": [{"Identity": CANARY_NAME, "AllowTeamsConsumerInbound": True,
                                                      "AllowTeamsConsumer": True}], "scuba_config": COMMERCIAL}),
    ("MS.TEAMS.2.3v2", {"federation_configuration": [{"Identity": CANARY}], "scuba_config": {"M365Environment": CANARY}}),
    ("MS.TEAMS.4.1v1", {"client_configuration": [{"Identity": None, "AllowEmailIntoChannel": True}],
                        "scuba_config": {**COMMERCIAL, "M365Environment": "gcc"}}),
    ("MS.TEAMS.5.1v2", {"tenant_app_settings": [{"SettingName": "DefaultApp", "SettingValue": CANARY}],
                        "app_policies": [{"Identity": CANARY_NAME}]}),
    ("MS.TEAMS.5.2v2", {"tenant_app_settings": None,
                        "app_policies": [{"Identity": CANARY, "GlobalCatalogAppsType": "BlockedAppList"}]}),
    ("MS.TEAMS.5.3v2", {"tenant_app_settings": None, "app_policies": [{"Identity": CANARY, "PrivateCatalogAppsType": CANARY}]}),
    ("MS.EXO.2.2v3", {"spf_records": [{"domain": CANARY, "message": CANARY_NAME, "compliant": False}]}),
    ("MS.EXO.5.1v1", {"transport_config": [{"Name": CANARY, "SmtpClientAuthenticationDisabled": False}]}),
    ("MS.EXO.6.1v1", {"sharing_policy": [{"Name": CANARY_NAME, "Domains": [f"*:{CANARY}:ContactsSharing"]}]}),
    ("MS.EXO.6.2v1", {"sharing_policy": [{"Name": CANARY, "Domains": [CANARY, 3]}]}),
    ("MS.EXO.7.1v1", {"transport_rule": [{"Name": CANARY, "State": "Enabled", "Mode": "Enforce",
                                          "FromScope": "NotInOrganization", "PrependSubject": CANARY_NAME}]}),
    ("MS.EXO.13.1v1", {"org_config": [{"Name": CANARY, "AuditDisabled": True}]}),
    ("MS.SECURITYSUITE.1.4v1", {"atp_policy_for_o365": [{"Identity": CANARY, "EnableATPForSPOTeamsODB": True}]}),
    ("MS.SECURITYSUITE.4.1v1", {"protection_alerts": [{"Name": CANARY, "Disabled": False},
                                                      {"Name": "Messages have been delayed", "Disabled": True,
                                                       "NotifyUser": [CANARY], "Comment": CANARY_NAME}]}),
    ("MS.SECURITYSUITE.5.1v1", {"admin_audit_log_config": [{"Identity": CANARY_NAME, "UnifiedAuditLogIngestionEnabled": False}]}),
    ("MS.SECURITYSUITE.8.1v1", {"conn_filter": [{"Name": CANARY, "IPAllowList": [CANARY_NAME]}]}),
    ("MS.SECURITYSUITE.8.2v1", {"conn_filter": [{"Name": CANARY, "EnableSafeList": CANARY_NAME}]}),
]


def test_stage3_cases_cover_every_stage3_policy():
    assert {policy for policy, _ in STAGE3_CANARY_CASES} == STAGE3_POLICIES


@pytest.mark.parametrize("policy,sections", STAGE3_CANARY_CASES, ids=[case[0] for case in STAGE3_CANARY_CASES])
def test_stage3_rule_output_never_echoes_evidence(policy, sections):
    """Labels, values and list entries read from the rule view never reach the
    record, the precheck detail or the pack response."""
    record = assess(policy, sections)
    detail = precheck_policy(policy, sections, list(catalogue()["policies"][policy]["sections"]), value_rules=True)
    response = precheck_response(detail, {"policy_id": policy, "criticality": "Shall"}, list(sections))
    for output in (record, detail, response):
        dumped = json.dumps(output)
        assert CANARY not in dumped and CANARY_NAME not in dumped and "canary" not in dumped.lower()
    assert record["reason_text"] in catalogue()["policies"][policy]["cells"][record["cell"]]["reason_texts"]
    assert all(value is None or isinstance(value, str) and value in {"D103", "none", "tenant_app_settings_null",
                                                                      "certificate_auth"}
               for value in record["detail"].values())


# Gold responses can differ in citations for one D90 and three D94 rows. Four
# other D94-marked controls match exactly and must still be compared in full.
FULL_SOURCE_PARITY_EXEMPT = {
    "D90": "D90: the gold response cites scuba_config, which the rule does not read from v3.6",
    "D94": "D94: the gold response cites conditional_access_policies or scuba_config, which the rule does not read from v3.7",
}
FULL_SOURCE_PARITY_EXEMPT_COUNTS = {"D90": 1, "D94": 3}


def _source_response_exemption(row, response, overrides):
    """Compare gold first; permit only the replay's documented citation differences."""
    gold = row["gold_response"]
    if response == gold:
        return None
    marker = row.get("parity_exempt") or ""
    key = marker[:3]
    assert FULL_SOURCE_PARITY_EXEMPT.get(key) == marker, row["vector_id"]
    assert row["policy"] == {"D90": "MS.SECURITYSUITE.3.2v1", "D94": "MS.AAD.3.3v2"}[key], row["vector_id"]
    # When A2 is available, its exact override set separates the three D94
    # citation changes from the four controls that must match unmodified gold.
    if key == "D94" and overrides is not None:
        assert row["vector_id"] in overrides, row["vector_id"]
    assert [(c["id"], c["status"], c["value"]) for c in response["claims"]] == [
        (c["id"], c["status"], c["value"]) for c in gold["claims"]], row["vector_id"]
    assert (response["limitations"], response["recommendations"]) == (
        gold["limitations"], gold["recommendations"]), row["vector_id"]
    return key


def test_full_source_response_guard_checks_controls_and_citation_exceptions():
    gold = {"claims": [{"id": "requirement_met", "status": "satisfied", "value": True, "evidence_ids": ["e0"]}],
            "limitations": [], "recommendations": []}
    row = {"vector_id": "constructed:guard", "policy": "MS.AAD.3.3v2",
           "parity_exempt": FULL_SOURCE_PARITY_EXEMPT["D94"], "gold_response": gold}
    assert _source_response_exemption(row, deepcopy(gold), {}) is None
    citation_change = deepcopy(gold)
    citation_change["claims"][0]["evidence_ids"] = ["e1"]
    assert _source_response_exemption(row, citation_change, None) == "D94"
    assert _source_response_exemption(row, citation_change, {row["vector_id"]: {}}) == "D94"
    with pytest.raises(AssertionError):
        _source_response_exemption(row, citation_change, {})
    for field, value in (("id", "different"), ("status", "different"), ("value", False)):
        changed = deepcopy(citation_change)
        changed["claims"][0][field] = value
        with pytest.raises(AssertionError):
            _source_response_exemption(row, changed, {row["vector_id"]: {}})
    for field in ("limitations", "recommendations"):
        changed = deepcopy(citation_change)
        changed[field] = ["different"]
        with pytest.raises(AssertionError):
            _source_response_exemption(row, changed, {row["vector_id"]: {}})


def test_optional_full_source_vectors():
    path = os.getenv("AUDITEX_TEST_VALUE_RULE_VECTORS_V391")
    if not path:
        pytest.skip("AUDITEX_TEST_VALUE_RULE_VECTORS_V391 unset")
    from hashlib import sha256
    from test_value_rules_replay import MANIFEST, _overrides, override_gold

    override_path = Path(path).with_name("a2-label-overrides.jsonl")
    overrides = _overrides(override_path) if override_path.is_file() else None
    if overrides is not None:
        pins = json.loads(MANIFEST.read_text())
        with Path(path).open("rb") as source:
            assert sha256(source.read()).hexdigest() == pins["source_vectors_sha256"]
        assert sha256(override_path.read_bytes()).hexdigest() == pins["a2_label_overrides_sha256"]
        assert len(overrides) == 190
    policy_items = json.loads(open_text_resource("configs/scuba-policy-sections.json"))["policies"]
    reached = defaultdict(set)
    licence_excluded = 0
    parity_exempt = {}
    d94_controls = 0
    overlays_applied = set()
    for row in _rows(Path(path)):
        if row["policy"] not in STAGE_POLICIES:
            continue
        detail = precheck_policy(row["policy"], row["sections"], list(row["sections"]), value_rules=True)
        record = assess(row["policy"], row["sections"])
        assert (record["cell"], record["reason_code"]) == (row["rule_cell"], row["rule_reason_code"])
        assert detail["class"] == "value_rule"
        assert (detail["cell"], detail["reason_code"]) == (row["rule_cell"], row["rule_reason_code"])
        assert detail["section"] == (row["rule_cited_sections"] or catalogue()["policies"][row["policy"]]["sections"])
        assert catalogue()["policies"][row["policy"]]["cells"][detail["cell"]]["verdict"] == row["rule_verdict"]
        # The v2 source (no origin field) predates the v3.6 Power BI licence
        # wording; the checked-in fixture carries the new exact text.
        if "origin" in row or detail["cell"] not in {"licence_false", "licence_flag_unusable"}:
            assert detail["reason_text"] == row["rule_reason_text"]
        criticality = policy_items[row["policy"]]["policy_item"]["criticality"]
        item = {"policy_id": row["policy"], "criticality": criticality}
        response = precheck_response(detail, item, list(row["sections"]), named_limitations=False)
        if row.get("gold_response") is not None and row.get("disagreement") is None:
            if row["source_kind"].startswith("packlic-"):
                # Match the reference checker: these twins' gold predates the
                # licence section. All exact rule assertions above still run.
                licence_excluded += 1
            else:
                exemption = _source_response_exemption(row, response, overrides)
                if exemption is not None:
                    assert row["vector_id"] not in parity_exempt
                    parity_exempt[row["vector_id"]] = exemption
                elif (row.get("parity_exempt") or "").startswith("D94"):
                    d94_controls += 1
                entry = overrides.get(row["vector_id"]) if overrides is not None else None
                if entry is not None:
                    gold = override_gold(row, entry)
                    overlaid_response = precheck_response(detail, item, entry["evidence_section_order"],
                                                          named_limitations=False)
                    assert overlaid_response == gold, row["vector_id"]
                    assert row["vector_id"] not in overlays_applied
                    overlays_applied.add(row["vector_id"])
        assert row.get("disagreement") is None or row["disagreement"].startswith("expected:")
        reached[row["policy"]].add(detail["cell"])
    assert all(reached[policy] == set(cells_for(policy)) for policy in reached)
    assert set(reached) in (STAGE1_POLICIES, STAGE_POLICIES)
    if set(reached) == STAGE_POLICIES:
        assert licence_excluded == 45
        assert dict(Counter(parity_exempt.values())) == FULL_SOURCE_PARITY_EXEMPT_COUNTS
        assert d94_controls == 4
        if overrides is not None:
            assert overlays_applied == set(overrides)
    else:
        assert licence_excluded == 0 and parity_exempt == {} and d94_controls == 0


def test_stage3_answers_validate_end_to_end(tmp_path, monkeypatch):
    """Served stage-3 answers (the gate rendered as the rule's closed_gate cell, a lookup verdict, an environment
    cell and a raising rule) validate under the 2026-11-05 assessment validator and never call the model."""
    from auditex.rule_assessment import assess_run
    from azure_tenant_audit import value_rules
    from azure_tenant_audit.scuba_assessment import validate_assessment
    from test_model_serving import fake_projection

    (tmp_path / "run-manifest.json").write_text('{"run_id":"stage3"}')
    rule_sections = {"meeting_policies": [{"Identity": "Global", "AllowExternalParticipantGiveRequestControl": True}],
                     "federation_configuration": [{"Identity": "Global", "AllowTeamsConsumer": False}],
                     "client_configuration": [{"Identity": "Global", "AllowEmailIntoChannel": False}],
                     "org_config": [{"Name": "x", "AuditDisabled": False}]}
    views = {"MS.TEAMS.2.2v2": {"M365Environment": "gcchigh"}, "MS.TEAMS.2.3v2": {"M365Environment": "Commercial"},
             "MS.TEAMS.4.1v1": {"M365Environment": "commercial"}}

    def projected(root, **options):
        projection = fake_projection(root, {})
        projection.rule_sections.update(rule_sections)
        for policy, config in views.items():
            projection.rule_views.setdefault(policy, {})["scuba_config"] = config
        return projection

    original = value_rules.assess

    def failing_for_exo(policy_id, sections):
        if policy_id == "MS.EXO.13.1v1":
            raise TypeError("Canary Evidence Text")
        return original(policy_id, sections)

    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    monkeypatch.setattr("auditex.rule_assessment.project_run", projected)
    monkeypatch.setattr(value_rules, "assess", failing_for_exo)
    policies = ["MS.TEAMS.1.1v1", "MS.TEAMS.2.2v2", "MS.TEAMS.2.3v2", "MS.TEAMS.4.1v1", "MS.EXO.13.1v1"]
    result = assess_run(tmp_path, policies=policies)
    cells = {row["policy_id"]: row["rule_precheck"]["cell"] for row in result["policies"]}
    assert cells == {"MS.TEAMS.1.1v1": "flag_bad", "MS.TEAMS.2.2v2": "closed_gate",
                     "MS.TEAMS.2.3v2": "environment_unknown", "MS.TEAMS.4.1v1": "all_clear",
                     "MS.EXO.13.1v1": None}
    assert all(row["rule_precheck"]["class"] == "value_rule" for row in result["policies"])
    failed = next(row for row in result["policies"] if row["policy_id"] == "MS.EXO.13.1v1")
    assert failed["recommendations"] == ["report_product_fault"] and failed["limitations"] == []
    assert "Canary Evidence Text" not in json.dumps(result)
    validate_assessment(result)
    for key, bad in (("section", ["org_config", "org_config"]), ("reason_text", "Not assessed: other."),
                     ("reason_code", "rule_failed")):
        from copy import deepcopy
        tampered = deepcopy(result)
        next(row for row in tampered["policies"] if row["policy_id"] == "MS.EXO.13.1v1")["rule_precheck"][key] = bad
        with pytest.raises(ValueError):
            validate_assessment(tampered)


# Every catalogue policy has a value rule; a policy that loses its rule fails this guard.
EXPECTED_UNCOVERED = frozenset()


def test_expected_uncovered_policies_matches_registry():
    from auditex.rule_assessment import policy_catalogue
    catalogue = set(policy_catalogue()['policies'])
    assert catalogue - set(rule_policies()) == EXPECTED_UNCOVERED
    assert len(rule_policies()) == len(catalogue) - len(EXPECTED_UNCOVERED) == 102


@pytest.mark.parametrize('rule_view', [False, True], ids=['case-evidence', 'production-rule-view'])
def test_covered_vectors_never_reach_rule_not_implemented(rule_view, monkeypatch, record_property):
    from auditex.rule_assessment import _assess_policies, policy_catalogue
    from auditex.scuba_projection import Projection
    items = policy_catalogue()
    reached = defaultdict(set)
    by_cell = Counter()
    by_fixture = Counter()
    for path in sorted(FIXTURE.parent.glob('vectors-*.jsonl.xz')):
        for row in _rows(path):
            policy = row['policy']
            if policy not in rule_policies():
                continue
            sections = deepcopy(row['sections'])
            projection = Projection() if rule_view else {}
            projection.update(sections)
            if rule_view:
                projection.rule_sections = deepcopy(sections)
                projection.rule_views = {}
                if 'scuba_config' in sections:
                    projection.rule_views[policy] = {'scuba_config': deepcopy(sections['scuba_config'])}
            records = _assess_policies(projection, [policy], items, 'synthetic', baseline={})
            assert records[0]['reason'] == 'rule_precheck', row['vector_id']
            assert records[0]['rule_precheck']['class'] == 'value_rule', row['vector_id']
            cell = records[0]['rule_precheck']['cell']
            reached[policy].add(cell)
            by_cell[f'{policy}:{cell}'] += 1
            by_fixture[path.name] += 1
    record_property('vector_counts', json.dumps({'total': sum(by_cell.values()), 'by_fixture': dict(by_fixture),
                                                'by_cell': dict(sorted(by_cell.items()))}, sort_keys=True))
    assert set(reached) == set(rule_policies())
    # The plain case route deliberately lacks rule-only dependencies from the frozen model catalogue.
    # Full cell reach is a production-view assertion; both routes must keep every covered vector in rules.
    if rule_view:
        assert all(set(cells_for(policy)) - {'rule_evaluation_failed'} <= cells for policy, cells in reached.items())
