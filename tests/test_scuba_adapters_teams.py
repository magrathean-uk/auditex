"""Offline Teams rule-view contracts, including the unchanged model shape gate."""
from collections import Counter
from copy import deepcopy
import inspect
import json
from pathlib import Path

import pytest

from auditex.rule_assessment import canonical
from auditex.scuba_adapters_teams import ADAPTERS, TEAMS_ADAPTERS
from auditex.scuba_projection import AREA_ADAPTER_MODULES, PS_SECTIONS, project_run
from azure_tenant_audit.collection_markers import NOT_COLLECTED


OPERATIONS = {
    "broadcast_policies": "broadcastPolicies",
    "client_configuration": "clientConfiguration",
    "app_policies": "appPermissionPolicies",
    "federation_configuration": "tenantFederationConfiguration",
}
VALID = {
    "broadcast_policies": {"Identity": "Global", "BroadcastRecordingMode": "AlwaysDisabled"},
    "client_configuration": {"Identity": "Global", "AllowEmailIntoChannel": False},
    "app_policies": {"Identity": "Global", "DefaultCatalogAppsType": "AllowedAppList",
                     "GlobalCatalogAppsType": "AllowedAppList", "PrivateCatalogAppsType": "AllowedAppList"},
    "federation_configuration": {"Identity": "Global", "AllowFederatedUsers": True,
                                 "AllowTeamsConsumer": False, "AllowTeamsConsumerInbound": False,
                                 "AllowedDomains": []},
}
FIXTURE = json.loads((Path(__file__).parent / "fixtures/teams-rule-vectors-v39.json").read_text())
CASES = [(row, section) for row in FIXTURE["vectors"] for section in OPERATIONS if section in row["sections"]]
SENTINEL = "Domain=<withheld>"
PARTNERS = ["partner-one.invalid", "partner-two.invalid"]


def write(root, path, payload):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload) + '\n')


def operation(root, collector, name, rows, **metadata):
    path = root / f'raw/{collector}.json'
    payload = json.loads(path.read_text()) if path.exists() else {}
    payload[name] = {'value': rows, 'status': 'ok', **metadata}
    write(root, f'raw/{collector}.json', payload)


@pytest.fixture
def bundle(tmp_path):
    write(tmp_path, "run-manifest.json", {
        "run_id": "synthetic-run", "platform": "m365",
        "tenant_id": "11111111-1111-4111-8111-111111111111",
        "graph_endpoint": "https://graph.microsoft.com/v1.0",
    })
    return tmp_path


def put(root, section, rows):
    operation(root, "teams_policy", OPERATIONS[section], rows)


def expected_rows(section, rows):
    """Independent fixture oracle for field presence and scalar types.

    Federation vectors include REST lists and the exact open cmdlet marker.
    This deliberately does not call adapter helpers.
    """
    if not isinstance(rows, list):
        return NOT_COLLECTED
    result = []
    for row in rows:
        if not isinstance(row, dict) or not VALID[section].keys() <= row.keys():
            return NOT_COLLECTED
        item = {field: row[field] for field in VALID[section]}
        for field, value in item.items():
            if field == "AllowedDomains":
                if value == "AllowAllKnownDomains" or value == {}:
                    item[field] = []
                    continue
                if not isinstance(value, list):
                    return NOT_COLLECTED
                if any(not isinstance(entry, dict) or not isinstance(entry.get("AllowedDomain"), list)
                       or not entry["AllowedDomain"] for entry in value):
                    return NOT_COLLECTED
                total = sum(len(entry["AllowedDomain"]) for entry in value)
                item[field] = [{"AllowedDomain": [SENTINEL] * total}] if total else []
            elif field == "Identity" and section == "client_configuration":
                if value is not None and not isinstance(value, str):
                    return NOT_COLLECTED
            elif isinstance(VALID[section][field], bool):
                if type(value) is not bool:
                    return NOT_COLLECTED
            elif not isinstance(value, str) or not value:
                return NOT_COLLECTED
        result.append(item)
    return result


@pytest.mark.parametrize("row,section", CASES,
                         ids=[f"{row['vector_id']}:{section}" for row, section in CASES])
def test_rule_vectors(bundle, row, section):
    rows = row["sections"][section]
    put(bundle, section, rows)
    p = project_run(bundle, redact=False)
    assert p.rule_sections[section] == expected_rows(section, rows)
    # No model shape digest exists, even when the rule view holds valid data.
    assert p[section] == NOT_COLLECTED
    assert p.report["sections"][section]["reason"] == "incomplete_shape"


def test_fixture_projection_counts():
    counts = {section: [0, 0] for section in OPERATIONS}
    for row, section in CASES:
        counts[section][expected_rows(section, row["sections"][section]) == NOT_COLLECTED] += 1
    assert counts == {
        "broadcast_policies": [16, 12],
        "client_configuration": [25, 18],
        "app_policies": [104, 40],
        "federation_configuration": [50, 49],
    }


@pytest.mark.parametrize("raw,expected", [
    ([], []),
    ([{"AllowedDomain": ["Domain=" + PARTNERS[0]]},
      {"AllowedDomain": ["Domain=" + PARTNERS[1], "Domain=" + PARTNERS[0]]}],
     [{"AllowedDomain": [SENTINEL] * 3}]),
    ({}, []),
    ({"AllowedDomain": PARTNERS}, [{"AllowedDomain": [SENTINEL] * 2}]),
    ({"AllowedDomains": PARTNERS}, [{"AllowedDomain": [SENTINEL] * 2}]),
    ({"Domains": PARTNERS}, [{"AllowedDomain": [SENTINEL] * 2}]),
    ({"Domain": PARTNERS[0]}, [{"AllowedDomain": [SENTINEL]}]),
    ({"AllowedDomainsAsAList": PARTNERS}, [{"AllowedDomain": [SENTINEL] * 2}]),
    ({" allowed-domain ": PARTNERS}, [{"AllowedDomain": [SENTINEL] * 2}]),
    ({"AllowedDomain": []}, NOT_COLLECTED),
    ({"AllowedDomain": None, "Description": "AllowAllKnownDomains"}, NOT_COLLECTED),
    ({"AllowAllKnownDomains": {}}, NOT_COLLECTED),
    ({"Unrecognised": "partner.invalid AllowAllKnownDomains"}, NOT_COLLECTED),
    ({"Description": "allowallknowndomains.partner.invalid"}, NOT_COLLECTED),
    ({"AllowedDomain": ["AllowAllKnownDomains"]}, NOT_COLLECTED),
    ({"AllowedDomain": "AllowAllKnownDomains"}, NOT_COLLECTED),
    ("AllowAllKnownDomains", []),
    ("allowallknowndomains", []),
    (" \tALLOWALLKNOWNDOMAINS\n", []),
    (None, NOT_COLLECTED),
    (7, NOT_COLLECTED),
    (True, NOT_COLLECTED),
    (" ", NOT_COLLECTED),
    (", ".join(PARTNERS), NOT_COLLECTED),
    ("allowallknowndomains.partner.invalid", NOT_COLLECTED),
    ("partner.invalid, AllowAllKnownDomains", NOT_COLLECTED),
    ([{"AllowedDomain": ["AllowAllKnownDomains"]}], NOT_COLLECTED),
    ([{"AllowedDomain": [" \tALLOWALLKNOWNDOMAINS\n"]}], NOT_COLLECTED),
    ([{"AllowedDomain": [PARTNERS[0], "AllowAllKnownDomains"]}], NOT_COLLECTED),
    ([{"AllowedDomain": ["allowallknowndomains.partner.invalid"]}],
     [{"AllowedDomain": [SENTINEL]}]),
    ([{"AllowedDomain": []}], NOT_COLLECTED),
    ([{"AllowedDomain": [PARTNERS[0]]}, {"AllowedDomain": []}], NOT_COLLECTED),
    ([PARTNERS[0]], NOT_COLLECTED),
    ([None], NOT_COLLECTED),
    ([{"AllowedDomain": [PARTNERS[0]]}, None], NOT_COLLECTED),
    ([{"AllowedDomain": [PARTNERS[0]]}, PARTNERS[1]], NOT_COLLECTED),
    ([{}], NOT_COLLECTED),
    ([{"AllowedDomain": PARTNERS[0]}], NOT_COLLECTED),
    ({"Unrecognised": PARTNERS}, NOT_COLLECTED),
])
def test_allowed_domains_contract_and_privacy(bundle, raw, expected):
    row = {**VALID["federation_configuration"], "AllowedDomains": raw}
    put(bundle, "federation_configuration", [row])
    p = project_run(bundle, redact=False)
    actual = p.rule_sections["federation_configuration"]
    if expected == NOT_COLLECTED:
        assert actual == NOT_COLLECTED
        assert p.report["sections"]["federation_configuration"]["reason"] == "incomplete_shape"
    else:
        assert actual == [{**row, "AllowedDomains": expected}]
    for partner in PARTNERS:
        assert partner not in canonical(p)
        assert partner not in json.dumps(p.report)
        assert partner not in canonical(p.rule_sections)


GAPS = [(section, field) for section, row in VALID.items() for field in row]


@pytest.mark.parametrize("section,field", GAPS)
def test_required_key_gaps_withhold_whole_section(bundle, section, field):
    row = deepcopy(VALID[section])
    del row[field]
    put(bundle, section, [VALID[section], row])
    p = project_run(bundle, redact=False)
    assert p.rule_sections[section] == NOT_COLLECTED
    detail = p.report["sections"][section]
    assert detail["reason"] == "incomplete_shape"
    assert detail["detail"] == {"field": field, "kind": "missing_field"}


BAD_TYPES = [(section, field, value) for section, row in VALID.items() for field in row
             if field != "AllowedDomains" for value in
             ([None, "false", 0, 1, [], {}] if isinstance(row[field], bool) else
              [False, 1, [], {}] if section == "client_configuration" else
              [None, "", False, 1, [], {}])]


@pytest.mark.parametrize("section,field,value", BAD_TYPES)
def test_invalid_scalar_types_withhold(bundle, section, field, value):
    put(bundle, section, [{**VALID[section], field: value}])
    p = project_run(bundle, redact=False)
    assert p.rule_sections[section] == NOT_COLLECTED
    assert p.report["sections"][section]["reason"] == "incomplete_shape"


@pytest.mark.parametrize("section", OPERATIONS)
@pytest.mark.parametrize("metadata", [
    {"error": "Injected Private Error"},
    {"error_class": "permission_denied"},
    {"error": "Injected Private Error", "error_class": "permission_denied"},
])
def test_failed_operation_withholds_only_its_section(bundle, section, metadata):
    for other, row in VALID.items():
        put(bundle, other, [row])
    operation(bundle, "teams_policy", OPERATIONS[section], [VALID[section]], **metadata)
    p = project_run(bundle, redact=False)
    assert p.rule_sections[section] == NOT_COLLECTED
    assert p.report["sections"][section]["reason"] == "collector_error"
    for other, row in VALID.items():
        if other != section:
            assert p.rule_sections[other] == [row]
    assert "Injected Private Error" not in canonical(p.report)


def test_coverage_attribution_keeps_other_operation(bundle):
    for section, row in VALID.items():
        put(bundle, section, [row])
    write(bundle, "coverage.json", [
        {"collector": "teams_policy", "name": "broadcastPolicies", "status": "failed"},
    ])
    p = project_run(bundle, redact=False)
    assert p.rule_sections["broadcast_policies"] == NOT_COLLECTED
    assert p.report["sections"]["broadcast_policies"]["reason"] == "incomplete_shape"
    for section in set(OPERATIONS) - {"broadcast_policies"}:
        assert p.rule_sections[section] == [VALID[section]]


def test_null_client_identity_projects_but_absent_identity_withholds(bundle):
    row = {"Identity": None, "AllowEmailIntoChannel": True}
    put(bundle, "client_configuration", [row])
    assert project_run(bundle, redact=False).rule_sections["client_configuration"] == [row]
    del row["Identity"]
    put(bundle, "client_configuration", [row])
    p = project_run(bundle, redact=False)
    assert p.rule_sections["client_configuration"] == NOT_COLLECTED
    assert p.report["sections"]["client_configuration"]["detail"]["kind"] == "missing_field"


@pytest.mark.parametrize("section", OPERATIONS)
def test_extra_field_records_name_without_private_value(bundle, section):
    put(bundle, section, [{**VALID[section], "UnexpectedPersonName": "Injected Private Person"}])
    p = project_run(bundle, redact=False)
    assert p.rule_sections[section] == [VALID[section]]
    assert p.report["sections"][section]["ignored_fields"] == ["UnexpectedPersonName"]
    assert "Injected Private Person" not in canonical(p)
    assert "Injected Private Person" not in json.dumps(p.report)
    assert "Injected Private Person" not in canonical(p.rule_sections)


def test_federation_unused_fields_are_named_and_discarded(bundle):
    put(bundle, "federation_configuration", [{**VALID["federation_configuration"],
        "AllowPublicUsers": True, "BlockedDomains": PARTNERS}])
    p = project_run(bundle, redact=False)
    assert p.rule_sections["federation_configuration"] == [VALID["federation_configuration"]]
    assert p.report["sections"]["federation_configuration"]["ignored_fields"] == [
        "AllowPublicUsers", "BlockedDomains",
    ]
    assert all(partner not in canonical([p, p.report, p.rule_sections]) for partner in PARTNERS)


@pytest.mark.parametrize("section", OPERATIONS)
def test_normalised_rows_are_never_a_fallback(bundle, section):
    write(bundle, "normalized/teams_policy_objects.json", {"records": [
        {**VALID[section], "source_name": OPERATIONS[section]},
    ]})
    p = project_run(bundle, redact=False)
    assert p.rule_sections[section] == NOT_COLLECTED
    assert p.report["sections"][section]["reason"] == "missing_artifact"


@pytest.mark.parametrize("section,field", [
    ("broadcast_policies", "BroadcastRecordingMode"),
    ("app_policies", "DefaultCatalogAppsType"),
    ("app_policies", "GlobalCatalogAppsType"),
    ("app_policies", "PrivateCatalogAppsType"),
])
def test_enum_decisions_belong_to_rules(bundle, section, field):
    row = {**VALID[section], field: "UnrecognisedEnum"}
    put(bundle, section, [row])
    assert project_run(bundle, redact=False).rule_sections[section] == [row]


def test_area_hook_registration():
    assert ADAPTERS is TEAMS_ADAPTERS
    assert set(TEAMS_ADAPTERS) == set(OPERATIONS)
    assert not set(TEAMS_ADAPTERS) & (PS_SECTIONS.keys() | {"sharing_policy", "scuba_config", "tenant_id"})
    assert "meeting_policies" not in TEAMS_ADAPTERS
    assert AREA_ADAPTER_MODULES.count("auditex.scuba_adapters_teams") == 1
    source = inspect.getsource(project_run)
    assert "for name in AREA_ADAPTER_MODULES:" in source
    assert "adapters.update(area_adapters)" in source


def test_rule_view_precedes_unchanged_model_shape_gate(bundle):
    put(bundle, "broadcast_policies", [VALID["broadcast_policies"]])
    p = project_run(bundle, redact=False)
    assert p["broadcast_policies"] == NOT_COLLECTED
    assert p.rule_sections["broadcast_policies"] == [VALID["broadcast_policies"]]
    assert p.report["sections"]["broadcast_policies"]["reason"] == "incomplete_shape"


def test_fixture_hygiene_and_provenance():
    text = canonical(FIXTURE)
    import re

    assert "@" not in text
    assert not re.search(r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b", text, re.I)
    # Inspect evidence only; the metadata intentionally names the source file.
    domains = set(re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", canonical([
        row["sections"] for row in FIXTURE["vectors"]])))
    assert domains == {"test365.some.domain.com"}
    assert len(FIXTURE["vectors"]) == 471
    assert sum(row["vector_id"].startswith("constructed:") for row in FIXTURE["vectors"]) == 459
    assert FIXTURE["_meta"]["spec_version"] == "3.9.1 FINAL"
    for section, kinds in FIXTURE["_meta"]["source_coverage"].items():
        actual = {row["vector_id"].split(":", 1)[0] for row in FIXTURE["vectors"]
                  if section in row["sections"]}
        assert actual == set(kinds)


def test_fixture_allowed_origins():
    vectors = FIXTURE["vectors"]
    ids = [row["vector_id"] for row in vectors]
    assert len(set(ids)) == len(ids)
    counts = Counter(vector_id.split(":", 1)[0] for vector_id in ids)
    assert counts == FIXTURE["_meta"]["origin_counts"] == {
        "constructed": 459, "pack-train": 6, "pack-validation": 6,
    }
    allowed = {
        "constructed": {"source_file": "constructed by build_vectors.py", "split": None},
        "pack-train": {"source_file": "20261030-oracle-pack-v10/.../approved-cases.jsonl", "split": "train"},
        "pack-validation": {"source_file": "20261030-oracle-pack-v10/.../approved-cases.jsonl", "split": "validation"},
        "packlic-train": {"source_file": "20261030-oracle-pack-v10/.../approved-cases.jsonl", "split": "train"},
    }
    assert set(FIXTURE["_meta"]["origins"]) == set(counts)
    for kind, origin in FIXTURE["_meta"]["origins"].items():
        assert origin == allowed[kind]
    assert FIXTURE["_meta"]["provenance"] == (
        "constructed rows and pack train and validation rows from v3.9.1; "
        "held-out test and pilot rows excluded"
    )
    assert not any(":v38_" in vector_id for vector_id in ids)
    replacement = next(row for row in vectors
                       if row["vector_id"] == "pack-train:scuba-teams-ms-teams-5-1v2-a133783860")
    assert replacement["policy"] == "MS.TEAMS.5.1v2"
    assert replacement["rule_reason_code"] == "required_evidence_section_not_collected"
    assert replacement["rule_verdict"] == "not_assessed"
    assert replacement["sections"]["app_policies"] == NOT_COLLECTED


def test_fixture_local_constructions_use_allowed_parents():
    by_id = {row["vector_id"]: row for row in FIXTURE["vectors"]}
    constructions = FIXTURE["_meta"]["local_constructions"]
    assert len(constructions) == 18
    local_ids = {item["vector_id"] for item in constructions}
    assert len(local_ids) == 18
    assert {vector_id for vector_id in by_id if ":fixture_" in vector_id} == local_ids
    assert Counter(by_id[vector_id]["policy"] for vector_id in local_ids) == {
        "MS.TEAMS.1.6v1": 3, "MS.TEAMS.1.3v1": 3, "MS.TEAMS.1.4v1": 3,
        "MS.TEAMS.1.7v2": 3, "MS.TEAMS.5.1v2": 2, "MS.TEAMS.5.2v2": 2, "MS.TEAMS.5.3v2": 2,
    }
    for item in constructions:
        parent_id = item["parent_vector_id"]
        assert parent_id.startswith("constructed:")
        assert parent_id not in local_ids
        parent = by_id[parent_id]
        cell = "setting_duplicated" if item["section"] == "tenant_app_settings" else "global_duplicated"
        suffix = "org_duplicated_identical" if cell == "setting_duplicated" else "global_duplicated_identical"
        assert parent_id == f"constructed:{parent['policy']}:{suffix}"
        assert parent["rule_reason_code"] == f"data_unusable_{cell}"
        assert parent["rule_verdict"] == "not_assessed"
        expected = deepcopy(parent)
        expected["vector_id"] = item["vector_id"]
        expected["sections"][item["section"]][0]["UnrelatedField"] = f"fixture-variant-{item['variant']}"
        assert by_id[item["vector_id"]] == expected
