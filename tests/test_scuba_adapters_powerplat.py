"""Synthetic C1 bundles and offline vector round trips; no tenant calls."""
from __future__ import annotations

from collections import Counter, defaultdict
from hashlib import sha256
import builtins
import io
import json
import lzma
from pathlib import Path
import socket

import pytest

from auditex import scuba_adapters_powerplat as adapters
from auditex.scuba_projection import project_run
from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.tenant_identity import canonical_tenant_uuid
from azure_tenant_audit.value_rules import assess


FIXTURES = Path(__file__).parent / "fixtures"
RAW = json.loads((FIXTURES / "powerplat/raw-cases.json").read_text())
READS = {
    "environment_creation": ("power_platform", "environmentCreation"),
    "tenant_isolation": ("power_platform", "tenantIsolation"),
    "dlp_policies": ("power_platform", "dlpPolicyScopes"),
    "environment_list": ("power_platform", "environments"),
    "powerbi_tenant_settings": ("power_bi", "tenantSettings"),
    "powerbi_license_found": ("licensing", "subscribedSkus"),
    "powerbi_access_denied_reason": ("power_bi", "accessState"),
}
CREATION_KEYS = {
    "disableEnvironmentCreationByNonAdminUsers", "disableTrialEnvironmentCreationByNonAdminUsers",
    "disablePortalsCreationByNonAdminUsers", "powerPlatform",
}
TENANT = "11111111-1111-4111-8111-111111111111"


def write(root, path, payload):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload) + "\n")


def operation(root, collector, name, rows, **metadata):
    path = root / f"raw/{collector}.json"
    payload = json.loads(path.read_text()) if path.exists() else {}
    payload[name] = {"value": rows, "status": "ok", **metadata}
    write(root, f"raw/{collector}.json", payload)


def coverage(root, collector, name, status="ok", error_class=None):
    write(root, "coverage.json", [{"collector": collector, "name": name,
                                   "status": status, "error_class": error_class}])


def bundle(root, raw=None):
    write(root, "run-manifest.json", {"platform": "m365"})
    for collector, operations in (RAW["raw"] if raw is None else raw).items():
        for name, rows in operations.items():
            operation(root, collector, name, rows)
    return root


def select(row, keys):
    return {key: value for key, value in row.items() if key in keys}


def settings_rows(rows):
    result = []
    for row in rows:
        item = select(row, {"settingName", "enabled", "enabledSecurityGroups"})
        if isinstance(item.get("enabledSecurityGroups"), list):
            item["enabledSecurityGroups"] = [select(g, {"graphId"}) if isinstance(g, dict) else g
                                              for g in item["enabledSecurityGroups"]]
        result.append(item)
    return result


def plan_rows(name="POWER_BI_STANDARD", status="Success"):
    return [{"servicePlans": [{"servicePlanId": TENANT, "servicePlanName": name,
                               "provisioningStatus": status}]}]


def invert(sections):
    """Return raw C1 evidence and its reduced rule view, or a counted exclusion.

    Older denial prose reduces to the fixed C1 string. Invalid tenant identifiers
    are never repaired: the existing tenant adapter requires a canonical UUID.
    """
    raw, reduced = {}, {}
    for section, value in sections.items():
        if section == "tenant_id":
            if canonical_tenant_uuid(value) != value or not isinstance(value, str):
                return "tenant_id_unproducible"
            raw["identity"] = {"organization": [{"id": value}]}
            reduced[section] = value
            continue
        if section == "powerbi_license_found":
            if type(value) is not bool:
                return "licence_not_boolean"
            rows = plan_rows() if value else []
        elif section == "powerbi_access_denied_reason":
            if not isinstance(value, str):
                return "denial_not_string"
            status = 401 if "401" in value else 403
            rows = [{"denied": value != "", "http_status": status if value else 200}]
            value = f"Power BI Admin API denied access (HTTP {status})" if value else ""
        else:
            if not isinstance(value, list):
                return "section_not_list"
            if not all(isinstance(row, dict) for row in value):
                return "section_non_object_row"
            if section == "powerbi_tenant_settings":
                rows = value = settings_rows(value)
            elif section == "environment_creation":
                if not value or any(not row.keys() & CREATION_KEYS for row in value):
                    return "creation_no_recognised_field"
                rows = value = [select(row, CREATION_KEYS) for row in value]
            elif section == "tenant_isolation":
                if any(not isinstance(row.get("properties"), dict)
                       or "isDisabled" not in row["properties"] for row in value):
                    return "isolation_no_flag"
                rows = value = [{"properties": {"isDisabled": row["properties"]["isDisabled"]}}
                                for row in value]
            elif section == "dlp_policies":
                if len(value) != 1 or not isinstance(value[0].get("value"), list):
                    return "dlp_wrapper_unproducible"
                if not all(isinstance(row, dict) for row in value[0]["value"]):
                    return "dlp_non_object_policy"
                rows = []
                for row in value[0]["value"]:
                    item = select(row, {"name", "displayName", "environmentType", "environments"})
                    if isinstance(item.get("environments"), list):
                        item["environments"] = [select(e, {"name"}) if isinstance(e, dict) else e
                                                for e in item["environments"]]
                    rows.append(item)
                value = [{"value": rows}]
            elif section == "environment_list":
                rows = [{"name": row.get("EnvironmentName"), "is_default": row.get("IsDefault")}
                        for row in value]
                value = [{"EnvironmentName": row["name"], "IsDefault": row["is_default"]} for row in rows]
            else:
                raise AssertionError(f"Unexpected vector section: {section}")
        collector, name = READS[section]
        raw.setdefault(collector, {})[name] = rows
        reduced[section] = value
    return raw, reduced


def vector_rows():
    for fixture, prefix in (("value-rules/vectors-v2.jsonl.xz", "MS.POWERBI"),
                            ("powerplat/pp-vectors-sample.jsonl.xz", "MS.POWERPLATFORM")):
        with lzma.open(FIXTURES / fixture, "rt") as handle:
            for line in handle:
                row = json.loads(line)
                if row["policy"].startswith(prefix):
                    yield row


VECTORS = list(vector_rows())


def supported_assessment(policy, sections):
    try:
        return assess(policy, sections)
    except ValueError as exc:
        if "kind is not implemented" not in str(exc):
            raise
        return None


@pytest.mark.parametrize("vector", VECTORS,
                         ids=[f"{r['policy']}:{r['rule_cell']}:{i}" for i, r in enumerate(VECTORS)])
def test_vector_round_trip_and_verdict(tmp_path, vector):
    inverted = invert(vector["sections"])
    if isinstance(inverted, str):
        pytest.skip("C1 cannot produce vector: " + inverted)
    raw, expected = inverted
    projection = project_run(bundle(tmp_path, raw), redact=False)
    observed = {section: projection.rule_sections[section] for section in expected}
    assert observed == expected
    full = supported_assessment(vector["policy"], vector["sections"])
    if full is None:
        assert vector["policy"].startswith("MS.POWERPLATFORM")
    else:
        actual = assess(vector["policy"], observed)
        assert tuple(actual[k] for k in ("verdict", "reason_code", "cell")) == tuple(
            full[k] for k in ("verdict", "reason_code", "cell"))


def test_vector_counts_and_sample_contract(capsys):
    counts = defaultdict(Counter)
    cells = Counter()
    for vector in VECTORS:
        result = invert(vector["sections"])
        count = counts[vector["policy"]]
        if isinstance(result, str):
            count["skipped:" + result] += 1
        else:
            count["used"] += 1
            if supported_assessment(vector["policy"], vector["sections"]) is not None:
                count["verdict_equal"] += 1
        if vector["policy"].startswith("MS.POWERPLATFORM"):
            assert set(vector) == {"policy", "rule_cell", "rule_verdict", "sections"}
            cells[vector["policy"], vector["rule_cell"]] += 1
    assert max(cells.values()) <= 6
    with capsys.disabled():
        print("\nVector counts: " + json.dumps(dict(counts), sort_keys=True))


@pytest.mark.parametrize("section", READS)
@pytest.mark.parametrize("failure", RAW["failure_modes"])
def test_failed_reads_never_become_empty_or_false(tmp_path, section, failure):
    bundle(tmp_path)
    collector, name = READS[section]
    if failure.get("missing_operation"):
        path = tmp_path / f"raw/{collector}.json"
        data = json.loads(path.read_text())
        del data[name]
        write(tmp_path, f"raw/{collector}.json", data)
    elif failure.get("collection_truncated"):
        operation(tmp_path, collector, name, RAW["raw"][collector][name], collection_truncated=True)
    else:
        coverage(tmp_path, collector, name, failure["status"], failure.get("error_class"))
    projection = project_run(tmp_path, redact=False)
    assert projection.rule_sections[section] == NOT_COLLECTED
    assert projection.report["sections"][section]["reason"] == failure["reason"]


@pytest.mark.parametrize("case", RAW["cases"], ids=[case["id"] for case in RAW["cases"]])
def test_raw_cases(tmp_path, case):
    bundle(tmp_path)
    operation(tmp_path, *READS[case["section"]], case["rows"])
    projection = project_run(tmp_path, redact=False)
    if "reason" in case:
        assert projection.rule_sections[case["section"]] == NOT_COLLECTED
        assert projection.report["sections"][case["section"]]["reason"] == case["reason"]
    else:
        assert projection.rule_sections[case["section"]] == case["expected"]


def test_never_configured_switch(tmp_path, monkeypatch):
    assert adapters.NEVER_CONFIRMED_NULL_SENTINEL is False
    bundle(tmp_path)
    operation(tmp_path, "power_platform", "tenantIsolation", [{"never_configured": True}])
    monkeypatch.setattr(adapters, "NEVER_CONFIRMED_NULL_SENTINEL", True)
    assert project_run(tmp_path, redact=False).rule_sections["tenant_isolation"] == ["null"]


@pytest.mark.parametrize("plan", RAW["plans"], ids=[p["name"] + p["status"] for p in RAW["plans"]])
def test_licence_plan_matches(tmp_path, plan):
    bundle(tmp_path)
    operation(tmp_path, "licensing", "subscribedSkus", plan_rows(plan["name"], plan["status"]))
    assert project_run(tmp_path, redact=False).rule_sections["powerbi_license_found"] is plan["expected"]


def test_licence_consumes_full_scan_before_positive_result(tmp_path):
    bundle(tmp_path)
    rows = plan_rows() + [{"servicePlans": [{"servicePlanId": TENANT, "servicePlanName": "OTHER"}]}]
    operation(tmp_path, "licensing", "subscribedSkus", rows)
    assert project_run(tmp_path).rule_sections["powerbi_license_found"] == NOT_COLLECTED


def test_creation_unknown_fields_are_lenient_and_recorded(tmp_path):
    bundle(tmp_path)
    operation(tmp_path, "power_platform", "environmentCreation",
              [{"disableEnvironmentCreationByNonAdminUsers": True, "unknown": "discard"}])
    projection = project_run(tmp_path, redact=False)
    assert projection.rule_sections["environment_creation"] == [{"disableEnvironmentCreationByNonAdminUsers": True}]
    assert "unknown" in projection.report["sections"]["environment_creation"]["ignored_fields"]


def test_all_seven_rule_sections_and_model_view_unchanged(tmp_path):
    projection = project_run(bundle(tmp_path), redact=False)
    expected = {
        "environment_creation": [{"disableEnvironmentCreationByNonAdminUsers": True}],
        "tenant_isolation": [{"properties": {"isDisabled": False}}],
        "dlp_policies": [{"value": []}],
        "environment_list": [{"EnvironmentName": "test", "IsDefault": False}],
        "powerbi_tenant_settings": [{"settingName": "PublishToWeb", "enabled": False}],
        "powerbi_license_found": True,
        "powerbi_access_denied_reason": "",
    }
    for section, value in expected.items():
        assert projection.rule_sections[section] == value
        assert projection[section] == NOT_COLLECTED
        report = projection.report["sections"][section]
        assert report["reason"] == "incomplete_shape"
        assert report["detail"]["kind"] == "unseen_shape"


def test_projection_is_read_only_and_has_no_network(tmp_path, monkeypatch):
    bundle(tmp_path)

    def tree():
        return {str(p.relative_to(tmp_path)): (p.stat().st_mode, sha256(p.read_bytes()).hexdigest())
                for p in tmp_path.rglob("*") if p.is_file()}

    def no_socket(*args, **kwargs):
        pytest.fail("Projection opened a network socket")

    def read_only(original):
        def guarded(file, mode="r", *args, **kwargs):
            assert not any(flag in mode for flag in "wax+"), "Projection opened a file for writing"
            return original(file, mode, *args, **kwargs)
        return guarded

    before = tree()
    with monkeypatch.context() as patch:
        patch.setattr(socket, "socket", no_socket)
        patch.setattr(builtins, "open", read_only(builtins.open))
        patch.setattr(io, "open", read_only(io.open))
        projection = project_run(tmp_path, redact=False)
    assert all(projection.rule_sections[s] != NOT_COLLECTED for s in READS)
    assert tree() == before
