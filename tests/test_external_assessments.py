"""Own synthetic cases using the inspected external export shapes, not source data."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from auditex.external_assessments import import_assessment, validate_assessment

TENANT = "11111111-2222-4333-8444-555555555555"
OTHER = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
TIME = "2026-10-18T10:00:00Z"


def _write(tmp_path: Path, payload: object, *, encoding: str = "utf-8") -> Path:
    path = tmp_path / "assessment.json"
    path.write_text(json.dumps(payload), encoding=encoding)
    return path


def _maester(results: tuple[str, ...] = ("Passed",)) -> dict:
    # ConvertTo-MtMaesterResult.ps1: top-level run metadata + Tests rows.
    return {
        "TenantId": TENANT, "CurrentVersion": "2.3.0", "ExecutedAt": TIME,
        "MgContext": {"TenantId": TENANT, "Account": "operator@example.com", "AccessToken": "do-not-copy"},
        "Tests": [{"Id": f"CISA.MS.AAD.3.{index + 1}", "Title": "Require strong authentication",
                   "Result": status, "Severity": "High", "ScriptBlock": "do not execute",
                   "ResultDetail": {"RelatedObjects": [{"Id": "principal-1", "DisplayName": "Example"}]}}
                  for index, status in enumerate(results)],
    }


def _scuba(results: tuple[str, ...] = ("Pass",)) -> dict:
    # Sample-Reports/ScubaResults_*.json: product -> groups -> Controls.
    return {
        "MetaData": {"TenantId": TENANT, "Tool": "ScubaGear", "ToolVersion": "1.8.0", "TimestampZulu": TIME},
        "Results": {"AAD/identity~checks": [{"GroupName": "Authentication", "Controls": [
            {"Control ID": f"MS.AAD.3.{index + 1}v1", "Requirement": "Require MFA.<div>badge text</div>",
             "Result": status, "Criticality": "Shall", "Details": "Raw collection detail"}
            for index, status in enumerate(results)
        ]}]},
        "Raw": {"access_token": "never copied"},
    }


def _monkey(status: str = "pass", *, provider: str = "Microsoft365") -> dict:
    # monkeyoutput/Get-OcsfDetectionFindingObject + Get-CloudObject writers.
    return {
        "metadata": {"product": {"name": "Monkey365", "version": "1.0.0"}, "version": "1.1.0"},
        "findingInfo": {"id": "Monkey365-synthetic-check-1", "title": "Review privileged access"},
        "cloud": {"provider": provider, "organization": {"id": TENANT, "name": "Customer"},
                  "account": {"id": TENANT, "name": "Customer"}},
        "time": TIME, "statusCode": status, "status": "New", "severity": "High",
        "resources": {"id": "principal-1", "data": {"access_token": "not copied"}},
        "unmapped": {"ruleId": "internal-check", "pluginId": "collector-1"},
    }


def _resolve(payload: object, pointer: str) -> object:
    current = payload
    for part in pointer.split("/")[1:] if pointer else []:
        part = part.replace("~1", "/").replace("~0", "~")
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current


def test_maester_preserves_nondecisive_states_and_strips_context(tmp_path: Path) -> None:
    payload = _maester(("Passed", "Failed", "Skipped", "Investigate", "Error", "NotRun", "FutureResult"))
    path = _write(tmp_path, payload)
    result = import_assessment("maester", path)
    assert [check["status"] for check in result["checks"]] == ["pass", "fail", "unknown", "unknown", "error", "unknown", "unknown"]
    assert result["tenant_id"] == TENANT
    assert result["source_version"] == "2.3.0"
    assert result["checks"][0]["resource_ids"] == ["principal-1"]
    assert result["checks"][0]["control_ids"] == ["CISA.MS.AAD.3.1"]
    assert result["provenance"]["identity_source"] == "source"
    encoded = json.dumps(result)
    assert "do-not-copy" not in encoded and "ScriptBlock" not in encoded and "Account" not in encoded


def test_scuba_manual_na_and_omissions_are_unknown_not_pass(tmp_path: Path) -> None:
    payload = _scuba(("Pass", "Fail", "Warning", "N/A", "Omitted", "Error", "-", "Incorrect Result"))
    result = import_assessment("scubagear", _write(tmp_path, payload, encoding="utf-8-sig"))
    assert [check["status"] for check in result["checks"]] == ["pass", "fail", "fail", "unknown", "unknown", "error", "unknown", "unknown"]
    assert result["checks"][0]["title"] == "Require MFA."
    assert result["checks"][0]["severity"] == "unknown"  # SHALL is not a risk severity.
    assert result["checks"][0]["control_ids"] == ["MS.AAD.3.1v1"]
    ref = result["checks"][0]["evidence_refs"][0]
    assert ref["json_pointer"] == "/Results/AAD~1identity~0checks/0/Controls/0"
    assert _resolve(payload, ref["json_pointer"])["Control ID"] == "MS.AAD.3.1v1"


@pytest.mark.parametrize("as_array", [False, True])
def test_monkey_actual_ocsf_singleton_and_array(tmp_path: Path, as_array: bool) -> None:
    row = _monkey("manual")
    payload = [row] if as_array else row
    result = import_assessment("monkey365", _write(tmp_path, payload, encoding="utf-16"))
    check = result["checks"][0]
    assert check["status"] == "unknown"  # OCSF status=New is workflow, not a test result.
    assert check["control_ids"] == []  # OCSF writer has no benchmark/version mapping.
    assert check["resource_ids"] == ["principal-1"]
    assert _resolve(payload, check["evidence_refs"][0]["json_pointer"]) == row
    assert "access_token" not in json.dumps(result)


def test_monkey_azure_subscription_is_not_tenant_identity(tmp_path: Path) -> None:
    row = _monkey("fail", provider="Azure")
    row["cloud"]["account"]["id"] = OTHER
    result = import_assessment("monkey365", _write(tmp_path, [row]))
    assert result["tenant_id"] == TENANT
    assert result["checks"][0]["status"] == "fail"


@pytest.mark.parametrize("source,factory", [("maester", _maester), ("scubagear", _scuba), ("monkey365", _monkey)])
def test_explicit_binding_cannot_override_source_identity(tmp_path: Path, source: str, factory) -> None:
    with pytest.raises(ValueError, match="conflicting tenant IDs"):
        import_assessment(source, _write(tmp_path, factory()), tenant_id=OTHER)


def test_conflicting_nested_identity_and_mixed_tenants_rejected(tmp_path: Path) -> None:
    payload = _maester()
    payload["MgContext"]["TenantId"] = OTHER
    with pytest.raises(ValueError, match="conflicting tenant IDs"):
        import_assessment("maester", _write(tmp_path, payload))
    second = _monkey()
    second["cloud"]["organization"]["id"] = OTHER
    second["cloud"]["account"]["id"] = OTHER
    with pytest.raises(ValueError, match="conflicting tenant IDs"):
        import_assessment("monkey365", _write(tmp_path, [_monkey(), second]))


def test_missing_identity_never_uses_name_and_can_be_bound(tmp_path: Path) -> None:
    payload = _maester()
    payload["TenantId"] = "TenantId (not connected to Graph)"
    payload["MgContext"] = None
    payload["TenantName"] = TENANT  # Display names cannot supply tenant identity.
    path = _write(tmp_path, payload)
    unbound = import_assessment("maester", path)
    assert unbound["tenant_id"] is None
    assert unbound["provenance"]["identity_source"] == "unverified"
    bound = import_assessment("maester", path, tenant_id=TENANT.upper())
    assert bound["tenant_id"] == TENANT
    assert bound["provenance"]["identity_source"] == "operator"
    with pytest.raises(ValueError, match="UUID"):
        import_assessment("maester", path, tenant_id="Customer name")


def test_sha256_is_of_exact_input_bytes_and_references_resolve(tmp_path: Path) -> None:
    path = _write(tmp_path, _maester(), encoding="utf-8-sig")
    result = import_assessment("maester", path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["provenance"]["input_sha256"] == digest
    assert result["checks"][0]["evidence_refs"][0]["input_sha256"] == digest
    assert validate_assessment(result) is result


@pytest.mark.parametrize("source,payload", [
    ("maester", {"Tests": []}), ("scubagear", {"MetaData": {}, "Results": {}}),
    ("monkey365", {"findingInfo": {}}), ("maester", []),
])
def test_malformed_source_shapes_are_rejected(tmp_path: Path, source: str, payload: object) -> None:
    with pytest.raises(ValueError):
        import_assessment(source, _write(tmp_path, payload))


@pytest.mark.parametrize("key", ["MgContext", "ResultDetail"])
def test_empty_arrays_are_not_silently_accepted_as_objects(tmp_path: Path, key: str) -> None:
    payload = _maester()
    if key == "MgContext":
        payload[key] = []
    else:
        payload["Tests"][0][key] = []
    with pytest.raises(ValueError, match="must be an object"):
        import_assessment("maester", _write(tmp_path, payload))


@pytest.mark.parametrize("raw", ['{"Tests":[],"Tests":[]}', '{"Tests":NaN}', '{"bad":', 'null'])
def test_invalid_or_ambiguous_json_rejected(tmp_path: Path, raw: str) -> None:
    path = tmp_path / "bad.json"
    path.write_text(raw)
    with pytest.raises(ValueError):
        import_assessment("maester", path)


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(access_token="unexpected"),
    lambda p: p.update(tenant_id="Customer"),
    lambda p: p.update(tenant_id=""),
    lambda p: p["checks"][0].update(status=[]),
    lambda p: p["checks"][0]["evidence_refs"][0].update(input_sha256="0" * 64),
    lambda p: p["checks"][0]["evidence_refs"][0].update(json_pointer="/bad~2escape"),
    lambda p: p["provenance"].update(input_name="../source.json"),
    lambda p: p["provenance"].update(identity_source="unverified"),
])
def test_canonical_validation_rejects_tampered_contract(tmp_path: Path, mutation) -> None:
    payload = copy.deepcopy(import_assessment("maester", _write(tmp_path, _maester())))
    mutation(payload)
    with pytest.raises(ValueError):
        validate_assessment(payload)
