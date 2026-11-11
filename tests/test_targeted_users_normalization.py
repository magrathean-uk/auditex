"""Local normalised and SQLite retention of TargetedUsersCoverage v1 (SS 2.1 interface section 3).

Only identity/source metadata and a shape-validated summary survive; the literal target list, unknown fields and
unrepresentable rows never do. Local retention of the summary is intentional; shareable outputs strip it.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from azure_tenant_audit.normalize import build_normalized_snapshot
from azure_tenant_audit.value_rules.defender_targeted_users import COVERAGE_KEY

FIXTURES = json.loads(Path("tests/fixtures/targeted-users-coverage-v1.json").read_text())
KNOWN = FIXTURES["cases"][0]["policy_row"][COVERAGE_KEY]
DIGEST = FIXTURES["fixture_hmac_sha256"]
CANARIES = ["target-canary@example.invalid", "Target Canary Name", "canary-domain.invalid", "mal;formed;canary"]
ALLOWED = {"kind", "source", "id", "key", "source_name", "display_name", COVERAGE_KEY}


def rows():
    return [
        {"Identity": "Default", "Name": "Default", "IsDefault": True, "Enabled": True,
         "EnableTargetedUserProtection": True, "TargetedUsersToProtect": list(CANARIES), "FreeField": CANARIES[0],
         COVERAGE_KEY: dict(KNOWN)},
        {"Identity": "Bad", "Name": "Bad", COVERAGE_KEY: {**KNOWN, "extra": CANARIES[1]}},
        {"Identity": "Absent", "Name": "Absent", "TargetedUsersToProtect": list(CANARIES)},
        {"Identity": "Minimal", COVERAGE_KEY: {"version": 1, "state": "over_limit"}},
        {"Identity": "Nested", COVERAGE_KEY: {"version": 1, "state": "unusable", "nested": {"x": CANARIES[2]}}},
        "scalar-row-canary",
        ["list-row-canary"],
    ]


def snapshot():
    return build_normalized_snapshot(tenant_name="t", run_id="r", collector_payloads={
        "exchange_policy": {"antiPhishPolicies": {"status": "ok", "value": rows()}}})


def test_normaliser_keeps_identity_and_the_validated_summary_only():
    result = snapshot()
    records = [r for r in result["exchange_policy_objects"]["records"] if r["source_name"] == "antiPhishPolicies"]
    by_id = {record["id"]: record for record in records}
    assert set(by_id) == {"Default", "Bad", "Absent", "Minimal", "Nested"}
    assert by_id["Default"][COVERAGE_KEY] == KNOWN
    assert by_id["Bad"][COVERAGE_KEY] == {"version": 1, "state": "unusable"}
    assert by_id["Absent"][COVERAGE_KEY] == {"version": 1, "state": "not_collected"}
    assert by_id["Minimal"][COVERAGE_KEY] == {"version": 1, "state": "over_limit"}
    assert by_id["Nested"][COVERAGE_KEY] == {"version": 1, "state": "unusable"}
    assert all(set(record) <= ALLOWED for record in records)
    assert all(record["source"] == "exchange_policy.antiPhishPolicies" for record in records)
    text = json.dumps(result, default=str)
    for canary in (*CANARIES, "scalar-row-canary", "list-row-canary", "TargetedUsersToProtect", "FreeField"):
        assert canary not in text


def test_other_exchange_operations_are_unchanged_by_the_new_source():
    payload = {"acceptedDomains": {"status": "ok", "value": [{"Identity": "example.invalid", "DomainName": "example.invalid"}]}}
    without = build_normalized_snapshot(tenant_name="t", run_id="r", collector_payloads={"exchange_policy": dict(payload)})
    payload["antiPhishPolicies"] = {"status": "ok", "value": rows()[:1]}
    with_policies = build_normalized_snapshot(tenant_name="t", run_id="r", collector_payloads={"exchange_policy": payload})
    other = [r for r in with_policies["exchange_policy_objects"]["records"] if r["source_name"] != "antiPhishPolicies"]
    assert other == without["exchange_policy_objects"]["records"]


def test_local_index_keeps_the_summary_and_never_the_list(tmp_path):
    from azure_tenant_audit.evidence_db import build_run_evidence_index
    from azure_tenant_audit.output import AuditWriter

    writer = AuditWriter(tmp_path, "mocktenant", "ss21-normalised")
    writer.write_bundle({"collectors": [], "overall_status": "ok"})
    root = writer.run_dir
    (root / "normalized").mkdir(exist_ok=True)
    (root / "normalized/exchange_policy_objects.json").write_text(json.dumps(snapshot()["exchange_policy_objects"]))
    database = build_run_evidence_index(root)
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        stored = json.dumps(connection.execute("SELECT * FROM normalized_records").fetchall(), default=str)
    finally:
        connection.close()
    assert COVERAGE_KEY in stored and DIGEST in stored          # intentional local evidence copy
    for canary in (*CANARIES, "scalar-row-canary", "list-row-canary", "TargetedUsersToProtect"):
        assert canary not in stored
