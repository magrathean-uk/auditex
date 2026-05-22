from __future__ import annotations

import json
from pathlib import Path

from azure_tenant_audit.api_inventory import build_api_call_inventory
from azure_tenant_audit.contracts import build_validation_report
from azure_tenant_audit.finalize import finalize_bundle_contract
from test_finalize_idempotent import _prepare_bundle_for_finalize


def test_api_inventory_maps_observed_calls_to_read_only_customer_ledger() -> None:
    inventory = build_api_call_inventory(
        platform="m365",
        selected_collectors=["identity"],
        capability_rows=[
            {
                "collector": "identity",
                "status": "supported_exact_scope",
                "required_permissions": ["Directory.Read.All"],
                "observed_permissions": ["Directory.Read.All"],
                "missing_permissions": [],
            }
        ],
        coverage_rows=[
            {
                "collector": "identity",
                "name": "users",
                "endpoint": "/users",
                "status": "ok",
                "item_count": 2,
                "duration_ms": 1.5,
            }
        ],
        data_handling={
            "platform": "m365",
            "plane": "inventory",
            "read_only": True,
            "content_reads": False,
            "write_actions": False,
            "scope_risk": "read_only_scopes",
            "write_capable_scopes": [],
        },
        collector_descriptions={"identity": "Directory posture"},
    )

    assert inventory["safety"]["read_only"] is True
    assert inventory["safety"]["no_content_reads"] is True
    assert inventory["counts"]["observed_calls"] == 1
    assert inventory["declared_collectors"][0]["description"] == "Directory posture"
    call = inventory["observed_calls"][0]
    assert call["method"] == "GET"
    assert call["access_mode"] == "read"
    assert call["data_class"] == "directory_identity"
    assert call["required_permissions"] == ["Directory.Read.All"]


def test_finalize_writes_api_inventory_and_report_evidence_path(tmp_path: Path) -> None:
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    writer.write_index_records(
        [
            {
                "collector": "identity",
                "name": "users",
                "endpoint": "/users",
                "status": "ok",
                "item_count": 1,
                "duration_ms": 1.0,
            }
        ]
    )

    finalize_bundle_contract(**kwargs)

    run_dir = writer.run_dir
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    inventory = json.loads((run_dir / manifest["api_inventory_path"]).read_text(encoding="utf-8"))
    report_pack = json.loads((run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))

    assert manifest["api_inventory_path"] == "api-inventory.json"
    assert inventory["observed_calls"][0]["endpoint"] == "/users"
    assert inventory["safety"]["read_only"] is True
    assert "api-inventory.json" in report_pack["evidence_paths"]
    assert validation["valid"] is True, validation["issues"]


def test_contract_rejects_audit_plane_mutating_api_inventory(tmp_path: Path) -> None:
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    finalize_bundle_contract(**kwargs)
    run_dir = writer.run_dir
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    inventory_path = run_dir / manifest["api_inventory_path"]
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory["safety"]["read_only"] = False
    inventory["safety"]["write_actions"] = True
    inventory["observed_calls"].append(
        {
            "id": "identity:bad:1",
            "collector": "identity",
            "name": "bad",
            "endpoint": "/users",
            "method": "PATCH",
            "content_reads": False,
            "write_actions": True,
        }
    )
    inventory_path.write_text(json.dumps(inventory, indent=2), encoding="utf-8")

    report = build_validation_report(run_dir=run_dir)

    assert report["valid"] is False
    assert "invalid_api_inventory_safety" in {item["code"] for item in report["issues"]}
