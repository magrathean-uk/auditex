"""C1: idempotent finalize.

Running ``finalize_bundle_contract`` twice on the same writer with the same
in-memory inputs must produce byte-identical content for the deterministic
artifacts (validation.json, ai_context.json, reports/report-pack.json,
summary.json) and a logically-equal evidence DB. The contract guard
``contracts.py`` + the validator in ``finalize.py`` rely on this — a
finalize that drifted between two calls would cause spurious
contract-status flips on re-runs of the same bundle.

Wall-clock-dependent fields (audit-log.jsonl, run-manifest.created_utc)
are intentionally NOT compared; the AuditLogger appends an event each
finalize call by design, and the manifest's created_utc is set when the
writer is constructed (the same writer is reused across both calls so it
stays stable for run-manifest.json byte equality, but the test still
focuses on the contract-bound artifacts to stay robust under a future
refactor).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from azure_tenant_audit.ai_context import build_privacy_block
from azure_tenant_audit.ai_context import build_ai_context
from azure_tenant_audit.finalize import finalize_bundle_contract
from azure_tenant_audit.findings import build_findings, build_report_pack
from azure_tenant_audit.normalize import build_ai_safe_summary, build_normalized_snapshot
from azure_tenant_audit.output import AuditWriter
from azure_tenant_audit import run as run_core


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sqlite_logical_dump(db_path: Path) -> dict[str, list[tuple]]:
    """Snapshot every (table, all-rows) so we can compare logical content
    rather than relying on byte-stable SQLite page layout."""
    conn = sqlite3.connect(db_path)
    try:
        tables = sorted(
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            if not row[0].startswith("sqlite_")
        )
        snapshot: dict[str, list[tuple]] = {}
        for table in tables:
            rows = sorted(conn.execute(f"SELECT * FROM {table}").fetchall())
            snapshot[table] = rows
        return snapshot
    finally:
        conn.close()


def _prepare_bundle_for_finalize(out_dir: Path) -> tuple[AuditWriter, dict]:
    """Mirror the offline-runner setup up to (but not including) the first
    finalize call. Returns the writer and the kwargs used for finalize.
    """
    repo = Path(__file__).resolve().parent.parent
    sample = json.loads(
        (repo / "examples" / "sample_audit_bundle" / "sample_result.json").read_text(
            encoding="utf-8"
        )
    )

    writer = AuditWriter(out_dir, tenant_name="ci-idem", run_name="contract")

    collector_payloads: dict[str, dict] = {}
    result_rows: list[dict] = []
    (writer.raw_dir / "sample_input.json").write_text(
        json.dumps(sample, indent=2), encoding="utf-8"
    )
    writer.record_artifact(writer.raw_dir / "sample_input.json")
    for key, value in sample.items():
        if isinstance(value, dict):
            collector_payloads[str(key)] = value
        row = {
            "name": str(key),
            "status": "ok",
            "item_count": len(value.get("value", [])) if isinstance(value, dict) else 0,
            "message": "offline simulation",
            "coverage_rows": 0,
        }
        result_rows.append(row)
        writer.write_summary(row)
        writer.write_checkpoint(str(key), row)

    diagnostics: list[dict] = []
    coverage_rows: list[dict] = []
    capability_rows = [
        {
            "collector": row["name"],
            "status": "offline_sample",
            "reason": "offline_bundle",
            "required_permissions": [],
            "missing_permissions": [],
            "observed_permissions": [],
            "delegated_roles": [],
            "minimum_role_hints": [],
            "notes": "Offline sample run; no tenant auth exercised.",
        }
        for row in result_rows
    ]
    coverage_ledger = run_core.build_coverage_ledger(
        capability_rows=capability_rows,
        result_rows=result_rows,
        diagnostics=diagnostics,
    )
    normalized_snapshot = build_normalized_snapshot(
        tenant_name="ci-idem",
        run_id=writer.run_id,
        collector_payloads=collector_payloads,
        diagnostics=diagnostics,
        result_rows=result_rows,
        coverage_rows=coverage_rows,
        run_dir=writer.run_dir,
    )
    findings = build_findings(diagnostics, normalized_snapshot=normalized_snapshot)
    writer.write_normalized(
        "capability_matrix", {"kind": "capability_matrix", "records": capability_rows}
    )
    writer.write_normalized(
        "coverage_ledger", {"kind": "coverage_ledger", "records": coverage_ledger}
    )
    for name, payload in normalized_snapshot.items():
        writer.write_normalized(name, payload)
    writer.write_ai_safe(
        "run_summary", build_ai_safe_summary(normalized_snapshot, findings=findings)
    )
    if findings:
        writer.write_findings(findings)

    evidence_paths = [
        "run-manifest.json",
        "summary.json",
        "reports/report-pack.json",
        "index/evidence.sqlite",
        "ai_context.json",
        "validation.json",
        "ai_safe/run_summary.json",
    ]
    if findings:
        evidence_paths.append("findings/findings.json")
    evidence_paths.extend(
        f"normalized/{name}.json"
        for name in ["capability_matrix", "coverage_ledger", *normalized_snapshot.keys()]
    )
    privacy = build_privacy_block(safe_for_external_llm=False)
    writer.write_report_pack(
        build_report_pack(
            tenant_name="ci-idem",
            overall_status="ok",
            findings=findings,
            evidence_paths=evidence_paths,
            blocker_count=0,
            privacy=privacy,
        )
    )

    finalize_kwargs = {
        "writer": writer,
        "bundle_metadata": {
            "executed_by": "azure_tenant_audit",
            "collectors": list(sample.keys()),
            "overall_status": "ok",
            "duration_seconds": 0,
            "mode": "offline",
            "auditor_profile": "auto",
            "plane": "inventory",
            "since": None,
            "until": None,
            "command_line": [],
            "coverage_count": 0,
            "privacy": privacy,
        },
        "run_metadata": {
            "tenant_name": "ci-idem",
            "tenant_id": None,
            "run_id": writer.run_id,
            "overall_status": "ok",
            "auditor_profile": "auto",
            "mode": "offline",
            "plane": "inventory",
            "selected_collectors": list(sample.keys()),
            "duration_seconds": 0,
        },
        "normalized_snapshot": normalized_snapshot,
        "capability_rows": capability_rows,
        "coverage_ledger": coverage_ledger,
        "blockers": diagnostics,
        "findings": findings,
    }
    return writer, finalize_kwargs


# Artifacts whose content depends only on the input data — must be byte-stable
# across two finalize calls.
_BYTE_STABLE_ARTIFACTS = (
    "validation.json",
    "ai_context.json",
    "reports/report-pack.json",
    "summary.json",
)


def test_ai_context_ignores_sqlite_sidecar_artifacts(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    index_dir = run_dir / "index"
    index_dir.mkdir(parents=True)
    for name in ("evidence.sqlite", "evidence.sqlite-wal", "evidence.sqlite-shm"):
        (index_dir / name).write_text("", encoding="utf-8")

    context = build_ai_context(
        run_dir=run_dir,
        run_metadata={},
        normalized_snapshot={},
        capability_rows=[],
        coverage_ledger=[],
        blockers=[],
        findings=[],
    )

    assert "index/evidence.sqlite" in context["artifacts"]["index"]
    assert "index/evidence.sqlite-wal" not in context["artifacts"]["index"]
    assert "index/evidence.sqlite-shm" not in context["artifacts"]["index"]


def test_finalize_bundle_contract_is_idempotent_for_byte_stable_artifacts(
    tmp_path: Path,
) -> None:
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)

    finalize_bundle_contract(**kwargs)
    first_hashes = {name: _sha(writer.run_dir / name) for name in _BYTE_STABLE_ARTIFACTS}

    finalize_bundle_contract(**kwargs)
    second_hashes = {name: _sha(writer.run_dir / name) for name in _BYTE_STABLE_ARTIFACTS}

    drift = {name: (first_hashes[name], second_hashes[name]) for name in _BYTE_STABLE_ARTIFACTS if first_hashes[name] != second_hashes[name]}
    assert not drift, (
        f"finalize_bundle_contract drifted between calls for {sorted(drift)} — "
        f"this breaks reproducibility and would cause spurious contract-status flips "
        f"on re-runs. Hashes: {drift}"
    )


def test_finalize_evidence_db_is_logically_idempotent(tmp_path: Path) -> None:
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)

    finalize_bundle_contract(**kwargs)
    first_dump = _sqlite_logical_dump(writer.run_dir / "index" / "evidence.sqlite")

    finalize_bundle_contract(**kwargs)
    second_dump = _sqlite_logical_dump(writer.run_dir / "index" / "evidence.sqlite")

    assert sorted(first_dump) == sorted(second_dump), (
        f"evidence.sqlite tables changed between finalize calls: "
        f"{sorted(first_dump)} vs {sorted(second_dump)}"
    )
    for table in first_dump:
        assert first_dump[table] == second_dump[table], (
            f"table={table} drifted between finalize calls "
            f"(first {len(first_dump[table])} rows vs second {len(second_dump[table])})"
        )


def test_finalize_validation_status_remains_valid_after_re_run(
    tmp_path: Path,
) -> None:
    """Re-finalising a clean bundle must NOT flip contract_status to invalid."""
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)

    first = finalize_bundle_contract(**kwargs)
    assert first["validation"]["valid"] is True

    second = finalize_bundle_contract(**kwargs)
    assert second["validation"]["valid"] is True
    assert second["validation"].get("issue_count", 0) == first["validation"].get(
        "issue_count", 0
    )
