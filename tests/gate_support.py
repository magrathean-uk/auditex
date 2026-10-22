"""Fixtures for the fail-closed gate tests: real offline bundles with controlled findings and coverage."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = REPO_ROOT / "examples" / "sample_audit_bundle" / "sample_result.json"
SAMPLE_COLLECTORS = ("identity", "security", "intune", "teams")


def offline_run(root: Path, label: str = "gate") -> Path:
    """A finished, contract-valid offline run in which exactly SAMPLE_COLLECTORS completed and no finding exists.

    The sample's own collectors and findings are replaced so the tests do not depend on what the
    sample happens to produce today.
    """
    from azure_tenant_audit.cli import run_offline

    rc = run_offline(SAMPLE, root, "contoso", label, auditor_profile="global-reader", plane="inventory")
    assert rc == 0
    run_dir = root / f"contoso-{label}"
    set_coverage(run_dir, {name: "complete_exact_scope" for name in SAMPLE_COLLECTORS}, overall_status="ok")
    write_findings(run_dir, [], file=False)
    return run_dir


def finding(
    finding_id: str,
    severity: str = "high",
    *,
    rule_id: str | None = None,
    status: str = "open",
    collector: str = "identity",
    waiver: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A finding that satisfies the bundle contract (collector, evidence reference that resolves)."""
    row: dict[str, Any] = {
        "id": finding_id,
        "rule_id": rule_id or f"rule.{finding_id}",
        "severity": severity,
        "title": f"Finding {finding_id}",
        "status": status,
        "collector": collector,
        "evidence_refs": [
            {
                "artifact_path": "run-manifest.json",
                "artifact_kind": "run_manifest",
                "collector": collector,
                "record_key": finding_id,
                "json_pointer": "/run_id",
            }
        ],
    }
    if waiver is not None:
        # apply_waivers attaches the waiver row it matched, which always names the finding or its rule.
        if not (waiver.get("finding_id") or waiver.get("rule_id")):
            waiver = {**waiver, "rule_id": row["rule_id"]}
        row["waiver"] = waiver
        row["waiver_applied"] = True
    return row


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def rehash(run_dir: Path) -> None:
    """Rewrite bundle-hashes.json for the files as they stand, as finalization would.

    The helpers below edit a finalized bundle to set up a scenario; the gate checks the hash manifest, so
    each helper re-hashes afterwards. Tests that exercise tampering edit files directly and do not call it.
    """
    from azure_tenant_audit.bundle_integrity import BUNDLE_HASHES_PATH, build_bundle_hash_manifest

    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    payload = build_bundle_hash_manifest(run_dir, run_id=manifest.get("run_id"), created_utc=manifest.get("created_utc"))
    (run_dir / BUNDLE_HASHES_PATH).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _update_manifest(run_dir: Path, **changes: Any) -> None:
    manifest_path = run_dir / "run-manifest.json"
    manifest = read_json(manifest_path)
    for key, value in changes.items():
        if value is None:
            manifest.pop(key, None)
        else:
            manifest[key] = value
    _write_json(manifest_path, manifest)
    rehash(run_dir)


def set_findings_file(run_dir: Path, findings: list[dict[str, Any]] | None) -> None:
    """Write findings/findings.json and the manifest fields the real writer sets, or remove both."""
    path = run_dir / "findings" / "findings.json"
    if findings is None:
        path.unlink(missing_ok=True)
        _update_manifest(run_dir, findings_path=None, findings_count=None)
        return
    _write_json(path, findings)
    _update_manifest(run_dir, findings_path="findings/findings.json", findings_count=len(findings))


def set_pack_findings(run_dir: Path, findings: list[dict[str, Any]]) -> None:
    report_path = run_dir / "reports" / "report-pack.json"
    report = read_json(report_path)
    report["findings"] = findings
    # The proof table cites each finding's records by content hash; rows of a replaced finding would go stale.
    kept = {row.get("id") for row in findings}
    report["proof_table"] = [row for row in report.get("proof_table") or [] if row.get("finding_id") in kept]
    _write_json(report_path, report)
    rehash(run_dir)


def write_findings(run_dir: Path, findings: list[dict[str, Any]], *, pack: bool = True, file: bool = True) -> None:
    """Replace the run's findings in findings/findings.json (or remove it) and in the report pack."""
    set_findings_file(run_dir, findings if file else None)
    if pack:
        set_pack_findings(run_dir, findings)


def completed_in_summary(run_dir: Path) -> list[str]:
    """The collectors the run's summary lists as ok."""
    return [row["name"] for row in read_json(run_dir / "summary.json")["collectors"] if row.get("status") == "ok"]


def set_admin_set(run_dir: Path, state: str = "complete", reasons: tuple[str, ...] = ()) -> None:
    """Write the run's effective administrator set summary: ``complete``, or ``unknown`` with reasons."""
    summary = {
        "kind": "effective_admin_set_summary",
        "key": "effective_admin_set_summary:summary",
        "id": "summary",
        "state": state,
        "reasons": list(reasons),
        "licence_state": "known",
    }
    _write_json(run_dir / "normalized" / "effective_admin_set.json", {"kind": "effective_admin_set", "records": [summary]})
    rehash(run_dir)


def set_coverage(run_dir: Path, statuses: dict[str, str], *, overall_status: str | None = None) -> None:
    """Rewrite the coverage ledger to exactly these collectors and coverage statuses."""
    ledger_path = run_dir / "normalized" / "coverage_ledger.json"
    ledger = read_json(ledger_path)
    ledger["records"] = [
        {"collector": name, "coverage_status": status, "coverage_reason": "test"} for name, status in statuses.items()
    ]
    _write_json(ledger_path, ledger)
    if overall_status is not None:
        manifest_path = run_dir / "run-manifest.json"
        manifest = read_json(manifest_path)
        manifest["overall_status"] = overall_status
        _write_json(manifest_path, manifest)
    rehash(run_dir)
