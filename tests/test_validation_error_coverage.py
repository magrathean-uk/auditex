"""C3: validation.json error coverage.

Currently ``contracts.build_validation_report`` catches missing
artifacts, broken evidence_refs, malformed normalized records, and
unsafe ``ai_safe/`` drift. C3 adds three more failure modes that have
historically slipped through:

(a) ``duplicate_record_key`` — two records in the same normalised
    section resolve to the same key (collides in evidence DB).
(b) ``unknown_finding_collector`` — a finding's ``collector`` field
    points at something that isn't in REGISTRY (typo, removed
    collector, hand-edited bundle).
(c) ``unknown_framework_mapping_key`` /
    ``invalid_framework_mapping_value`` — a finding's
    ``framework_mappings`` references a framework key outside the
    canonical set, or a value isn't a non-empty list of strings.
"""
from __future__ import annotations

import json
from pathlib import Path

from azure_tenant_audit.contracts import build_validation_report
from azure_tenant_audit.finalize import finalize_bundle_contract

# Re-use the bundle prep from C1.
from test_finalize_idempotent import _prepare_bundle_for_finalize


def _bundle(tmp_path: Path) -> Path:
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    finalize_bundle_contract(**kwargs)
    return writer.run_dir


def _issue_codes(report: dict) -> list[str]:
    return [issue["code"] for issue in report.get("issues", [])]


# ----- (a) duplicate_record_key -----


def test_validation_flags_duplicate_record_keys_within_section(tmp_path: Path) -> None:
    run_dir = _bundle(tmp_path)

    target = None
    for path in sorted((run_dir / "normalized").glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        records = payload.get("records") or []
        if isinstance(records, list) and records and isinstance(records[0], dict):
            target = (path, payload)
            break
    assert target is not None, "normalized fixture must yield at least one section with records"

    path, payload = target
    duplicated = dict(payload["records"][0])
    payload["records"].append(duplicated)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    report = build_validation_report(run_dir=run_dir)
    assert "duplicate_record_key" in _issue_codes(report), report["issues"]
    assert report["valid"] is False


def test_validation_clean_bundle_has_no_duplicate_record_key_issue(tmp_path: Path) -> None:
    run_dir = _bundle(tmp_path)
    report = build_validation_report(run_dir=run_dir)
    assert "duplicate_record_key" not in _issue_codes(report)


# ----- (b) unknown_finding_collector -----


def _ensure_finding(run_dir: Path, mutator) -> None:  # noqa: ANN001
    findings_path = run_dir / "findings" / "findings.json"
    if not findings_path.exists():
        findings_path.parent.mkdir(parents=True, exist_ok=True)
        findings_path.write_text("[]", encoding="utf-8")
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    if not findings:
        findings = [
            {
                "id": "synthetic:1",
                "rule_id": "synthetic.rule",
                "severity": "medium",
                "title": "synthetic",
                "status": "open",
                "collector": "identity",
                "evidence_refs": [
                    {
                        "artifact_path": "summary.json",
                        "artifact_kind": "summary",
                        "collector": "identity",
                        "record_key": "k",
                    }
                ],
                "framework_mappings": {"cis_m365_v3": ["1.1"]},
            }
        ]
    mutator(findings[0])
    findings_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")


def test_validation_flags_finding_with_unknown_collector(tmp_path: Path) -> None:
    run_dir = _bundle(tmp_path)
    _ensure_finding(run_dir, lambda f: f.update({"collector": "no_such_collector_xyz"}))
    report = build_validation_report(run_dir=run_dir)
    assert "unknown_finding_collector" in _issue_codes(report), report["issues"]


def test_validation_clean_bundle_has_no_unknown_collector_issue(tmp_path: Path) -> None:
    run_dir = _bundle(tmp_path)
    report = build_validation_report(run_dir=run_dir)
    assert "unknown_finding_collector" not in _issue_codes(report)


# ----- (c) framework_mappings -----


def test_validation_flags_unknown_framework_key(tmp_path: Path) -> None:
    run_dir = _bundle(tmp_path)
    _ensure_finding(
        run_dir,
        lambda f: f.setdefault("framework_mappings", {}).update(
            {"made_up_framework_2099": ["XYZ-1"]}
        ),
    )
    report = build_validation_report(run_dir=run_dir)
    assert "unknown_framework_mapping_key" in _issue_codes(report), report["issues"]


def test_validation_flags_empty_control_id_in_mapping(tmp_path: Path) -> None:
    run_dir = _bundle(tmp_path)
    _ensure_finding(
        run_dir,
        lambda f: f.update({"framework_mappings": {"cis_m365_v3": ["", "  "]}}),
    )
    report = build_validation_report(run_dir=run_dir)
    assert "invalid_framework_mapping_value" in _issue_codes(report), report["issues"]


def test_validation_flags_non_list_framework_value(tmp_path: Path) -> None:
    run_dir = _bundle(tmp_path)
    _ensure_finding(
        run_dir,
        lambda f: f.update({"framework_mappings": {"cis_m365_v3": "not-a-list"}}),
    )
    report = build_validation_report(run_dir=run_dir)
    assert "invalid_framework_mapping_value" in _issue_codes(report), report["issues"]


def test_validation_accepts_google_workspace_baseline_mapping(tmp_path: Path) -> None:
    run_dir = _bundle(tmp_path)
    _ensure_finding(
        run_dir,
        lambda f: f.update({"framework_mappings": {"google_workspace_baseline": ["identity.2sv"]}}),
    )

    report = build_validation_report(run_dir=run_dir)

    assert "unknown_framework_mapping_key" not in _issue_codes(report), report["issues"]


def test_validation_clean_bundle_has_no_framework_mapping_issues(tmp_path: Path) -> None:
    run_dir = _bundle(tmp_path)
    report = build_validation_report(run_dir=run_dir)
    codes = _issue_codes(report)
    assert "unknown_framework_mapping_key" not in codes
    assert "invalid_framework_mapping_value" not in codes


def test_clean_bundle_validation_remains_valid(tmp_path: Path) -> None:
    """C3 additions must not regress the clean-bundle case."""
    run_dir = _bundle(tmp_path)
    report = build_validation_report(run_dir=run_dir)
    assert report["valid"] is True, report["issues"]
