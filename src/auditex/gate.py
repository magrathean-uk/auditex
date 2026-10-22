"""Fail-closed CI gates over finished run bundles.

``auditex gate`` and ``auditex gate-drift`` decide whether a pipeline may
continue, so a missing, empty, unreadable or invalid input must never read as
"nothing found". Each run has to prove four things before its findings count:

* a readable ``run-manifest.json``;
* a contract that is valid as recorded *and* when its structural validation is recomputed
  now;
* a hash manifest (``bundle-hashes.json``) that still matches every artifact, so a bundle edited
  after finalization is blocked. The manifest is unsigned: it stops accidental and naive edits, not
  someone who can rewrite the bundle and re-hash it, and it is not a statement about who wrote the run;
* a readable findings list that agrees with the report pack on every finding's id, status, severity
  and rule;
* collectors that completed (``--allow-partial`` accepts known gaps, but a run
  with no completed collector is never accepted).

A finding counts as accepted (or closed) only when a matching waiver stands behind that status; the
engine never writes one without it, so a bare ``accepted_risk`` or ``closed`` counts as open.

Anything else returns ``status: "blocked"`` with a machine-readable ``code``
and a human ``reason``. The CLI turns a blocked or failed result into a
non-zero exit code. Nothing here reads message bodies or file content, and
nothing writes to a run or a tenant.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from azure_tenant_audit.bundle_integrity import BUNDLE_HASHES_SCHEMA_VERSION, integrity_failed
from azure_tenant_audit.rule_parameters import changed_rule_parameters, recorded_rule_parameters
from azure_tenant_audit.waivers import accepted_risk_summary, has_matching_waiver, is_accepted_status

from .compare import NormalizedSections, reassessment_gap, require_same_tenant_runs
from .run_bundle import RunBundle

SEVERITY_RANKS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_CLOSED_STATUSES = frozenset({"resolved", "closed"})
# A collector that was skipped as not applicable produced no evidence, but it was never expected to.
_NEUTRAL_COVERAGE = frozenset({"not_applicable"})
_ISSUE_CODE_LIMIT = 10


class GateInputError(Exception):
    """A run input is missing, empty, unreadable or invalid; the gate must fail closed."""

    def __init__(self, code: str, reason: str, **extra: Any) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason
        self.extra = extra


def _threshold(fail_on: str) -> tuple[str, int]:
    threshold = fail_on.strip().lower()
    if threshold not in SEVERITY_RANKS:
        raise ValueError(f"unsupported --fail-on severity: {fail_on}")
    return threshold, SEVERITY_RANKS[threshold]


def _blocked(error: GateInputError, **context: Any) -> dict[str, Any]:
    return {
        "pass": False,
        "status": "blocked",
        "code": error.code,
        "reason": error.reason,
        **context,
        **error.extra,
    }


def _severity(row: Mapping[str, Any]) -> str:
    return str(row.get("severity") or "medium").lower()


def _claimed_class(row: Mapping[str, Any]) -> str:
    """The class a finding's status claims: ``accepted``, ``closed`` or ``open`` (anything unrecognised)."""
    status = str(row.get("status") or "open").strip().lower()
    if is_accepted_status(status):
        return "accepted"
    if status in _CLOSED_STATUSES:
        return "closed"
    return "open"


def _status_class(row: Mapping[str, Any]) -> str:
    """``accepted``, ``closed`` or ``open``. Anything unrecognised stays open (fail closed).

    An accepted or closed status counts only when a matching waiver stands behind it. The engine writes
    ``accepted_risk`` only together with the waiver it matched and never writes ``closed`` or ``resolved``,
    so a status without a waiver is an edit and the finding stays open.
    """
    claimed = _claimed_class(row)
    if claimed != "open" and not has_matching_waiver(row):
        return "open"
    return claimed


def _unbacked_status_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Findings that claim an accepted or closed status with no matching waiver (counted as open)."""
    return [row for row in rows if _claimed_class(row) != "open" and _status_class(row) == "open"]


def _unbacked_status_warning(label: str, rows: list[dict[str, Any]]) -> str | None:
    unbacked = _unbacked_status_rows(rows)
    if not unbacked:
        return None
    ids = ", ".join(str(row.get("id")) for row in unbacked[:5])
    more = f" and {len(unbacked) - 5} more" if len(unbacked) > 5 else ""
    return (
        f"{label}: {len(unbacked)} finding(s) claim an accepted or closed status without a matching waiver "
        f"and are counted as open ({ids}{more})"
    )


def _brief(row: Mapping[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "rule_id": row.get("rule_id"),
        "severity": _severity(row),
        "title": row.get("title"),
        "collector": row.get("collector"),
        **extra,
    }


def _summary_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if key in {"severity", "title", "rule_id", "collector"}}


def _open_run(run_dir: str | Path, label: str) -> RunBundle:
    """Structure only: the directory and a non-empty, parseable manifest must exist."""
    root = Path(run_dir)
    if not root.is_dir():
        raise GateInputError("run_dir_missing", f"{label} directory not found: {run_dir}")
    manifest_path = root / "run-manifest.json"
    if not manifest_path.is_file():
        raise GateInputError("missing_manifest", f"{label} has no run-manifest.json: {run_dir}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GateInputError("unreadable_manifest", f"{label} run-manifest.json is unreadable: {exc}") from exc
    if not isinstance(manifest, dict) or not manifest:
        raise GateInputError("unreadable_manifest", f"{label} run-manifest.json is empty or not a JSON object")
    return RunBundle(root)


def _read_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _verify_contract(bundle: RunBundle, label: str) -> dict[str, Any]:
    """Require a valid recorded contract and recompute the structural validation now.

    The recompute catches missing or malformed artifacts, broken evidence references and unknown
    collectors. It is not an integrity check: nothing here proves the bundle is unmodified, because
    a bundle can be edited and stay structurally valid.
    """
    from azure_tenant_audit.contracts import build_validation_report

    root = bundle.run_dir
    manifest = bundle.manifest()
    try:
        recorded = _read_json_file(root / "validation.json")
    except (OSError, ValueError) as exc:
        raise GateInputError("contract_invalid", f"{label} validation.json is missing or unreadable: {exc}") from exc
    recorded_valid = isinstance(recorded, Mapping) and recorded.get("valid") is True
    if manifest.get("contract_status") != "valid" or not recorded_valid:
        raise GateInputError(
            "contract_invalid",
            f"{label} does not record a valid contract; the manifest contract_status is "
            f"{manifest.get('contract_status')!r} and validation.json is "
            f"{'valid' if recorded_valid else 'not valid'}",
        )
    try:
        report = build_validation_report(run_dir=root, read_only=True)
    except Exception as exc:  # noqa: BLE001 - any failure to validate means the evidence cannot be trusted
        raise GateInputError(
            "contract_invalid", f"{label} contract could not be recomputed: {type(exc).__name__}: {exc}"
        ) from exc
    errors = [issue for issue in report.get("issues") or [] if isinstance(issue, Mapping) and issue.get("severity") == "error"]
    legacy_refs = sum(1 for issue in errors if issue.get("code") == "legacy_unresolved_ref")
    summary = {
        "valid": bool(report.get("valid")),
        "contract_version": report.get("contract_version"),
        "error_count": len(errors),
        "warning_count": int(report.get("warning_count") or 0),
    }
    if not summary["valid"]:
        codes = sorted({str(issue.get("code")) for issue in errors})[:_ISSUE_CODE_LIMIT]
        # The gate fails closed either way. A legacy citation is named so that it reads as what it is:
        # a bundle written before references had to resolve, not one that was edited.
        legacy_note = (
            f"; {legacy_refs} legacy_unresolved_ref (citations written before references had to resolve, "
            "not evidence of editing)"
            if legacy_refs
            else ""
        )
        raise GateInputError(
            "contract_invalid",
            f"{label} fails contract validation when recomputed "
            f"({summary['error_count']} errors: {', '.join(codes)}{legacy_note})",
            contract={
                **summary,
                "issue_codes": codes,
                "legacy_unresolved_ref_count": legacy_refs,
                "only_legacy_unresolved_refs": legacy_refs == len(errors),
            },
        )
    return summary


def _verify_integrity(bundle: RunBundle, label: str) -> tuple[dict[str, Any], list[str]]:
    """Require the hash manifest to match every artifact; return its summary and any warnings.

    ``mismatch`` and ``invalid`` block. ``absent`` blocks for a bundle finalized under the contract that
    writes the manifest (a bundle that lost it, or never listed it, is not trustworthy) and is a warning
    for an older bundle that predates it. Files added after finalization are listed as a warning. The
    manifest is unsigned: this stops accidental and naive edits, not a deliberate re-hash.
    """
    integrity = bundle.integrity()
    status = str(integrity.get("status"))
    summary = {
        "status": status,
        "checked_count": integrity.get("checked_count", 0),
        "unlisted_count": integrity.get("unlisted_count", 0),
        "manifest_sha256": integrity.get("manifest_sha256"),
    }
    if integrity_failed(integrity):
        problem = integrity.get("message") or (
            f"{integrity.get('modified_count', 0)} modified and {integrity.get('missing_count', 0)} missing "
            "artifact(s) since finalization"
        )
        raise GateInputError(
            f"bundle_integrity_{status}",
            f"{label} does not match its hash manifest ({problem})",
            integrity={
                **summary,
                "modified": [row.get("path") for row in integrity.get("modified") or []][:_ISSUE_CODE_LIMIT],
                "missing": list(integrity.get("missing") or [])[:_ISSUE_CODE_LIMIT],
            },
        )
    warnings: list[str] = []
    if status == "absent":
        version = bundle.manifest().get("schema_contract_version")
        if isinstance(version, str) and version >= BUNDLE_HASHES_SCHEMA_VERSION:
            raise GateInputError(
                "bundle_integrity_absent",
                f"{label} was finalized under contract {version} but has no bundle-hashes.json",
                integrity=summary,
            )
        warnings.append(f"{label} predates the hash manifest, so its artifacts could not be checked for edits")
    if summary["unlisted_count"]:
        warnings.append(
            f"{label} holds {summary['unlisted_count']} file(s) added after finalization that the hash manifest does not list"
        )
    return summary, warnings


def _finding_ids(rows: list[dict[str, Any]]) -> set[str]:
    return {str(row.get("id")) for row in rows}


# What the findings file and the report pack must agree on for a finding: the gate counts the pack's rows.
_FINDING_COMPARED_FIELDS = ("status", "severity", "rule_id")


def _disagreeing_findings(file_rows: list[dict[str, Any]], pack_rows: list[dict[str, Any]]) -> list[str]:
    by_id = {str(row.get("id")): row for row in pack_rows}
    differing: list[str] = []
    for row in file_rows:
        other = by_id.get(str(row.get("id")))
        if other is None:
            continue
        if any(str(row.get(field) or "").strip().lower() != str(other.get(field) or "").strip().lower() for field in _FINDING_COMPARED_FIELDS):
            differing.append(str(row.get("id")))
    return sorted(differing)


def _verify_findings(bundle: RunBundle, label: str) -> list[dict[str, Any]]:
    """Return the run's findings after checking the findings file and report pack agree.

    A run with no findings at all legitimately has no ``findings/findings.json``; any
    other missing, empty, unreadable or disagreeing findings input is an error.
    """
    root = bundle.run_dir
    manifest = bundle.manifest()
    declared = manifest.get("findings_path")
    relative = str(declared or "findings/findings.json")
    path = root / relative
    if not path.is_file() and (root / "findings/findings.json").is_file():
        path = root / "findings/findings.json"
    try:
        inside = path.resolve().is_relative_to(root.resolve())
    except OSError:
        inside = False
    if not inside:
        raise GateInputError("unreadable_findings", f"{label} findings path escapes the run directory: {relative}")

    file_rows: list[dict[str, Any]] | None = None
    if path.is_file():
        try:
            payload = _read_json_file(path)
        except (OSError, ValueError) as exc:
            raise GateInputError("unreadable_findings", f"{label} {relative} is empty or unreadable: {exc}") from exc
        if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
            raise GateInputError("unreadable_findings", f"{label} {relative} must be a JSON list of finding objects")
        file_rows = payload
    elif declared:
        raise GateInputError("missing_findings", f"{label} manifest declares {relative} but the file is missing")

    pack_path, pack = bundle.report_pack()
    pack_rows = pack.get("findings") if isinstance(pack, Mapping) else None
    if pack_path is None or not isinstance(pack_rows, list) or any(not isinstance(item, dict) for item in pack_rows):
        raise GateInputError("unreadable_findings", f"{label} reports/report-pack.json has no readable findings list")

    for source, rows in (("report pack", pack_rows), (relative, file_rows or [])):
        if any(not str(row.get("id") or "").strip() for row in rows):
            raise GateInputError("unreadable_findings", f"{label} {source} contains a finding without an id")
    if file_rows is None:
        if pack_rows:
            raise GateInputError(
                "missing_findings",
                f"{label} report pack lists {len(pack_rows)} findings but {relative} is missing",
            )
        if manifest.get("findings_count"):
            raise GateInputError(
                "missing_findings",
                f"{label} manifest records {manifest.get('findings_count')} findings but {relative} is missing",
            )
        return []
    count = manifest.get("findings_count")
    if (isinstance(count, int) and count != len(file_rows)) or _finding_ids(file_rows) != _finding_ids(pack_rows):
        raise GateInputError(
            "findings_inconsistent",
            f"{label} {relative} ({len(file_rows)} findings) disagrees with the manifest or the report pack "
            f"({len(pack_rows)} findings)",
        )
    differing = _disagreeing_findings(file_rows, pack_rows)
    if differing:
        raise GateInputError(
            "findings_inconsistent",
            f"{label} {relative} and the report pack disagree on the status, severity or rule of "
            f"{len(differing)} finding(s): {', '.join(differing[:5])}",
            disagreeing_findings=differing[:_ISSUE_CODE_LIMIT],
        )
    return bundle.finding_rows()


def _assess_coverage(bundle: RunBundle) -> dict[str, Any]:
    coverage = bundle.collector_coverage()
    overall = str(bundle.manifest().get("overall_status") or "unknown")
    completed = sorted(name for name, row in coverage.items() if row["complete"])
    incomplete = [
        {"collector": name, "status": row["status"]}
        for name, row in sorted(coverage.items())
        if not row["complete"] and row["status"] not in _NEUTRAL_COVERAGE
    ]
    return {
        "overall_status": overall,
        "complete": overall == "ok" and not incomplete,
        "completed_collectors": completed,
        "incomplete_collectors": incomplete,
        "not_applicable_collectors": sorted(
            name for name, row in coverage.items() if row["status"] in _NEUTRAL_COVERAGE
        ),
    }


def _describe_incomplete(coverage: Mapping[str, Any]) -> str:
    parts = [f"overall_status={coverage['overall_status']}"]
    parts.extend(f"{row['collector']}={row['status']}" for row in coverage["incomplete_collectors"])
    return ", ".join(parts)


def _require_coverage(coverage: dict[str, Any], label: str, *, allow_partial: bool) -> list[str]:
    """Raise unless the run's collectors completed; return warnings for accepted gaps."""
    if not coverage["completed_collectors"]:
        raise GateInputError(
            "no_completed_collectors",
            f"{label} has no completed collector, so its findings are not evidence of anything",
            coverage=coverage,
        )
    if coverage["complete"]:
        return []
    detail = _describe_incomplete(coverage)
    if not allow_partial:
        raise GateInputError(
            "incomplete_coverage",
            f"{label} did not complete every collector ({detail}); fix the gaps or pass --allow-partial",
            coverage=coverage,
        )
    return [f"{label} is partial and was accepted by --allow-partial ({detail})"]


def _verified_run(
    run_dir: str | Path, label: str, *, bundle: RunBundle | None = None
) -> tuple[RunBundle, dict[str, Any], list[dict[str, Any]], dict[str, Any], list[str]]:
    """Contract, hash manifest, findings and coverage for one run, raising ``GateInputError`` on the first problem.

    The contract carries the recomputed validation and, under ``integrity``, the hash manifest check. The
    last element is the warnings the checks accept (a legacy bundle without a manifest, files added later).
    """
    bundle = bundle or _open_run(run_dir, label)
    contract = _verify_contract(bundle, label)
    integrity, warnings = _verify_integrity(bundle, label)
    rows = _verify_findings(bundle, label)
    return bundle, {**contract, "integrity": integrity}, rows, _assess_coverage(bundle), warnings


def gate_findings(*, run_dir: str, fail_on: str, allow_partial: bool = False) -> dict[str, object]:
    threshold, threshold_rank = _threshold(fail_on)
    context = {"fail_on": threshold, "run_dir": str(run_dir)}
    try:
        bundle, contract, rows, coverage, run_warnings = _verified_run(run_dir, "run")
        warnings = [*run_warnings, *_require_coverage(coverage, "run", allow_partial=allow_partial)]
    except GateInputError as error:
        return _blocked(error, **context)
    status_warning = _unbacked_status_warning("run", rows)
    if status_warning:
        warnings.append(status_warning)

    counts_by_severity = {key: 0 for key in SEVERITY_RANKS}
    accepted_by_severity = {key: 0 for key in SEVERITY_RANKS}
    triggered: list[dict[str, object]] = []
    closed_count = 0
    accepted_count = 0
    for row in rows:
        state = _status_class(row)
        severity = _severity(row)
        if state == "closed":
            closed_count += 1
            continue
        if state == "accepted":
            accepted_count += 1
            if severity in accepted_by_severity:
                accepted_by_severity[severity] += 1
            continue
        if severity in counts_by_severity:
            counts_by_severity[severity] += 1
        if SEVERITY_RANKS.get(severity, 0) >= threshold_rank:
            triggered.append(_brief(row, reason="open"))

    accepted_summary = accepted_risk_summary(rows)
    stale_accepted = [
        _brief(row, reason="stale_accepted_risk", expires_on=row.get("expires_on"))
        for row in accepted_summary["stale"]
        if SEVERITY_RANKS.get(_severity(row), 0) >= threshold_rank
    ]
    triggered.extend(stale_accepted)
    warnings.extend(accepted_summary["warnings"])
    return {
        "pass": not triggered,
        "status": "pass" if not triggered else "fail",
        **context,
        "counts_by_severity": counts_by_severity,
        "counts_at_or_above_threshold": len(triggered),
        "threshold_findings": triggered,
        "accepted_count": accepted_count,
        "accepted_by_severity": accepted_by_severity,
        "stale_accepted_risk_count_at_or_above_threshold": len(stale_accepted),
        "closed_count": closed_count,
        "unbacked_status_count": len(_unbacked_status_rows(rows)),
        "accepted_risk_summary": accepted_summary,
        "contract": contract,
        # The windows the run's rules were judged with, so a later run with a laxer one is visible.
        "rule_parameters": recorded_rule_parameters(bundle.manifest()),
        "coverage": coverage,
        "warnings": warnings,
    }


def _index(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = str(row.get("id") or row.get("rule_id") or "")
        if key:
            index[key] = row
    return index


def gate_drift(
    *, baseline_run_dir: str, current_run_dir: str, fail_on: str, allow_partial: bool = False
) -> dict[str, object]:
    threshold, threshold_rank = _threshold(fail_on)
    context = {"fail_on": threshold, "baseline_run_dir": str(baseline_run_dir), "current_run_dir": str(current_run_dir)}
    try:
        baseline_bundle = _open_run(baseline_run_dir, "baseline run")
        current_bundle = _open_run(current_run_dir, "current run")
    except GateInputError as error:
        return _blocked(error, **context)
    try:
        tenant_context = require_same_tenant_runs([baseline_run_dir, current_run_dir])
    except ValueError as exc:
        return {"pass": False, "status": "blocked", "code": "tenant_guard", "reason": str(exc)}
    try:
        _, baseline_contract, baseline_rows, baseline_coverage, baseline_warnings = _verified_run(
            baseline_run_dir, "baseline run", bundle=baseline_bundle
        )
        _, current_contract, current_rows, current_coverage, current_warnings = _verified_run(
            current_run_dir, "current run", bundle=current_bundle
        )
        warnings = [
            *baseline_warnings,
            *current_warnings,
            *_require_coverage(current_coverage, "current run", allow_partial=allow_partial),
        ]
        for label, rows in (("baseline run", baseline_rows), ("current run", current_rows)):
            status_warning = _unbacked_status_warning(label, rows)
            if status_warning:
                warnings.append(status_warning)
        baseline_done = set(baseline_coverage["completed_collectors"])
        current_done = set(current_coverage["completed_collectors"])
        parity = {
            "baseline_completed": sorted(baseline_done),
            "current_completed": sorted(current_done),
            "lost": sorted(baseline_done - current_done),
            "gained": sorted(current_done - baseline_done),
        }
        if parity["lost"]:
            message = f"current run completed fewer collectors than the baseline (lost: {', '.join(parity['lost'])})"
            if not allow_partial:
                raise GateInputError(
                    "collector_parity_lost", f"{message}; rerun with the same scope or pass --allow-partial",
                    collector_parity=parity,
                )
            warnings.append(f"{message}; accepted by --allow-partial")
    except GateInputError as error:
        return _blocked(error, **context)

    current_collectors = current_bundle.collector_coverage()
    current_sections = NormalizedSections(current_bundle)
    # The windows each run's rules were judged with. A vanished finding is only resolved when the later
    # run used the same or a stricter window; a laxer window (or one nobody recorded) hides the same object.
    parameters = (recorded_rule_parameters(baseline_bundle.manifest()), recorded_rule_parameters(current_bundle.manifest()))
    parameter_changes = changed_rule_parameters(*parameters)
    if parameter_changes:
        warnings.append(
            "rule parameters differ between the runs ("
            + ", ".join(f"{row['parameter']} {row['baseline']} -> {row['current']}" for row in parameter_changes)
            + "); findings that vanished under a larger window are not resolved"
        )
    baseline_index = _index(baseline_rows)
    current_index = _index(current_rows)

    new_keys = [key for key in current_index if key not in baseline_index]
    persisting_keys = [key for key in current_index if key in baseline_index]
    resolved_keys: list[str] = []
    not_reassessed: list[dict[str, object]] = []
    for key in baseline_index:
        if key in current_index:
            continue
        reason = reassessment_gap(baseline_index[key], current_collectors, current_sections, parameters=parameters)
        if reason is None:
            resolved_keys.append(key)
        else:
            not_reassessed.append({"id": key, **_summary_fields(baseline_index[key]), "reason": reason})

    new_above_threshold: list[dict[str, object]] = []
    new_accepted: list[dict[str, object]] = []
    reactivated_above_threshold: list[dict[str, object]] = []
    state_transitions: list[dict[str, object]] = []
    for key in new_keys:
        row = current_index[key]
        if _status_class(row) != "open":
            new_accepted.append(_brief(row, status=str(row.get("status") or "").lower()))
        elif SEVERITY_RANKS.get(_severity(row), 0) >= threshold_rank:
            new_above_threshold.append(_brief(row))

    for key in persisting_keys:
        baseline_row = baseline_index[key]
        current_row = current_index[key]
        from_status = str(baseline_row.get("status") or "open").lower()
        to_status = str(current_row.get("status") or "open").lower()
        if from_status != to_status:
            state_transitions.append(
                {
                    "id": current_row.get("id") or baseline_row.get("id") or key,
                    "rule_id": current_row.get("rule_id") or baseline_row.get("rule_id"),
                    "severity": str(current_row.get("severity") or baseline_row.get("severity") or "medium").lower(),
                    "title": current_row.get("title") or baseline_row.get("title"),
                    "collector": current_row.get("collector") or baseline_row.get("collector"),
                    "from_status": from_status,
                    "to_status": to_status,
                }
            )
        if _status_class(baseline_row) == "accepted" and _status_class(current_row) != "accepted":
            if SEVERITY_RANKS.get(_severity(current_row), 0) >= threshold_rank:
                reactivated_above_threshold.append(
                    {
                        **_brief(current_row),
                        "id": current_row.get("id") or key,
                        "from_status": from_status,
                        "to_status": to_status,
                    }
                )

    accepted_summary = accepted_risk_summary(current_rows)
    warnings.extend(accepted_summary["warnings"])
    stale_accepted_above_threshold = [
        {
            **_brief(row),
            "expires_on": row.get("expires_on"),
            "days_until_expiry": row.get("days_until_expiry"),
        }
        for row in accepted_summary["stale"]
        if SEVERITY_RANKS.get(_severity(row), 0) >= threshold_rank
    ]

    passed = not (new_above_threshold or reactivated_above_threshold or stale_accepted_above_threshold)
    return {
        "pass": passed,
        "status": "pass" if passed else "fail",
        "fail_on": threshold,
        "baseline_run_dir": str(baseline_run_dir),
        "current_run_dir": str(current_run_dir),
        "compare_context": tenant_context,
        "contract": {"baseline": baseline_contract, "current": current_contract},
        "coverage": {"baseline": baseline_coverage, "current": current_coverage},
        "rule_parameters": {
            "baseline": parameters[0],
            "current": parameters[1],
            "changed": parameter_changes,
        },
        "collector_parity": parity,
        "new": [{"id": key, **_summary_fields(current_index[key])} for key in new_keys],
        "resolved": [{"id": key, **_summary_fields(baseline_index[key])} for key in resolved_keys],
        "not_reassessed": not_reassessed,
        "persisting": [{"id": key} for key in persisting_keys],
        "state_transitions": state_transitions,
        "accepted_risk_summary": accepted_summary,
        "new_count": len(new_keys),
        "resolved_count": len(resolved_keys),
        "not_reassessed_count": len(not_reassessed),
        "persisting_count": len(persisting_keys),
        "new_accepted_count": len(new_accepted),
        "new_accepted": new_accepted,
        "new_count_at_or_above_threshold": len(new_above_threshold),
        "new_at_or_above_threshold": new_above_threshold,
        "reactivated_count_at_or_above_threshold": len(reactivated_above_threshold),
        "reactivated_at_or_above_threshold": reactivated_above_threshold,
        "stale_accepted_risk_count_at_or_above_threshold": len(stale_accepted_above_threshold),
        "stale_accepted_risks_at_or_above_threshold": stale_accepted_above_threshold,
        "warnings": warnings,
    }
