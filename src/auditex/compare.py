from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from azure_tenant_audit.citations import build_citation_summary, dedupe_citations
from azure_tenant_audit.diffing import diff_run_directories

from .run_bundle import RunBundle


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        try:
            parsed = datetime.strptime(value, "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _run_metadata(run_dir: Path) -> dict[str, Any]:
    metadata = RunBundle(run_dir).metadata()
    metadata["_created_at"] = _parse_utc(metadata.get("created_utc"))
    return metadata


def _tenant_gate(runs: list[dict[str, Any]]) -> dict[str, Any]:
    platforms = [run.get("platform") or "m365" for run in runs]
    same_platform = len(set(platforms)) <= 1
    tenant_ids = [run.get("tenant_id") for run in runs]
    tenant_names = [run.get("tenant_name") for run in runs]
    if all(tenant_ids) and len(set(tenant_ids)) == 1:
        gate = "same_tenant" if same_platform else "same_platform_required"
        return {
            "same_tenant": True,
            "same_platform": same_platform,
            "gate": gate,
            "tenant_key": tenant_ids[0],
            "platform_key": platforms[0] if same_platform and platforms else None,
        }
    if all(tenant_names) and len(set(tenant_names)) == 1:
        gate = "same_tenant" if same_platform else "same_platform_required"
        return {
            "same_tenant": True,
            "same_platform": same_platform,
            "gate": gate,
            "tenant_key": tenant_names[0],
            "platform_key": platforms[0] if same_platform and platforms else None,
        }
    gate = "same_tenant_required" if same_platform else "same_platform_required"
    return {
        "same_tenant": False,
        "same_platform": same_platform,
        "gate": gate,
        "tenant_key": None,
        "platform_key": platforms[0] if same_platform and platforms else None,
    }


def _sort_runs(runs: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        list(runs),
        key=lambda item: (
            item.get("_created_at") is None,
            item.get("_created_at") or datetime.max.replace(tzinfo=timezone.utc),
            str(item.get("run_id") or item.get("path") or ""),
        ),
    )


def _blocked_diff(left_run: dict[str, Any], right_run: dict[str, Any], reason: str) -> dict[str, Any]:
    same_tenant = (
        bool(left_run.get("tenant_id"))
        and left_run.get("tenant_id") == right_run.get("tenant_id")
    ) or (
        bool(left_run.get("tenant_name"))
        and left_run.get("tenant_name") == right_run.get("tenant_name")
    )
    same_platform = (left_run.get("platform") or "m365") == (right_run.get("platform") or "m365")
    return {
        "left_run": _public_run(left_run),
        "right_run": _public_run(right_run),
        "status": "blocked",
        "reason": reason,
        "compare_context": {"same_tenant": same_tenant, "same_platform": same_platform, "gate": reason},
        "summary": {"added": 0, "removed": 0, "changed": 0, "object_kinds": 0},
        "changes": {},
        "compared_files": [],
        "citations": [
            {"artifact_path": "run-manifest.json", "reason": "Run identity and compare gate for blocked comparison."}
        ],
        "citation_summary": build_citation_summary(
            [{"artifact_path": "run-manifest.json", "reason": "Run identity and compare gate for blocked comparison."}]
        ),
        "evidence_missing": [],
    }


def _public_run(run: dict[str, Any]) -> dict[str, Any]:
    payload = dict(run)
    payload.pop("_created_at", None)
    return payload


def _compare_pair(
    left_run: dict[str, Any],
    right_run: dict[str, Any],
    same_tenant: bool,
    *,
    allow_cross_tenant: bool,
    classic: bool,
) -> dict[str, Any]:
    if (left_run.get("platform") or "m365") != (right_run.get("platform") or "m365"):
        return _blocked_diff(left_run, right_run, "same_platform_required")
    if not same_tenant and not allow_cross_tenant:
        return _blocked_diff(left_run, right_run, "same_tenant_required")
    diff = diff_run_directories(left_run["path"], right_run["path"], classic=classic)
    diff["left_run"] = _public_run(left_run)
    diff["right_run"] = _public_run(right_run)
    diff["status"] = "ok"
    diff["reason"] = None
    diff["compare_context"] = {
        "same_tenant": same_tenant,
        "same_platform": True,
        "gate": "same_tenant" if same_tenant else "allow_cross_tenant",
        "tenant_name": left_run.get("tenant_name"),
        "tenant_id": left_run.get("tenant_id"),
        "platform": left_run.get("platform") or "m365",
    }
    return diff


def compare_run_directories(run_dirs: Iterable[str | Path], *, allow_cross_tenant: bool = False, classic: bool = False) -> dict[str, Any]:
    runs = [_run_metadata(Path(run_dir)) for run_dir in run_dirs]
    ordered_runs = _sort_runs(runs)
    compare_context = _tenant_gate(ordered_runs)
    ordered_runs_public = [_public_run(run) for run in ordered_runs]

    timeline: list[dict[str, Any]] = []
    for position, run in enumerate(ordered_runs_public):
        timeline.append(
            {
                "position": position,
                **run,
            }
        )

    adjacent_diffs: list[dict[str, Any]] = []
    for left_run, right_run in zip(ordered_runs, ordered_runs[1:]):
        adjacent_diffs.append(
            _compare_pair(left_run, right_run, compare_context["same_tenant"], allow_cross_tenant=allow_cross_tenant, classic=classic)
        )

    if len(ordered_runs) >= 2:
        baseline_diff = _compare_pair(
            ordered_runs[0],
            ordered_runs[-1],
            compare_context["same_tenant"],
            allow_cross_tenant=allow_cross_tenant,
            classic=classic,
        )
    else:
        baseline_diff = _blocked_diff(
            ordered_runs[0] if ordered_runs else {},
            ordered_runs[0] if ordered_runs else {},
            "needs_at_least_two_runs",
        )

    citations = dedupe_citations(
        [{"artifact_path": "run-manifest.json", "reason": "Run identity and ordering for compared runs."}]
        + [
            dict(row)
            for diff in [*adjacent_diffs, baseline_diff]
            for row in diff.get("citations") or []
            if isinstance(row, dict)
        ]
    )
    evidence_missing = sorted(
        {
            str(item)
            for diff in [*adjacent_diffs, baseline_diff]
            for item in diff.get("evidence_missing") or []
            if str(item)
        }
    )

    return {
        "runs": ordered_runs_public,
        "timeline": timeline,
        "adjacent_diffs": adjacent_diffs,
        "baseline_diff": baseline_diff,
        "compare_context": compare_context,
        "classic": classic,
        "citations": citations,
        "citation_summary": build_citation_summary(citations),
        "evidence_missing": evidence_missing,
    }


def compare_runs(run_dirs: Iterable[str | Path], *, allow_cross_tenant: bool = False, classic: bool = False) -> dict[str, Any]:
    return compare_run_directories(run_dirs, allow_cross_tenant=allow_cross_tenant, classic=classic)


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _severity(row: dict[str, Any]) -> str:
    text = str(row.get("severity") or row.get("risk_rating") or "info").strip().lower()
    return text if text in _SEVERITY_ORDER else "info"


def _finding_key(row: dict[str, Any]) -> str:
    return str(row.get("id") or f"{row.get('rule_id')}:{','.join(str(item) for item in row.get('affected_objects') or [])}")


def _risk_snapshot(run: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    risk = run.get("risk") if isinstance(run.get("risk"), dict) else {}
    if risk.get("grade") is not None:
        return {"grade": risk.get("grade"), "score": risk.get("score")}
    from azure_tenant_audit.findings import build_risk_rollup

    rollup = build_risk_rollup(findings)
    return {"grade": rollup.get("grade"), "score": rollup.get("score")}


def build_finding_delta(left_run: dict[str, Any], right_run: dict[str, Any]) -> dict[str, Any]:
    """Summarise findings that are new, resolved, or changed between two runs."""
    left_rows = RunBundle(Path(str(left_run.get("path")))).finding_rows() if left_run.get("path") else []
    right_rows = RunBundle(Path(str(right_run.get("path")))).finding_rows() if right_run.get("path") else []
    left = {_finding_key(row): row for row in left_rows}
    right = {_finding_key(row): row for row in right_rows}

    def _summary(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row.get("id"),
            "rule_id": row.get("rule_id"),
            "severity": _severity(row),
            "status": row.get("status"),
            "title": row.get("title"),
        }

    new = [_summary(right[key]) for key in sorted(set(right) - set(left))]
    resolved = [_summary(left[key]) for key in sorted(set(left) - set(right))]
    changed: list[dict[str, Any]] = []
    for key in sorted(set(left) & set(right)):
        before, after = left[key], right[key]
        if _severity(before) != _severity(after) or str(before.get("status") or "") != str(after.get("status") or ""):
            changed.append(
                {
                    **_summary(after),
                    "severity_before": _severity(before),
                    "status_before": before.get("status"),
                }
            )
    return {
        "new": new,
        "resolved": resolved,
        "changed": changed,
        "risk_before": _risk_snapshot(left_run, left_rows),
        "risk_after": _risk_snapshot(right_run, right_rows),
    }


def _md(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def _severity_counts(rows: list[dict[str, Any]]) -> str:
    counts = {severity: 0 for severity in _SEVERITY_ORDER}
    for row in rows:
        counts[_severity(row)] += 1
    parts = [f"{severity} {count}" for severity, count in counts.items() if count]
    return ", ".join(parts) if parts else "none"


def _finding_table(title: str, rows: list[dict[str, Any]], *, changed: bool = False) -> list[str]:
    lines = [f"## {title} ({len(rows)})", ""]
    if not rows:
        return lines + ["None.", ""]
    ordered = sorted(rows, key=lambda row: (_SEVERITY_ORDER.index(_severity(row)), str(row.get("id") or "")))
    if changed:
        lines += ["| Severity | Was | Status | Was | Finding | Rule |", "| --- | --- | --- | --- | --- | --- |"]
        for row in ordered:
            lines.append(
                f"| {_md(row.get('severity'))} | {_md(row.get('severity_before'))} | {_md(row.get('status'))} | "
                f"{_md(row.get('status_before'))} | {_md(row.get('title') or row.get('id'))} | {_md(row.get('rule_id'))} |"
            )
    else:
        lines += ["| Severity | Finding | Rule |", "| --- | --- | --- |"]
        for row in ordered:
            lines.append(f"| {_md(row.get('severity'))} | {_md(row.get('title') or row.get('id'))} | {_md(row.get('rule_id'))} |")
    return lines + [""]


def render_compare_markdown(result: dict[str, Any]) -> str:
    """Render a readable before/after summary of the baseline (first vs last) comparison."""
    runs = [row for row in result.get("runs") or [] if isinstance(row, dict)]
    baseline = result.get("baseline_diff") if isinstance(result.get("baseline_diff"), dict) else {}
    context = result.get("compare_context") if isinstance(result.get("compare_context"), dict) else {}
    lines = ["# Auditex Run Comparison", ""]
    if len(runs) < 2:
        return "\n".join(lines + ["At least two runs are needed for a comparison.", ""])
    before, after = runs[0], runs[-1]
    lines += [
        f"- Tenant: {_md(context.get('tenant_key') or before.get('tenant_name') or before.get('tenant_id'))}",
        f"- Before: {_md(before.get('run_id') or before.get('path'))} ({_md(before.get('created_utc'))})",
        f"- After: {_md(after.get('run_id') or after.get('path'))} ({_md(after.get('created_utc'))})",
        f"- Runs compared: {len(runs)}",
    ]
    if baseline.get("status") == "blocked":
        lines += [f"- Status: blocked ({_md(baseline.get('reason'))})", ""]
        return "\n".join(lines)
    delta = build_finding_delta(before, after)
    risk_before, risk_after = delta["risk_before"], delta["risk_after"]
    grade_before, grade_after = risk_before.get("grade") or "unknown", risk_after.get("grade") or "unknown"
    risk_change = "unchanged" if grade_before == grade_after else f"{grade_before} -> {grade_after}"
    summary = baseline.get("summary") if isinstance(baseline.get("summary"), dict) else {}
    lines += [
        f"- Risk grade: {_md(grade_before)} -> {_md(grade_after)} ({_md(risk_change)}; score {_md(risk_before.get('score'))} -> {_md(risk_after.get('score'))})",
        f"- New findings: {len(delta['new'])} ({_severity_counts(delta['new'])})",
        f"- Resolved findings: {len(delta['resolved'])} ({_severity_counts(delta['resolved'])})",
        f"- Changed findings: {len(delta['changed'])} ({_severity_counts(delta['changed'])})",
        f"- Object changes: {_md(summary.get('added', 0))} added, {_md(summary.get('removed', 0))} removed, {_md(summary.get('changed', 0))} changed",
        "",
    ]
    lines += _finding_table("New findings", delta["new"])
    lines += _finding_table("Resolved findings", delta["resolved"])
    lines += _finding_table("Changed findings", delta["changed"], changed=True)
    return "\n".join(lines)
