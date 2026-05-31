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
