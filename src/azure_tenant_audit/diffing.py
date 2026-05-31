from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any

from .citations import build_citation_summary, dedupe_citations
from .waivers import accepted_risk_summary, is_accepted_status


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_findings(run_dir: Path) -> list[dict[str, Any]]:
    pack = _load_json(run_dir / "reports" / "report-pack.json")
    rows = pack.get("findings") if isinstance(pack, dict) else []
    if not isinstance(rows, list):
        rows = []
    return [dict(item) for item in rows if isinstance(item, dict)]


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_VOLATILE_FIELD_NAMES = frozenset(
    {
        "last_sync",
        "last_seen",
        "last_seen_at",
        "last_login_time",
        "last_sign_in",
        "last_sign_in_date_time",
        "approximatelastsignindatetime",
        "created_at",
        "created_utc",
        "created_time",
        "createddatetime",
        "modified_at",
        "modified_time",
        "updated_at",
        "updated_time",
        "lastmodifieddatetime",
        "timestamp",
        "ts_utc",
    }
)
_KIND_VOLATILE_PATHS = {
    "usage_report_objects": frozenset({"report_refresh_date"}),
    "copilot_usage_objects": frozenset({"created"}),
}


def _finding_key(finding: dict[str, Any]) -> str:
    if finding.get("id"):
        return str(finding["id"])
    affected = finding.get("affected_objects")
    affected_key = ",".join(str(item) for item in affected) if isinstance(affected, list) else ""
    return f"{finding.get('rule_id') or finding.get('title') or 'finding'}:{affected_key}"


def _finding_index(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {_finding_key(item): item for item in rows}


def _field_name_from_path(path: str) -> str:
    name = path.split(".")[-1] if path else ""
    bracket = name.split("[", 1)[0]
    return bracket.strip().lower()


def _is_volatile_path(path: str, *, kind: str | None = None) -> bool:
    normalized_path = path.strip().lower()
    if kind:
        kind_paths = _KIND_VOLATILE_PATHS.get(kind)
        if kind_paths and normalized_path in kind_paths:
            return True
    field_name = _field_name_from_path(path)
    return (
        field_name in _VOLATILE_FIELD_NAMES
        or field_name.endswith("_at")
        or field_name.endswith("_utc")
        or "timestamp" in field_name
        or field_name.endswith("datetime")
    )


def _collect_changed_paths(before: Any, after: Any, *, prefix: str = "") -> list[str]:
    if isinstance(before, dict) and isinstance(after, dict):
        paths: list[str] = []
        for key in sorted(set(before) | set(after)):
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            if key not in before or key not in after:
                paths.append(child_prefix)
                continue
            paths.extend(_collect_changed_paths(before.get(key), after.get(key), prefix=child_prefix))
        return paths
    if isinstance(before, list) and isinstance(after, list):
        if len(before) != len(after):
            return [prefix or "list"]
        paths: list[str] = []
        for index, (left_item, right_item) in enumerate(zip(before, after)):
            child_prefix = f"{prefix}[{index}]" if prefix else f"[{index}]"
            paths.extend(_collect_changed_paths(left_item, right_item, prefix=child_prefix))
        return paths
    if before != after:
        return [prefix or "value"]
    return []


def _posture_drift_summary(left: Path, right: Path) -> dict[str, Any]:
    before = _finding_index(_load_findings(left))
    after = _finding_index(_load_findings(right))
    new_keys = sorted(set(after) - set(before))
    resolved_keys = sorted(set(before) - set(after))
    worsened: list[str] = []
    improved: list[str] = []
    state_transitions: list[dict[str, Any]] = []
    reactivated_accepted_risks: list[dict[str, Any]] = []
    for key in sorted(set(before) & set(after)):
        before_rank = _SEVERITY_RANK.get(str(before[key].get("severity") or ""), -1)
        after_rank = _SEVERITY_RANK.get(str(after[key].get("severity") or ""), -1)
        if after_rank > before_rank:
            worsened.append(key)
        elif after_rank < before_rank:
            improved.append(key)
        from_status = str(before[key].get("status") or "open").lower()
        to_status = str(after[key].get("status") or "open").lower()
        if from_status != to_status:
            state_transitions.append(
                {
                    "id": after[key].get("id") or before[key].get("id") or key,
                    "rule_id": after[key].get("rule_id") or before[key].get("rule_id"),
                    "severity": str(after[key].get("severity") or before[key].get("severity") or "medium").lower(),
                    "title": after[key].get("title") or before[key].get("title"),
                    "collector": after[key].get("collector") or before[key].get("collector"),
                    "from_status": from_status,
                    "to_status": to_status,
                }
            )
        if is_accepted_status(from_status) and not is_accepted_status(to_status):
            reactivated_accepted_risks.append(
                {
                    "id": after[key].get("id") or before[key].get("id") or key,
                    "rule_id": after[key].get("rule_id") or before[key].get("rule_id"),
                    "severity": str(after[key].get("severity") or before[key].get("severity") or "medium").lower(),
                    "title": after[key].get("title") or before[key].get("title"),
                    "collector": after[key].get("collector") or before[key].get("collector"),
                    "from_status": from_status,
                    "to_status": to_status,
                }
            )
    accepted_summary = accepted_risk_summary(list(after.values()))
    return {
        "new_findings": new_keys,
        "resolved_findings": resolved_keys,
        "worsened_findings": worsened,
        "improved_findings": improved,
        "state_transitions": state_transitions,
        "reactivated_accepted_risks": reactivated_accepted_risks,
        "accepted_risk_summary": accepted_summary,
        "stale_accepted_risks": [dict(row) for row in accepted_summary.get("stale") or [] if isinstance(row, dict)],
        "new_count": len(new_keys),
        "resolved_count": len(resolved_keys),
        "worsened_count": len(worsened),
        "improved_count": len(improved),
        "state_transition_count": len(state_transitions),
        "reactivated_accepted_risk_count": len(reactivated_accepted_risks),
        "stale_accepted_risk_count": int(accepted_summary.get("stale_count") or 0),
        "notification_recommended": bool(
            new_keys
            or worsened
            or reactivated_accepted_risks
            or int(accepted_summary.get("stale_count") or 0) > 0
        ),
    }


def _filter_changed_rows(
    kind: str,
    shared_keys: list[str],
    before_index: dict[str, dict[str, Any]],
    after_index: dict[str, dict[str, Any]],
    *,
    classic: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    changed: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for key in shared_keys:
        before = before_index[key]
        after = after_index[key]
        if before == after:
            continue
        changed_paths = _collect_changed_paths(before, after)
        if not classic and changed_paths and all(_is_volatile_path(path, kind=kind) for path in changed_paths):
            suppressed.append(
                {
                    "key": key,
                    "before": before,
                    "after": after,
                    "reason": "volatile_fields_only",
                    "changed_paths": changed_paths,
                    "kind": kind,
                }
            )
            continue
        changed.append({"key": key, "before": before, "after": after})
    return changed, suppressed


def _load_records(path: Path) -> tuple[str, list[dict[str, Any]]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    kind = str(payload.get("kind") or path.stem)
    records = payload.get("records", [])
    if not isinstance(records, list):
        records = []
    return kind, [item for item in records if isinstance(item, dict)]


def _record_key(record: dict[str, Any], kind: str) -> str:
    return str(record.get("key") or f"{kind}:{record.get('id') or record.get('display_name') or 'unknown'}")


def _records_for_run(run_dir: Path) -> tuple[dict[str, str], dict[str, list[dict[str, Any]]]]:
    normalized_dir = run_dir / "normalized"
    if not normalized_dir.exists():
        return {}, {}

    files: dict[str, str] = {}
    records_by_kind: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(normalized_dir.glob("*.json")):
        kind, records = _load_records(path)
        if not records:
            continue
        files[kind] = path.name
        records_by_kind[kind] = records
    return files, records_by_kind


def _run_metadata(run_dir: Path) -> dict[str, Any]:
    manifest = _load_json(run_dir / "run-manifest.json")
    snapshot = _load_json(run_dir / "normalized" / "snapshot.json")
    snapshot_meta = snapshot if isinstance(snapshot, dict) else {}
    platform = manifest.get("platform") or snapshot_meta.get("platform") or "m365"
    return {
        "path": str(run_dir),
        "platform": platform,
        "tenant_name": manifest.get("tenant_name") or snapshot_meta.get("tenant_name"),
        "tenant_id": manifest.get("tenant_id") or snapshot_meta.get("tenant_id"),
        "run_id": manifest.get("run_id") or snapshot_meta.get("run_id"),
        "created_utc": manifest.get("created_utc"),
        "overall_status": manifest.get("overall_status"),
        "auditor_profile": manifest.get("auditor_profile"),
    }


def _diff_citations(
    *,
    left: Path,
    right: Path,
    compared_files: list[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    missing: list[str] = []

    left_manifest = left / "run-manifest.json"
    right_manifest = right / "run-manifest.json"
    if left_manifest.exists() or right_manifest.exists():
        rows.append({"artifact_path": "run-manifest.json", "reason": "Run identity and compare gate for both compared runs."})
    else:
        missing.append("run-manifest.json")

    if compared_files:
        rows.extend(
            {"artifact_path": f"normalized/{path}", "reason": "Normalized records compared across both runs."}
            for path in compared_files
        )
    else:
        missing.append("normalized/*.json")

    return dedupe_citations(rows), sorted(set(missing))


def diff_run_directories(run_a: str | Path, run_b: str | Path, *, classic: bool = False) -> dict[str, Any]:
    left = Path(run_a)
    right = Path(run_b)
    left_files, left_records = _records_for_run(left)
    right_files, right_records = _records_for_run(right)
    left_info = _run_metadata(left)
    right_info = _run_metadata(right)
    same_tenant = (
        (
            bool(left_info.get("tenant_id"))
            and left_info.get("tenant_id") == right_info.get("tenant_id")
        )
        or (
            bool(left_info.get("tenant_name"))
            and left_info.get("tenant_name") == right_info.get("tenant_name")
        )
    )
    same_platform = str(left_info.get("platform") or "m365") == str(right_info.get("platform") or "m365")

    if not same_platform:
        citations, evidence_missing = _diff_citations(left=left, right=right, compared_files=[])
        return {
            "run_a": str(left),
            "run_b": str(right),
            "run_a_info": left_info,
            "run_b_info": right_info,
            "status": "blocked",
            "reason": "same_platform_required",
            "compare_context": {
                "same_tenant": same_tenant,
                "same_platform": False,
                "gate": "same_platform_required",
            },
            "compared_files": [],
            "summary": {"added": 0, "removed": 0, "changed": 0, "object_kinds": 0},
            "changes": {},
            "citations": citations,
            "citation_summary": build_citation_summary(citations),
            "evidence_missing": evidence_missing,
        }

    compared_files = sorted(set(left_files.values()) | set(right_files.values()))
    changes: dict[str, dict[str, list[dict[str, Any]]]] = {}
    total_added = 0
    total_removed = 0
    total_changed = 0
    raw_total_changed = 0
    suppressed_total_changed = 0
    suppressed_changes: dict[str, list[dict[str, Any]]] = {}
    suppressed_reason_counts: Counter[str] = Counter()
    suppressed_path_counts: Counter[str] = Counter()

    for kind in sorted(set(left_records) | set(right_records)):
        before_index = {_record_key(item, kind): item for item in left_records.get(kind, [])}
        after_index = {_record_key(item, kind): item for item in right_records.get(kind, [])}
        added_keys = sorted(set(after_index) - set(before_index))
        removed_keys = sorted(set(before_index) - set(after_index))
        shared_keys = sorted(set(before_index) & set(after_index))
        changed, suppressed = _filter_changed_rows(kind, shared_keys, before_index, after_index, classic=classic)
        changes[kind] = {
            "added": [after_index[key] for key in added_keys],
            "removed": [before_index[key] for key in removed_keys],
            "changed": changed,
        }
        if suppressed:
            changes[kind]["suppressed"] = suppressed
            suppressed_changes[kind] = suppressed
            for row in suppressed:
                reason = str(row.get("reason") or "suppressed")
                suppressed_reason_counts[reason] += 1
                for path in row.get("changed_paths") or []:
                    if isinstance(path, str) and path:
                        suppressed_path_counts[path] += 1
        total_added += len(added_keys)
        total_removed += len(removed_keys)
        total_changed += len(changed)
        raw_total_changed += len(changed) + len(suppressed)
        suppressed_total_changed += len(suppressed)

    citations, evidence_missing = _diff_citations(left=left, right=right, compared_files=compared_files)
    return {
        "run_a": str(left),
        "run_b": str(right),
        "run_a_info": left_info,
        "run_b_info": right_info,
        "compare_context": {
            "same_tenant": same_tenant,
            "same_platform": same_platform,
        },
        "classic": classic,
        "compared_files": compared_files,
        "summary": {
            "added": total_added,
            "removed": total_removed,
            "changed": total_changed,
            "object_kinds": len(changes),
        },
        "noise_suppression": {
            "enabled": not classic,
            "profile": "volatile_fields_v1",
            "raw_changed": raw_total_changed,
            "suppressed_changed": suppressed_total_changed,
            "remaining_changed": total_changed,
            "suppressed_object_kinds": len(suppressed_changes),
            "suppressed_reason_counts": dict(sorted(suppressed_reason_counts.items())),
            "suppressed_path_counts": dict(sorted(suppressed_path_counts.items())),
        },
        "drift_summary": _posture_drift_summary(left, right),
        "changes": changes,
        "citations": citations,
        "citation_summary": build_citation_summary(citations),
        "evidence_missing": evidence_missing,
    }
