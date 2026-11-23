from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .citations import build_citation_summary, dedupe_citations
from .guarded_io import UnsafeRunFileError
from .run_files import hash_run_file, read_run_file
from .tenant_identity import canonical_tenant_uuid
from .waivers import accepted_risk_summary, is_accepted_status


class MalformedRunEvidence(ValueError):
    """A regular, admitted normalised artifact that is not a JSON object; the comparison cannot read it."""

    def __init__(self, run_dir: Path, relative: str) -> None:
        super().__init__(f"normalised artifact {relative} is not a JSON object")
        self.run_dir = run_dir
        self.relative = relative


def _load_json(run_dir: Path, relative: str) -> dict[str, Any]:
    try:
        payload = json.loads(read_run_file(run_dir, relative).decode("utf-8"))
    except UnsafeRunFileError:
        raise
    except (json.JSONDecodeError, OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_findings(run_dir: Path) -> list[dict[str, Any]]:
    pack = _load_json(run_dir, "reports/report-pack.json")
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
    # The day the end-of-life table was applied; it moves every day without any device changing.
    "device_posture": frozenset({"os_lifecycle_evaluated_on"}),
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
        for index, (left_item, right_item) in enumerate(zip(before, after, strict=False)):
            child_prefix = f"{prefix}[{index}]" if prefix else f"[{index}]"
            paths.extend(_collect_changed_paths(left_item, right_item, prefix=child_prefix))
        return paths
    if before != after:
        return [prefix or "value"]
    return []


def _collector_coverage(run_dir: Path) -> dict[str, bool]:
    """Whether each collector the run recorded completed: the coverage ledger, else the ``summary.json`` statuses."""
    ledger = _load_json(run_dir, "normalized/coverage_ledger.json")
    coverage: dict[str, bool] = {}
    for row in ledger.get("records") if isinstance(ledger.get("records"), list) else []:
        if isinstance(row, dict) and row.get("collector"):
            coverage[str(row["collector"])] = str(row.get("coverage_status") or "unknown").startswith("complete")
    if coverage:
        return coverage
    summary = _load_json(run_dir, "summary.json")
    for row in summary.get("collectors") if isinstance(summary.get("collectors"), list) else []:
        if isinstance(row, dict) and row.get("name"):
            coverage[str(row["name"])] = str(row.get("status") or "unknown") == "ok"
    return coverage


def _posture_drift_summary(left: Path, right: Path) -> dict[str, Any]:
    before = _finding_index(_load_findings(left))
    after = _finding_index(_load_findings(right))
    new_keys = sorted(set(after) - set(before))
    resolved_keys = sorted(set(before) - set(after))
    # R054: a finding is resolved only when the later run's collector for it completed. When the later run records
    # its collector coverage and the finding's collector did not complete there (or did not run), the finding was not
    # reassessed. ``auditex compare`` refines this with the rule inputs and the bundle and tenant checks.
    # A later run that recorded no coverage at all completed no collector, so a removed finding that names one was
    # not reassessed either; a finding that names no collector gives no evidence either way and stays resolved.
    later_coverage = _collector_coverage(right)
    not_reassessed_keys: list[str] = []
    still_resolved: list[str] = []
    for key in resolved_keys:
        collector = str(before[key].get("collector") or "")
        (not_reassessed_keys if collector and not later_coverage.get(collector, False) else still_resolved).append(key)
    resolved_keys = still_resolved
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
        "not_reassessed_findings": not_reassessed_keys,
        "worsened_findings": worsened,
        "improved_findings": improved,
        "state_transitions": state_transitions,
        "reactivated_accepted_risks": reactivated_accepted_risks,
        "accepted_risk_summary": accepted_summary,
        "stale_accepted_risks": [dict(row) for row in accepted_summary.get("stale") or [] if isinstance(row, dict)],
        "new_count": len(new_keys),
        "resolved_count": len(resolved_keys),
        "not_reassessed_count": len(not_reassessed_keys),
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
    shared_keys: list[RowKey],
    before_index: dict[RowKey, dict[str, Any]],
    after_index: dict[RowKey, dict[str, Any]],
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
                    "key": key[1],
                    "before": before,
                    "after": after,
                    "reason": "volatile_fields_only",
                    "changed_paths": changed_paths,
                    "kind": kind,
                }
            )
            continue
        changed.append({"key": key[1], "before": before, "after": after})
    return changed, suppressed


def _load_records(run_dir: Path, path: Path) -> tuple[str, list[dict[str, Any]]]:
    relative = path.relative_to(run_dir)
    data = read_run_file(run_dir, relative)
    try:
        payload = json.loads(data.decode("utf-8"))
    except ValueError:
        raise MalformedRunEvidence(run_dir, relative.as_posix()) from None
    if not isinstance(payload, dict):
        raise MalformedRunEvidence(run_dir, relative.as_posix())
    kind = str(payload.get("kind") or path.stem)
    records = payload.get("records", [])
    if not isinstance(records, list):
        records = []
    return kind, [item for item in records if isinstance(item, dict)]


# A row's comparison key: whether it is positional (the row carries no identity field), then its readable text. Keeping
# the two kinds apart stops an anonymous row at position 0 pairing with a row whose id is 0: both read ``kind:0``.
RowKey = tuple[bool, str]


def _record_key(record: dict[str, Any], kind: str, index: int) -> RowKey:
    """The row's identity, in the order the evidence index and the validator use (R053)."""
    for field in ("key", "id", "display_name", "name", "collector", "surface"):
        value = record.get(field)
        if value is not None and str(value).strip():
            return (False, str(value) if field == "key" else f"{kind}:{value}")
    return (True, f"{kind}:{index}")


def _rows_match(before: dict[str, Any], after: dict[str, Any], kind: str, *, classic: bool) -> bool:
    """Whether two rows differ in volatile fields at most (or not at all, for a classic diff)."""
    if before == after:
        return True
    if classic:
        return False
    paths = _collect_changed_paths(before, after)
    return bool(paths) and all(_is_volatile_path(path, kind=kind) for path in paths)


def _pair_duplicates(
    before: list[dict[str, Any]], after: list[dict[str, Any]], kind: str, *, classic: bool
) -> tuple[list[tuple[int, int]], list[int], list[int]]:
    """Pair the rows of one repeated key: equal rows first, then rows differing only in volatile fields, then the
    rest in order. Returns the (before, after) position pairs and the unpaired positions on each side."""
    free_after = list(range(len(after)))
    pairs: list[tuple[int, int]] = []
    unpaired_before: list[int] = []
    for exact in (True, False):
        waiting: list[int] = []
        for left in (unpaired_before if not exact else range(len(before))):
            match = next(
                (
                    right
                    for right in free_after
                    if (before[left] == after[right] if exact else _rows_match(before[left], after[right], kind, classic=classic))
                ),
                None,
            )
            if match is None:
                waiting.append(left)
            else:
                free_after.remove(match)
                pairs.append((left, match))
        unpaired_before = waiting
    leftover = min(len(unpaired_before), len(free_after))
    pairs.extend(zip(unpaired_before[:leftover], free_after[:leftover], strict=True))
    pairs.sort()
    return pairs, unpaired_before[leftover:], free_after[leftover:]


def _suffixed_keys(key: RowKey, count: int, taken: set[RowKey]) -> list[RowKey]:
    """``key`` then ``key#2``, ``key#3``... (``count`` keys), skipping a suffix that is already taken."""
    keys = [key]
    suffix = 2
    while len(keys) < count:
        generated = (key[0], f"{key[1]}#{suffix}")
        suffix += 1
        if generated not in taken:
            taken.add(generated)
            keys.append(generated)
    return keys[:count]


def _paired_record_indexes(
    before_rows: list[dict[str, Any]], after_rows: list[dict[str, Any]], kind: str, *, classic: bool
) -> tuple[dict[RowKey, dict[str, Any]], dict[RowKey, dict[str, Any]], list[str]]:
    """Both runs' rows by key, and the keys more than one row of a run carries.

    A repeated key is reported, not overwritten. Its rows are paired across the runs (equal rows first, so a reordered
    but unchanged set reads unchanged) and every pair after the first, and every unpaired row, gets a ``#2``, ``#3``
    suffix so every row is compared. A suffix that is also a real key in either run is skipped, so a generated key
    never replaces or pairs with a real one.
    """
    before_keys = [_record_key(record, kind, position) for position, record in enumerate(before_rows)]
    after_keys = [_record_key(record, kind, position) for position, record in enumerate(after_rows)]
    taken = set(before_keys) | set(after_keys)
    before_groups: dict[RowKey, list[int]] = {}
    after_groups: dict[RowKey, list[int]] = {}
    for groups, keys in ((before_groups, before_keys), (after_groups, after_keys)):
        for position, key in enumerate(keys):
            groups.setdefault(key, []).append(position)
    before_index: dict[RowKey, dict[str, Any]] = {}
    after_index: dict[RowKey, dict[str, Any]] = {}
    duplicates: list[str] = []
    for key in dict.fromkeys([*before_keys, *after_keys]):
        lefts, rights = before_groups.get(key, []), after_groups.get(key, [])
        if len(lefts) <= 1 and len(rights) <= 1:
            if lefts:
                before_index[key] = before_rows[lefts[0]]
            if rights:
                after_index[key] = after_rows[rights[0]]
            continue
        duplicates.append(key[1])
        pairs, only_before, only_after = _pair_duplicates(
            [before_rows[position] for position in lefts], [after_rows[position] for position in rights], kind, classic=classic
        )
        row_keys = iter(_suffixed_keys(key, len(pairs) + len(only_before) + len(only_after), taken))
        for left, right in pairs:
            row_key = next(row_keys)
            before_index[row_key] = before_rows[lefts[left]]
            after_index[row_key] = after_rows[rights[right]]
        for left in only_before:
            before_index[next(row_keys)] = before_rows[lefts[left]]
        for right in only_after:
            after_index[next(row_keys)] = after_rows[rights[right]]
    return before_index, after_index, duplicates


def admit_run_files(run_dir: str | Path) -> None:
    """Open every file ``diff_run_directories`` reads through its guarded loaders, without comparing anything.

    An unsafe file (a link, a private key, an oversize artifact) raises ``UnsafeRunFileError`` here, before a compare
    gate could block the pair unread. Malformed content is left to the comparison, which blocks the pair.
    """
    run = Path(run_dir)
    for relative in (
        "run-manifest.json",
        "normalized/snapshot.json",
        "normalized/coverage_ledger.json",
        "summary.json",
        "reports/report-pack.json",
    ):
        _load_json(run, relative)
    normalized = run / "normalized"
    if normalized.exists():
        for path in sorted(normalized.glob("*.json")):
            hash_run_file(run, path.relative_to(run))


def _records_for_run(run_dir: Path) -> tuple[dict[str, str], dict[str, list[dict[str, Any]]]]:
    normalized_dir = run_dir / "normalized"
    if not normalized_dir.exists():
        return {}, {}

    files: dict[str, str] = {}
    records_by_kind: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(normalized_dir.glob("*.json")):
        kind, records = _load_records(run_dir, path)
        if not records:
            continue
        files[kind] = path.name
        records_by_kind[kind] = records
    return files, records_by_kind


def _run_metadata(run_dir: Path) -> dict[str, Any]:
    manifest = _load_json(run_dir, "run-manifest.json")
    snapshot = _load_json(run_dir, "normalized/snapshot.json")
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


def _tenant_key(info: dict[str, Any]) -> str | None:
    value = info.get("tenant_id")
    if not value or value == "my_customer":
        return None
    return canonical_tenant_uuid(value) or str(value).strip().lower() or None


def _same_tenant(left_info: dict[str, Any], right_info: dict[str, Any]) -> bool:
    """Whether two runs read the same tenant.

    Known tenant IDs decide: two different IDs are two tenants whatever their operator-chosen names say. A shared
    tenant name counts only when at most one side records an ID.
    """
    left_id, right_id = _tenant_key(left_info), _tenant_key(right_info)
    if left_id and right_id:
        return left_id == right_id
    return bool(left_info.get("tenant_name")) and left_info.get("tenant_name") == right_info.get("tenant_name")


def diff_run_directories(run_a: str | Path, run_b: str | Path, *, classic: bool = False) -> dict[str, Any]:
    left = Path(run_a)
    right = Path(run_b)
    left_files, left_records = _records_for_run(left)
    right_files, right_records = _records_for_run(right)
    left_info = _run_metadata(left)
    right_info = _run_metadata(right)
    same_tenant = _same_tenant(left_info, right_info)
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
        before_rows, after_rows = left_records.get(kind, []), right_records.get(kind, [])
        before_index, after_index, duplicate_keys = _paired_record_indexes(before_rows, after_rows, kind, classic=classic)
        added_keys = sorted(set(after_index) - set(before_index))
        removed_keys = sorted(set(before_index) - set(after_index))
        shared_keys = sorted(set(before_index) & set(after_index))
        changed, suppressed = _filter_changed_rows(kind, shared_keys, before_index, after_index, classic=classic)
        changes[kind] = {
            "added": [after_index[key] for key in added_keys],
            "removed": [before_index[key] for key in removed_keys],
            "changed": changed,
        }
        if duplicate_keys:
            changes[kind]["duplicate_keys"] = sorted(duplicate_keys)
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
