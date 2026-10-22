from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from datetime import date, timedelta
from pathlib import Path
from typing import Any


_MATCH_FIELDS = ("finding_id", "rule_id", "collector", "category")
# A waiver must name a specific finding or rule. collector and category only narrow it.
_IDENTIFYING_FIELDS = ("finding_id", "rule_id")
_SPECIFICITY = {"finding_id": 8, "rule_id": 4, "collector": 2, "category": 1}
_ACCOUNTABILITY_FIELDS = ("owner", "reason", "expires_on")
_STATUS_ACCEPTED_RISK = "accepted_risk"
_ACCEPTED_STATUSES = frozenset({"accepted_risk", "accepted", "waived"})


class WaiverFileError(ValueError):
    """A configured waiver file is missing, unreadable or invalid.

    Waivers turn findings into accepted risk, so a file that cannot be trusted
    must stop the run instead of silently applying no waivers.
    """


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _row_value(row: Mapping[str, Any], field: str) -> Any:
    if field == "reason":
        return row.get("reason") or row.get("comment")
    if field == "expires_on":
        return row.get("expires_on") or row.get("expires")
    return row.get(field)


def _populated_match_fields(row: Mapping[str, Any]) -> list[str]:
    return [field for field in _MATCH_FIELDS if _text(row.get(field))]


def waiver_gaps(row: Mapping[str, Any] | None) -> list[str]:
    """Accountability fields (owner, reason, expires_on) a waiver row does not carry."""
    source = row if isinstance(row, Mapping) else {}
    gaps: list[str] = []
    for field in _ACCOUNTABILITY_FIELDS:
        if field == "expires_on":
            if _parse_expiry_date(source) is None:
                gaps.append(field)
        elif not _text(_row_value(source, field)):
            gaps.append(field)
    return gaps


def _waiver_label(row: Mapping[str, Any]) -> str:
    for field in _MATCH_FIELDS:
        value = _text(row.get(field))
        if value:
            return f"{field}={value}"
    return "no match fields"


def validate_waiver_rows(rows: list[Any]) -> list[str]:
    """Structural problems that make a waiver file untrustworthy (not just incomplete)."""
    errors: list[str] = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, Mapping):
            errors.append(f"waiver #{index} is not a JSON object")
            continue
        for field in _MATCH_FIELDS:
            value = row.get(field)
            if value is not None and not isinstance(value, str):
                errors.append(f"waiver #{index}: {field} must be a string")
        if not any(_text(row.get(field)) for field in _IDENTIFYING_FIELDS):
            errors.append(
                f"waiver #{index}: needs finding_id or rule_id (collector and category alone never match)"
            )
        raw_expiry = _row_value(row, "expires_on")
        if raw_expiry:
            try:
                date.fromisoformat(str(raw_expiry))
            except ValueError:
                errors.append(f"waiver #{index}: expires_on {str(raw_expiry)!r} is not an ISO date (YYYY-MM-DD)")
    return errors


def waiver_warnings(rows: list[dict[str, Any]], *, today: date | None = None) -> list[str]:
    """Human-readable warnings for waivers that lack accountability or have expired."""
    current_day = today or date.today()
    warnings: list[str] = []
    for index, row in enumerate(rows, start=1):
        label = f"waiver #{index} ({_waiver_label(row)})"
        gaps = waiver_gaps(row)
        if gaps:
            warnings.append(f"{label} has no {', '.join(gaps)}")
        expiry = _parse_expiry_date(row)
        if expiry is not None and expiry < current_day:
            warnings.append(f"{label} expired on {expiry.isoformat()} and will not match any finding")
    return warnings


def load_waivers(path: Path | None, *, warn: bool = True) -> list[dict[str, Any]]:
    """Load and validate a waiver file; raise ``WaiverFileError`` if it cannot be trusted.

    ``None`` means no waiver file was configured. Missing owner, reason or expiry
    only warn (on stderr unless ``warn`` is false); the caller can read the same
    text from ``waiver_warnings``.
    """
    if path is None:
        return []
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise WaiverFileError(f"waiver file not found: {path}") from exc
    except (OSError, ValueError) as exc:
        raise WaiverFileError(f"waiver file {path} is unreadable or not valid JSON: {exc}") from exc

    rows = payload.get("waivers") if isinstance(payload, Mapping) else payload
    if not isinstance(rows, list):
        raise WaiverFileError(f"waiver file {path} must be a JSON list or an object with a 'waivers' list")
    errors = validate_waiver_rows(rows)
    if errors:
        raise WaiverFileError(f"waiver file {path} is invalid: " + "; ".join(errors))
    loaded = [dict(row) for row in rows]
    if warn:
        for message in waiver_warnings(loaded):
            print(f"warning: {message}", file=sys.stderr)
    return loaded


def _expired(row: Mapping[str, Any]) -> bool:
    expiry = _parse_expiry_date(row)
    return expiry is not None and expiry < date.today()


def _parse_expiry_date(row: Mapping[str, Any]) -> date | None:
    raw_value = row.get("expires_on") or row.get("expires")
    if not raw_value:
        return None
    try:
        return date.fromisoformat(str(raw_value))
    except ValueError:
        return None


def is_accepted_status(status: Any) -> bool:
    return str(status or "").strip().lower() in _ACCEPTED_STATUSES


def has_matching_waiver(finding: Mapping[str, Any]) -> bool:
    """Whether a finding carries the waiver that accepted it.

    ``apply_waivers`` is the only writer of an accepted status and always attaches the waiver it matched,
    so an accepted finding without one was edited, not waived. The waiver must name the finding or its
    rule and every match field it populates must equal the finding's, the same test ``apply_waivers`` ran.
    """
    waiver = finding.get("waiver")
    return isinstance(waiver, Mapping) and _match_score(finding, waiver) > 0


def accepted_risk_summary(
    findings: list[dict[str, Any]],
    *,
    today: date | None = None,
    warning_window_days: int = 30,
) -> dict[str, Any]:
    current_day = today or date.today()
    warning_cutoff = current_day + timedelta(days=warning_window_days)
    rows: list[dict[str, Any]] = []

    for finding in findings:
        if not is_accepted_status(finding.get("status")):
            continue
        waiver = finding.get("waiver") if isinstance(finding.get("waiver"), Mapping) else {}
        expiry = _parse_expiry_date(waiver) if isinstance(waiver, Mapping) else None
        days_until_expiry = (expiry - current_day).days if expiry is not None else None
        row = {
            "id": finding.get("id"),
            "rule_id": finding.get("rule_id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "collector": finding.get("collector"),
            "status": finding.get("status"),
            "expires_on": expiry.isoformat() if expiry is not None else None,
            "days_until_expiry": days_until_expiry,
            "expired": expiry is not None and expiry < current_day,
            "expires_soon": expiry is not None and current_day <= expiry <= warning_cutoff,
            "comment": waiver.get("comment") if isinstance(waiver, Mapping) else None,
            "owner": _text(waiver.get("owner")) or None,
            "reason": _text(_row_value(waiver, "reason")) or None,
            "missing_fields": waiver_gaps(waiver),
        }
        rows.append(row)

    stale = [row for row in rows if row["expired"]]
    expiring_soon = [row for row in rows if row["expires_soon"] and not row["expired"]]
    dated_rows = [row for row in rows if row["expires_on"]]
    next_expiry = min((row["expires_on"] for row in dated_rows), default=None)

    def _sort_key(row: dict[str, Any]) -> tuple[int, int, str]:
        days = row.get("days_until_expiry")
        return (
            0 if row.get("expired") else 1,
            int(days) if isinstance(days, int) else 999999,
            str(row.get("id") or ""),
        )

    rows.sort(key=_sort_key)
    stale.sort(key=_sort_key)
    expiring_soon.sort(key=_sort_key)
    warnings = [
        f"accepted risk {row['id'] or row['rule_id']} has no {', '.join(row['missing_fields'])}"
        for row in rows
        if row["missing_fields"]
    ]
    return {
        "count": len(rows),
        "stale_count": len(stale),
        "expiring_soon_count": len(expiring_soon),
        "without_expiry_count": sum(1 for row in rows if not row.get("expires_on")),
        "without_owner_count": sum(1 for row in rows if not row.get("owner")),
        "without_reason_count": sum(1 for row in rows if not row.get("reason")),
        "warnings": warnings,
        "next_expiry": next_expiry,
        "warning_window_days": warning_window_days,
        "accepted_risks": rows,
        "stale": stale,
        "expiring_soon": expiring_soon,
    }


def _match_score(finding: Mapping[str, Any], waiver: Mapping[str, Any]) -> int:
    """Specificity score when every populated match field equals the finding's, else 0.

    All populated fields must match (AND). A waiver with neither finding_id nor
    rule_id never matches, so a collector or category cannot be waived wholesale.
    """
    populated = _populated_match_fields(waiver)
    if not any(field in populated for field in _IDENTIFYING_FIELDS):
        return 0
    for field in populated:
        actual = finding.get("id") if field == "finding_id" else finding.get(field)
        if _text(actual) != _text(waiver.get(field)):
            return 0
    return sum(_SPECIFICITY[field] for field in populated)


def _best_waiver(finding: Mapping[str, Any], waiver_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    best_score = 0
    best_row: dict[str, Any] | None = None
    for row in waiver_rows:
        if not isinstance(row, Mapping) or _expired(row):
            continue
        score = _match_score(finding, row)
        if score > best_score:
            best_score = score
            best_row = dict(row)
    if best_row is None:
        return None
    best_row["matched_fields"] = _populated_match_fields(best_row)
    gaps = waiver_gaps(best_row)
    if gaps:
        best_row["missing_fields"] = gaps
    return best_row


def apply_waivers(findings: list[dict[str, Any]], waiver_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for finding in findings:
        updated = dict(finding)
        waiver = _best_waiver(updated, waiver_rows)
        if waiver is not None:
            updated["status"] = _STATUS_ACCEPTED_RISK
            updated["waiver_applied"] = True
            updated["waiver"] = waiver
        output.append(updated)
    return output
