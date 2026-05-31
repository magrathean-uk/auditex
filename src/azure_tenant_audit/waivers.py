from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import date, timedelta
from pathlib import Path
from typing import Any


_MATCH_FIELDS = ("finding_id", "rule_id", "collector", "category")
_STATUS_ACCEPTED_RISK = "accepted_risk"
_ACCEPTED_STATUSES = frozenset({"accepted_risk", "accepted", "waived"})


def load_waivers(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return []

    rows = payload.get("waivers") if isinstance(payload, Mapping) else payload
    if not isinstance(rows, list):
        return []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


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
    return {
        "count": len(rows),
        "stale_count": len(stale),
        "expiring_soon_count": len(expiring_soon),
        "without_expiry_count": sum(1 for row in rows if not row.get("expires_on")),
        "next_expiry": next_expiry,
        "warning_window_days": warning_window_days,
        "accepted_risks": rows,
        "stale": stale,
        "expiring_soon": expiring_soon,
    }


def _match_score(finding: Mapping[str, Any], waiver: Mapping[str, Any]) -> int:
    for score, field in enumerate(_MATCH_FIELDS, start=1):
        wanted = waiver.get(field)
        if wanted is None or wanted == "":
            continue
        actual = finding.get("id") if field == "finding_id" else finding.get(field)
        if str(actual or "") == str(wanted):
            return len(_MATCH_FIELDS) - score + 1
    return 0


def _best_waiver(finding: Mapping[str, Any], waiver_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    best_score = 0
    best_row: dict[str, Any] | None = None
    for row in waiver_rows:
        if _expired(row):
            continue
        score = _match_score(finding, row)
        if score > best_score:
            best_score = score
            best_row = row
    return dict(best_row) if best_row is not None else None


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
