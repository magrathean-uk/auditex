from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def dedupe_citations(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        key = (
            str(row.get("artifact_path") or "").strip(),
            str(row.get("reason") or "").strip(),
            str(row.get("record_key") or "").strip(),
            str(row.get("json_pointer") or "").strip(),
        )
        if not key[0] or key in seen:
            continue
        seen.add(key)
        payload = dict(row)
        payload["artifact_path"] = key[0]
        if key[1]:
            payload["reason"] = key[1]
        if key[2]:
            payload["record_key"] = key[2]
        if key[3]:
            payload["json_pointer"] = key[3]
        result.append(payload)
    return result


def build_citation_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    citations = dedupe_citations(rows)
    artifacts = sorted({str(row.get("artifact_path")) for row in citations})
    record_keys = sorted({str(row.get("record_key")) for row in citations if str(row.get("record_key") or "").strip()})
    return {
        "citation_count": len(citations),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "record_key_count": len(record_keys),
        "json_pointer_count": sum(1 for row in citations if str(row.get("json_pointer") or "").strip()),
        "evidence_missing": not citations,
    }
