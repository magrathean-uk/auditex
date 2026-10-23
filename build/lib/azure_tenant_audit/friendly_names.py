from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
from typing import Any


_ID_KEYS = (
    "id",
    "object_id",
    "objectId",
    "policy_id",
    "role_id",
    "service_principal_id",
    "site_id",
    "target_id",
)
_LABEL_KEYS = (
    "display_name",
    "displayName",
    "name",
    "user_principal_name",
    "userPrincipalName",
    "principal_name",
    "mail",
    "title",
    "policy_name",
    "site_name",
    "service_principal_name",
    "app_display_name",
    "target_name",
)
_KIND_KEYS = ("kind", "object_kind", "type", "@odata.type")


def _first_string(record: Mapping[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = record.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _fallback_kind(section: str) -> str:
    cleaned = section.strip().replace("-", "_") or "object"
    if cleaned.endswith("ies"):
        return cleaned[:-3] + "y"
    if cleaned.endswith("s") and len(cleaned) > 1:
        return cleaned[:-1]
    return cleaned


def _catalog_entry(section: str, record: Mapping[str, Any]) -> tuple[dict[str, Any] | None, bool]:
    object_id = _first_string(record, _ID_KEYS)
    if not object_id:
        return None, False

    label = _first_string(record, _LABEL_KEYS)
    if not label:
        return None, True

    kind = _first_string(record, _KIND_KEYS) or _fallback_kind(section)
    key = f"translation:{kind}:{object_id}"
    return (
        {
            "key": key,
            "object_kind": kind,
            "object_id": object_id,
            "display_name": label,
            "source_section": section,
        },
        False,
    )


def _iter_source_records(value: Any) -> list[Mapping[str, Any]]:
    records: list[Mapping[str, Any]] = []
    if isinstance(value, Mapping):
        if any(key in value for key in _ID_KEYS):
            records.append(value)
        nested_value = value.get("value")
        if isinstance(nested_value, list):
            records.extend(item for item in nested_value if isinstance(item, Mapping))
        for nested in value.values():
            if isinstance(nested, (dict, list)):
                records.extend(_iter_source_records(nested))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                records.extend(_iter_source_records(item))
    return records


def _load_chunk_records(run_dir: Path | None, relative_paths: list[str]) -> list[Mapping[str, Any]]:
    if run_dir is None:
        return []
    rows: list[Mapping[str, Any]] = []
    for relative in relative_paths:
        path = run_dir / relative
        if not path.exists():
            continue
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    payload = json.loads(line)
                    if isinstance(payload, Mapping):
                        rows.append(payload)
        except (OSError, json.JSONDecodeError, ValueError):
            continue
    return rows


def build_friendly_name_catalog(
    records_by_section: dict[str, list[dict[str, Any]]],
    *,
    collector_payloads: dict[str, Any] | None = None,
    run_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], int]:
    entries: dict[str, dict[str, Any]] = {}
    missing_label_count = 0

    for section in sorted(records_by_section):
        records = records_by_section.get(section) or []
        for record in records:
            if not isinstance(record, Mapping):
                continue
            entry, missing_label = _catalog_entry(section, record)
            if missing_label:
                missing_label_count += 1
            if entry is not None:
                entries[entry["key"]] = entry

    for collector_name, payload in sorted((collector_payloads or {}).items()):
        if not isinstance(payload, Mapping):
            continue
        for section_name, section_payload in payload.items():
            section_key = f"{collector_name}.{section_name}"
            chunk_paths = []
            if isinstance(section_payload, Mapping):
                raw_chunk_paths = section_payload.get("chunk_files")
                if isinstance(raw_chunk_paths, list):
                    chunk_paths = [str(item) for item in raw_chunk_paths if isinstance(item, str)]
            for record in [*_iter_source_records(section_payload), *_load_chunk_records(run_dir, chunk_paths)]:
                entry, missing_label = _catalog_entry(section_key, record)
                if missing_label:
                    missing_label_count += 1
                if entry is not None:
                    entries.setdefault(entry["key"], entry)

    return [entries[key] for key in sorted(entries)], missing_label_count
