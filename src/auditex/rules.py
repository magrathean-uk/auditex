from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from azure_tenant_audit.resources import resolve_resource_path

DEFAULT_RULE_PACKS_PATH = Path("configs/rule-packs.json")
DEFAULT_FINDING_TEMPLATES_PATH = Path("configs/finding-templates.json")
DEFAULT_CONTROL_MAPPINGS_PATH = Path("configs/control-mappings.json")
_RULE_METADATA_FIELDS = ("risk_rating", "impact", "remediation", "references", "control_ids", "expected_value")

_M365_PRODUCT_FAMILIES = {
    "app_consent": "identity",
    "app_credentials": "identity",
    "collector": "core",
    "consent_policy": "identity",
    "coverage": "core",
    "cross_tenant_access": "identity",
    "dns_posture": "dns",
    "exchange": "exchange",
    "external_identity": "identity",
    "identity": "identity",
    "intune": "endpoint",
    "mailbox_forwarding": "exchange",
    "security": "security",
    "service_health": "service_health",
    "sharepoint": "sharepoint",
    "teams": "teams",
}

_GOOGLE_PRODUCT_FAMILIES = {
    "apps": "apps",
    "audit": "core",
    "calendar": "calendar",
    "devices": "endpoint",
    "domains": "dns",
    "drive": "drive",
    "gmail": "gmail",
    "groups": "groups",
    "identity": "identity",
    "security": "security",
}


def _read_rules(path: Path) -> list[Mapping[str, Any]]:
    path = resolve_resource_path(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return []
    rows = payload.get("rules") if isinstance(payload, Mapping) else []
    return [row for row in rows if isinstance(row, Mapping)] if isinstance(rows, list) else []


def _read_registry(path: Path) -> dict[str, Mapping[str, Any]]:
    path = resolve_resource_path(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(payload, Mapping):
        return {}
    return {
        str(rule_id): value
        for rule_id, value in payload.items()
        if isinstance(rule_id, str) and isinstance(value, Mapping) and not rule_id.startswith("_")
    }


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({str(item) for item in value if item is not None})


def _title_from_rule_id(rule_id: str) -> str:
    return rule_id.replace(".", " ").replace("_", " ").title()


def _namespace(rule_id: str) -> str:
    return rule_id.split(".", 1)[0]


def _m365_product_family(rule_id: str) -> str:
    return _M365_PRODUCT_FAMILIES.get(_namespace(rule_id), _namespace(rule_id))


def _google_product_family(rule_id: str, mappings: Mapping[str, Any]) -> str:
    baseline = _string_list(mappings.get("google_workspace_baseline"))
    if baseline:
        family = baseline[0].split(".", 1)[0]
        return _GOOGLE_PRODUCT_FAMILIES.get(family, family)
    return _GOOGLE_PRODUCT_FAMILIES.get(
        _namespace(rule_id.replace("google.", "", 1)),
        "google_workspace",
    )


def _framework_mappings(value: Mapping[str, Any] | None) -> dict[str, list[str]]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): _string_list(items) for key, items in value.items() if _string_list(items)}


def _metadata_fields(source: Mapping[str, Any]) -> dict[str, Any]:
    return {field: source[field] for field in _RULE_METADATA_FIELDS if _has_value(source.get(field))}


def _rule_row(item: Mapping[str, Any]) -> dict[str, Any] | None:
    name = str(item.get("name") or "").strip()
    if not name:
        return None
    product_family = str(item.get("product_family") or "")
    row = {
        "name": name,
        "title": item.get("title"),
        "description": item.get("description"),
        "tags": _string_list(item.get("tags")),
        "path": str(item.get("path") or ""),
        "enabled": bool(item.get("enabled", True)),
        "platform": str(item.get("platform") or "m365"),
        "product_family": product_family,
        "license_tiers": _string_list(item.get("license_tiers")),
        "audit_levels": _string_list(item.get("audit_levels")),
        "framework_mappings": _framework_mappings(
            item.get("framework_mappings") if isinstance(item.get("framework_mappings"), Mapping) else None
        ),
    }
    row.update(_metadata_fields(item))
    return row


def _generated_m365_rows() -> list[dict[str, Any]]:
    templates = _read_registry(DEFAULT_FINDING_TEMPLATES_PATH)
    mappings = _read_registry(DEFAULT_CONTROL_MAPPINGS_PATH)
    rows: list[dict[str, Any]] = []
    for rule_id in sorted(set(templates) | set(mappings)):
        template = templates.get(rule_id, {})
        family = _m365_product_family(rule_id)
        row = {
            "name": rule_id,
            "title": template.get("title") or _title_from_rule_id(rule_id),
            "description": template.get("description"),
            "tags": sorted({"m365", family, _namespace(rule_id)}),
            "path": f"findings/m365/{family}",
            "enabled": True,
            "platform": "m365",
            "product_family": family,
            "license_tiers": ["all"],
            "audit_levels": ["baseline", "deep"],
            "framework_mappings": _framework_mappings(mappings.get(rule_id)),
        }
        row.update(_metadata_fields(template))
        rows.append(row)
    return rows


def _generated_google_rows() -> list[dict[str, Any]]:
    try:
        from auditex.google_workspace import findings as google_findings
    except Exception:
        return []

    metadata_loader = getattr(google_findings, "google_rule_metadata", None)
    metadata_by_rule = metadata_loader() if callable(metadata_loader) else {}
    mappings_by_rule = getattr(google_findings, "_GOOGLE_FRAMEWORK_MAPPINGS", {})
    if not isinstance(mappings_by_rule, Mapping):
        return []
    rows: list[dict[str, Any]] = []
    for rule_id, raw_mappings in sorted(mappings_by_rule.items()):
        if not isinstance(rule_id, str) or not isinstance(raw_mappings, Mapping):
            continue
        mappings = _framework_mappings(raw_mappings)
        metadata = metadata_by_rule.get(rule_id, {}) if isinstance(metadata_by_rule, Mapping) else {}
        metadata = metadata if isinstance(metadata, Mapping) else {}
        family = _google_product_family(rule_id, mappings)
        row = {
            "name": rule_id,
            "title": metadata.get("title") or _title_from_rule_id(rule_id.removeprefix("google.")),
            "description": metadata.get("description") or "Google Workspace evidence is outside the approved audit baseline.",
            "tags": sorted(
                {
                    "google",
                    "google_workspace",
                    family,
                    _namespace(rule_id.removeprefix("google.")),
                }
            ),
            "path": f"findings/google_workspace/{family}",
            "enabled": True,
            "platform": "google_workspace",
            "product_family": family,
            "license_tiers": ["workspace"],
            "audit_levels": ["baseline", "deep"],
            "framework_mappings": mappings,
        }
        row.update(_metadata_fields(metadata))
        rows.append(row)
    return rows


def _has_value(value: Any) -> bool:
    return value not in (None, "", [], {})


def _merge_rows(existing: Mapping[str, Any], incoming: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(incoming)
    for key, value in existing.items():
        if key in {"tags", "license_tiers", "audit_levels"}:
            merged[key] = sorted(set(_string_list(merged.get(key))) | set(_string_list(value)))
            continue
        if key == "framework_mappings":
            current = merged.get("framework_mappings")
            current_mappings = current if isinstance(current, Mapping) else {}
            merged[key] = {
                **_framework_mappings(current_mappings),
                **_framework_mappings(value if isinstance(value, Mapping) else None),
            }
            continue
        if _has_value(value):
            merged[key] = value
    return merged


def _all_rule_rows(path: Path | None = None) -> list[dict[str, Any]]:
    by_name: dict[str, dict[str, Any]] = {}
    rows = [_rule_row(item) for item in _read_rules(path or DEFAULT_RULE_PACKS_PATH)]
    if path is None:
        rows.extend(_generated_m365_rows())
        rows.extend(_generated_google_rows())
    for row in rows:
        if row is None:
            continue
        name = row["name"]
        existing = by_name.get(name)
        by_name[name] = _merge_rows(existing, row) if existing else dict(row)
    return list(by_name.values())


def _matches(
    row: Mapping[str, Any],
    *,
    tag: str | None,
    path_prefix: str | None,
    platform: str | None,
    product_family: str | None,
    license_tier: str | None,
    audit_level: str | None,
) -> bool:
    if tag and tag not in row.get("tags", []):
        return False
    if path_prefix and str(row.get("path") or "") and not str(row.get("path")).startswith(path_prefix):
        return False
    if platform and row.get("platform") != platform:
        return False
    if product_family and row.get("product_family") != product_family:
        return False
    if license_tier and license_tier not in row.get("license_tiers", []):
        return False
    if audit_level and audit_level not in row.get("audit_levels", []):
        return False
    return True


def list_rule_inventory(
    *,
    path: Path | None = None,
    tag: str | None = None,
    path_prefix: str | None = None,
    platform: str | None = None,
    product_family: str | None = None,
    license_tier: str | None = None,
    audit_level: str | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _all_rule_rows(path):
        if row is not None and _matches(
            row,
            tag=tag,
            path_prefix=path_prefix,
            platform=platform,
            product_family=product_family,
            license_tier=license_tier,
            audit_level=audit_level,
        ):
            rows.append(row)
    return sorted(rows, key=lambda row: row["name"])
