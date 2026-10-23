"""Offline, allow-listed readers for external Microsoft assessment exports.

Formats were checked against Maester 2.3's ConvertTo-MtMaesterResult,
ScubaGear 1.8's consolidated sample/report writer, and Monkey365 1.0's
monkeyoutput OCSF writer. This module never runs those tools or copies raw
provider/authentication payloads into its output.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from uuid import UUID

SCHEMA_VERSION = "2026-10-18"
SOURCES = ("maester", "scubagear", "monkey365")
STATUSES = {"pass", "fail", "unknown", "not_applicable", "error"}
SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
_SHA = re.compile(r"^[0-9a-f]{64}$")
_POINTER = re.compile(r"^(?:/(?:[^~]|~[01])*)*$")


def _object(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _optional_object(value: Any, label: str) -> dict:
    return {} if value is None else _object(value, label)


def _text(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value.strip()


def _list(value: Any, label: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return value


def _tenant(value: Any) -> str | None:
    if value is None or value == "":
        return None
    text = _text(value, "tenant ID")
    # Maester explicitly emits this placeholder when no Graph/Teams session exists.
    if text == "TenantId (not connected to Graph)":
        return None
    try:
        result = UUID(text)
    except (ValueError, AttributeError) as exc:
        raise ValueError("tenant ID must be an immutable Microsoft tenant UUID") from exc
    if result.int == 0:
        raise ValueError("tenant ID must not be the empty UUID")
    return str(result)


def _timestamp(value: Any) -> str | None:
    value = _text(value, "assessment timestamp", nullable=True)
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("assessment timestamp must be ISO 8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("assessment timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _status(value: Any, mapping: dict[str, str]) -> str:
    return mapping.get(_text(value, "check status").casefold(), "unknown")


def _severity(value: Any) -> str:
    if value is None:
        return "unknown"
    name = _text(value, "severity").casefold()
    name = {"informational": "info", "information": "info"}.get(name, name)
    return name if name in SEVERITIES else "unknown"


def _pointer(*parts: Any) -> str:
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in parts)


def _check(source: str, digest: str, pointer: str, *, check_id: Any, title: Any,
           status: str, severity: Any = None, controls: list[str] | None = None,
           resources: list[str] | None = None) -> dict:
    return {
        "id": _text(check_id, "check ID"),
        "title": _text(title, "check title"),
        "status": status,
        "severity": _severity(severity),
        "control_ids": list(dict.fromkeys(controls or [])),
        "resource_ids": list(dict.fromkeys(resources or [])),
        "evidence_refs": [{"source": source, "input_sha256": digest, "json_pointer": pointer}],
    }


class _PlainTitle(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _scuba_title(value: Any) -> str:
    # Scuba appends an HTML badge div to the requirement in its JSON output.
    title = _text(value, "ScubaGear requirement").split("<div", 1)[0]
    parser = _PlainTitle()
    parser.feed(title)
    return " ".join("".join(parser.parts).split())


def _maester(payload: Any, digest: str) -> tuple[list[dict], list[Any], Any, Any]:
    root = _object(payload, "Maester export")
    if not {"Tests", "TenantId", "CurrentVersion", "ExecutedAt"} <= root.keys():
        raise ValueError("JSON is not a supported Maester results export")
    tests = _list(root.get("Tests"), "Maester Tests")
    context = _optional_object(root.get("MgContext"), "Maester MgContext")
    checks = []
    for index, raw in enumerate(tests):
        row = _object(raw, "Maester test")
        check_id = _text(row.get("Id"), "Maester test ID")
        detail = _optional_object(row.get("ResultDetail"), "Maester ResultDetail")
        resources = []
        for related in _list(detail.get("RelatedObjects", []), "Maester RelatedObjects"):
            related = _object(related, "Maester related object")
            if related.get("Id") is not None:
                resources.append(_text(related["Id"], "related object ID"))
        checks.append(_check(
            "maester", digest, _pointer("Tests", index), check_id=check_id,
            title=row.get("Title"),
            status=_status(row.get("Result"), {"passed": "pass", "failed": "fail", "error": "error"}),
            severity=row.get("Severity"), resources=resources,
            controls=[check_id] if check_id.startswith(("CIS.", "CISA.")) else [],
        ))
    return checks, [root.get("TenantId"), context.get("TenantId")], root.get("CurrentVersion"), root.get("ExecutedAt")


def _scubagear(payload: Any, digest: str) -> tuple[list[dict], list[Any], Any, Any]:
    root = _object(payload, "ScubaGear export")
    metadata = _object(root.get("MetaData"), "ScubaGear MetaData")
    if metadata.get("Tool") != "ScubaGear":
        raise ValueError("JSON is not a ScubaGear consolidated export")
    results = _object(root.get("Results"), "ScubaGear Results")
    checks = []
    for product, groups in results.items():
        for group_index, group in enumerate(_list(groups, "ScubaGear product groups")):
            group = _object(group, "ScubaGear group")
            for index, raw in enumerate(_list(group.get("Controls"), "ScubaGear Controls")):
                row = _object(raw, "ScubaGear control")
                control = _text(row.get("Control ID"), "ScubaGear control ID")
                # N/A means manual/not-implemented/third-party in this writer,
                # rather than proof that the control does not apply.
                status = _status(row.get("Result"), {
                    "pass": "pass", "fail": "fail", "warning": "fail", "error": "error",
                    "not applicable": "not_applicable",
                })
                checks.append(_check(
                    "scubagear", digest, _pointer("Results", product, group_index, "Controls", index),
                    check_id=control, title=_scuba_title(row.get("Requirement")), status=status,
                    controls=[control],
                ))
    return checks, [metadata.get("TenantId")], metadata.get("ToolVersion"), metadata.get("TimestampZulu")


def _monkey365(payload: Any, digest: str) -> tuple[list[dict], list[Any], Any, Any]:
    # PowerShell's pipeline JSON export unwraps a single result object.
    rows = payload if isinstance(payload, list) else [_object(payload, "Monkey365 export")]
    checks, tenant_ids, versions, timestamps = [], [], set(), []
    for index, raw in enumerate(rows):
        row = _object(raw, "Monkey365 finding")
        finding = _object(row.get("findingInfo"), "Monkey365 findingInfo")
        metadata = _object(row.get("metadata"), "Monkey365 metadata")
        product = _object(metadata.get("product"), "Monkey365 product")
        if product.get("name") != "Monkey365":
            raise ValueError("JSON is not a Monkey365 export")
        cloud = _object(row.get("cloud"), "Monkey365 cloud")
        organization = _object(cloud.get("organization"), "Monkey365 organization")
        tenant_ids.append(organization.get("id"))
        # Azure cloud.account.id is a subscription ID, not the tenant ID.
        if str(cloud.get("provider", "")).casefold() in {"microsoft365", "entraid"}:
            tenant_ids.append(_optional_object(cloud.get("account"), "Monkey365 account").get("id"))
        version = _text(product.get("version"), "Monkey365 version", nullable=True)
        if version is not None:
            versions.add(version)
        timestamp = _timestamp(row.get("time"))
        if timestamp:
            timestamps.append(timestamp)
        resource = _optional_object(row.get("resources"), "Monkey365 resources")
        resources = [_text(resource["id"], "Monkey365 resource ID")] if resource.get("id") else []
        checks.append(_check(
            "monkey365", digest, _pointer(index) if isinstance(payload, list) else "",
            check_id=finding.get("id"), title=finding.get("title"), severity=row.get("severity"),
            status=_status(row.get("statusCode"), {"pass": "pass", "fail": "fail", "error": "error"}),
            resources=resources,
        ))
    if len(versions) > 1:
        raise ValueError("Monkey365 export contains conflicting tool versions")
    # No benchmark version/controls are present in the OCSF JSON writer. Do not
    # infer them from titles, severity, plugin IDs or the separate ruleset files.
    return checks, tenant_ids, next(iter(versions), None), max(timestamps, default=None)


def validate_assessment(payload: Any) -> dict:
    """Validate the strict canonical envelope; return it unchanged or raise ValueError."""
    root = _object(payload, "external assessment")
    expected = {"schema_version", "source", "source_version", "tenant_id", "assessed_at", "provenance", "checks"}
    if set(root) != expected or root.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported or malformed external assessment envelope")
    if not isinstance(root.get("source"), str) or root["source"] not in SOURCES:
        raise ValueError("unsupported assessment source")
    _text(root["source_version"], "source_version", nullable=True)
    if _tenant(root["tenant_id"]) != root["tenant_id"]:
        raise ValueError("canonical tenant ID must be a normalized UUID or null")
    _timestamp(root["assessed_at"])
    provenance = _object(root["provenance"], "provenance")
    if set(provenance) != {"input_sha256", "input_name", "identity_source"}:
        raise ValueError("malformed assessment provenance")
    digest = provenance["input_sha256"]
    if not isinstance(digest, str) or not _SHA.fullmatch(digest):
        raise ValueError("invalid input SHA-256")
    name = _text(provenance["input_name"], "input_name")
    if name != Path(name).name or "/" in name or "\\" in name or name in {".", ".."}:
        raise ValueError("input_name must be a filename")
    identity = provenance["identity_source"]
    if not isinstance(identity, str) or identity not in {"source", "operator", "unverified"}:
        raise ValueError("invalid identity_source")
    if (root["tenant_id"] is None) != (identity == "unverified"):
        raise ValueError("tenant identity and provenance disagree")
    fields = {"id", "title", "status", "severity", "control_ids", "resource_ids", "evidence_refs"}
    for check in _list(root["checks"], "checks"):
        check = _object(check, "check")
        if set(check) != fields:
            raise ValueError("malformed canonical check")
        _text(check["id"], "check ID")
        _text(check["title"], "check title")
        if (not isinstance(check["status"], str) or check["status"] not in STATUSES
                or not isinstance(check["severity"], str) or check["severity"] not in SEVERITIES):
            raise ValueError("invalid canonical check status or severity")
        for key in ("control_ids", "resource_ids"):
            for value in _list(check[key], key):
                _text(value, key)
        refs = _list(check["evidence_refs"], "evidence_refs")
        if not refs:
            raise ValueError("every check requires an evidence reference")
        for ref in refs:
            ref = _object(ref, "evidence reference")
            if set(ref) != {"source", "input_sha256", "json_pointer"}:
                raise ValueError("malformed evidence reference")
            if ref["source"] != root["source"] or ref["input_sha256"] != digest:
                raise ValueError("evidence source hash does not match provenance")
            if not isinstance(ref["json_pointer"], str) or not _POINTER.fullmatch(ref["json_pointer"]):
                raise ValueError("invalid JSON pointer")
    return root


def import_assessment(source: str, input_path: str | Path, tenant_id: str | None = None) -> dict:
    """Read one external JSON export without contacting or changing a tenant."""
    source = source.casefold()
    if source not in SOURCES:
        raise ValueError(f"unsupported assessment source: {source}")
    path = Path(input_path)
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("external assessment exceeds 64 MiB")
    raw = path.read_bytes()
    if len(raw) > 64 * 1024 * 1024:
        raise ValueError("external assessment exceeds 64 MiB")
    try:
        # json.loads recognizes PowerShell UTF-8/UTF-16 BOMs as well as UTF-8.
        payload = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("input must be a valid JSON assessment") from exc
    digest = hashlib.sha256(raw).hexdigest()
    parser = {"maester": _maester, "scubagear": _scubagear, "monkey365": _monkey365}[source]
    checks, identities, version, timestamp = parser(payload, digest)
    explicit_ids = {_tenant(value) for value in identities} - {None}
    supplied = _tenant(tenant_id)
    if len(explicit_ids) > 1 or (explicit_ids and supplied and supplied not in explicit_ids):
        raise ValueError("conflicting tenant IDs in source or operator binding")
    identified = next(iter(explicit_ids), supplied)
    return validate_assessment({
        "schema_version": SCHEMA_VERSION, "source": source,
        "source_version": _text(version, "source version", nullable=True),
        "tenant_id": identified, "assessed_at": _timestamp(timestamp),
        "provenance": {
            "input_sha256": digest, "input_name": path.name,
            "identity_source": "source" if explicit_ids else "operator" if supplied else "unverified",
        },
        "checks": checks,
    })
