"""Tenant identity from recorded evidence, never from a display label.

"Verified" means the organization/token tenant observations agree. It does not
authenticate a saved bundle or validate a token signature. Only tenant IDs and
evidence locations are copied into metadata; tokens and other claims stay out.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any
from uuid import UUID


IDENTITY_FIELDS = ("tenant_id", "tenant_id_requested", "tenant_identity")
_AUTHORITIES = {"common", "organizations", "consumers"}
_MIRROR_SURFACES = {
    "run-manifest.json", "summary.json", "reports/report-pack.json#/summary",
    "ai_context.json#/run", "index/evidence.sqlite#run_meta",
}


def canonical_tenant_uuid(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = UUID(value.strip())
    except ValueError:
        return None
    return str(parsed) if parsed.int else None


def _text(value: Any) -> str | None:
    return (value.strip() or None) if isinstance(value, str) else None


def _domain(value: Any) -> str | None:
    text = (_text(value) or "").rstrip(".").lower()
    return text if re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*", text) else None


def _read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _rows(section: Any) -> list[dict[str, Any]]:
    if not isinstance(section, dict) or section.get("error"):
        return []
    values = section.get("value", section.get("records", []))
    return [row for row in values if isinstance(row, dict)] if isinstance(values, list) else []


def _observations(run_dir: Path, auth_path: Any = None) -> tuple[list[dict[str, Any]], set[str], bool, list[tuple[str, Any]]]:
    observations: list[dict[str, Any]] = []
    domains: set[str] = set()
    complete_domains = False
    requests: list[tuple[str, Any]] = []

    def observe(value: Any, path: str, pointer: str, source: str) -> None:
        tenant_id = canonical_tenant_uuid(value)
        if tenant_id:
            observations.append({"tenant_id": tenant_id, "source": source, "artifact_path": path, "json_pointer": pointer})

    payloads = [(f"raw/{name}.json", "", _read(run_dir / "raw" / f"{name}.json")) for name in ("identity", "domains_hybrid")]
    sample = _read(run_dir / "raw" / "sample_input.json")
    payloads.extend(("raw/sample_input.json", f"/{name}", sample.get(name, {})) for name in ("identity", "domains_hybrid"))
    for path, prefix, payload in payloads:
        if not isinstance(payload, dict):
            continue
        section = payload.get("organization")
        row_key = "records" if isinstance(section, dict) and "value" not in section else "value"
        organization_rows = section.get(row_key, []) if isinstance(section, dict) and not section.get("error") else []
        for index, row in enumerate(organization_rows if isinstance(organization_rows, list) else []):
            if not isinstance(row, dict):
                continue
            observe(row.get("id"), path, f"{prefix}/organization/{row_key}/{index}/id", "organization")
            if canonical_tenant_uuid(row.get("id")) and isinstance(row.get("verifiedDomains"), list):
                complete_domains = True
                domains.update(domain for item in row["verifiedDomains"] if isinstance(item, dict) and (domain := _domain(item.get("name"))))
        domain_section = payload.get("domains")
        domain_rows = _rows(domain_section)
        if domain_rows:
            domains.update(domain for item in domain_rows if item.get("isVerified") is True and (domain := _domain(item.get("id"))))
            if not domain_section.get("sample_truncated") and not domain_section.get("@odata.nextLink"):
                count = domain_section.get("item_count", len(domain_rows))
                if isinstance(count, int) and count == len(domain_rows):
                    complete_domains = True

    auth_paths = {"normalized/auth_context.json", "auth-context.json"}
    if isinstance(auth_path, str):
        candidate = run_dir / auth_path
        if candidate.resolve().is_relative_to(run_dir.resolve()):
            auth_paths.add(str(candidate.resolve().relative_to(run_dir.resolve())))
    for path in sorted(auth_paths):
        auth = _read(run_dir / path)
        requests.append((f"{path}#/tenant_id", auth.get("tenant_id")))
        claims = auth.get("token_claims")
        if isinstance(claims, dict):
            for key in ("tenant_id", "tid"):
                observe(claims.get(key), path, f"/token_claims/{key}", "token_tenant_claim")
    return observations, domains, complete_domains, requests


def resolve_tenant_identity(
    run_dir: Path,
    *,
    platform: str = "m365",
    requested: Any = None,
    metadata: Mapping[str, Any] | None = None,
    additional_requests: Iterable[tuple[str, Any]] = (),
) -> dict[str, Any]:
    metadata = metadata or {}
    requested = _text(requested)
    identity: dict[str, Any] = {"status": "unknown", "kind": "entra_tenant_id", "sources": [], "conflicts": []}
    fields: dict[str, Any] = {"tenant_id": None, "tenant_id_requested": requested, "tenant_identity": identity}
    if platform != "m365":
        # Google customer IDs and workspace domains are not Entra UUIDs. In
        # particular, my_customer is an auth-relative alias, not a tenant ID.
        customer_id = _text(metadata.get("customer_id")) or requested
        identity["kind"] = "google_customer_id" if platform == "google_workspace" else "provider_identifier"
        identity["domain"] = _domain(metadata.get("workspace_domain"))
        if customer_id and customer_id != "my_customer" and not _domain(customer_id):
            fields["tenant_id"] = customer_id
            identity["status"] = "provider_identifier"
        identity["reason"] = "provider_identifier_not_verified"
        return fields

    sources, domains, complete_domains, requests = _observations(run_dir, metadata.get("auth_context_path"))
    identity["sources"] = sources
    if _domain(requested):
        identity["domain"] = _domain(requested)
    ids = {row["tenant_id"] for row in sources}
    conflicts = identity["conflicts"]
    if len(ids) > 1:
        conflicts.append({"code": "observed_tenant_ids_disagree", "tenant_ids": sorted(ids)})
    requested_match = "not_requested" if requested is None else "unknown"
    for source, value in [("requested", requested), *requests, *additional_requests]:
        request_id = canonical_tenant_uuid(value)
        request_domain = _domain(value)
        match = "unknown"
        if request_id and ids:
            match = "matched" if ids == {request_id} else "mismatch"
        elif request_domain and domains:
            match = "matched" if request_domain in domains else "mismatch" if complete_domains else "unknown"
        elif _text(value) in _AUTHORITIES:
            match = "authority_alias"
        if match == "mismatch":
            conflicts.append({"code": "requested_tenant_mismatch", "source": source, "requested": _text(value)})
        if source == "requested" and requested is not None:
            requested_match = match
    identity["requested_match"] = requested_match
    if conflicts:
        identity["status"] = "conflict"
        identity["reason"] = "inconsistent_tenant_evidence"
    elif isinstance(metadata.get("fixture_provenance"), Mapping) and metadata["fixture_provenance"].get("synthetic"):
        identity["reason"] = "synthetic_fixture"
    elif len(ids) == 1:
        fields["tenant_id"] = next(iter(ids))
        identity["status"] = "verified"
    else:
        identity["reason"] = "no_observed_uuid"
    return fields


def decode_identity_metadata(values: Mapping[str, Any]) -> dict[str, Any]:
    """Decode just the identity fields in SQLite run_meta (all values are text)."""
    result = {key: values[key] or None for key in IDENTITY_FIELDS if key in values}
    if isinstance(result.get("tenant_identity"), str):
        try:
            result["tenant_identity"] = json.loads(result["tenant_identity"])
        except ValueError:
            pass
    return result


def reconcile_tenant_identity(
    run_dir: Path,
    surfaces: Mapping[str, Mapping[str, Any]],
    *,
    platform: str = "m365",
) -> dict[str, Any]:
    """Resolve evidence and detect contradictory saved metadata, including an old index.

    Legacy UUIDs remain established identifiers but are explicitly unverified
    without organization/token evidence. Domain aliases never become UUIDs.
    """
    primary = next(iter(surfaces.values()), {})
    mirror = next((data for data in surfaces.values() if isinstance(data.get("tenant_identity"), Mapping)), None)
    requested = primary.get("tenant_id_requested") if "tenant_id_requested" in primary else primary.get("tenant_id")
    if not requested and "tenant_id_requested" not in primary:
        requested = next((data.get("tenant_id") for data in surfaces.values() if data.get("tenant_id")), None)
    fields = resolve_tenant_identity(
        run_dir, platform=platform, requested=requested, metadata=primary,
        additional_requests=[(f"{path}#/tenant_id", data.get("tenant_id")) for path, data in surfaces.items()],
    )
    identity = fields["tenant_identity"]
    conflicts = identity["conflicts"]
    declared_ids: set[str] = set()
    legacy_ids: set[str] = set()
    for path, data in surfaces.items():
        if data.get("tenant_id") is not None and not isinstance(data["tenant_id"], str):
            conflicts.append({"code": "invalid_tenant_id_type", "source": path})
        value = _text(data.get("tenant_id"))
        canonical = canonical_tenant_uuid(value) if platform == "m365" else (
            value if value != "my_customer" and not _domain(value) else None
        )
        if canonical:
            declared_ids.add(canonical)
        elif value and not _domain(value) and value not in _AUTHORITIES and value != "my_customer":
            legacy_ids.add(value)
        recorded = data.get("tenant_identity")
        if recorded is not None:
            if not isinstance(recorded, Mapping):
                conflicts.append({"code": "invalid_identity_metadata", "source": path})
            elif recorded.get("status") == "conflict":
                conflicts.append({"code": "recorded_identity_conflict", "source": path})
            elif recorded.get("status") == "verified" and (not canonical or value != canonical):
                conflicts.append({"code": "invalid_verified_tenant_id", "source": path})
            elif recorded.get("status") == "verified" and not identity["sources"]:
                conflicts.append({"code": "verified_identity_without_evidence", "source": path})
            elif recorded.get("status") == "verified" and recorded.get("sources") != identity["sources"]:
                conflicts.append({"code": "identity_sources_mismatch", "source": path})
            elif recorded.get("status") == "verified" and identity["status"] != "verified":
                conflicts.append({"code": "identity_evidence_mismatch", "source": path})
            elif recorded.get("status") == "unknown" and value:
                conflicts.append({"code": "unknown_identity_with_tenant_id", "source": path})
            elif recorded.get("status") == "unknown" and identity["status"] == "verified":
                conflicts.append({"code": "identity_evidence_mismatch", "source": path})
            elif recorded.get("status") not in {"verified", "unknown", "legacy_unverified", "provider_identifier"}:
                conflicts.append({"code": "invalid_identity_status", "source": path})
        if mirror is not None:
            for key in IDENTITY_FIELDS:
                if (key in data or path in _MIRROR_SURFACES) and (key not in data or data[key] != mirror.get(key)):
                    conflicts.append({"code": "identity_metadata_mismatch", "source": path, "field": key})

    observed_ids = {row["tenant_id"] for row in identity["sources"]}
    if len(declared_ids | observed_ids) > 1:
        conflicts.append({"code": "metadata_tenant_ids_disagree", "tenant_ids": sorted(declared_ids | observed_ids)})
    if len(legacy_ids) > 1:
        conflicts.append({"code": "legacy_identifiers_disagree"})
    if platform == "m365" and legacy_ids and (declared_ids or observed_ids):
        conflicts.append({"code": "non_uuid_metadata_identity"})
    if conflicts:
        fields["tenant_id"] = None
        identity["status"] = "conflict"
        identity["reason"] = "inconsistent_tenant_evidence"
    elif identity["status"] == "unknown" and identity.get("reason") != "synthetic_fixture":
        if declared_ids or legacy_ids:
            fields["tenant_id"] = next(iter(declared_ids or legacy_ids))
            identity["status"] = "legacy_unverified"
            if legacy_ids and not declared_ids:
                identity["kind"] = "legacy_identifier"
    return fields
