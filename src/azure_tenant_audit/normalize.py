from __future__ import annotations

from collections import Counter
from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import date, datetime
from pathlib import Path
import re
from typing import Any

from . import break_glass
from . import endpoint_posture
from . import exchange_protection
from . import external_sharing
from .chunk_reader import iter_endpoint_records
from .collection_gaps import (
    BOUNDED_SAMPLE_SECTION,
    COLLECTION_GAP_SECTION,
    REASON_OPERATOR_LIMIT,
    REASON_UNKNOWN,
    bounded_sample_records,
    collection_gap_records,
    event_span,
    list_truncations,
    truncations_from_payloads,
)
from .data_minimisation import minimise_mailbox_settings
from .detection_coverage import build_detection_signals
from .directory_relationships import normalize_directory_relationships
from .effective_admins import (
    SECTION as EFFECTIVE_ADMIN_SECTION,
    AdminSetEvidence,
    admin_scope as build_admin_scope,
    build_effective_admin_set,
)
from .friendly_names import build_friendly_name_catalog
from .identity_controls import (
    EVIDENCE_ABSENT,
    EVIDENCE_BLOCKED,
    EVIDENCE_COLLECTED,
    EVIDENCE_TRUNCATED,
    KIND as IDENTITY_CONTROL_KIND,
    SECTION as IDENTITY_CONTROL_SECTION,
    Evidence,
    compact_targeting,
    evaluate_administrator_mfa,
    evaluate_effective_mfa,
    evaluate_legacy_authentication_block,
    evaluate_user_consent,
    policy_targeting,
)


# Detection coverage is assessed for Microsoft 365 runs that collected any of these surfaces.
_DETECTION_SOURCE_COLLECTORS = (
    "identity",
    "security",
    "conditional_access",
    "defender",
    "sentinel_xdr",
    "identity_protection",
    "exchange_policy",
)

def _values(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    section = payload.get(key, {})
    values = section.get("value", []) if isinstance(section, dict) else []
    if isinstance(values, list):
        return [item for item in values if isinstance(item, dict)]
    return []


def _latest_endpoint_coverage(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A resumed endpoint replaces its earlier observation, not its row count."""
    latest = {}
    for row in rows:
        if isinstance(row, dict):
            key = (str(row.get("collector") or ""), str(row.get("name") or ""),
                   str(row.get("endpoint") or row.get("command") or ""))
            latest[key] = row
    return list(latest.values())


class _NormalizationSources:
    """Run-scoped reads and completeness accounting, without caching full raw rows."""

    def __init__(
        self,
        payloads: dict[str, dict[str, Any]],
        run_dir: Path | None,
        coverage_rows: list[dict[str, Any]],
    ) -> None:
        self.payloads = payloads
        self.run_dir = run_dir
        self.collector_names = {id(payload): name for name, payload in payloads.items()}
        self.coverage: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in _latest_endpoint_coverage(coverage_rows):
            self.coverage[(str(row.get("collector") or ""), str(row.get("name") or ""))].append(row)
        self.reports: dict[str, dict[str, Any]] = {}

    @staticmethod
    def is_endpoint(section: Any) -> bool:
        return isinstance(section, dict) and any(
            key in section for key in ("value", "chunk_files", "sample_truncated", "item_count")
        )

    def values(self, payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
        section = payload.get(key) if isinstance(payload, dict) else None
        if not self.is_endpoint(section):
            return []
        collector = self.collector_names.get(id(payload), "unknown")
        effective_section = dict(section)
        coverage = self.coverage.get((collector, key), [])
        # A fan-out can have many coverage rows counting nested members rather
        # than its wrapper records. Only a single paged endpoint is comparable.
        if len(coverage) == 1 and ("chunk_files" in section or section.get("sample_truncated")):
            if effective_section.get("item_count") is None and coverage[0].get("item_count") is not None:
                effective_section["item_count"] = coverage[0]["item_count"]
        issues: list[dict[str, Any]] = []
        rows = list(iter_endpoint_records(effective_section, self.run_dir, issues=issues))
        if len(coverage) == 1 and "chunk_files" in section:
            count = coverage[0].get("item_count")
            if type(count) is int and count != len(rows):
                issues.append({"code": "coverage_count_mismatch", "expected_count": count, "observed_count": len(rows)})

        result_limit = section.get("result_limit")
        if result_limit is None and len(coverage) == 1:
            result_limit = coverage[0].get("result_limit")
        try:
            limit = max(int(result_limit or 0), 0)
        except (TypeError, ValueError):
            limit = 0
        count = effective_section.get("item_count")
        collected_count = count if type(count) is int and count >= 0 else len(rows)
        truncated = section.get("collection_truncated")
        if isinstance(truncated, bool):
            # The collector knew whether the list continued; a limit that equals the list's length is not a cut.
            collection_limited = truncated
        else:
            collection_limited = bool(section.get("collection_limit_reached") or (limit and collected_count >= limit))
        truncation_reason = None
        if collection_limited:
            truncation_reason = section.get("truncation_reason")
            if truncation_reason is None and len(coverage) == 1:
                truncation_reason = coverage[0].get("truncation_reason")
            truncation_reason = str(truncation_reason or (REASON_OPERATOR_LIMIT if limit else REASON_UNKNOWN))
        source_failed = bool(section.get("error")) or any(row.get("status") == "failed" for row in coverage)
        source = f"{collector}.{key}"
        previous = self.reports.get(source)
        if previous:
            if previous["record_count"] != len(rows):
                issues.append({"code": "inconsistent_endpoint_read"})
            issues.extend(issue for issue in previous["issues"] if issue not in issues)
        self.reports[source] = {
            "key": f"normalization:{source}",
            "collector": collector,
            "source_name": key,
            "source": source,
            "storage": "chunks" if section.get("chunk_files") else "inline",
            "record_count": len(rows),
            "expected_count": count,
            "sample_count": len(section["value"]) if isinstance(section.get("value"), list) else 0,
            "complete": not issues,
            "status": "partial" if issues else "complete",
            "collection_status": "failed" if source_failed else "limited" if collection_limited else "collected",
            "collection_limited": collection_limited,
            "truncation_reason": truncation_reason,
            "derived_fanout": isinstance(section.get("fanout"), dict),
            "result_limit": limit or None,
            "issues": issues,
        }
        return rows

    def endpoint_evidence(self, payload: dict[str, Any], key: str, *, singleton: bool = False) -> Evidence:
        """How completely one endpoint was collected, for analyses that must not guess.

        ``singleton`` endpoints return one object, which Graph may deliver bare or wrapped in
        ``value``; every other endpoint must be a collection.
        """
        section = payload.get(key) if isinstance(payload, dict) else None
        if not isinstance(section, dict):
            return Evidence(EVIDENCE_ABSENT)
        if section.get("error"):
            return Evidence(EVIDENCE_BLOCKED, detail=str(section.get("error_class") or "error"))
        if not self.is_endpoint(section):
            if singleton and section:
                return Evidence(EVIDENCE_COLLECTED, (section,))
            return Evidence(EVIDENCE_ABSENT)
        rows = tuple(self.values(payload, key))
        report = self.reports.get(f"{self.collector_names.get(id(payload), 'unknown')}.{key}") or {}
        if report.get("collection_limited"):
            return Evidence(EVIDENCE_TRUNCATED, rows, "collection_limit_reached")
        if report.get("complete") is False:
            return Evidence(EVIDENCE_TRUNCATED, rows, "incomplete_read")
        return Evidence(EVIDENCE_COLLECTED, rows)

    def analysis_payloads(self, collectors: tuple[str, ...]) -> dict[str, dict[str, Any]]:
        """Temporary complete views for analyses that consume raw-shaped sections."""
        result: dict[str, dict[str, Any]] = {}
        for collector in collectors:
            payload = self.payloads.get(collector)
            if not isinstance(payload, dict):
                continue
            result[collector] = {}
            for name, section in payload.items():
                if not self.is_endpoint(section):
                    result[collector][name] = section
                    continue
                view = {**section, "value": self.values(payload, name)}
                view.pop("chunk_files", None)
                report = self.reports[f"{collector}.{name}"]
                incomplete = not report["complete"] or report["collection_limited"]
                view["sample_truncated"] = incomplete
                if incomplete and not view.get("error"):
                    view["error"] = "Endpoint evidence is incomplete."
                    view["error_class"] = "incomplete_evidence"
                result[collector][name] = view
        return result

    def friendly_names(self, records: dict[str, list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], int]:
        catalog, warnings = build_friendly_name_catalog(records)
        entries = {row["key"]: row for row in catalog}
        # The legacy catalog loader accepts arbitrary paths. Supply already
        # checked rows and no run_dir so it never reopens unvalidated chunks.
        # Loading one endpoint at a time also avoids retaining a full raw copy
        # of every collector alongside the normalized snapshot.
        for collector, payload in sorted(self.payloads.items()):
            if not isinstance(payload, dict):
                continue
            for name, section in payload.items():
                view = section
                if self.is_endpoint(section):
                    view = {**section, "value": self.values(payload, name)}
                    view.pop("chunk_files", None)
                extra, missing = build_friendly_name_catalog({}, collector_payloads={collector: {name: view}})
                warnings += missing
                for row in extra:
                    entries.setdefault(row["key"], row)
        return [entries[key] for key in sorted(entries)], warnings


def _secure_score_control_scores(value: Any) -> list[dict[str, Any]]:
    """Keep only the per-control numbers needed for Secure Score reconciliation."""
    if not isinstance(value, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or not item.get("controlName"):
            continue
        rows.append(
            {
                key: field
                for key, field in {
                    "control_name": str(item.get("controlName")),
                    "control_category": item.get("controlCategory"),
                    "score": item.get("score"),
                    "score_in_percentage": item.get("scoreInPercentage"),
                    "implementation_status": item.get("implementationStatus"),
                }.items()
                if field not in (None, "")
            }
        )
    return sorted(rows, key=lambda row: row["control_name"])


def _compact(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if value not in (None, [], {}, "")}


def _record(kind: str, source: str, object_id: str, **fields: Any) -> dict[str, Any]:
    payload = {
        "kind": kind,
        "source": source,
        "id": object_id,
        "key": f"{kind}:{object_id}",
    }
    payload.update(fields)
    return _compact(payload)


def _ordered_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _ordered_value(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        normalized = [_ordered_value(item) for item in value]
        if normalized and all(isinstance(item, dict) for item in normalized):
            return sorted(
                normalized,
                key=lambda item: (
                    str(item.get("key") or ""),
                    str(item.get("id") or ""),
                    str(item.get("display_name") or item.get("title") or ""),
                ),
            )
        return normalized
    return value


def _canonical_count_key(name: str) -> str:
    text = re.sub(r"(?<!^)(?=[A-Z])", "_", str(name or "")).replace("-", "_").lower()
    return text.strip("_")


def _collector_count_summaries(
    collector_payloads: dict[str, Any],
    coverage_rows: list[dict[str, Any]],
) -> tuple[dict[str, int], dict[str, int], dict[str, int], list[str], dict[str, list[str]]]:
    full_counts: dict[str, int] = {}
    sample_counts: dict[str, int] = {}
    chunk_counts: dict[str, int] = {}
    truncated_sections: list[str] = []
    chunk_paths: dict[str, list[str]] = {}

    coverage_counts: dict[tuple[str, str], int] = defaultdict(int)
    for row in _latest_endpoint_coverage(coverage_rows):
        key = _canonical_count_key(str(row.get("name") or ""))
        if not key:
            continue
        count = row.get("item_count")
        if type(count) is int and count >= 0:
            coverage_counts[(str(row.get("collector") or ""), key)] += count
    for (_collector, key), count in coverage_counts.items():
        # Different collectors can inventory the same objects. This legacy
        # surface is a per-source maximum, never a unique union of identities.
        full_counts[key] = max(full_counts.get(key, 0), count)

    for payload in collector_payloads.values():
        if not isinstance(payload, dict):
            continue
        for name, section in payload.items():
            key = _canonical_count_key(str(name))
            if not key or not isinstance(section, dict):
                continue
            values = section.get("value")
            if isinstance(values, list):
                sample_counts[key] = max(sample_counts.get(key, 0), len(values))
            if type(section.get("item_count")) is int:
                full_counts[key] = max(full_counts.get(key, 0), int(section["item_count"]))
            if section.get("sample_truncated"):
                truncated_sections.append(key)
            raw_chunk_files = section.get("chunk_files")
            if isinstance(raw_chunk_files, list):
                clean_chunk_files = [str(item) for item in raw_chunk_files if isinstance(item, str)]
                if clean_chunk_files:
                    chunk_paths.setdefault(key, []).extend(clean_chunk_files)
                    chunk_counts[key] = chunk_counts.get(key, 0) + len(clean_chunk_files)

    return (
        dict(sorted(full_counts.items())),
        dict(sorted(sample_counts.items())),
        dict(sorted(chunk_counts.items())),
        sorted(set(truncated_sections)),
        {key: sorted(set(value)) for key, value in sorted(chunk_paths.items())},
    )


def _build_index(items: list[dict[str, Any]], key: str = "id") -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for item in items:
        item_id = item.get(key)
        if isinstance(item_id, str) and item_id:
            index[item_id] = item
    return index


def _to_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int)) or item is not None]


def _ensure_placeholder_skipped(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        if value.lower() in {"all", "none", "unknownfuturevalue", "allusers", "all_guests"}:
            continue
        normalized.append(value)
    return normalized


def _iter_permission_targets(permission: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    targets: list[tuple[str, dict[str, Any]]] = []
    granted_v2 = permission.get("grantedToIdentitiesV2")
    if isinstance(granted_v2, list):
        identity_items = granted_v2
    else:
        identity_items = []
        granted_to_v2 = permission.get("grantedToV2")
        if isinstance(granted_to_v2, dict):
            identity_items = [granted_to_v2]

    for item in identity_items:
        if not isinstance(item, dict):
            continue
        for target_type in ("user", "group", "application", "siteUser", "device"):
            target = item.get(target_type)
            if isinstance(target, dict):
                targets.append((target_type, target))
                break
    return targets


def _first_non_empty(item: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key not in item:
            continue
        value = item.get(key)
        if value is not None and value != "":
            return value
    return None


def _site_kind_from_web_url(web_url: Any) -> str:
    url = str(web_url or "").lower()
    if "-my.sharepoint.com" in url:
        return "personal"
    if "/sites/" in url or "/teams/" in url:
        return "team"
    return "other"


def _site_permission_summary(
    item: dict[str, Any],
    *,
    default_sharing_capability: Any = None,
) -> dict[str, Any]:
    permissions = item.get("permissions")
    if not isinstance(permissions, list):
        permissions = []

    user_targets: set[str] = set()
    group_targets: set[str] = set()
    application_targets: set[str] = set()
    link_permission_count = 0
    anonymous_link_count = 0
    organization_link_count = 0
    write_like_permission_count = 0

    for permission in permissions:
        if not isinstance(permission, dict):
            continue

        raw_roles = permission.get("roles")
        roles = [str(role).lower() for role in raw_roles if role is not None] if isinstance(raw_roles, list) else []
        if any(role not in {"read", "view"} for role in roles):
            write_like_permission_count += 1

        link = permission.get("link") if isinstance(permission.get("link"), dict) else {}
        link_scope = str(link.get("scope") or "").lower()
        if link_scope:
            link_permission_count += 1
            if link_scope == "anonymous":
                anonymous_link_count += 1
            elif link_scope == "organization":
                organization_link_count += 1

        for target_type, target in _iter_permission_targets(permission):
            target_id = str(target.get("id") or target.get("userPrincipalName") or target.get("displayName") or "")
            if not target_id:
                continue
            if target_type == "user":
                user_targets.add(target_id)
            elif target_type == "group":
                group_targets.add(target_id)
            elif target_type == "application":
                application_targets.add(target_id)

    permission_count = _first_non_empty(item, "permissionCount", "permission_count")
    if permission_count is None:
        permission_count = len(permissions)
    else:
        permission_count = int(permission_count)

    principal_count = _first_non_empty(item, "principalCount", "principal_count")
    if principal_count is None:
        principal_count = len(user_targets | group_targets | application_targets)
    else:
        principal_count = int(principal_count)

    user_principal_count = _first_non_empty(item, "userPrincipalCount", "user_principal_count")
    if user_principal_count is None:
        user_principal_count = len(user_targets)
    else:
        user_principal_count = int(user_principal_count)

    group_principal_count = _first_non_empty(item, "groupPrincipalCount", "group_principal_count")
    if group_principal_count is None:
        group_principal_count = len(group_targets)
    else:
        group_principal_count = int(group_principal_count)

    application_principal_count = _first_non_empty(item, "applicationPrincipalCount", "application_principal_count")
    if application_principal_count is None:
        application_principal_count = len(application_targets)
    else:
        application_principal_count = int(application_principal_count)

    link_permission_count_value = _first_non_empty(item, "linkPermissionCount", "link_permission_count")
    if link_permission_count_value is None:
        link_permission_count_value = link_permission_count
    else:
        link_permission_count_value = int(link_permission_count_value)

    anonymous_link_count_value = _first_non_empty(item, "anonymousLinkCount", "anonymous_link_count")
    if anonymous_link_count_value is None:
        anonymous_link_count_value = anonymous_link_count
    else:
        anonymous_link_count_value = int(anonymous_link_count_value)

    organization_link_count_value = _first_non_empty(item, "organizationLinkCount", "organization_link_count")
    if organization_link_count_value is None:
        organization_link_count_value = organization_link_count
    else:
        organization_link_count_value = int(organization_link_count_value)

    write_like_permission_count_value = _first_non_empty(item, "writeLikePermissionCount", "write_like_permission_count")
    if write_like_permission_count_value is None:
        write_like_permission_count_value = write_like_permission_count
    else:
        write_like_permission_count_value = int(write_like_permission_count_value)

    site_kind = _first_non_empty(item, "siteKind", "site_kind")
    if isinstance(site_kind, str) and site_kind:
        site_kind = site_kind.lower()
    else:
        site_kind = _site_kind_from_web_url(_first_non_empty(item, "webUrl", "web_url"))

    sharing_capability = _first_non_empty(item, "sharingCapability", "sharing_capability")
    if sharing_capability is None:
        sharing_capability = default_sharing_capability

    ownership_state = _first_non_empty(item, "ownershipState", "ownership_state")
    if not ownership_state:
        if permission_count:
            if principal_count == 0:
                ownership_state = "orphaned"
            elif principal_count <= 1:
                ownership_state = "weak"
            else:
                ownership_state = "sampled"
        else:
            ownership_state = "unknown"

    return {
        "site_kind": site_kind,
        "sharing_capability": sharing_capability,
        "permission_count": permission_count,
        "principal_count": principal_count,
        "user_principal_count": user_principal_count,
        "group_principal_count": group_principal_count,
        "application_principal_count": application_principal_count,
        "link_permission_count": link_permission_count_value,
        "anonymous_link_count": anonymous_link_count_value,
        "organization_link_count": organization_link_count_value,
        "write_like_permission_count": write_like_permission_count_value,
        "ownership_state": ownership_state,
    }


def _resolve_reference(
    reference_type: str,
    reference_id: str,
    indices: dict[str, dict[str, dict[str, Any]]],
) -> tuple[dict[str, Any] | None, str]:
    index = indices.get(reference_type, {})
    record = index.get(reference_id)
    if record is None:
        # Many policy surfaces are identity IDs but sometimes carry app IDs.
        app_alt = index.get(reference_id.lower())
        if app_alt is not None:
            record = app_alt
    if record is None:
        return None, "unresolved"
    return record, "resolved"


def _normalize_mfa_registration(user_registration_rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not user_registration_rows:
        return {
            "sampled_users": 0,
            "mfa_registered": 0,
            "mfa_not_registered": 0,
            "data": "unavailable",
        }
    mfa_registered = sum(1 for row in user_registration_rows if bool(row.get("isMfaRegistered")))
    total = len(user_registration_rows)
    return {
        "sampled_users": total,
        "mfa_registered": mfa_registered,
        "mfa_not_registered": max(total - mfa_registered, 0),
        "data": "sampled",
    }


def _extract_conditional_access_reference(
    *,
    references: dict[str, list[str]],
    target_type: str,
    source_id: str,
    resolved_target: dict[str, Any] | None,
    target_id: str,
    direction: str,
    relationship_type: str,
    indices: dict[str, dict[str, dict[str, Any]]],
) -> dict[str, Any]:
    if resolved_target:
        target_name = resolved_target.get("displayName") or resolved_target.get("name")
        if not target_name:
            target_name = resolved_target.get("appId") or resolved_target.get("id")
        status = "resolved"
    else:
        target_name = None
        status = "unresolved"
    reference_key = f"{source_id}:{direction}:{target_type}:{target_id}:{relationship_type}"
    if reference_key in references.get("edges", []):
        return {}
    references.setdefault("edges", [])
    references["edges"].append(reference_key)
    return {
        "kind": "relationship",
        "source_type": "conditional_access_policy",
        "source_id": source_id,
        "relationship_type": relationship_type,
        "direction": direction,
        "target_type": target_type,
        "target_id": target_id,
        "target_name": target_name,
        "resolution": status,
    }


def _disambiguate_keys(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Policies of different types can share an Identity (e.g. "Global"); qualify only the colliding keys."""
    counts: dict[str, int] = {}
    for record in records:
        counts[str(record.get("key"))] = counts.get(str(record.get("key")), 0) + 1
    result = []
    for record in records:
        if counts[str(record.get("key"))] > 1 and record.get("source_name"):
            object_id = f"{record['source_name']}:{record.get('id')}"
            record = {**record, "id": object_id, "key": f"{record.get('kind')}:{object_id}"}
        result.append(record)
    return result


def _keyed_relationship(record: dict[str, Any]) -> dict[str, Any]:
    """Give a Conditional Access relationship a stable id/key so evidence refs can cite it."""
    if record.get("key"):
        return record
    relationship_id = ":".join(
        str(record.get(field) or "")
        for field in ("source_id", "direction", "target_type", "target_id", "relationship_type")
    )
    return {**record, "id": relationship_id, "key": f"conditional_access_relationship:{relationship_id}"}


def _build_conditional_access_graph(
    policies: list[dict[str, Any]],
    identity_payload: dict[str, Any],
    named_locations: list[dict[str, Any]],
    auth_strengths: list[dict[str, Any]],
    auth_contexts: list[dict[str, Any]],
    auth_methods_payload: dict[str, Any],
    values: Callable[[dict[str, Any], str], list[dict[str, Any]]] = _values,
    break_glass_accounts: Sequence[str] = (),
    admin_rows: Sequence[dict[str, Any]] = (),
    membership_edges: Sequence[dict[str, Any]] = (),
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
    list[dict[str, Any]],
    dict[str, Any] | None,
    break_glass.BreakGlassAccounts,
]:
    """The Conditional Access graph, its findings, the break-glass assessment and the emergency-access accounts.

    ``values`` reads each endpoint in full (the chunk files, not the inline sample). The accounts are resolved here,
    once, against those full lists, and the identity control verdicts use this same resolution.
    """
    users = values(identity_payload, "users")
    groups = values(identity_payload, "groups")
    role_definitions = values(identity_payload, "roleDefinitions")
    role_assignments = values(identity_payload, "roleAssignments")
    applications = values(identity_payload, "applications")
    service_principals = values(identity_payload, "servicePrincipals")

    indices: dict[str, dict[str, dict[str, Any]]] = {
        "group": _build_index(groups),
        "role_definition": _build_index(role_definitions),
        "application": _build_index(applications),
        "service_principal": _build_index(service_principals),
        "user": _build_index(users),
        "named_location": _build_index(named_locations),
        "auth_strength": _build_index(auth_strengths),
        "auth_context": _build_index(auth_contexts),
        "service_principal_app_id": {item.get("appId"): item for item in service_principals if item.get("appId")},
    }

    mfa_stats = _normalize_mfa_registration(values(auth_methods_payload, "userRegistrationDetails"))
    accounts = break_glass.resolve_accounts(
        break_glass_accounts,
        users=users,
        groups=groups,
        role_assignments=role_assignments,
        role_definitions=role_definitions,
        admin_rows=admin_rows,
        membership_edges=membership_edges,
    )
    break_glass_flagged: list[dict[str, Any]] = []
    break_glass_in_scope = 0

    reference_tracker: dict[str, list[str]] = {}
    graph_records: list[dict[str, Any]] = []
    relationship_records: list[dict[str, Any]] = []
    policy_findings: list[dict[str, Any]] = []

    for policy in policies:
        policy_id = str(policy.get("id"))
        if not policy_id:
            continue

        policy_state = str(policy.get("state", "") or "")
        conditions = policy.get("conditions") if isinstance(policy.get("conditions"), dict) else {}
        grant = policy.get("grantControls") if isinstance(policy.get("grantControls"), dict) else {}
        included_users = _ensure_placeholder_skipped(_to_str_list((conditions.get("users") or {}).get("includeUsers") if isinstance(conditions.get("users"), dict) else conditions.get("users")))
        excluded_users = _ensure_placeholder_skipped(_to_str_list((conditions.get("users") or {}).get("excludeUsers") if isinstance(conditions.get("users"), dict) else conditions.get("users")))
        included_groups = _ensure_placeholder_skipped(_to_str_list((conditions.get("users") or {}).get("includeGroups") if isinstance(conditions.get("users"), dict) else []))
        excluded_groups = _ensure_placeholder_skipped(_to_str_list((conditions.get("users") or {}).get("excludeGroups") if isinstance(conditions.get("users"), dict) else []))
        included_apps = _ensure_placeholder_skipped(_to_str_list((conditions.get("applications") or {}).get("includeApplications") if isinstance(conditions.get("applications"), dict) else []))
        excluded_apps = _ensure_placeholder_skipped(_to_str_list((conditions.get("applications") or {}).get("excludeApplications") if isinstance(conditions.get("applications"), dict) else []))
        include_locations = _ensure_placeholder_skipped(_to_str_list((conditions.get("locations") or {}).get("includeLocations") if isinstance(conditions.get("locations"), dict) else []))
        exclude_locations = _ensure_placeholder_skipped(_to_str_list((conditions.get("locations") or {}).get("excludeLocations") if isinstance(conditions.get("locations"), dict) else []))
        grant_strength = grant.get("authenticationStrength") if isinstance(grant, dict) else None
        include_auth_strengths = _ensure_placeholder_skipped(
            [str(grant_strength["id"])] if isinstance(grant_strength, dict) and grant_strength.get("id") else []
        )

        built_in_controls = _to_str_list(grant.get("builtInControls") if isinstance(grant, dict) else grant.get("builtInControls"))
        built_in_controls = [str(item).lower() for item in built_in_controls]
        requires_mfa = "mfa" in built_in_controls

        for user_id in included_users:
            record, status = _resolve_reference("user", user_id, indices)
            if status == "resolved":
                relationship_records.append(
                    _extract_conditional_access_reference(
                        references=reference_tracker,
                        target_type="user",
                        source_id=policy_id,
                        resolved_target=record,
                        target_id=user_id,
                        direction="include",
                        relationship_type="principal",
                        indices=indices,
                    )
                )
            else:
                relationship_records.append(
                    {
                        "kind": "relationship",
                        "source_type": "conditional_access_policy",
                        "source_id": policy_id,
                        "relationship_type": "principal",
                        "direction": "include",
                        "target_type": "user",
                        "target_id": user_id,
                        "resolution": "unresolved",
                    }
                )

        for user_id in excluded_users:
            record, status = _resolve_reference("user", user_id, indices)
            if status == "resolved":
                relationship_records.append(
                    _extract_conditional_access_reference(
                        references=reference_tracker,
                        target_type="user",
                        source_id=policy_id,
                        resolved_target=record,
                        target_id=user_id,
                        direction="exclude",
                        relationship_type="principal",
                        indices=indices,
                    )
                )
            else:
                relationship_records.append(
                    {
                        "kind": "relationship",
                        "source_type": "conditional_access_policy",
                        "source_id": policy_id,
                        "relationship_type": "principal",
                        "direction": "exclude",
                        "target_type": "user",
                        "target_id": user_id,
                        "resolution": "unresolved",
                    }
                )

        for group_id in included_groups + excluded_groups:
            direction = "include" if group_id in included_groups else "exclude"
            record, status = _resolve_reference("group", group_id, indices)
            relationship_records.append(
                _extract_conditional_access_reference(
                    references=reference_tracker,
                    target_type="group",
                    source_id=policy_id,
                    resolved_target=record,
                    target_id=group_id,
                    direction=direction,
                    relationship_type="membership",
                    indices=indices,
                )
                if status == "resolved"
                else {
                    "kind": "relationship",
                    "source_type": "conditional_access_policy",
                    "source_id": policy_id,
                    "relationship_type": "membership",
                    "direction": direction,
                    "target_type": "group",
                    "target_id": group_id,
                    "resolution": "unresolved",
                }
            )

        for app_id in included_apps + excluded_apps:
            direction = "include" if app_id in included_apps else "exclude"
            record, status = _resolve_reference("application", app_id, indices)
            if status != "resolved":
                record = _build_index(service_principals).get(app_id) or _build_index(service_principals).get(app_id.lower())
                if record is not None:
                    status = "resolved"
                else:
                    sp_by_app_id = indices.get("service_principal_app_id", {})
                    record = sp_by_app_id.get(app_id)
                    if record is not None:
                        status = "resolved"
            relationship_records.append(
                _extract_conditional_access_reference(
                    references=reference_tracker,
                    target_type="application",
                    source_id=policy_id,
                    resolved_target=record,
                    target_id=app_id,
                    direction=direction,
                    relationship_type="application",
                    indices=indices,
                )
                if status == "resolved"
                else {
                    "kind": "relationship",
                    "source_type": "conditional_access_policy",
                    "source_id": policy_id,
                    "relationship_type": "application",
                    "direction": direction,
                    "target_type": "application",
                    "target_id": app_id,
                    "resolution": "unresolved",
                }
            )

        for loc_id in include_locations + exclude_locations:
            direction = "include" if loc_id in include_locations else "exclude"
            record, status = _resolve_reference("named_location", loc_id, indices)
            relationship_records.append(
                _extract_conditional_access_reference(
                    references=reference_tracker,
                    target_type="named_location",
                    source_id=policy_id,
                    resolved_target=record,
                    target_id=loc_id,
                    direction=direction,
                    relationship_type="location",
                    indices=indices,
                )
                if status == "resolved"
                else {
                    "kind": "relationship",
                    "source_type": "conditional_access_policy",
                    "source_id": policy_id,
                    "relationship_type": "location",
                    "direction": direction,
                    "target_type": "named_location",
                    "target_id": loc_id,
                    "resolution": "unresolved",
                }
            )

        for auth_strength_id in include_auth_strengths:
            record, status = _resolve_reference("auth_strength", auth_strength_id, indices)
            relationship_records.append(
                _extract_conditional_access_reference(
                    references=reference_tracker,
                    target_type="auth_strength",
                    source_id=policy_id,
                    resolved_target=record,
                    target_id=auth_strength_id,
                    direction="include",
                    relationship_type="auth_strength",
                    indices=indices,
                )
                if status == "resolved"
                else {
                    "kind": "relationship",
                    "source_type": "conditional_access_policy",
                    "source_id": policy_id,
                    "relationship_type": "auth_strength",
                    "direction": "include",
                    "target_type": "auth_strength",
                    "target_id": auth_strength_id,
                    "resolution": "unresolved",
                }
            )

        # Filter out accidental empty placeholder dictionaries from helper paths.
        relationship_records = [item for item in relationship_records if item]
        unique_relationship_records = list(
            {tuple(sorted(record.items())): record for record in relationship_records}.values()
        )
        relationship_records = unique_relationship_records

        targeting = policy_targeting(policy)
        assessment = break_glass.assess_policy(targeting, policy_state.lower(), accounts)
        missing_break_glass = bool(assessment["missing"])
        if assessment["in_scope"]:
            break_glass_in_scope += 1
        if missing_break_glass:
            break_glass_flagged.append(
                {
                    "policy_id": policy_id,
                    "policy_name": policy.get("displayName"),
                    "key": f"conditional_access_policy:{policy_id}",
                    "enforces": assessment["enforces"],
                    "reach": assessment["reach"],
                    "broad": assessment["broad"],
                }
            )

        report_only = policy_state == "enabledForReportingButNotEnforced"
        mfa_enforcement = {
            "requires_mfa": requires_mfa,
            "mfa_registration": mfa_stats,
            "mfa_enrollment_ratio": (
                round(mfa_stats["mfa_registered"] / mfa_stats["sampled_users"], 4)
                if mfa_stats["sampled_users"] > 0 and requires_mfa
                else None
            ),
        }

        graph_records.append(
            _record(
                "conditional_access_policy",
                "conditional_access.conditionalAccessPolicies",
                policy_id,
                display_name=policy.get("displayName"),
                state=policy_state,
                report_only=report_only,
                enabled_for_reporting=report_only,
                grant_controls={
                    "built_in_controls": built_in_controls,
                    "operator": grant.get("operator"),
                    "custom_auth_factors": grant.get("customAuthenticationFactors"),
                },
                include_exclude_counts={
                    "included_users": len(included_users),
                    "excluded_users": len(excluded_users),
                    "included_groups": len(included_groups),
                    "excluded_groups": len(excluded_groups),
                    "included_applications": len(included_apps),
                    "excluded_applications": len(excluded_apps),
                    "included_locations": len(include_locations),
                    "excluded_locations": len(exclude_locations),
                },
                missing_break_glass_exclusion=missing_break_glass,
                break_glass_in_scope=assessment["in_scope"] or None,
                break_glass_enforces=assessment.get("enforces"),
                break_glass_excluded_accounts=assessment.get("excluded_accounts"),
                break_glass_not_excluded_accounts=assessment.get("not_excluded_accounts"),
                targeting=compact_targeting(targeting),
                mfa_enforcement=mfa_enforcement,
                relationships=[
                    item
                    for item in relationship_records
                    if item.get("source_id") == policy_id
                ],
            )
        )

        if report_only:
            policy_findings.append(
                _record(
                    "ca_finding",
                    "conditional_access",
                    policy_id,
                    title="Conditional Access policy not enforcing",
                    finding_type="ca_reporting_only",
                    severity="medium",
                    description="Policy is in report-only mode.",
                    policy_id=policy_id,
                )
            )
    break_glass_record: dict[str, Any] | None = None
    if graph_records:
        severity = break_glass.grade(accounts.source, break_glass_flagged)
        break_glass_record = _record(
            break_glass.KIND,
            "conditional_access.conditionalAccessPolicies",
            "tenant",
            state=accounts.state,
            account_source=accounts.source,
            account_count=len(accounts.ids),
            accounts=accounts.labels,
            unresolved_accounts=accounts.unresolved,
            unresolved_account_details=accounts.unresolved_detail,
            unverified_accounts=accounts.unverified,
            policies_in_scope=break_glass_in_scope,
            policies_missing_exclusion=len(break_glass_flagged),
        )
        if break_glass_flagged:
            policy_findings.append(
                _record(
                    "ca_finding",
                    "conditional_access",
                    "tenant",
                    title="Emergency access accounts are not excluded from enforcing Conditional Access policies",
                    finding_type="ca_break_glass_exclusion",
                    severity=severity,
                    description=(
                        f"{len(break_glass_flagged)} enabled Conditional Access "
                        f"{'policy requires' if len(break_glass_flagged) == 1 else 'policies require'} MFA or a managed "
                        f"device, or {'blocks' if len(break_glass_flagged) == 1 else 'block'} sign-ins, and "
                        f"{'excludes' if len(break_glass_flagged) == 1 else 'exclude'} none of the "
                        f"{'operator-listed' if accounts.source == break_glass.SOURCE_OPERATOR else 'inferred'} "
                        "emergency access accounts."
                        + (
                            f" {len(accounts.unresolved)} listed "
                            f"{'entry' if len(accounts.unresolved) == 1 else 'entries'} could not be resolved against the "
                            f"collected users and groups and {'is' if len(accounts.unresolved) == 1 else 'are'} not "
                            f"judged: {', '.join(accounts.unresolved)}."
                            if accounts.unresolved
                            else ""
                        )
                    ),
                    account_source=accounts.source,
                    unresolved_accounts=accounts.unresolved,
                    unresolved_account_details=accounts.unresolved_detail,
                    account_basis=(
                        "Accounts listed by the operator."
                        if accounts.source == break_glass.SOURCE_OPERATOR
                        else "Accounts inferred from names containing break glass or emergency access and from Global "
                        "Administrator role holders; list the real accounts with --break-glass-accounts or "
                        f"{break_glass.ENV_VAR} to confirm."
                    ),
                    accounts=accounts.labels,
                    policies=break_glass_flagged,
                    policy_count=len(break_glass_flagged),
                )
            )

    relationship_records = [_keyed_relationship(item) for item in relationship_records if item]
    unique_relationship_records = list({tuple(sorted(item.items())): item for item in relationship_records}.values())

    summary = {
        "policy_count": len(policies),
        "relationship_count": len(unique_relationship_records),
        "report_only_policies": sum(1 for policy in graph_records if policy.get("enabled_for_reporting")),
        "enabled_policies": sum(1 for policy in graph_records if str(policy.get("state", "")).lower() == "enabled"),
        "policies_missing_break_glass_exclusion": sum(
            1 for policy in graph_records if policy.get("missing_break_glass_exclusion")
        ),
        "dangling_references": sum(1 for rel in unique_relationship_records if rel.get("resolution") == "unresolved"),
    }
    return graph_records, unique_relationship_records, summary, policy_findings, break_glass_record, accounts


def _owner_type(owner: dict[str, Any]) -> str:
    odata_type = str(owner.get("@odata.type") or owner.get("type") or "").lower()
    if "serviceprincipal" in odata_type:
        return "service_principal"
    if "group" in odata_type:
        return "group"
    return "user"


def _build_group_membership_edges(
    identity_payload: dict[str, Any],
    values: Callable[[dict[str, Any], str], list[dict[str, Any]]] = _values,
) -> list[dict[str, Any]]:
    """Membership and ownership of role-assignable groups (identity fan-out).

    Only role-assignable groups (and groups that hold directory roles) are
    expanded by the collector, so these edges describe who can inherit or
    manage a privileged group, not the whole directory membership graph.
    """
    records: list[dict[str, Any]] = []
    for source_name, relationship, list_key in (
        ("roleAssignableGroupMembers", "member", "members"),
        ("roleAssignableGroupOwners", "owner", "owners"),
    ):
        for item in values(identity_payload, source_name):
            group_id = str(item.get("groupId") or "")
            rows = item.get(list_key)
            if not group_id or not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict) or not row.get("id"):
                    continue
                member_id = str(row.get("id"))
                records.append(
                    _record(
                        "group_membership_edge",
                        f"identity.{source_name}",
                        f"{relationship}:{group_id}:{member_id}",
                        source_name=source_name,
                        relationship=relationship,
                        group_id=group_id,
                        group_display_name=item.get("displayName"),
                        member_id=member_id,
                        member_type=_owner_type(row),
                        member_display_name=row.get("displayName"),
                        member_principal_name=row.get("userPrincipalName"),
                    )
                )
    return list({record["key"]: record for record in records}.values())


def _build_app_owner_edges(
    app_consent_payload: dict[str, Any],
    app_credentials_payload: dict[str, Any],
    values: Callable[[dict[str, Any], str], list[dict[str, Any]]] = _values,
) -> list[dict[str, Any]]:
    """Owners of service principals and application objects.

    An owner can add credentials to the object it owns, so ownership is a
    privilege-escalation edge in the attack graph.
    """
    records: list[dict[str, Any]] = []
    for item in values(app_consent_payload, "servicePrincipalOwners"):
        sp_id = str(item.get("servicePrincipalId") or "")
        owners = item.get("owners")
        if not sp_id or not isinstance(owners, list):
            continue
        for owner in owners:
            if not isinstance(owner, dict) or not owner.get("id"):
                continue
            owner_id = str(owner.get("id"))
            records.append(
                _record(
                    "app_owner_edge",
                    "app_consent.servicePrincipalOwners",
                    f"service_principal:{sp_id}:{owner_id}",
                    source_name="servicePrincipalOwners",
                    collector="app_consent",
                    target_type="service_principal",
                    target_id=sp_id,
                    target_display_name=item.get("displayName"),
                    owner_id=owner_id,
                    owner_type=_owner_type(owner),
                    owner_display_name=owner.get("displayName"),
                    owner_principal_name=owner.get("userPrincipalName"),
                )
            )
    for source_name, target_type in (
        ("applicationCredentials", "application"),
        ("servicePrincipalCredentials", "service_principal"),
    ):
        for item in values(app_credentials_payload, source_name):
            object_id = str(item.get("id") or "")
            owners = item.get("owners")
            if not object_id or not isinstance(owners, list):
                continue
            for owner in owners:
                if not isinstance(owner, dict) or not owner.get("id"):
                    continue
                owner_id = str(owner.get("id"))
                records.append(
                    _record(
                        "app_owner_edge",
                        f"app_credentials.{source_name}",
                        f"{target_type}:{object_id}:{owner_id}",
                        source_name=source_name,
                        collector="app_credentials",
                        target_type=target_type,
                        target_id=object_id,
                        target_display_name=item.get("display_name"),
                        app_id=item.get("app_id"),
                        owner_id=owner_id,
                        owner_type=_owner_type(owner),
                        owner_display_name=owner.get("displayName") or owner.get("display_name"),
                        owner_principal_name=owner.get("userPrincipalName") or owner.get("user_principal_name"),
                    )
                )
    return list({record["key"]: record for record in records}.values())


def _authorization_policy_fields(item: dict[str, Any]) -> dict[str, Any]:
    """User consent and app-creation settings that the authorization policy carries."""
    defaults = item.get("defaultUserRolePermissions") if isinstance(item.get("defaultUserRolePermissions"), dict) else {}
    return {
        "permission_grant_policies_assigned": defaults.get("permissionGrantPoliciesAssigned"),
        "allowed_to_create_apps": defaults.get("allowedToCreateApps"),
        "guest_user_role_id": item.get("guestUserRoleId"),
    }


def _build_identity_control_verdicts(
    sources: "_NormalizationSources",
    collector_payloads: dict[str, dict[str, Any]],
    *,
    users: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    role_definitions: list[dict[str, Any]],
    accounts: break_glass.BreakGlassAccounts,
    admin_records: Sequence[dict[str, Any]] = (),
    membership_edges: Sequence[dict[str, Any]] = (),
) -> list[dict[str, Any]]:
    """Tenant-level verdicts, one record per control, for every collector that was part of the run.

    The principals the operator lists as emergency-access accounts (``--break-glass-accounts``) may be excluded from
    a policy without it counting against the verdicts; any other exclusion is a gap. ``accounts`` is the resolution the
    Conditional Access graph made against the full user and group lists, so the verdicts and the break-glass check
    always agree on who the accounts are. The verdicts read the effective administrator set (``admin_records``), its
    role definitions in full (``role_definitions`` is the normalized list) and the group members the run read.
    """
    lookups = {
        "user": {str(item["id"]): str(item.get("principal_name") or item.get("display_name") or "") for item in users},
        "group": {str(item["id"]): str(item.get("display_name") or "") for item in groups},
        "role": {str(item["id"]): str(item.get("display_name") or "") for item in role_definitions},
    }
    lookups = {kind: {key: name for key, name in rows.items() if name} for kind, rows in lookups.items()}
    verdicts: list[dict[str, Any]] = []
    access_payload = collector_payloads.get("conditional_access")
    if isinstance(access_payload, dict):
        sanctioned = frozenset(accounts.ids) if accounts.source == break_glass.SOURCE_OPERATOR else frozenset()
        unresolved = tuple(accounts.unresolved) if accounts.source == break_glass.SOURCE_OPERATOR else ()
        admin_scope = build_admin_scope(admin_records, role_definitions, membership_edges)
        policies = sources.endpoint_evidence(access_payload, "conditionalAccessPolicies")
        security_defaults = sources.endpoint_evidence(
            access_payload, "identitySecurityDefaultsEnforcementPolicy", singleton=True
        )
        strengths = sources.endpoint_evidence(access_payload, "authenticationStrengthPolicies")
        auth_payload = collector_payloads.get("auth_methods", {})
        registration = _normalize_mfa_registration(sources.values(auth_payload, "userRegistrationDetails"))
        verdicts.append(
            evaluate_effective_mfa(
                policies=policies,
                security_defaults=security_defaults,
                authentication_strengths=strengths,
                lookups=lookups,
                registration=registration if registration["sampled_users"] else None,
                sanctioned=sanctioned,
                admin_scope=admin_scope,
                unresolved_accounts=unresolved,
            )
        )
        verdicts.append(
            evaluate_administrator_mfa(
                policies=policies,
                security_defaults=security_defaults,
                authentication_strengths=strengths,
                lookups=lookups,
                admin_scope=admin_scope,
                sanctioned=sanctioned,
                unresolved_accounts=unresolved,
            )
        )
        verdicts.append(
            evaluate_legacy_authentication_block(
                policies=policies,
                security_defaults=security_defaults,
                lookups=lookups,
                sanctioned=sanctioned,
                admin_scope=admin_scope,
                unresolved_accounts=unresolved,
            )
        )
    consent_payload = collector_payloads.get("consent_policy")
    if isinstance(consent_payload, dict):
        verdicts.append(
            evaluate_user_consent(
                authorization_policy=sources.endpoint_evidence(consent_payload, "authorizationPolicy", singleton=True),
                permission_grant_policies=sources.endpoint_evidence(consent_payload, "permissionGrantPolicies"),
            )
        )
    return [
        _record(IDENTITY_CONTROL_KIND, f"identity_controls.{item['control']}", str(item["control"]), **item)
        for item in verdicts
    ]


def _build_effective_admin_records(
    sources: "_NormalizationSources",
    collector_payloads: dict[str, dict[str, Any]],
    result_rows: list[dict[str, Any]],
    *,
    users: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    service_principals: list[dict[str, Any]],
    role_definitions: list[dict[str, Any]],
    role_assignments: list[dict[str, Any]],
    governance_objects: list[dict[str, Any]],
    group_membership_edges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """The effective administrator set, or nothing when the run read neither identity nor governance.

    Completeness comes from how each source was collected: the endpoint states (blocked, truncated,
    absent), the group fan-out's own ``fanout_complete`` and, for PIM, a skipped collector (blocked:
    nothing says why it was skipped).
    """
    identity_payload = collector_payloads.get("identity")
    governance_payload = collector_payloads.get("identity_governance")
    if not isinstance(identity_payload, dict) and not isinstance(governance_payload, dict):
        return []
    identity_payload = identity_payload if isinstance(identity_payload, dict) else {}
    governance_payload = governance_payload if isinstance(governance_payload, dict) else {}
    governance_skipped = any(
        row.get("name") == "identity_governance" and row.get("status") == "skipped" for row in result_rows
    )

    def schedules(name: str) -> Evidence:
        if not governance_payload and governance_skipped:
            # The run skips a collector on a permission block, an exception or a missing raw file as well as
            # on a missing licence, and a skipped collector leaves no payload to tell them apart. Only a
            # ``license_required`` refusal on the schedule read itself proves the tenant has no PIM.
            return Evidence(EVIDENCE_BLOCKED, detail="collector_skipped")
        return sources.endpoint_evidence(governance_payload, name)

    fanout = sources.endpoint_evidence(identity_payload, "roleAssignableGroupMembers")
    fanout_section = identity_payload.get("roleAssignableGroupMembers")
    fanout_meta = fanout_section.get("fanout") if isinstance(fanout_section, dict) else None
    if fanout.state == EVIDENCE_COLLECTED and isinstance(fanout_meta, dict) and fanout_meta.get("fanout_complete") is not True:
        fanout = Evidence(EVIDENCE_TRUNCATED, fanout.rows, "fanout_incomplete")
    licensing_payload = collector_payloads.get("licensing")
    licensing_payload = licensing_payload if isinstance(licensing_payload, dict) else {}
    evidence = AdminSetEvidence(
        role_definitions=sources.endpoint_evidence(identity_payload, "roleDefinitions"),
        role_assignments=sources.endpoint_evidence(identity_payload, "roleAssignments"),
        assignment_schedules=schedules("roleAssignmentSchedules"),
        eligibility_schedules=schedules("roleEligibilitySchedules"),
        group_fanout=fanout,
        licence_skus=sources.endpoint_evidence(licensing_payload, "subscribedSkus"),
        licensed_users=sources.endpoint_evidence(licensing_payload, "licensedUsers"),
    )
    return build_effective_admin_set(
        users=users,
        groups=groups,
        service_principals=service_principals,
        role_definitions=role_definitions,
        role_assignments=role_assignments,
        governance_objects=governance_objects,
        membership_edges=group_membership_edges,
        evidence=evidence,
    )


def _with_assignments(assignments: Any) -> dict[str, Any]:
    """Assignment fields for a policy record: known only when the assignment read returned that policy's list."""
    if not isinstance(assignments, list):
        return {"assignments_known": False}
    return {"assignments_known": True, **endpoint_posture.assignment_summary(assignments)}


def _assignments_by_policy(evidence: Evidence) -> dict[str, list[Any]]:
    return {
        str(row.get("policyId")): row["assignments"]
        for row in evidence.rows
        if row.get("policyId") and isinstance(row.get("assignments"), list)
    }


def _present_settings(settings: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in settings.items() if value is not None}


def _build_endpoint_records(
    sources: _NormalizationSources,
    payloads: dict[str, dict[str, Any]],
    devices: list[dict[str, Any]],
    today: date | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Device posture, compliance policy, update management and Defender antivirus evidence.

    Each section carries a summary record that says how completely its inputs were read, so a rule can tell
    "nothing found" from "nothing read". A section is left out when its collector did not run at all.
    """
    sections: dict[str, list[dict[str, Any]]] = {}
    intune = payloads.get("intune") if isinstance(payloads.get("intune"), dict) else {}
    depth = payloads.get("intune_depth") if isinstance(payloads.get("intune_depth"), dict) else {}

    device_evidence = sources.endpoint_evidence(intune, "managedDevices")
    if device_evidence.state != EVIDENCE_ABSENT:
        sections[endpoint_posture.DEVICE_SECTION] = [
            _record(
                endpoint_posture.DEVICE_SUMMARY_KIND,
                "intune.managedDevices",
                "tenant",
                **endpoint_posture.device_posture_summary(
                    devices, read_state=device_evidence.state, read_detail=device_evidence.detail, today=today
                ),
            )
        ]

    policy_evidence = sources.endpoint_evidence(intune, "deviceCompliancePolicies")
    if policy_evidence.state != EVIDENCE_ABSENT:
        assignment_evidence = sources.endpoint_evidence(intune, "deviceCompliancePolicyAssignments")
        assigned = _assignments_by_policy(assignment_evidence)
        policy_records = [
            _record(
                endpoint_posture.COMPLIANCE_POLICY_KIND,
                "intune.deviceCompliancePolicies",
                str(item.get("id")),
                display_name=item.get("displayName"),
                platform=endpoint_posture.compliance_platform(item.get("@odata.type")),
                policy_type=str(item.get("@odata.type") or "").rsplit(".", 1)[-1] or None,
                settings=_present_settings(endpoint_posture.compliance_settings(item)),
                **_with_assignments(assigned.get(str(item.get("id")))),
            )
            for item in policy_evidence.rows
            if item.get("id")
        ]
        coverage_rows = endpoint_posture.compliance_platform_coverage(devices, policy_records)
        sections[endpoint_posture.COMPLIANCE_SECTION] = [
            *policy_records,
            *(
                _record(endpoint_posture.COMPLIANCE_PLATFORM_KIND, "intune.deviceCompliancePolicies", row["platform"], **row)
                for row in coverage_rows
            ),
            _record(
                endpoint_posture.COMPLIANCE_SUMMARY_KIND,
                "intune.deviceCompliancePolicies",
                "tenant",
                policies_read_state=policy_evidence.state,
                policies_read_detail=policy_evidence.detail,
                assignments_read_state=assignment_evidence.state,
                assignments_read_detail=assignment_evidence.detail,
                devices_read_state=device_evidence.state,
                policy_count=len(policy_records),
                policies_with_unknown_assignments=sum(1 for row in policy_records if row.get("assignments_known") is not True),
            ),
        ]

    ring_evidence = sources.endpoint_evidence(depth, "windowsUpdateRings")
    profile_inputs = {
        "quality": (sources.endpoint_evidence(depth, "windowsQualityUpdateProfiles"), "windowsQualityUpdateProfiles", "windowsQualityUpdateProfileAssignments"),
        "feature": (sources.endpoint_evidence(depth, "windowsFeatureUpdateProfiles"), "windowsFeatureUpdateProfiles", "windowsFeatureUpdateProfileAssignments"),
    }
    if ring_evidence.state != EVIDENCE_ABSENT or any(evidence.state != EVIDENCE_ABSENT for evidence, _, _ in profile_inputs.values()):
        ring_assignment_evidence = sources.endpoint_evidence(depth, "windowsUpdateRingAssignments")
        assigned = _assignments_by_policy(ring_assignment_evidence)
        rings = [
            _record(
                endpoint_posture.UPDATE_RING_KIND,
                "intune_depth.windowsUpdateRings",
                str(item.get("id")),
                display_name=item.get("displayName"),
                **endpoint_posture.update_ring_fields(item),
                **_with_assignments(assigned.get(str(item.get("id")))),
            )
            for item in ring_evidence.rows
            if item.get("id")
        ]
        profiles: list[dict[str, Any]] = []
        profile_states: dict[str, Any] = {}
        profile_counts: dict[str, int] = {}
        for profile_type, (evidence, list_name, assignments_name) in profile_inputs.items():
            assignment_evidence = sources.endpoint_evidence(depth, assignments_name)
            by_profile = _assignments_by_policy(assignment_evidence)
            profile_states[f"{profile_type}_profiles_read_state"] = evidence.state
            profile_states[f"{profile_type}_profile_assignments_read_state"] = assignment_evidence.state
            profile_counts[profile_type] = sum(1 for item in evidence.rows if item.get("id"))
            profiles.extend(
                _record(
                    endpoint_posture.UPDATE_PROFILE_KIND,
                    f"intune_depth.{list_name}",
                    str(item.get("id")),
                    display_name=item.get("displayName"),
                    api_version="beta",
                    **endpoint_posture.update_profile_fields(item, profile_type),
                    **_with_assignments(by_profile.get(str(item.get("id")))),
                )
                for item in evidence.rows
                if item.get("id")
            )
        known = [ring for ring in rings if ring.get("assignments_known") is True]
        # Other update management that is visible: an assigned update profile, or Windows devices that Configuration
        # Manager co-manages (its update settings and WSUS are not read). With either, "no update ring" is not "no
        # update management".
        comanaged = sum(
            1
            for device in devices
            if device.get("os_family") == "windows" and str(device.get("enrollment_type") or "").lower() == "windowscomanagement"
        )
        sections[endpoint_posture.UPDATE_SECTION] = [
            *rings,
            *profiles,
            _record(
                endpoint_posture.UPDATE_SUMMARY_KIND,
                "intune_depth.windowsUpdateRings",
                "tenant",
                rings_read_state=ring_evidence.state,
                rings_read_detail=ring_evidence.detail,
                ring_assignments_read_state=ring_assignment_evidence.state,
                ring_count=len(rings),
                rings_with_unknown_assignments=len(rings) - len(known),
                rings_assigned=sum(1 for ring in known if ring.get("assigned") is True),
                rings_assigned_to_all_devices=sum(
                    1 for ring in known if ring.get("assigned") is True and (ring.get("assigned_to_all_devices") or ring.get("assigned_to_all_users"))
                ),
                profile_count=len(profiles),
                profiles_assigned=sum(1 for profile in profiles if profile.get("assigned") is True),
                profiles_with_unknown_assignments=sum(1 for profile in profiles if profile.get("assignments_known") is not True),
                # Why "no profile is assigned" cannot be trusted (a beta list that was blocked or cut, or assignments that
                # were not read); absent when the profile reads are complete. A rule that exempts tenants managing
                # updates through a profile must read this before it treats "no profile assigned" as a fact.
                update_profiles_gap=_update_profiles_gap(profile_states, profile_counts, profiles),
                windows_comanaged_device_count=comanaged,
                devices_read_state=device_evidence.state,
                windows_device_count=sum(1 for device in devices if device.get("os_family") == "windows"),
                update_ring_source="deviceConfigurations of type windowsUpdateForBusinessConfiguration (v1.0)",
                update_profile_api_version="beta",
                **profile_states,
            ),
        ]

    av_evidence = sources.endpoint_evidence(intune, "windowsProtectionStates")
    if av_evidence.state != EVIDENCE_ABSENT:
        fanout = (intune.get("windowsProtectionStates") or {}).get("fanout") if isinstance(intune.get("windowsProtectionStates"), dict) else None
        fanout = fanout if isinstance(fanout, dict) else {}
        states = [
            _record(
                endpoint_posture.DEFENDER_STATE_KIND,
                "intune.windowsProtectionStates",
                str(row.get("deviceId")),
                **endpoint_posture.defender_state_fields(row),
            )
            for row in av_evidence.rows
            if row.get("deviceId")
        ]
        statuses = Counter(str(row.get("read_status")) for row in states)
        sections[endpoint_posture.DEFENDER_SECTION] = [
            *states,
            _record(
                endpoint_posture.DEFENDER_SUMMARY_KIND,
                "intune.windowsProtectionStates",
                "tenant",
                read_state=av_evidence.state,
                read_detail=av_evidence.detail,
                devices_read_state=device_evidence.state,
                windows_device_count=sum(1 for device in devices if device.get("os_family") == "windows"),
                devices_expanded=len(states),
                devices_not_expanded=fanout.get("fanout_omitted_count"),
                state_read=statuses[endpoint_posture.READ_OK],
                state_not_reported=statuses[endpoint_posture.READ_NOT_REPORTED],
                state_read_failed=statuses[endpoint_posture.READ_FAILED],
                read_via="Intune managedDevices/{id}/windowsProtectionState (GET per Windows device)",
            ),
        ]
    return sections


def _update_profiles_gap(
    profile_states: dict[str, Any], profile_counts: dict[str, int], profiles: list[dict[str, Any]]
) -> str | None:
    """Why the Windows quality and feature update profiles cannot say "no profile is assigned", or ``None``.

    The profiles are beta lists, so a refused or cut read is common; it is "not read", never "no profile".
    ``absent`` (a bundle from before the lists were collected) is not reported as a gap.
    """
    for profile_type in ("quality", "feature"):
        state = profile_states.get(f"{profile_type}_profiles_read_state")
        if state in {EVIDENCE_BLOCKED, EVIDENCE_TRUNCATED}:
            return f"update_profiles_{state}"
    for profile_type in ("quality", "feature"):
        if not profile_counts.get(profile_type):
            continue
        state = profile_states.get(f"{profile_type}_profile_assignments_read_state")
        if state != EVIDENCE_COLLECTED:
            return f"profile_assignments_{state}"
    if any(profile.get("assignments_known") is not True for profile in profiles):
        return "profile_assignments_unknown"
    return None


def _dns_presence(item: dict[str, Any], section: str) -> bool | None:
    """Whether a DNS record section is published; ``None`` (unknown) when the resolver could not answer for the domain."""
    if item.get("resolver_error"):
        return None
    return bool((item.get(section) or {}).get("present"))


def build_normalized_snapshot(
    *,
    tenant_name: str,
    run_id: str,
    collector_payloads: dict[str, dict[str, Any]],
    diagnostics: list[dict[str, Any]] | None = None,
    result_rows: list[dict[str, Any]] | None = None,
    coverage_rows: list[dict[str, Any]] | None = None,
    run_dir: Path | None = None,
    break_glass_accounts: Sequence[str] | None = None,
    as_of: datetime | None = None,
) -> dict[str, dict[str, Any]]:
    """Normalize collector payloads. ``as_of`` pins the day date-dependent evidence (the end-of-life table) is applied."""
    diagnostics = diagnostics or []
    result_rows = result_rows or []
    coverage_rows = coverage_rows or []
    sources = _NormalizationSources(collector_payloads, run_dir, coverage_rows)
    # All section reads, including the relationship helpers, use this run's
    # checked chunk reader. The caller's bounded inline samples stay untouched.
    _values = sources.values

    identity_payload = collector_payloads.get("identity", {})
    signin_section = identity_payload.get("userSignInActivity") if isinstance(identity_payload, dict) else None
    # signin_data_available is only True when the separate signInActivity query
    # succeeded; otherwise stale-account rules stay inert rather than guessing.
    user_signin_available = isinstance(signin_section, dict) and "error" not in signin_section and "value" in signin_section
    signin_by_user: dict[str, dict[str, Any]] = {}
    if user_signin_available:
        for item in _values(identity_payload, "userSignInActivity"):
            activity = item.get("signInActivity")
            if item.get("id"):
                signin_by_user[str(item.get("id"))] = activity if isinstance(activity, dict) else {}
    users = [
        _record(
            "user",
            "identity.users",
            str(item.get("id")),
            display_name=item.get("displayName"),
            principal_name=item.get("userPrincipalName"),
            mail=item.get("mail"),
            department=item.get("department"),
            user_type=item.get("userType"),
            enabled=item.get("accountEnabled"),
            created_at=item.get("createdDateTime"),
            last_password_change_at=item.get("lastPasswordChangeDateTime"),
            last_successful_signin_at=(signin_by_user.get(str(item.get("id"))) or {}).get("lastSuccessfulSignInDateTime"),
            last_signin_at=(signin_by_user.get(str(item.get("id"))) or {}).get("lastSignInDateTime"),
            signin_data_available=(str(item.get("id")) in signin_by_user) if user_signin_available else None,
        )
        for item in _values(identity_payload, "users")
        if item.get("id")
    ]
    groups = [
        _record(
            "group",
            "identity.groups",
            str(item.get("id")),
            display_name=item.get("displayName"),
            mail=item.get("mail"),
            group_types=item.get("groupTypes"),
            is_assignable_to_role=item.get("isAssignableToRole"),
        )
        for item in _values(collector_payloads.get("identity", {}), "groups")
        if item.get("id")
    ]
    applications = [
        _record(
            "application",
            "identity.applications",
            str(item.get("id")),
            display_name=item.get("displayName"),
            app_id=item.get("appId"),
            created=item.get("createdDateTime"),
            audience=item.get("signInAudience"),
        )
        for item in _values(collector_payloads.get("identity", {}), "applications")
        if item.get("id")
    ]
    service_principals = [
        _record(
            "service_principal",
            "identity.servicePrincipals",
            str(item.get("id")),
            display_name=item.get("displayName"),
            app_id=item.get("appId"),
            service_principal_type=item.get("servicePrincipalType"),
            enabled=item.get("accountEnabled"),
        )
        for item in _values(collector_payloads.get("identity", {}), "servicePrincipals")
        if item.get("id")
    ]
    role_definitions = [
        _record(
            "role_definition",
            "identity.roleDefinitions",
            str(item.get("id")),
            display_name=item.get("displayName"),
            description=item.get("description"),
        )
        for item in _values(collector_payloads.get("identity", {}), "roleDefinitions")
        if item.get("id")
    ]
    role_assignments = [
        _record(
            "role_assignment",
            "identity.roleAssignments",
            str(item.get("id")),
            principal_id=item.get("principalId"),
            role_definition_id=item.get("roleDefinitionId"),
            directory_scope_id=item.get("directoryScopeId"),
        )
        for item in _values(collector_payloads.get("identity", {}), "roleAssignments")
        if item.get("id")
    ]
    devices = [
        _record(
            "device",
            "intune.managedDevices",
            str(item.get("id")),
            display_name=item.get("deviceName"),
            platform=item.get("operatingSystem"),
            os_version=item.get("osVersion"),
            compliance_state=item.get("complianceState"),
            azure_ad_device_id=item.get("azureADDeviceId"),
            last_sync_at=item.get("lastSyncDateTime"),
            **endpoint_posture.device_fields(item),
        )
        for item in _values(collector_payloads.get("intune", {}), "managedDevices")
        if item.get("id")
    ]
    incidents = [
        _record(
            "incident",
            "defender.defenderIncidents",
            str(item.get("id")),
            display_name=item.get("displayName"),
            severity=item.get("severity"),
            status=item.get("status"),
            classification=item.get("classification"),
            determination=item.get("determination"),
        )
        for item in _values(collector_payloads.get("defender", {}), "defenderIncidents")
        if item.get("id")
    ]
    security_scores = [
        _record(
            "security_score",
            "defender.secureScores",
            str(item.get("id")),
            current_score=item.get("currentScore"),
            max_score=item.get("maxScore"),
            created=item.get("createdDateTime"),
            control_scores=_secure_score_control_scores(item.get("controlScores")),
        )
        for item in _values(collector_payloads.get("defender", {}), "secureScores")
        if item.get("id")
    ]
    security_score_control_profiles = [
        _record(
            "security_score_control_profile",
            "defender.secureScoreControlProfiles",
            str(item.get("id")),
            title=item.get("title"),
            max_score=item.get("maxScore"),
            service=item.get("service"),
            control_category=item.get("controlCategory"),
            deprecated=item.get("deprecated"),
        )
        for item in _values(collector_payloads.get("defender", {}), "secureScoreControlProfiles")
        if item.get("id")
    ]
    security_signin_events = [
        _record(
            "security_signin_event",
            "security.signIns",
            str(item.get("id")),
            created=item.get("createdDateTime"),
            user_principal_name=item.get("userPrincipalName"),
            app_display_name=item.get("appDisplayName"),
            ip_address=item.get("ipAddress"),
            risk_level_aggregated=item.get("riskLevelAggregated"),
            risk_level_during_signin=item.get("riskLevelDuringSignIn"),
            risk_state=item.get("riskState"),
            risk_detail=item.get("riskDetail"),
            conditional_access_status=item.get("conditionalAccessStatus"),
            status=item.get("status") or {},
        )
        for item in _values(collector_payloads.get("security", {}), "signIns")
        if item.get("id")
    ]
    security_directory_audit_events = [
        _record(
            "security_directory_audit_event",
            "security.directoryAudits",
            str(item.get("id")),
            activity_time=item.get("activityDateTime"),
            activity_display_name=item.get("activityDisplayName"),
            category=item.get("category"),
            result=item.get("result"),
            initiated_by=item.get("initiatedBy") or {},
            target_resources=item.get("targetResources") or [],
        )
        for item in _values(collector_payloads.get("security", {}), "directoryAudits")
        if item.get("id")
    ]
    exchange_mailbox_records: list[dict[str, Any]] = []
    for source_name in ("mailboxInventory", "mailboxCount"):
        for item in _values(collector_payloads.get("exchange", {}), source_name):
            mailbox_id = item.get("ExternalDirectoryObjectId") or item.get("id")
            if not mailbox_id:
                continue
            exchange_mailbox_records.append(
                _record(
                    "mailbox",
                    f"exchange.{source_name}",
                    str(mailbox_id),
                    display_name=item.get("DisplayName") or item.get("displayName"),
                    primary_smtp_address=item.get("PrimarySmtpAddress")
                    or item.get("primarySmtpAddress")
                    or item.get("mail"),
                    recipient_type=item.get("RecipientTypeDetails") or item.get("recipientTypeDetails"),
                )
            )
    mailboxes = list({record["key"]: record for record in exchange_mailbox_records}.values())

    policies: list[dict[str, Any]] = []
    for source_name in ("conditionalAccessPolicies",):
        for item in _values(collector_payloads.get("conditional_access", {}), source_name):
            if item.get("id"):
                policies.append(
                    _record(
                        "policy",
                        source_name,
                        f"{source_name}:{item.get('id')}",
                        display_name=item.get("displayName"),
                        state=item.get("state"),
                    )
                )
    for source_name in ("deviceCompliancePolicies", "deviceConfigurationProfiles"):
        for item in _values(collector_payloads.get("intune", {}), source_name):
            if item.get("id"):
                policies.append(
                    _record(
                        "policy",
                        source_name,
                        f"{source_name}:{item.get('id')}",
                        display_name=item.get("displayName"),
                        state=item.get("state"),
                    )
                )
    for source_name in ("authenticationMethodsPolicy", "registrationCampaign", "authenticationMethodConfigurations"):
        for item in _values(collector_payloads.get("auth_methods", {}), source_name):
            object_id = str(item.get("id") or item.get("policyType") or item.get("@odata.type") or source_name)
            policies.append(
                _record(
                    "policy",
                    source_name,
                    f"{source_name}:{object_id}",
                    display_name=item.get("displayName") or item.get("policyType") or object_id,
                    state=item.get("state"),
                )
            )
    auth_method_registration_records = [
        _record(
            "auth_method_registration",
            "auth_methods.userRegistrationDetails",
            str(item.get("id") or item.get("userPrincipalName")),
            user_principal_name=item.get("userPrincipalName"),
            user_type=item.get("userType"),
            is_admin=item.get("isAdmin"),
            is_mfa_registered=item.get("isMfaRegistered"),
            is_mfa_capable=item.get("isMfaCapable"),
            is_passwordless_capable=item.get("isPasswordlessCapable"),
            is_sspr_enabled=item.get("isSsprEnabled"),
        )
        for item in _values(collector_payloads.get("auth_methods", {}), "userRegistrationDetails")
        if item.get("id") or item.get("userPrincipalName")
    ]

    sites = [
        _record(
            "site",
            "sharepoint.sites",
            str(item.get("id")),
            display_name=item.get("displayName") or item.get("name"),
            web_url=item.get("webUrl"),
        )
        for item in _values(collector_payloads.get("sharepoint", {}), "sites")
        if item.get("id")
    ]
    sharepoint_site_posture_objects: list[dict[str, Any]] = []
    sharepoint_permission_edges: list[dict[str, Any]] = []
    sharepoint_sharing_findings: list[dict[str, Any]] = []
    for item in _values(collector_payloads.get("sharepoint_access", {}), "sitePermissionsBySite"):
        site_id = str(item.get("siteId") or "")
        site_name = item.get("siteName")
        web_url = item.get("webUrl")
        site_kind = item.get("siteKind") or _site_kind_from_web_url(web_url)
        sharing_capability = item.get("sharingCapability")
        permissions = item.get("permissions")
        if not site_id:
            continue
        sharepoint_site_posture_objects.append(
            _record(
                "sharepoint_site_posture",
                "sharepoint_access.sitePermissionsBySite",
                site_id,
                site_name=site_name,
                web_url=web_url,
                site_kind=site_kind,
                sharing_capability=sharing_capability,
                permission_count=item.get("permissionCount"),
                principal_count=item.get("principalCount"),
                user_principal_count=item.get("userPrincipalCount"),
                group_principal_count=item.get("groupPrincipalCount"),
                application_principal_count=item.get("applicationPrincipalCount"),
                link_permission_count=item.get("linkPermissionCount"),
                anonymous_link_count=item.get("anonymousLinkCount"),
                organization_link_count=item.get("organizationLinkCount"),
                write_like_permission_count=item.get("writeLikePermissionCount"),
                ownership_state=item.get("ownershipState"),
            )
        )
        if not isinstance(permissions, list):
            continue
        for permission in permissions:
            if not isinstance(permission, dict):
                continue
            permission_id = str(permission.get("id") or f"{site_id}:permission")
            roles = _to_str_list(permission.get("roles"))
            link = permission.get("link") if isinstance(permission.get("link"), dict) else {}
            link_scope = link.get("scope")
            targets = _iter_permission_targets(permission)
            if not targets:
                sharepoint_permission_edges.append(
                    _record(
                        "sharepoint_permission_edge",
                        "sharepoint_access.sitePermissionsBySite",
                        f"{site_id}:{permission_id}",
                        site_id=site_id,
                        site_name=site_name,
                        web_url=web_url,
                        permission_id=permission_id,
                        target_type="link" if link_scope else "unknown",
                        target_id=permission_id,
                        target_name=link.get("type") or link_scope or permission_id,
                        roles=roles,
                        link_scope=link_scope,
                    )
                )
            for target_type, target in targets:
                target_id = str(target.get("id") or target.get("userPrincipalName") or target.get("displayName") or permission_id)
                sharepoint_permission_edges.append(
                    _record(
                        "sharepoint_permission_edge",
                        "sharepoint_access.sitePermissionsBySite",
                        f"{site_id}:{permission_id}:{target_id}",
                        site_id=site_id,
                        site_name=site_name,
                        web_url=web_url,
                        permission_id=permission_id,
                        target_type=target_type,
                        target_id=target_id,
                        target_name=target.get("displayName") or target.get("userPrincipalName") or target_id,
                        roles=roles,
                        link_scope=link_scope,
                    )
                )
            if isinstance(link_scope, str) and link_scope.lower() in {"anonymous", "organization"}:
                sharepoint_sharing_findings.append(
                    _record(
                        "sharepoint_sharing_finding",
                        "sharepoint_access.sitePermissionsBySite",
                        f"{site_id}:{permission_id}:sharing",
                        finding_type="broad_sharing_link",
                        site_id=site_id,
                        site_name=site_name,
                        permission_id=permission_id,
                        link_scope=link_scope,
                        roles=roles,
                        severity="high" if link_scope.lower() == "anonymous" else "medium",
                    )
                )
    app_consent_payload = collector_payloads.get("app_consent", {})
    app_service_principals = _values(app_consent_payload, "servicePrincipals")
    app_service_principal_by_id = _build_index(app_service_principals)
    service_principal_records = {str(row["id"]): row for row in service_principals}
    for item in app_service_principals:
        if not item.get("id"):
            continue
        object_id = str(item["id"])
        consent_record = _record(
            "service_principal", "app_consent.servicePrincipals", object_id,
            display_name=item.get("displayName"), app_id=item.get("appId"),
            service_principal_type=item.get("servicePrincipalType"), enabled=item.get("accountEnabled"),
        )
        # Identity is the primary inventory. Consent-only runs still need SP
        # nodes, but a second observation must not erase its enabled state.
        service_principal_records[object_id] = {**consent_record, **service_principal_records.get(object_id, {})}
    service_principals = list(service_principal_records.values())
    app_owners_by_sp_id = {
        str(item.get("servicePrincipalId")): item.get("owners", [])
        for item in _values(app_consent_payload, "servicePrincipalOwners")
        if item.get("servicePrincipalId")
    }
    application_consents = [
        _record(
            "application_consent",
            "app_consent.oauth2PermissionGrants",
            str(item.get("id")),
            service_principal_id=item.get("clientId"),
            service_principal_name=(app_service_principal_by_id.get(str(item.get("clientId"))) or {}).get("displayName"),
            resource_id=item.get("resourceId"),
            scope=item.get("scope"),
            consent_type=item.get("consentType"),
            principal_id=item.get("principalId"),
            owner_count=len(app_owners_by_sp_id.get(str(item.get("clientId")), [])),
            source_name="oauth2PermissionGrants",
        )
        for item in _values(app_consent_payload, "oauth2PermissionGrants")
        if item.get("id")
    ]
    for item in _values(app_consent_payload, "servicePrincipalAppRoleAssignments"):
        service_principal_id = str(item.get("servicePrincipalId") or "")
        assignments = item.get("assignments")
        if not service_principal_id or not isinstance(assignments, list):
            continue
        for assignment in assignments:
            if not isinstance(assignment, dict):
                continue
            object_id = str(assignment.get("id") or f"{service_principal_id}:assignment")
            application_consents.append(
                _record(
                    "application_consent",
                    "app_consent.servicePrincipalAppRoleAssignments",
                    object_id,
                    service_principal_id=service_principal_id,
                    service_principal_name=(app_service_principal_by_id.get(service_principal_id) or {}).get("displayName"),
                    principal_display_name=assignment.get("principalDisplayName"),
                    principal_type=assignment.get("principalType"),
                    principal_id=assignment.get("principalId"),
                    resource_id=assignment.get("resourceId") or service_principal_id,
                    resource_display_name=assignment.get("resourceDisplayName"),
                    app_role_id=assignment.get("appRoleId"),
                    app_role_value=assignment.get("appRoleValue"),
                    source_name="servicePrincipalAppRoleAssignments",
                )
            )
    group_membership_edges = _build_group_membership_edges(collector_payloads.get("identity", {}), values=_values)
    app_owner_edges = _build_app_owner_edges(app_consent_payload, collector_payloads.get("app_credentials", {}), values=_values)
    license_inventory = [
        _record(
            "license_sku",
            "licensing.subscribedSkus",
            str(item.get("skuId") or item.get("id")),
            sku_part_number=item.get("skuPartNumber"),
            consumed_units=item.get("consumedUnits"),
            enabled_units=(item.get("prepaidUnits") or {}).get("enabled") if isinstance(item.get("prepaidUnits"), dict) else None,
            warning_units=(item.get("prepaidUnits") or {}).get("warning") if isinstance(item.get("prepaidUnits"), dict) else None,
            suspended_units=(item.get("prepaidUnits") or {}).get("suspended") if isinstance(item.get("prepaidUnits"), dict) else None,
            service_plan_count=len(item.get("servicePlans", [])) if isinstance(item.get("servicePlans"), list) else 0,
        )
        for item in _values(collector_payloads.get("licensing", {}), "subscribedSkus")
        if item.get("skuId") or item.get("id")
    ]
    exchange_policy_objects: list[dict[str, Any]] = []
    for source_name in (
        "transportRules",
        "inboundConnectors",
        "outboundConnectors",
        "acceptedDomains",
        "remoteDomains",
        "mailboxForwarding",
        "adminAuditLogConfig",
        "organizationAuditConfig",
        "mailboxAuditBypass",
        "protectionAlerts",
        exchange_protection.SOURCE_MALWARE,
        exchange_protection.SOURCE_TRANSPORT,
        exchange_protection.SOURCE_DKIM,
    ):
        for item in _values(collector_payloads.get("exchange_policy", {}), source_name):
            object_id = str(
                item.get("Identity") or item.get("Name") or item.get("Domain") or item.get("PrimarySmtpAddress") or source_name
            )
            exchange_policy_objects.append(
                _record(
                    "exchange_policy_object",
                    f"exchange_policy.{source_name}",
                    object_id,
                    source_name=source_name,
                    display_name=item.get("Name") or item.get("Identity") or item.get("DisplayName"),
                    domain_name=exchange_protection.domain_text(item.get("DomainName") or item.get("Domain")),
                    trusted_mail_outbound_enabled=item.get("TrustedMailOutboundEnabled"),
                    auto_reply_enabled=item.get("AutoReplyEnabled"),
                    auto_forward_enabled=item.get("AutoForwardEnabled"),
                    primary_smtp_address=item.get("PrimarySmtpAddress"),
                    forwarding_smtp_address=item.get("ForwardingSmtpAddress"),
                    forwarding_address=item.get("ForwardingAddress"),
                    deliver_to_mailbox_and_forward=item.get("DeliverToMailboxAndForward"),
                    redirect_message_to=_to_str_list(item.get("RedirectMessageTo")),
                    blind_copy_to=_to_str_list(item.get("BlindCopyTo")),
                    copy_to=_to_str_list(item.get("CopyTo")),
                    apply_html_disclaimer_text=item.get("ApplyHtmlDisclaimerText"),
                    state=item.get("State"),
                    priority=item.get("Priority"),
                    mode=item.get("Mode"),
                    unified_audit_log_ingestion_enabled=item.get("UnifiedAuditLogIngestionEnabled"),
                    audit_disabled=item.get("AuditDisabled"),
                    audit_bypass_count=item.get("Count") if source_name == "mailboxAuditBypass" else None,
                    disabled=item.get("Disabled"),
                    severity=item.get("Severity"),
                    category=item.get("Category"),
                    is_system_rule=item.get("IsSystemRule"),
                    **exchange_protection.protection_fields(source_name, item),
                )
            )
    governance_objects: list[dict[str, Any]] = []
    for source_name, kind in (
        ("accessReviews", "access_review"),
        ("entitlementCatalogs", "entitlement_catalog"),
        ("accessPackages", "access_package"),
        ("roleAssignmentSchedules", "role_assignment_schedule"),
        ("roleEligibilitySchedules", "role_eligibility_schedule"),
        ("administrativeUnits", "administrative_unit"),
    ):
        for item in _values(collector_payloads.get("identity_governance", {}), source_name):
            object_id = str(item.get("id") or item.get("displayName") or source_name)
            governance_objects.append(
                _record(
                    kind,
                    f"identity_governance.{source_name}",
                    object_id,
                    display_name=item.get("displayName"),
                    description=item.get("description"),
                    status=item.get("status"),
                    principal_id=item.get("principalId"),
                    role_definition_id=item.get("roleDefinitionId"),
                    directory_scope_id=item.get("directoryScopeId"),
                    member_type=item.get("memberType"),
                    assignment_type=item.get("assignmentType"),
                )
            )
    intune_assignment_objects: list[dict[str, Any]] = []
    # One row per policy the assignment read returned, with how many assignments it has. A policy with
    # none has no row in ``intune_assignment_objects``, so these rows are what shows it was read and empty.
    intune_policy_assignment_objects: list[dict[str, Any]] = []
    # "No assignments" is evidence only when the policy inventory and the assignment reads both
    # succeeded, so the inventory gets a normalization coverage report too (its rows are not kept).
    _values(collector_payloads.get("intune_depth", {}), "deviceConfigurations")
    for item in _values(collector_payloads.get("intune_depth", {}), "deviceConfigurationAssignments"):
        policy_id = str(item.get("policyId") or "")
        assignments = item.get("assignments")
        if not policy_id or not isinstance(assignments, list):
            continue
        intune_policy_assignment_objects.append(
            _record(
                "intune_policy_assignment",
                "intune_depth.deviceConfigurationAssignments",
                policy_id,
                policy_name=item.get("displayName"),
                assignment_count=len([entry for entry in assignments if isinstance(entry, dict)]),
            )
        )
        for assignment in assignments:
            if not isinstance(assignment, dict):
                continue
            target = assignment.get("target") if isinstance(assignment.get("target"), dict) else {}
            assignment_id = str(assignment.get("id") or f"{policy_id}:assignment")
            intune_assignment_objects.append(
                _record(
                    "intune_assignment_object",
                    "intune_depth.deviceConfigurationAssignments",
                    assignment_id,
                    policy_id=policy_id,
                    policy_name=item.get("displayName"),
                    target_group_id=target.get("groupId"),
                )
            )
    teams_policy_objects: list[dict[str, Any]] = []
    for source_name in (
        "tenantFederationConfiguration",
        "messagingPolicies",
        "meetingPolicies",
        "appPermissionPolicies",
        "appSetupPolicies",
    ):
        for item in _values(collector_payloads.get("teams_policy", {}), source_name):
            object_id = str(item.get("Identity") or item.get("id") or source_name)
            federation: dict[str, Any] = {}
            if source_name == "tenantFederationConfiguration":
                # Federation is open only when no allow list restricts it; the lists are kept as counts.
                allowed_state, allowed_count = external_sharing.federation_allow_list(item.get("AllowedDomains"))
                federation = {
                    "allowed_domains_state": allowed_state,
                    "allowed_domain_count": allowed_count if allowed_state != external_sharing.FEDERATION_UNKNOWN else None,
                    "blocked_domain_count": external_sharing.federation_block_count(item.get("BlockedDomains")),
                }
            teams_policy_objects.append(
                _record(
                    "teams_policy_object",
                    f"teams_policy.{source_name}",
                    object_id,
                    source_name=source_name,
                    policy_name=item.get("Identity") or item.get("displayName"),
                    allow_public_users=item.get("AllowPublicUsers"),
                    allow_federated_users=item.get("AllowFederatedUsers"),
                    allow_teams_consumer=item.get("AllowTeamsConsumer"),
                    allow_cloud_recording=item.get("AllowCloudRecording"),
                    **federation,
                )
            )
    service_health_objects: list[dict[str, Any]] = []
    for source_name in ("healthOverviews", "serviceIssues", "messages"):
        section = collector_payloads.get("service_health", {})
        rows = _values(section, source_name)
        for item in rows:
            object_id = str(item.get("id") or item.get("service") or item.get("title") or source_name)
            service_health_objects.append(
                _record(
                    "service_health_object",
                    f"service_health.{source_name}",
                    object_id,
                    source_name=source_name,
                    service=item.get("service"),
                    title=item.get("title"),
                    status=item.get("status"),
                )
            )
    # Microsoft 365 reports are anonymized by default — when a tenant has
    # ``ConcealedInfo=true`` (the secure-by-default setting), every row's
    # Site Id / Owner Principal Name / User Principal Name comes back as
    # the all-zeros placeholder UUID, collapsing all rows to one
    # record_key. Live audit on 2026-05-09 surfaced this as a
    # ``duplicate_record_key`` violation in C3. Detect the placeholder and
    # synthesize a stable per-row key from source + refresh-date + index.
    _USAGE_ANONYMIZED_PLACEHOLDERS = {
        "00000000-0000-0000-0000-000000000000",
        "00000000-0000-0000-0000-000000000000@",
        "anonymous",
        "",
    }

    def _usage_object_id(item: dict[str, Any], source_name: str, idx: int) -> str:
        raw = item.get("Site Id") or item.get("Owner Principal Name") or item.get("User Principal Name") or ""
        text = str(raw).strip()
        if text and text.lower() not in _USAGE_ANONYMIZED_PLACEHOLDERS:
            return text
        refresh_date = str(item.get("Report Refresh Date") or "").strip()
        if refresh_date:
            return f"anonymized:{source_name}:{refresh_date}:{idx}"
        return f"anonymized:{source_name}:{idx}"

    usage_report_objects: list[dict[str, Any]] = []
    for source_name in (
        "office365ActiveUserCounts",
        "sharePointSiteUsageDetail",
        "oneDriveUsageAccountDetail",
        "mailboxUsageDetail",
    ):
        for idx, item in enumerate(_values(collector_payloads.get("reports_usage", {}), source_name), start=1):
            object_id = _usage_object_id(item, source_name, idx)
            usage_report_objects.append(
                _record(
                    "usage_report_object",
                    f"reports_usage.{source_name}",
                    object_id,
                    source_name=source_name,
                    report_refresh_date=item.get("Report Refresh Date"),
                )
            )
    usage_report_setting_objects = [
        _record(
            "usage_report_settings",
            "reports_usage.reportSettings",
            "reportSettings",
            concealed_names=item.get("displayConcealedNames"),
        )
        for item in _values(collector_payloads.get("reports_usage", {}), "reportSettings")
    ]
    external_identity_objects: list[dict[str, Any]] = []
    for source_name in ("crossTenantAccessPolicy", "authorizationPolicy", "authenticationFlowsPolicy"):
        section = collector_payloads.get("external_identity", {})
        value = section.get(source_name)
        rows = _values(section, source_name) if sources.is_endpoint(value) else [value] if isinstance(value, dict) else []
        for item in rows:
            object_id = str(item.get("id") or item.get("displayName") or source_name)
            external_identity_objects.append(
                _record(
                    "external_identity_object",
                    f"external_identity.{source_name}",
                    object_id,
                    source_name=source_name,
                    display_name=item.get("displayName"),
                    allow_invites_from=item.get("allowInvitesFrom"),
                )
            )
    consent_policy_objects: list[dict[str, Any]] = []
    for source_name in ("adminConsentRequestPolicy", "permissionGrantPolicies", "authorizationPolicy"):
        section = collector_payloads.get("consent_policy", {})
        value = section.get(source_name)
        rows = _values(section, source_name) if sources.is_endpoint(value) else [value] if isinstance(value, dict) else []
        for item in rows:
            object_id = str(item.get("id") or item.get("displayName") or source_name)
            consent_policy_objects.append(
                _record(
                    "consent_policy_object",
                    f"consent_policy.{source_name}",
                    object_id,
                    source_name=source_name,
                    display_name=item.get("displayName"),
                    is_enabled=item.get("isEnabled"),
                    **(_authorization_policy_fields(item) if source_name == "authorizationPolicy" else {}),
                )
            )
    domain_hybrid_objects: list[dict[str, Any]] = []
    for item in _values(collector_payloads.get("domains_hybrid", {}), "domains"):
        object_id = str(item.get("id") or item.get("name"))
        if object_id:
            domain_hybrid_objects.append(
                _record(
                    "domain_hybrid_object",
                    "domains_hybrid.domains",
                    object_id,
                    source_name="domains",
                    authentication_type=item.get("authenticationType"),
                    is_default=item.get("isDefault"),
                    is_verified=item.get("isVerified"),
                )
            )
    sync_users = _values(collector_payloads.get("domains_hybrid", {}), "syncSampleUsers")
    if any(bool(item.get("onPremisesSyncEnabled")) for item in sync_users):
        domain_hybrid_objects.append(
            _record(
                "domain_hybrid_object",
                "domains_hybrid.syncSampleUsers",
                "sync-signal",
                source_name="syncSampleUsers",
                synced_user_count=sum(1 for item in sync_users if bool(item.get("onPremisesSyncEnabled"))),
            )
        )
    onedrive_posture_objects: list[dict[str, Any]] = []
    for source_name in ("oneDriveSites", "teamSites"):
        for item in _values(collector_payloads.get("onedrive_posture", {}), source_name):
            object_id = str(item.get("id") or item.get("webUrl"))
            if object_id:
                onedrive_posture_objects.append(
                    _record(
                        "onedrive_posture_object",
                        f"onedrive_posture.{source_name}",
                        object_id,
                        site_name=item.get("displayName") or item.get("name"),
                        web_url=item.get("webUrl"),
                        site_kind=item.get("siteKind") or _site_kind_from_web_url(item.get("webUrl")),
                        sharing_capability=item.get("sharingCapability"),
                        # "tenant" marks the tenant's single value copied onto the site, "site" the site's own.
                        sharing_capability_source=item.get("sharingCapabilitySource"),
                    )
                )
    sharepoint_tenant_settings: list[dict[str, Any]] = []
    for collector_name in ("onedrive_posture", "sharepoint_access"):
        settings_payload = collector_payloads.get(collector_name)
        if not isinstance(settings_payload, dict) or "sharePointSettings" not in settings_payload:
            continue
        settings_evidence = sources.endpoint_evidence(settings_payload, "sharePointSettings", singleton=True)
        settings_fields = (
            external_sharing.tenant_settings_fields(settings_evidence.rows[0])
            if settings_evidence.state == EVIDENCE_COLLECTED and settings_evidence.rows
            else {}
        )
        sharepoint_tenant_settings.append(
            _record(
                external_sharing.KIND,
                f"{collector_name}.sharePointSettings",
                collector_name,
                collector=collector_name,
                source_name="sharePointSettings",
                read_state=settings_evidence.state,
                **settings_fields,
            )
        )
    purview_audit_jobs = [
        _record(
            "purview_audit_job",
            "purview.auditLogJobs",
            str(item.get("id") or item.get("name")),
            status=item.get("status"),
            created_date_time=item.get("createdDateTime") or item.get("createdDateTimeUTC"),
            operation=item.get("operation"),
            error_code=item.get("errorCode"),
            source=item.get("source"),
        )
        for item in _values(collector_payloads.get("purview", {}), "auditLogJobs")
        if item.get("id") or item.get("name")
    ]
    purview_audit_exports = [
        _record(
            "purview_audit_export",
            "purview.auditLogExports",
            str(item.get("id") or item.get("name")),
            status=item.get("status"),
            export_id=item.get("exportId"),
            download_url=item.get("downloadUrl") or item.get("download_url"),
            created_date_time=item.get("createdDateTime") or item.get("createdDateTimeUTC"),
            source=item.get("source"),
        )
        for item in _values(collector_payloads.get("purview", {}), "auditLogExports")
        if item.get("id") or item.get("name")
    ]
    purview_retention_labels = [
        _record(
            "purview_retention_label",
            "purview.retentionLabels",
            str(item.get("id") or item.get("name")),
            display_name=item.get("name") or item.get("displayName"),
            retention_duration=item.get("retentionDuration"),
            enabled=item.get("isEnabled"),
        )
        for item in _values(collector_payloads.get("purview", {}), "retentionLabels")
        if item.get("id") or item.get("name")
    ]
    purview_retention_policies = [
        _record(
            "purview_retention_policy",
            "purview.retentionPolicies",
            str(item.get("id") or item.get("name")),
            display_name=item.get("name") or item.get("displayName"),
            priority=item.get("priority"),
            type=item.get("type"),
        )
        for item in _values(collector_payloads.get("purview", {}), "retentionPolicies")
        if item.get("id") or item.get("name")
    ]
    purview_dlp_policies = [
        _record(
            "purview_dlp_policy",
            "purview.dlpPolicies",
            str(item.get("id") or item.get("name")),
            display_name=item.get("name") or item.get("displayName"),
            description=item.get("description"),
            priority=item.get("priority"),
        )
        for item in _values(collector_payloads.get("purview", {}), "dlpPolicies")
        if item.get("id") or item.get("name")
    ]
    cross_tenant_default_objects = [
        _record(
            "cross_tenant_default",
            "cross_tenant_access.defaultPolicy",
            "default",
            is_service_default=item.get("is_service_default"),
            b2b_collaboration_outbound_access=item.get("b2b_collaboration_outbound_access"),
            b2b_collaboration_inbound_access=item.get("b2b_collaboration_inbound_access"),
            b2b_direct_connect_outbound_access=item.get("b2b_direct_connect_outbound_access"),
            b2b_direct_connect_inbound_access=item.get("b2b_direct_connect_inbound_access"),
            inbound_trust_mfa_accepted=item.get("inbound_trust_mfa_accepted"),
            inbound_trust_compliant_device_accepted=item.get("inbound_trust_compliant_device_accepted"),
            inbound_trust_hybrid_aad_joined_accepted=item.get("inbound_trust_hybrid_aad_joined_accepted"),
            automatic_user_consent_inbound_allowed=bool(item.get("automatic_user_consent_inbound_allowed")),
            automatic_user_consent_outbound_allowed=bool(item.get("automatic_user_consent_outbound_allowed")),
        )
        for item in _values(collector_payloads.get("cross_tenant_access", {}), "defaultPolicy")
    ]
    cross_tenant_partner_objects = [
        _record(
            "cross_tenant_partner",
            "cross_tenant_access.partnerConfigurations",
            str(item.get("tenant_id") or item.get("id") or ""),
            tenant_id=item.get("tenant_id"),
            is_service_provider=bool(item.get("is_service_provider")),
            b2b_collaboration_outbound_access=item.get("b2b_collaboration_outbound_access"),
            b2b_collaboration_inbound_access=item.get("b2b_collaboration_inbound_access"),
            b2b_direct_connect_outbound_access=item.get("b2b_direct_connect_outbound_access"),
            b2b_direct_connect_inbound_access=item.get("b2b_direct_connect_inbound_access"),
            inbound_trust_mfa_accepted=item.get("inbound_trust_mfa_accepted"),
            inbound_trust_compliant_device_accepted=item.get("inbound_trust_compliant_device_accepted"),
            inbound_trust_hybrid_aad_joined_accepted=item.get("inbound_trust_hybrid_aad_joined_accepted"),
        )
        for item in _values(collector_payloads.get("cross_tenant_access", {}), "partnerConfigurations")
        if item.get("tenant_id") or item.get("id")
    ]
    inbox_rule_objects = [
        _record(
            "inbox_rule",
            "mailbox_forwarding.messageRules",
            f"{item.get('user_id')}:{item.get('rule_id')}",
            user_id=item.get("user_id"),
            rule_id=item.get("rule_id"),
            user_principal_name=item.get("user_principal_name"),
            user_mail=item.get("user_mail"),
            display_name=item.get("display_name"),
            is_enabled=item.get("is_enabled"),
            sequence=item.get("sequence"),
            forwards_externally=bool(item.get("forwards_externally")),
            forwards_internally=bool(item.get("forwards_internally")),
            external_recipients=item.get("external_recipients") or [],
            internal_recipients=item.get("internal_recipients") or [],
            move_to_folder=item.get("move_to_folder"),
            delete_action=bool(item.get("delete_action")),
            hide_from_user=bool(item.get("hide_from_user")),
        )
        for item in _values(collector_payloads.get("mailbox_forwarding", {}), "messageRules")
        if item.get("user_id") and item.get("rule_id")
    ]
    mailbox_setting_objects = [
        _record(
            "mailbox_settings",
            "mailbox_forwarding.mailboxSettings",
            str(item.get("user_id")),
            user_principal_name=item.get("user_principal_name"),
            # Replay fixtures can carry auto-reply bodies that live collection would have dropped.
            settings=minimise_mailbox_settings(item["settings"]) if isinstance(item.get("settings"), dict) else {},
        )
        for item in _values(collector_payloads.get("mailbox_forwarding", {}), "mailboxSettings")
        if item.get("user_id")
    ]
    application_credential_objects = [
        _record(
            "application_credentials",
            "app_credentials.applicationCredentials",
            str(item.get("id")),
            display_name=item.get("display_name"),
            app_id=item.get("app_id"),
            created_date_time=item.get("created_date_time"),
            sign_in_audience=item.get("sign_in_audience"),
            publisher_domain=item.get("publisher_domain"),
            password_credentials=item.get("password_credentials") or [],
            key_credentials=item.get("key_credentials") or [],
            redirect_uris=item.get("redirect_uris") or [],
            owner_count=item.get("owner_count"),
            federated_credentials=item.get("federated_credentials") or [],
            required_resource_access=item.get("required_resource_access") or [],
            # Populated from the beta /reports/servicePrincipalSignInActivities report
            # (AuditLog.Read.All). When that report is unavailable the collector sets
            # signin_data_available=False and the dormant-credential finding stays inert.
            # (User signInActivity, by contrast, is v1.0 and handled in identity.)
            last_signin_at=item.get("last_signin_at"),
            signin_data_available=bool(item.get("signin_data_available")),
        )
        for item in _values(collector_payloads.get("app_credentials", {}), "applicationCredentials")
        if item.get("id")
    ]
    service_principal_credential_objects = [
        _record(
            "service_principal_credentials",
            "app_credentials.servicePrincipalCredentials",
            str(item.get("id")),
            display_name=item.get("display_name"),
            app_id=item.get("app_id"),
            service_principal_type=item.get("service_principal_type"),
            publisher_name=item.get("publisher_name"),
            sign_in_audience=item.get("sign_in_audience"),
            account_enabled=item.get("account_enabled"),
            app_owner_organization_id=item.get("app_owner_organization_id"),
            tags=item.get("tags") or [],
            password_credentials=item.get("password_credentials") or [],
            key_credentials=item.get("key_credentials") or [],
            reply_urls=item.get("reply_urls") or [],
            owner_count=item.get("owner_count"),
        )
        for item in _values(collector_payloads.get("app_credentials", {}), "servicePrincipalCredentials")
        if item.get("id")
    ]
    dns_posture_objects = [
        _record(
            "dns_posture",
            "dns_posture.domainPosture",
            str(item.get("domain")),
            domain=item.get("domain"),
            managed_by_microsoft=bool(item.get("managed_by_microsoft")),
            authentication_type=item.get("authentication_type") or item.get("authenticationType"),
            is_default=item.get("isDefault"),
            resolver_error=item.get("resolver_error"),
            spf_present=_dns_presence(item, "spf"),
            spf_all_qualifier=(item.get("spf") or {}).get("all_qualifier"),
            spf_mechanisms=(item.get("spf") or {}).get("mechanisms"),
            spf_multiple_records=bool((item.get("spf") or {}).get("multiple_records")),
            dmarc_present=_dns_presence(item, "dmarc"),
            dmarc_policy=(item.get("dmarc") or {}).get("policy"),
            dmarc_subdomain_policy=(item.get("dmarc") or {}).get("subdomain_policy"),
            dmarc_pct=(item.get("dmarc") or {}).get("pct"),
            dmarc_pct_partial=bool((item.get("dmarc") or {}).get("pct_partial")),
            dmarc_aggregate_addresses=(item.get("dmarc") or {}).get("aggregate_addresses"),
            dmarc_aggregate_invalid=(item.get("dmarc") or {}).get("aggregate_addresses_invalid") or [],
            dkim_selectors_present=(item.get("dkim") or {}).get("selectors_present") or [],
            dkim_selectors_missing=(item.get("dkim") or {}).get("selectors_missing") or [],
            dkim_selectors_unresolved=(item.get("dkim") or {}).get("selectors_unresolved") or [],
            mta_sts_dns_present=(
                None if item.get("resolver_error") else bool((item.get("mta_sts") or {}).get("dns_present"))
            ),
            mta_sts_id=(item.get("mta_sts") or {}).get("id"),
            mta_sts_policy_fetch_status=((item.get("mta_sts") or {}).get("policy") or {}).get("fetch_status"),
            mta_sts_policy_mode=((item.get("mta_sts") or {}).get("policy") or {}).get("mode"),
            mta_sts_policy_http_status=((item.get("mta_sts") or {}).get("policy") or {}).get("http_status"),
            # None when the bundle predates TLS-RPT collection, so absence is never inferred.
            tls_rpt_present=(
                _dns_presence(item, "tls_rpt") if isinstance(item.get("tls_rpt"), dict) else None
            ),
            tls_rpt_rua=(item.get("tls_rpt") or {}).get("rua") if isinstance(item.get("tls_rpt"), dict) else None,
            bimi_present=_dns_presence(item, "bimi"),
            bimi_logo_https=(item.get("bimi") or {}).get("logo_url_is_https"),
        )
        for item in _values(collector_payloads.get("dns_posture", {}), "domainPosture")
        if item.get("domain")
    ]
    public_footprint_objects = [
        _record(
            "public_footprint",
            "dns_posture.publicFootprint",
            str(item.get("domain")),
            domain=item.get("domain"),
            authentication_type=item.get("authentication_type"),
            is_default=item.get("is_default"),
            discovery_status=item.get("discovery_status"),
            tenant_id=item.get("tenant_id"),
            tenant_region_scope=item.get("tenant_region_scope"),
            tenant_region_sub_scope=item.get("tenant_region_sub_scope"),
            cloud_instance_name=item.get("cloud_instance_name"),
            issuer_host=item.get("issuer_host"),
        )
        for item in _values(collector_payloads.get("dns_posture", {}), "publicFootprint")
        if item.get("domain")
    ]
    identity_protection_objects = [
        _record(
            "identity_protection_summary",
            "identity_protection.riskyUserSummary",
            str(item.get("id") or "summary"),
            available=item.get("available"),
            sampled_count=item.get("sampled_count"),
            sample_limit=item.get("sample_limit"),
            at_risk_count=item.get("at_risk_count"),
            risk_state_counts=item.get("risk_state_counts"),
            risk_level_counts=item.get("risk_level_counts"),
        )
        for item in _values(collector_payloads.get("identity_protection", {}), "riskyUserSummary")
    ]
    detection_signal_objects = (
        [
            _record("detection_signal", "detection_coverage", str(row["name"]), **row)
            for row in build_detection_signals(sources.analysis_payloads(_DETECTION_SOURCE_COLLECTORS), diagnostics)
        ]
        if any(collector_payloads.get(name) for name in _DETECTION_SOURCE_COLLECTORS)
        else []
    )
    ediscovery_cases = [
        _record(
            "ediscovery_case",
            "ediscovery.caseOverview",
            str(item.get("id") or item.get("name")),
            display_name=item.get("name") or item.get("displayName"),
            status=item.get("status"),
            created_date_time=item.get("createdDateTime"),
        )
        for item in _values(collector_payloads.get("ediscovery", {}), "caseOverview")
        if item.get("id") or item.get("name")
    ]
    ediscovery_searches = [
        _record(
            "ediscovery_search",
            "ediscovery.searchList",
            str(item.get("id") or item.get("name")),
            display_name=item.get("name") or item.get("displayName"),
            case_id=item.get("caseId"),
            status=item.get("status"),
        )
        for item in _values(collector_payloads.get("ediscovery", {}), "searchList")
        if item.get("id") or item.get("name")
    ]
    ediscovery_export_jobs = [
        _record(
            "ediscovery_export_job",
            "ediscovery.exportJobs",
            str(item.get("id") or item.get("name")),
            status=item.get("status"),
            case_id=item.get("caseId"),
            created_date_time=item.get("createdDateTime"),
        )
        for item in _values(collector_payloads.get("ediscovery", {}), "exportJobs")
        if item.get("id") or item.get("name")
    ]
    ediscovery_review_sets = [
        _record(
            "ediscovery_review_set",
            "ediscovery.reviewSets",
            str(item.get("id") or item.get("name")),
            status=item.get("status"),
            source=item.get("source"),
        )
        for item in _values(collector_payloads.get("ediscovery", {}), "reviewSets")
        if item.get("id") or item.get("name")
    ]

    # ----- Capability-gated collector sections (A7 normalize coverage) -----
    # Each gated collector exposes a small structured payload when the underlying
    # service is provisioned; flattening to records ensures the evidence DB indexes
    # the data and downstream report-pack consumers can reference it. When the
    # service is not provisioned the source list is empty and the section stays
    # absent (records_by_section drops empty values via object_counts).

    power_platform_environment_records = [
        _record(
            "power_platform_environment",
            "power_platform.environments",
            str(item.get("id") or item.get("name")),
            display_name=item.get("display_name") or item.get("displayName"),
            environment_sku=item.get("environment_sku") or item.get("environmentSku"),
            is_default=bool(item.get("is_default") or item.get("isDefault")),
            created_time=item.get("created_time") or item.get("createdTime"),
        )
        for item in _values(collector_payloads.get("power_platform", {}), "environments")
        if item.get("id") or item.get("name")
    ]
    power_platform_dlp_policy_records = [
        _record(
            "power_platform_dlp_policy",
            "power_platform.dlpPolicies",
            str(item.get("id") or item.get("name") or item.get("display_name") or "policy"),
            display_name=item.get("display_name"),
            environment_type=item.get("environment_type"),
            business_connector_count=item.get("business_connector_count"),
            non_business_connector_count=item.get("non_business_connector_count"),
            blocked_connector_count=item.get("blocked_connector_count"),
        )
        for item in _values(collector_payloads.get("power_platform", {}), "dlpPolicies")
        if item.get("id") or item.get("name") or item.get("display_name")
    ]
    power_platform_tenant_setting_records = [
        _record(
            "power_platform_tenant_setting",
            "power_platform.tenantSettings",
            "tenant",
            **{k: v for k, v in item.items() if isinstance(k, str)},
        )
        for item in _values(collector_payloads.get("power_platform", {}), "tenantSettings")
    ]

    sentinel_xdr_incident_records = [
        _record(
            "sentinel_xdr_incident",
            "sentinel_xdr.xdrIncidents",
            str(item.get("id") or item.get("incidentId") or ""),
            display_name=item.get("displayName"),
            severity=item.get("severity"),
            status=item.get("status"),
            classification=item.get("classification"),
            created=item.get("createdDateTime"),
        )
        for item in _values(collector_payloads.get("sentinel_xdr", {}), "xdrIncidents")
        if item.get("id") or item.get("incidentId")
    ]
    sentinel_xdr_alert_records = [
        _record(
            "sentinel_xdr_alert",
            "sentinel_xdr.xdrAlerts",
            str(item.get("id") or ""),
            title=item.get("title"),
            severity=item.get("severity"),
            status=item.get("status"),
            category=item.get("category"),
            created=item.get("createdDateTime"),
        )
        for item in _values(collector_payloads.get("sentinel_xdr", {}), "xdrAlerts")
        if item.get("id")
    ]

    defender_cloud_apps_consent_records = [
        _record(
            "defender_cloud_apps_consent_request",
            "defender_cloud_apps.appConsentRequests",
            str(item.get("id") or ""),
            app_id=item.get("appId") or item.get("applicationId"),
            status=item.get("status"),
            created=item.get("createdDateTime"),
        )
        for item in _values(collector_payloads.get("defender_cloud_apps", {}), "appConsentRequests")
        if item.get("id")
    ]

    copilot_admin_setting_records = [
        _record(
            "copilot_admin_setting",
            "copilot_governance.copilotAdminSettings",
            str(item.get("id") or "settings"),
            **{k: v for k, v in item.items() if isinstance(k, str) and k != "id"},
        )
        for item in _values(collector_payloads.get("copilot_governance", {}), "copilotAdminSettings")
    ]
    copilot_usage_records = [
        _record(
            "copilot_usage_summary",
            "copilot_governance.copilotUsageReports",
            str(item.get("id") or item.get("reportPeriod") or "summary"),
            report_period=item.get("reportPeriod"),
            assigned_users=item.get("assignedUsers"),
            active_users=item.get("activeUsers"),
            created=item.get("reportRefreshDate"),
        )
        for item in _values(collector_payloads.get("copilot_governance", {}), "copilotUsageReports")
    ]

    records_by_section = {
        "users": users,
        "groups": groups,
        "applications": applications,
        "service_principals": service_principals,
        "role_definitions": role_definitions,
        "role_assignments": role_assignments,
        "group_membership_edges": group_membership_edges,
        "app_owner_edges": app_owner_edges,
        "devices": devices,
        "incidents": incidents,
        "security_scores": security_scores,
        "security_score_control_profiles": security_score_control_profiles,
        "security_signin_events": security_signin_events,
        "security_directory_audit_events": security_directory_audit_events,
        "mailboxes": mailboxes,
        "policies": policies,
        "auth_method_registration_objects": auth_method_registration_records,
        "sites": sites,
        "sharepoint_site_posture_objects": sharepoint_site_posture_objects,
        "sharepoint_permission_edges": sharepoint_permission_edges,
        "sharepoint_sharing_findings": sharepoint_sharing_findings,
        "application_consents": application_consents,
        "license_inventory": license_inventory,
        "exchange_policy_objects": _disambiguate_keys(exchange_policy_objects),
        "governance_objects": governance_objects,
        "intune_assignment_objects": intune_assignment_objects,
        "intune_policy_assignment_objects": _disambiguate_keys(intune_policy_assignment_objects),
        "teams_policy_objects": _disambiguate_keys(teams_policy_objects),
        "service_health_objects": service_health_objects,
        "usage_report_objects": usage_report_objects,
        "usage_report_setting_objects": usage_report_setting_objects,
        "external_identity_objects": external_identity_objects,
        "consent_policy_objects": consent_policy_objects,
        "domain_hybrid_objects": domain_hybrid_objects,
        "onedrive_posture_objects": onedrive_posture_objects,
        external_sharing.SECTION: sharepoint_tenant_settings,
        "purview_audit_jobs": purview_audit_jobs,
        "purview_audit_exports": purview_audit_exports,
        "purview_retention_labels": purview_retention_labels,
        "purview_retention_policies": purview_retention_policies,
        "purview_dlp_policies": purview_dlp_policies,
        "application_credential_objects": application_credential_objects,
        "service_principal_credential_objects": service_principal_credential_objects,
        "inbox_rule_objects": inbox_rule_objects,
        "mailbox_setting_objects": mailbox_setting_objects,
        "cross_tenant_default_objects": cross_tenant_default_objects,
        "cross_tenant_partner_objects": cross_tenant_partner_objects,
        "dns_posture_objects": dns_posture_objects,
        "public_footprint_objects": public_footprint_objects,
        "identity_protection_objects": identity_protection_objects,
        "detection_signal_objects": detection_signal_objects,
        "ediscovery_cases": ediscovery_cases,
        "ediscovery_searches": ediscovery_searches,
        "ediscovery_export_jobs": ediscovery_export_jobs,
        "ediscovery_review_sets": ediscovery_review_sets,
        # Capability-gated sections (A7) — drop out via empty-section pruning
        # below when the underlying tenant lacks the feature.
        "power_platform_environment_objects": power_platform_environment_records,
        "power_platform_dlp_policy_objects": power_platform_dlp_policy_records,
        "power_platform_tenant_setting_objects": power_platform_tenant_setting_records,
        "sentinel_xdr_incident_objects": sentinel_xdr_incident_records,
        "sentinel_xdr_alert_objects": sentinel_xdr_alert_records,
        "defender_cloud_apps_consent_objects": defender_cloud_apps_consent_records,
        "copilot_admin_setting_objects": copilot_admin_setting_records,
        "copilot_usage_objects": copilot_usage_records,
    }
    records_by_section.update(_build_endpoint_records(sources, collector_payloads, devices, as_of.date() if as_of else None))
    directory_payload = collector_payloads.get("directory_relationships", {})
    if directory_payload:
        directory_payload = sources.analysis_payloads(("directory_relationships",))["directory_relationships"]
        for section, payload in normalize_directory_relationships(directory_payload).items():
            records_by_section[section] = payload["records"]

    # The effective administrator set comes first: the break-glass check reads the roles each account holds and the
    # administrator MFA verdict reads who the administrators are.
    effective_admin_records = _build_effective_admin_records(
        sources,
        collector_payloads,
        result_rows,
        users=users,
        groups=groups,
        service_principals=service_principals,
        role_definitions=role_definitions,
        role_assignments=role_assignments,
        governance_objects=governance_objects,
        group_membership_edges=group_membership_edges,
    )
    configured_break_glass = break_glass.configured_accounts(break_glass_accounts)
    (
        conditional_access_graph_records,
        relationships,
        graph_summary,
        policy_findings,
        break_glass_record,
        break_glass_accounts_resolved,
    ) = _build_conditional_access_graph(
        policies=_values(collector_payloads.get("conditional_access", {}), "conditionalAccessPolicies"),
        identity_payload=collector_payloads.get("identity", {}),
        named_locations=_values(collector_payloads.get("conditional_access", {}), "namedLocations"),
        auth_strengths=_values(collector_payloads.get("conditional_access", {}), "authenticationStrengthPolicies"),
        auth_contexts=_values(collector_payloads.get("conditional_access", {}), "authenticationContextClassReferences"),
        auth_methods_payload=collector_payloads.get("auth_methods", {}),
        values=_values,
        break_glass_accounts=configured_break_glass,
        admin_rows=effective_admin_records,
        membership_edges=group_membership_edges,
    )
    if break_glass_record:
        records_by_section[break_glass.SECTION] = [break_glass_record]
    if conditional_access_graph_records:
        records_by_section["conditional_access_graph"] = conditional_access_graph_records
    if relationships:
        records_by_section["relationships"] = relationships
    if policy_findings:
        records_by_section["ca_findings"] = policy_findings
    identity_control_verdicts = _build_identity_control_verdicts(
        sources,
        collector_payloads,
        users=users,
        groups=groups,
        role_definitions=role_definitions,
        accounts=break_glass_accounts_resolved,
        admin_records=effective_admin_records,
        membership_edges=group_membership_edges,
    )
    if identity_control_verdicts:
        records_by_section[IDENTITY_CONTROL_SECTION] = identity_control_verdicts
    if effective_admin_records:
        records_by_section[EFFECTIVE_ADMIN_SECTION] = effective_admin_records

    for key, value in graph_summary.items():
        if value:
            # Make graph summary available in snapshot-level counts without inventing a separate section.
            pass

    translation_catalog, translation_warning_count = sources.friendly_names(records_by_section)
    if translation_catalog:
        records_by_section["translation_catalog"] = translation_catalog
    normalization_coverage = [sources.reports[key] for key in sorted(sources.reports)]
    if normalization_coverage:
        records_by_section["normalization_coverage"] = normalization_coverage
    incomplete_sections = [row["source"] for row in normalization_coverage if not row["complete"]]
    collection_limited_sections = [row["source"] for row in normalization_coverage if row["collection_limited"]]
    # Every list that was cut short is a coverage gap: from the coverage ledger, the raw sections,
    # and any endpoint whose read says it stopped at a limit.
    gap_truncations = list_truncations(coverage_rows)
    gap_truncations.extend(truncations_from_payloads(collector_payloads, gap_truncations))
    gap_keys = {(item["collector"], item["list"]) for item in gap_truncations}
    for row in normalization_coverage:
        # A fan-out wrapper restates its own coverage row (privilegedGroupFanout and the like).
        if row["collection_limited"] and not row["derived_fanout"] and (row["collector"], row["source_name"]) not in gap_keys:
            gap_keys.add((row["collector"], row["source_name"]))
            gap = {
                "collector": row["collector"],
                "list": row["source_name"],
                "rows_collected": row["record_count"],
                "reason": row["truncation_reason"] or REASON_UNKNOWN,
            }
            if row["result_limit"]:
                gap["result_limit"] = row["result_limit"]
            gap_truncations.append(gap)
    collection_gaps = collection_gap_records(sorted(gap_truncations, key=lambda item: (item["collector"], item["list"])))
    if collection_gaps:
        records_by_section[COLLECTION_GAP_SECTION] = collection_gaps
    # Event logs read as a sample by design (the newest events), cut at that bound: not a gap, but the rules that read
    # them cannot call "no finding" a pass. The time span says how far back the sample reaches.
    bounded_samples = bounded_sample_records(
        coverage_rows,
        collector_payloads,
        spans={
            ("security", "signIns"): event_span(row.get("created") for row in security_signin_events),
            ("security", "directoryAudits"): event_span(row.get("activity_time") for row in security_directory_audit_events),
        },
    )
    if bounded_samples:
        records_by_section[BOUNDED_SAMPLE_SECTION] = bounded_samples

    object_counts = {name: len(records) for name, records in records_by_section.items() if records}
    full_counts, sample_counts, chunk_counts, truncated_sections, chunk_paths = _collector_count_summaries(
        collector_payloads,
        coverage_rows,
    )
    all_diagnostics = [
        *diagnostics,
        *build_normalization_diagnostics({"normalization_coverage": {"records": normalization_coverage}}),
    ]
    diagnostic_classes = Counter(str(item.get("error_class") or "unknown") for item in all_diagnostics)

    normalized: dict[str, dict[str, Any]] = {
        "snapshot": {
            "tenant_name": tenant_name,
            "run_id": run_id,
            "object_counts": object_counts,
            "normalized_counts": object_counts,
            "full_counts": full_counts,
            "full_counts_basis": "maximum_per_source_not_unique_union",
            "sample_counts": sample_counts,
            "chunk_counts": chunk_counts,
            "chunk_paths": chunk_paths,
            "sample_truncated": bool(truncated_sections),
            "truncated_sections": truncated_sections,
            "normalization_scope": "collected_rows",
            "normalization_complete": not incomplete_sections,
            "normalization_issue_count": sum(len(row["issues"]) for row in normalization_coverage),
            "normalization_incomplete_sections": incomplete_sections,
            "collection_limited_sections": collection_limited_sections,
            "collection_gap_count": len(collection_gaps),
            "collector_count": len(result_rows),
            "coverage_row_count": len(coverage_rows),
            "blocker_count": len(all_diagnostics),
            "diagnostic_classes": dict(diagnostic_classes),
            "friendly_name_warning_count": translation_warning_count,
        }
    }
    for section, records in records_by_section.items():
        if records:
            normalized[section] = {"kind": section, "records": _ordered_value(records)}
    return _ordered_value(normalized)


def build_normalization_diagnostics(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Promote unreadable collected evidence to ordinary run coverage blockers.

    Call after normalization and before findings/coverage-ledger finalization.
    A list cut short is not a read failure: its collector already reports ``partial`` and the cut
    is listed in ``collection_gaps``, so it is not promoted here.
    """
    diagnostics = []
    for row in (normalized_snapshot.get("normalization_coverage") or {}).get("records", []):
        if row.get("complete") is not False:
            continue
        diagnostics.append(
            {
                "collector": row["collector"],
                "item": row["source_name"],
                "status": "partial",
                "error_class": "incomplete_evidence",
                "error": "Collected endpoint evidence could not be read completely; review normalization coverage.",
                "evidence_refs": [
                    {
                        "artifact_path": "normalized/normalization_coverage.json",
                        "artifact_kind": "normalized_json",
                        "collector": row["collector"],
                        "record_key": row["key"],
                        "source_name": row["source_name"],
                    }
                ],
            }
        )
    return diagnostics


def build_ai_safe_summary(
    normalized_snapshot: dict[str, dict[str, Any]],
    *,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    snapshot = normalized_snapshot.get("snapshot", {})
    findings = findings or []
    return {
        "tenant_name": snapshot.get("tenant_name"),
        "run_id": snapshot.get("run_id"),
        "object_counts": snapshot.get("normalized_counts", snapshot.get("object_counts", {})),
        "normalized_counts": snapshot.get("normalized_counts", snapshot.get("object_counts", {})),
        "full_counts": snapshot.get("full_counts", {}),
        "full_counts_basis": snapshot.get("full_counts_basis"),
        "sample_counts": snapshot.get("sample_counts", {}),
        "chunk_counts": snapshot.get("chunk_counts", {}),
        "sample_truncated": snapshot.get("sample_truncated", False),
        "truncated_sections": snapshot.get("truncated_sections", []),
        "normalization_scope": snapshot.get("normalization_scope"),
        "normalization_complete": snapshot.get("normalization_complete"),
        "normalization_issue_count": snapshot.get("normalization_issue_count", 0),
        "normalization_incomplete_sections": snapshot.get("normalization_incomplete_sections", []),
        "collection_limited_sections": snapshot.get("collection_limited_sections", []),
        "collection_gap_count": snapshot.get("collection_gap_count", 0),
        "blocker_count": snapshot.get("blocker_count", 0),
        "translation_catalog_count": len((normalized_snapshot.get("translation_catalog") or {}).get("records", [])),
        "friendly_name_warning_count": snapshot.get("friendly_name_warning_count", 0),
        "privacy_level": "ai_safe_redacted",
        "redaction_mode": "summary_only",
        "contains_pii": False,
        "contains_auth_claims": False,
        "safe_for_external_llm": True,
        "findings_count": len(findings),
        "top_findings": [
            {
                "id": item.get("id"),
                "severity": item.get("severity"),
                "category": item.get("category"),
                "title": item.get("title"),
            }
            for item in findings[:10]
        ],
    }
