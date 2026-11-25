from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from azure_tenant_audit.collection_gaps import (
    BOUNDED_SAMPLE_SECTION,
    COLLECTION_GAP_SECTION,
    bounded_sample_records,
    collection_gap_records,
    list_truncations,
    section_was_cut,
    truncations_from_payloads,
)
from azure_tenant_audit.data_minimisation import (
    minimise_gmail_settings,
    minimise_policy_settings,
)

from .collectors import (
    POLICY_SECTION_PROBLEMS,
    POLICY_TARGET_PROBLEMS,
    POLICY_UNIT_ID,
    SUBJECT_SCOPE_ADMIN,
    SUBJECT_SCOPE_USER,
    SUBJECT_SCOPED_COLLECTORS,
    finite_number,
    policy_problems,
    policy_query_target,
    policy_row_readable,
    two_step_subset_differs,
)


def _values(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    section = payload.get(key, {})
    values = section.get("value", []) if isinstance(section, dict) else []
    return [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []


def _alert_metadata(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _compact(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if value not in (None, [], {}, "")}


def _record(kind: str, source: str, object_id: str, **fields: Any) -> dict[str, Any]:
    payload = {"kind": kind, "source": source, "id": object_id, "key": f"{kind}:{object_id}"}
    payload.update(fields)
    return _compact(payload)


def _email_domain(value: Any) -> str | None:
    text = str(value or "")
    if "@" not in text:
        return None
    return text.rsplit("@", 1)[1].lower()


def _utc_text(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _epoch_text(value: Any) -> str | None:
    """A Google int64 timestamp (epoch seconds or milliseconds) as UTC ISO text; None when absent or zero."""
    text = str(value or "").strip()
    if not text.isdigit():
        return None
    number = int(text)
    if number <= 0:
        return None
    if len(text) == 8:
        # An Android patch level is sometimes a YYYYMMDD date rather than an epoch.
        try:
            return _utc_text(datetime.strptime(text, "%Y%m%d").replace(tzinfo=UTC))
        except ValueError:
            return None
    seconds = number / 1000 if number > 10**11 else number
    try:
        return _utc_text(datetime.fromtimestamp(seconds, tz=UTC))
    except (OverflowError, OSError, ValueError):
        return None


def _auto_update_expiration(item: dict[str, Any]) -> tuple[str | None, str | None]:
    """ChromeOS auto-update expiration as UTC text, and which API field it came from."""
    through = _parse_timestamp(item.get("autoUpdateThrough"))
    if through is not None:
        return _utc_text(through), "autoUpdateThrough"
    legacy = _epoch_text(item.get("autoUpdateExpiration"))
    return (legacy, "autoUpdateExpiration") if legacy else (None, None)


_NEGATIVE_STATES = ("not encrypted", "unencrypted", "no encryption", "not enabled", "disabled", "off", "not set", "no password", "non compliant", "noncompliant", "not compliant")
_POSITIVE_STATES = ("encrypted", "enabled", "on", "set", "compliant", "password enabled")


def _device_state(value: Any, *, positive: str, negative: str) -> str | None:
    """Tri-state of a device posture string; None when absent or in a form this tool does not recognise.

    The Directory API does not enumerate the values of ``encryptionStatus`` or ``devicePasswordStatus``,
    so an unrecognised value is unknown, never a pass and never a failure. The raw text is kept beside it.
    """
    text = " ".join(str(value or "").replace("_", " ").replace("-", " ").lower().split())
    if not text or text in {"unknown", "unspecified", "not supported", "unsupported", "n/a"}:
        return None
    if text in _NEGATIVE_STATES:
        return negative
    if text in _POSITIVE_STATES:
        return positive
    return None


# The Directory API describes ``deviceCompromisedStatus`` only as "the compromised device status" and
# lists no values. These are the texts seen in the Admin console and API output, and the Cloud Identity
# Devices enum (COMPROMISED, UNCOMPROMISED). Anything else is unknown: never a pass, never a failure.
COMPROMISED = "compromised"
NOT_COMPROMISED = "not_compromised"
UNKNOWN_COMPROMISE = "unknown"
_COMPROMISED_TEXTS = frozenset({"compromised", "compromise detected", "device compromised"})
_NOT_COMPROMISED_TEXTS = frozenset({"no compromise detected", "no compromise", "not compromised", "uncompromised"})


def compromised_state(value: Any) -> str:
    """``compromised``, ``not_compromised`` or ``unknown`` for a ``deviceCompromisedStatus`` value.

    Only the recognised texts classify. An absent field, ``unknown`` or ``COMPROMISED_STATE_UNSPECIFIED``,
    or any text this tool has not seen, is ``unknown``; the raw text stays on the record beside it.
    """
    text = " ".join(str(value or "").replace("_", " ").replace("-", " ").lower().split())
    if text in _COMPROMISED_TEXTS:
        return COMPROMISED
    if text in _NOT_COMPROMISED_TEXTS:
        return NOT_COMPROMISED
    return UNKNOWN_COMPROMISE


_POLICY_PREFIX = "settings/"


def _policy_value(setting: dict[str, Any], *names: str) -> Any:
    value = setting.get("value") if isinstance(setting.get("value"), dict) else {}
    for name in names:
        if value.get(name) not in (None, ""):
            return value.get(name)
    return None


def _org_unit_key(value: Any) -> str:
    """An org unit id without the ``id:`` (Directory) or ``orgUnits/`` (Policy API) prefix; ``""`` unless a string."""
    text = value.strip() if isinstance(value, str) else ""
    for prefix in ("orgUnits/", "id:"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    return text


def _org_unit_topology(
    directory: dict[str, Any] | None, coverage_rows: list[dict[str, Any]]
) -> tuple[bool, dict[str, str], set[str], int] | None:
    """The Directory org unit read as (complete, parents, root ids, malformed count); ``None`` without an ``orgUnits``.

    Every listed row counts, including ones that are not objects (``null``): the tree is checked on the list as read,
    never on the rows that happen to be readable. A section whose ``value`` is not a list is one malformed read.
    """
    if not isinstance(directory, dict) or not isinstance(directory.get("orgUnits"), dict):
        return None
    section = directory["orgUnits"]
    values = section.get("value")
    units = values if isinstance(values, list) else None
    parents, roots, malformed = _org_unit_tree(units or [])
    if units is None:
        malformed += 1
    complete = malformed == 0 and _read_complete("google_directory", section, None, coverage_rows, names=("orgUnits",))
    return complete, parents, roots, malformed


def _root_org_unit(
    directory: dict[str, Any] | None, coverage_rows: list[dict[str, Any]], policies: dict[str, Any] | None
) -> tuple[bool, set[str], set[str]]:
    """Whether the root organisational unit is positively identified, its id, and the ids of the other units.

    The Directory list holds no row for the root: it is the parent of the top-level units. A complete list that is
    empty means the root is the only unit; its id is then known only when the policies name exactly one unit, which
    must be the root (a second unit id can only be a unit the list does not hold, such as a deleted one whose policy
    lingers, so neither can be told to be the root). A list that was not read completely (not collected, failed,
    cut, or holding any row that cannot be read or does not hang from one root) leaves the root unknown, so no
    policy can be called organisation-wide.
    """
    topology = _org_unit_topology(directory, coverage_rows)
    if topology is None:
        return False, set(), set()
    complete, parents, roots, _malformed = topology
    if not complete:
        return False, set(), set()
    if not parents:
        named = _policy_org_units(policies)
        return len(named) == 1, named if len(named) == 1 else set(), set()
    return len(roots) == 1, roots, set(parents)


def _policy_org_units(policies: dict[str, Any] | None) -> set[str]:
    """The bare ids of every unit a policy of either policies section names as its ``orgUnit``."""
    named: set[str] = set()
    for name in _POLICY_READ_ROWS:
        section = (policies or {}).get(name)
        values = section.get("value") if isinstance(section, dict) else None
        for item in minimise_policy_settings(values) if isinstance(values, list) else []:
            query = item.get("policyQuery") if isinstance(item, dict) else None
            unit = policy_query_target(query, "orgUnit") if isinstance(query, dict) else None
            if isinstance(unit, str):
                named.add(unit)
    return named


def _org_unit_id(value: Any) -> str:
    """A Directory org unit id (``id:<id>``) as its bare id; ``""`` unless it is a sound id."""
    bare = _org_unit_key(value)
    return bare if POLICY_UNIT_ID.fullmatch(bare) else ""


def _org_unit_tree(units: list[Any]) -> tuple[dict[str, str], set[str], int]:
    """The units' parents, the root id(s) and how many units or tree checks failed.

    Ids must be sound id strings. The root is the parent of the top-level units (``parentOrgUnitPath`` ``/``); there
    must be exactly one, it must not be listed itself, and every unit's parent chain must reach it with no cycle. A
    unit listed twice under different parents fails too, and so does a row that is not an object.
    """
    parents: dict[str, str] = {}
    order: list[str] = []
    roots: set[str] = set()
    malformed = 0
    for unit in units:
        unit_id = _org_unit_id(unit.get("orgUnitId")) if isinstance(unit, dict) else ""
        parent_id = _org_unit_id(unit.get("parentOrgUnitId")) if isinstance(unit, dict) else ""
        if not unit_id or not parent_id:
            malformed += 1
            continue
        if unit.get("parentOrgUnitPath") == "/":
            roots.add(parent_id)
        if unit_id in parents:
            if parents[unit_id] != parent_id:
                malformed += 1  # one unit listed under two parents: the tree cannot be trusted
            continue
        parents[unit_id] = parent_id
        order.append(unit_id)
    if len(roots) > 1 or (parents and not roots) or roots & set(parents):
        # Two roots, units with no top-level unit among them, or a root that is also listed: no single root.
        return parents, roots, malformed + 1
    for unit_id in order:
        seen: set[str] = set()
        node = unit_id
        while node not in roots:
            if node in seen or node not in parents:
                malformed += 1  # an orphan (its parent is not listed) or a cycle: not under the root
                break
            seen.add(node)
            node = parents[node]
    return parents, roots, malformed


def _query_scope_supported(query: dict[str, Any]) -> bool:
    """Whether a minimised policy's CEL query applies to exactly what its ``orgUnit`` and ``group`` fields say.

    No query (older evidence holds only the fields) or ``query_scope`` ``targets``; see
    :func:`azure_tenant_audit.data_minimisation.policy_query_scope`. Anything else is a scope the fields cannot show,
    so the policy is not unconditional evidence for that unit.
    """
    return query.get("query_scope") in (None, "targets")


def _policy_scope(record: dict[str, Any], *, root_known: bool, root_ids: set[str], unit_ids: set[str]) -> str:
    """``group``, ``organisation`` (the root unit, no group), ``org_unit`` or ``unclassified``.

    ``unclassified``: the root or the scope is unknown, or the policy names a unit the org unit read does not hold
    (a policy lingering after its unit was deleted): such a policy cannot be placed, never the root's.
    """
    if record.get("scope_supported") is False:
        return "unclassified"
    if record.get("group"):
        return "group"
    if not root_known:
        return "unclassified"
    unit = _org_unit_key(record.get("org_unit"))
    if unit in root_ids:
        return "organisation"
    return "org_unit" if unit in unit_ids else "unclassified"


_POLICY_READ_ROWS = ("twoStepVerificationPolicies", "policySettings")


def _read_complete(
    collector: str,
    section: Any,
    result_rows: list[dict[str, Any]] | None,
    coverage_rows: list[dict[str, Any]],
    *,
    names: tuple[str, ...] | None = None,
) -> bool:
    """Whether a collector's read of one section is complete: no coverage row failed or cut, no section marker.

    With ``result_rows`` the collector's own row must also be ``ok``; without one the read cannot be shown
    complete, so it is not. ``names`` limits the coverage rows to the ones of this section.
    """
    if result_rows is not None:
        statuses = [row.get("status") for row in result_rows if isinstance(row, dict) and row.get("name") == collector]
        if not statuses or any(status != "ok" for status in statuses):
            return False
    if any(
        row.get("status") not in (None, "ok") or row.get("collection_truncated") is True
        for row in coverage_rows
        if row.get("collector") == collector and (names is None or row.get("name") in names)
    ):
        return False
    return isinstance(section, dict) and not section_was_cut(section) and not (section.get("error") or section.get("error_class"))


def _policy_section(setting_type: Any) -> str | None:
    """``settings/gmail.auto_forwarding`` -> ``gmail_auto_forwarding``; ``None`` for anything else."""
    if not isinstance(setting_type, str) or not setting_type.startswith(_POLICY_PREFIX):
        return None
    section = setting_type.removeprefix(_POLICY_PREFIX).replace(".", "_")
    return section or None


def _policy_targets(policy: dict[str, Any]) -> tuple[str | None, str | None] | None:
    """A readable policy's bare (org unit, group) ids; ``None`` when its targets cannot be read."""
    query = policy.get("policyQuery")
    if not isinstance(query, dict):
        return None
    org_unit, group = policy_query_target(query, "orgUnit"), policy_query_target(query, "group")
    if org_unit is False or group is False or (org_unit is None and group is None):
        return None
    return org_unit, group  # type: ignore[return-value]


# Policy sections whose evidence decides the organisation's 2-step verification status.
_TWO_STEP_SECTION_PREFIX = "security_two_step_verification"


def _policy_read_state(complete: bool, records: int, malformed: int, unusable: set[str], scopes: set[tuple[str, str, str]]) -> dict[str, Any]:
    return {
        "kind": "google_policy_settings_read_state",
        "source": "google_policies.policySettings",
        "id": "read_state",
        "key": "google_policy_settings_read_state:read_state",
        "complete": complete,
        "record_count": records,
        "malformed_count": malformed,
        "unusable_sections": sorted(unusable),
        "unusable_scopes": [
            {"section": section, "org_unit": org_unit or None, "group": group or None}
            for section, org_unit, group in sorted(scopes)
        ],
    }


def _policy_settings_read(
    payload: dict[str, Any] | None, result_rows: list[dict[str, Any]], coverage_rows: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], bool | None]:
    """``google_policy_settings`` records and whether the read can decide the 2-step verification status.

    The records are one per usable Policy API policy plus one read-state record, absent (empty list) when the run
    holds no ``policySettings`` key, so an older bundle is not read as an empty but complete read; a key that holds
    anything but an object is a malformed section, never absent. Each policy is checked with
    :func:`policy_problems`:

    - a policy whose section cannot be told is malformed for the whole read;
    - one whose targets cannot be read makes its section unusable (``unusable_sections``, every record of it left out);
    - one with any other problem, a scope its targets cannot represent (an exception or another unit in its query),
      or no order against another policy of the same unit and section, makes that unit's setting unusable
      (``unusable_scopes``): those records are left out and every other unit's records are kept.

    Any of these makes the read incomplete: unknown is never safe. The second value is ``None`` without a
    ``policySettings`` key; otherwise whether the read is complete as far as the 2-step verification sections go.
    """
    if not isinstance(payload, dict) or "policySettings" not in payload:
        return [], None
    section = payload["policySettings"]
    values = section.get("value") if isinstance(section, dict) else None
    if not isinstance(values, list):
        return [_policy_read_state(False, 0, 1, set(), set())], False
    items = minimise_policy_settings(values)
    malformed = unattributed = 0
    unusable: set[str] = set()
    scopes: set[tuple[str, str, str]] = set()
    candidates: list[tuple[str, str | None, str | None, Any, dict[str, Any]]] = []
    for item in items:
        problems = set(policy_problems(item))
        setting = item.get("setting") if isinstance(item, dict) else None
        setting_section = None if problems & POLICY_SECTION_PROBLEMS else _policy_section(setting.get("type"))  # type: ignore[union-attr]
        if setting_section is None:
            malformed += 1
            unattributed += 1
            continue
        targets = None if problems & POLICY_TARGET_PROBLEMS else _policy_targets(item)
        if targets is None:
            malformed += 1
            unusable.add(setting_section)
            continue
        org_unit, group = targets
        if problems:
            malformed += 1
        if problems or not _query_scope_supported(item["policyQuery"]):
            scopes.add((setting_section, org_unit or "", group or ""))
            continue
        candidates.append((setting_section, org_unit, group, item["policyQuery"].get("sortOrder"), item))
    by_unit: dict[tuple[str, str, str], list[Any]] = defaultdict(list)
    for setting_section, org_unit, group, sort_order, _item in candidates:
        by_unit[(setting_section, org_unit or "", group or "")].append(sort_order)
    for scope, orders in by_unit.items():
        if len(orders) > 1 and (any(order is None for order in orders) or len(set(orders)) < len(orders)):
            # Two policies for one unit and section with no order between them: no reliable winner for that unit.
            scopes.add(scope)
    records: list[dict[str, Any]] = []
    seen: Counter[str] = Counter()
    for setting_section, org_unit, group, sort_order, item in candidates:
        if setting_section in unusable or (setting_section, org_unit or "", group or "") in scopes:
            continue
        key = f"{setting_section}|{org_unit or ''}|{group or ''}|{sort_order if sort_order is not None else ''}"
        seen[key] += 1
        record = _record(
            "google_policy_setting",
            "google_policies.policySettings",
            key if seen[key] == 1 else f"{key}#{seen[key]}",
            section=setting_section,
            unit_kind="group" if group else "org_unit",
            org_unit=org_unit,
            group=group,
            sort_order=sort_order if finite_number(sort_order) else None,
            policy_type=item.get("type"),
        )
        record["value"] = item["setting"]["value"]  # kept even when empty: an empty value is a setting at its defaults
        records.append(record)
    read_complete = _read_complete("google_policies", section, result_rows, coverage_rows) and bool(values)
    complete = read_complete and malformed == 0 and not unusable and not scopes
    records.append(_policy_read_state(complete, len(records), malformed, unusable, scopes))
    # A policy whose section cannot be told may be a 2-step verification one; others weaken only their own section.
    two_step_affected = any(name.startswith(_TWO_STEP_SECTION_PREFIX) for name in unusable | {scope[0] for scope in scopes})
    return records, read_complete and unattributed == 0 and not two_step_affected


def _org_unit_records(
    directory: dict[str, Any] | None, result_rows: list[dict[str, Any]], coverage_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """``google_org_units``: ``id``, ``parent_id`` and ``is_root`` per unit plus one read-state record.

    The OU path and name are never kept (they can be personal). The root has no row of its own in the Directory
    list, so it is added as the parent of the top-level units. Absent when the run holds no ``orgUnits`` section.
    A unit tree that does not hang from one root (see :func:`_org_unit_tree`) is not a complete read.
    """
    topology = _org_unit_topology(directory, coverage_rows)
    if topology is None:
        return []
    complete, parents, roots, malformed = topology
    records: list[dict[str, Any]] = [
        {"kind": "google_org_unit", "source": "google_directory.orgUnits", "id": unit_id, "key": f"google_org_unit:{unit_id}", "parent_id": parent_id, "is_root": False}
        for unit_id, parent_id in parents.items()
    ]
    for root in sorted(roots - set(parents)):
        records.append({"kind": "google_org_unit", "source": "google_directory.orgUnits", "id": root, "key": f"google_org_unit:{root}", "parent_id": None, "is_root": True})
    # Only the orgUnits read counts here: another directory list failing does not make the unit tree unknown.
    # A complete, empty list means the root is the only unit; its id is then not in this list (``root_id_known``).
    records.append(
        {
            "kind": "google_org_units_read_state",
            "source": "google_directory.orgUnits",
            "id": "read_state",
            "key": "google_org_units_read_state:read_state",
            "complete": complete,
            "root_id_known": len(roots) == 1 and malformed == 0,
            "record_count": len(records),
            "malformed_count": malformed,
        }
    )
    return records


def _two_step_policy_status(
    payload: dict[str, Any] | None,
    records: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
    now: datetime,
    *,
    widened_complete: bool | None = None,
) -> str:
    """Whether 2-step verification is enforced for the organisation.

    ``enforcing``: the organisation-level policy (root unit, no group) is in force. ``partial``: only
    some organisational units or groups are enforced, the organisation-level policy is not. ``scheduled``:
    every enforcement date is still ahead. ``not_enforced``: the read completed and no policy enforces.
    ``unknown``: the read did not happen or is incomplete, a policy cannot be read, or an enforcing policy cannot be
    placed in the organisation because the root unit is unknown. Unknown is never read as not enforced.

    ``widened_complete`` is ``None`` for an older bundle without the widened read. With it, the widened read must be
    complete for the 2-step verification sections, its 2-step verification list must be the subset of it, and
    ``not_enforced`` or ``partial`` needs the organisation's own enforcement policy positively read as not in force:
    the widened read returns every setting type at the root, so its absence means the read is not what was asked for.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("twoStepVerificationPolicies"), dict):
        return "unknown"
    section = payload["twoStepVerificationPolicies"]
    values = section.get("value")
    if not isinstance(values, list) or any(not policy_row_readable(item) for item in values):
        # A policy that cannot be read may be the organisation's enforcement: the status is unknown.
        return "unknown"
    if section.get("error") or section.get("error_class") or section_was_cut(section):
        # A read that failed or was cut may have left out the organisation's own policy.
        return "unknown"
    if widened_complete is False or (widened_complete is not None and two_step_subset_differs(payload)):
        return "unknown"
    rows = [row for row in coverage_rows if row.get("collector") == "google_policies"]
    # Since the SCuBA widening the one Policy API read is recorded as ``policySettings``; older bundles name it
    # ``twoStepVerificationPolicies``. Either failing leaves the 2-step verification status unknown.
    if any(row.get("status") not in (None, "ok") and row.get("name") in _POLICY_READ_ROWS for row in rows):
        return "unknown"
    truncated = any(row.get("collection_truncated") is True for row in rows)
    enforcement = [record for record in records if record.get("setting_type") == "security.two_step_verification_enforcement"]
    in_force = [record for record in enforcement if (_parse_timestamp(record.get("enforced_from")) or now + timedelta(days=1)) <= now]
    # A policy that cannot be placed (root unknown, unit not in the org unit read, scope unsupported) may be the
    # organisation's: only the organisation's own policy in force can decide the status past it.
    unplaced = any(record.get("policy_scope") == "unclassified" for record in enforcement)
    if in_force:
        scopes = {record.get("policy_scope") for record in in_force}
        if "organisation" in scopes:
            return "enforcing"
        if unplaced:
            return "unknown"
        if widened_complete is not None and not any(record.get("policy_scope") == "organisation" for record in enforcement):
            return "unknown"
        return "partial"
    if unplaced:
        return "unknown"
    if any(_parse_timestamp(record.get("enforced_from")) is not None for record in enforcement):
        return "scheduled"
    if widened_complete is not None and not any(record.get("policy_scope") == "organisation" for record in enforcement):
        return "unknown"
    return "unknown" if truncated else "not_enforced"


def _two_step_records(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    """``google_two_step_policies``: one record per readable 2-step verification policy.

    The policies are minimised first (no address or local path survives into a record) and must have no problem
    (:func:`policy_problems`), so every field copied is a checked id, number, Boolean, enum, duration or timestamp.
    The id is built from the setting type and targets, never from the policy's resource name. A policy that cannot be
    read gives no record (the status is then unknown); one whose query names another unit or holds an exception gets
    ``scope_supported`` false and is never placed in the organisation.
    """
    records: list[dict[str, Any]] = []
    seen: Counter[str] = Counter()
    section = (payload or {}).get("twoStepVerificationPolicies")
    values = section.get("value") if isinstance(section, dict) else None
    for item in minimise_policy_settings(values) if isinstance(values, list) else []:
        if not policy_row_readable(item):
            continue
        setting, query = item["setting"], item["policyQuery"]
        setting_type = setting["type"].removeprefix(_POLICY_PREFIX)
        org_unit = query.get("orgUnit") or None
        group = query.get("group") or None
        base = ":".join(part for part in (setting_type, org_unit, group) if part)
        seen[base] += 1
        record = _record(
            "google_two_step_policy",
            "google_policies.twoStepVerificationPolicies",
            base if seen[base] == 1 else f"{base}#{seen[base]}",
            setting_type=setting_type or None,
            policy_type=item.get("type"),
            org_unit=org_unit,
            group=group,
            sort_order=query.get("sortOrder"),
            enforced_from=_policy_value(setting, "enforcedFrom", "enforced_from"),
            allow_enrollment=_policy_value(setting, "allowEnrollment", "allow_enrollment"),
            allowed_sign_in_factor_set=_policy_value(setting, "allowedSignInFactorSet", "allowed_sign_in_factor_set"),
            enrollment_grace_period=_policy_value(setting, "enrollmentGracePeriod", "enrollment_grace_period"),
        )
        if not _query_scope_supported(query):
            record["scope_supported"] = False
        records.append(record)
    return records


def build_google_normalized_snapshot(
    *,
    tenant_name: str,
    run_id: str,
    collector_payloads: dict[str, dict[str, Any]],
    domain: str | None = None,
    customer_id: str | None = None,
    diagnostics: list[dict[str, Any]] | None = None,
    result_rows: list[dict[str, Any]] | None = None,
    coverage_rows: list[dict[str, Any]] | None = None,
    top_limit: int | None = None,
    as_of: datetime | None = None,
) -> dict[str, dict[str, Any]]:
    """Normalise a Google Workspace run. ``as_of`` (offline ``--as-of``) is the instant date-derived values use."""
    diagnostics = diagnostics or []
    result_rows = result_rows or []
    coverage_rows = coverage_rows or []
    workspace_domain = str(domain or "").lower() or None
    now = as_of or datetime.now(tz=UTC)

    users = [
        _record(
            "google_user",
            "google_directory.users",
            str(item.get("id") or item.get("primaryEmail")),
            primary_email=item.get("primaryEmail"),
            display_name=(item.get("name") or {}).get("fullName") if isinstance(item.get("name"), dict) else item.get("name"),
            is_admin=bool(item.get("isAdmin")),
            is_delegated_admin=bool(item.get("isDelegatedAdmin")),
            # Super admin or delegated admin: the flag the 2-step verification and stale-account rules use.
            is_privileged=bool(item.get("isAdmin") or item.get("isDelegatedAdmin")),
            suspended=bool(item.get("suspended")),
            archived=bool(item.get("archived")),
            is_enrolled_in_2sv=item.get("isEnrolledIn2Sv"),
            is_enforced_in_2sv=item.get("isEnforcedIn2Sv"),
            last_login_time=item.get("lastLoginTime"),
            creation_time=item.get("creationTime"),
            org_unit_path=item.get("orgUnitPath"),
            domain=_email_domain(item.get("primaryEmail")),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "users")
        if item.get("id") or item.get("primaryEmail")
    ]
    domain_records: list[dict[str, Any]] = []
    seen_domains: set[str] = set()
    for item in _values(collector_payloads.get("google_directory", {}), "domains"):
        domain_name = str(item.get("domainName") or item.get("domain") or "").strip().lower()
        if not domain_name or domain_name in seen_domains:
            continue
        seen_domains.add(domain_name)
        domain_records.append(
            _record(
                "google_domain",
                "google_directory.domains",
                domain_name,
                domain_name=domain_name,
                domain_kind="primary" if item.get("isPrimary") else "secondary",
                is_primary=bool(item.get("isPrimary")),
                verified=item.get("verified"),
            )
        )
        for alias in item.get("domainAliases") or []:
            if not isinstance(alias, dict):
                continue
            alias_name = str(alias.get("domainAliasName") or "").strip().lower()
            if not alias_name or alias_name in seen_domains:
                continue
            seen_domains.add(alias_name)
            domain_records.append(
                _record(
                    "google_domain",
                    "google_directory.domains",
                    alias_name,
                    domain_name=alias_name,
                    domain_kind="alias",
                    is_primary=False,
                    parent_domain=domain_name,
                    verified=alias.get("verified"),
                )
            )
    # Internal domains: every primary, secondary and alias domain of the customer, plus the --domain label.
    # With neither, the external-principal checks cannot say what is external and report unknown.
    internal_domains = sorted(seen_domains | ({workspace_domain} if workspace_domain else set()))
    domain_rows = [
        row for row in coverage_rows if row.get("collector") == "google_directory" and row.get("name") == "domains"
    ]
    domains_section = (collector_payloads.get("google_directory") or {}).get("domains")
    domains_incomplete = any(
        row.get("status") not in (None, "ok") or row.get("collection_truncated") is True for row in domain_rows
    ) or (isinstance(domains_section, dict) and domains_section.get("collection_truncated") is True)
    if seen_domains:
        # A list cut short or partly read can miss a secondary or alias domain, so it is not "known".
        internal_domains_status = "partial" if domains_incomplete else "known"
        internal_domains_source = "directory+label" if workspace_domain and workspace_domain not in seen_domains else "directory"
    elif workspace_domain:
        internal_domains_status = "label_only"
        internal_domains_source = "label"
    else:
        internal_domains_status = "unknown"
        internal_domains_source = "none"
    root_known, root_ids, unit_ids = _root_org_unit(
        collector_payloads.get("google_directory"), coverage_rows, collector_payloads.get("google_policies")
    )
    policy_records = _two_step_records(collector_payloads.get("google_policies"))
    for record in policy_records:
        # organisation (root unit, no group), org_unit, group, or unclassified when it cannot be placed
        record["policy_scope"] = _policy_scope(record, root_known=root_known, root_ids=root_ids, unit_ids=unit_ids)
    policy_setting_records, two_step_widened = _policy_settings_read(collector_payloads.get("google_policies"), result_rows, coverage_rows)
    org_unit_records = _org_unit_records(collector_payloads.get("google_directory"), result_rows, coverage_rows)
    groups = [
        _record(
            "google_group",
            "google_directory.groups",
            str(item.get("id") or item.get("email")),
            email=item.get("email"),
            display_name=item.get("name"),
            description=item.get("description"),
            direct_members_count=item.get("directMembersCount"),
            who_can_join=item.get("whoCanJoin"),
            who_can_view_membership=item.get("whoCanViewMembership"),
            domain=_email_domain(item.get("email")),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "groups")
        if item.get("id") or item.get("email")
    ]
    group_members = [
        _record(
            "google_group_member",
            "google_directory.groupMembers",
            f"{item.get('groupEmail')}:{item.get('id') or item.get('email')}",
            group_email=item.get("groupEmail"),
            email=item.get("email"),
            role=item.get("role"),
            type=item.get("type"),
            status=item.get("status"),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "groupMembers")
        if item.get("groupEmail") and (item.get("id") or item.get("email"))
    ]
    group_member_errors = [
        _record(
            "google_group_member_error",
            "google_directory.groupMembersErrors",
            str(item.get("groupEmail")),
            group_email=item.get("groupEmail"),
            error_class=item.get("error_class"),
            error=item.get("error"),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "groupMembersErrors")
        if item.get("groupEmail")
    ]
    alias_errors = [
        _record(
            "google_alias_error",
            "google_directory.aliasesErrors",
            str(item.get("userKey")),
            user_email=item.get("userKey"),
            error_class=item.get("error_class"),
            error=item.get("error"),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "aliasesErrors")
        if item.get("userKey")
    ]
    roles = {
        str(item.get("roleId")): item
        for item in _values(collector_payloads.get("google_directory", {}), "roles")
        if item.get("roleId")
    }
    role_assignments = [
        _record(
            "google_role_assignment",
            "google_directory.roleAssignments",
            str(item.get("roleAssignmentId") or f"{item.get('roleId')}:{item.get('assignedTo')}"),
            role_id=item.get("roleId"),
            role_name=(roles.get(str(item.get("roleId"))) or {}).get("roleName"),
            assigned_to=item.get("assignedTo"),
            scope_type=item.get("scopeType"),
            org_unit_id=item.get("orgUnitId"),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "roleAssignments")
        if item.get("roleId") or item.get("assignedTo")
    ]
    oauth_grants = [
        _record(
            "google_oauth_grant",
            "google_directory.oauthGrants",
            f"{item.get('userKey')}:{item.get('clientId') or item.get('client_id')}",
            user_email=item.get("userKey"),
            client_id=item.get("clientId") or item.get("client_id"),
            display_name=item.get("displayText") or item.get("display_name") or item.get("anonymous"),
            scopes=item.get("scopes") or [],
        )
        for item in _values(collector_payloads.get("google_directory", {}), "oauthGrants")
        if item.get("clientId") or item.get("client_id")
    ]
    oauth_grant_errors = [
        _record(
            "google_oauth_grant_error",
            "google_directory.oauthGrantsErrors",
            str(item.get("userKey")),
            user_email=item.get("userKey"),
            error_class=item.get("error_class"),
            error=item.get("error"),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "oauthGrantsErrors")
        if item.get("userKey")
    ]
    mailbox_settings = [
        _record(
            "google_mailbox_setting",
            "google_gmail_settings.mailboxSettings",
            str(item.get("userEmail")),
            user_email=item.get("userEmail"),
            auto_forwarding=item.get("autoForwarding"),
            auto_forwarding_error=item.get("autoForwarding_error") or {},
            filters=item.get("filters") or [],
            filters_error=item.get("filters_error") or {},
            forwarding_addresses=item.get("forwardingAddresses") or [],
            forwarding_addresses_error=item.get("forwardingAddresses_error") or {},
            send_as=minimise_gmail_settings(item).get("sendAs") or [],
            send_as_error=item.get("sendAs_error") or {},
            delegates=item.get("delegates") or [],
            delegates_error=item.get("delegates_error") or {},
            imap=item.get("imap") or {},
            imap_error=item.get("imap_error") or {},
            pop=item.get("pop") or {},
            pop_error=item.get("pop_error") or {},
            vacation=minimise_gmail_settings(item).get("vacation") or {},
            vacation_error=item.get("vacation_error") or {},
        )
        for item in _values(collector_payloads.get("google_gmail_settings", {}), "mailboxSettings")
        if item.get("userEmail")
    ]
    alerts = [
        _record(
            "google_alert",
            "google_alert_center.alerts",
            str(item.get("alertId") or item.get("id")),
            alert_type=item.get("type"),
            severity=_alert_metadata(item).get("severity") or item.get("severity"),
            status=_alert_metadata(item).get("status") or item.get("status"),
            deleted=item.get("deleted") is True,
            create_time=item.get("createTime"),
        )
        for item in _values(collector_payloads.get("google_alert_center", {}), "alerts")
        if item.get("alertId") or item.get("id")
    ]
    dns_posture = [
        _record(
            "google_domain_posture",
            "google_dns_posture.domainPosture",
            str(item.get("domain")),
            domain=item.get("domain"),
            resolver_error=item.get("resolver_error"),
            spf=item.get("spf"),
            dmarc=item.get("dmarc"),
            dkim=item.get("dkim"),
            is_primary=item.get("isPrimary"),
        )
        for item in _values(collector_payloads.get("google_dns_posture", {}), "domainPosture")
        if item.get("domain")
    ]
    mobile_devices = [
        _record(
            "google_mobile_device",
            "google_devices.mobileDevices",
            str(item.get("resourceId") or item.get("deviceId") or item.get("serialNumber")),
            email=item.get("email"),
            model=item.get("model"),
            os=item.get("os"),
            device_type=item.get("type"),
            status=item.get("status"),
            # The Directory API names the field deviceCompromisedStatus; compromisedStatus is the older sample key.
            compromised_status=item.get("deviceCompromisedStatus") or item.get("compromisedStatus"),
            compromised_state=compromised_state(item.get("deviceCompromisedStatus") or item.get("compromisedStatus")),
            encryption_status=item.get("encryptionStatus"),
            encryption=_device_state(item.get("encryptionStatus"), positive="encrypted", negative="not_encrypted"),
            # Named for the lock, not the password: the bundle's sensitive-key scanner rejects the word.
            device_lock_status=item.get("devicePasswordStatus"),
            device_lock_policy=_device_state(item.get("devicePasswordStatus"), positive="enabled", negative="disabled"),
            os_release=item.get("releaseVersion"),
            security_patch_level=item.get("securityPatchLevel"),
            security_patch_date=_epoch_text(item.get("securityPatchLevel")),
            last_sync=item.get("lastSync"),
        )
        for item in _values(collector_payloads.get("google_devices", {}), "mobileDevices")
        if item.get("resourceId") or item.get("deviceId") or item.get("serialNumber")
    ]
    chrome_devices = [
        _record(
            "google_chromeos_device",
            "google_devices.chromeosDevices",
            str(item.get("deviceId") or item.get("serialNumber")),
            serial_number=item.get("serialNumber"),
            annotated_user=item.get("annotatedUser"),
            status=item.get("status"),
            model=item.get("model"),
            os_version=item.get("osVersion"),
            platform_version=item.get("platformVersion"),
            boot_mode=item.get("bootMode"),
            org_unit_path=item.get("orgUnitPath"),
            auto_update_expiration=_auto_update_expiration(item)[0],
            auto_update_source=_auto_update_expiration(item)[1],
            support_end_date=item.get("supportEndDate"),
            last_sync=item.get("lastSync"),
        )
        for item in _values(collector_payloads.get("google_devices", {}), "chromeosDevices")
        if item.get("deviceId") or item.get("serialNumber")
    ]
    drive_files = [
        _record(
            "google_drive_file",
            "google_drive_posture.driveFiles",
            str(item.get("id")),
            name=item.get("name"),
            mime_type=item.get("mimeType"),
            web_view_link=item.get("webViewLink"),
            shared=item.get("shared"),
            owners=item.get("owners") or [],
            permissions=item.get("permissions") or [],
            modified_time=item.get("modifiedTime"),
        )
        for item in _values(collector_payloads.get("google_drive_posture", {}), "driveFiles")
        if item.get("id")
    ]
    shared_drives = [
        _record(
            "google_shared_drive",
            "google_drive_posture.sharedDrives",
            str(item.get("id")),
            name=item.get("name"),
            hidden=item.get("hidden"),
            created_time=item.get("createdTime"),
            restrictions=item.get("restrictions") or {},
        )
        for item in _values(collector_payloads.get("google_drive_posture", {}), "sharedDrives")
        if item.get("id")
    ]
    group_settings = [
        _record(
            "google_group_setting",
            "google_groups_settings.groupSettings",
            str(item.get("email")),
            email=item.get("email"),
            allow_external_members=item.get("allowExternalMembers"),
            who_can_join=item.get("whoCanJoin"),
            who_can_post_message=item.get("whoCanPostMessage"),
            message_moderation_level=item.get("messageModerationLevel"),
            who_can_view_membership=item.get("whoCanViewMembership"),
            who_can_view_group=item.get("whoCanViewGroup"),
        )
        for item in _values(collector_payloads.get("google_groups_settings", {}), "groupSettings")
        if item.get("email")
    ]
    group_setting_errors = [
        _record(
            "google_group_setting_error",
            "google_groups_settings.groupSettingsErrors",
            str(item.get("email")),
            email=item.get("email"),
            error_class=item.get("error_class"),
            error=item.get("error"),
        )
        for item in _values(collector_payloads.get("google_groups_settings", {}), "groupSettingsErrors")
        if item.get("email")
    ]
    calendar_resources = [
        _record(
            "google_calendar_resource",
            "google_calendar_posture.calendarResources",
            str(item.get("resourceId") or item.get("resourceEmail")),
            resource_name=item.get("resourceName"),
            resource_email=item.get("resourceEmail"),
            resource_type=item.get("resourceType"),
            resource_category=item.get("resourceCategory"),
            capacity=item.get("capacity"),
            building_id=item.get("buildingId"),
            floor_name=item.get("floorName"),
        )
        for item in _values(collector_payloads.get("google_calendar_posture", {}), "calendarResources")
        if item.get("resourceId") or item.get("resourceEmail")
    ]
    calendars = [
        _record(
            "google_calendar",
            "google_calendar_posture.calendars",
            str(item.get("id")),
            summary=item.get("summary"),
            description=item.get("description"),
            access_role=item.get("accessRole"),
            primary=item.get("primary"),
            hidden=item.get("hidden"),
            deleted=item.get("deleted"),
        )
        for item in _values(collector_payloads.get("google_calendar_posture", {}), "calendars")
        if item.get("id")
    ]
    calendar_acls = [
        _record(
            "google_calendar_acl",
            "google_calendar_posture.calendarAcls",
            f"{item.get('calendarId')}:{item.get('id') or item.get('scope')}",
            calendar_id=item.get("calendarId"),
            acl_id=item.get("id"),
            role=item.get("role"),
            scope=item.get("scope") or {},
        )
        for item in _values(collector_payloads.get("google_calendar_posture", {}), "calendarAcls")
        if item.get("calendarId") and (item.get("id") or item.get("scope"))
    ]
    calendar_acl_errors = [
        _record(
            "google_calendar_acl_error",
            "google_calendar_posture.calendarAclsErrors",
            str(item.get("calendarId")),
            calendar_id=item.get("calendarId"),
            error_class=item.get("error_class"),
            error=item.get("error"),
        )
        for item in _values(collector_payloads.get("google_calendar_posture", {}), "calendarAclsErrors")
        if item.get("calendarId")
    ]
    activity_records: list[dict[str, Any]] = []
    for source, payload in collector_payloads.get("google_reports", {}).items():
        for item in _values({"items": payload}, "items"):
            activity_records.append(
                _record(
                    "google_activity",
                    f"google_reports.{source}",
                    str(item.get("id", {}).get("uniqueQualifier") if isinstance(item.get("id"), dict) else item.get("id") or f"{source}:{len(activity_records)}"),
                    application=source.replace("Activities", ""),
                    actor_email=(item.get("actor") or {}).get("email") if isinstance(item.get("actor"), dict) else None,
                    event_names=[
                        str(event.get("name"))
                        for event in item.get("events") or []
                        if isinstance(event, dict) and event.get("name")
                    ],
                    events=item.get("events") or [],
                )
            )

    sections: dict[str, Any] = {
        "google_users": users,
        "google_domains": domain_records,
        "google_two_step_policies": policy_records,
        "google_policy_settings": policy_setting_records,
        "google_org_units": org_unit_records,
        "google_groups": groups,
        "google_group_members": group_members,
        "google_group_member_errors": group_member_errors,
        "google_alias_errors": alias_errors,
        "google_role_assignments": role_assignments,
        "google_oauth_grants": oauth_grants,
        "google_oauth_grant_errors": oauth_grant_errors,
        "google_mailbox_settings": mailbox_settings,
        "google_alerts": alerts,
        "google_dns_posture": dns_posture,
        "google_mobile_devices": mobile_devices,
        "google_chromeos_devices": chrome_devices,
        "google_drive_files": drive_files,
        "google_shared_drives": shared_drives,
        "google_group_settings": group_settings,
        "google_group_setting_errors": group_setting_errors,
        "google_calendar_resources": calendar_resources,
        "google_calendars": calendars,
        "google_calendar_acls": calendar_acls,
        "google_calendar_acl_errors": calendar_acl_errors,
        "google_activity_events": activity_records,
    }
    # Every list cut short (an operator limit, never a silent default) is a coverage gap.
    truncations = list_truncations(coverage_rows)
    truncations.extend(truncations_from_payloads(collector_payloads, truncations))
    collection_gaps = collection_gap_records(sorted(truncations, key=lambda item: (item["collector"], item["list"])))
    if collection_gaps:
        sections[COLLECTION_GAP_SECTION] = collection_gaps
    # A list read as a sample by design (the Drive crawl, the event logs) and cut at that bound is not a gap, but the
    # rules that read it cannot call "no finding" a pass.
    bounded_samples = bounded_sample_records(coverage_rows, collector_payloads)
    if bounded_samples:
        sections[BOUNDED_SAMPLE_SECTION] = bounded_samples
    object_counts = {name: len(records) for name, records in sections.items()}
    status_counts = Counter(str(row.get("status") or "unknown") for row in result_rows if isinstance(row, dict))
    truncated_sections = sorted({f"{item['collector']}.{item['list']}" for item in truncations})
    # Which collectors' evidence is the view of one subject, not the tenant. Drive and Calendar are the
    # delegated admin's view; Gmail settings are "user" when each mailbox was read as its own user.
    scope_labels: dict[str, set[str]] = {
        collector: {label} for collector, label in SUBJECT_SCOPED_COLLECTORS.items() if collector in collector_payloads
    }
    for row in coverage_rows:
        label = row.get("subject_scoped")
        if label in {SUBJECT_SCOPE_ADMIN, SUBJECT_SCOPE_USER} and row.get("collector"):
            scope_labels.setdefault(str(row["collector"]), set()).add(str(label))
    subject_scope = {
        collector: SUBJECT_SCOPE_ADMIN if SUBJECT_SCOPE_ADMIN in labels else SUBJECT_SCOPE_USER
        for collector, labels in sorted(scope_labels.items())
    }
    snapshot = {
        "kind": "snapshot",
        "platform": "google_workspace",
        "tenant_name": tenant_name,
        "workspace_domain": workspace_domain,
        "customer_id": customer_id,
        "run_id": run_id,
        "object_counts": object_counts,
        "normalized_counts": object_counts,
        "collector_count": len(result_rows),
        "coverage_row_count": len(coverage_rows),
        "blocker_count": len(diagnostics),
        "status_counts": dict(status_counts),
        "full_counts": object_counts,
        "sample_counts": object_counts,
        "top_limit": top_limit,
        "sample_truncated": bool(truncated_sections),
        "truncated_sections": truncated_sections,
        "collection_gap_count": len(collection_gaps),
        "internal_domains": internal_domains,
        "internal_domains_status": internal_domains_status,
        "internal_domains_source": internal_domains_source,
        "two_step_policy_status": _two_step_policy_status(
            collector_payloads.get("google_policies"), policy_records, coverage_rows, now, widened_complete=two_step_widened
        ),
        "subject_scope": subject_scope,
        "mailbox_settings_skipped_suspended": sum(
            int(row.get("skipped_suspended") or 0) for row in coverage_rows if row.get("collector") == "google_gmail_settings"
        ),
    }
    normalized: dict[str, dict[str, Any]] = {"snapshot": snapshot}
    for name, records in sections.items():
        if records:
            normalized[name] = {"kind": name, "records": records}
    return normalized
