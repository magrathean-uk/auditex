"""The effective administrator set: who holds a privileged directory role, by any route.

``/roleManagement/directory/roleAssignments`` lists only the direct, active assignments. A real
tenant also has administrators who are PIM-eligible, who inherit a role from a role-assignable
group, or whose "administrator" is a group or a service principal. Counting the first list alone
gives a false "only one Global Administrator", an empty result when every administrator is
eligible, and no MFA, stale-password or disabled-account check for anyone reached another way.

This module resolves that set once, for every rule that needs it:

* one row per principal that holds an administrator role, with each role and the route it comes
  by (``direct_active``, ``pim_eligible`` or ``via_group`` with the role-holding group's id);
* users only are counted. Groups and service principals that hold a role are listed with
  ``counted: false``; their members and the role they pass on are expanded to the users and
  service principals behind them. A principal that no inventory resolves is ``unresolved`` and is
  still counted, because a role assignment holds a user, a group or a service principal and the
  group and service principal inventories rule the last two out;
* licence flags for each counted principal (does the account hold an Exchange Online mailbox or a
  productivity licence), taken from the licensing collector when it ran;
* a ``state``. The set is ``complete`` only when every source it is built from was read in full:
  role definitions, active assignments, both PIM schedule lists and the group membership
  fan-out. A source that was blocked, truncated or not run makes the set ``unknown`` with the
  reasons, and no rule may read an ``unknown`` set as a pass.

Nothing here performs I/O. Callers supply the normalized records and how completely each
source was collected.
"""
from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .identity_controls import (
    EVIDENCE_ABSENT,
    EVIDENCE_BLOCKED,
    EVIDENCE_COLLECTED,
    AdminScope,
    Evidence,
)

SECTION = "effective_admin_set"
ROW_KIND = "effective_admin"
SUMMARY_KIND = "effective_admin_set_summary"
SOURCE = "effective_admin_set"

STATE_COMPLETE = "complete"
STATE_UNKNOWN = "unknown"

# The tenant cannot hold what this source describes (PIM needs Microsoft Entra ID P2), or the
# collector was skipped for that reason. An empty list is then a real answer, not a gap.
EVIDENCE_NOT_APPLICABLE = "not_applicable"
SOURCE_NOT_NEEDED = "not_needed"

ROUTE_DIRECT = "direct_active"
ROUTE_ELIGIBLE = "pim_eligible"
ROUTE_GROUP = "via_group"

TYPE_USER = "user"
TYPE_GROUP = "group"
TYPE_SERVICE_PRINCIPAL = "service_principal"
TYPE_UNRESOLVED = "unresolved"
_COUNTED_TYPES = frozenset({TYPE_USER, TYPE_UNRESOLVED})

GLOBAL_ADMINISTRATOR_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"
GLOBAL_ADMINISTRATOR_NAME = "global administrator"
# Privileged built-in roles whose name does not say administrator, by role template id (a built-in role's
# definition id is its template id). Partner Tier2 Support can reset any administrator's credentials, which the
# attack graph treats as tier 0; Partner Tier1 Support and Directory Writers are the same kind of role.
PRIVILEGED_ROLE_TEMPLATE_IDS = frozenset(
    {
        "4ba39ca4-527c-499a-b93d-d9b492c50246",  # Partner Tier1 Support
        "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8",  # Partner Tier2 Support
        "9360feb5-f418-4baa-8175-e2a00bac4301",  # Directory Writers
    }
)

SCHEDULE_KIND_ACTIVE = "role_assignment_schedule"
SCHEDULE_KIND_ELIGIBLE = "role_eligibility_schedule"

# Error class a PIM schedule read returns when the tenant has no Microsoft Entra ID P2 licence.
_LICENCE_ERROR_CLASS = "license_required"

SOURCE_ROLE_DEFINITIONS = "role_definitions"
SOURCE_ROLE_ASSIGNMENTS = "role_assignments"
SOURCE_ASSIGNMENT_SCHEDULES = "role_assignment_schedules"
SOURCE_ELIGIBILITY_SCHEDULES = "role_eligibility_schedules"
SOURCE_GROUP_FANOUT = "group_membership_fanout"
SOURCE_LICENCE_SKUS = "licence_skus"
SOURCE_LICENCED_USERS = "licensed_users"

# Exchange Online plans that provide a mailbox. EXCHANGE_S_FOUNDATION is left out on purpose: it is
# bundled into many licences that carry no mailbox.
MAILBOX_SERVICE_PLANS = frozenset(
    {
        "EXCHANGE_S_STANDARD",
        "EXCHANGE_S_ENTERPRISE",
        "EXCHANGE_S_ESSENTIALS",
        "EXCHANGE_S_DESKLESS",
        "EXCHANGE_S_STANDARD_MIDMARKET",
    }
)
# Plans for the everyday productivity apps and collaboration services an administrator should not
# use from an account that also holds a privileged role.
PRODUCTIVITY_SERVICE_PLANS = frozenset(
    {
        "OFFICESUBSCRIPTION",
        "OFFICEMOBILE_SUBSCRIPTION",
        "SHAREPOINTENTERPRISE",
        "SHAREPOINTSTANDARD",
        "SHAREPOINTWAC",
        "TEAMS1",
        "MCOSTANDARD",
        "YAMMER_ENTERPRISE",
    }
)
# Government and education variants of a plan carry a suffix (``EXCHANGE_S_ENTERPRISE_GOV``,
# ``SHAREPOINTENTERPRISE_EDU``); the plan is the same service.
_PLAN_SUFFIXES = ("_GOV", "_EDU")
# Used only for a licence whose SKU lists no service plans at all (an inventory without
# ``servicePlans``), and kept as two lists because a SKU can carry either without the other: the
# Exchange Online standalone SKUs are mailbox only, Microsoft 365 Apps for business is productivity only.
_MAILBOX_SKU_PART_NUMBERS = frozenset(
    {
        "EXCHANGESTANDARD",
        "EXCHANGEENTERPRISE",
        "O365_BUSINESS_ESSENTIALS",
        "O365_BUSINESS_PREMIUM",
        "SMB_BUSINESS_ESSENTIALS",
        "SMB_BUSINESS_PREMIUM",
        "SPB",
        "STANDARDPACK",
        "ENTERPRISEPACK",
        "ENTERPRISEPREMIUM",
        "DESKLESSPACK",
        "SPE_E3",
        "SPE_E5",
        "SPE_F1",
    }
)
_PRODUCTIVITY_SKU_PART_NUMBERS = frozenset(
    {
        "O365_BUSINESS",
        "SMB_BUSINESS",
        "OFFICESUBSCRIPTION",
        "O365_BUSINESS_ESSENTIALS",
        "O365_BUSINESS_PREMIUM",
        "SMB_BUSINESS_ESSENTIALS",
        "SMB_BUSINESS_PREMIUM",
        "SPB",
        "STANDARDPACK",
        "ENTERPRISEPACK",
        "ENTERPRISEPREMIUM",
        "DESKLESSPACK",
        "SPE_E3",
        "SPE_E5",
        "SPE_F1",
    }
)


@dataclass(frozen=True)
class AdminSetEvidence:
    """How completely each source of the set was collected.

    The three evidence groups are the three sources the effective set is resolved from, plus the
    licensing reads. ``Evidence.state`` is ``collected``, ``blocked``, ``truncated``, ``absent`` or
    (for the PIM schedules only) ``not_applicable``.
    """

    role_definitions: Evidence = Evidence()
    role_assignments: Evidence = Evidence()
    assignment_schedules: Evidence = Evidence()
    eligibility_schedules: Evidence = Evidence()
    group_fanout: Evidence = Evidence()
    licence_skus: Evidence = Evidence()
    licensed_users: Evidence = Evidence()


def _text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _key(value: Any) -> str:
    return _text(value).lower()


def _record(kind: str, object_id: str, **fields: Any) -> dict[str, Any]:
    payload = {"kind": kind, "source": SOURCE, "id": object_id, "key": f"{kind}:{object_id}"}
    payload.update(fields)
    return {key: value for key, value in payload.items() if value not in (None, [], {}, "")}


def _privileged_roles(role_definitions: Iterable[Mapping[str, Any]]) -> dict[str, tuple[str, bool]]:
    """Role definition id (lower-case) -> (display name, is Global Administrator).

    A role is privileged when its name says administrator, the convention the privileged MFA and
    stale-account rules already use, when it is the Global Administrator template, or when it is one of
    the privileged roles that do not say administrator (``PRIVILEGED_ROLE_TEMPLATE_IDS``).
    """
    roles: dict[str, tuple[str, bool]] = {}
    for item in role_definitions:
        role_id = _key(item.get("id"))
        name = _text(item.get("display_name"))
        if not role_id:
            continue
        is_global = name.lower() == GLOBAL_ADMINISTRATOR_NAME or role_id == GLOBAL_ADMINISTRATOR_TEMPLATE_ID
        if is_global or "administrator" in name.lower() or role_id in PRIVILEGED_ROLE_TEMPLATE_IDS:
            roles[role_id] = (name or "Global Administrator", is_global)
    return roles


def admin_scope(records: Sequence[Mapping[str, Any]], role_definitions: Sequence[Mapping[str, Any]]) -> AdminScope | None:
    """The administrator MFA verdict's view of the set (``build_effective_admin_set`` records), or ``None`` without one.

    Only enabled, counted principals matter: a disabled account cannot sign in, so a policy that excludes it does not
    leave an administrator without MFA. Service principals and groups are not counted (they are not people).
    """
    summary = next((row for row in records if row.get("kind") == SUMMARY_KIND), None)
    if summary is None:
        return None
    rows = [
        row
        for row in records
        if row.get("kind") == ROW_KIND and row.get("counted") and row.get("enabled") is not False
    ]
    guests = summary.get("guest_admin_count")
    return AdminScope(
        complete=summary.get("state") == STATE_COMPLETE,
        privileged_role_ids=frozenset(_privileged_roles(role_definitions)),
        held_role_ids=frozenset(
            _key(role.get("role_definition_id")) for row in rows for role in row.get("roles") or [] if role.get("role_definition_id")
        ),
        admin_principal_ids=frozenset(_key(row.get("principal_id")) for row in rows if row.get("principal_id")),
        guest_admin_count=guests if isinstance(guests, int) and not isinstance(guests, bool) else None,
    )


def _source_row(name: str, evidence: Evidence, *, state: str | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {"source": name, "state": state or evidence.state}
    if evidence.detail:
        row["detail"] = evidence.detail
    return row


def _schedule_state(evidence: Evidence) -> str:
    """PIM schedules: a licence-required refusal means the tenant has no PIM, so none are hidden."""
    if evidence.state == EVIDENCE_BLOCKED and evidence.detail == _LICENCE_ERROR_CLASS:
        return EVIDENCE_NOT_APPLICABLE
    return evidence.state


def _read_in_full(state: str) -> bool:
    return state in {EVIDENCE_COLLECTED, EVIDENCE_NOT_APPLICABLE, SOURCE_NOT_NEEDED}


def _plan_name(value: Any) -> str:
    """A service plan name in upper case, without the ``_GOV`` or ``_EDU`` suffix of a sovereign or education variant."""
    name = _text(value).upper()
    for suffix in _PLAN_SUFFIXES:
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)]
    return name


def _licence_class(
    sku: Mapping[str, Any] | None,
    disabled_plans: set[str],
) -> tuple[bool, bool] | None:
    """(mailbox, productivity) for one assigned SKU, or ``None`` when the SKU cannot be classified."""
    if not isinstance(sku, Mapping):
        return None
    plans = sku.get("servicePlans")
    if isinstance(plans, list) and plans:
        enabled: set[str] = set()
        for plan in plans:
            if not isinstance(plan, Mapping):
                continue
            plan_id = _key(plan.get("servicePlanId"))
            if plan_id in disabled_plans or _key(plan.get("provisioningStatus")) == "disabled":
                continue
            name = _plan_name(plan.get("servicePlanName"))
            if name:
                enabled.add(name)
        return bool(enabled & MAILBOX_SERVICE_PLANS), bool(enabled & PRODUCTIVITY_SERVICE_PLANS)
    part_number = _text(sku.get("skuPartNumber")).upper()
    mailbox, productivity = part_number in _MAILBOX_SKU_PART_NUMBERS, part_number in _PRODUCTIVITY_SKU_PART_NUMBERS
    return (mailbox, productivity) if mailbox or productivity else None


def _licence_fields(
    user_id: str,
    *,
    skus: Mapping[str, Mapping[str, Any]],
    licensed: Mapping[str, Mapping[str, Any]],
    evidence_reasons: Sequence[str],
) -> dict[str, Any]:
    """Licence flags for one principal, or ``licence_state: unknown`` with the reason."""
    if evidence_reasons:
        return {"licence_state": STATE_UNKNOWN, "licence_reason": ",".join(evidence_reasons)}
    assigned = licensed.get(user_id.lower(), {}).get("assignedLicenses")
    assigned = [item for item in assigned if isinstance(item, Mapping)] if isinstance(assigned, list) else []
    mailbox = productivity = False
    part_numbers: list[str] = []
    for item in assigned:
        sku_id = _key(item.get("skuId"))
        sku = skus.get(sku_id)
        disabled = {_key(plan) for plan in item.get("disabledPlans") or [] if plan}
        classified = _licence_class(sku, disabled)
        if classified is None:
            return {"licence_state": STATE_UNKNOWN, "licence_reason": "sku_not_classifiable"}
        part_numbers.append(_text((sku or {}).get("skuPartNumber")) or sku_id)
        mailbox = mailbox or classified[0]
        productivity = productivity or classified[1]
    return {
        "licence_state": "known",
        "mailbox_licence": mailbox,
        "productivity_licence": productivity,
        "licence_sku_part_numbers": sorted(set(part_numbers)),
    }


def _licence_reasons(evidence: AdminSetEvidence) -> list[str]:
    reasons: list[str] = []
    for name, item in ((SOURCE_LICENCE_SKUS, evidence.licence_skus), (SOURCE_LICENCED_USERS, evidence.licensed_users)):
        if item.state != EVIDENCE_COLLECTED:
            reasons.append(f"{name}_{item.state}")
    return reasons


def build_effective_admin_set(
    *,
    users: Sequence[Mapping[str, Any]],
    groups: Sequence[Mapping[str, Any]],
    service_principals: Sequence[Mapping[str, Any]],
    role_definitions: Sequence[Mapping[str, Any]],
    role_assignments: Sequence[Mapping[str, Any]],
    governance_objects: Sequence[Mapping[str, Any]],
    membership_edges: Sequence[Mapping[str, Any]],
    evidence: AdminSetEvidence,
) -> list[dict[str, Any]]:
    """Normalized records for the ``effective_admin_set`` section: one summary and one row per principal.

    The inputs are the normalized sections (``users``, ``groups``, ``service_principals``,
    ``role_definitions``, ``role_assignments``, ``governance_objects`` and
    ``group_membership_edges``). ``evidence`` says how completely each underlying source was read.
    """
    privileged = _privileged_roles(role_definitions)
    users_by_id = {_key(item.get("id")): item for item in users if item.get("id")}
    groups_by_id = {_key(item.get("id")): item for item in groups if item.get("id")}
    sps_by_id = {_key(item.get("id")): item for item in service_principals if item.get("id")}

    member_edges = [edge for edge in membership_edges if edge.get("relationship") == "member" and edge.get("group_id")]
    children: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for edge in member_edges:
        children[_key(edge.get("group_id"))].append(edge)
    edge_group_ids = {_key(edge.get("group_id")) for edge in membership_edges if edge.get("group_id")}

    display_ids: dict[str, str] = {}
    edge_types: dict[str, str] = {}

    def display_id(principal: str) -> str:
        record = users_by_id.get(principal) or groups_by_id.get(principal) or sps_by_id.get(principal) or {}
        return _text(record.get("id")) or display_ids.get(principal) or principal
    held: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def add_entry(principal_id: str, entry: dict[str, Any]) -> None:
        principal = _key(principal_id)
        display_ids.setdefault(principal, _text(principal_id))
        identity = (entry["role_definition_id"].lower(), entry["route"], entry.get("group_id", ""))
        for existing in held[principal]:
            if (existing["role_definition_id"].lower(), existing["route"], existing.get("group_id", "")) == identity:
                return
        held[principal].append(entry)

    def role_entry(role_id: Any, route: str, section: str, row: Mapping[str, Any]) -> dict[str, Any] | None:
        role = privileged.get(_key(role_id))
        if role is None:
            return None
        name, is_global = role
        scope = _text(row.get("directory_scope_id")) or ("/" if is_global else "")
        return {
            "role": name,
            "role_definition_id": _text(role_id),
            "route": route,
            "scope": scope or None,
            "global_administrator": is_global,
            "records": [{"section": section, "key": _text(row.get("key") or row.get("id"))}],
        }

    for row in role_assignments:
        if row.get("principal_id"):
            entry = role_entry(row.get("role_definition_id"), ROUTE_DIRECT, "role_assignments", row)
            if entry:
                add_entry(str(row["principal_id"]), entry)
    for row in governance_objects:
        kind = row.get("kind")
        if kind not in {SCHEDULE_KIND_ACTIVE, SCHEDULE_KIND_ELIGIBLE} or not row.get("principal_id"):
            continue
        route = ROUTE_ELIGIBLE if kind == SCHEDULE_KIND_ELIGIBLE else ROUTE_DIRECT
        entry = role_entry(row.get("role_definition_id"), route, "governance_objects", row)
        if entry:
            add_entry(str(row["principal_id"]), entry)

    def principal_type(principal: str) -> str:
        if principal in users_by_id:
            return TYPE_USER
        if principal in groups_by_id or principal in edge_group_ids:
            return TYPE_GROUP
        if principal in sps_by_id:
            return TYPE_SERVICE_PRINCIPAL
        return edge_types.get(principal, TYPE_UNRESOLVED)

    # Role-holding groups hand their roles to their members, and to the members of nested groups.
    expanded_member_count: dict[str, int] = {}
    group_holders = [principal for principal in list(held) if principal_type(principal) == TYPE_GROUP]
    for holder in group_holders:
        holder_name = _text((groups_by_id.get(holder) or {}).get("display_name")) or None
        holder_entries = list(held[holder])
        seen = {holder}
        queue: deque[tuple[str, list[str]]] = deque([(holder, [])])
        reached: set[str] = set()
        while queue:
            group, path = queue.popleft()
            for edge in children.get(group, []):
                member = _key(edge.get("member_id"))
                if not member or member in seen:
                    continue
                seen.add(member)
                member_type = _text(edge.get("member_type")) or TYPE_USER
                edge_path = [*path, _text(edge.get("key") or edge.get("id"))]
                if member_type == TYPE_GROUP:
                    queue.append((member, edge_path))
                    continue
                edge_types.setdefault(member, member_type if member_type in {TYPE_USER, TYPE_SERVICE_PRINCIPAL} else TYPE_USER)
                display_ids.setdefault(member, _text(edge.get("member_id")))
                reached.add(member)
                for source_entry in holder_entries:
                    add_entry(
                        _text(edge.get("member_id")),
                        {
                            "role": source_entry["role"],
                            "role_definition_id": source_entry["role_definition_id"],
                            "route": ROUTE_GROUP,
                            "scope": source_entry.get("scope"),
                            "global_administrator": source_entry["global_administrator"],
                            "group_id": display_id(holder),
                            "group_name": holder_name,
                            "group_assignment": "eligible" if source_entry["route"] == ROUTE_ELIGIBLE else "active",
                            "nested_group": bool(path) or None,
                            "records": [
                                *source_entry["records"],
                                *({"section": "group_membership_edges", "key": key} for key in edge_path if key),
                            ],
                        },
                    )
        expanded_member_count[holder] = len(reached)

    # What the three sources say about completeness.
    group_expansion_needed = any(principal_type(principal) in {TYPE_GROUP, TYPE_UNRESOLVED} for principal in held)
    assignment_state = _schedule_state(evidence.assignment_schedules)
    eligibility_state = _schedule_state(evidence.eligibility_schedules)
    fanout_state = evidence.group_fanout.state
    if fanout_state == EVIDENCE_ABSENT and not group_expansion_needed:
        fanout_state = SOURCE_NOT_NEEDED
    source_rows = [
        _source_row(SOURCE_ROLE_DEFINITIONS, evidence.role_definitions),
        _source_row(SOURCE_ROLE_ASSIGNMENTS, evidence.role_assignments),
        _source_row(SOURCE_ASSIGNMENT_SCHEDULES, evidence.assignment_schedules, state=assignment_state),
        _source_row(SOURCE_ELIGIBILITY_SCHEDULES, evidence.eligibility_schedules, state=eligibility_state),
        _source_row(SOURCE_GROUP_FANOUT, evidence.group_fanout, state=fanout_state),
    ]
    reasons = [f"{row['source']}_{row['state']}" for row in source_rows if not _read_in_full(row["state"])]
    state = STATE_COMPLETE if not reasons else STATE_UNKNOWN

    licence_reasons = _licence_reasons(evidence)
    skus = {_key(item.get("skuId") or item.get("id")): item for item in evidence.licence_skus.rows}
    licensed = {_key(item.get("id")): item for item in evidence.licensed_users.rows if item.get("id")}

    rows: list[dict[str, Any]] = []
    for principal, entries in sorted(held.items()):
        kind = principal_type(principal)
        counted = kind in _COUNTED_TYPES
        user = users_by_id.get(principal) or {}
        group = groups_by_id.get(principal) or {}
        sp = sps_by_id.get(principal) or {}
        user_type = _text(user.get("user_type"))
        routes = sorted({entry["route"] for entry in entries})
        scopes = {entry.get("scope") for entry in entries}
        scope = "tenant" if "/" in scopes else "scoped" if scopes and None not in scopes else "unknown"
        fields: dict[str, Any] = {
            "principal_id": display_id(principal),
            "principal_type": kind,
            "is_user": True if kind == TYPE_USER else None if kind == TYPE_UNRESOLVED else False,
            "counted": counted,
            "display_name": user.get("display_name") or group.get("display_name") or sp.get("display_name"),
            "principal_name": user.get("principal_name"),
            "user_type": user_type or None,
            "is_guest": (user_type.lower() == "guest") if user_type else None,
            "enabled": user.get("enabled") if kind == TYPE_USER else sp.get("enabled") if kind == TYPE_SERVICE_PRINCIPAL else None,
            "roles": [{key: value for key, value in entry.items() if value not in (None, [], {}, "")} for entry in entries],
            "role_names": sorted({entry["role"] for entry in entries}),
            "routes": routes,
            "scope": scope,
            "global_administrator": any(entry["global_administrator"] for entry in entries),
            "expanded_member_count": expanded_member_count.get(principal) if kind == TYPE_GROUP else None,
            "state": state,
        }
        if counted:
            fields.update(
                _licence_fields(
                    fields["principal_id"], skus=skus, licensed=licensed, evidence_reasons=licence_reasons
                )
            )
        rows.append(_record(ROW_KIND, fields["principal_id"], **fields))

    counted_rows = [row for row in rows if row.get("counted")]
    licence_unknown = [row for row in counted_rows if row.get("licence_state") != "known"]
    summary = _record(
        SUMMARY_KIND,
        "summary",
        state=state,
        reasons=reasons,
        sources=source_rows,
        admin_count=len(counted_rows),
        global_admin_count=sum(1 for row in counted_rows if row.get("global_administrator")),
        direct_active_count=sum(1 for row in counted_rows if ROUTE_DIRECT in row.get("routes", [])),
        pim_eligible_count=sum(1 for row in counted_rows if ROUTE_ELIGIBLE in row.get("routes", [])),
        group_expanded_count=sum(1 for row in counted_rows if ROUTE_GROUP in row.get("routes", [])),
        guest_admin_count=sum(1 for row in counted_rows if row.get("is_guest") is True),
        non_user_principal_count=len(rows) - len(counted_rows),
        unresolved_principal_count=sum(1 for row in counted_rows if row.get("principal_type") == TYPE_UNRESOLVED),
        licence_state=STATE_UNKNOWN if licence_unknown else "known",
        licence_reasons=licence_reasons or sorted({row["licence_reason"] for row in licence_unknown if row.get("licence_reason")}),
    )
    return [summary, *rows]
