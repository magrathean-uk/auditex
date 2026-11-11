"""The ``privileged_roles`` artefact: PIM policy rules and assignments of the privileged directory roles.

``normalized/privileged_roles.json`` is written in the ScubaGear ProviderExport shape that
``auditex.scuba_projection`` reads: one row per privileged directory role with ``DisplayName``, ``RoleTemplateId``,
``Assignments`` and ``Rules`` (plus the ``key`` every normalized record carries, which the projection ignores: the
bundle contract, the evidence index and run comparison identify a record by it). It is built only from what the
``identity_governance`` collector read
(``roleManagementPolicyAssignments``, ``roleManagementPolicyRules`` and ``roleAssignmentSchedules``) and the role
definitions of the ``identity`` collector, and only when every one of those reads succeeded in full. Nothing is
defaulted: a value Graph did not return is never filled in, and any gap withholds the whole artefact (a bundle without
it is "not collected", never an empty list).

A role is privileged by the same convention as the effective administrator set (``effective_admins``): its name says
administrator, or it is the Global Administrator or one of the privileged built-in roles that do not say so. Every
privileged role must have a policy with rules; a role without one is a gap, not an omission.

Rules are the expiration, notification and approval rules (``Expiration_*``, ``Notification_*``, ``Approval_*``), the
only kinds the export shape holds; the enablement and authentication-context rules are not carried. A rule keeps only
the fields of its kind. Dates are ``/Date(ms)/`` strings, as in the packs. PIM for Groups policies are not read.

When every read succeeded in full and the artefact is still withheld, the builder says why (``Built.reasons``) and the
normaliser records it as a ``collection_gaps`` record, so "withheld for this reason" is never read as "not collected".

Inference to confirm on a live tenant before the shape gate opens (that is, before a pack that holds this shape is frozen
and ``PACK_SHAPE_DIGESTS`` changes): ``Assignments`` come from ``roleAssignmentSchedules``, which also lists the schedules
scoped to an administrative unit (``directoryScopeId``), and they are copied without their scope; ScubaGear may read the
schedule instances (``roleAssignmentScheduleInstances``) instead. Neither point is established offline, and nothing here
filters or reshapes on either.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, NamedTuple

from .effective_admins import _privileged_roles

SECTION = "privileged_roles"
# The envelope marks the file complete: the projection trusts an empty ``records`` list only with this.
ENVELOPE: Mapping[str, Any] = {"collection_status": "collected", "complete": True}
RULE_SOURCE_TYPE = "Directory Role"

KIND_PRIVILEGED_ROLE = "privileged_role"
KIND_POLICY_ASSIGNMENT = "role_management_policy_assignment"
KIND_POLICY_RULE = "role_management_policy_rule"

# Why the artefact is withheld although every read behind it succeeded in full. A reason is a code, or a code and the
# role definition id it concerns (``role_without_policy:<id>``); these strings are part of the output contract.
REASON_EMPTY_POLICY_LIST = "empty_policy_assignment_list"
REASON_ROLE_WITHOUT_NAME = "role_without_name"
REASON_ROLE_WITHOUT_POLICY = "role_without_policy"
REASON_CONFLICTING_POLICIES = "conflicting_policies"
REASON_POLICY_WITHOUT_RULES = "policy_without_rules"
REASON_NO_EXPORTABLE_RULES = "policy_without_exportable_rules"
REASON_UNREADABLE_RULE = "unreadable_rule"
REASON_UNREADABLE_SCHEDULE = "unreadable_schedule"
# The gap reason the normaliser records for the withheld artefact (``collection_gaps``); the codes above are its ``reasons``.
GAP_REASON = "artefact_withheld"
GAP_LIST = SECTION

_EXPIRATION, _NOTIFICATION, _APPROVAL = "Expiration_", "Notification_", "Approval_"
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class Unreadable(ValueError):
    """An input the export shape cannot hold without guessing; the artefact is not written."""


def read_in_full(report: Mapping[str, Any] | None) -> bool:
    """Whether a normalization report says the endpoint was read without error, cut or unreadable rows."""
    return bool(report) and report.get("collection_status") == "collected" and report.get("complete") is True


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _date(value: Any) -> str:
    """``/Date(ms)/`` of an ISO 8601 timestamp (Graph returns UTC). Anything else cannot be dated."""
    if not isinstance(value, str) or not value:
        raise Unreadable("date")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Unreadable("date") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    delta = parsed - _EPOCH
    return f"/Date({(delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000})/"


def _assignment(row: Mapping[str, Any]) -> dict[str, Any]:
    principal = _text(row.get("principalId"))
    info = row.get("scheduleInfo")
    expiration = info.get("expiration") if isinstance(info, Mapping) else None
    if not principal or not isinstance(expiration, Mapping):
        raise Unreadable("assignment")
    item: dict[str, Any] = {"PrincipalId": principal}
    # Preserve Graph's presence semantics: a returned null is evidence, an omitted key is not.
    # An end is null only when the schedule explicitly says it does not expire.
    if "startDateTime" in info:
        start = info["startDateTime"]
        item["StartDateTime"] = None if start is None else _date(start)
    if expiration.get("type") == "noExpiration":
        item["EndDateTime"] = None
    else:
        item["EndDateTime"] = _date(expiration.get("endDateTime"))
    return item


# A rule carries exactly the properties Graph returned for its type, and no padding. The frozen v7 pack was checked for a
# per-family not-applicable value (null or empty) that would let a rule match its rule shapes, read-only, over the
# privileged_roles evidence of train.jsonl and test.jsonl (and tests/fixtures/scuba-projection-shapes-v7.json):
#   Expiration_Admin_Assignment (568 rows; train 10/e2, 20/e1): IsExpirationRequired true, MaximumDuration str,
#     NotificationRecipients a non-empty list and Setting an object {IsApprovalRequired: bool} in every row; only
#     NotificationType varies (str, null at 20/e1, or absent).
#   Approval_EndUser_Assignment (37 rows; train 1675/e2, 1680/e1): the same full key set; no row is Setting-only.
#   Notification_* (476 rows; 3 ids): the bare set {Id, NotificationRecipients, NotificationType, RuleSource,
#     RuleSourceType} (train 10/e2), with Setting null (18/e1), recipients [] (1710/e1) or NotificationType null (1723/e1);
#     the same ids also appear with the full key set (1700/e1, 1705/e1).
#   Assignments: {PrincipalId, EndDateTime} or {PrincipalId, EndDateTime, StartDateTime} (train 10/e2); StartDateTime is
#     null in 13 of 409 rows, EndDateTime null in 72 of 706.
# So the pack holds no null or empty form of Setting on an expiration rule, nor of IsExpirationRequired, MaximumDuration or
# NotificationRecipients on an approval rule: padding them would need a bool, a string or a list Graph never returned.
# The rows are ScubaGear Rego unit-test inputs (provenance AADConfig.rego variants), not exporter output: the exporter at
# the pinned commit 2446ad723b7f (ExportAADProvider.psm1 GetConfigurationsForRoles, and Sample-Reports/
# ProviderSettingsExport.json) writes the rules of Invoke-GraphDirectly as returned (@odata.type and Target kept) plus
# RuleSource and RuleSourceType, so its expiration rules carry no NotificationRecipients or Setting either. A rule that does not match a frozen shape is
# withheld by the projection's whole-shape gate; it is never reshaped to match.
def _rule(row: Mapping[str, Any], role_name: str) -> dict[str, Any] | None:
    rule_id = row["id"]
    item: dict[str, Any] = {"Id": rule_id, "RuleSource": role_name, "RuleSourceType": RULE_SOURCE_TYPE}
    if rule_id.startswith(_EXPIRATION):
        required, duration = row.get("isExpirationRequired"), row.get("maximumDuration")
        if not isinstance(required, bool) or not _text(duration):
            raise Unreadable("expiration rule")
        item.update(IsExpirationRequired=required, MaximumDuration=duration)
    elif rule_id.startswith(_NOTIFICATION):
        recipients, kind = row.get("notificationRecipients"), row.get("notificationType")
        if not isinstance(recipients, list) or not all(isinstance(item, str) for item in recipients):
            raise Unreadable("notification rule")
        if "notificationType" in row and kind is not None and not isinstance(kind, str):
            raise Unreadable("notification rule")
        item["NotificationRecipients"] = list(recipients)
        if "notificationType" in row:
            item["NotificationType"] = kind
    elif rule_id.startswith(_APPROVAL):
        setting = row.get("setting")
        if not isinstance(setting, Mapping) or not isinstance(setting.get("isApprovalRequired"), bool):
            raise Unreadable("approval rule")
        item["Setting"] = {"IsApprovalRequired": setting["isApprovalRequired"]}
    else:
        # Enablement and authentication-context rules have no place in the export shape.
        return None
    return item


class Built(NamedTuple):
    """The rows of ``privileged_roles`` (``None`` when withheld) and, when withheld, every reason, sorted."""

    rows: list[dict[str, Any]] | None
    reasons: list[str]


def build_privileged_roles(
    *,
    role_definitions: Sequence[Mapping[str, Any]],
    policy_assignments: Sequence[Mapping[str, Any]],
    policy_rules: Sequence[Mapping[str, Any]],
    assignment_schedules: Sequence[Mapping[str, Any]],
) -> Built:
    """The rows of ``privileged_roles``, or ``None`` rows and the reasons when any input cannot be read without guessing.

    The caller passes the inputs only when each was read in full. ``role_definitions`` are the normalized role
    definitions (``id`` and ``display_name``); the other three are the raw rows of the collector's operations. Empty
    rows mean the tenant has no privileged role definition. Every privileged role is checked, so the reasons name each
    role that cannot be read, not only the first.
    """
    privileged = _privileged_roles(role_definitions)
    definitions = {_text(item.get("id")).lower(): item for item in role_definitions}
    policies: dict[str, str] = {}
    conflicting: set[str] = set()
    for row in policy_assignments:
        scope_id, scope_type = row.get("scopeId"), row.get("scopeType")
        if (scope_id is not None and scope_id != "/") or (scope_type is not None and str(scope_type).lower() != "directoryrole"):
            continue
        role_id, policy_id = _text(row.get("roleDefinitionId")).lower(), _text(row.get("policyId"))
        # Two policies for one role: which one governs it is not something to guess.
        if role_id and policy_id and policies.setdefault(role_id, policy_id) != policy_id:
            conflicting.add(role_id)
    rules_by_policy: dict[str, list[Mapping[str, Any]]] = {}
    for row in policy_rules:
        if _text(row.get("policyId")) and _text(row.get("id")):
            rules_by_policy.setdefault(str(row["policyId"]), []).append(row)
    schedules_by_role: dict[str, list[Mapping[str, Any]]] = {}
    for row in assignment_schedules:
        schedules_by_role.setdefault(_text(row.get("roleDefinitionId")).lower(), []).append(row)

    records: list[dict[str, Any]] = []
    reasons: list[str] = []
    if privileged and not policy_assignments:
        # No role has a policy: one reason for the list, not one per role.
        reasons.append(REASON_EMPTY_POLICY_LIST)
    else:
        for role_id, (name, _is_global) in privileged.items():
            template_id = str(definitions[role_id]["id"])
            policy_id = policies.get(role_id)
            if not name:
                reasons.append(f"{REASON_ROLE_WITHOUT_NAME}:{template_id}")
                continue
            if role_id in conflicting:
                reasons.append(f"{REASON_CONFLICTING_POLICIES}:{template_id}")
                continue
            if policy_id is None:
                reasons.append(f"{REASON_ROLE_WITHOUT_POLICY}:{template_id}")
                continue
            if policy_id not in rules_by_policy:
                reasons.append(f"{REASON_POLICY_WITHOUT_RULES}:{template_id}")
                continue
            try:
                rules = [rule for rule in (_rule(row, name) for row in rules_by_policy[policy_id]) if rule is not None]
            except Unreadable:
                reasons.append(f"{REASON_UNREADABLE_RULE}:{template_id}")
                continue
            if not rules:
                reasons.append(f"{REASON_NO_EXPORTABLE_RULES}:{template_id}")
                continue
            try:
                assignments = sorted(
                    (_assignment(row) for row in schedules_by_role.get(role_id, ())),
                    key=lambda item: (item["PrincipalId"], item.get("StartDateTime") or "", item.get("EndDateTime") or ""),
                )
            except Unreadable:
                reasons.append(f"{REASON_UNREADABLE_SCHEDULE}:{template_id}")
                continue
            records.append(
                {
                    "key": f"{KIND_PRIVILEGED_ROLE}:{template_id}",
                    "DisplayName": name,
                    "RoleTemplateId": template_id,
                    "Assignments": assignments,
                    "Rules": sorted(rules, key=lambda item: item["Id"]),
                }
            )
    if reasons:
        return Built(None, sorted(reasons))
    return Built(sorted(records, key=lambda item: item["key"]), [])
