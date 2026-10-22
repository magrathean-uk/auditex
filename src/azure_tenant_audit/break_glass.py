"""Emergency-access (break-glass) exclusions in Conditional Access.

An emergency-access account must stay usable when a Conditional Access policy or the MFA service
fails, so every policy that could lock it out (one that requires MFA or blocks) should exclude it.
The check here is narrow on purpose:

* Only enabled policies are judged. A report-only policy enforces nothing, so it cannot lock anyone
  out, and a policy whose grant is a session control or a password change is not a lock-out risk. A
  policy that requires a compliant or hybrid-joined device with no MFA alternative is judged, at
  medium: an emergency account used from an unmanaged device would be refused.
* A policy is judged only when it can reach the accounts: it targets all users, targets a role the
  accounts hold, or names one of the accounts or groups itself. A policy aimed at a role none of the
  accounts holds, or at a user action or an authentication context (which cannot block a sign-in), is
  not judged. When the roles of the accounts cannot be established (the operator listed a group, or an
  object ID the run did not collect) a role-targeted policy is judged, but never graded high.
* An account counts as excluded when the policy excludes it, a group it belongs to (as far as the run read
  the group's members: role-assignable groups), or, for inferred accounts, the Global Administrator role.
* The accounts come from the operator when they supply them (``--break-glass-accounts`` or
  ``AUDITEX_BREAK_GLASS_ACCOUNTS``: object IDs, user principal names, or the group the policies
  exclude). Without a list the accounts are inferred, and an inference is weaker evidence: users and
  groups named for emergency access, and holders of the Global Administrator role.

The module is pure: it reads the collected users, groups, role data and each policy's targeting, and
returns what it found. Normalization stores the result and the finding builder grades it.
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

ENV_VAR = "AUDITEX_BREAK_GLASS_ACCOUNTS"
SECTION = "break_glass_assessment"
KIND = "break_glass_assessment"

SOURCE_OPERATOR = "operator"
SOURCE_INFERRED = "inferred"
SOURCE_NONE = "none"

STATE_ASSESSED = "assessed"
# No account could be identified: nothing is judged, and baselines read the rule as not assessed.
STATE_NO_ACCOUNTS = "no_accounts_identified"
# The operator listed accounts but none could be found in the collected identity data.
STATE_UNRESOLVED = "operator_accounts_unresolved"

_COMMENT = re.compile(r"(?:^|\s)#.*$")
_GUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
_NAME_SIGNALS = ("break glass", "breakglass", "break-glass", "break_glass", "emergency access", "emergency-access", "emergency_access")
_GLOBAL_ADMINISTRATOR = "global administrator"

# Grant controls that make a policy a lock-out risk.
ENFORCES_MFA = "mfa"
ENFORCES_BLOCK = "block"
ENFORCES_DEVICE = "device"
_DEVICE_CONTROLS = {"compliantdevice", "domainjoineddevice"}
_LEGACY_CLIENT_TYPES = {"exchangeactivesync", "other"}


def parse_accounts(value: str | Iterable[str] | None) -> list[str]:
    """Break-glass entries from a comma, semicolon or line separated string (or a list of them).

    Spaces are not separators: a group is listed by its display name, which can contain them. A ``#``
    that starts a line or follows whitespace begins a comment; one inside an entry (a guest user
    principal name contains ``#EXT#``) does not. There is no limit on the number of entries.
    """
    if value is None:
        return []
    chunks = [value] if isinstance(value, str) else [str(item) for item in value if item is not None]
    entries: list[str] = []
    seen: set[str] = set()
    for chunk in chunks:
        for line in chunk.splitlines():
            # A comment starts at a # at the line start or after whitespace; a guest user principal
            # name contains #EXT# and must survive.
            line = _COMMENT.sub("", line)
            for entry in re.split(r"[,;]", line):
                entry = entry.strip().strip("'\"")
                if entry and entry.lower() not in seen:
                    seen.add(entry.lower())
                    entries.append(entry)
    return entries


def load_accounts_argument(value: str | Sequence[str] | None) -> list[str]:
    """The ``--break-glass-accounts`` value: a list, or ``@path`` for a file with one entry per line.

    Raises ``OSError`` for a file that cannot be read and ``UnicodeError`` for one that is not UTF-8
    text, so a run can stop before any tenant call.
    """
    if value is None:
        return []
    if not isinstance(value, str):
        return parse_accounts(list(value))
    text = value.strip()
    if text.startswith("@"):
        return parse_accounts(Path(text[1:]).expanduser().read_text(encoding="utf-8"))
    return parse_accounts(text)


def configured_accounts(explicit: Sequence[str] | None = None) -> list[str]:
    """The operator's break-glass list: the explicit argument, else ``AUDITEX_BREAK_GLASS_ACCOUNTS``."""
    if explicit:
        return parse_accounts(list(explicit))
    return parse_accounts(os.environ.get(ENV_VAR))


def _lower(values: Iterable[Any]) -> list[str]:
    return [str(value).lower() for value in values if value not in (None, "")]


class BreakGlassAccounts:
    """The accounts a run treats as emergency access, and how they were found."""

    def __init__(
        self,
        *,
        source: str,
        state: str,
        label_of: Mapping[str, str],
        role_ids: set[str] | None = None,
        unresolved: list[str] | None = None,
        roles_held: Mapping[str, set[str]] | None = None,
        roles_unknown: bool = False,
        global_admin_role_ids: set[str] | None = None,
        group_members: Mapping[str, set[str]] | None = None,
    ) -> None:
        self.source = source
        self.state = state
        # Lower-case object ID -> the name an assessor reads (user principal name or group name).
        self.label_of = dict(label_of)
        self.ids = set(self.label_of)
        self.labels = [self.label_of[identifier] for identifier in sorted(self.label_of)]
        self.role_ids = role_ids or set()
        self.unresolved = unresolved or []
        # Lower-case user ID -> lower-case ids of the directory roles the user holds (any route the run read).
        self.roles_held = {key: set(value) for key, value in (roles_held or {}).items()}
        # True when an account is a group or an object the run did not collect: its roles cannot be listed.
        self.roles_unknown = roles_unknown
        self.global_admin_role_ids = global_admin_role_ids or set()
        # Lower-case group ID -> lower-case ids of the members the run read.
        self.group_members = {key: set(value) for key, value in (group_members or {}).items()}

    def held_roles(self) -> set[str]:
        """Every directory role one of the accounts holds."""
        return {role for roles in self.roles_held.values() for role in roles}

    def covers(self, targeting: Mapping[str, Any]) -> list[str]:
        """Labels of the accounts a policy excludes: by user or group, by a group the run read the members of, or (inferred accounts) by role."""
        excluded_groups = set(_lower(targeting.get("exclude_groups", [])))
        excluded = set(_lower(targeting.get("exclude_users", []))) | excluded_groups
        member_of_excluded = {
            member for group in excluded_groups for member in self.group_members.get(group, ())
        }
        hits = [
            self.label_of[identifier]
            for identifier in sorted(self.label_of)
            if identifier in excluded or identifier in member_of_excluded
        ]
        if self.role_ids & set(_lower(targeting.get("exclude_roles", []))):
            hits.append("a role the policy excludes")
        return hits


def resolve_accounts(
    configured: Sequence[str],
    *,
    users: Sequence[Mapping[str, Any]],
    groups: Sequence[Mapping[str, Any]],
    role_assignments: Sequence[Mapping[str, Any]],
    role_definitions: Sequence[Mapping[str, Any]],
    admin_rows: Sequence[Mapping[str, Any]] = (),
    membership_edges: Sequence[Mapping[str, Any]] = (),
) -> BreakGlassAccounts:
    """Resolve the operator's list against the collected identity data, or infer the accounts.

    An entry resolves to a user (object ID, user principal name or mail) or a group (object ID or
    display name). An object ID that is not in the collected users or groups is still matched against
    the policies' exclusions as given.

    ``admin_rows`` (the effective administrator set's rows) and ``role_assignments`` give the roles each
    user holds, so a role-targeted policy is judged only when it can reach an account. ``membership_edges``
    (members of role-assignable groups) let a group the policy excludes cover the accounts in it.
    """
    user_by_key: dict[str, Mapping[str, Any]] = {}
    for user in users:
        for key in (user.get("id"), user.get("userPrincipalName"), user.get("mail")):
            if key:
                user_by_key.setdefault(str(key).lower(), user)
    group_by_key: dict[str, Mapping[str, Any]] = {}
    for group in groups:
        for key in (group.get("id"), group.get("displayName")):
            if key:
                group_by_key.setdefault(str(key).lower(), group)

    role_by_id = {str(role.get("id")): role for role in role_definitions if role.get("id")}
    global_admin_role_ids = {
        str(role["id"]).lower() for role in role_definitions if str(role.get("displayName") or "").lower() == _GLOBAL_ADMINISTRATOR
    }
    roles_by_principal: dict[str, set[str]] = {}
    for assignment in role_assignments:
        principal, role_id = assignment.get("principalId"), assignment.get("roleDefinitionId")
        if isinstance(principal, str) and principal and role_id:
            roles_by_principal.setdefault(principal.lower(), set()).add(str(role_id).lower())
    for row in admin_rows:
        principal = row.get("principal_id")
        if not principal:
            continue
        for role in row.get("roles") or []:
            if role.get("role_definition_id"):
                roles_by_principal.setdefault(str(principal).lower(), set()).add(str(role["role_definition_id"]).lower())
            if role.get("global_administrator") and role.get("role_definition_id"):
                global_admin_role_ids.add(str(role["role_definition_id"]).lower())
    group_members: dict[str, set[str]] = {}
    for edge in membership_edges:
        if edge.get("relationship") == "member" and edge.get("group_id") and edge.get("member_id"):
            group_members.setdefault(str(edge["group_id"]).lower(), set()).add(str(edge["member_id"]).lower())

    def role_view(label_of: Mapping[str, str]) -> tuple[dict[str, set[str]], bool]:
        user_ids = {str(user["id"]).lower() for user in users if user.get("id")}
        held = {key: roles_by_principal.get(key, set()) for key in label_of if key in user_ids}
        return held, any(key not in user_ids for key in label_of)

    label_of: dict[str, str] = {}
    if configured:
        unresolved: list[str] = []
        for entry in configured:
            key = entry.lower()
            user = user_by_key.get(key)
            group = group_by_key.get(key)
            if user is not None and user.get("id"):
                label_of[str(user["id"]).lower()] = str(user.get("userPrincipalName") or user.get("displayName") or user["id"])
            elif group is not None and group.get("id"):
                label_of[str(group["id"]).lower()] = str(group.get("displayName") or group["id"])
            elif _GUID.fullmatch(entry):
                label_of[key] = entry
            else:
                unresolved.append(entry)
        held, unknown = role_view(label_of)
        return BreakGlassAccounts(
            source=SOURCE_OPERATOR,
            state=STATE_ASSESSED if label_of else STATE_UNRESOLVED,
            label_of=label_of,
            unresolved=unresolved,
            roles_held=held,
            roles_unknown=unknown,
            global_admin_role_ids=global_admin_role_ids,
            group_members=group_members,
        )

    for user in users:
        text = f"{user.get('userPrincipalName') or ''} {user.get('displayName') or ''}".lower()
        if user.get("id") and any(signal in text for signal in _NAME_SIGNALS):
            label_of[str(user["id"]).lower()] = str(user.get("userPrincipalName") or user.get("displayName") or user["id"])
    for group in groups:
        name = str(group.get("displayName") or "").lower()
        if group.get("id") and any(signal in name for signal in _NAME_SIGNALS):
            label_of[str(group["id"]).lower()] = str(group.get("displayName") or group["id"])
    role_ids: set[str] = set()
    for assignment in role_assignments:
        role = role_by_id.get(str(assignment.get("roleDefinitionId")))
        principal = assignment.get("principalId")
        if role is None or not isinstance(principal, str) or not principal:
            continue
        if str(role.get("displayName") or "").lower() == _GLOBAL_ADMINISTRATOR:
            identifier = principal.lower()
            role_ids.add(str(role["id"]).lower())
            user = user_by_key.get(identifier)
            label_of.setdefault(identifier, str((user or {}).get("userPrincipalName") or principal))
    held, unknown = role_view(label_of)
    return BreakGlassAccounts(
        source=SOURCE_INFERRED if label_of else SOURCE_NONE,
        state=STATE_ASSESSED if label_of else STATE_NO_ACCOUNTS,
        label_of=label_of,
        role_ids=role_ids,
        roles_held=held,
        roles_unknown=unknown,
        global_admin_role_ids=global_admin_role_ids,
        group_members=group_members,
    )


def enforcement(targeting: Mapping[str, Any]) -> str | None:
    """``block``, ``mfa`` or ``device`` for a policy whose grant control can lock an account out.

    ``device`` is a compliant or hybrid-joined device requirement with no MFA alternative: either the
    grant is those controls alone, or the operator is AND. Any MFA control or authentication strength
    makes the policy ``mfa``; a block makes it ``block``.
    """
    grant = targeting.get("grant") or {}
    controls = set(_lower(grant.get("built_in_controls") or []))
    if "block" in controls:
        return ENFORCES_BLOCK
    if "mfa" in controls or grant.get("authentication_strength"):
        return ENFORCES_MFA
    if controls & _DEVICE_CONTROLS and (not controls - _DEVICE_CONTROLS or str(grant.get("operator") or "").upper() == "AND"):
        return ENFORCES_DEVICE
    return None


def applies_to_accounts(targeting: Mapping[str, Any], accounts: BreakGlassAccounts) -> str | None:
    """Why a policy can reach the break-glass accounts, or ``None`` when it cannot be shown to.

    ``all_users`` and ``administrator_roles`` are certain reaches (the latter only when the policy includes
    a role one of the accounts holds); ``administrator_roles_unverified`` is a role-targeted policy when the
    roles of the accounts cannot be listed (a group, or an object the run did not collect); ``names_account``
    is a policy whose include list names an account or group directly. A policy aimed at other groups or
    users, or at roles none of the accounts holds, is not judged: the membership of a group the run did not
    read cannot be assumed.
    """
    include_users = _lower(targeting.get("include_users") or [])
    if "all" in include_users:
        return "all_users"
    include_roles = set(_lower(targeting.get("include_roles") or []))
    if include_roles:
        if include_roles & accounts.held_roles():
            return "administrator_roles"
        if accounts.roles_unknown:
            return "administrator_roles_unverified"
    named = set(include_users) | set(_lower(targeting.get("include_groups") or []))
    return "names_account" if named & accounts.ids else None


def _applies_to_all_applications(targeting: Mapping[str, Any]) -> bool:
    included = _lower(targeting.get("include_applications") or [])
    return not included or "all" in included


def _legacy_clients_only(targeting: Mapping[str, Any]) -> bool:
    client_types = set(_lower(targeting.get("client_app_types") or []))
    return bool(client_types) and client_types <= _LEGACY_CLIENT_TYPES


def is_broad(targeting: Mapping[str, Any], enforces: str, reach: str, accounts: BreakGlassAccounts | None = None) -> bool:
    """A lock-out of every administrator is possible: MFA, or a block that is not legacy-protocol only,
    over all users or over Global Administrator, and over all applications. A device requirement can be met
    by enrolling a device, so it is judged but never broad. A policy for another administrator role (Helpdesk
    Administrator, say) cannot lock a Global Administrator out, so it is judged but not broad."""
    if enforces == ENFORCES_DEVICE:
        return False
    if reach not in {"all_users", "administrator_roles"} or not _applies_to_all_applications(targeting):
        return False
    if (
        reach == "administrator_roles"
        and accounts is not None
        and not set(_lower(targeting.get("include_roles") or [])) & accounts.global_admin_role_ids
    ):
        return False
    return enforces == ENFORCES_MFA or not _legacy_clients_only(targeting)


def assess_policy(targeting: Mapping[str, Any], state: str, accounts: BreakGlassAccounts) -> dict[str, Any]:
    """Whether one policy is in scope for the check, and whether it excludes the accounts.

    ``in_scope`` needs an enabled policy that enforces MFA or blocks and can reach the accounts.
    ``missing`` is an in-scope policy that excludes none of them. A policy aimed at a user action or an
    authentication context is not a sign-in control and is never in scope.
    """
    result: dict[str, Any] = {"in_scope": False, "missing": False}
    enforces = enforcement(targeting)
    if state != "enabled" or enforces is None or accounts.state != STATE_ASSESSED:
        return result
    if targeting.get("include_user_actions") or targeting.get("include_authentication_contexts"):
        return result
    reach = applies_to_accounts(targeting, accounts)
    if reach is None:
        return result
    excluded = accounts.covers(targeting)
    result.update(
        {
            "in_scope": True,
            "enforces": enforces,
            "reach": reach,
            "broad": is_broad(targeting, enforces, reach, accounts),
            "excluded_accounts": excluded,
            "missing": not excluded,
        }
    )
    if accounts.source == SOURCE_OPERATOR and excluded:
        result["not_excluded_accounts"] = [label for label in accounts.labels if label not in excluded]
    return result


def grade(source: str, flagged: Sequence[Mapping[str, Any]]) -> str:
    """``high`` only for operator-supplied accounts and a policy that can lock every administrator out;
    an inferred account list is a guess, so it never rates above ``medium``."""
    if source == SOURCE_OPERATOR and any(item.get("broad") for item in flagged):
        return "high"
    return "medium"
