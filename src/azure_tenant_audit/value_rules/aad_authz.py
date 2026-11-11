"""AAD authorisation and privileged users (spec v3.9 section 3.5).

The user section accepts a map or list. Counts by entry and distinct DisplayName,
including every allocation of unreadable roles, must agree before a verdict.
Names and identity values never enter a record.
"""
from __future__ import annotations

from .helpers import _scan_bad_wins
from .record import _A, BAD_SECTION_LIST, EMPTY_SECTION, ITEM_VALUE, _rec

RESTRICTED_GUEST = "2af84b1e-32c8-42b7-82bc-daa82404023b"
LIMITED_GUEST = "10dae51f-b6af-4016-8d66-8c2a99b929b3"
MEMBER_GUEST = "a0b1b346-4d3e-4e8b-98f8-753987be4970"
INVITE_OK, INVITE_NONE = "adminsAndGuestInviters", "none"
INVITE_BAD = ("adminsGuestInvitersAndAllMembers", "everyone")


def _obj_items(value) -> list[dict] | None:
    """Read the object values of a map or list; ignore non-object elements."""
    if isinstance(value, dict):
        return [item for item in value.values() if isinstance(item, dict)]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return None


def _ev_authz(params: dict):
    leaf = params["leaf"]

    def evaluate(item: dict) -> str:
        if leaf == "create_apps":
            permissions = item.get("DefaultUserRolePermissions")
            value = permissions.get("AllowedToCreateApps") if isinstance(permissions, dict) else None
            if type(value) is not bool:
                return "unusable"
            return "bad" if value else "clear"
        if leaf == "guest_role":
            value = item.get("GuestUserRoleId")
            if type(value) is not str:
                return "unusable"
            if value in (LIMITED_GUEST, RESTRICTED_GUEST):
                return "clear"
            return "bad" if value == MEMBER_GUEST else "unusable"
        value = item.get("AllowInvitesFrom")
        if type(value) is not str:
            return "unusable"
        if value in (INVITE_OK, INVITE_NONE):
            return "clear"
        return "bad" if value in INVITE_BAD else "unusable"

    return evaluate


def authz(policy_id: str, row: dict, sections: dict) -> dict:
    params = row["params"]
    return _scan_bad_wins(policy_id, params, sections, _ev_authz(params),
                          lambda item: type(item.get("Id")) is str)


def _cloud_only(policy_id: str, users: list[dict]) -> dict:
    labelled = unlabelled = unknown = 0
    for user in users:
        if "OnPremisesImmutableId" not in user:
            unknown += 1
        elif user["OnPremisesImmutableId"] is not None:
            if type(user.get("DisplayName")) is str:
                labelled += 1
            else:
                unlabelled += 1
    if labelled:
        return _rec(policy_id, "not_met", "federated_admin_found",
                    "Requirement not met: a privileged user has an on-premises identity (OnPremisesImmutableId is set).",
                    "federated_admin_found")
    if unlabelled or unknown:
        return _A(policy_id, ITEM_VALUE,
                  "Data unusable: a privileged user has no OnPremisesImmutableId value or no DisplayName beside one; "
                  "the policy was not assessed.", "user_record_unusable", ["privileged_users"])
    return _rec(policy_id, "met", "all_cloud_only",
                "Requirement met: no privileged user has an on-premises identity.", "all_cloud_only")


def _count_candidates(users: list[dict], unknown: int) -> set[int]:
    """Both entry and distinct-name counts, with every allocation of unknown roles."""
    names = len({user["DisplayName"] for user in users if type(user.get("DisplayName")) is str})
    return set(range(names, names + unknown + 1)) | set(range(len(users), len(users) + unknown + 1))


def privileged_users(policy_id: str, row: dict, sections: dict) -> dict:
    name = "privileged_users"
    users = _obj_items(sections[name])
    if users is None:
        return _A(policy_id, BAD_SECTION_LIST,
                  "Data unusable: privileged_users is not a map or list of objects; the policy was not assessed.",
                  "section_shape_unusable", [name])
    if not users:
        return _A(policy_id, EMPTY_SECTION,
                  "Data unavailable: privileged_users holds no objects; the policy was not assessed.",
                  "no_usable_items", [name])
    leaf = row["params"]["leaf"]
    if leaf == "cloud_only":
        return _cloud_only(policy_id, users)
    global_admins, other_admins, unknown = [], [], []
    for user in users:
        roles = user.get("roles")
        if not isinstance(roles, list) or any(type(role) is not str for role in roles):
            unknown.append(user)
        elif "Global Administrator" in roles:
            global_admins.append(user)
        else:
            other_admins.append(user)
    global_counts = _count_candidates(global_admins, len(unknown))
    other_counts = _count_candidates(other_admins, len(unknown))
    # 7.2 judges the ratio alone; the 2..8 requirement belongs only to 7.1 (D107).
    # The ratio is monotone: its two extrema give exactly the same agreement
    # as every pair, without quadratic work on a large in-memory rule view.
    verdicts = ({2 <= count <= 8 for count in global_counts} if leaf == "ga_count" else
                {min(global_counts) <= max(other_counts), max(global_counts) <= min(other_counts)})
    if len(verdicts) == 1:
        met = verdicts.pop()
        if leaf == "ga_count":
            if met:
                return _rec(policy_id, "met", "ga_count_in_range",
                            "Requirement met: two to eight users hold the Global Administrator role.", "ga_count_in_range")
            return _rec(policy_id, "not_met", "ga_count_out_of_range",
                        "Requirement not met: fewer than two or more than eight users hold the Global Administrator role.",
                        "ga_count_out_of_range")
        if met:
            return _rec(policy_id, "met", "least_privilege_ok",
                        "Requirement met: Global Administrators do not outnumber the privileged users without that role.",
                        "least_privilege_ok")
        return _rec(policy_id, "not_met", "least_privilege_failed",
                    "Requirement not met: Global Administrators outnumber the privileged users without that role.",
                    "least_privilege_failed")
    return _A(policy_id, ITEM_VALUE,
              "Data unusable: the number of privileged users cannot be fixed (a user without a readable role list, "
              "or users sharing a DisplayName); the policy was not assessed.", "count_ambiguous", [name])


KINDS = {"authz": authz, "priv_users": privileged_users}
