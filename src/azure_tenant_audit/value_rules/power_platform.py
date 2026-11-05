"""Power Platform value rules (spec v3.9, section 3.5).

Read the in-memory ScubaGear-shaped rule sections. Empty reads and malformed
policies remain distinct from successful reads with no policy. Records contain
only catalogue text and section names, never environment or tenant values.
"""
from __future__ import annotations

from .helpers import _list_state, _scan_bad_wins
from .record import _rec


def pp_flag(policy_id: str, row: dict, sections: dict) -> dict:
    def evaluate(item):
        value = item
        for key in row["params"]["path"]:
            if not isinstance(value, dict) or key not in value:
                return "unusable"
            value = value[key]
        if type(value) is not bool:
            return "unusable"
        return "clear" if value else "bad"

    return _scan_bad_wins(policy_id, row["params"], sections, evaluate, lambda item: True)


def _answer(policy_id: str, row: dict, cell: str, cited: list[str] | None = None) -> dict:
    """Render a single-text cell from the shipped constants."""
    entry = row["cells"][cell]
    return _rec(policy_id, entry["verdict"], entry["reason_code"], entry["reason_texts"][0], cell, cited)


def pp_isolation(policy_id: str, row: dict, sections: dict) -> dict:
    value = sections["tenant_isolation"]
    if not isinstance(value, list):
        return _answer(policy_id, row, "section_not_a_list", ["tenant_isolation"])
    never = bad = unusable = clear = False
    for item in value:
        if isinstance(item, str) and item == "null":
            never = True
        elif isinstance(item, dict):
            props = item.get("properties")
            disabled = props.get("isDisabled") if isinstance(props, dict) else None
            if disabled is True:
                bad = True
            elif disabled is False:
                clear = True
            else:
                unusable = True
    if not (never or bad or unusable or clear):
        return _answer(policy_id, row, "no_usable_items", ["tenant_isolation"])
    if bad:
        return _answer(policy_id, row, "flag_bad")
    if never:
        return _answer(policy_id, row, "never_configured")
    if unusable:
        return _answer(policy_id, row, "flag_unusable", ["tenant_isolation"])
    return _answer(policy_id, row, "all_clear")


def _dlp_policies(policy_id: str, sections: dict) -> tuple[dict | None, list[tuple[str, set[str]]], bool]:
    """Read wrappers, keeping unreadable policies separate from an empty value list.

    All policies need displayName; AllEnvironments also needs name. Only and
    Except need environments as objects with string names. All may omit it or
    use null. A readable covering policy can decide despite unreadable peers.
    """
    record, wrappers = _list_state(policy_id, sections, "dlp_policies")
    if record:
        return record, [], False
    policies, unreadable = [], False
    for wrapper in wrappers:
        value = wrapper.get("value")
        if not isinstance(value, list):
            unreadable = True
            continue
        for policy in value:
            if not isinstance(policy, dict):
                unreadable = True
                continue
            kind, environments = policy.get("environmentType"), policy.get("environments")
            if (kind not in ("AllEnvironments", "OnlyEnvironments", "ExceptEnvironments")
                    or "displayName" not in policy or (kind == "AllEnvironments" and "name" not in policy)):
                unreadable = True
                continue
            names = set()
            if kind != "AllEnvironments" or environments is not None:
                if (not isinstance(environments, list)
                        or any(not isinstance(item, dict) or type(item.get("name")) is not str
                               for item in environments)):
                    unreadable = True
                    continue
                names = {item["name"] for item in environments}
            policies.append((kind, names))
    return None, policies, unreadable


def pp_dlp(policy_id: str, row: dict, sections: dict) -> dict:
    record, policies, unreadable = _dlp_policies(policy_id, sections)
    if record:
        return record
    has_all = any(kind == "AllEnvironments" for kind, _ in policies)
    if row["params"]["variant"] == "default":
        if has_all:
            return _answer(policy_id, row, "default_environment_covered")
        tenant_id = sections["tenant_id"]
        if type(tenant_id) is not str or not tenant_id:
            return _answer(policy_id, row, "tenant_id_unusable", ["tenant_id"])
        # The rule view owns canonicalisation; environment-name matching is exact.
        default = "Default-" + tenant_id
        if any((kind == "OnlyEnvironments" and default in names)
               or (kind == "ExceptEnvironments" and default not in names) for kind, names in policies):
            return _answer(policy_id, row, "default_environment_covered")
        if unreadable:
            return _answer(policy_id, row, "dlp_structure_unusable", ["dlp_policies"])
        return _answer(policy_id, row, "default_environment_not_covered" if policies else "no_dlp_policies")
    if has_all:
        return _answer(policy_id, row, "all_environments_policy")
    record, environments = _list_state(policy_id, sections, "environment_list")
    if record:
        return record
    if any(type(item.get("EnvironmentName")) is not str or type(item.get("IsDefault")) is not bool
           for item in environments):
        return _answer(policy_id, row, "environment_list_unusable", ["environment_list"])
    nondefault = {item["EnvironmentName"] for item in environments if item["IsDefault"] is False}
    covered = set()
    for kind, names in policies:
        covered |= names if kind == "OnlyEnvironments" else nondefault - names
    if not nondefault - covered:
        return _answer(policy_id, row, "all_environments_covered" if nondefault else "no_nondefault_environments")
    if unreadable:
        return _answer(policy_id, row, "dlp_structure_unusable", ["dlp_policies"])
    return _answer(policy_id, row, "environment_without_policy")


def pp_constant(policy_id: str, row: dict, sections: dict) -> dict:
    # Missing sections are handled by assess before this constant answer.
    return _answer(policy_id, row, "no_baseline_text", list(row["sections"]))


KINDS = {"pp_flag": pp_flag, "pp_isolation": pp_isolation, "pp_dlp": pp_dlp, "pp_constant": pp_constant}
