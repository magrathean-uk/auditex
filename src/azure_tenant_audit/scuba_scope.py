"""Deterministic scope post-check for verdicts the pinned ScubaGear Rego reads blind.

The Rego ignores the location, platform, device-filter, client-application and (for most
policies) client-application-type conditions of a Conditional Access policy, and the grant
operator of several, so a policy applied to one office still gives a clean verdict. After a
verdict of met this module marks the row ``scope_narrowed`` when an enabled policy that could
have decided it carries such a condition and no compliant unscoped policy decides it as well.
It never changes the verdict, never reads message bodies or file content, and keeps of each
enabled policy only its display name, a few enumeration values, counts and which scope
conditions it carries. The per-policy table is ``configs/scuba-scope-blind.json``; the serving
layer, the validator and the tests share it. A policy "could have decided" an item only when it
carries every check the Rego makes of a deciding policy (users, applications, role exclusions,
client types, risk levels, the exact grant), so the policy that really decided can never be left
out; the table's ``source`` text cites the Rego line of each.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
import json
from typing import Any

from .resources import open_text_resource

POST_CHECK_KIND = "scope_narrowed"
# The one limitation id the post-check adds. It is an assessment-contract extension on the row, like the
# named ``required_evidence_section_not_collected:<section>`` limitations: the catalogue's closed
# ``limitation_ids`` (part of every prompt) and the pack vocabulary are untouched.
LIMITATION_ID = "scope_narrowed"
SECTION = "conditional_access_policies"
# A display name, a tracked enumeration value and a retained policy are all bounded: the scan bounds of the
# projection limit what is read, these limit what is kept and written.
NAME_LIMIT = 200
MAX_VALUES = 64
MAX_ENTRIES = 1000
UNNAMED = "(unnamed policy)"
_OPERATOR = "operator"
_OPERATOR_OR = "grantControls.operator=OR"
_AGENTS_INCLUDED = "includeagentidserviceprincipals"


class ScopeOversize(ValueError):
    """More candidate policies than the post-check retains; the check is not evaluated."""


@dataclass(frozen=True)
class ScopeEntry:
    """One enabled Conditional Access policy that could have decided some tabled item.

    ``groups`` are the scope conditions it carries; ``tokens`` are the enumeration values, counts and grant
    classes the table's requirements are written in.
    """

    name: str
    groups: frozenset[str]
    tokens: frozenset[str]

    @property
    def operator_or(self) -> bool:
        return _OPERATOR_OR in self.tokens


def scope_catalogue() -> dict[str, Any]:
    return json.loads(open_text_resource("configs/scuba-scope-blind.json"))


def scope_rule(policy_id: str) -> dict[str, Any] | None:
    return scope_catalogue()["policies"].get(policy_id)


def condition_paths() -> dict[str, str]:
    return scope_catalogue()["paths"]


def allowed_conditions(rule: dict[str, Any]) -> set[str]:
    """The condition paths a row of this policy may carry, given the policy's table entry."""
    paths = condition_paths()
    allowed = {paths[group] for group in rule["ignored"]}
    if rule["operator"]:
        allowed.add(paths[_OPERATOR])
    return allowed


def _get(mapping: Any, name: str) -> Any:
    """A field of a Graph (camelCase) or ProviderExport (PascalCase) object."""
    if not isinstance(mapping, dict):
        return None
    return mapping[name] if name in mapping else mapping.get(name[:1].upper() + name[1:])


def _dig(value: Any, path: str) -> Any:
    for part in path.split("."):
        value = _get(value, part)
    return value


def _present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, dict, str)):
        return bool(value)
    return True


def _items(value: Any) -> list[str]:
    """The non-empty strings of a list, or of a comma-separated string, trimmed and not otherwise bounded."""
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _values(value: Any) -> list[str]:
    """Enumeration values of a list, or of a comma-separated string, at most ``MAX_VALUES`` of them."""
    return [item[:NAME_LIMIT] for item in _items(value)[:MAX_VALUES]]


def _count(value: Any) -> int:
    """The Rego's ``Count`` of a field: null is 0, a list is its length, any other non-null value is one."""
    if value is None:
        return 0
    if isinstance(value, list):
        return len(value)
    if isinstance(value, str):
        return len(_items(value))
    return 1


def _unrestricted(include: Any, exclude: Any) -> bool:
    """An include of everything, or of nothing stated, with nothing excluded: the condition does not restrict."""
    included = [item.lower() for item in _values(include)]
    return not _values(exclude) and (not included or included == ["all"])


def _narrows(group: str, path: str, policy: Any) -> bool:
    """Whether the condition restricts where the policy applies, or exempts part of it.

    A condition that includes everything (or states no include) and excludes nothing ("any location", all
    platforms, all client application types) is the unscoped form and does not narrow. A condition that is
    present but not recognised narrows: the check errs towards flagging. A client-application condition
    that only targets every agent identity, with no agent excluded, is the unscoped form of the agent policy.
    """
    value = _dig(policy, path)
    if group == "client_app_types":
        values = {item.lower() for item in _values(value)}
        return bool(values) and values != {"all"}
    if value is None:
        return False
    if not isinstance(value, dict):
        return True
    if group == "locations":
        return not _unrestricted(_get(value, "includeLocations"), _get(value, "excludeLocations"))
    if group == "platforms":
        return not _unrestricted(_get(value, "includePlatforms"), _get(value, "excludePlatforms"))
    skip = ""
    if group == "client_applications" and _items(_get(value, "includeAgentIdServicePrincipals")) == ["All"] \
            and not _items(_get(value, "excludeAgentIdServicePrincipals")):
        skip = _AGENTS_INCLUDED
    return any(_present(item) for key, item in value.items() if str(key).lower() != skip)


def _strength_class(strength: Any, spec: dict[str, Any]) -> str | None:
    """How the Rego reads an authentication strength (Utils/AAD.rego l190-236), or None when there is none."""
    if not _present(strength):
        return None
    combinations = _get(strength, "allowedCombinations")
    found = {item for item in combinations if isinstance(item, str)} if isinstance(combinations, list) else set()
    resistant, multifactor = set(spec["phishing_resistant"]), set(spec["mfa_combinations"])
    if found and found <= resistant:
        return "phishingResistant"
    if found & multifactor and not found - multifactor and found - resistant:
        return "generalMfa"
    return "other"


def _tokens(policy: Any, catalogue: dict[str, Any]) -> frozenset[str]:
    """The facts of one policy the table's requirements are written in; no identifier or name is kept."""
    tokens = set()
    for path in catalogue["tracked"]:
        tokens.update(f"{path}={item}" for item in _values(_dig(policy, path)))
    for path, wanted in catalogue["members"].items():
        found = set(_items(_dig(policy, path)))
        tokens.update(f"{path}={item}" for item in wanted if item in found)
    for path in catalogue["exact"]:
        value = _dig(policy, path)
        if isinstance(value, str):
            tokens.add(f"{path}={value[:NAME_LIMIT]}")
    for path in catalogue["counted"]:
        tokens.add(f"{path}#{_count(_dig(policy, path))}")
    spec = catalogue["authentication_strength"]
    strength = _strength_class(_dig(policy, spec["path"]), spec)
    if strength:
        tokens.add(f"{spec['path']}={strength}")
    return frozenset(tokens)


def _candidate(rule: dict[str, Any], tokens: frozenset[str]) -> bool:
    """Whether a policy with these tokens carries a grant of the item and every check the Rego makes of it."""
    return bool(tokens.intersection(rule["grants"])) and all(tokens.intersection(group) for group in rule["requires"])


def scope_entries(policies: Iterable[Any], *, mask: Callable[[str], str] | None = None) -> list[ScopeEntry]:
    """Retain what the post-check needs of each enabled policy that could have decided a tabled item.

    Report-only and disabled policies never decide. ``mask`` rewrites a display name (before it is cut to
    ``NAME_LIMIT``, so a cut cannot leave part of what the mask would have hidden).
    """
    catalogue = scope_catalogue()
    groups = {group: path for group, path in sorted(catalogue["paths"].items()) if group != _OPERATOR}
    rules = list(catalogue["policies"].values())
    entries: list[ScopeEntry] = []
    for policy in policies:
        if not isinstance(policy, dict) or _get(policy, "state") != "enabled":
            continue
        tokens = _tokens(policy, catalogue)
        if not any(_candidate(rule, tokens) for rule in rules):
            continue
        if len(entries) >= MAX_ENTRIES:
            raise ScopeOversize("candidate policy bound exceeded")
        name = _get(policy, "displayName")
        label = UNNAMED if not isinstance(name, str) or not name else (mask(name) if mask else name)[:NAME_LIMIT]
        narrowed = frozenset(group for group, path in groups.items() if _narrows(group, path, policy))
        entries.append(ScopeEntry(label or UNNAMED, narrowed, tokens))
    return entries


def requirement_met(row: dict[str, Any]) -> bool:
    """A model row whose requirement is confirmed or inferred met; a not-applicable answer is not a clean pass."""
    claim = next((c for c in row.get("claims", []) if c.get("id") == "requirement_met"), None)
    return (row.get("validation_status") == "valid" and row.get("reason") != "rule_precheck"
            and isinstance(claim, dict) and claim.get("status") in {"confirmed", "inferred"}
            and claim.get("value") is True and "policy_not_applicable" not in row.get("limitations", []))


def _found(rule: dict[str, Any], entry: ScopeEntry, catalogue: dict[str, Any]) -> set[str]:
    """The condition paths through which this candidate is scoped for this item, in the Rego's blind spots."""
    paths = catalogue["paths"]
    found = {paths[group] for group in entry.groups & set(rule["ignored"])}
    if rule["operator"] and entry.operator_or:
        # An OR grant that offers a control the item does not accept lets a user pass without the required one.
        accepted, controls = {*rule["grants"], *rule["alongside"]}, set(catalogue["controls"])
        if any(token.partition("=")[0] in controls and token not in accepted for token in entry.tokens):
            found.add(paths[_OPERATOR])
    return found


def _without_exclusions(entry: ScopeEntry, catalogue: dict[str, Any]) -> bool:
    """A candidate with no exclusion the ScubaGear config would have to allow-list: nothing for the Rego to refuse."""
    return all(f"{path}#0" in entry.tokens for path in catalogue["exclusions"])


def post_check(policy_id: str, entries: Iterable[ScopeEntry], *, max_items: int = 40) -> dict[str, Any] | None:
    """The row-level record when a policy that could have decided ``policy_id`` is scope-narrowed, else None.

    Nothing is recorded when a compliant policy with no scope condition could have decided the item as well:
    the control is then applied everywhere, and the scoped policy is left to the envelope record.
    """
    catalogue = scope_catalogue()
    rule = catalogue["policies"].get(policy_id)
    if rule is None:
        return None
    names: set[str] = set()
    conditions: set[str] = set()
    count = 0
    for entry in entries:
        if not _candidate(rule, entry.tokens):
            continue
        found = _found(rule, entry, catalogue)
        if not found:
            if _without_exclusions(entry, catalogue):
                return None
            continue
        count += 1
        names.add(entry.name)
        conditions |= found
    if not count:
        return None
    return {"kind": POST_CHECK_KIND, "policies": sorted(names)[:max_items], "conditions": sorted(conditions),
            "count": count}


def scope_summary(entries: Iterable[ScopeEntry], *, max_items: int = 40) -> dict[str, Any]:
    """Every enabled policy scoped on a condition that a tabled item it could decide ignores (the envelope list).

    Whatever the verdicts. A condition the Rego reads for every item the policy could decide is part of the
    verdict, not a narrowing it misses, and is not listed.
    """
    catalogue = scope_catalogue()
    paths, rules = catalogue["paths"], list(catalogue["policies"].values())
    by_name: dict[str, set[str]] = {}
    count = 0
    for entry in entries:
        found = {paths[group] for rule in rules if _candidate(rule, entry.tokens)
                 for group in entry.groups & set(rule["ignored"])}
        if found:
            count += 1
            by_name.setdefault(entry.name, set()).update(found)
    return {"count": count, "policies": [{"name": name, "conditions": sorted(found)}
                                         for name, found in sorted(by_name.items())][:max_items]}


def apply_post_check(row: dict[str, Any], entries: Iterable[ScopeEntry], *, max_items: int = 40) -> None:
    """Mark a met row ``scope_narrowed``; the claims, comparison and recommendations stay as the verdict gave them."""
    if not requirement_met(row):
        return
    found = post_check(row["policy_id"], entries, max_items=max_items)
    if found is not None:
        row["post_check"] = found
        if LIMITATION_ID not in row["limitations"]:
            row["limitations"].append(LIMITATION_ID)
