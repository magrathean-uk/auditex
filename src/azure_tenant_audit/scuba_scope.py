"""Bounded Conditional Access scope evidence for the assessment envelope.

The summary lists enabled candidate policies carrying conditions the pinned ScubaGear
Rego ignores, independently of assessment verdicts. It never marks assessment rows.
The shared table also describes historical row metadata accepted by the validator.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from .resources import open_text_resource

SECTION = "conditional_access_policies"
# A display name, a tracked enumeration value and a retained policy are all bounded: the scan bounds of the
# projection limit what is read, these limit what is kept and written.
NAME_LIMIT = 200
MAX_VALUES = 64
MAX_ENTRIES = 1000
UNNAMED = "(unnamed policy)"
_OPERATOR = "operator"
_AGENTS_INCLUDED = "includeagentidserviceprincipals"


class ScopeOversize(ValueError):
    """More candidate policies than the scope summary retains; the check is not evaluated."""


@dataclass(frozen=True)
class ScopeEntry:
    """One enabled Conditional Access policy that could have decided some tabled item.

    ``groups`` are the scope conditions it carries; ``tokens`` are the enumeration values, counts and grant
    classes the table's requirements are written in.
    """

    name: str
    groups: frozenset[str]
    tokens: frozenset[str]


def scope_catalogue() -> dict[str, Any]:
    return json.loads(open_text_resource("configs/scuba-scope-blind.json"))


def condition_paths() -> dict[str, str]:
    return scope_catalogue()["paths"]


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
    """Retain what the scope summary needs of each enabled policy that could have decided a tabled item.

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
