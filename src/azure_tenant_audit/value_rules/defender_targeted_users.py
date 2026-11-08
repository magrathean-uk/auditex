"""SS 2.1 targeted-user membership and its bound coverage summary (TargetedUsersCoverage v1).

``membership`` is the literal comparison the SS 2.1 rule has always made: the second ``;`` component (or the
whole entry), trimmed and lower-cased, nulls skipped, any other non-string member unknown, and ``t`` only for a
non-empty protected set that holds every configured address. It is pure: no I/O, logging, lookup, mutation or
size cap. A run bundle never carries the literal list; it carries a per-policy ``TargetedUsersCoverage`` object
whose ``input_count`` and ``input_hmac_sha256`` bind it to the run's verified private SensitiveUsers copy
(``run-manifest.json`` ``operator_inputs.sensitive_users``). ``membership_from_coverage`` checks that binding and
never falls back to a literal list. The check is consistency with the private list and key, not authenticity.

Everything here is local evidence: the summary and the binding never enter a model view or a shareable output.
"""
from __future__ import annotations

import hmac
import re
from collections.abc import Mapping, Set
from dataclasses import dataclass
from typing import Literal

COVERAGE_KEY = "TargetedUsersCoverage"
BINDING_KEY = "TargetedUsersCoverageBinding"
COVERAGE_VERSION = 1
MAX_INPUT_COUNT = 10_000
STATES = frozenset({"known", "unusable", "not_collected", "over_limit"})
KNOWN_FIELDS = ("version", "state", "input_hmac_sha256", "input_count", "protected_nonempty", "missing_count")
MINIMAL_FIELDS = ("version", "state")
BINDING_FIELDS = ("input_count", "input_hmac_sha256")
_DIGEST = re.compile(r"[0-9a-f]{64}")

Membership = Literal["t", "f", "u"]


@dataclass(frozen=True)
class MembershipResult:
    """``value`` with the pair a known summary records; both are ``None`` when ``value`` is ``u``."""

    value: Membership
    protected_nonempty: bool | None
    missing_count: int | None


@dataclass(frozen=True, repr=False)
class SensitiveUsersBinding:
    """Count and manifest HMAC of the verified SensitiveUsers tuple. No repr: neither value is ever displayed."""

    input_count: int
    input_hmac_sha256: str

    def __post_init__(self) -> None:
        if (type(self.input_count) is not int or self.input_count < 1
                or type(self.input_hmac_sha256) is not str or not _DIGEST.fullmatch(self.input_hmac_sha256)):
            raise ValueError("Invalid sensitive-users binding.")


_UNKNOWN = MembershipResult("u", None, None)


def membership(policy_target_list: object, configured_sensitive_users_set: frozenset[str]) -> MembershipResult:
    """The literal SS 2.1 comparison of one policy's ``TargetedUsersToProtect`` with the configured set ``C``.

    ``C`` is already normalised (``_phish_cfg``). An empty ``C`` keeps the rule's defined behaviour: ``t`` for any
    non-empty protected set. Collection gates refuse to build a known summary for an empty ``C``.
    """
    if not isinstance(policy_target_list, list):
        return _UNKNOWN
    if any(type(x) is not str for x in policy_target_list if x is not None):
        return _UNKNOWN
    have = set()
    for x in policy_target_list:
        if x is None:
            continue
        s = x.strip().lower()
        parts = s.split(";")
        value = (parts[1] if len(parts) > 1 else s).strip().lower()
        if value:
            have.add(value)
    nonempty = bool(have)
    missing = len(configured_sensitive_users_set - have)
    return MembershipResult("t" if nonempty and configured_sensitive_users_set <= have else "f", nonempty, missing)


def _exact_int(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def validate_coverage_shape(value: object) -> bool:
    """A closed v1 object: ``known`` with exactly the six fields and consistent counts, else exactly two fields.

    Integers are exact (``bool`` and ``float`` are refused). This does not check the binding.
    """
    if type(value) is not dict or value.get("version", None) != COVERAGE_VERSION or type(value["version"]) is not int:
        return False
    state = value.get("state")
    if type(state) is not str or state not in STATES:
        return False
    if state != "known":
        return set(value) == set(MINIMAL_FIELDS)
    if set(value) != set(KNOWN_FIELDS):
        return False
    digest, count = value["input_hmac_sha256"], value["input_count"]
    nonempty, missing = value["protected_nonempty"], value["missing_count"]
    return (type(digest) is str and _DIGEST.fullmatch(digest) is not None
            and _exact_int(count, 1, MAX_INPUT_COUNT)
            and type(nonempty) is bool
            and _exact_int(missing, 0, count)
            and (nonempty or missing == count))


def _bound(coverage: dict, binding: object) -> bool:
    """A shape-valid known summary whose count and HMAC equal the verified binding's."""
    return (type(binding) is SensitiveUsersBinding
            and coverage["input_count"] == binding.input_count
            and hmac.compare_digest(coverage["input_hmac_sha256"], binding.input_hmac_sha256))


def membership_from_coverage(
    coverage: object,
    configured_sensitive_users_set: frozenset[str],
    binding: SensitiveUsersBinding | None,
) -> Membership:
    """``t``/``f`` from a valid known summary bound to ``binding`` and to the cardinality of ``C``; else ``u``.

    Never reads a literal list: an invalid or unbound summary is unknown membership, not a fallback.
    """
    if not validate_coverage_shape(coverage) or coverage["state"] != "known":
        return "u"
    if not isinstance(configured_sensitive_users_set, Set) or coverage["input_count"] != len(configured_sensitive_users_set):
        return "u"
    if not _bound(coverage, binding):
        return "u"
    return "t" if coverage["protected_nonempty"] and coverage["missing_count"] == 0 else "f"


def binding_from_config(value: object) -> SensitiveUsersBinding | None:
    """The binding a private SS 2.1 config block carries: exactly ``input_count`` and ``input_hmac_sha256``."""
    if type(value) is SensitiveUsersBinding:
        return value
    if type(value) is not dict or set(value) != set(BINDING_FIELDS):
        return None
    try:
        return SensitiveUsersBinding(value["input_count"], value["input_hmac_sha256"])
    except ValueError:
        return None


def binding_view(binding: SensitiveUsersBinding) -> dict[str, object]:
    """The private config value for ``binding`` (``TargetedUsersCoverageBinding``)."""
    return {"input_count": binding.input_count, "input_hmac_sha256": binding.input_hmac_sha256}


def minimal_coverage(state: str) -> dict[str, object]:
    """A non-known summary: exactly ``version`` and ``state``."""
    if state not in STATES or state == "known":
        raise ValueError("Not a minimal coverage state.")
    return {"version": COVERAGE_VERSION, "state": state}


def shaped_coverage(row: Mapping[str, object]) -> dict[str, object]:
    """A fresh copy of ``row``'s summary when its shape is valid: absent is ``not_collected``, malformed ``unusable``.

    Shape only, for local normalised evidence; ``bound_coverage`` is the rule-evidence gate.
    """
    if COVERAGE_KEY not in row:
        return minimal_coverage("not_collected")
    value = row[COVERAGE_KEY]
    if not validate_coverage_shape(value):
        return minimal_coverage("unusable")
    if value["state"] != "known":
        return minimal_coverage(value["state"])
    return {key: value[key] for key in KNOWN_FIELDS}


def bound_coverage(row: Mapping[str, object], binding: SensitiveUsersBinding | None) -> dict[str, object]:
    """``shaped_coverage`` whose known summary must also match the run's verified binding, else ``unusable``.

    The offending value is never echoed; the source evidence is not rewritten.
    """
    value = shaped_coverage(row)
    if value["state"] == "known" and not _bound(value, binding):
        return minimal_coverage("unusable")
    return value
