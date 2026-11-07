"""SS 2.1 ``TargetedUsersCoverage`` v1 producer and the anti-phish policy row boundary.

``Get-AntiPhishPolicy`` selects ``TargetedUsersToProtect`` so that the SS 2.1 rule can decide membership, but the list
(display names, addresses, domains, malformed strings, nested values) never leaves memory. Every policy row is rebuilt
from the other selected fields plus a fresh summary bound to the run's verified SensitiveUsers copy by the count and
manifest HMAC the writer returned. The raw key never reaches this module and no second HMAC scheme exists here.

One boundary serves every path that can carry the list: the live adapter (with or without the collector's callback),
a collector given another adapter, offline sample replay and resume. Membership semantics are the product helper's,
unchanged; this module adds only the collection caps and the closed summary shape. Nothing here logs, mutates its
input, keeps a list reference or raises value-bearing text.
"""
from __future__ import annotations

import hmac
import json
import re
from collections.abc import Mapping
from typing import Any

from ..sensitive_users import SensitiveUsers
from ..value_rules.defender_targeted_users import (
    COVERAGE_KEY, MAX_INPUT_COUNT, SensitiveUsersBinding, membership, minimal_coverage, validate_coverage_shape,
)
from .exchange_defender_commands import ANTI_PHISH_POLICY_FIELDS

COLLECTOR = "exchange_policy"
OPERATION = "antiPhishPolicies"
TARGET_KEY = "TargetedUsersToProtect"
RETAINED_FIELDS = tuple(field for field in ANTI_PHISH_POLICY_FIELDS if field != TARGET_KEY)
# Per-policy target-list caps (TargetedUsersCoverage v1): raw entries before any filtering, and the list's compact
# JSON as strict UTF-8. Inclusive: exactly the limit is allowed.
MAX_TARGET_ENTRIES = 10_000
MAX_TARGET_BYTES = 262_144
# Aggregate stdout the adapter reads for the sensitive command before it stops, kills and reaps the child.
STDOUT_LIMIT = 64 * 1024 * 1024
# CollectorRunContext.extra keys; only exchange_policy receives them.
CONTEXT_USERS = "sensitive_users"
CONTEXT_BINDING = "sensitive_users_binding"

PARSE_ERROR = "command_output_parse_error"
PARSE_ERROR_CLASS = "command_parse_error"
_SAFE_TOKEN = re.compile(r"[a-z][a-z0-9_]{0,63}(?::[a-z0-9_-]{1,32})?")
_ENVELOPE_TEXT = ("error", "error_class", "status", "reason", "state", "truncation_reason", "collection_status")
_ENVELOPE_NUMBERS = ("return_code", "duration_ms", "stdout_bytes", "stderr_bytes", "item_count", "result_limit")
_ENVELOPE_FLAGS = ("licence_inferred", "collection_truncated", "complete")
_ENVELOPE_KEYS = frozenset({"value", "command", *_ENVELOPE_TEXT, *_ENVELOPE_NUMBERS, *_ENVELOPE_FLAGS})
_ROW_KEYS = frozenset({*RETAINED_FIELDS, COVERAGE_KEY})
_TARGET_FOLD = TARGET_KEY.casefold()


class BoundaryError(ValueError):
    """A fixed-text refusal of a transformed response; never carries row or exception text."""


def is_sensitive_command(text: object) -> bool:
    """Whether a PowerShell script reads anti-phish policies or names the target field, whatever its select."""
    if not isinstance(text, str):
        return False
    folded = text.casefold()
    return "get-antiphishpolicy" in folded or _TARGET_FOLD in folded


def _operator_addresses(sensitive_users: object) -> tuple[str, ...] | None:
    if type(sensitive_users) is not SensitiveUsers:
        return None
    addresses = sensitive_users.addresses
    if type(addresses) is not tuple or not addresses or len(addresses) > MAX_INPUT_COUNT:
        return None
    if any(type(address) is not str for address in addresses):
        return None
    return addresses


def _over_byte_limit(value: list, limit: int = MAX_TARGET_BYTES) -> bool | None:
    """``True`` once the compact strict-UTF-8 JSON of ``value`` passes ``limit``; ``None`` if it cannot be encoded.

    Counts brackets, commas, escapes and content chunk by chunk and stops at the first chunk past the limit, so a
    large list is never fully serialised or concatenated.
    """
    encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    total = 0
    try:
        for chunk in encoder.iterencode(value):
            total += len(chunk.encode("utf-8", "strict"))
            if total > limit:
                return True
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None
    return False


def summarise(
    policy_row: Mapping[str, object],
    operator_list: SensitiveUsers | None,
    hmac_key_or_binding: SensitiveUsersBinding | None,
) -> dict[str, object]:
    """One policy's ``TargetedUsersCoverage`` v1 from its literal target list (interface section 4, steps 1-5).

    ``hmac_key_or_binding`` is the writer's binding (count and manifest HMAC), never a raw key. No loaded non-empty
    operator tuple or no matching binding gives ``not_collected``; an absent, null or non-list field ``unusable``;
    more than ``MAX_TARGET_ENTRIES`` raw entries or ``MAX_TARGET_BYTES`` encoded bytes ``over_limit`` (never a
    trimmed prefix); an unknown comparison ``unusable``; otherwise the six known fields.
    """
    addresses = _operator_addresses(operator_list)
    binding = hmac_key_or_binding
    if addresses is None or type(binding) is not SensitiveUsersBinding or binding.input_count != len(addresses):
        return minimal_coverage("not_collected")
    try:
        if not isinstance(policy_row, Mapping) or TARGET_KEY not in policy_row:
            return minimal_coverage("unusable")
        targets = policy_row[TARGET_KEY]
        if not isinstance(targets, list):
            return minimal_coverage("unusable")
        if len(targets) > MAX_TARGET_ENTRIES:
            return minimal_coverage("over_limit")
        over = _over_byte_limit(targets)
        if over is None:
            return minimal_coverage("unusable")
        if over:
            return minimal_coverage("over_limit")
        result = membership(targets, frozenset(addresses))
        if result.value == "u":
            return minimal_coverage("unusable")
        known = {
            "version": 1, "state": "known",
            "input_hmac_sha256": binding.input_hmac_sha256, "input_count": binding.input_count,
            "protected_nonempty": result.protected_nonempty, "missing_count": result.missing_count,
        }
    except Exception:  # noqa: BLE001 - a value-bearing failure is an unusable field, never an escaping message
        return minimal_coverage("unusable")
    return known if validate_coverage_shape(known) else minimal_coverage("unusable")


def sanitise_policy_row(
    row: Mapping[str, object],
    sensitive_users: SensitiveUsers | None,
    binding: SensitiveUsersBinding | None,
    *,
    observed: bool,
) -> dict[str, object]:
    """A new row of the retained selected fields plus a fresh summary; the target list and unknown fields are gone.

    Fresh literals are always summarised, overwriting any supplied summary. Without literals, ``observed`` (a live
    read that selected the field) summarises the absence as ``unusable``; a replayed or carried row gets
    ``not_collected``, because an old proof is never rebound to a new run.
    """
    clean = {field: row[field] for field in RETAINED_FIELDS if field in row}
    if TARGET_KEY in row or observed:
        clean[COVERAGE_KEY] = summarise(row, sensitive_users, binding)
    else:
        clean[COVERAGE_KEY] = minimal_coverage("not_collected")
    return clean


def _safe_text(value: object) -> bool:
    return type(value) is str and _SAFE_TOKEN.fullmatch(value) is not None


def _envelope_metadata(response: Mapping[str, object]) -> dict[str, object]:
    """Fixed classes, numbers and flags of an envelope; free text (stdout, stderr, samples, messages) is dropped."""
    out: dict[str, object] = {}
    for key in _ENVELOPE_TEXT:
        if key not in response:
            continue
        value = response[key]
        if value is None or _safe_text(value):
            out[key] = value
        elif key == "error_class":
            out[key] = "command_error"
    if "error" in response and "error" not in out:
        out["error"] = out.get("error_class") or "command_error"
    for key in _ENVELOPE_NUMBERS:
        if key in response and type(response[key]) in (int, float):
            out[key] = response[key]
    for key in _ENVELOPE_FLAGS:
        if key in response and type(response[key]) is bool:
            out[key] = response[key]
    return out


def sanitise_response(
    response: object,
    sensitive_users: SensitiveUsers | None = None,
    binding: SensitiveUsersBinding | None = None,
    *,
    observed: bool = True,
    command: str | None = None,
) -> Any:
    """The anti-phish operation envelope after the boundary.

    A row container that is not a list of mappings, or a live success without one, becomes the existing controlled
    parse error: no scalar row is kept and no policy is invented in its place. A container of another shape (replay
    only) keeps its structure with every target subtree discarded.
    """
    if not isinstance(response, Mapping):
        return strip_targets(response)
    out = _envelope_metadata(response)
    text_command = command if command is not None else response.get("command")
    if isinstance(text_command, str):
        out["command"] = text_command
    failed = "error" in out or "error_class" in out and out["error_class"] is not None
    if "value" in response:
        rows = response["value"]
        if type(rows) is not list or any(not isinstance(row, Mapping) for row in rows):
            return _parse_error(out)
        out["value"] = [sanitise_policy_row(row, sensitive_users, binding, observed=observed) for row in rows]
    elif observed and not failed:
        return _parse_error(out)
    return out


def _parse_error(metadata: Mapping[str, object]) -> dict[str, object]:
    out = {key: metadata[key] for key in ("command", *_ENVELOPE_NUMBERS) if key in metadata}
    out.update(error=PARSE_ERROR, error_class=PARSE_ERROR_CLASS)
    return out


def enforce_response(response: object, *, command: str) -> dict[str, object]:
    """Check a transform's output against the boundary's closed shape; raise ``BoundaryError`` otherwise.

    The adapter stays the boundary even when a callback is wrong: only allowlisted envelope keys and fixed text,
    rows of retained fields, and a shape-valid summary on every row.
    """
    if type(response) is not dict or not set(response) <= _ENVELOPE_KEYS:
        raise BoundaryError("anti-phish response shape")
    for key in _ENVELOPE_TEXT:
        if key in response and response[key] is not None and not _safe_text(response[key]):
            raise BoundaryError("anti-phish response text")
    if "value" in response:
        rows = response["value"]
        if type(rows) is not list:
            raise BoundaryError("anti-phish response rows")
        for row in rows:
            if (type(row) is not dict or not set(row) <= _ROW_KEYS or COVERAGE_KEY not in row
                    or not validate_coverage_shape(row[COVERAGE_KEY])):
                raise BoundaryError("anti-phish response row")
    return {**response, "command": command}


def strip_targets(value: Any) -> Any:
    """A copy with every target subtree discarded (any key case); a mapping that held one, or held a summary, is
    marked ``not_collected``. For layouts the boundary does not recognise: nothing there is summarised."""
    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        marked = False
        for key, item in value.items():
            folded = key.casefold() if isinstance(key, str) else None
            if folded == _TARGET_FOLD or key == COVERAGE_KEY:
                marked = True
                continue
            out[key] = strip_targets(item)
        if marked:
            out[COVERAGE_KEY] = minimal_coverage("not_collected")
        return out
    if isinstance(value, list):
        return [strip_targets(item) for item in value]
    return value


def has_targets(value: Any) -> bool:
    """Whether any mapping key in ``value`` names the target field, in any case."""
    if isinstance(value, Mapping):
        return any(
            (isinstance(key, str) and key.casefold() == _TARGET_FOLD) or has_targets(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(has_targets(item) for item in value)
    return False


def sanitise_sample(
    sample: Mapping[str, Any], sensitive_users: SensitiveUsers | None, binding: SensitiveUsersBinding | None,
) -> dict[str, Any]:
    """An offline sample with the boundary applied, built before the replay copy and before any collector replays.

    ``exchange_policy.antiPhishPolicies`` rows are rebuilt as in a live read, under this run's binding (fresh literals
    are summarised; a supplied summary alone becomes ``not_collected``). Every other location, including flat or
    legacy layouts, loses its target subtrees. A section too deep to walk is replaced by an empty mapping rather
    than copied. The source mapping is not modified.
    """
    out: dict[str, Any] = {}
    for key, value in sample.items():
        try:
            if key == COLLECTOR and isinstance(value, Mapping):
                out[key] = {
                    name: (sanitise_response(envelope, sensitive_users, binding, observed=False)
                           if name == OPERATION else strip_targets(envelope))
                    for name, envelope in value.items()
                }
            else:
                out[key] = strip_targets(value)
        except RecursionError:
            out[key] = {}
    return out


def _bound_known(coverage: object, binding: SensitiveUsersBinding) -> bool:
    return (validate_coverage_shape(coverage) and coverage["state"] == "known"
            and coverage["input_count"] == binding.input_count
            and hmac.compare_digest(coverage["input_hmac_sha256"], binding.input_hmac_sha256))


def resume_payload(
    payload: Mapping[str, Any], sensitive_users: SensitiveUsers | None, binding: SensitiveUsersBinding | None,
) -> tuple[dict[str, Any], bool]:
    """``(payload, reusable)`` for a carried exchange_policy raw payload under this session's operator input.

    Reusable only when no target literal is present and the SS 2.1 summaries can stand for this session: with a
    current binding, a healthy anti-phish read whose every row holds a known summary with this count and HMAC
    (compared in constant time); without one, no row claims membership. Otherwise the returned payload is a
    minimised in-memory copy whose anti-phish rows are ``not_collected`` and whose literals are gone; the stored
    raw file and its summaries are never rewritten or rebound.
    """
    try:
        envelope = payload.get(OPERATION)
        reusable = not has_targets(payload) and _reusable(envelope, sensitive_users, binding)
        if reusable:
            return dict(payload), True
        minimised = {
            name: (sanitise_response(item, None, None, observed=False) if name == OPERATION else strip_targets(item))
            for name, item in payload.items()
        }
    except RecursionError:
        return {}, False
    return minimised, False


def _reusable(envelope: object, sensitive_users: SensitiveUsers | None, binding: SensitiveUsersBinding | None) -> bool:
    addresses = _operator_addresses(sensitive_users)
    current = binding if (type(binding) is SensitiveUsersBinding and addresses is not None
                          and binding.input_count == len(addresses)) else None
    if envelope is None:
        return current is None
    if not isinstance(envelope, Mapping) or envelope.get("error") or envelope.get("error_class"):
        return False
    rows = envelope.get("value")
    if type(rows) is not list or any(not isinstance(row, Mapping) for row in rows):
        return False
    if current is None:
        return not any(
            isinstance(row.get(COVERAGE_KEY), Mapping) and row[COVERAGE_KEY].get("state") == "known" for row in rows
        )
    return all(_bound_known(row.get(COVERAGE_KEY), current) for row in rows)
