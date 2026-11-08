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

from functools import lru_cache
import hmac
import json
import math
import re
from collections.abc import Mapping
from typing import Any

from ..collection_gaps import REASON_UNKNOWN, TRUNCATION_REASONS
from ..sensitive_users import SensitiveUsers
from ..value_rules.defender_targeted_users import (
    COVERAGE_KEY, MAX_INPUT_COUNT, SensitiveUsersBinding, membership, minimal_coverage, validate_coverage_shape,
)
from .exchange_defender_commands import ANTI_PHISH_POLICY_FIELDS
from .anti_phish_admission import ADMITTED, FAILED, admit_response, subtree_healthy

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
FALLBACK_ERROR = "command_error"
# Closed diagnostic vocabulary: the classes and errors the adapter writes for this read, and the fixed outcome
# tokens envelopes carry. Anything else is replaced by FALLBACK_ERROR (error, error_class), dropped (other text) or,
# from a callback, refused. The only variant is the adapter's numeric exit code in ``command_failed:<n>``.
ERROR_CLASSES = frozenset({
    "command_error", "command_parse_error", "command_timeout", "command_exception", "command_not_found",
    "command_not_authenticated", "session_not_connected", "module_not_found", "command_output_empty",
})
_ERRORS = ERROR_CLASSES | {"command_empty", "command_not_found:pwsh", PARSE_ERROR, "command_output_over_limit"}
_FAILED_EXIT = re.compile(r"command_failed:-?[0-9]{1,10}")
_TEXT_VOCAB: dict[str, frozenset[str]] = {
    "error_class": ERROR_CLASSES,
    # ``ok``, ``success``, ``collected`` and ``complete`` are the values the projection reads as healthy.
    "status": frozenset({"ok", "success", "collected", "complete", "failed", "partial", "skipped"}),
    "reason": frozenset({"not_found", "rate_limit", "server_error", "dependency_unavailable", "offline_bundle",
                         "preflight_exception"}),
    "state": frozenset({"over_limit"}),
    "truncation_reason": frozenset(TRUNCATION_REASONS),
    "collection_status": frozenset({"collected", "failed", "not_collected"}),
    "read_state": frozenset({"collected", "failed", "not_collected"}),
}
# Health keys whose unknown value becomes a fixed refusal token instead of being dropped, so a refusal never reads as
# success. The projection (``auditex.scuba_projection._healthy``) and the resume publisher refuse a present ``status``,
# ``collection_status`` or ``read_state`` outside their healthy values, whatever it holds, and any truthy
# ``truncation_reason``. ``reason`` and ``state`` carry no health meaning there, so an unknown one is only dropped.
_PRESENT_REFUSAL = {"status": "failed", "collection_status": "failed", "read_state": "failed"}
_TRUTHY_REFUSAL = {"truncation_reason": REASON_UNKNOWN}
# Structural bounds for retained values and for sample, resume and unrecognised layouts. Text longer than
# MAX_SCAN_CHARS, nesting deeper than MAX_DEPTH or more than MAX_NODES walked items is never copied.
MAX_FIELD_CHARS = 4096
MAX_SCAN_CHARS = 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 10_000_000
_ESCAPE_ROUNDS = 8
_ESCAPE = re.compile(r"\\+[uU]([0-9a-fA-F]{4})")
_NON_ALNUM = re.compile(r"[^0-9a-z]+")
_TARGET_ALNUM = "targeteduserstoprotect"
_FIELDS_FOLDED = frozenset(field.casefold() for field in ANTI_PHISH_POLICY_FIELDS)
_COMMAND = re.compile(r"(,@\()?get-antiphishpolicy (?:\||'\|') select-object ([a-z]+(?:,[a-z]+)*)(\))?")
_ENVELOPE_TEXT = ("error", "error_class", "status", "reason", "state", "truncation_reason", "collection_status",
                  "read_state")
_ENVELOPE_NUMBERS = ("return_code", "duration_ms", "stdout_bytes", "stderr_bytes", "item_count", "result_limit")
_ENVELOPE_FLAGS = ("licence_inferred", "collection_truncated", "complete")
# Refusal markers the projection, the resume publisher or offline replay read by truthiness alone. Their values (a
# URL, resolver text, anything) are never copied: a truthy one becomes ``True`` and a falsy one is dropped.
_ENVELOPE_MARKERS = ("bounded_sample", "incomplete", "partial", "collection_limit_reached", "resolver_error",
                     "@odata.nextLink")
_ENVELOPE_KEYS = frozenset({"value", "command", *_ENVELOPE_TEXT, *_ENVELOPE_NUMBERS, *_ENVELOPE_FLAGS,
                            *_ENVELOPE_MARKERS})
# Keys that make a sample-root mapping an operation envelope (or a diagnostic carrier), never a collector section of
# independent operations: the envelope keys plus the diagnostic text slots adapters and older samples write.
_COMPONENT_KEYS = frozenset({*_ENVELOPE_KEYS, "message", "stdout", "stderr", "stdout_sample", "stderr_sample",
                             "details", "exception", "traceback", "warning", "warnings"})
_ROW_KEYS = frozenset({*RETAINED_FIELDS, COVERAGE_KEY})
# Sample-root keys that hold sample metadata rather than a collector section (the CLI's offline metadata keys). They
# keep the component walk; the CLI applies ``strip_targets`` to provenance again before it is published.
_SAMPLE_METADATA_KEYS = frozenset({"_fixture_provenance"})
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


def _key_names_target(key: object) -> bool:
    """A mapping key naming the target field in any case, with or without separators."""
    return type(key) is str and len(key) <= 256 and _NON_ALNUM.sub("", key.casefold()) == _TARGET_ALNUM


def _unescape(match: re.Match[str]) -> str:
    return chr(int(match.group(1), 16))


def _mentions_target(text: str) -> bool:
    """Whether ``text`` names the target field, plainly or inside JSON at any encoding depth.

    Letters survive JSON encoding, so after removing everything but ASCII letters and digits the name shows at
    any depth; ``\\uXXXX`` escapes (any backslash count) are undone for at most ``_ESCAPE_ROUNDS`` rounds. Text too
    long to examine, or still unescaping after the bound, counts as naming it. Values are never matched.
    """
    if len(text) > MAX_SCAN_CHARS:
        return True
    current = text
    for _ in range(_ESCAPE_ROUNDS):
        if _TARGET_ALNUM in _NON_ALNUM.sub("", current.casefold()):
            return True
        decoded = _ESCAPE.sub(_unescape, current)
        if decoded == current:
            return False
        current = decoded
    return True


def _controlled_command(value: object) -> bool:
    """The adapter's own anti-phish read (plain or as redacted for logs) selecting only known policy fields."""
    if type(value) is not str or len(value) > MAX_FIELD_CHARS:
        return False
    match = _COMMAND.fullmatch(value.strip().casefold())
    return (match is not None and bool(match.group(1)) == bool(match.group(3))
            and set(match.group(2).split(",")) <= _FIELDS_FOLDED)


def _safe_scalar(value: object) -> bool:
    if value is None or type(value) is bool or type(value) is int:
        return True
    if type(value) is float:
        return math.isfinite(value)
    return type(value) is str and len(value) <= MAX_FIELD_CHARS and not _mentions_target(value)


def _safe_field(value: object) -> bool:
    """A retained selected value: a JSON scalar or a flat bounded list of them, with no text naming the target.

    Mappings and nested lists are unknown structure and are never traversed into a returned row.
    """
    if type(value) is not list:
        return _safe_scalar(value)
    if len(value) > MAX_TARGET_ENTRIES:
        return False
    total = 0
    for item in value:
        if not _safe_scalar(item):
            return False
        if type(item) is str:
            total += len(item)
            if total > MAX_TARGET_BYTES:
                return False
    return True


def _retained(row: Mapping[str, object]) -> dict[str, object]:
    """The retained selected fields whose values pass ``_safe_field``, copied; an unsafe value drops that field only."""
    out: dict[str, object] = {}
    for field in RETAINED_FIELDS:
        if field in row:
            value = row[field]
            if _safe_field(value):
                out[field] = list(value) if type(value) is list else value
    return out


def sanitise_policy_row(
    row: Mapping[str, object],
    sensitive_users: SensitiveUsers | None,
    binding: SensitiveUsersBinding | None,
    *,
    observed: bool,
) -> dict[str, object]:
    """A new row of the retained selected fields plus a fresh summary; the target list and unknown fields are gone.

    A retained field is kept only as a scalar or a flat bounded list of scalars with no text naming the target
    field; a nested or encoded target subtree drops that field alone, so the policy's other settings stay usable.
    Fresh literals are always summarised, overwriting any supplied summary. Without literals, ``observed`` (a live
    read that selected the field) summarises the absence as ``unusable``; a replayed or carried row gets
    ``not_collected``, because an old proof is never rebound to a new run.
    """
    clean = _retained(row)
    if TARGET_KEY in row or observed:
        clean[COVERAGE_KEY] = summarise(row, sensitive_users, binding)
    else:
        clean[COVERAGE_KEY] = minimal_coverage("not_collected")
    return clean


def _known_text(key: str, value: object) -> bool:
    if value is None:
        return True
    if type(value) is not str:
        return False
    if key == "error":
        return value in _ERRORS or _FAILED_EXIT.fullmatch(value) is not None
    return value in _TEXT_VOCAB[key]


def _number(value: object) -> bool:
    return type(value) is int or (type(value) is float and math.isfinite(value))


def _truthy(value: object) -> bool:
    """JSON truthiness without calling into an unknown object; anything else counts as a present marker."""
    if value is None or type(value) in (bool, int, float, str, list, dict):
        return bool(value)
    return True


def _envelope_metadata(response: Mapping[str, object]) -> dict[str, object]:
    """Closed-vocabulary classes, numbers, flags and refusal markers of an envelope; free text (stdout, stderr,
    samples, messages, unknown tokens, URLs) is dropped.

    No refusal turns into apparent success: an unknown error or class becomes the fixed fallback, an unknown health
    value the fixed refusal token of its key, a non-boolean ``complete`` ``False``, a truthy non-boolean
    ``collection_truncated`` or marker ``True``. Only falsy unknown values, which refuse nothing, are dropped.
    """
    out: dict[str, object] = {}
    for key in _ENVELOPE_TEXT:
        if key not in response:
            continue
        value = response[key]
        if _known_text(key, value):
            out[key] = value
        elif key in _PRESENT_REFUSAL:
            out[key] = _PRESENT_REFUSAL[key]
        elif key in _TRUTHY_REFUSAL and _truthy(value):
            out[key] = _TRUTHY_REFUSAL[key]
    if "error_class" in response and "error_class" not in out:
        out["error_class"] = FALLBACK_ERROR
    if "error" in response and "error" not in out:
        out["error"] = out.get("error_class") or FALLBACK_ERROR
    for key in _ENVELOPE_NUMBERS:
        if key in response and _number(response[key]):
            out[key] = response[key]
    for key in _ENVELOPE_FLAGS:
        if key not in response:
            continue
        value = response[key]
        if type(value) is bool:
            out[key] = value
        elif key == "complete":
            out[key] = False  # only an exact ``True`` is complete
        elif key == "collection_truncated" and _truthy(value):
            out[key] = True
    for key in _ENVELOPE_MARKERS:
        if key in response and _truthy(response[key]):
            out[key] = True
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
    parse error: no scalar row is kept and no policy is invented in its place. A bare list of rows (replay only)
    keeps each mapping row's retained fields, marked ``not_collected`` and never summarised; any other shape is the
    parse error. A supplied command is kept only when it is the adapter's own anti-phish read.
    """
    if not isinstance(response, Mapping):
        if not observed and isinstance(response, list):
            return [{**_retained(row), COVERAGE_KEY: minimal_coverage("not_collected")}
                    for row in response if isinstance(row, Mapping)]
        return _parse_error({"command": command} if isinstance(command, str) else {})
    admission = admit_response(response, observed=observed)
    out = _envelope_metadata(response)
    if isinstance(command, str):
        out["command"] = command
    elif _controlled_command(response.get("command")):
        out["command"] = response["command"]
    if admission not in (ADMITTED, FAILED):
        # Keep fixed refusal metadata for replay coverage, but never generate a membership summary from a rejected read.
        out.update(error=PARSE_ERROR, error_class=PARSE_ERROR_CLASS)
        return out
    failed = "error" in out or ("error_class" in out and out["error_class"] is not None)
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

    The adapter stays the boundary even when a callback is wrong: only allowlisted envelope keys, closed-vocabulary
    text, finite numbers and booleans, a ``value`` list unless the envelope is a failure, and rows of retained
    fields holding safe values with a shape-valid summary.
    """
    if type(response) is not dict or not set(response) <= _ENVELOPE_KEYS:
        raise BoundaryError("anti-phish response shape")
    if admit_response(response, observed=True) not in (ADMITTED, FAILED):
        raise BoundaryError("anti-phish response admission")
    for key in _ENVELOPE_TEXT:
        if key in response and not _known_text(key, response[key]):
            raise BoundaryError("anti-phish response text")
    for key in _ENVELOPE_NUMBERS:
        if key in response and not _number(response[key]):
            raise BoundaryError("anti-phish response number")
    for key in (*_ENVELOPE_FLAGS, *_ENVELOPE_MARKERS):
        if key in response and type(response[key]) is not bool:
            raise BoundaryError("anti-phish response flag")
    if "value" not in response and response.get("error") is None and response.get("error_class") is None:
        raise BoundaryError("anti-phish response rows")  # a success always carries its rows
    if "value" in response:
        rows = response["value"]
        if type(rows) is not list:
            raise BoundaryError("anti-phish response rows")
        for row in rows:
            if (type(row) is not dict or not set(row) <= _ROW_KEYS or COVERAGE_KEY not in row
                    or not validate_coverage_shape(row[COVERAGE_KEY])
                    or not all(_safe_field(value) for key, value in row.items() if key != COVERAGE_KEY)):
                raise BoundaryError("anti-phish response row")
    return {**response, "command": command}


class _Unsafe(Exception):
    """Internal: a layout past the walking bounds. Caught inside this module; never carries text."""


class _Walk:
    __slots__ = ("nodes", "bearing")

    def __init__(self) -> None:
        self.nodes = 0
        # id -> (container, verdict); the container is held so its id cannot be reused while the walk lives.
        self.bearing: dict[int, tuple[Any, bool]] = {}

    def step(self, depth: int) -> None:
        self.nodes += 1
        if depth > MAX_DEPTH or self.nodes > MAX_NODES:
            raise _Unsafe


def _bears(value: Any, walk: _Walk, depth: int) -> bool:
    """Whether ``value`` is target-bearing anywhere below it: a key naming the field (or not text), a command reading
    anti-phish policies or naming the field, or text naming it, through any mix of mappings, lists and encoded text.

    Structure only, never a value match. Each container is judged once per walk and its verdict reused, so judging a
    parent and then each of its children stays linear; past the walking bounds ``_Unsafe`` is raised.
    """
    if isinstance(value, (Mapping, list)):
        seen = walk.bearing.get(id(value))
        if seen is not None and seen[0] is value:
            return seen[1]
    walk.step(depth)
    found = False
    if type(value) is str:
        return _mentions_target(value)
    if isinstance(value, Mapping):
        for key, item in value.items():
            if type(key) is not str or _key_names_target(key) or _mentions_target(key):
                found = True
            elif key == "command" and type(item) is str:
                walk.step(depth + 1)
                found = is_sensitive_command(item) or _mentions_target(item)
            else:
                found = _bears(item, walk, depth + 1)
            if found:
                break
    elif isinstance(value, list):
        for item in value:
            if _bears(item, walk, depth + 1):
                found = True
                break
    else:
        return False
    walk.bearing[id(value)] = (value, found)
    return found


def _reduce(mapping: Mapping[Any, Any], walk: _Walk, depth: int, *, strict_rows: bool) -> dict[str, Any]:
    """A target-bearing or unrecognised component: closed metadata (refusals kept as fixed tokens), the adapter's own
    command and its ``value`` rows; a component without ``value`` (a policy-like row) also keeps its safe retained
    fields. Every other key, and with it any value-bearing diagnostic or nested carrier, is discarded.

    ``strict_rows`` (an unrecognised operation) keeps only each row's safe retained fields; otherwise rows are
    walked as components of their own, so a row with no target stays as it was. A policy-like mapping, or one that
    named the field or held a summary, is marked ``not_collected``."""
    walk.step(depth)
    out: dict[str, Any] = _envelope_metadata(mapping)
    if "value" in mapping and admit_response(mapping, target_key=None) not in (ADMITTED, FAILED):
        # An affected operation envelope must be supported before fields can be removed from it. Row objects are
        # handled separately, so harmless unknown row fields still drop without changing their selected settings.
        out.update(error=PARSE_ERROR, error_class=PARSE_ERROR_CLASS)
        return out
    if _controlled_command(mapping.get("command")):
        out["command"] = mapping["command"]
    retained = {} if "value" in mapping else _retained(mapping)
    out.update(retained)
    rows = mapping.get("value")
    if type(rows) is list:
        out["value"] = [
            _reduce(row, walk, depth + 2, strict_rows=True) if strict_rows else _clean(row, walk, depth + 2)
            for row in rows if isinstance(row, Mapping)
        ]
    elif isinstance(rows, Mapping):
        out["value"] = (_reduce(rows, walk, depth + 1, strict_rows=True) if strict_rows
                        else _clean(rows, walk, depth + 1))
    if retained or any(key == COVERAGE_KEY or _key_names_target(key) for key in mapping):
        out[COVERAGE_KEY] = minimal_coverage("not_collected")
    return out


def _clean(value: Any, walk: _Walk, depth: int) -> Any:
    """A copy of an unrecognised value: a mapping with nothing target-bearing below it is kept, a target-bearing one
    (at any depth, through mappings, lists or encoded text) is reduced, a supplied summary is replaced by
    ``not_collected`` and text naming the field is dropped."""
    walk.step(depth)
    if isinstance(value, Mapping):
        if _bears(value, walk, depth):
            return _reduce(value, walk, depth, strict_rows=False)
        out: dict[Any, Any] = {}
        marked = False
        for key, item in value.items():
            if key == COVERAGE_KEY:
                marked = True
                continue
            out[key] = _clean(item, walk, depth + 1)
        if marked:
            out[COVERAGE_KEY] = minimal_coverage("not_collected")
        return out
    if isinstance(value, list):
        bearing = _bears(value, walk, depth)
        # Scalar text in an affected unsupported list can be a diagnostic for the target-bearing row beside it.
        # Keep independent record containers and numeric metadata; a non-bearing list keeps its original strings.
        return [_clean(item, walk, depth + 1) for item in value
                if not (type(item) is str and (bearing or _mentions_target(item)))]
    if type(value) is str and _mentions_target(value):
        return None
    return value


def _own_slot(name: Any) -> bool:
    """A collector-section key that belongs to the section itself, as in a flat or legacy layout where the section is
    also an envelope or a policy row: an envelope or diagnostic slot, a policy field, a supplied summary or a key
    naming the field. Every other key is one of the collector's operations or its scalar metadata."""
    return name in _COMPONENT_KEYS or name in _ROW_KEYS or _key_names_target(name)


_OPERATION_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*")


def _preserve_collector_health(original: Mapping[Any, Any], cleaned: dict[str, Any]) -> dict[str, Any]:
    """Keep the global refusal of list-valued or invalid-name pseudo-operations through reduction or omission.

    Projection ignores a failed unrelated named operation mapping, but a failing list or invalid operation name
    withholds the collector. Lift that meaning to a fixed failing list; if the key itself must disappear, lift it
    to fixed collector metadata instead. The generic scan includes target values, unlike actual policy admission.
    """
    for name, item in original.items():
        if type(name) is str and not isinstance(item, list) and _OPERATION_NAME.fullmatch(name):
            continue
        if subtree_healthy(item):
            continue
        failure = {"error": PARSE_ERROR, "error_class": PARSE_ERROR_CLASS}
        if type(name) is not str or _key_names_target(name) or _mentions_target(name):
            cleaned.update(failure)
        else:
            cleaned[name] = [failure]
    return cleaned


def _collector_section(section: Mapping[Any, Any]) -> dict[str, Any]:
    """A sample-root collector section, routed by its position in the sample and never by the types of its values.

    A section with nothing target-bearing below it is copied as it was. Otherwise its own slots (``_own_slot``) are
    reduced together as one component, exactly as a reduced envelope or row: closed metadata, refusal markers as fixed
    tokens, the adapter's own command, safe rows and policy fields, no diagnostic text. Every other key is an
    independent operation with its own walking budget, copied unless it bears the target (then reduced) or passes the
    bounds (then omitted), so one carrier never costs its siblings their evidence or health markers. Scalar metadata
    beside them keeps numbers, booleans and null; free text in a bearing section goes, as at the sample root. A key
    naming the field in another form is omitted. Own data past the bounds is omitted while its fixed collector
    refusal metadata survives.
    """
    try:
        bearing = _bears(section, _Walk(), 1)
    except Exception:  # noqa: BLE001 - past the bounds: route key by key, each operation with its own budget
        bearing = True
    if not bearing:
        try:
            return _preserve_collector_health(section, _clean(section, _Walk(), 1))
        except Exception:  # noqa: BLE001 - the copy passed the bounds: route key by key instead
            pass
    out: dict[str, Any] = {}
    own = {name: item for name, item in section.items() if _own_slot(name)}
    if own:
        # Fixed collector refusal metadata remains authoritative even if its accompanying data exceeds walk bounds.
        out.update(_envelope_metadata(own))
        try:
            out.update(_reduce(own, _Walk(), 1, strict_rows=False))
        except Exception:  # noqa: BLE001 - past the bounds or unexpected: omit, never copy and never raise text
            pass
    for name, item in section.items():
        if _own_slot(name) or type(name) is not str or _mentions_target(name):
            continue
        if isinstance(item, (Mapping, list)):
            try:
                if (isinstance(item, Mapping) and _bears(item, _Walk(), 2)
                        and admit_response(item, target_key=None) not in (ADMITTED, FAILED)):
                    out[name] = {**_envelope_metadata(item), "error": PARSE_ERROR, "error_class": PARSE_ERROR_CLASS}
                else:
                    out[name] = _clean(item, _Walk(), 2)
            except Exception:  # noqa: BLE001 - past the bounds or unexpected: omit, never copy and never raise text
                continue
        elif item is None or type(item) in (bool, int, float):
            out[name] = item
    return _preserve_collector_health(section, out)


@lru_cache(maxsize=1)
def _known_operations() -> frozenset[str]:
    """Operation names the exchange_policy collector writes; anything else in its section is an unsupported layout."""
    from .exchange_policy import ExchangePolicyCollector

    return frozenset(name for name, _command in ExchangePolicyCollector.command_collectors)


def _section(
    section: Any, sensitive_users: SensitiveUsers | None, binding: SensitiveUsersBinding | None,
) -> Any:
    """The exchange_policy section (sample) or payload (resume) after the boundary.

    The anti-phish operation is rebuilt as a replayed read; another known operation is walked; an unknown
    operation is an unsupported layout and is reduced. A key naming the field, a section-level scalar or an
    operation past the bounds is omitted. Each operation has its own walking budget.
    """
    if not isinstance(section, Mapping):
        return _clean(section, _Walk(), 1)
    known = _known_operations()
    # These are the collector's own health fields, not operation names. Preserve their refusal meaning through
    # fixed metadata before reducing operations, including mapping-valued errors that must stay truthy.
    out: dict[str, Any] = _envelope_metadata(section)
    metadata_keys = frozenset({*_ENVELOPE_TEXT, *_ENVELOPE_NUMBERS, *_ENVELOPE_FLAGS, *_ENVELOPE_MARKERS, "command"})
    for name, item in section.items():
        if (type(name) is not str or name in metadata_keys or name == COVERAGE_KEY
                or _key_names_target(name) or _mentions_target(name)):
            continue
        try:
            if name == OPERATION:
                out[name] = sanitise_response(item, sensitive_users, binding, observed=False)
            elif (name in known and isinstance(item, Mapping) and _bears(item, _Walk(), 2)
                  and admit_response(item, target_key=None) not in (ADMITTED, FAILED)):
                out[name] = {**_envelope_metadata(item), "error": PARSE_ERROR, "error_class": PARSE_ERROR_CLASS}
            elif name in known and isinstance(item, (Mapping, list)):
                out[name] = _clean(item, _Walk(), 2)
            elif isinstance(item, Mapping):
                out[name] = _reduce(item, _Walk(), 2, strict_rows=True)
            elif isinstance(item, list):
                walk = _Walk()
                out[name] = [_reduce(row, walk, 3, strict_rows=True) for row in item if isinstance(row, Mapping)]
        except Exception:  # noqa: BLE001 - past the bounds or unexpected: omit, never copy and never raise text
            if name == OPERATION:
                out[name] = _parse_error({})
    return _preserve_collector_health(section, out)


def strip_targets(value: Any) -> Any:
    """A copy of an unrecognised layout with every target-bearing component reduced (any key case or separator,
    encoded text, value-bearing diagnostics beside it); nothing is summarised. Past the bounds: an empty mapping."""
    try:
        return _clean(value, _Walk(), 0)
    except _Unsafe:
        return {}


def has_targets(value: Any) -> bool:
    """Whether ``value`` holds a key naming the target field, text naming it outside the adapter's own anti-phish
    command, or more structure than the boundary walks."""
    stack: list[tuple[Any, int, Any]] = [(value, 0, None)]
    nodes = 0
    while stack:
        item, depth, key = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            return True
        if isinstance(item, Mapping):
            for name, child in item.items():
                if type(name) is not str or _key_names_target(name) or _mentions_target(name):
                    return True
                stack.append((child, depth + 1, name))
        elif isinstance(item, list):
            stack.extend((child, depth + 1, key) for child in item)
        elif type(item) is str and _mentions_target(item) and not (key == "command" and _controlled_command(item)):
            return True
    return False


def sanitise_sample(
    sample: Mapping[str, Any], sensitive_users: SensitiveUsers | None, binding: SensitiveUsersBinding | None,
) -> dict[str, Any]:
    """An offline sample with the boundary applied, built before the replay copy and before any collector replays.

    ``exchange_policy.antiPhishPolicies`` rows are rebuilt as in a live read, under this run's binding (fresh literals
    are summarised; a supplied summary alone becomes ``not_collected``). Every other location, including flat,
    legacy, nested, error and encoded layouts, reduces each component that is target-bearing anywhere below it
    (a row, a nested object, a list or encoded text) to closed metadata, refusal markers as fixed tokens, the
    adapter's own command and its rows, so no ancestor keeps diagnostic text; unknown exchange_policy operations keep
    only closed metadata and safe retained fields. Every other top-level mapping except sample metadata is a collector
    section (``_collector_section``): its own envelope slots are reduced, while each operation beside them keeps its
    own budget and is kept as it was unless it bears the target, whatever scalar metadata sits beside it. A top-level
    key naming the field is omitted, and when anything in the sample bears the target the top level's own free text
    goes too. Sample metadata and a top-level list keep the component walk; one past the bounds is replaced by an
    empty mapping (an operation past them, inside a collector section, is omitted). The source mapping is not
    modified and the result shares no container with it.
    """
    try:
        top_bearing = _bears(sample, _Walk(), 0)
    except Exception:  # noqa: BLE001 - unexaminable: treat as bearing
        top_bearing = True
    out: dict[str, Any] = {}
    for key, value in sample.items():
        if type(key) is not str or key == COVERAGE_KEY or _key_names_target(key) or _mentions_target(key):
            continue
        try:
            if key == COLLECTOR:
                out[key] = _section(value, sensitive_users, binding)
            elif isinstance(value, Mapping) and key not in _SAMPLE_METADATA_KEYS:
                out[key] = _collector_section(value)
            elif isinstance(value, (Mapping, list)):
                out[key] = _clean(value, _Walk(), 1)
            elif type(value) is str:
                if not top_bearing and not _mentions_target(value):
                    out[key] = value
            else:
                out[key] = value
        except Exception:  # noqa: BLE001 - past the bounds or unexpected: no copy and no text
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

    Reusable only when the boundary would remove nothing (no target key, encoded target text, unknown operation or
    diagnostic beside them) and the SS 2.1 summaries can stand for this session: with a
    current binding, a healthy anti-phish read whose every row holds a known summary with this count and HMAC
    (compared in constant time); without one, no row claims membership. Otherwise the returned payload is a
    minimised in-memory copy whose anti-phish rows are ``not_collected`` and whose literals are gone; the stored
    raw file and its summaries are never rewritten or rebound.
    """
    try:
        envelope = payload.get(OPERATION)
        minimised = _section(payload, None, None)
        unchanged = all(name in minimised and minimised[name] == item
                        for name, item in payload.items() if name != OPERATION)
        if unchanged and not has_targets(envelope) and _reusable(envelope, sensitive_users, binding):
            return dict(payload), True
    except Exception:  # noqa: BLE001 - past the bounds or unexpected: nothing is carried
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
