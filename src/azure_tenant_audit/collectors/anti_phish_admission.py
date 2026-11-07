"""Typed inline admission of an original operation response before minimisation (SS 2.1).

The SS 2.1 boundary rebuilds every anti-phish policy row from its retained fields plus a fresh
``TargetedUsersCoverage`` summary, and keeps only closed envelope metadata. That rebuild must not turn evidence the
projection would refuse into a supported success. This module decides, on the ORIGINAL response and before any
envelope metadata or row field is removed or any known summary can be generated, whether the response is a
supported inline success.

``admit_response`` returns one fixed code:

- ``ADMITTED``: a closed, exactly typed inline success. Every envelope key is known and of its supported type,
  ``value`` is a list of row mappings, ``item_count`` (if present) is an exact ``int`` equal to the inline row count,
  ``sample_truncated`` (if present) is exactly ``False``, there is no ``chunk_files`` or ``chunk_count``, diagnostic
  text slots hold only text or null, and no row
  carries a health marker the projection refuses, at any depth outside the row's actual target value.
- ``FAILED``: an explicit failure envelope (a present ``error`` or ``error_class``). The boundary keeps its existing
  fixed failure handling; this module never upgrades or reinterprets it.
- ``REFUSED``: anything else. The boundary must not produce a success or a known summary from it.

Row health follows the projection's recursive refusal semantics (``_healthy`` with ``metadata=False`` and the row
checks of ``_fields``): a truthy ``error``, ``error_class``, ``resolver_error``, ``collection_truncated``,
``bounded_sample``, ``@odata.nextLink``, ``truncation_reason``, ``incomplete`` or ``partial``; a present ``complete``
that is not exactly ``True``; a present ``read_state`` or ``collection_status`` other than ``"collected"``. A row's
``status`` is record data (a role schedule's ``Provisioned``), never collection health, and unknown row fields are
allowed (the boundary discards them later). The value of the row's exact top-level ``TargetedUsersToProtect`` key is
not walked: a malformed target entry only makes that policy's coverage unusable, so the policy's other settings stay
usable. Every other key, including case or separator variants of that name and the same name below the top level, is
walked like any other field.

``scan_admitted`` is the scan/count/chunk part alone, for any operation envelope the boundary reduces.

Pure and data-free: both functions return only fixed constants, never mutate, retain, log or echo their input, never
call into a non-JSON object, and never raise. Walks are iterative and linear, bounded by ``MAX_DEPTH`` container levels
and ``MAX_NODES`` walked values; past either bound the response is refused. Nothing from ``auditex`` or from the
boundary helper is imported, so the helper can import this module without a cycle.
"""
from __future__ import annotations

import math

ADMITTED = "admitted"
FAILED = "failed"
REFUSED = "refused"
CODES = frozenset({ADMITTED, FAILED, REFUSED})

TARGET_KEY = "TargetedUsersToProtect"
# Container levels counted from the envelope (1): the ``value`` list is 2, a row 3. Matches the projection's bound.
MAX_DEPTH = 64
# Values walked across all rows; far above any real anti-phish read, which is a few policies of a few fields.
MAX_NODES = 1_000_000
_ROW_DEPTH = 3

_HEALTHY_STATUS = frozenset({"ok", "success", "collected", "complete"})
_COLLECTED = "collected"
_ROW_TRUTHY = ("error", "error_class", "resolver_error", "collection_truncated", "bounded_sample", "@odata.nextLink",
               "truncation_reason", "incomplete", "partial")
_ROW_STATE = ("read_state", "collection_status")
_CHUNK_KEYS = ("chunk_files", "chunk_count")
# Diagnostic text slots adapters and older samples write beside a success. Plain text carries no health meaning to the
# projection and the boundary never copies it, so text or null is admitted; any container (which could hide a marker)
# is refused. Other diagnostic carriers (details, exception, traceback, warnings) are not admitted on a success.
DIAGNOSTIC_TEXT = ("message", "stdout", "stderr", "stdout_sample", "stderr_sample")


def _none(value: object) -> bool:
    return value is None


def _false(value: object) -> bool:
    return value is False


def _false_or_none(value: object) -> bool:
    return value is None or value is False


def _true(value: object) -> bool:
    return value is True


def _boolean(value: object) -> bool:
    return value is True or value is False


def _text(value: object) -> bool:
    return type(value) is str


def _optional_text(value: object) -> bool:
    return value is None or type(value) is str


def _status(value: object) -> bool:
    # ``complete`` stays admitted because the boundary keeps it verbatim and the projection's own operation check
    # still refuses it after minimisation; every other value has no supported success meaning.
    return type(value) is str and value in _HEALTHY_STATUS


def _collected(value: object) -> bool:
    return type(value) is str and value == _COLLECTED


def _reason(value: object) -> bool:
    return value is None or (type(value) is str and value == "offline_bundle")


def _zero(value: object) -> bool:
    return type(value) is int and value == 0


def _count(value: object) -> bool:
    return type(value) is int and value >= 0


def _positive(value: object) -> bool:
    return type(value) is int and value > 0


def _duration(value: object) -> bool:
    if type(value) is int:
        return value >= 0
    return type(value) is float and math.isfinite(value) and value >= 0


# The closed success envelope: key -> exact supported type. ``value`` and ``item_count`` are checked against the rows.
_SUCCESS_TYPES = {
    "command": _text,
    "status": _status,
    "collection_status": _collected,
    "read_state": _collected,
    "complete": _true,
    "error": _none,
    "error_class": _none,
    "reason": _reason,
    "state": _none,
    "truncation_reason": _none,
    "resolver_error": _none,
    "@odata.nextLink": _none,
    "collection_truncated": _false_or_none,
    "bounded_sample": _false_or_none,
    "incomplete": _false_or_none,
    "partial": _false_or_none,
    "collection_limit_reached": _false_or_none,
    "sample_truncated": _false,
    "licence_inferred": _boolean,
    "return_code": _zero,
    "duration_ms": _duration,
    "stdout_bytes": _count,
    "stderr_bytes": _count,
    "result_limit": _positive,
    **{key: _optional_text for key in DIAGNOSTIC_TEXT},
}
SUCCESS_KEYS = frozenset({"value", "item_count", *_SUCCESS_TYPES})


def _present(value: object) -> bool:
    """JSON truthiness without calling into the value; anything that is not a JSON value counts as present."""
    if value is None or value is False:
        return False
    if value is True:
        return True
    kind = type(value)
    if kind is int:
        return value != 0
    if kind is float:
        return not value == 0.0
    if kind is str or kind is list or kind is dict:
        return len(value) > 0
    return True


def _scalar(value: object) -> bool:
    if value is None or value is True or value is False:
        return True
    kind = type(value)
    if kind is str or kind is int:
        return True
    return kind is float and math.isfinite(value)


def _mapping_healthy(mapping: dict) -> bool:
    for key in _ROW_TRUTHY:
        if key in mapping and _present(mapping[key]):
            return False
    if "complete" in mapping and mapping["complete"] is not True:
        return False
    for key in _ROW_STATE:
        if key in mapping:
            value = mapping[key]
            if type(value) is not str or value != _COLLECTED:
                return False
    return True


def _rows_healthy(rows: list, target_key: str | None) -> bool:
    """One iterative pass over every row; the exact top-level target value of each row is never walked."""
    nodes = len(rows)
    if nodes > MAX_NODES:
        return False
    stack: list[tuple[object, int, bool]] = []
    for row in rows:
        if type(row) is not dict:
            return False
        stack.append((row, _ROW_DEPTH, True))
    while stack:
        value, depth, top = stack.pop()
        kind = type(value)
        if kind is dict:
            if any(type(key) is not str for key in value):
                return False  # validate keys before string lookups could invoke a non-JSON key's equality
            if depth > MAX_DEPTH or not _mapping_healthy(value):
                return False
            nodes += len(value)
            if nodes > MAX_NODES:
                return False
            for key, child in value.items():
                if type(key) is not str:
                    return False
                if top and target_key is not None and key == target_key:
                    continue
                stack.append((child, depth + 1, False))
        elif kind is list:
            if depth > MAX_DEPTH:
                return False
            nodes += len(value)
            if nodes > MAX_NODES:
                return False
            for child in value:
                stack.append((child, depth + 1, False))
        elif not _scalar(value):
            return False
    return True


def _admit(response: object, target_key: str | None, observed: bool) -> str:
    if (type(response) is not dict or type(observed) is not bool
            or target_key is not None and type(target_key) is not str):
        return REFUSED
    if any(type(key) is not str for key in response):
        return REFUSED
    if _present(response.get("error")) or _present(response.get("error_class")):
        return FAILED
    for key in response:
        if key not in SUCCESS_KEYS:
            return REFUSED  # includes chunk_files, chunk_count and every unknown envelope key
    for key, check in _SUCCESS_TYPES.items():
        if key in response and not check(response[key]):
            return REFUSED
    if "value" not in response:
        return REFUSED
    rows = response["value"]
    if type(rows) is not list:
        return REFUSED
    if "item_count" in response:
        count = response["item_count"]
        if type(count) is not int or count != len(rows):
            return REFUSED
    if "result_limit" in response and len(rows) >= response["result_limit"]:
        return REFUSED  # a read that reached its limit may be cut
    if not rows and not observed and not any(key in response for key in ("status", "complete", "collection_status")):
        return REFUSED  # replay needs a health statement; a fresh successful adapter read is observed directly
    return ADMITTED if _rows_healthy(rows, target_key) else REFUSED


def admit_response(response: object, *, target_key: str | None = TARGET_KEY, observed: bool = False) -> str:
    """``ADMITTED``, ``FAILED`` or ``REFUSED`` for an original operation response; see the module docstring.

    ``target_key`` names the one top-level row field whose value is not walked; ``None`` walks every field.
    ``observed=True`` is reserved for a successful live adapter read: an explicit empty list is a valid read even
    without replay health metadata. It never bypasses a refusal marker, unsupported type, count or missing value.
    """
    try:
        return _admit(response, target_key, observed)
    except Exception:  # noqa: BLE001 - unexpected input refuses; no text, value or reference leaves this module
        return REFUSED


def is_admitted(response: object, *, target_key: str | None = TARGET_KEY, observed: bool = False) -> bool:
    """Whether ``admit_response`` admits ``response`` as a supported inline success."""
    return admit_response(response, target_key=target_key, observed=observed) is ADMITTED


def subtree_healthy(value: object) -> bool:
    """Whether a generic pseudo-operation keeps the projection's recursive health meaning.

    Unlike a recognised anti-phish policy row, this has no exempt target-value slot. Only the root mapping's
    ``status`` is envelope metadata; statuses below it are record data. Unsupported types, keys or walk bounds
    refuse without calling into an input object or returning any of its text.
    """
    try:
        nodes = 1
        stack: list[tuple[object, int, bool]] = [(value, 1, True)]
        while stack:
            item, depth, metadata = stack.pop()
            kind = type(item)
            if kind is dict:
                if (depth > MAX_DEPTH or any(type(key) is not str for key in item)
                        or not _mapping_healthy(item)):
                    return False
                if metadata and "status" in item and not _status(item["status"]):
                    return False
                nodes += len(item)
                if nodes > MAX_NODES:
                    return False
                stack.extend((child, depth + 1, False) for child in item.values())
            elif kind is list:
                if depth > MAX_DEPTH:
                    return False
                nodes += len(item)
                if nodes > MAX_NODES:
                    return False
                stack.extend((child, depth + 1, False) for child in item)
            elif not _scalar(item):
                return False
        return True
    except Exception:  # noqa: BLE001 - generic admission never exposes input text or invokes an unsupported value
        return False


def scan_admitted(envelope: object) -> bool:
    """Whether an operation envelope's scan/count/chunk metadata is supported inline.

    False for a non-mapping, any ``chunk_files`` or ``chunk_count`` (never an inline fallback), a present
    ``sample_truncated`` that is not exactly ``False``, an ``item_count`` or ``sample_truncated`` without an inline
    ``value`` list, or an ``item_count`` that is not an exact ``int`` equal to that list's length. Health markers and
    other keys are not judged here.
    """
    try:
        if type(envelope) is not dict or any(type(key) is not str for key in envelope):
            return False
        if any(key in envelope for key in _CHUNK_KEYS):
            return False
        if "sample_truncated" in envelope and envelope["sample_truncated"] is not False:
            return False
        if "item_count" not in envelope and "sample_truncated" not in envelope:
            return True
        rows = envelope.get("value")
        if type(rows) is not list:
            return False  # a scan or count key with no inline rows, as the projection refuses
        if "item_count" in envelope:
            count = envelope["item_count"]
            return type(count) is int and count == len(rows)
        return True
    except Exception:  # noqa: BLE001 - unexpected input refuses without text
        return False
