"""Strict JSON parsing hooks: duplicate keys and NaN or Infinity constants are errors."""
from __future__ import annotations

from typing import Any


def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that rejects a repeated key in one JSON object."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> None:
    """``parse_constant`` hook that rejects ``NaN``, ``Infinity`` and ``-Infinity``."""
    raise ValueError(f"invalid JSON constant: {value}")
