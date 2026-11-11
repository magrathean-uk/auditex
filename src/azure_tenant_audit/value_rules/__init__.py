"""Deterministic SCuBA value rules in the engine package.

Order for a policy with a row in ``configs/scuba-value-rules.json`` (plan 2.3, spec section 3): the closed gate, then
the rule's sections absent or marked (``section_not_collected``), then the kind, which always answers. Every answer is
checked against the shipped inventory before it leaves this package.
"""
from __future__ import annotations

import importlib
import pkgutil

from .catalogue import cells_for, row_for, rule_policies
from .gates import closed_gate
from .powerbi import aad_3_4, powerbi
from .record import _not_collected, as_pack_response, checked, rule_failure

_REGISTRY: dict | None = None


def _registry() -> dict:
    """Kinds from every module of this package that defines a module-level ``KINDS`` dict (name -> callable).

    A new rule module needs no edit here: it just defines ``KINDS``. A kind defined twice raises.
    """
    global _REGISTRY
    if _REGISTRY is None:
        merged: dict = {}
        for info in pkgutil.iter_modules(__path__):
            if info.name.startswith("_"):
                continue
            kinds = getattr(importlib.import_module(f"{__name__}.{info.name}"), "KINDS", None)
            if not isinstance(kinds, dict):
                continue
            for name, function in kinds.items():
                if name in merged:
                    raise ValueError("Value-rule kind is defined twice")
                merged[name] = function
        _REGISTRY = merged
    return _REGISTRY


def _kind(row):
    kind = row["kind"]
    if kind.startswith("powerbi."):
        return lambda policy_id, row, sections: powerbi(policy_id, sections)
    if kind == "aad_3_4":
        return lambda policy_id, row, sections: aad_3_4(policy_id, sections)
    registry = _registry()
    if kind in registry:
        return registry[kind]
    raise ValueError("Value-rule kind is not implemented")


def assess(policy_id: str, sections: dict):
    row = row_for(policy_id)
    if row is None:
        return None
    record = (closed_gate(policy_id, sections) or _not_collected(policy_id, sections, row["sections"])
              or _kind(row)(policy_id, row, sections))
    return checked(record)


__all__ = ["assess", "as_pack_response", "cells_for", "rule_failure", "rule_policies"]
