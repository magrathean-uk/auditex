"""Deterministic SCuBA value rules for Google Workspace (ScubaGoggles v1.1.0 at ``08a08ce1``; design M13).

Order for a policy with a row in ``configs/scuba-gws-value-rules.json`` or a fragment: the rule's sections absent
or marked (``section_not_collected``, skipped for an evidence-free kind), then the kind, which always answers. Every
answer is checked against the shipped GWS inventory before it leaves this package. This module defines no ``KINDS``,
so the M365 registry (``value_rules._registry``) skips the subpackage; the GWS registry below reads only its own
modules.
"""
from __future__ import annotations

import importlib
import pkgutil

from ..record import _not_collected, as_pack_response
from .catalogue import cells_for, is_evidence_free, policy_ids, row_for, rule_policies
from .record import checked_gws, rule_failure_gws

_REGISTRY: dict | None = None


def _registry() -> dict:
    """Kinds from every module of this subpackage that defines a module-level ``KINDS`` dict; a kind defined twice
    raises."""
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
                    raise ValueError("GWS value-rule kind is defined twice")
                merged[name] = function
        _REGISTRY = merged
    return _REGISTRY


def _kind(row: dict):
    registry = _registry()
    if row["kind"] in registry:
        return registry[row["kind"]]
    raise ValueError("GWS value-rule kind is not implemented")


def assess(policy_id: str, sections: dict):
    row = row_for(policy_id)
    if row is None:
        return None
    gate = None if is_evidence_free(row["kind"]) else _not_collected(policy_id, sections, row["sections"])
    return checked_gws(gate or _kind(row)(policy_id, row, sections))


__all__ = ["assess", "as_pack_response", "cells_for", "checked_gws", "policy_ids", "rule_failure_gws",
           "rule_policies"]
