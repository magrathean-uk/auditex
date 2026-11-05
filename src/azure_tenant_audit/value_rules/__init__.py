"""Deterministic SCuBA value rules in the engine package."""
from __future__ import annotations

from .catalogue import cells_for, row_for, rule_policies
from .record import as_pack_response
from .powerbi import AAD_34, aad_3_4, powerbi


def assess(policy_id: str, sections: dict):
    row = row_for(policy_id)
    if row is None:
        return None
    if row["kind"].startswith("powerbi."):
        return powerbi(policy_id, sections)
    if policy_id == AAD_34:
        return aad_3_4(policy_id, sections)
    raise ValueError("Value-rule kind is not implemented")


__all__ = ["assess", "as_pack_response", "cells_for", "rule_policies"]
