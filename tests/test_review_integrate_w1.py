"""Integrate wave 1: cross-lane changes and review blockers (I1-I12)."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIGS = ROOT / "configs"


def _load(name: str) -> dict:
    return json.loads((CONFIGS / name).read_text(encoding="utf-8"))


def test_i4_finding_templates_cite_only_current_scuba_policy_ids() -> None:
    """R043: a template's references and text must cite the SCuBA version the mappings use."""
    policies = set(_load("scuba-policy-sections.json")["policies"])
    text = (CONFIGS / "finding-templates.json").read_text(encoding="utf-8")
    cited = set(re.findall(r"MS\.[A-Z]+\.\d+\.\d+v\d+", text))
    assert sorted(cited - policies) == []


def test_i6_rule_inventory_rates_expired_app_credentials_low() -> None:
    """R050: the inventory must advertise the severity the expired-credential findings carry."""
    from auditex.rules import list_rule_inventory

    ratings = {row["name"]: row.get("risk_rating") for row in list_rule_inventory()}
    assert ratings["app_credentials.secret_expired"] == "low"
    assert ratings["app_credentials.certificate_expired"] == "low"
