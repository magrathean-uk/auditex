"""B1+B2: regression guard for finding-templates and control-mappings coverage.

Every ``rule_id`` emitted by ``src/azure_tenant_audit/findings.py`` must have:

1. A template entry in ``configs/finding-templates.json`` (description, impact,
   remediation, control_ids).
2. A control-mapping entry in ``configs/control-mappings.json`` that meets the
   coverage floor: at least one of ``nist_800_53`` or ``iso_27001``.
   Benchmark keys (``cis_m365_v7``, ``cisa_scuba``, ``ms_secure_score``,
   ``ms_zero_trust``, ``mcsb``) are only added where a verified control exists;
   tests/test_framework_baselines.py checks those against
   configs/framework-catalog.json.

These tests fail loudly the moment a new rule_id is added to findings.py
without the corresponding catalog entries — preventing the silent drift that
breaks SARIF/OSCAL exporters and downstream framework reporting.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parent.parent
_FINDINGS_SRC = (_REPO / "src" / "azure_tenant_audit" / "findings.py").read_text(
    encoding="utf-8"
)
_TEMPLATES = json.loads(
    (_REPO / "configs" / "finding-templates.json").read_text(encoding="utf-8")
)
_MAPPINGS = json.loads(
    (_REPO / "configs" / "control-mappings.json").read_text(encoding="utf-8")
)
_EMITTED_RULE_IDS = sorted(
    set(re.findall(r'"rule_id": "([a-z0-9_]+\.[a-z0-9_]+)"', _FINDINGS_SRC))
)


def test_at_least_one_rule_id_is_emitted() -> None:
    """Sanity guard against a regex that silently matches zero."""
    assert len(_EMITTED_RULE_IDS) > 20


@pytest.mark.parametrize("rule_id", _EMITTED_RULE_IDS)
def test_emitted_rule_id_has_finding_template(rule_id: str) -> None:
    template = _TEMPLATES.get(rule_id)
    assert template is not None, (
        f"rule_id={rule_id} is emitted by findings.py but has no template entry "
        f"in configs/finding-templates.json. Add description / impact / "
        f"remediation / control_ids."
    )
    for required in ("risk_rating", "description", "impact", "remediation", "control_ids"):
        assert template.get(required), (
            f"template for {rule_id} is missing required field {required!r}"
        )


@pytest.mark.parametrize("rule_id", _EMITTED_RULE_IDS)
def test_emitted_rule_id_has_control_mapping(rule_id: str) -> None:
    mapping = _MAPPINGS.get(rule_id)
    assert mapping is not None, (
        f"rule_id={rule_id} is emitted by findings.py but has no entry in "
        f"configs/control-mappings.json. Add at least one of nist_800_53 / "
        f"iso_27001, plus verified benchmark keys where they exist."
    )


@pytest.mark.parametrize("rule_id", _EMITTED_RULE_IDS)
def test_emitted_rule_id_meets_framework_floor(rule_id: str) -> None:
    """Floor: every rule must map to at least one of NIST 800-53 or ISO 27001
    (the two most-widely-cited international frameworks). Benchmark keys are
    optional and verified separately; the deprecated ``cis_m365_v3`` key must
    not be emitted by shipped mappings."""
    mapping = _MAPPINGS.get(rule_id) or {}
    nist = mapping.get("nist_800_53") or []
    iso = mapping.get("iso_27001") or []
    assert "cis_m365_v3" not in mapping, (
        f"{rule_id}: cis_m365_v3 is deprecated; map verified CIS v7 ids under cis_m365_v7"
    )
    assert nist or iso, (
        f"{rule_id}: must map to nist_800_53 OR iso_27001 (got neither)"
    )


# ``collector.issue.*`` is a separate namespace used by collector-blocker
# diagnostics (permission / service / collector errors) rather than by rules
# emitted through the normal _finalize_finding path. Templates and mappings
# for that namespace are referenced from findings.py via the diagnostic
# pipeline; exclude them from the orphan check.
_DIAGNOSTIC_NAMESPACES = ("collector.issue.",)
# Metadata keys (single-leading-underscore or $-prefixed) carry rationale /
# policy text rather than per-rule mappings — see the ``_documentation``
# block at the top of configs/control-mappings.json for the ATT&CK taxonomy
# rationale. The runtime loader (_load_rule_registry in findings.py) skips
# non-dict values, so these never reach the rule pipeline; the orphan check
# needs the same exclusion.
_METADATA_PREFIXES = ("_", "$")


def _is_orphan(rule_id: str) -> bool:
    if any(rule_id.startswith(ns) for ns in _DIAGNOSTIC_NAMESPACES):
        return False
    if any(rule_id.startswith(prefix) for prefix in _METADATA_PREFIXES):
        return False
    return rule_id not in _EMITTED_RULE_IDS


def test_no_orphan_templates() -> None:
    """Templates that don't correspond to any emitted rule_id are stale —
    most likely a rename left them behind. Catch the drift early."""
    orphans = sorted(rule_id for rule_id in _TEMPLATES if _is_orphan(rule_id))
    assert not orphans, (
        f"orphan templates in configs/finding-templates.json: {orphans}. "
        f"Either remove them or wire findings.py to emit the rule_id."
    )


def test_no_orphan_control_mappings() -> None:
    orphans = sorted(rule_id for rule_id in _MAPPINGS if _is_orphan(rule_id))
    assert not orphans, (
        f"orphan control-mappings in configs/control-mappings.json: {orphans}."
    )
