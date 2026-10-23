"""Cyber Essentials requirement rows for ``baseline_alignment``.

The ``cyber_essentials`` framework key differs from the benchmark keys: a Cyber
Essentials assessment covers devices, networks and processes that a tenant audit
cannot see. The section therefore lists every requirement in
``configs/framework-catalog.json``, not only the ones a rule maps to, and the
catalog ``status`` of each requirement decides whether Auditex may report a
verdict at all:

* ``automated`` requirements take their verdict from the mapped rules (``pass``,
  ``fail``, ``accepted_risk`` or ``not_assessed``).
* ``partial`` requirements can ``fail`` or read ``accepted_risk`` on the evidence
  they have, but never ``pass``: rules that cover only part of a requirement
  finding no gap say nothing about the rest. A clean result is recorded as
  ``not_assessed`` with the reason ``partial_requirement_no_gap_found``, and the
  ``evidence`` counts show what was evaluated. A row whose deciding rules were not
  all evaluated is ``not_assessed`` with the reason ``rules_not_evaluated`` and the
  per-rule reasons in ``not_assessed_reasons``.
* A rule mapped with the confidence ``supporting`` is listed with its status but
  never decides the row: it is a signal the requirement does not itself set (an
  administrator count, a compliance state). A row mapped only to supporting rules
  reads ``not_assessed`` with the reason ``supporting_evidence_only``.
* ``manual``, ``ce_plus_assessor_test`` and ``provider_responsibility``
  requirements are always ``not_assessed``. Rules mapped to them are listed as
  supporting evidence and never produce a ``pass`` for the requirement. An
  unknown or missing catalog status is treated the same way (fail closed).

Auditex output is evidence for an assessor. It is not a Cyber Essentials
assessment or certificate.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Collection, Mapping
from typing import Any

CE_FRAMEWORK_KEY = "cyber_essentials"
REQUIREMENT_STATUSES = ("automated", "partial", "manual", "ce_plus_assessor_test", "provider_responsibility")
VERDICT_REQUIREMENT_STATUSES = frozenset({"automated", "partial"})
# A partial requirement can fail on the part it covers but a clean result is not a pass.
PARTIAL_REQUIREMENT_STATUS = "partial"
PARTIAL_NO_GAP_REASON = "partial_requirement_no_gap_found"
SUPPORTING_CONFIDENCE = "supporting"
MAPPING_CONFIDENCE_VALUES = ("full", "partial", SUPPORTING_CONFIDENCE)
# A mapping without a declared confidence is read as the weaker claim that can still decide a row.
DEFAULT_MAPPING_CONFIDENCE = "partial"
RULES_NOT_EVALUATED_REASON = "rules_not_evaluated"
SUPPORTING_ONLY_REASON = "supporting_evidence_only"
NOT_ASSESSED = "not_assessed"
_FINDING_ID_LIMIT = 20


def mapping_confidence(
    confidence: Mapping[str, Mapping[str, str]] | None, rule_id: str, requirement_id: str
) -> str:
    """Declared confidence of ``rule_id`` for ``requirement_id``, or the weaker default."""
    declared = (confidence or {}).get(rule_id, {}).get(requirement_id)
    return declared if declared in MAPPING_CONFIDENCE_VALUES else DEFAULT_MAPPING_CONFIDENCE


def _evidence_counts(evaluations: list[dict[str, Any]], open_finding_count: int) -> dict[str, int]:
    statuses = [str(item.get("status")) for item in evaluations]
    return {
        "rules_mapped": len(evaluations),
        "rules_evaluated": sum(1 for item in evaluations if item.get("evaluated")),
        "rules_passed": statuses.count("pass"),
        "rules_failed": statuses.count("fail"),
        "rules_accepted_risk": statuses.count("accepted_risk"),
        "rules_not_assessed": statuses.count(NOT_ASSESSED),
        "rules_supporting": sum(1 for item in evaluations if item.get("confidence") == SUPPORTING_CONFIDENCE),
        "open_findings": open_finding_count,
    }


def _requirement_row(
    requirement_id: str,
    spec: Mapping[str, Any],
    rule_ids: list[str],
    *,
    evaluate: Callable[[str], dict[str, Any]],
    open_by_rule: Mapping[str, list[str]],
    control_status: Callable[[list[str]], str],
    confidence: Mapping[str, Mapping[str, str]] | None,
) -> dict[str, Any]:
    requirement_status = str(spec.get("status") or "unknown")
    evaluations = []
    for rule_id in rule_ids:
        evaluation = dict(evaluate(rule_id))
        evaluation["confidence"] = mapping_confidence(confidence, rule_id, requirement_id)
        evaluations.append(evaluation)
    finding_ids = sorted({finding_id for rule_id in rule_ids for finding_id in open_by_rule.get(rule_id, [])})
    reason: str | None = None
    # A supporting rule is shown but never decides the row.
    deciding = [item for item in evaluations if item["confidence"] != SUPPORTING_CONFIDENCE]
    not_assessed_reasons: list[str] = []
    if requirement_status in VERDICT_REQUIREMENT_STATUSES:
        status = control_status([str(item["status"]) for item in deciding])
        if not rule_ids:
            reason = "no_mapped_rules"
        elif not deciding:
            reason = SUPPORTING_ONLY_REASON
        elif status == "pass" and requirement_status == PARTIAL_REQUIREMENT_STATUS:
            status = NOT_ASSESSED
            reason = PARTIAL_NO_GAP_REASON
        elif status == NOT_ASSESSED:
            reason = RULES_NOT_EVALUATED_REASON
            not_assessed_reasons = sorted(
                {str(item["reason"]) for item in deciding if not item.get("evaluated") and item.get("reason")}
            )
    else:
        # No verdict is allowed here whatever the mapped rules say.
        status = NOT_ASSESSED
        reason = f"requirement_status:{requirement_status}"
    row: dict[str, Any] = {
        "control_id": requirement_id,
        "title": spec.get("title"),
        "theme": spec.get("theme"),
        "requirement_status": requirement_status,
        "status": status,
        "citation": spec.get("citation"),
        "evidence_limits": spec.get("evidence_limits"),
        "rule_ids": rule_ids,
        # A list, not a mapping: see the note in baselines.build_baseline_alignment.
        "rule_statuses": evaluations,
        "evidence": _evidence_counts(evaluations, len(finding_ids)),
        "open_finding_count": len(finding_ids),
        "finding_ids": finding_ids[:_FINDING_ID_LIMIT],
    }
    if spec.get("ce_plus_test"):
        row["ce_plus_test"] = spec["ce_plus_test"]
    if reason:
        row["reason"] = reason
    if not_assessed_reasons:
        row["not_assessed_reasons"] = not_assessed_reasons
    if status == "fail":
        # A failure rests on full confidence only when a failing rule tests the condition the requirement names.
        failing = [item for item in deciding if item["status"] == "fail"]
        row["confidence"] = "full" if any(item["confidence"] == "full" for item in failing) else "partial"
    return row


def build_cyber_essentials_section(
    entry: Mapping[str, Any],
    rules_by_requirement: Mapping[str, Collection[str]],
    *,
    evaluate: Callable[[str], dict[str, Any]],
    open_by_rule: Mapping[str, list[str]],
    control_status: Callable[[list[str]], str],
    status_order: tuple[str, ...],
    confidence: Mapping[str, Mapping[str, str]] | None = None,
) -> dict[str, Any]:
    """The ``cyber_essentials`` block of ``baseline_alignment.frameworks``.

    ``entry`` is the framework catalog entry, ``rules_by_requirement`` maps a
    requirement id to the rule ids that touch it, and ``evaluate`` returns the
    status of one rule (see ``baselines._rule_evaluation``). Every catalogued
    requirement gets a row, in catalog order. Requirement ids that a mapping or
    finding names but the catalog does not list are reported in
    ``uncatalogued_requirement_ids`` and never silently dropped.
    """
    catalog = entry.get("controls")
    catalog = catalog if isinstance(catalog, Mapping) else {}
    rows = []
    for requirement_id, spec in catalog.items():
        rows.append(
            _requirement_row(
                str(requirement_id),
                spec if isinstance(spec, Mapping) else {},
                sorted(rules_by_requirement.get(str(requirement_id), ())),
                evaluate=evaluate,
                open_by_rule=open_by_rule,
                control_status=control_status,
                confidence=confidence,
            )
        )
    status_counts: dict[str, int] = defaultdict(int)
    requirement_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        status_counts[row["status"]] += 1
        requirement_counts[row["requirement_status"]] += 1
    known = (*REQUIREMENT_STATUSES, *sorted(set(requirement_counts) - set(REQUIREMENT_STATUSES)))
    return {
        "title": entry.get("title"),
        "version": entry.get("version"),
        "published": entry.get("published"),
        "effective_date": entry.get("effective_date"),
        "verified_on": entry.get("verified_on"),
        "document_title": entry.get("document_title"),
        "document_url": entry.get("document_url"),
        "disclaimer": entry.get("disclaimer"),
        "status_counts": {status: status_counts.get(status, 0) for status in status_order},
        "requirement_status_counts": {status: requirement_counts.get(status, 0) for status in known},
        "uncatalogued_requirement_ids": sorted(set(map(str, rules_by_requirement)) - set(map(str, catalog))),
        "controls": rows,
    }
