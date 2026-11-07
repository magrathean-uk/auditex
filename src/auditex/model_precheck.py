"""Rule pre-check records and offline scoring of frozen oracle cases."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json
import logging
from typing import Any

from azure_tenant_audit.explainer import explain as render_explanation
from azure_tenant_audit.model_assessment import validate_explainer, value_rule_verdict
from azure_tenant_audit.output_redaction import PROFILE_EXPLAINER, RedactionContext, redact_output
from azure_tenant_audit.scuba_precheck import optional_collection_entry, precheck_policy, precheck_response

from .model_eval import _evaluate, _invalid_constant, _load_cases, _load_responses, _pairs, _score

LOG = logging.getLogger(__name__)


def precheck_case(case: dict[str, Any], *, skip_absent_sections: bool = False,
                  named_limitations: bool = True, absent_fields: bool = False,
                  empty_lists: bool = False, value_rules: bool = False,
                  rule_projection: dict[str, Any] | None = None, explain: bool = False,
                  redaction_context: RedactionContext | None = None) -> dict[str, Any] | None:
    sections = [item["section"] for item in case["evidence"][1:]]
    projection = {item["section"]: item["observed"] for item in case["evidence"][1:]}
    detail = None
    optional = optional_collection_entry()
    optional_policy = optional["policies"].get(case["policy_id"])
    if optional_policy and rule_projection is not None:
        missing = [s for s in sections if s in optional_policy["sections"]
                   and isinstance(rule_projection.get(s), dict)
                   and rule_projection[s].get("collection_status") == "not_collected"
                   and rule_projection[s].get("reason") == optional["reason_code"]]
        if missing:
            detail = {"class": "absent_section", "rule_id": "required_sections_present",
                      "section": missing, "field": None, "value": None,
                      "reason_code": optional["reason_code"], "reason_text": optional["reason_text"]}
    row = None
    if value_rules:
        from azure_tenant_audit.value_rules.catalogue import row_for
        row = row_for(case["policy_id"])
    if row is not None and detail is None:
        # A value-rule policy: the rule view when serving supplies one, else the case evidence.
        rule_input, rule_sections = ((rule_projection, list(row["sections"])) if rule_projection is not None
                                     else (projection, sections))
        try:
            candidate = precheck_policy(case["policy_id"], rule_input, rule_sections,
                                        skip_absent_sections=skip_absent_sections, value_rules=True,
                                        absent_fields=absent_fields, empty_lists=empty_lists)
        except MemoryError:
            raise
        except Exception as exc:
            # Log the rule id and the exception class name only: the message and repr can hold tenant evidence.
            LOG.warning("Value rule %s failed (%s); the row is answered not assessed",
                        row["rule_id"], type(exc).__name__)
            # The fault is ours, not the evidence's (main, 5 Nov 07:12 GMT): the catalogued rule_evaluation_failed
            # answer, a constant text and the report_product_fault recommendation. Never render the exception.
            from azure_tenant_audit.value_rules import rule_failure
            failed = rule_failure(case["policy_id"])
            candidate = {"class": "value_rule", "rule_id": row["rule_id"], "section": failed["cited_sections"],
                         "field": None, "value": None, "cell": failed["cell"],
                         "reason_code": failed["reason_code"], "reason_text": failed["reason_text"]}
        if rule_projection is None or candidate is not None and candidate["class"] in {"value_rule", "closed_gate"}:
            detail = candidate
    if detail is None and (row is None or rule_projection is not None):
        detail = precheck_policy(case["policy_id"], projection, sections,
                                 skip_absent_sections=skip_absent_sections, absent_fields=absent_fields,
                                 empty_lists=empty_lists, value_rules=False)
    if detail is None:
        return None
    record = {**precheck_response(detail, case["evidence"][0]["observed"], sections,
                                  named_limitations=named_limitations),
              "policy_id": case["policy_id"], "rule_precheck": detail,
              "validation_status": "valid", "reason": "rule_precheck", "latency_ms": 0,
              "attempts": 0, "prompt_sha256": None, "response_sha256": None,
              "thinking_disabled": False, "thinking_stripped": False}
    if explain and detail["class"] == "value_rule":
        try:
            # The case must carry the complete fixed read set, even if this cell cites only a subset.
            if row is None or not set(row["sections"]) <= set(sections):
                return record
            # Only the public rule answer and the case's redacted model-view evidence cross this boundary.
            public = {"policy_id": record["policy_id"], "verdict": value_rule_verdict(record),
                      "cell": detail["cell"], "reason_code": detail["reason_code"],
                      "reason_text": detail["reason_text"], "cited_sections": list(detail["section"])}
            explanation = render_explanation(public, deepcopy(projection), list(sections))
            safe = redact_output(explanation, profile=PROFILE_EXPLAINER, context=redaction_context)
            validate_explainer(record, safe)
            record["explainer"] = safe
        except MemoryError:
            raise
        except Exception as exc:
            LOG.debug("Explainer %s failed (%s)", case["policy_id"], type(exc).__name__)
    return record


def evaluate_precheck(cases_path: str, responses_path: str | None = None, *,
                      absent_fields: bool = False, empty_lists: bool = False) -> dict[str, Any]:
    """Use the checkpoint scorer's loaders and strict mechanical comparison.

    Gold labels and provenance never enter pre-check decisions. Missing/invalid
    model answers fail their remaining cases; all supplied models are separate.
    ``absent_fields`` and ``empty_lists`` score the field-level and empty-list classes as serving emits them (off here
    by default for comparability).
    """
    cases = _load_cases(cases_path)
    classes = {name: {"rule_answered": 0, "correct": 0} for name in ("closed_gate", "absent_section", "absent_field",
                                                                             "empty_required_list")}
    left = Counter()
    details = Counter()
    outcomes = {}
    answered = {}
    for row in cases:
        outcome = row["provenance"].get("oracle_outcome", "unspecified")
        outcome_count = outcomes.setdefault(outcome, {"rows": 0, "rule_answered": 0, "correct": 0, "left_to_model": 0})
        outcome_count["rows"] += 1
        case = json.loads(next(m["content"] for m in row["messages"] if m["role"] == "user"),
                          object_pairs_hook=_pairs, parse_constant=_invalid_constant)
        record = precheck_case(case, named_limitations=False, absent_fields=absent_fields, empty_lists=empty_lists)
        if record is None:
            left[outcome] += 1
            outcome_count["left_to_model"] += 1
            continue
        response = {key: record[key] for key in ("claims", "limitations", "recommendations")}
        passed = not _score(row, response)
        answered[row["id"]] = passed
        outcome_count["rule_answered"] += 1
        outcome_count["correct"] += passed
        cls = classes[record["rule_precheck"]["class"]]
        cls["rule_answered"] += 1
        cls["correct"] += passed
        if record["rule_precheck"]["class"] == "absent_section":
            details["missing_gate_input" if record["rule_precheck"]["field"] else "missing_section_or_marker"] += 1
    result = {"case_count": len(cases), "classes": classes, "absent_section_details": dict(details),
              "outcome_classes": dict(sorted(outcomes.items())),
              "rule_answered": len(answered), "rule_correct": sum(answered.values()),
              "left_to_model": len(cases) - len(answered), "left_to_model_by_outcome": dict(sorted(left.items())),
              "absent_fields": absent_fields, "empty_lists": empty_lists,
              "scoring": "Strict pack claims, typed values, evidence sets and limitation/recommendation IDs; named serving limitations excluded.",
              "product_scores": []}
    if responses_path is not None:
        records, invalid, inputs = _load_responses([responses_path])
        evaluation = _evaluate(cases, records, invalid, inputs)
        result["invalid_records"] = len(invalid)
        for model in evaluation["model_scores"]:
            rows = [row for row in evaluation["results"] if row["model_id"] == model["model_id"]
                    and row["case_id"] not in answered]
            model_correct = sum(row["mechanical_pass"] is True for row in rows)
            result["product_scores"].append({"model_id": model["model_id"],
                "correct": sum(answered.values()) + model_correct, "out_of": len(cases),
                "model_correct_on_remaining": model_correct,
                "missing_model_on_remaining": sum(row["model_id"] == model["model_id"] and
                    row["case_id"] not in answered for row in evaluation["missing_responses"])})
    return result
