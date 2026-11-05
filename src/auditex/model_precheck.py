"""Rule pre-check records and offline scoring of frozen oracle cases."""
from __future__ import annotations

from collections import Counter
import json
import logging
from typing import Any

from azure_tenant_audit.scuba_precheck import precheck_policy, precheck_response

from .model_eval import _evaluate, _invalid_constant, _load_cases, _load_responses, _pairs, _score

LOG = logging.getLogger(__name__)


def precheck_case(case: dict[str, Any], *, skip_absent_sections: bool = False,
                  named_limitations: bool = True, absent_fields: bool = False,
                  empty_lists: bool = False, value_rules: bool = False,
                  rule_projection: dict[str, Any] | None = None) -> dict[str, Any] | None:
    sections = [item["section"] for item in case["evidence"][1:]]
    projection = {item["section"]: item["observed"] for item in case["evidence"][1:]}
    detail = None
    if value_rules and rule_projection is not None:
        from azure_tenant_audit.value_rules.catalogue import row_for
        row = row_for(case["policy_id"])
        if row is not None:
            rule_sections = list(row["sections"])
            try:
                candidate = precheck_policy(case["policy_id"], rule_projection, rule_sections,
                                            skip_absent_sections=skip_absent_sections, value_rules=True)
            except MemoryError:
                raise
            except Exception as exc:
                # Log the rule id and the exception class name only: the message and repr can hold tenant evidence.
                LOG.warning("Value rule %s failed (%s); the row is answered not assessed",
                            row["rule_id"], type(exc).__name__)
                # OPEN SPEC QUESTION: "the rule failed on collected evidence" has no cell in the value-rule spec.
                # section_not_collected is a stand-in (the evidence was collected); the review proposes the
                # evidence_unusable family with recollect_unusable_evidence, which needs a spec decision (main).
                # Do not invent a reason code or text here. Never render the exception in any output.
                cell = row["cells"]["section_not_collected"]
                candidate = {"class": "value_rule", "rule_id": row["rule_id"],
                             "section": rule_sections, "field": None, "value": None,
                             "cell": "section_not_collected", "reason_code": cell["reason_code"],
                             "reason_text": "Data unavailable: required evidence section(s) not collected: "
                                            + ", ".join(rule_sections) + "."}
            if candidate is not None and candidate["class"] in {"value_rule", "closed_gate"}:
                detail = candidate
    if detail is None:
        detail = precheck_policy(case["policy_id"], projection, sections,
                                 skip_absent_sections=skip_absent_sections, absent_fields=absent_fields,
                                 empty_lists=empty_lists, value_rules=value_rules and rule_projection is None)
    if detail is None:
        return None
    return {**precheck_response(detail, case["evidence"][0]["observed"], sections,
                               named_limitations=named_limitations),
            "policy_id": case["policy_id"], "rule_precheck": detail,
            "validation_status": "valid", "reason": "rule_precheck", "latency_ms": 0,
            "attempts": 0, "prompt_sha256": None, "response_sha256": None,
            "thinking_disabled": False, "thinking_stripped": False}


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
