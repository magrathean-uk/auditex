"""Mechanical scoring and conservative curation of recorded model responses.

Expected labels come from reviewed cases, never model votes. These checks do
not establish natural-language entailment or the truth of tenant evidence.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "2026-10-18"
_STATUSES = {"confirmed", "inferred", "unknown"}
_RESPONSE_FIELDS = {"claims", "limitations", "recommendations"}
_CAVEATS = [
    "Structured checks only: claim IDs, statuses, typed values, evidence IDs and gap/recommendation IDs are compared mechanically; prose entailment is not verified.",
    "Evidence IDs are checked against each case's allowlist and expected references; source evidence truth and completeness are not independently established.",
    "Only explicitly approved case provenance is scored against expected labels; reviewer attribution must be inspected because approval does not establish independent human review. Unreviewed cases are quarantined.",
    "Model IDs and reviewer metadata are supplied labels, not independently verified identities or proof of model independence.",
    "Pooled scores include all declared splits; split_scores must be used to distinguish training fit from held-out evaluation.",
    "Recorded-response processing makes no inference, network or tenant calls.",
]


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _strings(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    for item in value:
        _text(item, label)
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must not contain duplicates")
    return value


def _json(value: Any) -> str:
    # JSON serialization preserves bool/int/float distinctions that Python
    # equality erases (True == 1 == 1.0).
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _validate_response(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _RESPONSE_FIELDS:
        raise ValueError("response must contain exactly claims, limitations and recommendations")
    if not isinstance(value["claims"], list):
        raise ValueError("claims must be an array")
    seen = set()
    for claim in value["claims"]:
        if not isinstance(claim, dict) or set(claim) not in (
            {"id", "status", "evidence_ids"}, {"id", "status", "evidence_ids", "value"},
        ):
            raise ValueError("claim must contain id, status, evidence_ids and optional value")
        claim_id = _text(claim["id"], "claim ID")
        if claim_id in seen:
            raise ValueError(f"duplicate claim ID: {claim_id}")
        seen.add(claim_id)
        if not isinstance(claim["status"], str) or claim["status"] not in _STATUSES:
            raise ValueError("claim status must be confirmed, inferred or unknown")
        refs = _strings(claim["evidence_ids"], "evidence_ids")
        if claim["status"] != "unknown" and not refs:
            raise ValueError("confirmed and inferred claims require evidence_ids")
        if "value" in claim:
            _json(claim["value"])
    _strings(value["limitations"], "limitations")
    _strings(value["recommendations"], "recommendations")
    return value


def _response_fingerprint(response: dict[str, Any]) -> str:
    canonical = {
        "claims": [{**claim, "evidence_ids": sorted(claim["evidence_ids"])}
                   for claim in sorted(response["claims"], key=lambda claim: claim["id"])],
        "limitations": sorted(response["limitations"]),
        "recommendations": sorted(response["recommendations"]),
    }
    return sha256(_json(canonical).encode("utf-8")).hexdigest()


def _load_cases(path: str | Path) -> list[dict[str, Any]]:
    from .model_training import load_cases

    cases = load_cases([path])
    if not cases:
        raise ValueError("case dataset must not be empty")
    # The shared case loader owns provenance and train/holdout leakage gates.
    # Keep the evaluator's expected-label contract explicit at its boundary.
    for case in cases:
        expected = case["expected"]
        if set(expected) != _RESPONSE_FIELDS | {"allowed_evidence_ids"}:
            raise ValueError(f"malformed expected rubric for case {case['id']}")
        allowed = set(_strings(expected["allowed_evidence_ids"], "allowed_evidence_ids"))
        _validate_response({key: expected[key] for key in _RESPONSE_FIELDS})
        if any(not set(claim["evidence_ids"]) <= allowed for claim in expected["claims"]):
            raise ValueError(f"expected evidence outside allowlist for case {case['id']}")
    return cases


def _load_responses(paths: list[str | Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(paths, list) or not paths:
        raise ValueError("provide at least one responses path")
    records, invalid, inputs = [], [], []
    seen: set[tuple[str, str]] = set()
    for supplied in paths:
        path = Path(supplied)
        if path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("responses file exceeds 64 MiB")
        data = path.read_bytes()
        inputs.append({"path": str(path), "sha256": sha256(data).hexdigest()})
        try:
            lines = data.decode("utf-8-sig").splitlines()
        except UnicodeError as exc:
            raise ValueError("responses must be UTF-8 JSONL") from exc
        if not any(line.strip() for line in lines):
            invalid.append({
                "path": str(path), "code": "empty_response_file",
                "detail": "Supplied response file contains no nonblank records; its model coverage cannot be verified.",
            })
            continue
        for line_number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            location = {"path": str(path), "line": line_number}
            try:
                row = json.loads(line, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
                if not isinstance(row, dict):
                    raise ValueError("response record must be an object")
                case_id = _text(row.get("case_id"), "case_id")
                model_id = _text(row.get("model_id"), "model_id")
            except (ValueError, TypeError, RecursionError) as exc:
                invalid.append({**location, "code": "invalid_record", "detail": str(exc)})
                continue
            identity = (case_id, model_id)
            if identity in seen:
                raise ValueError(f"duplicate case/model response: {case_id}/{model_id}")
            seen.add(identity)
            # Associate envelope-schema failures with their case so they cannot
            # disappear from curation as an omitted dissenting response.
            record = {**location, "case_id": case_id, "model_id": model_id, "response": row.get("response")}
            record["response_sha256"] = sha256(line.encode("utf-8")).hexdigest()
            record["envelope_valid"] = set(row) == {"case_id", "model_id", "response"}
            records.append(record)
    return records, invalid, inputs


def _score(case: dict[str, Any], response: dict[str, Any]) -> list[dict[str, Any]]:
    expected = case["expected"]
    actual = {claim["id"]: claim for claim in response["claims"]}
    targets = {claim["id"]: claim for claim in expected["claims"]}
    issues = []
    for claim_id in sorted(targets.keys() - actual.keys()):
        issues.append({"code": "missing_claim", "claim_id": claim_id})
    for claim_id, claim in actual.items():
        if claim_id not in targets:
            continue
        target = targets[claim_id]
        if claim["status"] != target["status"]:
            issues.append({"code": "status_mismatch", "claim_id": claim_id, "expected": target["status"], "observed": claim["status"]})
            if target["status"] == "unknown":
                issues.append({"code": "abstention_failure", "claim_id": claim_id})
        if set(claim["evidence_ids"]) != set(target["evidence_ids"]):
            issues.append({"code": "evidence_mismatch", "claim_id": claim_id,
                           "expected": target["evidence_ids"], "observed": claim["evidence_ids"]})
        if ("value" in claim) != ("value" in target) or (
            "value" in claim and "value" in target and _json(claim["value"]) != _json(target["value"])
        ):
            issues.append({"code": "value_mismatch", "claim_id": claim_id})
    for field in ("limitations", "recommendations"):
        missing = sorted(set(expected[field]) - set(response[field]))
        unexpected = sorted(set(response[field]) - set(expected[field]))
        if missing:
            issues.append({"code": f"missing_{field}", "ids": missing})
        if unexpected:
            issues.append({"code": f"unsupported_{field}", "ids": unexpected})
    return issues


def _check_allowlists(case: dict[str, Any], response: dict[str, Any]) -> list[dict[str, Any]]:
    allowed_claims = {claim["id"] for claim in case["expected"]["claims"]}
    allowed_evidence = set(case["expected"]["allowed_evidence_ids"])
    issues = []
    for claim in response["claims"]:
        if claim["id"] not in allowed_claims:
            issues.append({"code": "unsupported_claim", "claim_id": claim["id"]})
        unsupported = sorted(set(claim["evidence_ids"]) - allowed_evidence)
        if unsupported:
            issues.append({"code": "unsupported_evidence_refs", "claim_id": claim["id"], "evidence_ids": unsupported})
    return issues


def _evaluate(cases: list[dict[str, Any]], records: list[dict[str, Any]], invalid: list[dict[str, Any]], inputs: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {case["id"]: case for case in cases}
    models = sorted({record["model_id"] for record in records})
    results = []
    for record in records:
        case = by_id.get(record["case_id"])
        result = {key: value for key, value in record.items() if key not in {"response", "envelope_valid"}}
        result.update({"schema_valid": False, "mechanical_pass": None, "scored": False, "issues": []})
        if case is None:
            result["issues"].append({"code": "unknown_case"})
            results.append(result)
            continue
        result.update({"split": case["split"], "review_status": case["provenance"]["review_status"]})
        approved = case["provenance"]["review_status"] == "approved"
        result["scored"] = approved
        if approved:
            result["mechanical_pass"] = False
        try:
            if not record["envelope_valid"]:
                raise ValueError("response record must contain exactly case_id, model_id and response")
            response = _validate_response(record["response"])
            result["schema_valid"] = True
            result["structured_response_sha256"] = _response_fingerprint(response)
        except (ValueError, TypeError, OverflowError, RecursionError) as exc:
            result["issues"].append({"code": "response_schema_error", "detail": str(exc)})
        else:
            result["issues"].extend(_check_allowlists(case, response))
            if approved:
                result["issues"].extend(_score(case, response))
                result["mechanical_pass"] = not result["issues"]
        if not approved:
            result["issues"].append({"code": "unreviewed_case_quarantined"})
        results.append(result)
    observed = {(record["case_id"], record["model_id"]) for record in records}
    missing = [{"case_id": case["id"], "model_id": model}
               for case in cases for model in models if (case["id"], model) not in observed]
    approved_count = sum(case["provenance"]["review_status"] == "approved" for case in cases)
    scores = []
    for model in models:
        rows = [row for row in results if row["model_id"] == model]
        passed = sum(row["mechanical_pass"] is True for row in rows)
        split_scores = []
        for split in ("train", "validation", "test"):
            split_cases = [case for case in cases if case["split"] == split]
            split_approved = sum(case["provenance"]["review_status"] == "approved" for case in split_cases)
            split_rows = [row for row in rows if row.get("split") == split]
            split_passed = sum(row["mechanical_pass"] is True for row in split_rows)
            split_scores.append({
                "split": split,
                "approved_case_count": split_approved,
                "response_count": len(split_rows),
                "mechanical_pass_count": split_passed,
                "mechanical_fail_count": sum(row["mechanical_pass"] is False for row in split_rows),
                "quarantined_count": sum(row["review_status"] == "unreviewed" for row in split_rows),
                "missing_case_count": sum((case["id"], model) not in observed for case in split_cases),
                "mechanical_pass_rate": split_passed / split_approved if split_approved else None,
            })
        scores.append({
            "model_id": model,
            "approved_case_count": approved_count,
            "response_count": len(rows),
            "mechanical_pass_count": passed,
            "mechanical_fail_count": sum(row["mechanical_pass"] is False for row in rows),
            "quarantined_count": sum(row.get("review_status") == "unreviewed" for row in rows),
            "missing_case_count": sum(row["model_id"] == model for row in missing),
            "mechanical_pass_rate": passed / approved_count if approved_count else None,
            "split_scores": split_scores,
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "recorded_responses",
        "case_count": len(cases),
        "case_splits": dict(sorted(Counter(case["split"] for case in cases).items())),
        "response_count": len(records) + len(invalid),
        "inputs": inputs,
        "model_scores": scores,
        "results": results,
        "invalid_records": invalid,
        "missing_responses": missing,
        "caveats": list(_CAVEATS),
    }


def evaluate_responses(cases_path: str | Path, responses_path: str | Path) -> dict[str, Any]:
    """Score approved benchmark cases against local, recorded JSONL responses."""
    cases = _load_cases(cases_path)
    records, invalid, inputs = _load_responses([responses_path])
    result = _evaluate(cases, records, invalid, inputs)
    result["cases_input"] = {"path": str(cases_path), "sha256": sha256(Path(cases_path).read_bytes()).hexdigest()}
    return result


def combine_model_responses(cases_path: str | Path, response_paths: list[str | Path]) -> dict[str, Any]:
    """Curate exact-checked, approved train cases; never turn votes into labels.

    Every supplied model must answer each candidate case, every response must
    pass the reviewed expectations, and at least two distinct model labels are
    required. Unattributable invalid records block all candidate export.
    """
    cases = _load_cases(cases_path)
    records, invalid, inputs = _load_responses(response_paths)
    result = _evaluate(cases, records, invalid, inputs)
    result["cases_input"] = {"path": str(cases_path), "sha256": sha256(Path(cases_path).read_bytes()).hexdigest()}
    models = {record["model_id"] for record in records}
    by_case: dict[str, list[dict[str, Any]]] = {}
    for row in result["results"]:
        by_case.setdefault(row["case_id"], []).append(row)
    candidates, support, review_items = [], [], []
    for case in cases:
        rows = by_case.get(case["id"], [])
        reasons = []
        if case["split"] != "train":
            reasons.append("held_out_split_never_training")
        if case["provenance"]["review_status"] != "approved":
            reasons.append("unreviewed_case_quarantined")
        if len(models) < 2:
            reasons.append("at_least_two_model_labels_required")
        if {row["model_id"] for row in rows} != models or not rows:
            reasons.append("missing_model_responses")
        if any(row["mechanical_pass"] is False for row in rows):
            reasons.append("response_failed_independent_expected_checks")
        fingerprints = {row["structured_response_sha256"] for row in rows if row["schema_valid"]}
        if len(fingerprints) > 1:
            reasons.append("model_disagreement")
        if invalid:
            reasons.append("unattributable_invalid_records_block_export")
        if reasons:
            review_items.append({"case_id": case["id"], "split": case["split"], "reasons": reasons,
                                 "responses": rows})
            continue
        # Passing outputs are equivalent to the reviewed target under the
        # mechanical contract. Preserve target ordering so the shared training
        # validator can check the case again, rather than inventing a label.
        candidate = deepcopy(case)
        candidate["messages"][-1]["content"] = _json({key: case["expected"][key] for key in _RESPONSE_FIELDS})
        candidate["provenance"]["source"] = case["provenance"]["source"] + "; exact-checked recorded ensemble: " + ", ".join(sorted(models))
        candidates.append(candidate)
        support.append({"case_id": case["id"], "model_ids": sorted(models),
                        "response_sha256s": [row["response_sha256"] for row in rows]})
    review_items.extend({"case_id": row["case_id"], "reasons": ["unknown_case"], "responses": [row]}
                        for row in result["results"] if any(issue["code"] == "unknown_case" for issue in row["issues"]))
    result.update({
        "training_candidates": candidates,
        "candidate_support": support,
        "review_items": review_items,
        "candidate_export_blocked": bool(invalid),
        "curation_policy": "unanimous_expected_checks_and_human_approved_train_cases; no majority gold labels",
    })
    return result
