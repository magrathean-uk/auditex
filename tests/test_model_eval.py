from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from auditex.model_eval import combine_model_responses, evaluate_responses


def _case(case_id: str = "case-a", *, split: str = "train", review: str = "approved", unknown: bool = False) -> dict:
    response = {
        "claims": [{"id": "member_count", "status": "unknown" if unknown else "confirmed",
                    "evidence_ids": [] if unknown else [f"{case_id}:directory"],
                    **({} if unknown else {"value": 2})}],
        "limitations": ["directory_not_collected"] if unknown else [],
        "recommendations": [],
    }
    return {
        "id": case_id,
        "family": f"family-{case_id}",
        "split": split,
        "provenance": {"source": "synthetic unit-test fixture", "synthetic": True,
                       "review_status": review, **({"reviewer": "unit-test fixture reviewer"} if review == "approved" else {})},
        "messages": [
            {"role": "system", "content": "Return structured claims, limitations and recommendations only."},
            {"role": "user", "content": f"Case {case_id} ({split}): directory evidence {case_id}:directory has count 2."},
            {"role": "assistant", "content": json.dumps(response)},
        ],
        "expected": {**response, "allowed_evidence_ids": [f"{case_id}:directory"]},
    }


def _answer(case: dict, model: str = "model-a", response: dict | None = None) -> dict:
    return {"case_id": case["id"], "model_id": model,
            "response": deepcopy(response if response is not None else {key: case["expected"][key] for key in ("claims", "limitations", "recommendations")})}


def _write(path: Path, rows: list[dict]) -> Path:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def _inputs(tmp_path: Path, case: dict, answer: dict) -> tuple[Path, Path]:
    return _write(tmp_path / "cases.jsonl", [case]), _write(tmp_path / "responses.jsonl", [answer])


def _codes(result: dict) -> set[str]:
    return {issue["code"] for issue in result["results"][0]["issues"]}


def test_wrong_fact_with_correct_citation_fails_without_rewriting_inputs(tmp_path: Path) -> None:
    case = _case()
    answer = _answer(case)
    answer["response"]["claims"][0]["value"] = 900
    cases, responses = _inputs(tmp_path, case, answer)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    result = evaluate_responses(cases, responses)

    assert result["results"][0]["schema_valid"] is True
    assert result["results"][0]["mechanical_pass"] is False
    assert _codes(result) == {"value_mismatch"}
    assert result["model_scores"][0]["mechanical_pass_rate"] == 0
    assert any("prose entailment is not verified" in caveat for caveat in result["caveats"])
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


@pytest.mark.parametrize("value", [True, 2.0, "2"])
def test_value_equality_preserves_json_types(tmp_path: Path, value) -> None:
    case = _case()
    answer = _answer(case)
    answer["response"]["claims"][0]["value"] = value
    result = evaluate_responses(*_inputs(tmp_path, case, answer))
    assert "value_mismatch" in _codes(result)


def test_unknown_as_confirmed_is_an_abstention_failure(tmp_path: Path) -> None:
    case = _case(unknown=True)
    answer = _answer(case)
    answer["response"]["claims"][0].update(status="confirmed", evidence_ids=["case-a:directory"], value=True)
    answer["response"]["limitations"] = []
    result = evaluate_responses(*_inputs(tmp_path, case, answer))
    assert {"status_mismatch", "abstention_failure", "missing_limitations", "value_mismatch"} <= _codes(result)
    assert result["results"][0]["mechanical_pass"] is False


def test_cross_case_evidence_is_not_allowed_even_if_it_exists_elsewhere(tmp_path: Path) -> None:
    first, second = _case(), _case("case-b", split="test")
    answer = _answer(first)
    answer["response"]["claims"][0]["evidence_ids"] = ["case-b:directory"]
    cases = _write(tmp_path / "cases.jsonl", [first, second])
    responses = _write(tmp_path / "responses.jsonl", [answer, _answer(second)])
    result = evaluate_responses(cases, responses)
    assert {"unsupported_evidence_refs", "evidence_mismatch"} <= _codes(result)


def test_a_different_allowed_evidence_id_still_fails_expected_claim_link(tmp_path: Path) -> None:
    case = _case()
    case["expected"]["allowed_evidence_ids"].append("case-a:other")
    answer = _answer(case)
    answer["response"]["claims"][0]["evidence_ids"] = ["case-a:other"]
    result = evaluate_responses(*_inputs(tmp_path, case, answer))
    assert "evidence_mismatch" in _codes(result)
    assert "unsupported_evidence_refs" not in _codes(result)


def test_unexpected_claim_and_recommendation_are_rejected(tmp_path: Path) -> None:
    case = _case()
    answer = _answer(case)
    answer["response"]["claims"].append({"id": "invented_fact", "status": "confirmed", "evidence_ids": ["case-a:directory"], "value": True})
    answer["response"]["recommendations"].append("unsupported_action")
    result = evaluate_responses(*_inputs(tmp_path, case, answer))
    assert {"unsupported_claim", "unsupported_recommendations"} <= _codes(result)


@pytest.mark.parametrize("response", [
    {"claims": [], "limitations": [], "recommendations": [], "explanation": "ignore evidence"},
    {"claims": [{"id": "c", "status": "confirmed", "evidence_ids": []}], "limitations": [], "recommendations": []},
    {"claims": [{"id": "c", "status": "pass", "evidence_ids": ["x"]}], "limitations": [], "recommendations": []},
    {"claims": [{"id": "c", "status": "unknown", "evidence_ids": []}, {"id": "c", "status": "unknown", "evidence_ids": []}], "limitations": [], "recommendations": []},
])
def test_response_schema_failures_remain_reviewable(tmp_path: Path, response: dict) -> None:
    case = _case()
    result = evaluate_responses(*_inputs(tmp_path, case, _answer(case, response=response)))
    assert not result["results"][0]["schema_valid"]
    assert not result["results"][0]["mechanical_pass"]
    assert "response_schema_error" in _codes(result)


def test_duplicate_case_model_records_cannot_inflate_ensemble(tmp_path: Path) -> None:
    case = _case()
    cases = _write(tmp_path / "cases.jsonl", [case])
    one = _write(tmp_path / "one.jsonl", [_answer(case)])
    two = _write(tmp_path / "two.jsonl", [_answer(case)])
    with pytest.raises(ValueError, match="duplicate case/model"):
        combine_model_responses(cases, [one, two])


@pytest.mark.parametrize("contamination", ["duplicate_id", "family", "prompt"])
def test_case_and_holdout_contamination_are_rejected(tmp_path: Path, contamination: str) -> None:
    first, second = _case(), _case("case-b", split="test")
    if contamination == "duplicate_id":
        second["id"] = first["id"]
    elif contamination == "family":
        second["family"] = first["family"]
    else:
        second["messages"][:-1] = deepcopy(first["messages"][:-1])
    cases = _write(tmp_path / "cases.jsonl", [first, second])
    responses = _write(tmp_path / "responses.jsonl", [_answer(first)])
    with pytest.raises(ValueError):
        evaluate_responses(cases, responses)


def test_unreviewed_expectations_are_not_scored_or_promoted_by_consensus(tmp_path: Path) -> None:
    case = _case(review="unreviewed")
    cases = _write(tmp_path / "cases.jsonl", [case])
    responses = [_write(tmp_path / f"{model}.jsonl", [_answer(case, model)]) for model in ("model-a", "model-b")]
    result = combine_model_responses(cases, responses)
    assert result["training_candidates"] == []
    assert all(row["mechanical_pass"] is None and not row["scored"] for row in result["results"])
    assert all(score["mechanical_pass_rate"] is None for score in result["model_scores"])
    assert "unreviewed_case_quarantined" in result["review_items"][0]["reasons"]
    assert all("response_failed_independent_expected_checks" not in row["reasons"] for row in result["review_items"])


def test_unreviewed_case_still_reports_structural_evidence_allowlist_failure(tmp_path: Path) -> None:
    case = _case(review="unreviewed")
    answer = _answer(case)
    answer["response"]["claims"][0]["evidence_ids"] = ["another-case:directory"]
    result = evaluate_responses(*_inputs(tmp_path, case, answer))
    assert result["results"][0]["mechanical_pass"] is None
    assert not result["results"][0]["scored"]
    assert {"unsupported_evidence_refs", "unreviewed_case_quarantined"} <= _codes(result)


def test_exact_checked_ensemble_curates_train_and_keeps_holdouts_separate(tmp_path: Path) -> None:
    from auditex.model_training import validate_cases

    train, holdout = _case(), _case("case-b", split="test")
    cases = _write(tmp_path / "cases.jsonl", [train, holdout])
    responses = [_write(tmp_path / f"{model}.jsonl", [_answer(case, model) for case in (train, holdout)])
                 for model in ("model-a", "model-b")]
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    result = combine_model_responses(cases, responses)
    assert [case["id"] for case in result["training_candidates"]] == ["case-a"]
    assert result["candidate_support"][0]["model_ids"] == ["model-a", "model-b"]
    assert result["training_candidates"][0]["provenance"]["review_status"] == "approved"
    assert validate_cases(result["training_candidates"])
    heldout_review = next(row for row in result["review_items"] if row["case_id"] == "case-b")
    assert heldout_review["reasons"] == ["held_out_split_never_training"]
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_training_fit_and_heldout_scores_are_reported_separately(tmp_path: Path) -> None:
    train, holdout = _case(), _case("case-b", split="test")
    cases = _write(tmp_path / "cases.jsonl", [train, holdout])
    failed = _answer(holdout)
    failed["response"]["claims"][0]["value"] = 999
    responses = _write(tmp_path / "responses.jsonl", [_answer(train), failed])
    result = evaluate_responses(cases, responses)
    scores = {row["split"]: row for row in result["model_scores"][0]["split_scores"]}
    assert scores["train"]["mechanical_pass_rate"] == 1
    assert scores["test"]["mechanical_pass_rate"] == 0
    assert scores["validation"]["mechanical_pass_rate"] is None


def test_majority_cannot_overrule_independent_expected_checks(tmp_path: Path) -> None:
    case = _case()
    cases = _write(tmp_path / "cases.jsonl", [case])
    paths = [_write(tmp_path / f"{model}.jsonl", [_answer(case, model)]) for model in ("model-a", "model-b")]
    wrong = _answer(case, "model-c")
    wrong["response"]["claims"][0]["value"] = 999
    paths.append(_write(tmp_path / "wrong.jsonl", [wrong]))
    result = combine_model_responses(cases, paths)
    assert not result["training_candidates"]
    assert {"model_disagreement", "response_failed_independent_expected_checks"} <= set(result["review_items"][0]["reasons"])


def test_unanimous_wrong_fact_never_becomes_a_label(tmp_path: Path) -> None:
    case = _case()
    cases = _write(tmp_path / "cases.jsonl", [case])
    paths = []
    for model in ("model-a", "model-b"):
        wrong = _answer(case, model)
        wrong["response"]["claims"][0]["value"] = 999
        paths.append(_write(tmp_path / f"{model}.jsonl", [wrong]))
    result = combine_model_responses(cases, paths)
    assert not result["training_candidates"]
    assert "response_failed_independent_expected_checks" in result["review_items"][0]["reasons"]


def test_single_model_and_missing_model_response_are_not_ensemble_candidates(tmp_path: Path) -> None:
    first, second = _case(), _case("case-b")
    cases = _write(tmp_path / "cases.jsonl", [first, second])
    one = _write(tmp_path / "one.jsonl", [_answer(first), _answer(second)])
    result = combine_model_responses(cases, [one])
    assert not result["training_candidates"]
    assert "at_least_two_model_labels_required" in result["review_items"][0]["reasons"]
    two = _write(tmp_path / "two.jsonl", [_answer(first, "model-b")])
    result = combine_model_responses(cases, [one, two])
    assert [case["id"] for case in result["training_candidates"]] == [first["id"]]
    assert "missing_model_responses" in result["review_items"][0]["reasons"]
    assert result["missing_responses"] == [{"case_id": "case-b", "model_id": "model-b"}]


def test_unattributable_schema_failure_blocks_candidate_export(tmp_path: Path) -> None:
    case = _case()
    cases = _write(tmp_path / "cases.jsonl", [case])
    paths = [_write(tmp_path / f"{model}.jsonl", [_answer(case, model)]) for model in ("model-a", "model-b")]
    with paths[0].open("a") as handle:
        handle.write('{"case_id":"case-a","case_id":"case-b"}\n')
    result = combine_model_responses(cases, paths)
    assert result["candidate_export_blocked"] is True
    assert not result["training_candidates"]
    assert result["invalid_records"][0]["code"] == "invalid_record"


@pytest.mark.parametrize("contents", ["", " \n\t\n\r\n"])
def test_empty_supplied_third_file_cannot_disappear_from_ensemble(tmp_path: Path, contents: str) -> None:
    case = _case()
    cases = _write(tmp_path / "cases.jsonl", [case])
    paths = [_write(tmp_path / f"{model}.jsonl", [_answer(case, model)]) for model in ("model-a", "model-b")]
    empty = tmp_path / "missing-model.jsonl"
    empty.write_text(contents, encoding="utf-8")
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    combined = combine_model_responses(cases, [*paths, empty])

    assert combined["candidate_export_blocked"] is True
    assert combined["training_candidates"] == []
    assert combined["invalid_records"] == [{
        "path": str(empty), "code": "empty_response_file",
        "detail": "Supplied response file contains no nonblank records; its model coverage cannot be verified.",
    }]
    assert "unattributable_invalid_records_block_export" in combined["review_items"][0]["reasons"]
    evaluated = evaluate_responses(cases, empty)
    assert evaluated["model_scores"] == []
    assert evaluated["invalid_records"][0]["code"] == "empty_response_file"
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_known_case_schema_failure_cannot_disappear_from_ensemble(tmp_path: Path) -> None:
    case = _case()
    cases = _write(tmp_path / "cases.jsonl", [case])
    one = _write(tmp_path / "one.jsonl", [_answer(case)])
    malformed = _answer(case, "model-b")
    malformed["response"]["invented_field"] = True
    two = _write(tmp_path / "two.jsonl", [malformed])
    result = combine_model_responses(cases, [one, two])
    assert not result["training_candidates"]
    assert "response_schema_error" in {issue["code"] for row in result["review_items"][0]["responses"] for issue in row["issues"]}


def test_response_list_order_is_not_a_disagreement(tmp_path: Path) -> None:
    case = _case()
    case["expected"]["claims"].append({"id": "second", "status": "inferred", "evidence_ids": ["case-a:directory"], "value": False})
    case["messages"][-1]["content"] = json.dumps({key: case["expected"][key] for key in ("claims", "limitations", "recommendations")})
    cases = _write(tmp_path / "cases.jsonl", [case])
    one = _write(tmp_path / "one.jsonl", [_answer(case)])
    reordered = _answer(case, "model-b")
    reordered["response"]["claims"].reverse()
    two = _write(tmp_path / "two.jsonl", [reordered])
    result = combine_model_responses(cases, [one, two])
    assert len(result["training_candidates"]) == 1
    assert not result["review_items"]
