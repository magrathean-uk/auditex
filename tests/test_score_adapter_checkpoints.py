"""Checkpoint selection by generation (G3): no model download, no GPU, no inference.

The generator is a stub returning canned text per checkpoint and case, so these tests cover prompt rendering,
strict parsing, the evaluator hand-off, the selection rule and the output contract. The one test that renders
with a real tokenizer is skipped unless the staged Qwen3.5-0.8B snapshot and transformers are present.
"""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from auditex.model_eval import evaluate_responses
from auditex.model_training import _trl_record, load_cases

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "score-adapter-checkpoints.py"
_spec = importlib.util.spec_from_file_location("score_adapter_checkpoints", SCRIPT)
sac = importlib.util.module_from_spec(_spec)
sys.modules["score_adapter_checkpoints"] = sac
_spec.loader.exec_module(sac)

BASE = "Qwen/Qwen3.5-0.8B"
REVISION = "2fc06364715b967f1860aea9cf38778875588b17"
FIELDS = ("claims", "limitations", "recommendations")


def make_case(case_id: str, *, split: str = "validation", approved: bool = True, unknown_claim: bool = True) -> dict:
    claims = [{"id": "registered", "status": "confirmed", "evidence_ids": [f"{case_id}:e1"], "value": True}]
    if unknown_claim:
        claims.append({"id": "enforced", "status": "unknown", "evidence_ids": [f"{case_id}:e2"], "value": None})
    expected = {"claims": claims, "limitations": ["controls_not_collected"], "recommendations": ["collect_controls"],
                "allowed_evidence_ids": [f"{case_id}:e1", f"{case_id}:e2"]}
    provenance = {"source": "test fixture", "synthetic": True, "review_status": "approved" if approved else "unreviewed"}
    if approved:
        provenance["reviewer"] = "test"
    return {
        "id": case_id, "family": f"family-{case_id}", "split": split, "provenance": provenance,
        "messages": [
            {"role": "system", "content": "Return exactly a JSON object."},
            {"role": "user", "content": json.dumps({"case_id": case_id, "question": f"question about {case_id}"})},
            {"role": "assistant", "content": json.dumps({key: expected[key] for key in FIELDS})},
        ],
        "expected": expected,
    }


def good(case: dict) -> dict:
    return {key: deepcopy(case["expected"][key]) for key in FIELDS}


def overconfident(case: dict) -> dict:
    answer = good(case)
    for claim in answer["claims"]:
        if claim["status"] == "unknown":
            claim.update(status="confirmed", value=True)
    return answer


def over_abstaining(case: dict) -> dict:
    answer = good(case)
    for claim in answer["claims"]:
        if claim["status"] == "confirmed":
            claim.update(status="unknown", value=None, evidence_ids=[])
    return answer


def write_cases(path: Path, cases: list[dict]) -> Path:
    path.write_text("".join(json.dumps(case) + "\n" for case in cases), encoding="utf-8")
    return path


def make_checkpoint(root: Path, name: str, *, base: str = BASE, revision: str = REVISION, identity: bool = True) -> Path:
    directory = root / name
    directory.mkdir(parents=True)
    (directory / "adapter_config.json").write_text(json.dumps({
        "base_model_name_or_path": f"/hf/hub/models--Qwen--Qwen3.5-0.8B/snapshots/{revision}"}), encoding="utf-8")
    (directory / "adapter_model.safetensors").write_bytes(b"stub adapter weights")
    if identity:
        (directory / "auditex-training-input.json").write_text(json.dumps(
            {"base_model": base, "base_revision": revision, "pack_manifest_sha256": "0" * 64}), encoding="utf-8")
    return directory


class StubBackend:
    """Canned answers keyed by checkpoint name then case id; records every adapter and generate call."""

    def __init__(self, answers: dict[str, dict[str, object]], fail_on: str | None = None) -> None:
        self.answers, self.fail_on, self.events, self.current = answers, fail_on, [], None

    def describe(self) -> dict:
        return {"backend": "stub"}

    def render_prompt(self, case: dict) -> str:
        return f"PROMPT[{case['id']}]"

    def load_adapter(self, path: Path) -> None:
        self.current = Path(path).name
        self.events.append(("load", self.current))

    def unload_adapter(self) -> None:
        self.events.append(("unload", self.current))
        self.current = None

    def generate(self, prompts: list[str], progress) -> list[dict]:
        self.events.append(("generate", self.current, list(prompts)))
        if self.fail_on == self.current:
            raise RuntimeError("stub generation failure")
        results = []
        for prompt in prompts:
            answer = self.answers[self.current][prompt[len("PROMPT["):-1]]
            text = answer if isinstance(answer, str) else json.dumps(answer)
            results.append({"text": text, "new_tokens": 9, "prompt_tokens": 11, "finish_reason": "eos"})
        progress(len(prompts), len(prompts))
        return results


def run_main(tmp_path: Path, cases_path: Path, checkpoints_root: Path, backend: StubBackend | None, *extra: str,
             output: str = "out") -> tuple[int, Path]:
    created = []
    code = sac.main([
        "--base-model", BASE, "--revision", REVISION, "--checkpoints-root", str(checkpoints_root),
        "--cases", str(cases_path), "--output-dir", str(tmp_path / output), *extra,
    ], backend_factory=lambda args: created.append(args) or backend)
    run_main.backend_built = bool(created)
    return code, tmp_path / output


@pytest.fixture
def held_out(tmp_path):
    cases = [make_case(f"case-{index}", split="validation" if index < 3 else "test") for index in range(5)]
    return cases, write_cases(tmp_path / "cases.jsonl", cases)


# --- strict parsing -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    '```json\n{"claims": [], "limitations": [], "recommendations": []}\n```',
    '{"claims": [], "limitations": [], "recommendations": []} Hope that helps.',
    'Here is the answer: {"claims": [], "limitations": [], "recommendations": []}',
    '{"claims": [], "claims": [], "limitations": [], "recommendations": []}',
    '{"claims": [NaN], "limitations": [], "recommendations": []}',
    '{"claims": [], "limitations"',
    '<think>\n\n</think>\n\n{"claims": []}',
    "",
])
def test_strict_parse_rejects_fences_trailing_text_and_repairs(text):
    parsed, error = sac.parse_strict(text)
    assert parsed is None and error


def test_strict_parse_accepts_exactly_one_json_value():
    answer = {"claims": [], "limitations": [], "recommendations": []}
    assert sac.parse_strict(json.dumps(answer)) == (answer, None)
    assert sac.parse_strict("\n" + json.dumps(answer) + "\n")[0] == answer


# --- row format ---------------------------------------------------------------------------------------------

def test_response_row_matches_the_evaluator_contract(tmp_path):
    case = make_case("case-row")
    cases_path = write_cases(tmp_path / "cases.jsonl", [case])
    model_id = f"{BASE}@{REVISION}+checkpoint-25"
    ok_row, ok_trace = sac.response_row(case["id"], model_id, {"text": json.dumps(good(case)), "new_tokens": 3,
                                                               "prompt_tokens": 4, "finish_reason": "eos"})
    assert set(ok_row) == {"case_id", "model_id", "response"} and ok_row["response"] == good(case)
    assert ok_trace["strict_json"] is True and ok_trace["parse_error"] is None and ok_trace["finish_reason"] == "eos"
    fenced = "```json\n" + json.dumps(good(case)) + "\n```"
    bad_row, bad_trace = sac.response_row(case["id"], "other-model", {"text": fenced, "finish_reason": "length"})
    assert set(bad_row) == {"case_id", "model_id", "response"} and bad_row["response"] == fenced
    assert bad_trace["strict_json"] is False and bad_trace["raw_text"] == fenced and bad_trace["parse_error"]
    responses = tmp_path / "responses.jsonl"
    responses.write_text(json.dumps(ok_row) + "\n" + json.dumps(bad_row) + "\n", encoding="utf-8")
    evaluation = evaluate_responses(cases_path, responses)
    scores = {item["model_id"]: item for item in evaluation["model_scores"]}
    assert scores[model_id]["mechanical_pass_count"] == 1
    assert scores["other-model"]["mechanical_pass_count"] == 0
    codes = [issue["code"] for row in evaluation["results"] if row["model_id"] == "other-model" for issue in row["issues"]]
    assert codes == ["response_schema_error"]
    assert evaluation["invalid_records"] == []


# --- generation helpers -------------------------------------------------------------------------------------

def test_pad_left_aligns_prompt_ends_and_masks_padding():
    ids, mask = sac.pad_left([[1, 2, 3], [4], [5, 6]], pad_id=0)
    assert ids == [[1, 2, 3], [0, 0, 4], [0, 5, 6]]
    assert mask == [[1, 1, 1], [0, 0, 1], [0, 1, 1]]


def test_cut_at_stop_keeps_tokens_before_the_first_stop_token():
    assert sac.cut_at_stop([5, 6, 99, 7, 99], {99, 100}) == ([5, 6], "eos")
    assert sac.cut_at_stop([99], {99}) == ([], "eos")
    assert sac.cut_at_stop([5, 6, 7], {99}) == ([5, 6, 7], "length")


# --- prompt rendering ---------------------------------------------------------------------------------------

class RecordingTokenizer:
    def __init__(self) -> None:
        self.calls = []

    def apply_chat_template(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        return "|".join(f"{item['role']}:{item['content']}" for item in messages) + "|assistant:"


def test_prompt_is_the_training_record_prompt_with_thinking_off_and_no_target():
    case = make_case("case-prompt")
    tokenizer = RecordingTokenizer()
    rendered = sac.render_prompt(tokenizer, case)
    record = _trl_record(case)
    (messages, kwargs), = tokenizer.calls
    assert messages == record["prompt"] == case["messages"][:-1]
    assert kwargs == {"tokenize": False, "add_generation_prompt": True, **record["chat_template_kwargs"]}
    assert kwargs["enable_thinking"] is False
    assert case["messages"][-1]["content"] not in rendered


def _staged_tokenizer():
    pytest.importorskip("transformers")
    home = Path(os.environ.get("AUDITEX_TEST_HF_HOME", "~/dev/machine/work/auditex-data/hf-home")).expanduser()
    snapshots = sorted((home / "hub" / "models--Qwen--Qwen3.5-0.8B" / "snapshots").glob("*/tokenizer.json"))
    if not snapshots:
        pytest.skip("Qwen/Qwen3.5-0.8B is not staged under the offline HF_HOME")
    from transformers import AutoTokenizer

    return AutoTokenizer.from_pretrained(str(snapshots[0].parent), local_files_only=True, trust_remote_code=False)


def test_prompt_rendering_equals_the_training_time_prompt_with_the_staged_tokenizer():
    tokenizer = _staged_tokenizer()
    for case in (make_case("case-real-1"), make_case("case-real-2", unknown_claim=False)):
        record = _trl_record(case)
        prompt = sac.render_prompt(tokenizer, case)
        # What TRL's SFT tokenisation renders for a prompt/completion record: the prompt alone, generation prompt
        # appended, with the record's own chat_template_kwargs.
        assert prompt == tokenizer.apply_chat_template(record["prompt"], tokenize=False, add_generation_prompt=True,
                                                       enable_thinking=False)
        trained = tokenizer.apply_chat_template(record["prompt"], tokenize=True, return_dict=True,
                                                add_generation_prompt=True, **record["chat_template_kwargs"])["input_ids"]
        assert tokenizer(prompt, add_special_tokens=False)["input_ids"] == list(trained)
        # Thinking off ends the prompt on an empty think block, and the full training sequence extends it.
        assert prompt.endswith("<think>\n\n</think>\n\n")
        full = tokenizer.apply_chat_template(case["messages"], tokenize=False, enable_thinking=False)
        assert full.startswith(prompt)
        assert full[len(prompt):].startswith(case["messages"][-1]["content"])
        try:
            from trl.data_utils import _tokenize
        except ImportError:
            continue
        assert trained == _tokenize(tokenizer, record["prompt"], add_generation_prompt=True, chat_template=None,
                                    tools=None, **record["chat_template_kwargs"])["input_ids"]


# --- selection rule -----------------------------------------------------------------------------------------

def entry(name, passes, over_confident=0, over_abstained=0, step="auto", **extra):
    if step == "auto":
        step = sac._checkpoint_step(name)
    return {"name": name, "step": step, "strict_pass_count": passes, "overconfidence": over_confident,
            "over_abstention": over_abstained, "scored_cases": 10, "applicability_errors": 0, **extra}


def test_selection_takes_the_highest_strict_pass_rate():
    result = sac.select_checkpoint([entry("checkpoint-25", 7), entry("checkpoint-50", 9), entry("checkpoint-75", 8)])
    assert result["selected"] == "checkpoint-50"
    assert result["ranking"] == ["checkpoint-50", "checkpoint-75", "checkpoint-25"]
    assert result["tied_with"] == []


def test_selection_ignores_eval_loss_even_when_it_disagrees():
    entries = [entry("checkpoint-25", 3, eval_loss=0.01), entry("checkpoint-50", 9, eval_loss=9.0)]
    assert sac.select_checkpoint(entries)["selected"] == "checkpoint-50"
    assert "eval_loss" not in json.dumps(sac.SELECTION_RULE["order"])
    assert sac.SELECTION_RULE["never_by"] == "eval_loss"


def test_selection_tiebreak_prefers_lower_overconfidence_before_over_abstention():
    entries = [entry("checkpoint-25", 8, over_confident=2, over_abstained=0),
               entry("checkpoint-50", 8, over_confident=1, over_abstained=5),
               entry("checkpoint-75", 8, over_confident=1, over_abstained=3)]
    assert sac.select_checkpoint(entries)["ranking"] == ["checkpoint-75", "checkpoint-50", "checkpoint-25"]


def test_selection_tiebreak_over_abstention_then_earliest_step_with_the_tie_reported():
    result = sac.select_checkpoint([entry("checkpoint-100", 8, 1, 1), entry("checkpoint-25", 8, 1, 1),
                                    entry("checkpoint-50", 8, 1, 2)])
    assert result["selected"] == "checkpoint-25"
    assert result["tied_with"] == ["checkpoint-100"]
    named = sac.select_checkpoint([entry("adapter", 8, step=None), entry("checkpoint-300", 8)])
    assert named["selected"] == "checkpoint-300"


def test_selection_needs_at_least_one_checkpoint():
    with pytest.raises(ValueError):
        sac.select_checkpoint([])


@pytest.mark.parametrize("scored,passes,width", [(348, 292, 14), (290, 249, 12), (10, 10, 1), (10, 0, 1), (0, 0, 1)])
def test_selection_band_uses_binomial_standard_error_at_the_best_point(scored, passes, width):
    result = sac.select_checkpoint([entry("checkpoint-25", passes, scored_cases=scored)])
    assert result["band_width"] == width
    assert result["best_strict_pass_count"] == passes
    assert result["band_members"] == ["checkpoint-25"]


def test_selection_prioritises_applicability_within_the_inclusive_band():
    entries = [entry("checkpoint-125", 292, scored_cases=348, applicability_errors=20),
               entry("checkpoint-150", 278, scored_cases=348, over_confident=5, over_abstained=5),
               entry("checkpoint-175", 277, scored_cases=348)]
    result = sac.select_checkpoint(entries)
    assert result["selected"] == "checkpoint-150"
    assert result["selected_by_strict_first"] == "checkpoint-125"
    assert result["band_members"] == ["checkpoint-150", "checkpoint-125"]
    assert result["ranking"] == ["checkpoint-150", "checkpoint-125", "checkpoint-175"]
    assert result["tied_with"] == []
    assert len(result["warnings"]) == 1
    assert all(name in result["warnings"][0] for name in ("checkpoint-125", "checkpoint-150"))


def test_selection_keeps_strict_first_winner_when_safer_checkpoint_is_outside_band():
    result = sac.select_checkpoint([entry("checkpoint-150", 292, scored_cases=348, applicability_errors=20),
                                    entry("checkpoint-175", 277, scored_cases=348)])
    assert result["selected"] == result["selected_by_strict_first"] == "checkpoint-150"
    assert result["band_members"] == ["checkpoint-150"]
    assert result["warnings"] == []


def test_selection_ties_include_applicability_and_pass_count_before_step():
    entries = [entry("checkpoint-25", 9, applicability_errors=1), entry("checkpoint-50", 8),
               entry("checkpoint-75", 8, applicability_errors=1), entry("checkpoint-100", 8),
               entry("checkpoint-200", 7)]
    result = sac.select_checkpoint(entries)
    assert result["selected"] == "checkpoint-50"
    assert result["tied_with"] == ["checkpoint-100"]
    assert result["ranking"] == ["checkpoint-50", "checkpoint-100", "checkpoint-200", "checkpoint-25", "checkpoint-75"]
    named = sac.select_checkpoint([entry("z-adapter", 8, step=None), entry("a-adapter", 8, step=None)])
    assert named["selected"] == "a-adapter" and named["tied_with"] == ["z-adapter"]


@pytest.mark.parametrize("extra", [{"over_confident": 1}, {"over_abstained": 1}])
def test_selection_strict_count_precedes_unknown_related_error_counts_within_band(extra):
    result = sac.select_checkpoint([entry("checkpoint-25", 8), entry("checkpoint-50", 9, **extra)])
    assert result["selected"] == result["selected_by_strict_first"] == "checkpoint-50"
    assert result["band_members"] == ["checkpoint-50", "checkpoint-25"]
    assert result["warnings"] == []


def test_selection_requires_comparable_case_counts():
    with pytest.raises(ValueError, match="same scored_cases"):
        sac.select_checkpoint([entry("checkpoint-25", 8), entry("checkpoint-50", 8, scored_cases=20)])


@pytest.mark.parametrize("base_name,base_step", [("checkpoint-0", None), ("null-adapter", 0)])
@pytest.mark.parametrize("base_passes,trained_passes,base_errors,trained_errors,winner", [
    (280, 292, 0, 1, "checkpoint-150"),
    (292, 280, 1, 0, "base"),
    (292, 292, 1, 0, "base"),
])
def test_selection_requires_trained_checkpoints_to_strictly_beat_the_base(
        base_name, base_step, base_passes, trained_passes, base_errors, trained_errors, winner):
    result = sac.select_checkpoint([
        entry(base_name, base_passes, step=base_step, scored_cases=348, applicability_errors=base_errors),
        entry("checkpoint-150", trained_passes, scored_cases=348, applicability_errors=trained_errors),
    ])
    selected = base_name if winner == "base" else winner
    assert result["selected"] == selected
    assert result["band_members"] == [selected]
    assert result["tied_with"] == []
    assert result["base_strict_pass_count"] == base_passes
    assert result["base_floor_applied"] is True


def test_selection_excludes_trained_checkpoints_at_or_below_base_even_when_another_beats_it():
    result = sac.select_checkpoint([
        entry("checkpoint-0", 280, scored_cases=348),
        entry("checkpoint-100", 280, scored_cases=348),
        entry("checkpoint-125", 279, scored_cases=348),
        entry("checkpoint-150", 292, scored_cases=348, applicability_errors=1),
    ])
    assert result["selected"] == "checkpoint-150"
    assert result["band_members"] == ["checkpoint-150"]
    assert result["ranking"] == ["checkpoint-150", "checkpoint-0", "checkpoint-100", "checkpoint-125"]


def test_selection_without_base_keeps_noise_band_behaviour():
    result = sac.select_checkpoint([entry("checkpoint-125", 292, scored_cases=348, applicability_errors=1),
                                    entry("checkpoint-150", 280, scored_cases=348)])
    assert result["selected"] == "checkpoint-150"
    assert result["band_members"] == ["checkpoint-150", "checkpoint-125"]
    assert result["base_strict_pass_count"] is None
    assert result["base_floor_applied"] is False


@pytest.mark.parametrize("relative,models,scored,width,previous", [
    ("results-v7-20261026/real-v7-validation-20261026T150431Z", 13, 348, 14, "checkpoint-125"),
    ("results-v6-20261025T225631Z/real-v6-validation-20261025T144736Z", 18, 290, 12, "checkpoint-150"),
])
def test_selection_on_real_validation_runs_when_present(relative, models, scored, width, previous):
    # Explicit opt-in only. Historical real model results are never discovered under the home directory:
    # with the variable unset (the model streams are parked) nothing is probed or opened and the test skips.
    configured = os.environ.get("AUDITEX_TEST_JUPITER_RESULTS", "").strip()
    if not configured:
        pytest.skip("set AUDITEX_TEST_JUPITER_RESULTS to an existing results directory to run this check")
    base = Path(configured)
    if not base.is_absolute() or not base.is_dir():
        pytest.skip("AUDITEX_TEST_JUPITER_RESULTS is not an existing absolute directory")
    root = base / relative
    if not all((root / name).is_file() for name in ("evaluation.json", "scored-cases.jsonl")):
        pytest.skip("the opted-in results directory lacks this validation run's scoring files")
    evaluation = json.loads((root / "evaluation.json").read_text(encoding="utf-8"))
    cases = load_cases([root / "scored-cases.jsonl"])
    assert len(evaluation["model_scores"]) == models
    assert len(cases) == scored and {case["split"] for case in cases} == {"validation"}
    entries = []
    for score in evaluation["model_scores"]:
        model = score["model_id"]
        name = model.rsplit("+", 1)[1]
        entries.append({"name": name, "step": sac._checkpoint_step(name),
                        **sac.checkpoint_metrics(evaluation, cases, model)})
    result = sac.select_checkpoint(entries)
    assert result["selected"] == "checkpoint-150"
    assert result["selected_by_strict_first"] == previous
    assert result["band_width"] == width
    if scored == 348:
        assert result["band_width"] == 14
        assert result["band_members"] == [f"checkpoint-{step}" for step in (150, 175, 225, 125, 100)]
    else:
        assert result["band_width"] == 12
    assert bool(result["warnings"]) == (previous != result["selected"])


# --- metrics from the evaluator -----------------------------------------------------------------------------

@pytest.mark.parametrize("claim_id", ["requirement_met", "registered"])
@pytest.mark.parametrize("expected,observed,applicability,confidence,abstention", [
    ("inferred", "confirmed", 1, 0, 0), ("confirmed", "inferred", 1, 0, 0),
    ("unknown", "confirmed", 0, 1, 0), ("unknown", "inferred", 0, 1, 0),
    ("confirmed", "unknown", 0, 0, 1), ("inferred", "unknown", 0, 0, 1),
    ("confirmed", "confirmed", 0, 0, 0), ("inferred", "inferred", 0, 0, 0),
])
def test_metrics_distinguish_applicability_from_unknown_mismatches(tmp_path, expected, observed,
                                                                applicability, confidence, abstention, claim_id):
    case = make_case("gate", unknown_claim=False)
    claim = case["expected"]["claims"][0]
    claim.update(id=claim_id, status=expected, value=None if expected == "unknown" else True)
    case["messages"][-1]["content"] = json.dumps(good(case))
    cases_path = write_cases(tmp_path / "cases.jsonl", [case])
    answer = good(case)
    answer["claims"][0].update(status=observed, value=None if observed == "unknown" else True)
    responses = tmp_path / "responses.jsonl"
    responses.write_text(json.dumps({"case_id": case["id"], "model_id": "m", "response": answer}) + "\n")
    evaluation = evaluate_responses(cases_path, responses)
    metrics = sac.checkpoint_metrics(evaluation, [case], "m")
    assert metrics["applicability_errors"] == (applicability if claim_id == "requirement_met" else 0)
    assert metrics["applicability_errors_rate"] == (
        float(applicability) if claim_id == "requirement_met" and expected != "unknown" else None)
    assert metrics["overconfidence"] == confidence
    assert metrics["over_abstention"] == abstention


def test_applicability_rate_counts_only_expected_confirmed_and_inferred_policy_gates(tmp_path):
    cases = [make_case(f"gate-{status}") for status in ("confirmed", "inferred", "unknown")]
    answers = []
    for case, status in zip(cases, ("confirmed", "inferred", "unknown")):
        case["expected"]["claims"].append({"id": "requirement_met", "status": status,
                                           "value": None if status == "unknown" else True,
                                           "evidence_ids": [f"{case['id']}:e1"]})
        case["messages"][-1]["content"] = json.dumps(good(case))
        answer = good(case)
        answer["claims"][0]["status"] = "inferred"  # Non-gate swaps affect neither numerator nor denominator.
        if status == "inferred":
            answer["claims"][2]["status"] = "confirmed"
        answers.append({"case_id": case["id"], "model_id": "m", "response": answer})
    cases_path = write_cases(tmp_path / "cases.jsonl", cases)
    responses = tmp_path / "responses.jsonl"
    responses.write_text("".join(json.dumps(answer) + "\n" for answer in answers))
    metrics = sac.checkpoint_metrics(evaluate_responses(cases_path, responses), cases, "m")
    assert metrics["applicability_errors"] == 1
    assert metrics["applicability_errors_rate"] == 0.5
    assert metrics["expected_answered_claims"] == 5


def test_metrics_count_schema_errors_overconfidence_and_over_abstention(tmp_path):
    cases = [make_case(f"case-{name}") for name in ("ok", "bold", "shy", "bad")]
    cases_path = write_cases(tmp_path / "cases.jsonl", cases)
    answers = {"case-ok": good(cases[0]), "case-bold": overconfident(cases[1]), "case-shy": over_abstaining(cases[2]),
               "case-bad": "```json\n{}\n```"}
    responses = tmp_path / "responses.jsonl"
    responses.write_text("".join(json.dumps(
        {"case_id": case["id"], "model_id": "m", "response": answers[case["id"]]}) + "\n" for case in cases), encoding="utf-8")
    evaluation = evaluate_responses(cases_path, responses)
    metrics = sac.checkpoint_metrics(evaluation, load_cases([cases_path]), "m")
    assert metrics["strict_pass_count"] == 1 and metrics["scored_cases"] == 4 and metrics["strict_pass_rate"] == 0.25
    assert metrics["schema_error_count"] == 1
    assert metrics["overconfidence"] == 1 and metrics["over_abstention"] == 1
    assert metrics["expected_unknown_claims"] == 4 and metrics["expected_answered_claims"] == 4
    assert metrics["overconfidence_rate"] == 0.25 and metrics["over_abstention_rate"] == 0.25
    assert metrics["missing_responses"] == 0
    assert metrics["issue_counts"]["response_schema_error"] == 1


def test_per_policy_denominators_include_missing_cases_and_only_approved_cases(tmp_path):
    cases = [make_case(name) for name in ("answered", "missing", "unscored", "other-policy")]
    for case in cases[:3]:
        prompt = json.loads(case["messages"][1]["content"])
        prompt["policy_id"] = "shared-policy"
        case["messages"][1]["content"] = json.dumps(prompt)
    cases.append(make_case("unreviewed", approved=False))
    cases_path = write_cases(tmp_path / "cases.jsonl", cases)
    responses = tmp_path / "responses.jsonl"
    responses.write_text("".join(json.dumps({"case_id": case["id"], "model_id": model,
                                             "response": good(case)}) + "\n"
                                 for model, subset in (("partial", [cases[0], cases[2], cases[4]]), ("full", cases))
                                 for case in subset), encoding="utf-8")
    evaluation = evaluate_responses(cases_path, responses)
    # An unscored row must still leave its approved case missing from the policy's scored coverage.
    unscored = next(row for row in evaluation["results"]
                    if row["model_id"] == "partial" and row["case_id"] == "unscored")
    unscored.update(scored=False, mechanical_pass=False)
    table = sac.per_policy_metrics(evaluation, cases, "partial")
    assert table == {
        "family-other-policy": {"rows": 1, "strict_pass": 0, "missing": 1, "strict_pass_rate": 0.0},
        "shared-policy": {"rows": 3, "strict_pass": 1, "missing": 2, "strict_pass_rate": 1 / 3},
    }
    metrics = sac.checkpoint_metrics(evaluation, cases, "partial")
    assert metrics["per_policy_count"] == 2
    assert metrics["per_policy_mean"] == pytest.approx(1 / 6)
    assert all(counts["missing"] == 0 for counts in sac.per_policy_metrics(evaluation, cases, "full").values())


@pytest.mark.parametrize("cases", [[], [make_case("unreviewed", approved=False)]])
def test_per_policy_mean_is_none_without_approved_cases(cases):
    evaluation = {"results": [], "model_scores": [{"model_id": "m", "approved_case_count": 0,
                                                   "mechanical_pass_count": 0, "missing_case_count": 0}]}
    assert sac.per_policy_metrics(evaluation, cases, "m") == {}
    metrics = sac.checkpoint_metrics(evaluation, cases, "m")
    assert metrics["per_policy_mean"] is None
    assert metrics["strict_pass_rate"] is None
    assert metrics["per_policy_count"] == 0
    assert metrics["applicability_errors_rate"] is None


@pytest.mark.parametrize("content", [
    "not JSON", "[]", "null", "42", '"text"', "true", "{}",
    '{"policy_id": null}', '{"policy_id": ""}', '{"policy_id": "   "}',
    '{"policy_id": 42}', '{"policy_id": true}', '{"policy_id": []}', '{"policy_id": {}}',
    None, {"policy_id": "unencoded"},
])
def test_policy_lookup_falls_back_to_family_for_invalid_user_content(content):
    case = make_case("fallback")
    case["messages"][1]["content"] = content
    table = sac.per_policy_metrics({"results": []}, [case], "m")
    assert table == {"family-fallback": {"rows": 1, "strict_pass": 0, "missing": 1, "strict_pass_rate": 0.0}}


@pytest.mark.parametrize("user_index", [0, 2])
def test_policy_lookup_uses_first_user_message_and_sorts_string_keys(user_index):
    case = make_case("lookup")
    user = {"role": "user", "content": '{"policy_id": "z-policy"}'}
    case["messages"] = [{"role": "system", "content": '{"policy_id": "wrong-system"}'} for _ in range(user_index)]
    case["messages"] += [user, {"role": "user", "content": '{"policy_id": "wrong-later-user"}'}]
    fallback = make_case("fallback")
    fallback["family"] = "a-family"
    fallback["messages"] = []
    table = sac.per_policy_metrics({"results": []}, [case, fallback], "m")
    assert list(table) == ["a-family", "z-policy"]
    assert all(isinstance(key, str) for key in table)


@pytest.mark.parametrize("scored", [False, True])
def test_metrics_count_rows_without_cases_and_skip_them_in_per_policy(tmp_path, scored):
    case = make_case("known")
    cases_path = write_cases(tmp_path / "cases.jsonl", [case])
    responses = tmp_path / "responses.jsonl"
    responses.write_text("".join(json.dumps({"case_id": case_id, "model_id": model, "response": good(case)}) + "\n"
                                 for model, case_id in (("m", "known"), ("m", "absent"), ("other", "also-absent"))),
                         encoding="utf-8")
    evaluation = evaluate_responses(cases_path, responses)
    absent = next(row for row in evaluation["results"] if row["case_id"] == "absent")
    absent.update(scored=scored, mechanical_pass=True)
    metrics = sac.checkpoint_metrics(evaluation, [case], "m")
    assert type(metrics["rows_without_case"]) is int
    assert metrics["rows_without_case"] == 1
    assert metrics["per_policy_count"] == 1 and metrics["per_policy_mean"] == 1.0
    assert sac.per_policy_metrics(evaluation, [case], "m") == {
        "family-known": {"rows": 1, "strict_pass": 1, "missing": 0, "strict_pass_rate": 1.0},
    }


def test_checkpoint_metrics_accepts_precomputed_empty_policy_table(monkeypatch):
    evaluation = {"results": [], "model_scores": [{"model_id": "m", "approved_case_count": 0,
                                                   "mechanical_pass_count": 0, "missing_case_count": 0}]}

    def unexpected_recompute(*args):
        pytest.fail("a supplied empty policy table must not be recomputed")

    monkeypatch.setattr(sac, "per_policy_metrics", unexpected_recompute)
    metrics = sac.checkpoint_metrics(evaluation, [], "m", per_policy={})
    assert metrics["per_policy_mean"] is None and metrics["per_policy_count"] == 0


def test_per_policy_metrics_and_overconfidence_use_real_evaluator_without_changing_ranking(tmp_path, monkeypatch):
    cases = [make_case(f"case-{index}") for index in range(6)]
    for case, policy in zip(cases, ["policy-a"] * 3 + ["policy-b"] * 2):
        prompt = json.loads(case["messages"][1]["content"])
        prompt["policy_id"] = policy
        case["messages"][1]["content"] = json.dumps(prompt)
    cases[-1]["family"] = "immutable-tenant-identity"
    cases_path = write_cases(tmp_path / "scored-cases.jsonl", cases)
    answers = {model: [good(case) for case in cases] for model in ("model-25", "model-50")}
    # Both models make one confirmed and one inferred assertion where the rubric requires unknown.
    for model, indices in (("model-25", (3, 4)), ("model-50", (0, 1))):
        for index, status in zip(indices, ("confirmed", "inferred")):
            answers[model][index]["claims"][1].update(status=status, value=True)
    answers["model-25"][5] = "invalid JSON"
    answers["model-50"][3]["limitations"] = []
    responses = tmp_path / "responses.jsonl"
    responses.write_text("".join(json.dumps({"case_id": case["id"], "model_id": model, "response": answer}) + "\n"
                                 for model, model_answers in answers.items()
                                 for case, answer in zip(cases, model_answers)), encoding="utf-8")
    evaluation = evaluate_responses(cases_path, responses)
    direct_metrics = {model: sac.checkpoint_metrics(evaluation, load_cases([cases_path]), model) for model in answers}
    run = {
        "base_model": BASE, "base_revision": REVISION,
        "checkpoints": [{"name": f"checkpoint-{step}", "step": step, "model_id": f"model-{step}",
                         "path": str(tmp_path / f"checkpoint-{step}")} for step in (25, 50)],
        "generation": {"limit": None}, "cases": {}, "runtime": {},
    }
    policy_calls = []
    computed_tables = {}
    original_per_policy = sac.per_policy_metrics
    original_metrics = sac.checkpoint_metrics

    def tracked_per_policy(evaluation, cases, model_id):
        policy_calls.append(model_id)
        computed_tables[model_id] = original_per_policy(evaluation, cases, model_id)
        return computed_tables[model_id]

    def checked_metrics(evaluation, cases, model_id, per_policy=None):
        assert per_policy is computed_tables[model_id]
        return original_metrics(evaluation, cases, model_id, per_policy=per_policy)

    monkeypatch.setattr(sac, "per_policy_metrics", tracked_per_policy)
    monkeypatch.setattr(sac, "checkpoint_metrics", checked_metrics)
    sac.evaluate_and_select(tmp_path, load_cases([cases_path]), run)
    assert sorted(policy_calls) == sorted(answers)
    evaluation = json.loads((tmp_path / "evaluation.json").read_text())
    selection = json.loads((tmp_path / "selection.json").read_text())
    assert evaluation["per_policy"] == {
        "model-25": {
            "policy-a": {"rows": 3, "strict_pass": 3, "missing": 0, "strict_pass_rate": 1.0},
            "policy-b": {"rows": 2, "strict_pass": 0, "missing": 0, "strict_pass_rate": 0.0},
            "immutable-tenant-identity": {"rows": 1, "strict_pass": 0, "missing": 0, "strict_pass_rate": 0.0},
        },
        "model-50": {
            "policy-a": {"rows": 3, "strict_pass": 1, "missing": 0, "strict_pass_rate": 1 / 3},
            "policy-b": {"rows": 2, "strict_pass": 1, "missing": 0, "strict_pass_rate": 1 / 2},
            "immutable-tenant-identity": {"rows": 1, "strict_pass": 1, "missing": 0, "strict_pass_rate": 1.0},
        },
    }
    for checkpoint, mean in zip(selection["checkpoints"], (1 / 3, (1 / 3 + 1 / 2 + 1) / 3)):
        metrics = direct_metrics[checkpoint["model_id"]]
        assert all(checkpoint[key] == value for key, value in metrics.items())
        assert checkpoint["overconfidence"] == 2 and checkpoint["overconfidence_rate"] == 2 / 6
        assert checkpoint["over_abstention"] == 0
        assert checkpoint["strict_pass_count"] == 3 and checkpoint["strict_pass_rate"] == 0.5
        assert checkpoint["per_policy_count"] == 3
        assert isinstance(checkpoint["per_policy_mean"], float)
        assert checkpoint["per_policy_mean"] == pytest.approx(mean)
    assert selection["selected"] == "checkpoint-25"
    assert selection["ranking"] == ["checkpoint-25", "checkpoint-50"]
    assert selection["tied_with"] == ["checkpoint-50"]
    assert selection["selection_rule"]["order"] == [
        "applicability_errors asc", "strict_pass_count desc", "overconfidence asc", "over_abstention asc",
        "step asc", "name asc",
    ]
    assert selection["selection_rule"]["version"] == "2026-10-27"
    assert "claims expected unknown answered confirmed or inferred" in selection["selection_rule"]["description"]
    assert "per_policy_mean" in selection["selection_rule"]["description"]


# --- end to end with the stub generator ---------------------------------------------------------------------

@pytest.mark.parametrize("base_passes", [None, 7])
def test_selection_bundle_records_band_and_warns_when_applicability_changes_the_winner(tmp_path, base_passes):
    cases = [make_case(f"gate-{index}", unknown_claim=False) for index in range(10)]
    for case in cases:
        case["expected"]["claims"][0]["id"] = "requirement_met"
        case["messages"][-1]["content"] = json.dumps(good(case))
    cases_path = write_cases(tmp_path / "cases.jsonl", cases)
    root = tmp_path / "run"
    answers = {}
    for name in ("checkpoint-125", "checkpoint-150"):
        make_checkpoint(root, name)
        answers[name] = {case["id"]: good(case) for case in cases}
    answers["checkpoint-125"][cases[0]["id"]]["claims"][0]["status"] = "inferred"
    for case in cases[:2]:
        answers["checkpoint-150"][case["id"]]["limitations"] = []
    if base_passes is not None:
        make_checkpoint(root, "checkpoint-0")
        answers["checkpoint-0"] = {case["id"]: good(case) for case in cases}
        for case in cases[base_passes:]:
            answers["checkpoint-0"][case["id"]]["limitations"] = []
    code, out = run_main(tmp_path, cases_path, root, StubBackend(answers))
    assert code == 0
    selection = json.loads((out / "selection.json").read_text())
    assert selection["schema_version"] == "2026-10-27"
    assert selection["selection_rule"]["metric"] == (
        "strict_pass_count within a noise band, applicability errors first, base floor")
    assert selection["base_strict_pass_count"] == base_passes
    assert selection["base_floor_applied"] is (base_passes is not None)
    assert selection["selected"] == "checkpoint-150"
    assert selection["selected_by_strict_first"] == "checkpoint-125"
    assert selection["band_width"] == 2 and selection["best_strict_pass_count"] == 9
    assert selection["band_members"] == ["checkpoint-150", "checkpoint-125"]
    expected_ranking = ["checkpoint-150", "checkpoint-125"] + (["checkpoint-0"] if base_passes is not None else [])
    assert selection["ranking"] == [item["name"] for item in selection["checkpoints"]] == expected_ranking
    assert len(selection["warnings"]) == 1 and "strict-first" in selection["warnings"][0]
    by_name = {item["name"]: item for item in selection["checkpoints"]}
    assert by_name["checkpoint-125"]["applicability_errors"] == 1
    assert by_name["checkpoint-125"]["applicability_errors_rate"] == 0.1
    assert by_name["checkpoint-150"]["applicability_errors"] == 0


@pytest.mark.parametrize("fix_mistral_regex", [False, True])
def test_end_to_end_ranks_checkpoints_by_generated_answers_and_writes_the_bundle(tmp_path, held_out, fix_mistral_regex):
    cases, cases_path = held_out
    root = tmp_path / "run"
    for name in ("checkpoint-100", "checkpoint-25", "checkpoint-50"):
        make_checkpoint(root, name)
    (root / "adapter").mkdir()  # not a checkpoint-<step> directory: ignored by discovery
    fenced = {case["id"]: "```json\n" + json.dumps(good(case)) + "\n```" for case in cases}
    one_bad = {case["id"]: good(case) for case in cases} | {"case-0": overconfident(cases[0])}
    answers = {"checkpoint-25": one_bad, "checkpoint-50": {case["id"]: good(case) for case in cases},
               "checkpoint-100": fenced}
    backend = StubBackend(answers)
    backend.describe = lambda: {"backend": "stub", "tokenizer_fix_mistral_regex": fix_mistral_regex}
    code, out = run_main(tmp_path, cases_path, root, backend)
    assert code == 0
    # Natural step order, one adapter at a time, always unloaded again.
    assert [event[:2] for event in backend.events if event[0] != "generate"] == [
        ("load", "checkpoint-25"), ("unload", "checkpoint-25"), ("load", "checkpoint-50"), ("unload", "checkpoint-50"),
        ("load", "checkpoint-100"), ("unload", "checkpoint-100")]
    assert all(event[2] == [f"PROMPT[case-{i}]" for i in range(5)] for event in backend.events if event[0] == "generate")
    assert sorted(path.name for path in out.iterdir()) == [
        "evaluation.json", "generations.jsonl", "responses.jsonl", "scored-cases.jsonl", "selection.json"]
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in out.iterdir())

    rows = [json.loads(line) for line in (out / "responses.jsonl").read_text().splitlines()]
    assert len(rows) == 15 and all(set(row) == {"case_id", "model_id", "response"} for row in rows)
    assert {row["model_id"] for row in rows} == {f"{BASE}@{REVISION}+checkpoint-{n}" for n in (25, 50, 100)}
    row = next(item for item in rows if item["model_id"].endswith("checkpoint-50") and item["case_id"] == "case-2")
    assert row["response"] == good(cases[2])
    fenced_row = next(item for item in rows if item["model_id"].endswith("checkpoint-100") and item["case_id"] == "case-2")
    assert isinstance(fenced_row["response"], str) and fenced_row["response"].startswith("```json")

    evaluation = json.loads((out / "evaluation.json").read_text())
    assert evaluation["tokenizer_fix_mistral_regex"] is fix_mistral_regex
    assert {item["model_id"] for item in evaluation["model_scores"]} == {row["model_id"] for row in rows}
    assert evaluation["missing_responses"] == [] and evaluation["invalid_records"] == []

    selection = json.loads((out / "selection.json").read_text())
    assert selection["tokenizer_fix_mistral_regex"] is fix_mistral_regex
    assert selection["runtime"]["tokenizer_fix_mistral_regex"] is fix_mistral_regex
    assert selection["selected"] == "checkpoint-50" and selection["gate"] == "G3"
    assert selection["selected_model_id"] == f"{BASE}@{REVISION}+checkpoint-50"
    assert selection["ranking"] == ["checkpoint-50", "checkpoint-25", "checkpoint-100"]
    assert selection["selection_rule"]["never_by"] == "eval_loss" and selection["smoke"] is False
    by_name = {item["name"]: item for item in selection["checkpoints"]}
    assert by_name["checkpoint-50"]["strict_pass_rate"] == 1.0 and by_name["checkpoint-50"]["schema_error_count"] == 0
    assert by_name["checkpoint-25"]["strict_pass_count"] == 4 and by_name["checkpoint-25"]["overconfidence"] == 1
    assert by_name["checkpoint-100"]["strict_pass_count"] == 0 and by_name["checkpoint-100"]["schema_error_count"] == 5
    assert by_name["checkpoint-100"]["strict_json_failures"] == 5
    assert by_name["checkpoint-50"]["seconds_per_case"] >= 0 and len(by_name["checkpoint-50"]["adapter_weights_sha256"]) == 64
    assert selection["cases"]["splits_scored"] == {"test": 2, "validation": 3}
    assert selection["generation"]["do_sample"] is False and selection["generation"]["enable_thinking"] is False
    assert selection["generation"]["max_new_tokens"] == 512
    traces = [json.loads(line) for line in (out / "generations.jsonl").read_text().splitlines()]
    assert len(traces) == 15 and sum(not trace["strict_json"] for trace in traces) == 5


def test_adapter_is_unloaded_even_when_generation_fails(tmp_path, held_out):
    cases, cases_path = held_out
    root = tmp_path / "run"
    make_checkpoint(root, "checkpoint-25")
    backend = StubBackend({"checkpoint-25": {case["id"]: good(case) for case in cases}}, fail_on="checkpoint-25")
    with pytest.raises(RuntimeError, match="stub generation failure"):
        run_main(tmp_path, cases_path, root, backend)
    assert [event[:2] for event in backend.events if event[0] != "generate"] == [
        ("load", "checkpoint-25"), ("unload", "checkpoint-25")]


def test_only_approved_held_out_cases_are_generated_for(tmp_path):
    cases = [make_case("case-train", split="train"), make_case("case-val"), make_case("case-test", split="test"),
             make_case("case-draft", approved=False)]
    cases_path = write_cases(tmp_path / "cases.jsonl", cases)
    root = tmp_path / "run"
    make_checkpoint(root, "checkpoint-25")
    answers = {"checkpoint-25": {case["id"]: good(case) for case in cases}}
    backend = StubBackend(answers)
    code, out = run_main(tmp_path, cases_path, root, backend)
    assert code == 0
    assert [event[2] for event in backend.events if event[0] == "generate"] == [["PROMPT[case-val]", "PROMPT[case-test]"]]
    selection = json.loads((out / "selection.json").read_text())
    assert selection["cases"]["skipped_unreviewed"] == 1 and selection["cases"]["scored"] == 2
    # The evaluator sees only the scored cases, so nothing is reported missing or quarantined.
    evaluation = json.loads((out / "evaluation.json").read_text())
    assert evaluation["case_count"] == 2 and evaluation["missing_responses"] == []


def test_splits_option_restricts_to_validation_and_train_needs_asking_for(tmp_path, held_out):
    cases, cases_path = held_out
    root = tmp_path / "run"
    make_checkpoint(root, "checkpoint-25")
    backend = StubBackend({"checkpoint-25": {case["id"]: good(case) for case in cases}})
    code, out = run_main(tmp_path, cases_path, root, backend, "--splits", "validation")
    assert code == 0
    assert json.loads((out / "selection.json").read_text())["cases"]["splits_scored"] == {"validation": 3}
    train_only = write_cases(tmp_path / "train.jsonl", [make_case("case-t", split="train")])
    code, _ = run_main(tmp_path, train_only, root, backend, output="out-train")
    assert code == 2 and not (tmp_path / "out-train").exists()


def test_limit_marks_the_result_as_a_smoke(tmp_path, held_out):
    cases, cases_path = held_out
    root = tmp_path / "run"
    make_checkpoint(root, "checkpoint-25")
    backend = StubBackend({"checkpoint-25": {case["id"]: good(case) for case in cases}})
    code, out = run_main(tmp_path, cases_path, root, backend, "--limit", "2")
    assert code == 0
    selection = json.loads((out / "selection.json").read_text())
    assert selection["smoke"] is True and selection["cases"]["scored"] == 2
    assert any("smoke" in warning for warning in selection["warnings"])


def test_existing_output_directory_is_refused_before_anything_loads(tmp_path, held_out, capsys):
    cases, cases_path = held_out
    root = tmp_path / "run"
    make_checkpoint(root, "checkpoint-25")
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "keep.txt").write_text("existing", encoding="utf-8")
    backend = StubBackend({"checkpoint-25": {case["id"]: good(case) for case in cases}})
    code, out = run_main(tmp_path, cases_path, root, backend)
    assert code == 2 and "already exists" in capsys.readouterr().err
    assert run_main.backend_built is False and backend.events == []
    assert [path.name for path in out.iterdir()] == ["keep.txt"]


def test_unusable_checkpoint_directories_are_refused(tmp_path, held_out, capsys):
    cases, cases_path = held_out
    answers = {"checkpoint-25": {case["id"]: good(case) for case in cases}}
    # Trained from another revision.
    wrong = tmp_path / "wrong"
    make_checkpoint(wrong, "checkpoint-25", revision="1" * 40)
    code, out = run_main(tmp_path, cases_path, wrong, StubBackend(answers))
    assert code == 2 and "another base model or revision" in capsys.readouterr().err and not out.exists()
    # Not an adapter directory.
    empty = tmp_path / "empty"
    (empty / "checkpoint-25").mkdir(parents=True)
    code, _ = run_main(tmp_path, cases_path, empty, StubBackend(answers), output="out2")
    assert code == 2 and "not an adapter checkpoint" in capsys.readouterr().err
    # A root with no checkpoint-<step> directories.
    code, _ = run_main(tmp_path, cases_path, tmp_path / "empty", StubBackend(answers), output="out3")
    assert code == 2
    code, _ = run_main(tmp_path, cases_path, tmp_path / "missing", StubBackend(answers), output="out4")
    assert code == 2 and "not a directory" in capsys.readouterr().err


def test_explicit_checkpoints_combine_with_a_root_and_names_must_be_unique(tmp_path, held_out, capsys):
    cases, cases_path = held_out
    root = tmp_path / "run"
    make_checkpoint(root, "checkpoint-25")
    final = make_checkpoint(tmp_path / "final", "adapter")
    other = make_checkpoint(tmp_path / "other", "adapter")
    answers = {name: {case["id"]: good(case) for case in cases} for name in ("checkpoint-25", "adapter")}
    backend = StubBackend(answers)
    code, out = run_main(tmp_path, cases_path, root, backend, "--checkpoint", str(final), "--checkpoint", str(root / "checkpoint-25"))
    assert code == 0  # a path given twice is scored once
    assert [event[1] for event in backend.events if event[0] == "load"] == ["checkpoint-25", "adapter"]
    assert json.loads((out / "selection.json").read_text())["selected"] == "checkpoint-25"  # tie: numbered step first
    tied = json.loads((out / "selection.json").read_text())["warnings"]
    assert any("checkpoint-25 is tied with adapter" in warning for warning in tied)
    code, _ = run_main(tmp_path, cases_path, root, StubBackend(answers), "--checkpoint", str(final), "--checkpoint", str(other),
                       output="out-dup")
    assert code == 2 and "two checkpoints are named adapter" in capsys.readouterr().err


@pytest.mark.parametrize("extra", [["--limit", "0"], ["--batch-size", "0"], ["--max-new-tokens", "-1"],
                                   ["--splits", "everything"]])
def test_invalid_numeric_and_split_options_are_rejected(tmp_path, held_out, extra):
    cases, cases_path = held_out
    root = tmp_path / "run"
    make_checkpoint(root, "checkpoint-25")
    backend = StubBackend({"checkpoint-25": {case["id"]: good(case) for case in cases}})
    try:
        code, out = run_main(tmp_path, cases_path, root, backend, *extra)
    except SystemExit as exc:  # argparse rejects an unknown --splits choice
        code, out = exc.code, tmp_path / "out"
    assert code == 2 and not out.exists() and backend.events == []


def test_base_model_and_revision_must_be_pinned(tmp_path, held_out, capsys):
    _, cases_path = held_out
    root = tmp_path / "run"
    make_checkpoint(root, "checkpoint-25")
    for base, revision in (("/local/path/model", REVISION), (BASE, "main")):
        code = sac.main(["--base-model", base, "--revision", revision, "--checkpoints-root", str(root),
                         "--cases", str(cases_path), "--output-dir", str(tmp_path / "pinned")],
                        backend_factory=lambda args: None)
        assert code == 2 and not (tmp_path / "pinned").exists()
    assert "40-character" in capsys.readouterr().err


# --- command line ---------------------------------------------------------------------------------------------

def test_help_and_import_need_neither_torch_nor_a_gpu():
    help_run = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True, timeout=60)
    assert help_run.returncode == 0
    for flag in ("--base-model", "--revision", "--checkpoints-root", "--checkpoint", "--cases", "--output-dir", "--device",
                 "--max-new-tokens", "--batch-size", "--limit", "--dtype"):
        assert flag in help_run.stdout
    probe = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('sac', {str(SCRIPT)!r})\n"
        "module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)\n"
        "print(sorted(name for name in ('torch', 'transformers', 'peft') if name in sys.modules))\n"
    )
    imported = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=60)
    assert imported.returncode == 0, imported.stderr
    assert imported.stdout.strip() == "[]"
