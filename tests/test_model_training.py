"""Synthetic curation and recipe checks; no models, GPUs or teacher calls."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from auditex.model_training import (
    _load_text_model,
    _measure_training_tokens,
    _record_checkpoint_input,
    _validate_resume_input,
    load_cases,
    prepare_training_pack,
    training_main,
    validate_case,
    validate_cases,
    validate_training_pack,
)

REVISION = "1" * 40


def _case(case_id: str, split: str = "train", *, approved: bool = True) -> dict:
    response = {
        "claims": [{"id": "count", "status": "confirmed", "evidence_ids": ["E1"], "value": 2}],
        "limitations": ["effective_sign_in_not_collected"], "recommendations": ["review_authentication"],
    }
    return {
        "id": case_id, "family": f"family-{case_id}", "split": split,
        "provenance": {"source": "synthetic unit-test fixture", "synthetic": True,
                       "review_status": "approved" if approved else "unreviewed", "reviewer": "unit-test-only"},
        "messages": [{"role": "user", "content": f"Case {case_id}: E1 records two privileged users. Explain the evidence."},
                     {"role": "assistant", "content": json.dumps(response)}],
        "expected": {**response, "allowed_evidence_ids": ["E1"]},
    }


def _write_cases(path: Path, cases: list[dict]) -> Path:
    path.write_text("".join(json.dumps(case) + "\n" for case in cases), encoding="utf-8")
    return path


def _ready_pack(tmp_path: Path) -> Path:
    source = _write_cases(tmp_path / "cases.jsonl", [_case("train"), _case("validation", "validation"), _case("test", "test")])
    output = tmp_path / "pack"
    prepare_training_pack(source, output, revision=REVISION)
    return output


def test_pack_separates_approved_splits_and_quarantines_proposed_labels(tmp_path: Path) -> None:
    cases = [_case("train"), _case("validation", "validation"), _case("test", "test"), _case("proposal", approved=False)]
    source = _write_cases(tmp_path / "cases.jsonl", cases)
    original = source.read_bytes()
    output = tmp_path / "pack"

    manifest = prepare_training_pack(source, output, revision=REVISION)

    assert manifest["counts"] == {"train": 1, "validation": 1, "test": 1, "quarantined": 1}
    assert manifest["job_ready"] is True
    assert manifest["runtime_qualification"].startswith("pending")
    assert manifest["token_budget"]["training_tokens"] is None
    assert manifest["token_budget"]["gpu_hours"] is None
    assert manifest["one_base_model"] is True and manifest["weight_merging"] is False
    assert manifest["sources"][0]["sha256"] == hashlib.sha256(original).hexdigest()
    train = [json.loads(line) for line in (output / "train.jsonl").read_text().splitlines()]
    assert set(train[0]) == {"prompt", "completion"}
    assert train[0]["prompt"] == cases[0]["messages"][:-1]
    assert train[0]["completion"] == [cases[0]["messages"][-1]]
    assert load_cases(output / "test.jsonl") == [cases[2]]
    assert load_cases(output / "quarantine.jsonl") == [cases[3]]
    assert source.read_bytes() == original
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    assert validate_training_pack(output)[0] == manifest


def test_unreviewed_only_pack_is_inspectable_but_cannot_load_training_runtime(tmp_path: Path) -> None:
    source = _write_cases(tmp_path / "cases.jsonl", [_case("proposal", approved=False)])
    output = tmp_path / "pack"
    manifest = prepare_training_pack(source, output)

    assert manifest["job_ready"] is False
    assert manifest["counts"]["quarantined"] == 1
    assert "immutable_base_revision_missing" in manifest["blocked_reasons"]
    assert (output / "train.jsonl").read_text() == ""
    assert (output / "train_lora.py").is_file()
    assert (output / "jupiter-auditex.sbatch").is_file()
    with pytest.raises(ValueError, match="not ready"):
        training_main(["--pack-dir", str(output), "--output-dir", str(tmp_path / "training-output")])
    assert not (tmp_path / "training-output").exists()


def test_ready_pack_still_requires_explicit_runtime_qualification_before_imports(tmp_path: Path) -> None:
    output = _ready_pack(tmp_path)
    with pytest.raises(ValueError, match="runtime-qualified"):
        training_main(["--pack-dir", str(output), "--output-dir", str(tmp_path / "training-output")])


def test_resume_cannot_mix_a_checkpoint_from_another_pack_before_runtime_imports(tmp_path: Path, monkeypatch) -> None:
    pack = _ready_pack(tmp_path)
    output = tmp_path / "training-output"
    checkpoint = output / "checkpoint-25"
    checkpoint.mkdir(parents=True)
    (output / "auditex-training-input.json").write_text(json.dumps({
        "base_model": "another/model", "base_revision": REVISION, "pack_manifest_sha256": "0" * 64,
    }))
    for name in ("HF_HOME", "XDG_CACHE_HOME", "TORCH_HOME", "TRITON_CACHE_DIR", "TMPDIR"):
        monkeypatch.setenv(name, str(tmp_path / "cache"))
    with pytest.raises(ValueError, match="another base model or data pack"):
        training_main(["--pack-dir", str(pack), "--output-dir", str(output),
                       "--resume-from-checkpoint", str(checkpoint), "--runtime-qualified"])


@pytest.mark.parametrize("checkpoint_identity", ["foreign", "missing"])
def test_matching_run_directory_cannot_hide_foreign_or_unbound_checkpoint(
    tmp_path: Path, monkeypatch, checkpoint_identity: str,
) -> None:
    pack = _ready_pack(tmp_path)
    output = tmp_path / "training-output"
    checkpoint = output / "checkpoint-25"
    checkpoint.mkdir(parents=True)
    identity = {
        "base_model": "Qwen/Qwen3.8-27B", "base_revision": REVISION,
        "pack_manifest_sha256": hashlib.sha256((pack / "manifest.json").read_bytes()).hexdigest(),
    }
    (output / "auditex-training-input.json").write_text(json.dumps(identity))
    if checkpoint_identity == "foreign":
        foreign = {**identity, "pack_manifest_sha256": "0" * 64}
        _record_checkpoint_input(output, 25, foreign)
    for name in ("HF_HOME", "XDG_CACHE_HOME", "TORCH_HOME", "TRITON_CACHE_DIR", "TMPDIR"):
        monkeypatch.setenv(name, str(tmp_path / "cache"))

    with pytest.raises(ValueError, match="another base model or data pack|selected checkpoint"):
        training_main(["--pack-dir", str(pack), "--output-dir", str(output),
                       "--resume-from-checkpoint", str(checkpoint), "--runtime-qualified"])


def test_saved_checkpoint_identity_survives_a_matching_resume(tmp_path: Path) -> None:
    output = tmp_path / "training-output"
    checkpoint = output / "checkpoint-25"
    checkpoint.mkdir(parents=True)
    identity = {"base_model": "owner/base", "base_revision": REVISION, "pack_manifest_sha256": "a" * 64}
    (output / "auditex-training-input.json").write_text(json.dumps(identity))
    _record_checkpoint_input(output, 25, identity)

    _validate_resume_input(output, checkpoint, identity)
    assert json.loads((checkpoint / "auditex-training-input.json").read_text()) == identity


@pytest.mark.parametrize("via_symlink", [False, True])
def test_training_output_cannot_enter_a_finalized_audit_bundle_before_runtime_imports(
    tmp_path: Path, monkeypatch, via_symlink: bool,
) -> None:
    pack = _ready_pack(tmp_path)
    run_dir = tmp_path / "finalized-run"
    run_dir.mkdir()
    marker = run_dir / "run-manifest.json"
    marker.write_text('{}\n', encoding="utf-8")
    selected = run_dir
    if via_symlink:
        selected = tmp_path / "run-link"
        selected.symlink_to(run_dir, target_is_directory=True)
    output = selected / "reports" / "new-checkpoints"
    for name in ("HF_HOME", "XDG_CACHE_HOME", "TORCH_HOME", "TRITON_CACHE_DIR", "TMPDIR"):
        monkeypatch.setenv(name, str(tmp_path / "cache"))

    with pytest.raises(ValueError, match="outside finalized audit runs"):
        training_main(["--pack-dir", str(pack), "--output-dir", str(output), "--runtime-qualified"])
    assert not output.exists()
    assert marker.read_text(encoding="utf-8") == '{}\n'


@pytest.mark.parametrize("revision", ["main", "latest", "abc123", "../local", ["1" * 40]])
def test_mutable_or_malformed_base_revision_is_rejected_without_output(tmp_path: Path, revision) -> None:
    source = _write_cases(tmp_path / "cases.jsonl", [_case("train")])
    with pytest.raises(ValueError, match="immutable"):
        prepare_training_pack(source, tmp_path / "pack", revision=revision)
    assert not (tmp_path / "pack").exists()


@pytest.mark.parametrize("kind", ["id", "family", "prompt"])
def test_cross_split_leakage_and_duplicate_ids_are_rejected(kind: str) -> None:
    first = _case("a")
    second = _case("b", "test")
    if kind == "id":
        second["id"] = first["id"]
    elif kind == "family":
        second["family"] = first["family"].upper()
    else:
        second["messages"][0]["content"] = "  " + first["messages"][0]["content"].upper().replace(" ", "\n ")
    with pytest.raises(ValueError, match="duplicate|leakage"):
        validate_cases([first, second])


def test_approved_answer_must_match_typed_expected_facts() -> None:
    case = _case("a")
    answer = json.loads(case["messages"][-1]["content"])
    answer["claims"][0]["value"] = 2.0
    case["messages"][-1]["content"] = json.dumps(answer)
    with pytest.raises(ValueError, match="conflicts"):
        validate_case(case)


@pytest.mark.parametrize("mismatch", ["claim_id_whitespace", "signed_zero"])
def test_preparation_cannot_approve_a_target_that_fails_evaluator_identity(mismatch: str) -> None:
    case = _case("a")
    answer = json.loads(case["messages"][-1]["content"])
    if mismatch == "claim_id_whitespace":
        answer["claims"][0]["id"] = " count "
    else:
        case["expected"]["claims"][0]["value"] = 0.0
        answer["claims"][0]["value"] = -0.0
    case["messages"][-1]["content"] = json.dumps(answer)
    with pytest.raises(ValueError, match="conflicts"):
        validate_case(case)


def test_approved_case_requires_a_named_reviewer() -> None:
    case = _case("a")
    del case["provenance"]["reviewer"]
    with pytest.raises(ValueError, match="approved case reviewer"):
        validate_case(case)
    case["provenance"]["review_status"] = "unreviewed"
    assert validate_case(case) == case


def test_approved_answer_may_reorder_evidence_and_gap_ids() -> None:
    case = _case("a")
    case["expected"]["allowed_evidence_ids"].append("E2")
    case["expected"]["claims"][0]["evidence_ids"].append("E2")
    case["expected"]["limitations"].append("policy_not_collected")
    answer = {key: copy.deepcopy(case["expected"][key]) for key in ("claims", "limitations", "recommendations")}
    answer["claims"][0]["evidence_ids"].reverse()
    answer["limitations"].reverse()
    case["messages"][-1]["content"] = json.dumps(answer)
    assert validate_case(case) == case


def test_case_local_evidence_allowlist_rejects_unrelated_reference() -> None:
    case = _case("a")
    case["expected"]["claims"][0]["evidence_ids"] = ["OTHER-TENANT-E1"]
    with pytest.raises(ValueError, match="allowlist"):
        validate_case(case)


def test_identical_training_prompt_cannot_teach_conflicting_approved_answers() -> None:
    first = _case("a")
    second = _case("b")
    second["messages"][0]["content"] = first["messages"][0]["content"]
    second["expected"]["claims"][0]["value"] = 3
    second["messages"][-1]["content"] = json.dumps({
        key: second["expected"][key] for key in ("claims", "limitations", "recommendations")
    })
    with pytest.raises(ValueError, match="conflicting labels"):
        validate_cases([first, second])


@pytest.mark.parametrize("field", ["split", "review_status", "status", "role"])
def test_untrusted_membership_fields_raise_value_error(field: str) -> None:
    case = _case("a")
    if field == "split":
        case[field] = []
    elif field == "review_status":
        case["provenance"][field] = {}
    elif field == "status":
        case["expected"]["claims"][0][field] = []
    else:
        case["messages"][0][field] = {}
    with pytest.raises(ValueError):
        validate_case(case)


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "bad.jsonl"
    source.write_text('{"id":"first","id":"second"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_cases(source)


def test_pack_refuses_overwrite_and_detects_tampered_training_rows(tmp_path: Path) -> None:
    output = _ready_pack(tmp_path)
    with pytest.raises(ValueError, match="new or empty"):
        prepare_training_pack(tmp_path / "cases.jsonl", output, revision=REVISION)
    with (output / "train.jsonl").open("a", encoding="utf-8") as stream:
        stream.write('{}\n')
    with pytest.raises(ValueError, match="hash mismatch"):
        validate_training_pack(output)


def test_recipe_is_completion_only_offline_and_records_candidate_stack(tmp_path: Path) -> None:
    output = _ready_pack(tmp_path)
    config = json.loads((output / "training-config.json").read_text())
    assert config["sft"]["completion_only_loss"] is True
    assert config["sft"]["bf16"] is True
    assert config["sft"]["gradient_checkpointing"] is True
    assert config["sft"]["max_steps"] == 100
    assert config["sft"]["report_to"] == "none"
    assert config["local_files_only"] is True and config["trust_remote_code"] is False
    assert config["runtime_package_candidates"]["trl"] == "1.16.0"
    script = (output / "jupiter-auditex.sbatch").read_text()
    assert "--nproc_per_node=4" in script and "--resume-from-checkpoint" in script
    assert "pip install" not in script and "sbatch --account=ACCOUNT" in script
    subprocess.run(["bash", "-n", str(output / "jupiter-auditex.sbatch")], check=True, capture_output=True)


def test_qwen_multimodal_config_uses_text_model_and_rejects_incomplete_loading() -> None:
    calls = []
    model = SimpleNamespace()
    loading = {"missing_keys": [], "unexpected_keys": ["model.visual.weight"]}

    class _Loader:
        @staticmethod
        def from_pretrained(snapshot, **kwargs):
            calls.append((snapshot, kwargs))
            return model, loading

    runtime = SimpleNamespace(
        AutoConfig=SimpleNamespace(from_pretrained=lambda *args, **kwargs: SimpleNamespace(model_type="qwen3_5")),
        Qwen3_5TextConfig=SimpleNamespace(from_pretrained=lambda *args, **kwargs: "text_config"),
        Qwen3_5ForCausalLM=_Loader,
    )
    assert _load_text_model("staged", torch=SimpleNamespace(bfloat16="bf16"), transformers=runtime) is model
    assert calls[0][1]["config"] == "text_config"
    assert calls[0][1]["key_mapping"] == {r"^model\.language_model\.": "model."}
    assert calls[0][1]["local_files_only"] is True
    loading["missing_keys"] = ["model.layers.0.weight"]
    with pytest.raises(ValueError, match="did not load completely"):
        _load_text_model("staged", torch=SimpleNamespace(bfloat16="bf16"), transformers=runtime)


def test_actual_tokenizer_preflight_excludes_test_and_refuses_silent_truncation() -> None:
    cases = [_case("train"), _case("validation", "validation"), _case("test", "test")]
    seen = []

    class _Tokenizer:
        def apply_chat_template(self, messages, **kwargs):
            seen.append(messages[0]["content"])
            return list(range(10))

    measured = _measure_training_tokens(cases, _Tokenizer(), 20)
    assert measured["tokens_per_pass"] == {"train": 10, "validation": 10}
    assert len(seen) == 2 and not any("Case test:" in prompt for prompt in seen)
    with pytest.raises(ValueError, match="instead of truncating"):
        _measure_training_tokens(cases, _Tokenizer(), 5)
