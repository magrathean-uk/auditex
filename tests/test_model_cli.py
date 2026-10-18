from __future__ import annotations

import json
from pathlib import Path

from auditex.cli import main


EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "model_development"
REVISION = "1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0"


def test_model_catalogue_is_pinned_without_runtime_execution(capsys):
    assert main(["model", "sources"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["tenant_access"] is result["inference_executed"] is result["training_executed"] is False
    assert all(len(source["revision"]) == 40 for source in result["sources"])
    assert {source["role"] for source in result["sources"]} >= {"proposed_single_training_base", "unreviewed_reference_conversations"}


def test_prepare_example_cases_does_not_invent_approval(tmp_path, capsys):
    destination = tmp_path / "pack"
    assert main(["model", "prepare", "--cases", str(EXAMPLES / "cases.jsonl"), "--output-dir", str(destination), "--revision", REVISION]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["counts"] == {"train": 0, "validation": 0, "test": 0, "quarantined": 48}
    assert result["job_ready"] is False
    assert result["token_budget"]["gpu_hours"] is None
    assert (destination / "jupiter-auditex.sbatch").is_file()
    assert main(["model", "prepare", "--cases", str(EXAMPLES / "cases.jsonl"), "--output-dir", str(destination)]) == 2
    assert "new or empty" in capsys.readouterr().err


def test_recorded_examples_remain_unscored_and_no_candidates_export(tmp_path, capsys):
    cases = str(EXAMPLES / "cases.jsonl")
    first = str(EXAMPLES / "fixture-model-a.jsonl")
    second = str(EXAMPLES / "fixture-model-b.jsonl")
    assert main(["model", "evaluate", "--cases", cases, "--responses", first]) == 0
    result = json.loads(capsys.readouterr().out)
    assert all(row["mechanical_pass"] is None for row in result["results"])
    output = tmp_path / "combined.json"
    assert main(["model", "combine", "--cases", cases, "--responses", first, "--responses", second, "--output", str(output)]) == 0
    result = json.loads(output.read_text())
    assert result["training_candidates"] == []
    assert len(result["review_items"]) == 48
    saved = output.read_bytes()
    assert main(["model", "combine", "--cases", cases, "--responses", first, "--responses", second, "--output", str(output)]) == 2
    assert output.read_bytes() == saved


def test_example_prompts_offer_shared_choices_without_revealing_expected_selections():
    cases = [json.loads(line) for line in (EXAMPLES / "cases.jsonl").read_text().splitlines()]
    codebooks = []
    for case in cases:
        prompt = json.loads(case["messages"][1]["content"])
        codebook = (prompt["limitation_ids"], prompt["recommendation_ids"])
        codebooks.append(codebook)
        for field, candidates in zip(("limitations", "recommendations"), codebook):
            assert set(case["expected"][field]) < set(candidates)
        assert "expected" not in prompt
        assert case["provenance"]["review_status"] == "unreviewed"
    assert all(codebook == codebooks[0] for codebook in codebooks)


def test_stage_command_is_offline_and_preserves_provenance(tmp_path, capsys):
    row = {"messages": [{"role": "user", "content": "Count?"}, {"role": "assistant", "content": "2"}]}
    training = tmp_path / "source.jsonl"
    training.write_text(json.dumps(row) + "\n")
    manifest = tmp_path / "sources.json"
    manifest.write_text(json.dumps({"sources": [{"id": "fixture", "revision": "a" * 40, "training_files": ["source.jsonl"], "evaluation_files": []}]}))
    output = tmp_path / "staged"
    assert main(["model", "stage", "--manifest", str(manifest), "--output-dir", str(output)]) == 0
    assert (output / "manifest.json").is_file()
    record = json.loads((output / "staged-corpus.jsonl").read_text())
    assert record["messages"] == row["messages"]
    assert record["review_status"] == "unreviewed"
    assert record["provenance"][0]["revision"] == "a" * 40
    assert record["provenance"][0]["line"] == 1


def test_model_outputs_cannot_modify_finalized_run(tmp_path, capsys):
    run = tmp_path / "run"
    run.mkdir()
    (run / "run-manifest.json").write_text("{}")
    output = run / "model-pack"
    assert main(["model", "prepare", "--cases", str(EXAMPLES / "cases.jsonl"), "--output-dir", str(output)]) == 2
    assert not output.exists()
    assert "outside finalized" in capsys.readouterr().err


def test_invalid_revision_fails_before_output_creation(tmp_path, capsys):
    output = tmp_path / "pack"
    assert main(["model", "prepare", "--cases", str(EXAMPLES / "cases.jsonl"), "--output-dir", str(output), "--revision", "main"]) == 2
    assert not output.exists()
    assert "immutable" in capsys.readouterr().err
