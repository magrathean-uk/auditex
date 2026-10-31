from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditex.cli import main
from auditex.model_sources import validate_model_sources


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "model_development"
REVISION = "1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0"


def test_model_catalogue_is_pinned_and_names_the_trained_product_model(capsys):
    assert main(["model", "sources"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["tenant_access"] is False
    assert result["inference_executed"] is result["training_executed"] is True
    assert all(len(source["revision"]) == 40 for source in result["sources"] if source["role"] != "product_model")
    assert {source["role"] for source in result["sources"]} >= {"proposed_single_training_base", "unreviewed_reference_conversations"}
    product, = [source for source in result["sources"] if source["role"] == "product_model"]
    assert product["id"] == "auditex-ministral3-8b-scuba-v10" and product["revision"] is None
    assert product["sha256"] == "840fb447eb062d7cae8ff1980d30548e1198138e8235e88e1bc0449bacead01a"
    assert product["bytes"] == sum(part["bytes"] for part in product["parts"]["files"]) == 6058747104
    assert product["base"]["revision"] == "f6fae9795746f63c9be8344932f01275f3c63734"
    assert product["conversion"]["llama_cpp_revision"] == "620d2225cc436ab0b001e3200e590e3b286ef9ab"
    assert {score["id"] for score in product["scores"]} == {
        "strict_model_alone", "product", "product_twin_free", "product_policy_weighted"}
    assert "pending" in product["availability"]
    assert product["licence"].startswith("Base model: Apache-2.0 (verified on the mistralai/Ministral-3-8B-Instruct-2512-BF16 model card")
    assert "modified work" in product["licence"] and "CC0 1.0" in product["licence"] and "verify on" not in product["licence"]
    assert product["adapter"]["archive"] == "results-round5-adapter-ministral3-8b-20261030T0250Z.tar"
    assert product["adapter"]["sha256"] == "40db5b31a3bff37d4d6d57294174ab2b0c4235ebe1687934079e96efd29f1886"
    assert product["adapter"]["weights_file"] == "adapter_model.safetensors"
    assert product["adapter"]["weights_sha256"] == "b477f2b60fe72b29207bac835811590706fc418aa2cbd6aa643465dd174be682"


def _catalogue():
    return json.loads((ROOT / "configs" / "model-sources.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("mutate, message", [
    (lambda d: d["sources"][0].update(sha256="840fb447"), "sha256"),
    (lambda d: d["sources"][0]["adapter"].update(sha256="B477" * 16), "adapter"),
    (lambda d: d["sources"][0]["adapter"].pop("weights_sha256"), "adapter"),
    (lambda d: d["sources"][0]["adapter"].update(weights_sha256="b477f2b6"), "adapter"),
    (lambda d: d["sources"][0]["adapter"].update(weights_file=""), "adapter"),
    (lambda d: d["sources"][0]["adapter"].update(sha256=d["sources"][0]["adapter"]["weights_sha256"]), "weights_sha256"),
    (lambda d: d["sources"][0]["base"].update(revision="main"), "base"),
    (lambda d: d["sources"][0].pop("availability"), "missing availability"),
    (lambda d: d["sources"][0]["parts"]["files"].pop(), "parts"),
    (lambda d: d["sources"][0]["scores"].append({"id": "x", "definition": "y", "correct": 9, "total": 4}), "score x"),
    (lambda d: d["sources"][0]["scores"].append({"id": "z", "definition": "y", "rate": 1.2}), "score z"),
    (lambda d: d["sources"][1].update(revision=None), "40-character"),
    (lambda d: d["sources"][1].update(role="product_model"), "exactly one"),
    (lambda d: d["sources"].append(dict(d["sources"][1])), "unique"),
    # Required metadata must be present and usable, not merely keyed.
    (lambda d: d["sources"][0].update(repository=None), "repository"),
    (lambda d: d["sources"][0].update(artifact=""), "artifact"),
    (lambda d: d["sources"][0].update(url="http://example.invalid/model"), "url"),
    (lambda d: d["sources"][0].update(evaluated_at="yesterday"), "evaluated_at"),
    (lambda d: d["sources"][0].update(known_weaknesses=[]), "known_weaknesses"),
    (lambda d: d["sources"][0].update(bytes=True), "bytes"),
    (lambda d: d["sources"][0].update(revision="main"), "revision"),
    (lambda d: d["sources"][0].update(serving=None), "serving"),
    (lambda d: d["sources"][0].update(training=None), "training"),
    (lambda d: d["sources"][0]["training"]["rows"].update(test=0), "training"),
    (lambda d: d["sources"][0]["training"].update(pack_manifest_sha256="62908b22"), "training"),
    (lambda d: d["sources"][0]["base"].update(repository=None), "base"),
    (lambda d: d["sources"][0]["base"].pop("url"), "base"),
    (lambda d: d["sources"][0]["adapter"].update(method=""), "adapter"),
    (lambda d: d["sources"][0]["conversion"].update(tokeniser=7), "conversion"),
    (lambda d: d["sources"][0]["parts"].update(reassemble=None), "parts"),
    (lambda d: d["sources"][0].update(parts=[]), "parts"),
    # Parts: positive sizes, unique names, summing to the whole.
    (lambda d: d["sources"][0]["parts"]["files"].extend([
        {**d["sources"][0]["parts"]["files"][1], "bytes": -5}, {**d["sources"][0]["parts"]["files"][1], "bytes": 5}]),
     "parts"),
    (lambda d: (d["sources"][0]["parts"]["files"][1].update(name=d["sources"][0]["parts"]["files"][0]["name"])), "parts"),
    (lambda d: d["sources"][0]["parts"]["files"][0].update(bytes=0), "parts"),
    # Serving: the measured protocol and the production request are both explicit and complete.
    (lambda d: d["sources"][0]["serving"].update(request={"temperature": 0}), "ambiguous"),
    (lambda d: d["sources"][0]["serving"].pop("benchmark_protocol"), "benchmark_protocol"),
    (lambda d: d["sources"][0]["serving"]["benchmark_protocol"]["request"].pop("seed"), "benchmark_protocol"),
    (lambda d: d["sources"][0]["serving"]["benchmark_protocol"]["request"].update(max_tokens=0), "benchmark_protocol"),
    (lambda d: d["sources"][0]["serving"]["benchmark_protocol"].update(response_format=None), "benchmark_protocol"),
    (lambda d: d["sources"][0]["serving"].pop("production_request"), "production_request"),
    (lambda d: d["sources"][0]["serving"]["production_request"].update(cache_prompt="no"), "production_request"),
    (lambda d: d["sources"][0]["serving"]["production_request"].update(chat_template_kwargs=None), "production_request"),
    (lambda d: d["sources"][0]["serving"]["production_request"].update(seed=42), "production_request"),
    (lambda d: d["sources"][0]["serving"].update(protocol_difference=""), "serving"),
    # Scores: each an object with an id and definition, a count or a rate, ids unique.
    (lambda d: d["sources"][0].update(scores=[None]), "score entry"),
    (lambda d: d["sources"][0]["scores"].append("product"), "score entry"),
    (lambda d: d["sources"][0]["scores"].append({"id": "w", "definition": "y", "rate": 0.5, "correct": 1, "total": 2}),
     "score w"),
    (lambda d: d["sources"][0]["scores"].append({"id": "v", "definition": None, "correct": 1, "total": 2}), "score v"),
    (lambda d: d["sources"][0]["scores"].append(dict(d["sources"][0]["scores"][0])), "score ids must be unique"),
    (lambda d: d["sources"].append(None), "Invalid model source catalogue"),
    (lambda d: d["sources"][1].update(id=["x"]), "unique"),
])
def test_model_catalogue_invariants_fail_closed(mutate, message):
    payload = _catalogue()
    validate_model_sources(payload)
    mutate(payload)
    with pytest.raises(ValueError, match=message):
        validate_model_sources(payload)


def test_prepare_example_cases_does_not_invent_approval(tmp_path, capsys):
    destination = tmp_path / "pack"
    assert main(["model", "prepare", "--cases", str(EXAMPLES / "cases.jsonl"), "--output-dir", str(destination), "--revision", REVISION]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["counts"] == {"train": 0, "validation": 0, "test": 0, "quarantined": 48,
                                "exported_train": 0, "exported_validation": 0}
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


def test_malformed_catalogue_fails_cleanly_in_the_cli(tmp_path, monkeypatch, capsys):
    payload = _catalogue()
    payload["sources"][0]["scores"] = [None]
    path = tmp_path / "model-sources.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr("auditex.model_sources.resolve_resource_path", lambda relative: path)
    assert main(["model", "sources"]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "Traceback" not in captured.err
    assert captured.err.startswith("Model command failed: Invalid product model entry: score entry.")
