"""Offline corpus staging preserves context and fails closed around holdouts."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from auditex import model_corpus
from auditex.model_corpus import stage_public_corpus

REVISION = "a" * 40


def _row(prompt: str = "Review evidence", answer: str = "Evidence is incomplete") -> dict:
    return {"messages": [{"role": "system", "content": "Use evidence only"},
                         {"role": "user", "content": prompt},
                         {"role": "assistant", "content": answer}]}


def _write(path: Path, rows: list[dict]) -> Path:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def _manifest(tmp_path: Path, training: list[Path], evaluation: list[Path] | None = None) -> Path:
    path = tmp_path / "sources.json"
    path.write_text(json.dumps({"sources": [{"id": "upstream/example", "revision": REVISION,
                                            "training_files": [str(p) for p in training],
                                            "evaluation_files": [str(p) for p in evaluation or []]}]}))
    return path


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_deduplicates_tracks_and_assembled_files_with_all_provenance(tmp_path: Path) -> None:
    first = _write(tmp_path / "track.jsonl", [_row(), _row("Other evidence")])
    assembled = _write(tmp_path / "train.jsonl", [_row()])
    output = tmp_path / "staged"
    result = stage_public_corpus(_manifest(tmp_path, [first, assembled]), output)
    rows = _rows(output / "staged-corpus.jsonl")
    assert result["counts"]["training_rows"] == 3
    assert result["counts"]["duplicate_rows"] == 1
    assert result["counts"]["staged_conversations"] == 2
    assert result["approved_training_records"] == 0
    assert rows[0]["review_status"] == "unreviewed"
    refs = rows[0]["provenance"]
    assert [(r["path"], r["line"]) for r in refs] == [(str(first), 1), (str(assembled), 1)]
    assert all(r["upstream_source_id"] == "upstream/example" and r["revision"] == REVISION for r in refs)
    assert refs[0]["sha256"] == hashlib.sha256(first.read_bytes()).hexdigest()
    for name, expected in result["artifacts"].items():
        data = (output / name).read_bytes()
        assert expected == {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def test_conflicting_completions_quarantine_every_variant_without_first_wins(tmp_path: Path) -> None:
    train = _write(tmp_path / "train.jsonl", [_row(answer="Pass"), _row(answer="Fail"), _row(answer="Pass")])
    output = tmp_path / "staged"
    result = stage_public_corpus(_manifest(tmp_path, [train]), output)
    assert _rows(output / "staged-corpus.jsonl") == []
    conflict = _rows(output / "conflicts.jsonl")[0]
    assert conflict["reason"] == "same_prompt_different_completion"
    assert {v["messages"][-1]["content"] for v in conflict["variants"]} == {"Pass", "Fail"}
    assert sum(len(v["provenance"]) for v in conflict["variants"]) == 3
    assert result["counts"]["conflicting_rows"] == 3
    assert result["counts"]["conflicting_conversations"] == 2


def test_strips_reasoning_fields_without_changing_literal_content(tmp_path: Path) -> None:
    row = _row(answer="The evidence contains the word analysis")
    row["analysis"] = "private root scratch"
    row["messages"][-1].update(thinking="private thought", reasoning_content="more thought", analysis="scratch")
    row["messages"][0]["reasoning"] = None
    train = _write(tmp_path / "train.jsonl", [row, _row(answer="The evidence contains the word analysis")])
    output = tmp_path / "staged"
    result = stage_public_corpus(_manifest(tmp_path, [train]), output)
    staged = _rows(output / "staged-corpus.jsonl")[0]
    assert result["counts"]["duplicate_rows"] == 1
    assert result["counts"]["rows_with_stripped_fields"] == 1
    assert result["stripped_fields"] == {"analysis": 2, "thinking": 1, "reasoning_content": 1, "reasoning": 1}
    assert "private thought" not in json.dumps(staged)
    assert staged["messages"][-1]["content"] == "The evidence contains the word analysis"


@pytest.mark.parametrize("with_ids", [False, True])
def test_preserves_function_definitions_calls_and_results(tmp_path: Path, with_ids: bool) -> None:
    call = {"type": "function", "function": {"name": "graph_get", "arguments": '{ "path": "/users" }'}}
    response = {"role": "tool", "content": '{"value": []}'}
    if with_ids:
        call["id"] = "call-1"
        response["tool_call_id"] = "call-1"
    else:
        response["name"] = "graph_get"
    row = {"tools": [{"type": "function", "function": {"name": "graph_get", "parameters": {"type": "object"}}}],
           "messages": [{"role": "user", "content": "Read users"},
                        {"role": "assistant", "tool_calls": [call]}, response,
                        {"role": "assistant", "content": "No users were returned."}]}
    train = _write(tmp_path / "train.jsonl", [row])
    output = tmp_path / "staged"
    result = stage_public_corpus(_manifest(tmp_path, [train]), output)
    assert result["counts"]["unsupported_rows"] == 0
    staged = _rows(output / "staged-corpus.jsonl")[0]
    assert staged["tools"] == row["tools"]
    assert staged["messages"][1]["content"] is None
    assert staged["messages"][1]["tool_calls"][0]["function"]["arguments"] == '{"path":"/users"}'
    assert staged["messages"][2] == response


def test_accepts_final_tool_call_as_assistant_target(tmp_path: Path) -> None:
    row = {"messages": [{"role": "user", "content": "Review tenant"},
                        {"role": "assistant", "content": None, "tool_calls": [
                            {"type": "function", "function": {"name": "graph_get", "arguments": '{"path":"/policies"}'}}]}]}
    train = _write(tmp_path / "train.jsonl", [row])
    result = stage_public_corpus(_manifest(tmp_path, [train]), tmp_path / "staged")
    assert result["counts"]["staged_conversations"] == 1


@pytest.mark.parametrize("change", ["role", "content", "no_target", "empty_target", "unknown_field", "unmatched_tool", "missing_result", "arguments"])
def test_quarantines_unsupported_conversations(tmp_path: Path, change: str) -> None:
    row = _row()
    if change == "role":
        row["messages"][-1]["role"] = "developer"
    elif change == "content":
        row["messages"][-1]["content"] = [{"text": "unsupported multimodal"}]
    elif change == "no_target":
        row["messages"].pop()
    elif change == "empty_target":
        row["messages"][-1]["content"] = None
    elif change == "unknown_field":
        row["completion"] = "silent guess"
    elif change == "unmatched_tool":
        row["messages"].insert(2, {"role": "tool", "tool_call_id": "missing", "content": "data"})
    elif change == "missing_result":
        row["messages"].insert(2, {"role": "assistant", "tool_calls": [{"type": "function", "id": "call-1", "function": {"name": "graph_get", "arguments": "{}"}}]})
    else:
        row["messages"][-1]["tool_calls"] = [{"type": "function", "function": {"name": "graph_get", "arguments": "not JSON"}}]
    train = _write(tmp_path / "train.jsonl", [row])
    output = tmp_path / "staged"
    result = stage_public_corpus(_manifest(tmp_path, [train]), output)
    assert result["counts"]["unsupported_rows"] == 1
    assert _rows(output / "staged-corpus.jsonl") == []
    reject = _rows(output / "rejected.jsonl")[0]
    assert reject["reason"] and reject["provenance"][0]["line"] == 1


def test_training_prompt_overlap_is_rejected_even_when_evaluation_completion_differs(tmp_path: Path) -> None:
    train = _write(tmp_path / "train.jsonl", [_row("Held out", "Training answer"), _row("Unique")])
    evaluate = _write(tmp_path / "eval.jsonl", [_row("Held out", "Independent evaluation answer")])
    output = tmp_path / "staged"
    result = stage_public_corpus(_manifest(tmp_path, [train], [evaluate]), output)
    assert result["counts"]["evaluation_overlap_rows"] == 1
    assert result["counts"]["staged_conversations"] == 1
    assert _rows(output / "rejected.jsonl")[0]["reason"] == "evaluation_prompt_overlap"
    inventory = json.loads((output / "evaluation-sources.json").read_text())
    assert inventory[0]["overlap_check"] == "exact_normalized_prompt"
    assert len(inventory[0]["prompt_sha256"]) == 1


def test_opaque_yaml_is_only_hashed_and_marked_unchecked(tmp_path: Path) -> None:
    train = _write(tmp_path / "train.jsonl", [_row()])
    evaluate = tmp_path / "holdout.yaml"
    evaluate.write_text("!!python/object/apply:os.system ['never execute this']\n")
    output = tmp_path / "staged"
    result = stage_public_corpus(_manifest(tmp_path, [train], [evaluate]), output)
    assert result["counts"]["opaque_evaluation_files"] == 1
    inventory = json.loads((output / "evaluation-sources.json").read_text())
    assert inventory[0]["overlap_check"] == "not_established_opaque_yaml"
    assert inventory[0]["sha256"] == hashlib.sha256(evaluate.read_bytes()).hexdigest()


@pytest.mark.parametrize("renamed", [False, True])
def test_same_file_or_hash_cannot_be_training_and_evaluation(tmp_path: Path, renamed: bool) -> None:
    train = _write(tmp_path / "train.jsonl", [_row()])
    evaluate = _write(tmp_path / "eval.jsonl", [_row()]) if renamed else train
    output = tmp_path / "staged"
    with pytest.raises(ValueError, match="same input path or file hash"):
        stage_public_corpus(_manifest(tmp_path, [train], [evaluate]), output)
    assert not output.exists()


@pytest.mark.parametrize("change", ["revision", "unknown", "missing", "duplicate_source", "missing_file", "wrong_extension", "duplicate_path"])
def test_invalid_manifest_has_no_output_side_effects(tmp_path: Path, change: str) -> None:
    train = _write(tmp_path / "train.jsonl", [_row()])
    path = _manifest(tmp_path, [train])
    payload = json.loads(path.read_text())
    source = payload["sources"][0]
    if change == "revision":
        source["revision"] = "main"
    elif change == "unknown":
        source["download"] = "https://never-fetch.example"
    elif change == "missing":
        del source["evaluation_files"]
    elif change == "duplicate_source":
        payload["sources"].append(copy.deepcopy(source))
    elif change == "missing_file":
        source["training_files"] = [str(tmp_path / "absent.jsonl")]
    elif change == "wrong_extension":
        source["training_files"] = [str(path)]
    else:
        source["training_files"].append(str(train))
    path.write_text(json.dumps(payload))
    output = tmp_path / "not-created" / "staged"
    with pytest.raises(ValueError):
        stage_public_corpus(path, output)
    assert not output.parent.exists()


def test_relative_paths_resolve_against_manifest_not_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    train = _write(tmp_path / "train.jsonl", [_row()])
    path = _manifest(tmp_path, [Path(train.name)])
    monkeypatch.chdir(tmp_path.parent)
    assert stage_public_corpus(path, tmp_path / "staged")["counts"]["staged_conversations"] == 1


def test_output_is_not_overwritten(tmp_path: Path) -> None:
    train = _write(tmp_path / "train.jsonl", [_row()])
    path = _manifest(tmp_path, [train])
    output = tmp_path / "staged"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("keep")
    with pytest.raises(FileExistsError):
        stage_public_corpus(path, output)
    assert marker.read_text() == "keep" and list(output.iterdir()) == [marker]


def test_bad_json_and_oversized_lines_are_quarantined_without_losing_line_numbers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(model_corpus, "MAX_LINE_BYTES", 600)
    train = tmp_path / "train.jsonl"
    train.write_text('{"messages":[],"messages":[]}\n' + "x" * 700 + "\n" + json.dumps(_row()) + "\n")
    output = tmp_path / "staged"
    result = stage_public_corpus(_manifest(tmp_path, [train]), output)
    assert result["counts"]["unsupported_rows"] == 2
    assert [r["provenance"][0]["line"] for r in _rows(output / "rejected.jsonl")] == [1, 2]
    assert _rows(output / "staged-corpus.jsonl")[0]["provenance"][0]["line"] == 3


def test_file_size_limit_is_checked_before_output_creation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    train = _write(tmp_path / "train.jsonl", [_row(answer="x" * 1000)])
    manifest = _manifest(tmp_path, [train])
    monkeypatch.setattr(model_corpus, "MAX_FILE_BYTES", 700)
    with pytest.raises(ValueError, match="exceeds"):
        stage_public_corpus(manifest, tmp_path / "staged")
    assert not (tmp_path / "staged").exists()


def test_invalid_evaluation_jsonl_fails_closed_before_outputs(tmp_path: Path) -> None:
    train = _write(tmp_path / "train.jsonl", [_row()])
    evaluate = _write(tmp_path / "eval.jsonl", [{"prompt": "unknown schema", "expected": "unknown"}])
    with pytest.raises(ValueError, match="unsupported evaluation row"):
        stage_public_corpus(_manifest(tmp_path, [train], [evaluate]), tmp_path / "staged")
    assert not (tmp_path / "staged").exists()


def test_tools_are_part_of_prompt_identity(tmp_path: Path) -> None:
    first = _row(answer="First")
    first["tools"] = [{"type": "function", "function": {"name": "read_one"}}]
    second = _row(answer="Second")
    second["tools"] = [{"type": "function", "function": {"name": "read_two"}}]
    train = _write(tmp_path / "train.jsonl", [first, second])
    result = stage_public_corpus(_manifest(tmp_path, [train]), tmp_path / "staged")
    assert result["counts"]["staged_conversations"] == 2
    assert result["counts"]["conflicting_prompts"] == 0
