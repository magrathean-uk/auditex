"""Regression tests for readers that hash or reopen an already selected input."""
from __future__ import annotations

from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path

import pytest

from azure_tenant_audit import run_files
from test_guarded_admission import KEY, private_run  # noqa: F401 - shared fixture
from test_model_eval import _answer, _case, _inputs


def _context(run: Path):
    cls = getattr(run_files, "GuardContext", None)
    return cls() if cls is not None else nullcontext(None)


def _bind(context: object, run: Path) -> None:
    if context is not None:
        context.bind_run(run)


def _swap_to_key(path: Path, run: Path) -> None:
    os.rename(path, path.with_name("held-" + path.name))
    os.link(run / "operator-inputs" / "sensitive-users.key", path)


def test_model_corpus_refuses_swap_before_later_stream(private_run: Path, tmp_path: Path) -> None:
    from auditex import model_corpus

    source = tmp_path / "training.jsonl"
    source.write_text('{"messages": []}\n', encoding="utf-8")
    with _context(private_run) as context:
        _bind(context, private_run)
        info = model_corpus._file_info(source)
        _swap_to_key(source, private_run)
        with pytest.raises(run_files.UnsafeRunFileError):
            list(model_corpus._rows(info))


def test_model_corpus_refuses_swap_before_manifest_reopen(
    private_run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from auditex import model_corpus

    manifest = tmp_path / "sources.json"
    manifest.write_text(json.dumps({"sources": []}), encoding="utf-8")
    original = model_corpus._file_info
    swapped = False

    def first_read_then_swap(path: Path) -> dict:
        nonlocal swapped
        info = original(path)
        if path == manifest:
            _swap_to_key(manifest, private_run)
            swapped = True
        return info

    monkeypatch.setattr(model_corpus, "_file_info", first_read_then_swap)
    with _context(private_run) as context:
        _bind(context, private_run)
        with pytest.raises(run_files.UnsafeRunFileError):
            model_corpus._manifest(manifest)
    assert swapped


@pytest.mark.parametrize("combine", [False, True])
def test_model_evaluation_never_rehashes_swapped_private_key(
    private_run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, combine: bool,
) -> None:
    from auditex import model_eval

    case = _case()
    cases, responses = _inputs(tmp_path, case, _answer(case))
    expected = hashlib.sha256(cases.read_bytes()).hexdigest()
    original = model_eval._load_responses
    swapped = False

    def load_then_swap(paths: list[str | Path]):
        nonlocal swapped
        result = original(paths)
        _swap_to_key(cases, private_run)
        swapped = True
        return result

    monkeypatch.setattr(model_eval, "_load_responses", load_then_swap)
    with _context(private_run) as context:
        _bind(context, private_run)
        try:
            result = (model_eval.combine_model_responses(cases, [responses]) if combine
                      else model_eval.evaluate_responses(cases, responses))
        except run_files.UnsafeRunFileError:
            pass
        else:
            assert result["cases_input"]["sha256"] == expected
            assert hashlib.sha256(KEY).hexdigest() not in json.dumps(result)
    assert swapped


@pytest.mark.parametrize("reader", ["cases", "responses", "replay"])
def test_active_reader_refuses_swapped_key(private_run: Path, tmp_path: Path, reader: str) -> None:
    from auditex.model_eval import _load_responses
    from auditex.model_training import load_cases
    from azure_tenant_audit.offline_replay import replay_source

    path = tmp_path / "selected.jsonl"
    path.write_text("{}\n", encoding="utf-8")
    with _context(private_run) as context:
        _bind(context, private_run)
        _swap_to_key(path, private_run)
        call = {"cases": lambda: load_cases(path), "responses": lambda: _load_responses([path]),
                "replay": lambda: replay_source(path)}[reader]
        with pytest.raises(run_files.UnsafeRunFileError):
            call()


@pytest.mark.parametrize("kind", ["export", "results"])
def test_scubagear_uses_selected_bytes_after_path_swap(private_run: Path, tmp_path: Path, kind: str) -> None:
    from auditex.scubagear_export import load_export, load_results
    from azure_tenant_audit.guarded_io import open_pinned_binary

    fixture = Path(__file__).parent / "fixtures/scubagear-export" / (
        "mocktenant-provider-export.json" if kind == "export" else "mocktenant-scubaresults.json"
    )
    path = tmp_path / "selected.json"
    original = fixture.read_bytes()
    path.write_bytes(original)
    with _context(private_run) as context:
        _bind(context, private_run)
        with open_pinned_binary(path, field="input", context=context):
            pass
        _swap_to_key(path, private_run)
        try:
            result = load_export(path) if kind == "export" else load_results(path)
        except run_files.UnsafeRunFileError:
            pass
        else:
            assert result.sha256 == hashlib.sha256(original).hexdigest() if kind == "export" else result[1] == "scubaresults"


def test_explorer_uses_selected_bytes_after_path_swap(private_run: Path, tmp_path: Path) -> None:
    from auditex.explorer import _read_json
    from azure_tenant_audit.guarded_io import open_pinned_binary

    path = tmp_path / "selected.json"
    path.write_text('{"expected": true}', encoding="utf-8")
    with _context(private_run) as context:
        _bind(context, private_run)
        with open_pinned_binary(path, field="input", context=context):
            pass
        _swap_to_key(path, private_run)
        try:
            result = _read_json(path, {})
        except run_files.UnsafeRunFileError:
            pass
        else:
            assert result == {"expected": True}


def test_gate_uses_pinned_manifest_after_path_swap(private_run: Path) -> None:
    from auditex.gate import _open_run

    manifest = private_run / "run-manifest.json"
    with _context(private_run) as context:
        _bind(context, private_run)
        _swap_to_key(manifest, private_run)
        try:
            result = _open_run(private_run, "run")
        except run_files.UnsafeRunFileError:
            pass
        else:
            assert isinstance(result.manifest(), dict)


def test_normalized_sections_use_pinned_run_after_root_swap(private_run: Path, tmp_path: Path) -> None:
    from azure_tenant_audit.output_redaction import read_normalized_sections

    original = private_run / "normalized"
    original.mkdir()
    (original / "users.json").write_text('{"origin":"admitted"}', encoding="utf-8")
    replacement = tmp_path / "replacement"
    (replacement / "normalized").mkdir(parents=True)
    (replacement / "normalized/users.json").write_text('{"origin":"swapped"}', encoding="utf-8")
    with _context(private_run) as context:
        _bind(context, private_run)
        private_run.rename(tmp_path / "held-run")
        private_run.symlink_to(replacement, target_is_directory=True)
        try:
            result = read_normalized_sections(private_run)
        except run_files.UnsafeRunFileError:
            pass
        else:
            assert result["users"]["origin"] == "admitted"
