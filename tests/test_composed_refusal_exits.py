"""Refusal must survive SQLite-open errors and direct optional-hook failures."""
from __future__ import annotations

import os
import sqlite3
import stat

import pytest

from azure_tenant_audit import evidence_db
from azure_tenant_audit.guarded_io import UnsafeRunFileError
from test_index_unproved_storage import _proof, _summary_run, _validation_codes


@pytest.mark.parametrize("proved", [False, True])
@pytest.mark.parametrize("error_kind", ["sqlite", "os"])
@pytest.mark.parametrize("changed", [False, True])
@pytest.mark.parametrize("entry", ["summary", "contract"])
def test_sqlite_open_error_preserves_source_change_refusal(tmp_path, monkeypatch, proved, error_kind, changed, entry):
    run, index = _summary_run(tmp_path)
    _proof(monkeypatch, tmp_path, proved)

    def fail_open(path, *, immutable=True):
        assert immutable
        if changed:
            with index.open("ab") as handle:
                handle.write(b"changed-before-sqlite-open")
        if error_kind == "sqlite":
            raise sqlite3.OperationalError("constructed open failure")
        raise OSError("constructed open failure")

    monkeypatch.setattr(evidence_db, "open_index_read_only", fail_open)
    call = (lambda: evidence_db.load_run_index_summary(run)) if entry == "summary" else (lambda: _validation_codes(run))
    if changed:
        with pytest.raises(UnsafeRunFileError, match="Refusing evidence index: unsafe input") as caught:
            call()
        assert caught.value.reason == "changed"
    elif entry == "summary":
        assert call() == {}
    else:
        assert call() == ["invalid_evidence_sqlite"]


@pytest.mark.parametrize("proved", [False, True])
@pytest.mark.parametrize("entry", ["summary", "contract"])
def test_direct_unsafe_sqlite_open_never_becomes_invalid_index(tmp_path, monkeypatch, proved, entry):
    run, _ = _summary_run(tmp_path)
    _proof(monkeypatch, tmp_path, proved)

    def refuse(*args, **kwargs):
        raise UnsafeRunFileError("evidence index")

    monkeypatch.setattr(evidence_db, "open_index_read_only", refuse)
    with pytest.raises(UnsafeRunFileError, match="Refusing evidence index: unsafe input"):
        if entry == "summary":
            evidence_db.load_run_index_summary(run)
        else:
            _validation_codes(run)


def test_real_permission_change_before_sqlite_open_refuses(tmp_path, monkeypatch):
    if os.geteuid() == 0:
        pytest.skip("a privileged process can bypass the constructed read denial")
    run, index = _summary_run(tmp_path)
    _proof(monkeypatch, tmp_path, False)
    original = evidence_db.open_index_read_only

    def revoke_then_open(path, *, immutable=True):
        index.chmod(0o200)
        return original(path, immutable=immutable)

    monkeypatch.setattr(evidence_db, "open_index_read_only", revoke_then_open)
    try:
        with pytest.raises(UnsafeRunFileError, match="Refusing evidence index: unsafe input") as caught:
            evidence_db.load_run_index_summary(run)
        assert caught.value.reason == "changed"
    finally:
        index.chmod(0o600)


def test_derive_preserves_the_identical_unsafe_refusal(monkeypatch):
    from azure_tenant_audit import explainer
    from azure_tenant_audit.scuba_assessment import derive_explainer
    from test_explainer_wire import explained

    row = explained("not_met")
    assert derive_explainer(row) is not None
    failure = UnsafeRunFileError("input")

    def refuse(*args, **kwargs):
        raise failure

    monkeypatch.setattr(explainer, "explain", refuse)
    with pytest.raises(UnsafeRunFileError) as caught:
        derive_explainer(row)
    assert caught.value is failure


def test_serving_preserves_unsafe_refusal_without_writing_assessment(tmp_path, monkeypatch):
    from auditex import model_serving, rule_assessment
    from test_explainer_wire import PBI

    (tmp_path / "run-manifest.json").write_text('{"run_id":"context"}')
    failure = UnsafeRunFileError("input")

    def refuse(*args, **kwargs):
        raise failure

    monkeypatch.setattr(rule_assessment, "context_for_run", refuse)
    with pytest.raises(UnsafeRunFileError) as caught:
        model_serving.assess_run(tmp_path, policies=[PBI])
    assert caught.value is failure
    assert not (tmp_path / "model_assessment.json").exists()


@pytest.mark.parametrize("hook", ["precheck_policy", "render_explanation", "redact_output"])
def test_precheck_direct_hooks_preserve_unsafe_refusal(monkeypatch, hook):
    from auditex import rule_assessment
    from test_explainer_wire import case_for

    failure = UnsafeRunFileError("input")

    def refuse(*args, **kwargs):
        raise failure

    monkeypatch.setattr(rule_assessment, hook, refuse)
    with pytest.raises(UnsafeRunFileError) as caught:
        rule_assessment.precheck_case(case_for("not_met"), value_rules=True, explain=True)
    assert caught.value is failure


@pytest.mark.parametrize("during_admission", [False, True])
def test_file_close_error_does_not_replace_primary_refusal(tmp_path, monkeypatch, during_admission):
    from azure_tenant_audit import guarded_io

    source = tmp_path / "input.json"
    source.write_text("{}")
    inode = source.stat().st_ino
    original_close = os.close
    failure = UnsafeRunFileError("input", reason="oversize")

    def close_then_fail(descriptor):
        selected = os.fstat(descriptor).st_ino == inode
        original_close(descriptor)
        if selected:
            raise OSError("constructed cleanup failure")

    monkeypatch.setattr(guarded_io.os, "close", close_then_fail)
    with guarded_io.GuardContext() as context:
        with pytest.raises(UnsafeRunFileError) as caught:
            with guarded_io.open_guarded_file(source, field="input", context=context,
                                             max_bytes=1 if during_admission else None):
                raise failure
    assert caught.value.reason == "oversize"
    if not during_admission:
        assert caught.value is failure


@pytest.mark.parametrize("mask", [0o000, 0o002, 0o022, 0o077])
def test_writer_owns_private_run_modes_without_changing_ancestors(tmp_path, mask):
    from azure_tenant_audit.output import AuditWriter

    existing = tmp_path / "existing"
    existing.mkdir()
    existing.chmod(0o755)
    previous = os.umask(mask)
    try:
        writer = AuditWriter(existing / "new-parent", "synthetic", "private")
    finally:
        os.umask(previous)
    assert stat.S_IMODE(existing.stat().st_mode) == 0o755
    assert not stat.S_IMODE(writer.run_dir.parent.stat().st_mode) & 0o022
    assert stat.S_IMODE(writer.run_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(writer.raw_dir.stat().st_mode) == 0o700
