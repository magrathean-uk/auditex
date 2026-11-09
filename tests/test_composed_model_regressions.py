"""Composed assessment-boundary regressions: direct MemoryError propagation.

Fail-first against 93ccb51: three explainer boundaries suppressed MemoryError. Every dataset here is constructed in
tmp_path (permitted test split); no held-out data.
"""
from __future__ import annotations

import json
import logging
import os

import pytest

from auditex import rule_assessment
from auditex.rule_assessment import assess_run
from auditex.reporting import load_report_bundle
from azure_tenant_audit.run_files import UnsafeRunFileError

from test_explainer_wire import PBI, assessment, make_report_run  # noqa: F401  (assessment is a fixture)


# --- finding 2: direct MemoryError propagates; ordinary failures stay suppressed ------------------------------------------

def test_report_context_memory_error_propagates(tmp_path, assessment, monkeypatch):  # noqa: F811 - shared pytest fixture injected by name
    import auditex.reporting as reporting
    root, _ = make_report_run(tmp_path, assessment)
    monkeypatch.setattr(reporting, "context_for_run", lambda _: (_ for _ in ()).throw(MemoryError()))
    with pytest.raises(MemoryError):
        load_report_bundle(root)


def test_report_derive_explainer_memory_error_propagates(tmp_path, assessment, monkeypatch):  # noqa: F811 - shared pytest fixture injected by name
    root, _ = make_report_run(tmp_path, assessment)
    monkeypatch.setattr("azure_tenant_audit.scuba_assessment.derive_explainer",
                        lambda _row: (_ for _ in ()).throw(MemoryError()))
    with pytest.raises(MemoryError):
        load_report_bundle(root)


@pytest.mark.parametrize("target", ["context", "derive"])
def test_report_runtime_error_still_suppresses_without_value(tmp_path, assessment, monkeypatch, target):  # noqa: F811 - shared pytest fixture injected by name
    import auditex.reporting as reporting
    root, _ = make_report_run(tmp_path, assessment)
    def broken(*args):
        raise RuntimeError("private-person@example.invalid")
    if target == "context":
        monkeypatch.setattr(reporting, "context_for_run", broken)
    else:
        monkeypatch.setattr("azure_tenant_audit.scuba_assessment.derive_explainer", broken)
    sections = load_report_bundle(root)["sections"]
    assert "policy_explanations" not in sections
    assert "private-person" not in json.dumps(sections, default=str)


def test_report_unsafe_file_still_propagates(tmp_path, assessment):  # noqa: F811 - shared pytest fixture injected by name
    root, _ = make_report_run(tmp_path, assessment)
    target = root / "model_assessment.json"
    moved = tmp_path / "moved.json"
    target.rename(moved)
    os.symlink(moved, target)
    with pytest.raises(UnsafeRunFileError):
        load_report_bundle(root)


def test_derive_explainer_memory_error_propagates_and_runtime_error_returns_none(monkeypatch):
    from azure_tenant_audit import explainer
    from azure_tenant_audit.scuba_assessment import derive_explainer
    from test_explainer_wire import explained
    row = explained("not_met")
    assert derive_explainer(row) is not None  # ordinary valid control
    monkeypatch.setattr(explainer, "explain", lambda *a, **k: (_ for _ in ()).throw(MemoryError()))
    with pytest.raises(MemoryError):
        derive_explainer(row)
    monkeypatch.setattr(explainer, "explain", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("private")))
    assert derive_explainer(row) is None


def test_serving_context_memory_error_propagates(tmp_path, monkeypatch):
    (tmp_path / "run-manifest.json").write_text('{"run_id":"context"}')
    monkeypatch.setattr(rule_assessment, "context_for_run", lambda *a: (_ for _ in ()).throw(MemoryError()))
    with pytest.raises(MemoryError):
        assess_run(tmp_path, policies=[PBI])


def test_serving_context_runtime_error_still_suppressed(tmp_path, monkeypatch, caplog):
    (tmp_path / "run-manifest.json").write_text('{"run_id":"context"}')
    def broken(*args):
        raise RuntimeError("private-person@example.invalid")
    monkeypatch.setattr(rule_assessment, "context_for_run", broken)
    caplog.set_level(logging.DEBUG, logger=rule_assessment.__name__)
    result = assess_run(tmp_path, policies=[PBI])
    assert "explainer" not in result["policies"][0]
    assert "private-person" not in caplog.text
