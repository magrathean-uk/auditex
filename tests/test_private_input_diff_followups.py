"""Follow-up: an unsafe run file is refused by the diff, never read as an empty report."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from azure_tenant_audit import diffing
from azure_tenant_audit.guarded_io import UnsafeRunFileError


def _write_pack(run: Path, ids: list[str]) -> None:
    (run / "reports").mkdir(parents=True, exist_ok=True)
    rows = [{"id": item, "rule_id": item, "severity": "high", "title": item} for item in ids]
    (run / "reports" / "report-pack.json").write_text(json.dumps({"findings": rows}))


def test_load_json_ordinary_missing_and_malformed_stay_empty(tmp_path):
    run = tmp_path / "r"
    run.mkdir()
    assert diffing._load_json(run, "reports/report-pack.json") == {}
    (run / "reports").mkdir()
    (run / "reports" / "report-pack.json").write_text("{not json")
    assert diffing._load_json(run, "reports/report-pack.json") == {}


def test_legitimate_resolved_finding_still_reported(tmp_path):
    before, after = tmp_path / "before", tmp_path / "after"
    _write_pack(before, ["F1", "F2"])
    _write_pack(after, ["F2"])
    summary = diffing._posture_drift_summary(before, after)
    assert summary["resolved_count"] == 1


def _unsafe_variants(run: Path, tmp_path: Path):
    target = run / "reports" / "report-pack.json"
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text(json.dumps({"findings": []}))
    target.unlink()
    target.symlink_to(elsewhere)
    yield "symlink"
    target.unlink()
    os.mkfifo(target)
    yield "fifo"


def test_unsafe_report_pack_is_refused_not_read_as_all_resolved(tmp_path):
    before, after = tmp_path / "before", tmp_path / "after"
    _write_pack(before, ["F1"])
    _write_pack(after, ["F1"])
    for _ in _unsafe_variants(after, tmp_path):
        with pytest.raises(UnsafeRunFileError):
            diffing._load_json(after, "reports/report-pack.json")
        with pytest.raises(UnsafeRunFileError):
            diffing._posture_drift_summary(before, after)
        with pytest.raises(UnsafeRunFileError):
            diffing._posture_drift_summary(after, before)


def test_cli_diff_refuses_unsafe_report_pack(tmp_path, capsys):
    from auditex import cli

    before, after = tmp_path / "before", tmp_path / "after"
    _write_pack(before, ["F1"])
    _write_pack(after, ["F1"])
    for _ in _unsafe_variants(after, tmp_path):
        try:
            code = cli.main(["diff", str(before), str(after)])
        except SystemExit as caught:
            code = caught.code
        except UnsafeRunFileError:
            pytest.fail("unsafe input escaped the CLI as an exception")
        captured = capsys.readouterr()
        assert code == 2
        assert '"resolved"' not in captured.out
        assert str(tmp_path) not in captured.err
