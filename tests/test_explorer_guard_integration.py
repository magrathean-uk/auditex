"""Read-aware explorer coverage keeps the guarded reader's refusal semantics."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from test_reporting import _write_run

from auditex import cli


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_explorer_refuses_unsafe_coverage(tmp_path: Path, capsys, kind: str) -> None:
    run = tmp_path / "run"
    _write_run(run)
    coverage = run / "coverage.json"
    coverage.unlink(missing_ok=True)
    if kind == "symlink":
        target = tmp_path / "coverage-target.json"
        target.write_text("[]", encoding="utf-8")
        coverage.symlink_to(target)
    else:
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO creation is unavailable")
        os.mkfifo(coverage)

    output = tmp_path / "explorer.html"
    assert cli.main(["report", "explorer", str(run), "--output", str(output)]) == 2
    assert not output.exists()
    captured = capsys.readouterr()
    assert "Refusing" in captured.err
