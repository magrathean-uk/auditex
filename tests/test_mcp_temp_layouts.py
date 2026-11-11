"""Closed evidence indexes work for common temporary-directory layouts."""
from __future__ import annotations

import os
import shutil
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from azure_tenant_audit.cli import run_offline

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples/demo_tenant/demo_tenant.json"


@pytest.fixture(scope="module")
def demo_run(tmp_path_factory: pytest.TempPathFactory) -> Path:
    parent = tmp_path_factory.mktemp("index-temp-demo")
    assert run_offline(DEMO, parent, "ci", "demo", auditor_profile="global-reader", plane="inventory") == 0
    return parent / "ci-demo"


@pytest.mark.parametrize("encrypted_proof", (False, True))
@pytest.mark.parametrize("layout", ("run_in_tmp", "cli_out_tmp", "run_job", "tmp_is_run", "tmp_in_run", "separate_scratch"))
def test_demo_index_in_common_tmp_layouts(
    demo_run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: str, encrypted_proof: bool,
) -> None:
    from auditex import mcp_server
    from auditex.reporting import (
        verify_enterprise_handoff_pack,
        write_enterprise_handoff_pack,
    )
    from azure_tenant_audit import evidence_db
    from azure_tenant_audit.contracts import build_validation_report

    parent = tmp_path / "out"
    parent.mkdir()
    run = parent / "ci-demo"
    scratch = {"run_job": parent / "tmp", "tmp_is_run": run, "tmp_in_run": run / "tmp", "separate_scratch": tmp_path / "snapshot-tmp"}.get(layout, parent)
    if layout == "cli_out_tmp":
        env = dict(os.environ, TMPDIR=str(scratch))
        env["PYTHONPATH"] = os.pathsep.join(filter(None, (str(ROOT / "src"), env.get("PYTHONPATH", ""))))
        result = subprocess.run(
            [sys.executable, "-B", "-m", "azure_tenant_audit", "--offline", "--sample", str(DEMO),
             "--tenant-name", "ci", "--run-name", "demo", "--out", str(scratch),
             "--auditor-profile", "global-reader", "--plane", "inventory"],
            env=env, capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, result.stderr
    else:
        shutil.copytree(demo_run, run)
    scratch.mkdir(exist_ok=True)
    monkeypatch.setenv("TMPDIR", str(scratch))

    # Exercise both routes for each layout. Real host proof is qualified separately without this stub.
    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda _path: encrypted_proof)
    # Temp roots within the run parent are excluded even when encrypted storage is proved.
    expect_copy = encrypted_proof and not scratch.resolve().is_relative_to(run.resolve().parent)
    original = evidence_db.open_index_read_only
    opened: list[Path] = []
    copies: list[Path] = []

    def inspect_copy(path: Path, *, immutable: bool = True) -> sqlite3.Connection:
        path = Path(path)
        if expect_copy:
            assert path.parent.parent == scratch
            assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            copies.append(path)
        else:
            assert path == run / "index" / "evidence.sqlite"
        assert immutable
        opened.append(path)
        return original(path, immutable=immutable)

    monkeypatch.setattr(evidence_db, "open_index_read_only", inspect_copy)
    summary = mcp_server.summarize_run(str(run))
    assert summary["metadata"]["item_count"] == 1080
    assert sum(row["item_count"] for row in summary["metadata"]["section_stats"]) == 1080
    validation = build_validation_report(run_dir=run, read_only=True)
    assert validation["valid"], validation["issues"]
    assert not {"invalid_evidence_sqlite", "tenant_identity_conflict"} & {issue["code"] for issue in validation["issues"]}
    assert mcp_server.enterprise_handoff(str(run))["handoff_status"] == "ready_with_limitations"
    pack = tmp_path / "pack"
    write_enterprise_handoff_pack(run, pack)
    assert verify_enterprise_handoff_pack(pack)["valid"]
    assert opened
    if expect_copy:
        assert copies and all(not copy.exists() for copy in copies)
    else:
        assert not copies and (run / "index" / "evidence.sqlite").is_file()
    assert not list(scratch.glob("auditex-index-*"))
