"""Review lane tenant-bootstrap-guards: generated fixture output stays out of git."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _replay_module():
    path = REPO / "tenant-bootstrap" / "scripts" / "replay-known-bad-fixtures.py"
    spec = importlib.util.spec_from_file_location("replay_known_bad_fixtures", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_fixture_replay_default_output_is_git_ignored_and_a_build_dir():
    default_out = Path(_replay_module().build_parser().parse_args([]).out).resolve()
    relative = default_out.relative_to(REPO.resolve()).as_posix()
    manifest = f"{relative}/known-bad-fixture-replay.json"
    check = subprocess.run(["git", "check-ignore", "-q", "--no-index", manifest], cwd=REPO, check=False)
    assert check.returncode == 0, f"{manifest} is not git-ignored"
    build_dirs = json.loads((REPO / ".clean-development.json").read_text(encoding="utf-8"))["buildDirs"]
    assert relative in build_dirs
