"""Release tooling: make dist, release smoke, release-check, audit-deps, audit-full and Dependabot (lane fixes)."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
VERSION = PYPROJECT["project"]["version"]

needs_git_checkout = pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("make") is None or not (ROOT / ".git").exists(),
    reason="needs make and a git checkout",
)


def _env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in {"SOURCE_DATE_EPOCH", "MAKEFLAGS", "MAKELEVEL", "MFLAGS"}}
    env.update(extra)
    return env


def _make(*args: str, umask: str = "022", cwd: Path = ROOT, env: dict[str, str] | None = None,
          timeout: int = 300) -> subprocess.CompletedProcess[str]:
    command = " ".join(["umask", umask, "&&", "exec", "make", "--no-print-directory", *[_quote(a) for a in args]])
    return subprocess.run(["sh", "-c", command], cwd=cwd, env=env or _env(), capture_output=True, text=True,
                          timeout=timeout)


def _quote(value: str) -> str:
    import shlex

    return shlex.quote(value)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# R070: make dist leaves only the artefacts of this build in the dist folder.
@needs_git_checkout
def test_dist_replaces_stale_artefacts(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "auditex-0.0.1-py3-none-any.whl").write_bytes(b"stale")
    (dist / "auditex-0.0.1.tar.gz").write_bytes(b"stale")

    run = _make("dist", f"DIST_DIR={dist}", f"PYTHON={sys.executable}")

    assert run.returncode == 0, run.stderr[-3000:]
    assert sorted(p.name for p in dist.iterdir()) == [f"auditex-{VERSION}-py3-none-any.whl", f"auditex-{VERSION}.tar.gz"]


# R070: release smoke refuses an ambiguous dist folder instead of testing whichever file sorts first.
def test_release_smoke_refuses_more_than_one_wheel(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    for name in ("auditex-1.7.0-py3-none-any.whl", f"auditex-{VERSION}-py3-none-any.whl",
                 "auditex-1.7.0.tar.gz", f"auditex-{VERSION}.tar.gz"):
        (dist / name).write_bytes(b"x")
    run = subprocess.run(["bash", str(ROOT / "scripts" / "release-smoke.sh"), str(dist), str(tmp_path / "smoke")],
                         env=_env(PYTHON="false"), capture_output=True, text=True, timeout=60)
    assert run.returncode == 2, (run.returncode, run.stderr)
    assert "exactly one wheel" in run.stderr


def test_release_smoke_refuses_a_wheel_of_another_version(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "auditex-0.0.1-py3-none-any.whl").write_bytes(b"x")
    (dist / "auditex-0.0.1.tar.gz").write_bytes(b"x")
    run = subprocess.run(["bash", str(ROOT / "scripts" / "release-smoke.sh"), str(dist), str(tmp_path / "smoke")],
                         env=_env(PYTHON="false"), capture_output=True, text=True, timeout=60)
    assert run.returncode == 2, (run.returncode, run.stderr)
    assert f"auditex-{VERSION}" in run.stderr
