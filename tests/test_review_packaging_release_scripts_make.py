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


# R136: the builder's umask must not change the wheel or sdist bytes.
@needs_git_checkout
def test_dist_bytes_do_not_depend_on_the_umask(tmp_path: Path) -> None:
    built = {}
    for umask in ("022", "077"):
        dist = tmp_path / f"dist-{umask}"
        run = _make("dist", f"DIST_DIR={dist}", f"PYTHON={sys.executable}", umask=umask)
        assert run.returncode == 0, run.stderr[-3000:]
        built[umask] = {p.name: _sha(p) for p in dist.iterdir()}
    assert built["022"] == built["077"]


# R137: the venv make install builds gets the setuptools that release-archive and dist need, at one pinned version.
def _setuptools_pin() -> str:
    pins = [dep for dep in PYPROJECT["project"]["optional-dependencies"]["test"] if dep.startswith("setuptools==")]
    assert len(pins) == 1, PYPROJECT["project"]["optional-dependencies"]["test"]
    return pins[0].split("==", 1)[1]


def test_test_extra_pins_setuptools_within_the_build_requirement() -> None:
    pin = _setuptools_pin()
    floor = next(req for req in PYPROJECT["build-system"]["requires"] if req.startswith("setuptools"))
    assert tuple(int(p) for p in pin.split(".")) >= tuple(int(p) for p in floor.split(">=", 1)[1].split("."))


@needs_git_checkout
@pytest.mark.parametrize("target", ["dist", "release-archive"])
def test_release_builds_stop_clearly_without_the_pinned_setuptools(tmp_path: Path, target: str) -> None:
    bare = tmp_path / "bare"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(bare)], check=True, timeout=120)
    run = _make(target, f"PYTHON={bare / 'bin' / 'python'}", f"DIST_DIR={tmp_path / 'dist'}")
    assert run.returncode == 2, (run.returncode, run.stderr[-2000:])
    assert f"setuptools {_setuptools_pin()}" in run.stderr
    assert "Traceback" not in run.stderr


# R139: release-check tests the working tree but packages HEAD, so it must refuse uncommitted changes first.
def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                    *args], cwd=repo, check=True, capture_output=True, timeout=60)


@needs_git_checkout
def test_release_check_refuses_uncommitted_changes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    for name in ("Makefile", "pyproject.toml", ".pre-commit-config.yaml", "scripts/select-python.sh"):
        shutil.copy2(ROOT / name, repo / name)
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")
    with (repo / "pyproject.toml").open("a", encoding="utf-8") as handle:
        handle.write("\n# local change\n")

    run = _make("release-check", f"PYTHON={sys.executable}", cwd=repo, timeout=60)

    assert run.returncode == 2, (run.returncode, run.stderr[-2000:])
    assert "uncommitted" in run.stderr


# R073: audit-deps resolves the base install and every extra pyproject.toml declares.
def test_audit_deps_resolves_every_declared_extra(tmp_path: Path) -> None:
    log = tmp_path / "uv.log"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "uv").write_text(
        "#!/usr/bin/env bash\n"
        f"printf '%s\\n' \"$*\" >> {log}\n"
        "if [[ \"$1 $2\" == 'pip compile' ]]; then\n"
        "  while [[ $# -gt 0 ]]; do if [[ \"$1\" == -o ]]; then : > \"$2\"; fi; shift; done\n"
        "elif [[ \"$1\" == venv ]]; then\n"
        "  dir=\"${@: -1}\"; mkdir -p \"$dir/bin\"\n"
        "  printf '#!/bin/sh\\nexit 0\\n' > \"$dir/bin/python\"; printf '#!/bin/sh\\nexit 0\\n' > \"$dir/bin/pip-audit\"\n"
        "  chmod +x \"$dir/bin/python\" \"$dir/bin/pip-audit\"\n"
        "fi\n",
        encoding="utf-8",
    )
    (fake_bin / "uv").chmod(0o755)
    env = _env(PATH=f"{fake_bin}:{os.environ['PATH']}")
    run = _make("audit-deps", f"PYTHON={sys.executable}", f"AUDIT_DEPS_DIR={tmp_path / 'out'}",
                f"AUDIT_DEPS_IGNORE={tmp_path / 'none.json'}", env=env, timeout=60)

    assert run.returncode == 0, run.stderr[-2000:]
    resolved = set()
    for line in log.read_text(encoding="utf-8").splitlines():
        if line.startswith("pip compile"):
            words = line.split()
            resolved.add(words[words.index("--extra") + 1] if "--extra" in words else "base")
    assert resolved == {"base", *PYPROJECT["project"]["optional-dependencies"]}


# R138: make audit-full runs the engine with the selected interpreter, not whatever python3 is on PATH.
def test_audit_full_uses_the_selected_python(tmp_path: Path) -> None:
    log = tmp_path / "python.log"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    for name in ("python3", "selected-python"):
        (fake_bin / name).write_text(f"#!/usr/bin/env bash\nprintf '%s\\n' \"{name} $*\" >> {log}\n", encoding="utf-8")
        (fake_bin / name).chmod(0o755)
    env = _env(PATH=f"{fake_bin}:{os.environ['PATH']}")
    run = _make("audit-full", f"PYTHON={fake_bin / 'selected-python'}", "TENANT_ID=contoso.onmicrosoft.com",
                "TENANT_NAME=CONTOSO", "CLIENT_ID=app-id", "CERTIFICATE_PATH=reader.key.pem",
                "CERTIFICATE_THUMBPRINT=0123456789ABCDEF0123456789ABCDEF01234567", env=env, timeout=60)

    assert run.returncode == 0, run.stderr[-2000:]
    (line,) = log.read_text(encoding="utf-8").splitlines()
    assert line.startswith("selected-python -m azure_tenant_audit --tenant-name CONTOSO"), line
