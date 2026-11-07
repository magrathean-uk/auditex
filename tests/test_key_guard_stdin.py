"""Inherited stdin must be admitted before buffered input is consumed."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_guarded_admission import ADDRESS, KEY, private_run  # noqa: F401 - shared fixture
from test_secret_cli_matrix import _pythons


_CHILD = r'''
import sys
from auditex.auth import resolve_token_input
from azure_tenant_audit.run_files import GuardContext, UnsafeRunFileError
if sys.argv[2] == "prebuffer":
    sys.stdin.read(1)
elif sys.argv[2] == "prebuffer-binary":
    sys.stdin.buffer.read(1)
with GuardContext() as context:
    context.bind_run(sys.argv[1])
    try:
        token, _ = resolve_token_input(token_stdin=True)
    except UnsafeRunFileError:
        print("REFUSED")
    else:
        print("ACCEPTED" if token else "EMPTY")
'''


def _env() -> dict[str, str]:
    env = os.environ.copy()
    source = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = os.pathsep.join((source, env.get("PYTHONPATH", "")))
    return env


@pytest.mark.parametrize("member", ["sensitive-users.key", "sensitive-users.txt"])
def test_stdin_refuses_registered_private_files(private_run: Path, member: str) -> None:
    with (private_run / "operator-inputs" / member).open("rb") as source:
        result = subprocess.run([sys.executable, "-B", "-c", _CHILD, str(private_run), "plain"],
                                stdin=source, env=_env(), capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert result.stdout == b"REFUSED\n"
    assert KEY not in result.stdout + result.stderr and ADDRESS.encode() not in result.stdout + result.stderr


def test_stdin_refuses_an_unregistered_hardlink(private_run: Path, tmp_path: Path) -> None:
    source = tmp_path / "unrelated"
    source.write_text("ordinary input", encoding="utf-8")
    alias = tmp_path / "hardlink"
    os.link(source, alias)
    with alias.open("rb") as handle:
        result = subprocess.run([sys.executable, "-B", "-c", _CHILD, str(private_run), "plain"],
                                stdin=handle, env=_env(), capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert result.stdout == b"REFUSED\n"


@pytest.mark.parametrize("kind", ["unseen-file", "pipe"])
def test_stdin_allows_unseen_single_link_file_and_pipe(private_run: Path, tmp_path: Path, kind: str) -> None:
    args = [sys.executable, "-B", "-c", _CHILD, str(private_run), "plain"]
    if kind == "pipe":
        result = subprocess.run(args, input=b"ordinary\n", env=_env(), capture_output=True, timeout=15, check=False)
    else:
        source = tmp_path / "unseen"
        source.write_bytes(b"ordinary\n")
        with source.open("rb") as handle:
            result = subprocess.run(args, stdin=handle, env=_env(), capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert result.stdout == b"ACCEPTED\n"


@pytest.mark.parametrize("mode", ["prebuffer", "prebuffer-binary"])
def test_stdin_rejects_unverifiable_buffered_input(private_run: Path, tmp_path: Path, mode: str) -> None:
    source = tmp_path / "buffered"
    source.write_bytes(b"ordinary\nwith prior buffered bytes\n")
    with source.open("rb") as handle:
        result = subprocess.run([sys.executable, "-B", "-c", _CHILD, str(private_run), mode],
                                stdin=handle, env=_env(), capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert result.stdout == b"REFUSED\n"


@pytest.mark.parametrize("size", [32, 20000])
@pytest.mark.parametrize("mode", ["prebuffer", "prebuffer-binary"])
def test_stdin_rejects_prebuffered_pipe(private_run: Path, size: int, mode: str) -> None:
    result = subprocess.run([sys.executable, "-B", "-c", _CHILD, str(private_run), mode],
                            input=b"x" * size, env=_env(),
                            capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert result.stdout == b"REFUSED\n"


@pytest.mark.parametrize("python", _pythons())
@pytest.mark.parametrize("mode", ["plain", "prebuffer", "prebuffer-binary"])
def test_pipe_provenance_on_supported_runtimes(private_run: Path, python: str, mode: str) -> None:
    result = subprocess.run([python, "-B", "-c", _CHILD, str(private_run), mode],
                            input=b"constructed-input\n", env=_env(), capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert result.stdout == (b"ACCEPTED\n" if mode == "plain" else b"REFUSED\n")


@pytest.mark.skipif(not hasattr(os, "openpty"), reason="pseudo-terminals are unavailable")
def test_stdin_allows_a_terminal(private_run: Path) -> None:
    master, slave = os.openpty()
    try:
        process = subprocess.Popen([sys.executable, "-B", "-c", _CHILD, str(private_run), "plain"],
                                   stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_env())
        os.close(slave)
        slave = -1
        os.write(master, b"ordinary\n\x04")
        try:
            stdout, stderr = process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            pytest.fail("terminal stdin did not reach EOF")
        assert process.returncode == 0, stderr.decode("utf-8", errors="replace")
        assert stdout == b"ACCEPTED\n"
    finally:
        os.close(master)
        if slave >= 0:
            os.close(slave)
