"""Hermetic argv regressions for the CLI that `tenant-bootstrap` forwards to."""
from __future__ import annotations

import ast
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest
import requests

from azure_tenant_audit import auth_runtime, cli
from azure_tenant_audit.secret_hygiene import redact_argv

ROOT = Path(__file__).resolve().parents[1]
CANARY = "constructed-canary-vendored-zz9"


@pytest.fixture
def engine_cli(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError("argv checks must not run handlers, network or subprocesses")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(requests.Session, "request", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "run_live", forbidden)
    monkeypatch.setattr(cli, "run_offline", forbidden)
    monkeypatch.setattr(cli, "load_env_file", forbidden)
    return cli


@pytest.mark.parametrize("flag", ["--client-secret", "--access-token"])
@pytest.mark.parametrize("inline", [False, True])
def test_main_rejects_all_sensitive_abbreviations(engine_cli, flag, inline, capsys, tmp_path):
    assert engine_cli.build_parser().allow_abbrev is False
    for length in range(3, len(flag)):
        option = flag[:length]
        argv = [f"{option}={CANARY}"] if inline else [option, CANARY]
        with pytest.raises(SystemExit) as exc:
            engine_cli.main(argv)
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "error: invalid arguments" in err
        assert CANARY not in err
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("flag", ["--client-secret", "--access-token"])
@pytest.mark.parametrize("inline", [False, True])
def test_full_flags_parse_and_scrub_with_prefix_parity(engine_cli, flag, inline):
    argv = [f"{flag}={CANARY}"] if inline else [flag, CANARY]
    args = engine_cli.build_parser().parse_args(argv)
    assert getattr(args, flag[2:].replace("-", "_")) == CANARY
    for length in range(3, len(flag) + 1):
        option = flag[:length]
        value_args = [f"{option}={CANARY}"] if inline else [option, CANARY]
        command = ["azure-tenant-audit", *value_args, "--tenant-name", "constructed-tenant"]
        expected = [f"{option}=***redacted***"] if inline else [option, "***redacted***"]
        assert auth_runtime.scrub_command_line(command) == [
            "azure-tenant-audit", *expected, "--tenant-name", "constructed-tenant",
        ]
        assert auth_runtime.scrub_command_line(command) == redact_argv(
            command, sensitive_flags=auth_runtime.SENSITIVE_CLI_ARGS,
        )
    assert auth_runtime.scrub_command_line([flag]) == [flag, "***redacted***"]
    assert auth_runtime.scrub_command_line(["--", "positional"]) == ["--", "positional"]


def test_ambiguous_sensitive_prefixes_are_redacted(engine_cli, monkeypatch):
    monkeypatch.setattr(auth_runtime, "SENSITIVE_CLI_ARGS", {"--client-secret", "--command-override"})
    assert auth_runtime.scrub_command_line(["--c", CANARY]) == ["--c", "***redacted***"]
    assert auth_runtime.scrub_command_line([f"--c={CANARY}"]) == ["--c=***redacted***"]


def test_the_bootstrap_forwarder_rejects_abbreviations_without_echo(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "tenant-bootstrap")}
    done = subprocess.run(
        [sys.executable, "-m", "azure_tenant_audit", f"--client-sec={CANARY}"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
    )
    assert done.returncode == 2
    assert "error: invalid arguments" in done.stderr
    assert CANARY not in done.stderr + done.stdout


def test_parser_constructions_disable_abbreviations():
    for path in (ROOT / "src" / "azure_tenant_audit").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"ArgumentParser", "add_parser"}:
                assert any(
                    keyword.arg == "allow_abbrev" and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False for keyword in node.keywords
                ), (path, node.lineno)
