"""Hermetic argv regressions for the standalone bootstrap engine copy."""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import socket
import subprocess
import sys
from types import ModuleType

import pytest
import requests

from azure_tenant_audit.secret_hygiene import redact_argv


ROOT = Path(__file__).resolve().parents[1]
VENDORED = ROOT / "tenant-bootstrap" / "azure_tenant_audit"
CANARY = "constructed-canary-vendored-zz9"


@pytest.fixture(params=[False, True], ids=["standalone", "shared-helper"])
def vendored_cli(request, monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("Vendored argv checks must not run handlers, network or subprocesses")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(requests.Session, "request", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.chdir(tmp_path)

    # Bypass the compatibility __init__, which forwards to src inside the repo.
    # An isolated package path makes relative imports use the real vendored files.
    package_name = "_argv_test_bootstrap_engine"
    package = ModuleType(package_name)
    package.__path__ = [str(VENDORED)]
    if request.param:
        package.__path__.append(str(ROOT / "src" / "azure_tenant_audit"))
    monkeypatch.setitem(sys.modules, package_name, package)
    try:
        spec = importlib.util.spec_from_file_location(f"{package_name}.cli", VENDORED / "cli.py")
        assert spec is not None and spec.loader is not None
        cli = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, spec.name, cli)
        spec.loader.exec_module(cli)
        assert Path(cli.__file__) == VENDORED / "cli.py"
        assert Path(sys.modules[f"{package_name}.config"].__file__) == VENDORED / "config.py"
        if request.param:
            helper = sys.modules[f"{package_name}.secret_hygiene"]
            assert cli._redact_argv is helper.redact_argv
        else:
            assert f"{package_name}.secret_hygiene" not in sys.modules
            assert cli._redact_argv.__module__ == spec.name
        monkeypatch.setattr(cli, "run_live", forbidden)
        monkeypatch.setattr(cli, "run_offline", forbidden)
        monkeypatch.setattr(cli, "load_env_file", forbidden)
        monkeypatch.setattr(cli.AuditWriter, "__init__", forbidden)
        yield cli
    finally:
        for name in list(sys.modules):
            if name.startswith(f"{package_name}."):
                del sys.modules[name]


@pytest.mark.parametrize("flag", ["--client-secret", "--access-token"])
@pytest.mark.parametrize("inline", [False, True])
def test_vendored_main_rejects_all_sensitive_abbreviations(vendored_cli, flag, inline, capsys, tmp_path):
    assert vendored_cli.build_parser().allow_abbrev is False
    for length in range(3, len(flag)):
        option = flag[:length]
        argv = [f"{option}={CANARY}"] if inline else [option, CANARY]
        with pytest.raises(SystemExit) as exc:
            vendored_cli.main(argv)
        assert exc.value.code == 2
        assert "error: invalid arguments" in capsys.readouterr().err
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("flag", ["--client-secret", "--access-token"])
@pytest.mark.parametrize("inline", [False, True])
def test_vendored_full_flags_parse_and_scrub_with_prefix_parity(vendored_cli, flag, inline):
    argv = [f"{flag}={CANARY}"] if inline else [flag, CANARY]
    args = vendored_cli.build_parser().parse_args(argv)
    assert getattr(args, flag[2:].replace("-", "_")) == CANARY
    for length in range(3, len(flag) + 1):
        option = flag[:length]
        value_args = [f"{option}={CANARY}"] if inline else [option, CANARY]
        command = ["azure-tenant-audit", *value_args, "--tenant-name", "constructed-tenant"]
        expected = [f"{option}=***redacted***"] if inline else [option, "***redacted***"]
        assert vendored_cli._scrub_command_line(command) == [
            "azure-tenant-audit", *expected, "--tenant-name", "constructed-tenant",
        ]
        assert vendored_cli._scrub_command_line(command) == redact_argv(
            command, sensitive_flags=vendored_cli.SENSITIVE_CLI_ARGS,
        )
    assert vendored_cli._scrub_command_line([flag]) == [flag, "***redacted***"]
    assert vendored_cli._scrub_command_line(["--", "positional"]) == ["--", "positional"]


def test_vendored_fallback_redacts_ambiguous_sensitive_prefixes(vendored_cli, monkeypatch):
    monkeypatch.setattr(vendored_cli, "SENSITIVE_CLI_ARGS", {"--client-secret", "--command-override"})
    assert vendored_cli._scrub_command_line(["--c", CANARY]) == ["--c", "***redacted***"]
    assert vendored_cli._scrub_command_line([f"--c={CANARY}"]) == ["--c=***redacted***"]


def test_vendored_parser_constructions_disable_abbreviations():
    for path in VENDORED.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"ArgumentParser", "add_parser"}:
                assert any(
                    keyword.arg == "allow_abbrev" and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False for keyword in node.keywords
                ), (path, node.lineno)
