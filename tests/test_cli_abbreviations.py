"""Security regressions for every public parser, using constructed values only."""
from __future__ import annotations

import argparse
import ast
from pathlib import Path

import pytest

from auditex import cli as product_cli
from auditex import model_training, mcp_server
from auditex.command_runner import SENSITIVE_ARGS
from auditex.demo import build_demo_parser
from auditex.google_workspace.run import _SENSITIVE_COMMAND_FLAGS, scrub_google_command_line
from auditex.guided import build_guided_parser
from auditex.mcp_server import _build_mcp_parser, main as mcp_main
from auditex.model_training import training_main
from azure_tenant_audit import cli as engine_cli
from azure_tenant_audit.auth_runtime import SENSITIVE_CLI_ARGS
from azure_tenant_audit.response import RESPONSE_SENSITIVE_ARGS
from azure_tenant_audit.secret_hygiene import SENSITIVE_ARG_FLAGS, collect_sensitive_argv_values, redact_argv


SENSITIVE_FLAGS = sorted(SENSITIVE_ARG_FLAGS | SENSITIVE_CLI_ARGS | SENSITIVE_ARGS | RESPONSE_SENSITIVE_ARGS | _SENSITIVE_COMMAND_FLAGS)
BUILDERS = [
    engine_cli.build_parser, build_guided_parser, build_demo_parser, _build_mcp_parser,
    *(getattr(product_cli, name) for name in sorted(vars(product_cli)) if name.startswith("_build_") and name.endswith("_parser")),
]


def _abbreviation(flag: str) -> str:
    return {"--client-secret": "--client-sec", "--access-token": "--access-tok"}.get(flag, flag[:-1])


def _required_args(parser: argparse.ArgumentParser) -> list[str]:
    """Supply valid required syntax without executing any command handlers."""
    argv = []
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            name, child = next(iter(action.choices.items()))
            argv.extend([name, *_required_args(child)])
        elif action.required or (not action.option_strings and action.nargs not in ("?", "*")):
            if action.option_strings:
                argv.append(action.option_strings[0])
            if action.nargs != 0:
                value = str(next(iter(action.choices))) if action.choices else "1" if action.type in (int, float) else "constructed"
                argv.extend([value] * (action.nargs if isinstance(action.nargs, int) else 1))
    return argv


def _parsers(parser: argparse.ArgumentParser):
    yield parser
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                yield from _parsers(child)


@pytest.mark.parametrize("builder", BUILDERS, ids=lambda builder: f"{builder.__module__}.{builder.__name__}")
def test_every_parser_rejects_sensitive_abbreviations(builder, capsys, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")
    monkeypatch.chdir(tmp_path)
    for parser in _parsers(builder()):
        assert parser.allow_abbrev is False, parser.prog
        required = _required_args(parser)
        parser.parse_args(required)
        for flag in SENSITIVE_FLAGS:
            option = _abbreviation(flag)
            for extra in ([option, "constructed-canary-argv-zz9"], [f"{option}=constructed-canary-argv-zz9"]):
                with pytest.raises(SystemExit) as exc:
                    parser.parse_args([*required, *extra])
                assert exc.value.code == 2, parser.prog
                assert "error: invalid arguments" in capsys.readouterr().err, parser.prog
    assert not list(tmp_path.rglob("run-manifest.json"))


@pytest.mark.parametrize("flag", SENSITIVE_FLAGS)
@pytest.mark.parametrize("inline", [False, True])
@pytest.mark.parametrize("entry", ["engine", "legacy", "run", "guided", "probe", "login", "import-token", "inspect-token", "google-run", "google-probe", "google-doctor", "setup-google", "response", "mcp", "setup", "doctor", "training"])
def test_entrypoints_reject_before_bundle_creation(entry, flag, inline, monkeypatch, tmp_path, capsys) -> None:
    from azure_tenant_audit.output import AuditWriter

    def forbidden_writer(*args, **kwargs):
        pytest.fail("Rejected argv must never reach bundle creation")

    monkeypatch.setattr(AuditWriter, "__init__", forbidden_writer)
    # A future regression must fail safely before a handler can sign in, read
    # credentials, install tools or write an auth context.
    monkeypatch.setattr(engine_cli, "run_live", forbidden_writer)
    for name in ("run_guided", "run_live_probe", "run_response", "run_google_live", "run_google_probe", "google_doctor", "run_setup", "print_doctor_report", "build_setup_guide"):
        monkeypatch.setattr(product_cli, name, forbidden_writer)
    for name in ("login_connection", "resolve_token_input", "import_token_context", "inspect_token_claims"):
        monkeypatch.setattr(product_cli.auditex_auth, name, forbidden_writer)
    monkeypatch.setattr(model_training, "validate_training_pack", forbidden_writer)
    monkeypatch.setattr(mcp_server, "mcp_root", forbidden_writer)
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")
    monkeypatch.chdir(tmp_path)
    entries = {
        "engine": (engine_cli.main, []),
        "legacy": (product_cli.main, []),
        "run": (product_cli.main, ["run"]),
        "guided": (product_cli.main, ["guided-run"]),
        "probe": (product_cli.main, ["probe", "live", "--tenant-name", "constructed"]),
        "login": (product_cli.main, ["auth", "login"]),
        "import-token": (product_cli.main, ["auth", "import-token", "--name", "constructed"]),
        "inspect-token": (product_cli.main, ["auth", "inspect-token"]),
        "google-run": (product_cli.main, ["google", "run", "--tenant-name", "constructed"]),
        "google-probe": (product_cli.main, ["google", "probe"]),
        "google-doctor": (product_cli.main, ["google", "doctor"]),
        "setup-google": (product_cli.main, ["setup-guide", "google"]),
        "response": (product_cli.main, ["response", "run", "--tenant-name", "constructed", "--action", "message_trace", "--intent", "constructed"]),
        "mcp": (mcp_main, []),
        "setup": (product_cli.main, ["setup"]),
        "doctor": (product_cli.main, ["doctor"]),
        "training": (training_main, ["--pack-dir", "constructed", "--output-dir", "constructed"]),
    }
    main, argv = entries[entry]
    option = _abbreviation(flag)
    extra = [f"{option}=constructed-canary-argv-zz9"] if inline else [option, "constructed-canary-argv-zz9"]
    with pytest.raises(SystemExit) as exc:
        main([*argv, *extra])
    assert exc.value.code == 2
    assert "error: invalid arguments" in capsys.readouterr().err
    assert not list(tmp_path.rglob("run-manifest.json"))


def test_all_parser_constructions_explicitly_disable_abbreviations() -> None:
    root = Path(__file__).resolve().parents[1] / "src"
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"ArgumentParser", "add_parser"}:
                assert any(keyword.arg == "allow_abbrev" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False for keyword in node.keywords), (path, node.lineno)


def test_public_parsers_use_the_shared_redacting_factory(monkeypatch) -> None:
    from azure_tenant_audit.secret_hygiene import DiagnosticRedactingArgumentParser

    root = Path(__file__).resolve().parents[1] / "src"
    plain = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        modules = {alias.asname or alias.name for node in ast.walk(tree)
                   if isinstance(node, ast.Import) for alias in node.names if alias.name == "argparse"}
        constructors = {alias.asname or alias.name for node in ast.walk(tree)
                        if isinstance(node, ast.ImportFrom) and node.module == "argparse"
                        for alias in node.names if alias.name == "ArgumentParser"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                    and func.value.id in modules and func.attr == "ArgumentParser"):
                plain.append((str(path.relative_to(root)), node.lineno))
            if isinstance(func, ast.Name) and func.id in constructors:
                plain.append((str(path.relative_to(root)), node.lineno))
    assert not plain
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")
    for builder in BUILDERS:
        for parser in _parsers(builder()):
            assert isinstance(parser, DiagnosticRedactingArgumentParser), parser.prog
            assert parser.allow_abbrev is False, parser.prog


@pytest.mark.parametrize("entry", ["probe", "google-run"])
@pytest.mark.parametrize("equals", [False, True])
def test_other_product_parsers_hide_rejected_sensitive_user_paths(entry, equals, tmp_path, capsys):
    path = tmp_path / "confidential user path.json"
    prefix = (["probe", "live", "--tenant-name", "constructed"] if entry == "probe"
              else ["google", "run", "--tenant-name", "constructed"])
    extra = [f"--sensitive-users={path}"] if equals else ["--sensitive-users", str(path)]
    with pytest.raises(SystemExit) as caught:
        product_cli.main([*prefix, *extra])
    assert caught.value.code == 2
    diagnostic = capsys.readouterr().err
    assert "error: invalid arguments" in diagnostic
    assert str(path) not in diagnostic
    assert path.name not in diagnostic


@pytest.mark.parametrize("flag", SENSITIVE_FLAGS)
@pytest.mark.parametrize("inline", [False, True])
def test_all_sensitive_sets_redact_unique_prefixes(flag, inline) -> None:
    option = _abbreviation(flag)
    argv = [f"{option}=constructed-canary-argv-zz9"] if inline else [option, "constructed-canary-argv-zz9"]
    for flags in (SENSITIVE_ARG_FLAGS, SENSITIVE_CLI_ARGS, SENSITIVE_ARGS, RESPONSE_SENSITIVE_ARGS, _SENSITIVE_COMMAND_FLAGS):
        if flag in flags:
            assert "constructed-canary-argv-zz9" not in str(redact_argv(argv, sensitive_flags=flags))
            assert collect_sensitive_argv_values(argv, sensitive_flags=flags) == {"constructed-canary-argv-zz9"}
    if flag in _SENSITIVE_COMMAND_FLAGS:
        assert "constructed-canary-argv-zz9" not in str(scrub_google_command_line(argv))
