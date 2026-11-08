"""Long and NUL-bearing secret arguments must not appear in CLI diagnostics."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig

import pytest


CANARY = "constructed-canary-r2-" * 18


def _pythons() -> list[str]:
    candidates = [sys.executable, *(shutil.which(f"python3.{minor}") for minor in (11, 12, 13))]
    candidates.extend(os.environ.get("AUDITEX_TEST_PYTHONS", "").split(os.pathsep))
    return list(dict.fromkeys(path for path in candidates if path and Path(path).is_file()))


_HARNESS = r'''
import contextlib, io, logging, os, runpy, sys, traceback
from auditex.command_runner import SENSITIVE_ARGS
from auditex.google_workspace.run import _SENSITIVE_COMMAND_FLAGS
from azure_tenant_audit.auth_runtime import SENSITIVE_CLI_ARGS
from azure_tenant_audit.response import RESPONSE_SENSITIVE_ARGS
from azure_tenant_audit.secret_hygiene import SENSITIVE_ARG_FLAGS

token = os.environ["AUDITEX_TEST_TOKEN_CANARY"]
flags = SENSITIVE_ARG_FLAGS | SENSITIVE_CLI_ARGS | SENSITIVE_ARGS | RESPONSE_SENSITIVE_ARGS | _SENSITIVE_COMMAND_FLAGS
failures = []
for module in ("auditex", "azure_tenant_audit"):
    prefix = ["auth", "inspect-token"] if module == "auditex" else ["--offline", "--sample", "__auditex_missing_sample_for_guard_test__"]
    for flag in sorted(flags):
        for inline in (False, True):
            for nul in (False, True):
                value = token[:150] + "\x00" + token[150:] if nul else token
                option = [flag + "=" + value] if inline else [flag, value]
                sys.argv = [module, *prefix, *option]
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    logging.basicConfig(stream=stderr, force=True)
                    try:
                        runpy.run_module(module, run_name="__main__", alter_sys=True)
                    except SystemExit:
                        pass
                    except BaseException as exc:
                        traceback.print_exc()
                        if not (module == "auditex" and flag == "--token" and type(exc) is ValueError and str(exc) == "token is not a JWT"):
                            failures.append((module, flag, inline, nul, "unexpected", type(exc).__name__))
                output = stdout.getvalue() + stderr.getvalue()
                if any(value[i:i + 16] in output for i in range(len(value) - 15)):
                    failures.append((module, flag, inline, nul, "secret fragment"))
if failures:
    print("failures:", failures)
    raise SystemExit(1)
print("checked", len(flags) * 8, "entrypoint cases")
'''


def _child_env() -> tuple[Path, dict[str, str]]:
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env.pop("AUDITEX_SENSITIVE_USERS_FILE", None)
    env["AUDITEX_TEST_TOKEN_CANARY"] = CANARY
    env["PYTHONPATH"] = os.pathsep.join((str(root / "src"), sysconfig.get_paths()["purelib"]))
    return root, env


@pytest.mark.parametrize("python", _pythons())
def test_long_token_cli_traceback_contains_no_secret_fragments(python: str) -> None:
    root, env = _child_env()
    result = subprocess.run(
        [python, "-B", "-m", "auditex", "auth", "inspect-token", "--token", CANARY],
        cwd=root, env=env, capture_output=True, text=True, timeout=30, check=False,
    )
    output = result.stdout + result.stderr
    assert "ValueError: token is not a JWT" in output
    assert not any(CANARY[i:i + 16] in output for i in range(len(CANARY) - 15))


@pytest.mark.parametrize("python", _pythons())
def test_cli_secret_matrix_does_not_echo_long_or_nul_arguments(python: str) -> None:
    root, env = _child_env()
    result = subprocess.run(
        [python, "-B", "-c", _HARNESS], cwd=root, env=env,
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("python", _pythons())
def test_mcp_entrypoint_does_not_echo_unrecognised_secret(python: str) -> None:
    root, env = _child_env()
    result = subprocess.run(
        [python, "-B", "-m", "auditex.mcp_server", "--client-secret", CANARY],
        cwd=root, env=env, capture_output=True, text=True, timeout=30, check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 2
    assert not any(CANARY[i:i + 16] in output for i in range(len(CANARY) - 15))


def test_parser_chained_exception_traceback_does_not_echo_secret(tmp_path: Path) -> None:
    import traceback
    from auditex.cli import main

    with pytest.raises(SystemExit) as error:
        main(["gate", str(tmp_path), "--fail-on", CANARY, "--client-secret", CANARY])
    rendered = "".join(traceback.format_exception(error.value))
    assert not any(CANARY[i:i + 16] in rendered for i in range(len(CANARY) - 15))
    assert error.value.__cause__ is None and error.value.__context__ is None


@pytest.mark.parametrize("entry", ["engine", "product"])
def test_single_malformed_sensitive_option_does_not_echo_value(entry: str, capsys) -> None:
    from auditex.cli import main as product_main
    from azure_tenant_audit.cli import main as engine_main

    main = engine_main if entry == "engine" else product_main
    argv = [f"--sensitive-users {CANARY}"]
    if entry == "product":
        argv.insert(0, "run")
    with pytest.raises(SystemExit):
        main(argv)
    output = capsys.readouterr()
    assert CANARY not in output.out + output.err
