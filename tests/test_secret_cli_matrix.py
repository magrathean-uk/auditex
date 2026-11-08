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

# Explicit inventories, rather than deriving expectations from the production sets:
# dropping a flag from a set must fail its regression case.
_ENGINE_FLAGS = (
    "--client-secret", "--access-token", "--sensitive-users", "--partner-domains",
    "--env", "--break-glass-accounts",
)
_GOOGLE_FLAGS = (
    "--service-account-key", "--oauth-client", "--token-cache",
    "--sensitive-users", "--partner-domains",
)
_PRODUCT_FLAGS = (
    *_ENGINE_FLAGS, "--token", "--token-file", "--command-override", "--adapter-override",
    "--service-account-key", "--oauth-client", "--token-cache",
)
_GENERIC_FLAGS = (*_PRODUCT_FLAGS, "--secret", "--password")
_REDACTION_CASES = [
    (name, flag)
    for name, flags in (
        ("generic", _GENERIC_FLAGS), ("engine", _ENGINE_FLAGS),
        ("product", _PRODUCT_FLAGS), ("google", _GOOGLE_FLAGS),
    )
    for flag in flags
]


@pytest.mark.parametrize("redactor,flag", _REDACTION_CASES)
@pytest.mark.parametrize("abbreviated", [False, True], ids=["full", "abbreviation"])
@pytest.mark.parametrize("inline", [False, True], ids=["separate", "equals"])
def test_sensitive_flag_inventory_is_redacted(redactor: str, flag: str, abbreviated: bool, inline: bool) -> None:
    from auditex.command_runner import SENSITIVE_ARGS, redact_command
    from auditex.google_workspace.run import _SENSITIVE_COMMAND_FLAGS, scrub_google_command_line
    from azure_tenant_audit.auth_runtime import SENSITIVE_CLI_ARGS, scrub_command_line
    from azure_tenant_audit.secret_hygiene import SENSITIVE_ARG_FLAGS, collect_sensitive_argv_values, redact_argv

    flags, scrub = {
        "generic": (SENSITIVE_ARG_FLAGS, redact_argv),
        "engine": (SENSITIVE_CLI_ARGS, scrub_command_line),
        "product": (SENSITIVE_ARGS, redact_command),
        "google": (_SENSITIVE_COMMAND_FLAGS, scrub_google_command_line),
    }[redactor]
    assert flag in flags
    option = flag[:-1] if abbreviated else flag
    argument = [f"{option}={CANARY}"] if inline else [option, CANARY]
    argv = ["auditex", *argument, "--tenant-name", "constructed-tenant"]
    expected = [f"{option}=***redacted***"] if inline else [option, "***redacted***"]
    assert scrub(argv) == ["auditex", *expected, "--tenant-name", "constructed-tenant"]
    assert collect_sensitive_argv_values(argv, sensitive_flags=flags) == {CANARY}


@pytest.mark.parametrize("flag", _PRODUCT_FLAGS)
@pytest.mark.parametrize("inline", [False, True])
def test_command_runner_redacts_secret_values_echoed_by_child(flag: str, inline: bool, monkeypatch) -> None:
    from auditex.command_runner import run_cli_command

    command = ["auditex", f"{flag}={CANARY}"] if inline else ["auditex", flag, CANARY]

    def echo(argv, **kwargs):
        assert argv == command  # Execution still receives the original credential/path.
        return subprocess.CompletedProcess(argv, 0, stdout=CANARY, stderr=CANARY)

    monkeypatch.setattr("auditex.command_runner.subprocess.run", echo)
    result = run_cli_command(command)
    assert result["returncode"] == 0
    assert CANARY not in str(result)
    assert result["stdout"] == result["stderr"] == "***redacted***"


@pytest.mark.parametrize("secret_source", ["argument", "environment"])
def test_guided_app_flow_keeps_secret_out_of_console_and_written_files(
    secret_source: str, tmp_path: Path, monkeypatch, capsys, caplog,
) -> None:
    from auditex import guided
    from azure_tenant_audit import cli as engine_cli
    from azure_tenant_audit.collectors.base import CollectorResult

    # Exercise the real guided flow, engine parser, event log and bundle writer.
    # Only the machine doctor and tenant transport/collector are replaced.
    monkeypatch.setattr(guided, "build_doctor_report", lambda **kwargs: {
        "system": {"os": "test", "machine": "test"}, "readiness": {"core_ready": True},
    })
    auth_env = tmp_path / "local-auth.env"
    monkeypatch.setenv("AUDITEX_LOCAL_AUTH_ENV", str(auth_env))
    monkeypatch.setenv("AUDITEX_AUTH_CONTEXTS_PATH", str(tmp_path / "auth-contexts.json"))
    monkeypatch.setenv("AUDITEX_M365_HOME", str(tmp_path / "m365-home"))
    if secret_source == "environment":
        monkeypatch.setenv("AZURE_CLIENT_SECRET", CANARY)

    def client(auth, **kwargs):
        assert auth.auth_mode == "app" and auth.client_secret == CANARY
        return object()

    class Collector:
        name = "identity"

        def run(self, context):
            return CollectorResult(name=self.name, status="ok", item_count=0, message="ok", payload={"value": []})

    monkeypatch.setattr(engine_cli, "GraphClient", client)
    monkeypatch.setattr(engine_cli, "REGISTRY", {"identity": Collector()})
    argv = [
        "--flow", "app-audit", "--tenant-id", "constructed.example", "--tenant-name", "CONSTRUCTED",
        "--client-id", "constructed-app", "--out", str(tmp_path / "runs"), "--run-name", "redaction",
        "--collectors", "identity", "--throttle-mode", "fast", "--no-probe-first",
        "--non-interactive", "--skip-login-check", "--skip-tool-check",
    ]
    if secret_source == "argument":
        argv.extend(["--client-secret", CANARY])
    assert guided.run_guided(guided.build_guided_parser().parse_args(argv)) == 0
    output = capsys.readouterr()
    assert CANARY not in output.out + output.err + caplog.text
    run_dir = tmp_path / "runs" / "CONSTRUCTED-redaction"
    manifest = (run_dir / "run-manifest.json").read_text(encoding="utf-8")
    assert "--client-secret" in manifest and "***redacted***" in manifest
    assert (run_dir / "audit-log.jsonl").is_file()
    assert auth_env.is_file()
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert CANARY.encode() not in path.read_bytes(), path.relative_to(tmp_path)


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
