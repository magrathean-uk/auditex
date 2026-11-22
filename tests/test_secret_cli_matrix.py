"""Long and NUL-bearing secret arguments must not appear in CLI diagnostics."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

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
# Flags that name certificate key material or its location. They are members of the generic and engine
# sets, and every other redactor (product, Google, response) redacts them through CERTIFICATE_ARG_FLAGS.
_CERTIFICATE_FLAGS = (
    "--certificate-path", "--certificate-thumbprint", "--certificate-password-env", "--certificate-password-file",
)
_REDACTION_CASES = [
    (name, flag)
    for name, flags in (
        ("generic", (*_GENERIC_FLAGS, *_CERTIFICATE_FLAGS)), ("engine", (*_ENGINE_FLAGS, *_CERTIFICATE_FLAGS)),
        ("product", _PRODUCT_FLAGS), ("google", _GOOGLE_FLAGS),
    )
    for flag in flags
]


@pytest.mark.parametrize("redactor,flag", _REDACTION_CASES)
@pytest.mark.parametrize("abbreviated", [False, True], ids=["full", "abbreviation"])
@pytest.mark.parametrize("inline", [False, True], ids=["separate", "equals"])
def test_sensitive_flag_inventory_is_redacted(redactor: str, flag: str, abbreviated: bool, inline: bool) -> None:
    from auditex.command_runner import SENSITIVE_ARGS, redact_command
    from auditex.google_workspace.run import (
        _SENSITIVE_COMMAND_FLAGS,
        scrub_google_command_line,
    )
    from azure_tenant_audit.auth_runtime import SENSITIVE_CLI_ARGS, scrub_command_line
    from azure_tenant_audit.secret_hygiene import (
        SENSITIVE_ARG_FLAGS,
        collect_sensitive_argv_values,
        redact_argv,
    )

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


@pytest.mark.parametrize("redactor", ["product", "google", "response"])
@pytest.mark.parametrize("flag", _CERTIFICATE_FLAGS)
@pytest.mark.parametrize("inline", [False, True], ids=["separate", "equals"])
def test_every_redactor_hides_certificate_flags(redactor: str, flag: str, inline: bool) -> None:
    from auditex.command_runner import redact_command
    from auditex.google_workspace.run import scrub_google_command_line
    from azure_tenant_audit.response import (
        _scrub_command_line as scrub_response_command_line,
    )
    from azure_tenant_audit.secret_hygiene import CERTIFICATE_ARG_FLAGS

    assert set(_CERTIFICATE_FLAGS) == CERTIFICATE_ARG_FLAGS
    scrub = {"product": redact_command, "google": scrub_google_command_line,
             "response": scrub_response_command_line}[redactor]
    argument = [f"{flag}={CANARY}"] if inline else [flag, CANARY]
    expected = [f"{flag}=***redacted***"] if inline else [flag, "***redacted***"]
    assert scrub(["auditex", *argument, "--tenant-name", "constructed-tenant"]) == [
        "auditex", *expected, "--tenant-name", "constructed-tenant"]


@pytest.mark.parametrize("flag", (*_PRODUCT_FLAGS, *_CERTIFICATE_FLAGS))
@pytest.mark.parametrize("inline", [False, True])
def test_command_runner_redacts_secret_values_echoed_by_child(flag: str, inline: bool, monkeypatch) -> None:
    from auditex.command_runner import run_cli_command

    command = ["auditex", f"{flag}={CANARY}"] if inline else ["auditex", flag, CANARY]

    def echo(argv, **kwargs):
        assert argv == command  # Execution still receives the original credential/path.
        return subprocess.CompletedProcess(argv, 0, stdout=CANARY, stderr=CANARY)

    monkeypatch.setattr("auditex.command_runner._run_process", echo)
    result = run_cli_command(command)
    assert result["returncode"] == 0
    assert CANARY not in str(result)
    assert result["stdout"] == result["stderr"] == "***redacted***"


@pytest.mark.parametrize("secret_source", ["argument", "environment"])
def test_guided_secret_flow_is_refused_and_keeps_secret_out_of_console_and_written_files(
    secret_source: str, tmp_path: Path, monkeypatch, capsys, caplog,
) -> None:
    from auditex import cli as product_cli
    from auditex import guided
    from azure_tenant_audit import cli as engine_cli

    # The real guided flow: a client secret on the command line is refused by name (DEC-107); one in the saved
    # environment is never read, so the run stops for the missing certificate. Neither appears in the console, the
    # log or any written file.
    monkeypatch.setattr(guided, "build_doctor_report", lambda **kwargs: {
        "system": {"os": "test", "machine": "test"}, "readiness": {"core_ready": True},
    })
    monkeypatch.setenv("AUDITEX_LOCAL_AUTH_ENV", str(tmp_path / "local-auth.env"))
    monkeypatch.setenv("AUDITEX_AUTH_CONTEXTS_PATH", str(tmp_path / "auth-contexts.json"))
    monkeypatch.setenv("AUDITEX_M365_HOME", str(tmp_path / "m365-home"))
    if secret_source == "environment":
        monkeypatch.setenv("AZURE_CLIENT_SECRET", CANARY)
    monkeypatch.setattr(engine_cli, "GraphClient", lambda *args, **kwargs: pytest.fail("a secret run never reaches Graph"))
    argv = [
        "--flow", "app-audit", "--tenant-id", "constructed.example", "--tenant-name", "CONSTRUCTED",
        "--client-id", "constructed-app", "--out", str(tmp_path / "runs"), "--run-name", "redaction",
        "--collectors", "identity", "--throttle-mode", "fast", "--no-probe-first",
        "--non-interactive", "--skip-tool-check",
    ]
    if secret_source == "argument":
        with pytest.raises(SystemExit) as raised:
            product_cli.main(["guided-run", *argv, "--client-secret", CANARY])
        assert raised.value.code == 2
        output = capsys.readouterr()
        assert "--client-secret was removed" in output.err and "reader app with a certificate" in output.err
    else:
        assert guided.run_guided(guided.build_guided_parser().parse_args(argv)) == 2
        output = capsys.readouterr()
        assert "--certificate-path" in output.out and "reader-app-permissions.md" in output.out
    assert CANARY not in output.out + output.err + caplog.text
    assert not (tmp_path / "runs" / "CONSTRUCTED-redaction").exists()
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert CANARY.encode() not in path.read_bytes(), path.relative_to(tmp_path)


def _certificate_run_fixtures(monkeypatch, certificate_material):
    """Real engine parser, GraphClient (msal), Teams collector, event log and bundle writer; only the
    Entra token endpoint and the Teams REST transport are fakes."""
    from test_certificate_auth import FakeEntra

    from azure_tenant_audit import certificate_auth
    from azure_tenant_audit import cli as engine_cli
    from azure_tenant_audit.collectors.teams_policy import TeamsPolicyCollector

    entra = FakeEntra(certificate_material)
    real = certificate_auth.build_confidential_client
    monkeypatch.setattr(certificate_auth, "build_confidential_client",
                        lambda credential, **kwargs: real(credential, **{**kwargs, "http_client": entra}))
    seen_tokens: list[str] = []

    class Rest:
        def get(self, name, token, environment, **kwargs):
            seen_tokens.append(token)
            return {"value": [{"Identity": "Global"}], "duration_ms": 1.0}

    monkeypatch.setattr("azure_tenant_audit.collectors.teams_policy.get_adapter", lambda name: Rest())
    monkeypatch.setattr(engine_cli, "REGISTRY", {"teams_policy": TeamsPolicyCollector()})
    return entra, seen_tokens


def _assert_no_certificate_material(root: Path, certificate_material, tokens: list[str], *texts: str) -> None:
    secrets = [
        certificate_material.password, certificate_material.thumbprint, certificate_material.thumbprint.lower(),
        str(certificate_material.root), certificate_material.key_pem_text[40:120], "PRIVATE KEY", *tokens,
    ]
    for text in texts:
        for secret in secrets:
            assert secret not in text
    for path in root.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            for secret in secrets:
                assert secret.encode() not in data, (path.relative_to(root), secret[:12])


@pytest.mark.parametrize("password_source", ["env", "file"])
def test_engine_certificate_run_keeps_key_material_out_of_ledger_and_bundle(
    password_source: str, certificate_material, tmp_path: Path, monkeypatch, capsys, caplog,
) -> None:
    from azure_tenant_audit import cli as engine_cli

    entra, seen_tokens = _certificate_run_fixtures(monkeypatch, certificate_material)
    monkeypatch.setenv("AZURE_CLIENT_SECRET", CANARY)  # ignored, never sent beside the certificate
    password_args = ["--certificate-password-file", str(certificate_material.password_file)]
    if password_source == "env":
        monkeypatch.setenv("AUDITEX_TEST_PFX_PASSWORD", certificate_material.password)
        password_args = ["--certificate-password-env", "AUDITEX_TEST_PFX_PASSWORD"]
    argv = [
        "--tenant-name", "CONSTRUCTED", "--tenant-id", "constructed.onmicrosoft.com", "--client-id", "constructed-app",
        "--certificate-path", str(certificate_material.pfx), "--certificate-thumbprint", certificate_material.thumbprint,
        *password_args, "--out", str(tmp_path / "runs"), "--run-name", "certificate", "--collectors", "teams_policy",
        "--throttle-mode", "fast", "--no-probe-first",
    ]
    assert engine_cli.main(argv) == 0
    assert "AUDITEX_TEST_PFX_PASSWORD" not in os.environ
    assert [request["scope"] for request in entra.token_requests] == [
        "https://graph.microsoft.com/.default", "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default"]
    assert len(seen_tokens) == 5
    run_dir = tmp_path / "runs" / "CONSTRUCTED-certificate"
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    command_line = manifest["command_line"]
    for flag in ("--certificate-path", "--certificate-thumbprint", password_args[0]):
        assert command_line[command_line.index(flag) + 1] == "***redacted***"
    # The run ledger is built from the audit log: two certificate token exchanges, no failure.
    events = [json.loads(line) for line in (run_dir / "audit-log.jsonl").read_text(encoding="utf-8").splitlines()]
    token_events = [event for event in events if str(event.get("event", "")).startswith("graph.token.")]
    assert [event["event"] for event in token_events].count("graph.token.succeeded") == 2
    assert all(event["details"]["mode"] == "certificate" for event in token_events)
    output = capsys.readouterr()
    assert CANARY not in output.out + output.err + caplog.text
    _assert_no_certificate_material(tmp_path, certificate_material, [*seen_tokens, CANARY],
                                    output.out, output.err, caplog.text)


def test_guided_certificate_flow_passes_through_and_keeps_key_material_out(
    certificate_material, tmp_path: Path, monkeypatch, capsys, caplog,
) -> None:
    from auditex import guided

    monkeypatch.setattr(guided, "build_doctor_report", lambda **kwargs: {
        "system": {"os": "test", "machine": "test"}, "readiness": {"core_ready": True},
    })
    monkeypatch.setenv("AUDITEX_LOCAL_AUTH_ENV", str(tmp_path / "local-auth.env"))
    monkeypatch.setenv("AUDITEX_AUTH_CONTEXTS_PATH", str(tmp_path / "auth-contexts.json"))
    monkeypatch.setenv("AUDITEX_M365_HOME", str(tmp_path / "m365-home"))
    monkeypatch.setenv("AZURE_CLIENT_SECRET", CANARY)  # a saved secret is never read for a certificate run
    entra, seen_tokens = _certificate_run_fixtures(monkeypatch, certificate_material)
    argv = [
        "--flow", "app-audit", "--tenant-id", "constructed.onmicrosoft.com", "--tenant-name", "CONSTRUCTED",
        "--client-id", "constructed-app", "--certificate-path", str(certificate_material.pem_encrypted),
        "--certificate-thumbprint", certificate_material.thumbprint,
        "--certificate-password-file", str(certificate_material.password_file),
        "--out", str(tmp_path / "runs"), "--run-name", "guided-certificate", "--collectors", "teams_policy",
        "--throttle-mode", "fast", "--no-probe-first", "--non-interactive", "--skip-tool-check",
    ]
    assert guided.run_guided(guided.build_guided_parser().parse_args(argv)) == 0
    assert len(entra.token_requests) == 2 and len(seen_tokens) == 5
    output = capsys.readouterr()
    manifest = (tmp_path / "runs" / "CONSTRUCTED-guided-certificate" / "run-manifest.json").read_text(encoding="utf-8")
    assert "--certificate-path" in manifest and "--client-secret" not in manifest
    _assert_no_certificate_material(tmp_path, certificate_material, [*seen_tokens, CANARY],
                                    output.out, output.err, caplog.text)

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
    prefix = ["doctor"] if module == "auditex" else ["--offline", "--sample", "__auditex_missing_sample_for_guard_test__"]
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
    # DEC-108 D4: the token commands are gone; the old command line is refused without a fragment of the token.
    assert result.returncode == 2 and "auditex auth was removed" in output
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
