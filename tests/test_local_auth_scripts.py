"""Operator scripts after DEC-107: no sign-in script is left; tenant-audit-full runs the reader app's certificate."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FULL = REPO_ROOT / "scripts" / "tenant-audit-full"
THUMBPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"
CERTIFICATE_ARGS = [
    "--tenant-id", "contoso.onmicrosoft.com", "--client-id", "app-id",
    "--certificate-path", "reader.key.pem", "--certificate-thumbprint", THUMBPRINT,
]


def _run_full(tmp_path: Path, *args: str) -> tuple[subprocess.CompletedProcess[str], Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    log = tmp_path / "python.log"
    for name in ("python3", "az", "m365"):
        target = fake_bin / name
        target.write_text(f"#!/usr/bin/env bash\nprintf '%s\\n' \"{name} $*\" >> {log!s}\n", encoding="utf-8")
        target.chmod(0o755)
    env = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"}
    result = subprocess.run(["bash", str(FULL), *args], cwd=tmp_path, env=env, capture_output=True, text=True, check=False)
    return result, log


def test_sign_in_scripts_are_gone() -> None:
    for name in ("tenant-audit-login", "load-local-auth.sh", "m365-home.sh"):
        assert not (REPO_ROOT / "scripts" / name).exists(), name
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "\nlogin:" not in makefile and "az login" not in makefile


def test_select_python_prefers_repo_venv() -> None:
    script = (REPO_ROOT / "scripts" / "select-python.sh").read_text(encoding="utf-8")
    assert 'repo_venv_python="${script_dir}/../.venv/bin/python"' in script
    assert script.index("repo_venv_python=") < script.index("for candidate in")


def test_tenant_audit_full_runs_the_engine_with_the_certificate_and_no_sign_in(tmp_path: Path) -> None:
    result, log = _run_full(tmp_path, *CERTIFICATE_ARGS, "--certificate-password-env", "READER_KEY_PASSWORD",
                            "--tenant-name", "CONTOSO", "--collectors", "identity", "--top", "5")

    assert result.returncode == 0, result.stderr
    (line,) = log.read_text(encoding="utf-8").splitlines()
    assert line.startswith("python3 -m azure_tenant_audit --tenant-name CONTOSO --tenant-id contoso.onmicrosoft.com")
    for expected in ("--client-id app-id", "--certificate-path reader.key.pem", f"--certificate-thumbprint {THUMBPRINT}",
                     "--certificate-password-env READER_KEY_PASSWORD", "--collectors identity", "--top 5"):
        assert expected in line
    for removed in ("--use-azure-cli-token", "--client-secret", "--include-exchange"):
        assert removed not in line


def test_tenant_audit_full_dry_run_redacts_the_certificate_values(tmp_path: Path) -> None:
    result, log = _run_full(tmp_path, *CERTIFICATE_ARGS, "--dry-run")

    assert result.returncode == 0, result.stderr
    assert not log.exists()
    assert "--certificate-path" in result.stdout and "reader.key.pem" not in result.stdout
    assert THUMBPRINT not in result.stdout


@pytest.mark.parametrize("removed", ["--client-secret", "--access-token", "--use-azure-cli-token", "--include-exchange",
                                     "--reauth", "--m365-app-id"])
def test_tenant_audit_full_refuses_a_removed_sign_in_option(tmp_path: Path, removed: str) -> None:
    result, log = _run_full(tmp_path, *CERTIFICATE_ARGS, removed, "constructed-script-canary")

    assert result.returncode == 1
    assert f"{removed} was removed" in result.stderr and "constructed-script-canary" not in result.stderr
    assert not log.exists()


CANARY = "constructed-script-canary"


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        # inline values of removed and kept sensitive options
        ([f"--client-secret={CANARY}"], "--client-secret was removed"),
        ([f"--access-token={CANARY}"], "--access-token was removed"),
        ([f"--certificate-password-file={CANARY}"], "--certificate-password-file=VALUE is not accepted"),
        ([f"--certificate-password-env={CANARY}"], "--certificate-password-env=VALUE is not accepted"),
        ([f"--certificate-thumbprint={CANARY}"], "--certificate-thumbprint=VALUE is not accepted"),
        # abbreviations, separate and inline
        (["--client-sec", CANARY], "Unknown argument 9 (not shown)"),
        ([f"--client-sec={CANARY}"], "Unknown argument 9 (not shown)"),
        (["--access-tok", CANARY], "Unknown argument 9 (not shown)"),
        (["--certificate-pass", CANARY], "Unknown argument 9 (not shown)"),
        # malformed tokens and a stray value
        ([f"-client-secret={CANARY}"], "Unknown argument 9 (not shown)"),
        ([f"--client-secret{CANARY}"], "Unknown argument 9 (not shown)"),
        ([f"---client-secret={CANARY}"], "Unknown argument 9 (not shown)"),
        ([CANARY], "Unknown argument 9 (not shown)"),
        ([f"={CANARY}"], "Unknown argument 9 (not shown)"),
    ],
)
def test_tenant_audit_full_never_echoes_a_rejected_argument(tmp_path: Path, args: list[str], expected: str) -> None:
    result, log = _run_full(tmp_path, *CERTIFICATE_ARGS, *args)

    assert result.returncode == 1
    assert expected in result.stderr
    assert CANARY not in result.stdout and CANARY not in result.stderr
    assert not log.exists()


@pytest.mark.parametrize("option", ["--certificate-password-file", "--certificate-password-env", "--certificate-thumbprint",
                                    "--client-id"])
def test_tenant_audit_full_refuses_a_sensitive_option_without_its_value(tmp_path: Path, option: str) -> None:
    result, log = _run_full(tmp_path, *CERTIFICATE_ARGS, option)

    assert result.returncode == 1
    assert f"{option} needs a value." in result.stderr
    assert "unbound variable" not in result.stderr
    assert not log.exists()


@pytest.mark.parametrize("missing", ["--tenant-id", "--client-id", "--certificate-path", "--certificate-thumbprint"])
def test_tenant_audit_full_needs_the_reader_app_values(tmp_path: Path, missing: str) -> None:
    args = list(CERTIFICATE_ARGS)
    index = args.index(missing)
    del args[index:index + 2]
    result, log = _run_full(tmp_path, *args)

    assert result.returncode == 2
    assert "client ID, its certificate key file and thumbprint are needed" in result.stderr
    assert not log.exists()


def test_bootstrap_installs_no_sign_in_tool() -> None:
    script = (REPO_ROOT / "scripts" / "bootstrap-local-tools.sh").read_text(encoding="utf-8")
    for removed in ("azure-cli", "cli-microsoft365", "ensure_azure_cli", "npm install"):
        assert removed not in script
    assert "Install-Module ExchangeOnlineManagement" in script
