from __future__ import annotations

import os
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755)


def test_tenant_audit_login_uses_saved_local_m365_app_id(tmp_path: Path) -> None:
    auth_env = tmp_path / "m365-auth.env"
    auth_env.write_text("M365_CLI_APP_ID=test-app-id\n", encoding="utf-8")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    az_log = tmp_path / "az.log"
    m365_log = tmp_path / "m365.log"
    m365_home_log = tmp_path / "m365-home.log"
    pwsh_log = tmp_path / "pwsh.log"

    _write_executable(
        fake_bin / "az",
        f"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> {az_log!s}
exit 0
""",
    )
    _write_executable(
        fake_bin / "m365",
        f"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> {m365_log!s}
printf '%s\n' "$HOME" >> {m365_home_log!s}
if [[ "${{1:-}}" == "status" ]]; then
  printf '{{"connectionName":"tenant-user","connectedAs":"user","appTenant":"contoso.onmicrosoft.com"}}\n'
fi
exit 0
""",
    )
    _write_executable(
        fake_bin / "pwsh",
        f"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> {pwsh_log!s}
if [[ "$*" == *"Get-Module -ListAvailable ExchangeOnlineManagement"* ]]; then
  printf '{{"Name":"ExchangeOnlineManagement","Version":"3.7.0"}}\n'
fi
exit 0
""",
    )

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["AUDITEX_LOCAL_AUTH_ENV"] = str(auth_env)
    m365_home = tmp_path / "m365-home"
    env["AUDITEX_M365_HOME"] = str(m365_home)

    result = subprocess.run(
        ["bash", "scripts/tenant-audit-login", "contoso.onmicrosoft.com", "--m365"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    az_args = az_log.read_text(encoding="utf-8")
    assert "login --tenant contoso.onmicrosoft.com --allow-no-subscriptions" in az_args
    m365_args = m365_log.read_text(encoding="utf-8")
    assert "login --authType browser --tenant contoso.onmicrosoft.com --output text --appId test-app-id" in m365_args
    pwsh_args = pwsh_log.read_text(encoding="utf-8")
    assert "Get-Module -ListAvailable ExchangeOnlineManagement" in pwsh_args
    # m365 (login and status) runs with HOME pointing at the private folder, which is created with mode 700.
    assert set(m365_home_log.read_text(encoding="utf-8").split()) == {str(m365_home)}
    assert (m365_home.stat().st_mode & 0o777) == 0o700


def test_tenant_audit_full_sources_local_auth_helper() -> None:
    script = (REPO_ROOT / "scripts/tenant-audit-full").read_text(encoding="utf-8")
    assert 'source "${CURRENT_DIR}/load-local-auth.sh"' in script
    assert 'source "${CURRENT_DIR}/m365-home.sh"' in script


def _run_m365_home_script(tmp_path: Path, env_overrides: dict[str, str | None]) -> str:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    _write_executable(
        fake_bin / "m365",
        """#!/usr/bin/env bash
printf '%s\n' "$HOME"
""",
    )
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["HOME"] = str(tmp_path / "real-home")
    env.pop("AUDITEX_M365_HOME", None)
    env.pop("XDG_DATA_HOME", None)
    for key, value in env_overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    result = subprocess.run(
        ["bash", "-c", 'source scripts/m365-home.sh; run_m365 status'],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout.strip()


def test_run_m365_uses_xdg_data_home_and_keeps_home_when_unrouted(tmp_path: Path) -> None:
    data_home = tmp_path / "data"
    assert _run_m365_home_script(tmp_path, {"XDG_DATA_HOME": str(data_home)}) == str(data_home / "auditex" / "m365")
    assert (data_home / "auditex" / "m365").is_dir()
    assert _run_m365_home_script(tmp_path, {}) == str(tmp_path / "real-home")


def test_run_m365_prefers_explicit_folder_and_honours_empty_value(tmp_path: Path) -> None:
    explicit = tmp_path / "explicit"
    routed = {"XDG_DATA_HOME": str(tmp_path / "data"), "AUDITEX_M365_HOME": str(explicit)}
    assert _run_m365_home_script(tmp_path, routed) == str(explicit)
    routed["AUDITEX_M365_HOME"] = ""
    assert _run_m365_home_script(tmp_path, routed) == str(tmp_path / "real-home")


def test_select_python_prefers_repo_venv() -> None:
    script = (REPO_ROOT / "scripts" / "select-python.sh").read_text(encoding="utf-8")
    assert 'repo_venv_python="${script_dir}/../.venv/bin/python"' in script
    assert script.index("repo_venv_python=") < script.index("for candidate in")


def test_tenant_audit_full_uses_allow_no_subscriptions(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    az_log = tmp_path / "az.log"
    py_log = tmp_path / "py.log"

    _write_executable(
        fake_bin / "az",
        f"""#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "account" && "$2" == "show" ]]; then
  exit 1
fi
printf '%s\n' "$*" >> {az_log!s}
exit 0
""",
    )
    _write_executable(
        fake_bin / "python3",
        f"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> {py_log!s}
exit 0
""",
    )

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"

    result = subprocess.run(
        ["bash", "scripts/tenant-audit-full", "--tenant-id", "contoso.onmicrosoft.com", "--tenant-name", "CONTOSO"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    az_args = az_log.read_text(encoding="utf-8")
    assert "login --tenant contoso.onmicrosoft.com --allow-no-subscriptions" in az_args
    py_args = py_log.read_text(encoding="utf-8")
    assert "azure_tenant_audit" in py_args
