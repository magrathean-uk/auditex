from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from azure_tenant_audit.secret_hygiene import secure_write_json, secure_write_text
from azure_tenant_audit.utils import load_env_file

from . import auth_runtime


LOCAL_AUTH_ENV_VAR = "AUDITEX_LOCAL_AUTH_ENV"
AUTH_CONTEXTS_PATH_ENV_VAR = "AUDITEX_AUTH_CONTEXTS_PATH"


def default_local_auth_env_path() -> Path:
    configured = os.environ.get(LOCAL_AUTH_ENV_VAR)
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parents[2] / ".secrets" / "m365-auth.env"


def default_auth_contexts_path() -> Path:
    configured = os.environ.get(AUTH_CONTEXTS_PATH_ENV_VAR)
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parents[2] / ".secrets" / "auditex-auth-contexts.json"


def _safe_context_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value.strip())
    cleaned = cleaned.strip("._") or "context"
    return cleaned[:64]


def _token_dir() -> Path:
    return default_auth_contexts_path().parent / ".tokens"


def _default_token_path(name: str, token_file: str | None = None) -> Path:
    directory = _token_dir()
    directory.mkdir(parents=True, exist_ok=True)
    if token_file:
        safe_token_file = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in token_file.strip())
        safe_token_file = safe_token_file.strip("._") or "token"
        return directory / safe_token_file[:64]
    return directory / f"{_safe_context_name(name)}.token"



def _load_local_auth_env() -> Path:
    path = default_local_auth_env_path()
    load_env_file(path)
    return path


def _masked_local_auth_values(path: Path) -> dict[str, Any]:
    values: dict[str, Any] = {"path": str(path), "present": path.exists()}
    if not path.exists():
        return values
    keys = (
        "AUDITEX_TENANT_ID",
        "AUDITEX_TENANT_NAME",
        "M365_CLI_APP_ID",
        "M365_CLI_CLIENT_ID",
        "AUDITEX_M365_CONNECTION_NAME",
        "AUDITEX_TENANT_ID",
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
    )
    values["values"] = {key: os.environ.get(key) for key in keys if os.environ.get(key)}
    return values


def local_auth_values() -> dict[str, str]:
    path = _load_local_auth_env()
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key:
            values[key] = value
    return values


def save_local_auth_values(values: dict[str, str | None]) -> Path:
    path = default_local_auth_env_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    output_lines: list[str] = []
    seen_keys: set[str] = set()

    for raw_line in existing_lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw_line:
            output_lines.append(raw_line)
            continue
        key, _sep, _value = raw_line.partition("=")
        clean_key = key.strip()
        if clean_key not in values:
            output_lines.append(raw_line)
            continue
        seen_keys.add(clean_key)
        new_value = values.get(clean_key)
        if new_value is None or new_value == "":
            continue
        output_lines.append(f"{clean_key}={new_value}")

    for key, value in values.items():
        if key in seen_keys or value is None or value == "":
            continue
        output_lines.append(f"{key}={value}")

    rendered = "\n".join(output_lines).rstrip()
    secure_write_text(path, f"{rendered}\n" if rendered else "")

    for key, value in values.items():
        if value is None or value == "":
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    return path


def _json_command(command: list[str]) -> dict[str, Any]:
    exe = shutil.which(command[0])
    if exe is None:
        return {
            "status": "blocked",
            "error_class": "command_not_found",
            "error": f"{command[0]} not installed",
            "command": command,
        }
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    payload: Any = None
    if stdout.strip():
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            payload = None
    return {
        "status": "supported" if completed.returncode == 0 else "blocked",
        "returncode": completed.returncode,
        "command": command,
        "payload": payload,
        "stdout": stdout,
        "stderr": stderr,
    }


def _pwsh_exchange_module_status() -> dict[str, Any]:
    pwsh_exe = shutil.which("pwsh")
    if pwsh_exe is None:
        return {
            "status": "blocked",
            "error_class": "command_not_found",
            "error": "pwsh not installed",
        }
    completed = subprocess.run(
        [
            pwsh_exe,
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "Get-Module -ListAvailable ExchangeOnlineManagement | "
            "Select-Object -First 1 Name,Version | ConvertTo-Json -Compress",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode == 0 and stdout and stdout != "null":
        payload: dict[str, Any] | None = None
        try:
            decoded = json.loads(stdout)
            if isinstance(decoded, dict):
                payload = decoded
        except json.JSONDecodeError:
            payload = None
        return {
            "status": "supported",
            "pwsh_path": pwsh_exe,
            "module_name": (payload or {}).get("Name") or "ExchangeOnlineManagement",
            "module_version": (payload or {}).get("Version"),
        }
    return {
        "status": "blocked",
        "pwsh_path": pwsh_exe,
        "error_class": "module_not_found",
        "error": stderr or stdout or f"return_code:{completed.returncode}",
    }


def ensure_exchange_online_module() -> int:
    status = _pwsh_exchange_module_status()
    if status.get("status") == "supported":
        return 0
    pwsh_exe = status.get("pwsh_path")
    if not pwsh_exe:
        return 2
    command = [
        str(pwsh_exe),
        "-NoLogo",
        "-NoProfile",
        "-Command",
        "Set-PSRepository PSGallery -InstallationPolicy Trusted; "
        "Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber",
    ]
    return subprocess.run(command, check=False).returncode


def _load_json(path: Path, *, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default


def _save_json(path: Path, payload: Any) -> None:
    secure_write_json(path, payload)


def _auth_context_store() -> dict[str, Any]:
    store = _load_json(default_auth_contexts_path(), default={"active_context": None, "contexts": {}})
    if not isinstance(store, dict):
        return {"active_context": None, "contexts": {}}
    if not isinstance(store.get("contexts"), dict):
        store["contexts"] = {}
    return store


def _save_auth_context_store(payload: dict[str, Any]) -> None:
    _save_json(default_auth_contexts_path(), payload)


def _product_auth_runtime() -> auth_runtime.ProductAuthRuntime:
    return auth_runtime.ProductAuthRuntime(
        auth_runtime.AuthRuntimeAdapters(
            load_local_auth_env=_load_local_auth_env,
            masked_local_auth_values=_masked_local_auth_values,
            json_command=_json_command,
            exchange_module_status=_pwsh_exchange_module_status,
            load_auth_context_store=_auth_context_store,
            save_auth_context_store=_save_auth_context_store,
            resolve_token_path=_default_token_path,
            write_token=lambda path, token: secure_write_text(path, f"{token}\n", mode=0o600),
            read_token=lambda path: Path(path).read_text(encoding="utf-8").strip(),
            environ_get=os.environ.get,
            run_returncode=lambda command: subprocess.run(command, check=False).returncode,
        )
    )


def inspect_token_claims(token: str) -> dict[str, Any]:
    return auth_runtime.inspect_token_claims(token)


def resolve_token_input(
    *,
    token: str | None = None,
    token_env: str | None = None,
    token_file: str | None = None,
    token_stdin: bool = False,
) -> tuple[str, str]:
    supplied = [bool(token), bool(token_env), bool(token_file), bool(token_stdin)]
    if sum(supplied) != 1:
        raise ValueError("provide exactly one of --token, --token-env, --token-file, or --token-stdin")
    if token:
        return token.strip(), "argv"
    if token_env:
        value = os.environ.get(token_env)
        if not value:
            raise ValueError(f"environment variable '{token_env}' is empty or missing")
        return value.strip(), f"env:{token_env}"
    if token_file:
        return Path(token_file).expanduser().read_text(encoding="utf-8").strip(), f"file:{token_file}"
    return sys.stdin.read().strip(), "stdin"


def _redacted_token_preview(token: str) -> str:
    return auth_runtime.redacted_token_preview(token)


def import_token_context(
    *,
    name: str,
    token: str,
    tenant_id: str | None = None,
    make_active: bool = True,
) -> dict[str, Any]:
    return _product_auth_runtime().import_token_context(
        name=name,
        token=token,
        tenant_id=tenant_id,
        make_active=make_active,
    )


def list_auth_contexts() -> dict[str, Any]:
    return _product_auth_runtime().list_auth_contexts()


def resolve_auth_context(name: str | None = None) -> dict[str, Any]:
    return _product_auth_runtime().resolve_auth_context(name)


def collector_capability_matrix(
    *,
    auth_context: dict[str, Any],
    collectors: list[str],
    auditor_profile: str = "auto",
    config_path: str = "configs/collector-definitions.json",
    permission_hints_path: str = "configs/collector-permissions.json",
) -> list[dict[str, Any]]:
    return auth_runtime.collector_capability_matrix(
        auth_context=auth_context,
        collectors=collectors,
        auditor_profile=auditor_profile,
        config_path=config_path,
        permission_hints_path=permission_hints_path,
    )


def capability_for_context(
    *,
    name: str | None = None,
    collectors: list[str],
    auditor_profile: str = "auto",
    config_path: str = "configs/collector-definitions.json",
    permission_hints_path: str = "configs/collector-permissions.json",
) -> dict[str, Any]:
    return _product_auth_runtime().capability_for_context(
        name=name,
        collectors=collectors,
        auditor_profile=auditor_profile,
        config_path=config_path,
        permission_hints_path=permission_hints_path,
    )


def get_auth_status(
    *,
    include_azure_cli: bool = True,
    include_m365: bool = True,
    include_exchange: bool = True,
) -> dict[str, Any]:
    return _product_auth_runtime().get_auth_status(
        include_azure_cli=include_azure_cli,
        include_m365=include_m365,
        include_exchange=include_exchange,
    )


def list_connections() -> dict[str, Any]:
    return _product_auth_runtime().list_connections()


def use_connection(name: str) -> dict[str, Any]:
    return _product_auth_runtime().use_connection(name)


def export_env() -> dict[str, Any]:
    path = _load_local_auth_env()
    return _masked_local_auth_values(path)


def login_connection(
    *,
    mode: str,
    tenant_id: str | None = None,
    connection_name: str | None = None,
    auth_type: str | None = None,
    app_id: str | None = None,
    client_secret: str | None = None,
) -> int:
    return _product_auth_runtime().login_connection(
        mode=mode,
        tenant_id=tenant_id,
        connection_name=connection_name,
        auth_type=auth_type,
        app_id=app_id,
        client_secret=client_secret,
    )
