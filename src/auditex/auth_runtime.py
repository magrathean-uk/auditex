from __future__ import annotations

import base64
import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from azure_tenant_audit.config import CollectorConfig
from azure_tenant_audit.profiles import get_profile
from azure_tenant_audit.resources import resolve_resource_path
from azure_tenant_audit.secret_hygiene import (
    sanitize_token_claims,
    secure_write_json,
    token_freshness as safe_token_freshness,
    validate_token_claims,
)
from azure_tenant_audit.utils import parse_csv_list


JsonCommand = Callable[[list[str]], dict[str, Any]]
ReturncodeCommand = Callable[[list[str]], int]


def _empty_store() -> dict[str, Any]:
    return {"active_context": None, "contexts": {}}


def _default_json_command(command: list[str]) -> dict[str, Any]:
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


def _default_run_json_command(command: list[str]) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        return {
            "status": "blocked",
            "command": command,
            "error": "command_not_found",
        }

    return {
        "status": "supported" if completed.returncode == 0 else "blocked",
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _default_exchange_module_status() -> dict[str, Any]:
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


def _default_list_adapter_capabilities() -> list[dict[str, Any]]:
    try:
        from azure_tenant_audit.adapters import list_adapters as _list_adapter_capabilities

        return _list_adapter_capabilities()
    except Exception:  # noqa: BLE001
        return []


def _default_run_returncode(command: list[str]) -> int:
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


@dataclass(frozen=True)
class AuthRuntimeAdapters:
    load_local_auth_env: Callable[[], Path] = lambda: Path(".secrets/m365-auth.env")
    masked_local_auth_values: Callable[[Path], dict[str, Any]] = lambda path: {"path": str(path), "present": path.exists()}
    json_command: JsonCommand = _default_json_command
    exchange_module_status: Callable[[], dict[str, Any]] = _default_exchange_module_status
    list_adapter_capabilities: Callable[[], list[dict[str, Any]]] = _default_list_adapter_capabilities
    load_auth_context_store: Callable[[], dict[str, Any]] = _empty_store
    save_auth_context_store: Callable[[dict[str, Any]], None] = lambda _payload: None
    environ_get: Callable[[str], str | None] = os.environ.get
    resolve_token_path: Callable[[str, str | None], Path | None] = lambda _name, _token_file=None: None
    write_token: Callable[[Path, str], None] = lambda _path, _token: None
    read_token: Callable[[Path], str] = lambda _path: ""
    run_returncode: ReturncodeCommand = _default_run_returncode


class ProductAuthRuntime:
    def __init__(self, adapters: AuthRuntimeAdapters | None = None) -> None:
        self.adapters = adapters or AuthRuntimeAdapters()

    def get_auth_status(
        self,
        *,
        include_azure_cli: bool = True,
        include_m365: bool = True,
        include_exchange: bool = True,
    ) -> dict[str, Any]:
        path = self.adapters.load_local_auth_env()
        azure = self.adapters.json_command(["az", "account", "show", "--output", "json"]) if include_azure_cli else {"status": "skipped"}
        m365 = self.adapters.json_command(["m365", "status", "--output", "json"]) if include_m365 else {"status": "skipped"}
        connections = self.adapters.json_command(["m365", "connection", "list", "--output", "json"]) if include_m365 else {"status": "skipped"}
        exchange = self.adapters.exchange_module_status() if include_exchange else {"status": "skipped"}

        result: dict[str, Any] = {
            "local_auth": self.adapters.masked_local_auth_values(path),
            "azure_cli": {
                "status": azure["status"],
            },
            "m365": {
                "status": m365["status"],
            },
            "exchange": exchange,
            "auth_contexts": self.list_auth_contexts(),
            "adapter_capabilities": self.adapters.list_adapter_capabilities(),
        }
        if azure.get("payload"):
            payload = azure["payload"]
            result["azure_cli"]["tenant_id"] = payload.get("tenantId") or payload.get("tenant_id")
            user = payload.get("user") or {}
            if isinstance(user, dict):
                result["azure_cli"]["user_name"] = user.get("name")
                result["azure_cli"]["user_type"] = user.get("type")
        else:
            result["azure_cli"]["error"] = (azure.get("stderr") or azure.get("stdout") or "").strip()

        if m365.get("payload"):
            payload = m365["payload"]
            if isinstance(payload, dict):
                result["m365"].update(
                    {
                        "active_connection": payload.get("connectionName"),
                        "connected_as": payload.get("connectedAs"),
                        "auth_type": payload.get("authType"),
                        "app_id": payload.get("appId"),
                        "tenant_id": payload.get("appTenant"),
                        "cloud_type": payload.get("cloudType"),
                        "authenticated": bool(payload.get("connectionName") or payload.get("connectedAs")),
                    }
                )
        else:
            result["m365"]["error"] = (m365.get("stderr") or m365.get("stdout") or "").strip()
            result["m365"]["authenticated"] = False

        if connections.get("payload") is not None:
            result["m365"]["saved_connections"] = connections.get("payload")
        elif connections.get("status") == "blocked":
            result["m365"]["saved_connections_error"] = (connections.get("stderr") or connections.get("stdout") or "").strip()

        return result

    def list_connections(self) -> dict[str, Any]:
        self.adapters.load_local_auth_env()
        response = self.adapters.json_command(["m365", "connection", "list", "--output", "json"])
        if response["status"] == "blocked":
            raise RuntimeError((response.get("stderr") or response.get("stdout") or "unable to list connections").strip())
        return {"connections": response.get("payload") or []}

    def use_connection(self, name: str) -> dict[str, Any]:
        self.adapters.load_local_auth_env()
        response = self.adapters.json_command(["m365", "connection", "use", "--name", name, "--output", "json"])
        if response["status"] == "blocked":
            raise RuntimeError((response.get("stderr") or response.get("stdout") or "unable to switch connection").strip())
        payload = response.get("payload")
        return payload if isinstance(payload, dict) else {"connectionName": name}

    def login_connection(
        self,
        *,
        mode: str,
        tenant_id: str | None = None,
        connection_name: str | None = None,
        auth_type: str | None = None,
        app_id: str | None = None,
        client_secret: str | None = None,
    ) -> int:
        self.adapters.load_local_auth_env()
        if mode not in {"delegated", "app"}:
            raise ValueError(f"unsupported auth mode: {mode}")

        if mode == "delegated":
            command = [
                "m365",
                "login",
                "--authType",
                auth_type or "deviceCode",
            ]
            effective_app_id = app_id or self.adapters.environ_get("M365_CLI_APP_ID") or self.adapters.environ_get("M365_CLI_CLIENT_ID")
            if effective_app_id:
                command.extend(["--appId", effective_app_id])
            if tenant_id:
                command.extend(["--tenant", tenant_id])
            if connection_name:
                command.extend(["--connectionName", connection_name])
            return self.adapters.run_returncode(command)

        effective_app_id = app_id or self.adapters.environ_get("M365_CLI_APP_ID") or self.adapters.environ_get("M365_CLI_CLIENT_ID")
        if not effective_app_id or not client_secret:
            raise ValueError("app auth requires app_id and client_secret")
        command = [
            "m365",
            "login",
            "--authType",
            "secret",
            "--appId",
            effective_app_id,
            "--secret",
            client_secret,
        ]
        if tenant_id:
            command.extend(["--tenant", tenant_id])
        if connection_name:
            command.extend(["--connectionName", connection_name])
        return self.adapters.run_returncode(command)

    def import_token_context(
        self,
        *,
        name: str,
        token: str,
        tenant_id: str | None = None,
        make_active: bool = True,
    ) -> dict[str, Any]:
        inspected = sanitize_token_claims(inspect_token_claims(token))
        effective_tenant_id = tenant_id or inspected.get("tenant_id")
        validation = validate_token_claims(inspected, tenant_id=effective_tenant_id)
        if validation.get("blockers"):
            raise ValueError(f"refusing to save unusable token context: {', '.join(validation['blockers'])}")

        token_file = _safe_token_file_name(name)
        token_path = self.adapters.resolve_token_path(name, token_file)
        if token_path is not None:
            self.adapters.write_token(token_path, token)
            token_value: str | None = None
        else:
            token_value = token

        store = self._auth_context_store()
        store["contexts"][name] = {
            "name": name,
            "auth_type": "imported_token",
            "tenant_id": effective_tenant_id,
            "token": token_value,
            "token_file": token_file,
            "token_preview": redacted_token_preview(token),
            "token_claims": inspected,
            "validation": validation,
        }
        if make_active:
            store["active_context"] = name
        self.adapters.save_auth_context_store(store)
        return {
            "name": name,
            "auth_type": "imported_token",
            "tenant_id": effective_tenant_id,
            "token_path": token_path and str(token_path),
            "token_preview": redacted_token_preview(token),
            "token_claims": {
                "audience": inspected.get("audience"),
                "delegated_scopes": inspected.get("delegated_scopes", []),
                "app_roles": inspected.get("app_roles", []),
                "expires_at_utc": inspected.get("expires_at_utc"),
            },
        }

    def list_auth_contexts(self) -> dict[str, Any]:
        store = self._auth_context_store()
        contexts: list[dict[str, Any]] = []
        active = store.get("active_context")
        for name, item in sorted(store.get("contexts", {}).items()):
            if not isinstance(item, dict):
                continue
            contexts.append(
                {
                    "name": name,
                    "active": name == active,
                    "auth_type": item.get("auth_type"),
                    "tenant_id": item.get("tenant_id"),
                    "token_preview": item.get("token_preview"),
                    "user_principal_name": ((item.get("token_claims") or {}).get("user_principal_name")),
                    "audience": ((item.get("token_claims") or {}).get("audience")),
                    "expires_at_utc": ((item.get("token_claims") or {}).get("expires_at_utc")),
                    "freshness": token_freshness(item.get("token_claims") or {}),
                }
            )
        return {"active_context": active, "contexts": contexts}

    def resolve_auth_context(self, name: str | None = None) -> dict[str, Any]:
        store = self._auth_context_store()
        selected_name = name or store.get("active_context")
        if not selected_name:
            raise RuntimeError("no saved auth context")
        context = store.get("contexts", {}).get(selected_name)
        if not isinstance(context, dict):
            raise RuntimeError(f"auth context '{selected_name}' not found")

        token = context.get("token")
        if not token:
            token_file = context.get("token_file")
            if isinstance(token_file, str) and token_file:
                token_path = self.adapters.resolve_token_path(selected_name, token_file)
                if token_path is not None:
                    token = self.adapters.read_token(token_path)
                    if token:
                        context = dict(context)
                        context["token"] = token

        validation = validate_token_claims(context.get("token_claims") or {}, tenant_id=context.get("tenant_id"))
        if validation.get("blockers"):
            raise RuntimeError(
                f"auth context '{selected_name}' is not usable: {', '.join(validation['blockers'])}"
            )
        return context

    def capability_for_context(
        self,
        *,
        name: str | None = None,
        collectors: list[str],
        auditor_profile: str = "auto",
        config_path: str = "configs/collector-definitions.json",
        permission_hints_path: str = "configs/collector-permissions.json",
    ) -> dict[str, Any]:
        context = self.resolve_auth_context(name)
        return {
            "auth_context": summarize_auth_context(context),
            "capabilities": collector_capability_matrix(
                auth_context=context,
                collectors=collectors,
                auditor_profile=auditor_profile,
                config_path=config_path,
                permission_hints_path=permission_hints_path,
            ),
        }

    def _auth_context_store(self) -> dict[str, Any]:
        store = self.adapters.load_auth_context_store()
        if not isinstance(store, dict):
            return _empty_store()
        if not isinstance(store.get("contexts"), dict):
            store["contexts"] = {}
        return store


def _safe_token_file_name(name: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(name).strip())
    safe = safe.strip("._") or "context"
    return f"{safe}.token"


def b64url_json(segment: str) -> dict[str, Any]:
    if not segment:
        return {}
    padding = "=" * ((4 - len(segment) % 4) % 4)
    raw = base64.urlsafe_b64decode(segment + padding)
    decoded = json.loads(raw.decode("utf-8"))
    return decoded if isinstance(decoded, dict) else {}


def iso_from_epoch(value: Any) -> str | None:
    try:
        epoch = int(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def token_freshness(token_claims: dict[str, Any]) -> dict[str, Any]:
    return safe_token_freshness(token_claims)


def inspect_token_claims(token: str, *, include_raw_claims: bool = False) -> dict[str, Any]:
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token.split(" ", 1)[1].strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token is not a JWT")
    if not all(parts):
        raise ValueError("token is not a complete JWT")
    payload = b64url_json(parts[1])
    delegated_scopes = sorted(parse_csv_list(str(payload.get("scp", "")).replace(" ", ",")) or [])
    app_roles = sorted(str(item) for item in payload.get("roles", []) if isinstance(item, str))
    result = {
        "tenant_id": payload.get("tid"),
        "audience": payload.get("aud"),
        "app_id": payload.get("appid") or payload.get("azp"),
        "subject": payload.get("sub"),
        "user_principal_name": payload.get("upn") or payload.get("preferred_username"),
        "delegated_scopes": delegated_scopes,
        "app_roles": app_roles,
        "issued_at_utc": iso_from_epoch(payload.get("iat")),
        "not_before_utc": iso_from_epoch(payload.get("nbf")),
        "expires_at_utc": iso_from_epoch(payload.get("exp")),
    }
    if include_raw_claims:
        result["raw_claims"] = payload
    return sanitize_token_claims(result)


def redacted_token_preview(token: str) -> str:
    token = token.strip()
    if len(token) <= 12:
        return "***redacted***"
    return f"{token[:8]}...{token[-4:]}"


def summarize_auth_context(context: dict[str, Any]) -> dict[str, Any]:
    token_claims = context.get("token_claims") or {}
    return {
        "name": context.get("name"),
        "auth_type": context.get("auth_type"),
        "tenant_id": context.get("tenant_id"),
        "token_claims": {
            "tenant_id": token_claims.get("tenant_id"),
            "audience": token_claims.get("audience"),
            "delegated_scopes": token_claims.get("delegated_scopes") or [],
            "app_roles": token_claims.get("app_roles") or [],
            "issued_at_utc": token_claims.get("issued_at_utc"),
            "expires_at_utc": token_claims.get("expires_at_utc"),
            "user_principal_name": token_claims.get("user_principal_name"),
        },
        "freshness": token_freshness(token_claims),
    }


def load_permission_hints(path: Path) -> dict[str, dict[str, Any]]:
    path = resolve_resource_path(path)
    payload = _load_json(path, default={})
    hints = payload.get("collector_permissions") if isinstance(payload, dict) else {}
    if not isinstance(hints, dict):
        return {}
    return {str(key): dict(value) if isinstance(value, dict) else {} for key, value in hints.items()}


def available_permissions(token_claims: dict[str, Any]) -> set[str]:
    scopes = token_claims.get("delegated_scopes") or []
    roles = token_claims.get("app_roles") or []
    return {str(item) for item in scopes if item} | {str(item) for item in roles if item}


def has_global_reader_like_role(context: dict[str, Any]) -> bool:
    roles = context.get("delegated_roles") or []
    return any(str(item).lower() == "global reader" for item in roles)


def collector_capability_matrix(
    *,
    auth_context: dict[str, Any],
    collectors: list[str],
    auditor_profile: str = "auto",
    config_path: str = "configs/collector-definitions.json",
    permission_hints_path: str = "configs/collector-permissions.json",
) -> list[dict[str, Any]]:
    config = CollectorConfig.from_path(Path(config_path))
    permission_hints = load_permission_hints(Path(permission_hints_path))
    profile = get_profile(auditor_profile)
    token_claims = auth_context.get("token_claims") or {}
    available = available_permissions(token_claims)
    has_global_reader = has_global_reader_like_role(auth_context)
    rows: list[dict[str, Any]] = []
    for collector_name in collectors:
        definition = config.collectors.get(collector_name)
        hints = permission_hints.get(collector_name, {})
        required = list(definition.required_permissions) if definition else list(hints.get("graph_scopes") or [])
        missing = [item for item in required if item not in available]
        status = "supported_exact_scope"
        reason = "required_permissions_present"
        if missing:
            status = "blocked_by_scope"
            reason = "missing_required_permissions"
        if collector_name in {"purview", "ediscovery"} and has_global_reader:
            status = "blocked_by_role"
            reason = "global_reader_limit"
        elif collector_name == "reports_usage" and has_global_reader and "Reports.Read.All" not in available:
            status = "partial"
            reason = "global_reader_tenant_level_reports_only"
        rows.append(
            {
                "collector": collector_name,
                "status": status,
                "reason": reason,
                "required_permissions": required,
                "missing_permissions": missing,
                "observed_permissions": sorted(available),
                "minimum_role_hints": list(hints.get("minimum_role_hints") or profile.delegated_role_hints),
                "notes": hints.get("notes") or profile.notes,
            }
        )
    return rows


@dataclass(frozen=True)
class ToolchainRuntimeAdapters:
    which: Callable[[str], str | None] = shutil.which
    run_json_command: JsonCommand = _default_run_json_command
    detect_package_manager: Callable[[], str | None] = lambda: "brew" if shutil.which("brew") else "apt" if shutil.which("apt-get") else "dnf" if shutil.which("dnf") else None


@dataclass(frozen=True)
class ToolchainRuntime:
    adapters: ToolchainRuntimeAdapters = field(default_factory=ToolchainRuntimeAdapters)
    repo_root: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2])
    bootstrap_script: Path | None = None
    select_python_script: Path | None = None
    venv_dir: Path | None = None

    def __post_init__(self) -> None:
        if self.bootstrap_script is None:
            object.__setattr__(self, "bootstrap_script", self.repo_root / "scripts" / "bootstrap-local-tools.sh")
        if self.select_python_script is None:
            object.__setattr__(self, "select_python_script", self.repo_root / "scripts" / "select-python.sh")
        if self.venv_dir is None:
            object.__setattr__(self, "venv_dir", self.repo_root / ".venv")

    def command_version(
        self,
        command: list[str],
        *,
        parser: Callable[[str], str | None] | None = None,
    ) -> tuple[str | None, str | None]:
        result = self.adapters.run_json_command(command)
        if result["status"] != "supported":
            error = (result.get("stderr") or result.get("stdout") or result.get("error") or "").strip() or "version_check_failed"
            return None, error
        output = (result.get("stdout") or result.get("stderr") or "").strip()
        if not output:
            return None, "empty_version_output"
        if parser is not None:
            try:
                parsed = parser(output)
            except Exception as exc:  # noqa: BLE001
                return None, str(exc)
            if not parsed:
                return None, "empty_version_output"
            return parsed, None
        return output, None

    def tool_status(
        self,
        command_name: str,
        *,
        version_args: list[str] | None = None,
        version_parser: Callable[[str], str | None] | None = None,
    ) -> dict[str, Any]:
        path = self.adapters.which(command_name)
        if not path:
            return {
                "name": command_name,
                "status": "blocked",
                "path": None,
                "version": None,
                "error": "command_not_found",
            }
        version = None
        error = None
        if version_args is not None:
            version, error = self.command_version([path, *version_args], parser=version_parser)
        status = "supported" if version or version_args is None else "blocked"
        return {
            "name": command_name,
            "status": status,
            "path": path,
            "version": version,
            "error": error,
        }

    def selected_python(self) -> dict[str, Any]:
        assert self.select_python_script is not None
        if not self.select_python_script.exists():
            return {
                "status": "blocked",
                "error": "missing_select_python_script",
                "path": str(self.select_python_script),
            }

        result = self.adapters.run_json_command(["bash", str(self.select_python_script)])
        stdout = (result.get("stdout") or "").strip()
        if result["status"] == "supported" and stdout:
            version, version_error = self.command_version([stdout, "--version"])
            return {
                "status": "supported" if version else "blocked",
                "path": stdout,
                "version": version,
                "selector": str(self.select_python_script),
                "error": version_error,
            }
        return {
            "status": "blocked",
            "path": None,
            "selector": str(self.select_python_script),
            "error": (result.get("stderr") or result.get("stdout") or result.get("error") or "").strip() or "no_supported_python",
        }

    def venv_status(self) -> dict[str, Any]:
        assert self.venv_dir is not None
        python_path = self.venv_dir / "bin" / "python"
        return {
            "status": "supported" if python_path.exists() else "blocked",
            "path": str(self.venv_dir),
            "python_path": str(python_path),
        }

    def build_doctor_report(
        self,
        auth_runtime: ProductAuthRuntime,
        *,
        auth_mode: str = "delegated",
        include_exchange: bool = True,
        include_auth_checks: bool = True,
    ) -> dict[str, Any]:
        auth_status = auth_runtime.get_auth_status(
            include_azure_cli=include_auth_checks and auth_mode == "delegated",
            include_m365=include_auth_checks and include_exchange,
            include_exchange=include_auth_checks and include_exchange,
        )
        python_status = self.selected_python()
        venv_status = self.venv_status()
        tools = {
            "az": self.tool_status(
                "az",
                version_args=["version", "--output", "json"],
                version_parser=lambda output: json.loads(output).get("azure-cli"),
            ),
            "node": self.tool_status("node", version_args=["--version"]),
            "npm": self.tool_status("npm", version_args=["--version"]),
            "m365": self.tool_status(
                "m365",
                version_args=["version"],
                version_parser=lambda output: output.splitlines()[0].strip() if output.strip() else None,
            ),
            "pwsh": self.tool_status("pwsh", version_args=["--version"]),
        }
        exchange = auth_status.get("exchange") or {}
        core_missing = [
            name
            for name, status in (
                ("python", python_status),
                ("venv", venv_status),
                *((("az", tools["az"]),) if auth_mode == "delegated" else ()),
            )
            if status["status"] != "supported"
        ]
        exchange_missing = []
        if include_exchange:
            exchange_missing = [
                name
                for name, status in (
                    ("node", tools["node"]),
                    ("npm", tools["npm"]),
                    ("m365", tools["m365"]),
                    ("pwsh", tools["pwsh"]),
                )
                if status["status"] != "supported"
            ]
            if exchange.get("status") != "supported":
                exchange_missing.append("exchange_online_module")
        pwsh_missing = [name for name, status in (("pwsh", tools["pwsh"]),) if status["status"] != "supported"]
        assert self.bootstrap_script is not None
        return {
            "system": {
                "os": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "package_manager": self.adapters.detect_package_manager(),
            },
            "bootstrap": {
                "script": str(self.bootstrap_script),
                "exists": self.bootstrap_script.exists(),
            },
            "python": python_status,
            "venv": venv_status,
            "tools": tools,
            "auth": auth_status,
            "readiness": {
                "core_ready": not core_missing,
                "core_missing": core_missing,
                "exchange_ready": not exchange_missing,
                "exchange_missing": exchange_missing,
                "pwsh_ready": not pwsh_missing,
                "pwsh_missing": pwsh_missing,
            },
        }
