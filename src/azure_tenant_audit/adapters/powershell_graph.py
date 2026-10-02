from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from typing import Any, Callable, Optional

from ..secret_hygiene import redact_command_string, redact_text
from .base import Adapter, AdapterMetadata


_ORGANIZATION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)*\.onmicrosoft\.(?:com|us|de|cn)")


class PowerShellGraphAdapter(Adapter):
    metadata = AdapterMetadata(
        name="powershell_graph",
        auth_requirements=("app_or_delegated",),
        tool_dependencies=("pwsh",),
    )

    def dependency_check(self) -> bool:
        return shutil.which("pwsh") is not None

    @staticmethod
    def _looks_like_not_found(text: str) -> bool:
        lowered = text.lower()
        return (
            "not recognized" in lowered
            or "command not found" in lowered
            or ("the term" in lowered and "is not recognized" in lowered)
        )

    @staticmethod
    def _looks_like_auth_required(text: str) -> bool:
        lowered = text.lower()
        return (
            "not authorized" in lowered
            or "access denied" in lowered
            or ("sign in" in lowered and "denied" in lowered)
            or "connect-exchangeonline" in lowered
            or "unauthorized" in lowered
        )

    @staticmethod
    def _normalize_payload(parsed: object) -> dict[str, Any]:
        if isinstance(parsed, dict):
            if "value" in parsed and isinstance(parsed["value"], list):
                return parsed
            return {"value": [parsed]}
        if isinstance(parsed, list):
            return {"value": parsed}
        if parsed is None:
            return {}
        return {"value": [parsed]}

    @staticmethod
    def _session_prelude(session: Optional[dict[str, Any]], env: dict[str, str]) -> str:
        """Connect step for a fresh pwsh process. Tokens travel in the environment, never on the command line."""
        if not session or session.get("kind") != "exchange_online":
            return ""
        token = session.get("access_token")
        organization = str(session.get("organization") or "")
        if not token or not _ORGANIZATION_PATTERN.fullmatch(organization):
            return ""
        env["AUDITEX_EXO_ACCESS_TOKEN"] = str(token)
        return (
            "Import-Module ExchangeOnlineManagement -ErrorAction Stop; "
            f"Connect-ExchangeOnline -AccessToken $env:AUDITEX_EXO_ACCESS_TOKEN -Organization '{organization}' "
            "-ShowBanner:$false -SkipLoadingFormatData -ErrorAction Stop | Out-Null; "
        )

    def run(
        self,
        command: str,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
        session: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        safe_command = redact_command_string(command)
        exe = shutil.which("pwsh")
        if exe is None:
            if log_event:
                log_event("command.failed", "PowerShell executable not found", {"command": safe_command})
            return {"error": "command_not_found:pwsh", "error_class": "command_not_found", "command": safe_command}

        script = command.strip()
        if script.startswith("pwsh"):
            parts = shlex.split(script)
            script = " ".join(parts[1:]) if len(parts) > 1 else ""

        if not script:
            return {"error": "command_empty", "error_class": "command_parse_error", "command": safe_command}

        env = dict(os.environ)
        prelude = self._session_prelude(session, env)
        prepared = f"{prelude}{script} | ConvertTo-Json -Depth 20 -Compress"
        try:
            if log_event:
                log_event("command.started", "PowerShell command started", {"command": safe_command, "executable": exe})

            start = time.time()
            result = subprocess.run(
                [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prepared],
                text=True,
                capture_output=True,
                timeout=180 if prelude else 120,
                env=env,
            )
            duration_ms = round((time.time() - start) * 1000, 2)
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            combined = f"{stdout}\n{stderr}".lower()

            if log_event:
                log_event(
                    "command.completed",
                    "PowerShell command completed",
                    {
                        "command": safe_command,
                        "return_code": result.returncode,
                        "duration_ms": duration_ms,
                        "stdout_bytes": len(stdout),
                        "stderr_bytes": len(stderr),
                        "stdout_sample": redact_text(stdout[:500]),
                    },
                )

            if result.returncode != 0 or self._looks_like_not_found(combined) or self._looks_like_auth_required(combined):
                if self._looks_like_not_found(combined) and session is not None and not prelude:
                    # Exchange/Teams cmdlets only exist inside a connected session.
                    error_class = "session_not_connected"
                elif self._looks_like_not_found(combined):
                    error_class = "command_not_found"
                elif self._looks_like_auth_required(combined):
                    error_class = "command_not_authenticated"
                else:
                    error_class = "command_error"
                return {
                    "error": f"command_failed:{result.returncode}",
                    "error_class": error_class,
                    "command": safe_command,
                    "return_code": result.returncode,
                    "stdout": redact_text(stdout),
                    "stderr": redact_text(stderr),
                }

            if not stdout.strip():
                return {
                    "error": "command_output_empty",
                    "error_class": "command_output_empty",
                    "command": safe_command,
                    "stdout": redact_text(stdout),
                    "stderr": redact_text(stderr),
                }

            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError:
                return {
                    "error": "command_output_parse_error",
                    "error_class": "command_parse_error",
                    "command": safe_command,
                    "stdout": redact_text(stdout),
                    "stderr": redact_text(stderr),
                }

            response = self._normalize_payload(parsed)
            response["command"] = safe_command
            return response
        except subprocess.TimeoutExpired:
            if log_event:
                log_event("command.failed", "PowerShell command timed out", {"command": safe_command})
            return {"error": "command_timeout", "error_class": "command_timeout", "command": safe_command}
        except subprocess.CalledProcessError as exc:  # noqa: BLE001
            if log_event:
                log_event("command.failed", "PowerShell command failed", {"command": safe_command, "error": str(exc)})
            return {"error": f"command_failed:{exc.returncode}", "error_class": "command_error", "command": safe_command}
        except Exception as exc:  # noqa: BLE001
            if log_event:
                log_event("command.failed", "PowerShell command exception", {"command": safe_command, "error": str(exc)})
            return {"error": redact_text(str(exc)), "error_class": "command_exception", "command": safe_command}
