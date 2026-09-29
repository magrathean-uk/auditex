from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import time
from typing import Any, Callable, Optional

from ..m365_home import m365_subprocess_kwargs
from ..secret_hygiene import collect_sensitive_argv_values, redact_command_string, redact_text
from .base import Adapter, AdapterMetadata


class M365CLIAdapter(Adapter):
    metadata = AdapterMetadata(
        name="m365_cli",
        auth_requirements=("delegated_or_app",),
        tool_dependencies=("m365",),
    )

    @staticmethod
    def _looks_like_not_found(text: str) -> bool:
        lowered = text.lower()
        return (
            "command '" in lowered and " was not found." in lowered
            or "was not found" in lowered
            or "unknown command" in lowered
            or "command not found" in lowered
        )

    @staticmethod
    def _looks_like_auth_required(text: str) -> bool:
        lowered = text.lower()
        return (
            "log in to microsoft 365 first" in lowered
            or "logged out" in lowered
            or "please sign in" in lowered
        )

    @staticmethod
    def _looks_like_help_output(text: str) -> bool:
        lowered = text.lower()
        return lowered.startswith("cli for microsoft 365 v") or "commands:" in lowered

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

    def dependency_check(self) -> bool:
        return shutil.which("m365") is not None

    def run(
        self,
        command: str,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
    ) -> dict[str, Any]:
        safe_command = redact_command_string(command)
        cmd_parts = shlex.split(command)
        sensitive_values = collect_sensitive_argv_values(cmd_parts)
        exe = shutil.which(cmd_parts[0]) if cmd_parts else None
        if exe is None:
            if log_event:
                log_event(
                    "command.failed",
                    "Command executable not found",
                    {"command": cmd_parts[0] if cmd_parts else safe_command},
                )
            return {
                "error": f"command_not_found:{cmd_parts[0] if cmd_parts else command}",
                "error_class": "command_not_found",
                "command": safe_command,
            }

        try:
            if log_event:
                log_event("command.started", "Exchange command started", {"command": safe_command, "executable": exe})
            start = time.time()
            result = subprocess.run(
                cmd_parts,
                text=True,
                capture_output=True,
                shell=False,
                timeout=120,
                **m365_subprocess_kwargs(cmd_parts),
            )
            duration_ms = round((time.time() - start) * 1000, 2)
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            status = "ok" if result.returncode == 0 else "error"
            if log_event:
                log_event(
                    "command.completed",
                    "Exchange command completed",
                    {
                        "command": safe_command,
                        "return_code": result.returncode,
                        "duration_ms": duration_ms,
                        "status": status,
                        "stdout_bytes": len(stdout),
                        "stderr_bytes": len(stderr),
                        "stdout_sample": redact_text(stdout[:500], sensitive_values),
                    },
                )

            combined = f"{stdout}\n{stderr}".lower()
            if result.returncode != 0 or self._looks_like_not_found(combined) or self._looks_like_auth_required(combined):
                if self._looks_like_not_found(combined):
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
                    "stdout": redact_text(stdout, sensitive_values),
                    "stderr": redact_text(stderr, sensitive_values),
                }

            if not stdout.strip():
                return {
                    "command": safe_command,
                    "error": "command_output_empty",
                    "error_class": "command_output_empty",
                    "stdout": redact_text(stdout, sensitive_values),
                    "stderr": redact_text(stderr, sensitive_values),
                }

            if self._looks_like_help_output(stdout):
                return {
                    "command": safe_command,
                    "error": "command_output_invalid_help",
                    "error_class": "command_parse_error",
                    "stdout": redact_text(stdout, sensitive_values),
                    "stderr": redact_text(stderr, sensitive_values),
                }

            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError:
                return {
                    "command": safe_command,
                    "error": "command_output_parse_error",
                    "error_class": "command_parse_error",
                    "stdout": redact_text(stdout, sensitive_values),
                    "stderr": redact_text(stderr, sensitive_values),
                }

            response = self._normalize_payload(parsed)
            response["command"] = safe_command
            return response

        except subprocess.CalledProcessError as exc:  # noqa: BLE001
            if log_event:
                log_event(
                    "command.failed",
                    "Exchange command failed",
                    {"command": safe_command, "return_code": exc.returncode, "error": str(exc)},
                )
            return {
                "error": f"command_failed:{exc.returncode}",
                "error_class": "command_error",
                "command": safe_command,
                "output": redact_text(str(exc.output), sensitive_values),
            }
        except Exception as exc:  # noqa: BLE001
            if log_event:
                log_event(
                    "command.failed",
                    "Exchange command exception",
                    {"command": safe_command, "error": str(exc)},
                )
            return {"error": redact_text(str(exc), sensitive_values), "error_class": "command_exception", "command": safe_command}
