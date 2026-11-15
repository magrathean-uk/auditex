from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from ..secret_hygiene import (
    redact_command_string,
    redact_output,
)
from .base import Adapter, AdapterMetadata
from .read_guard import CommandRefused, check_command, refusal_response

# Error of every command handed to the adapter: the CLI for Microsoft 365 is no longer used for live collection.
M365_CLI_NOT_USED = "m365_cli_not_used"


class M365CLIAdapter(Adapter):
    """The CLI for Microsoft 365 (``m365``) adapter, kept by name so old bundles and collectors still resolve it.

    It never starts ``m365`` (DEC-108 D2): Exchange is read by exchange_policy with the reader app's certificate.
    """

    metadata = AdapterMetadata(
        name="m365_cli",
        auth_requirements=(),
        tool_dependencies=(),
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

    def _classify_output(
        self,
        return_code: int,
        stdout: str,
        stderr: str,
        safe_command: str,
        sensitive_values: Any,
    ) -> dict[str, Any]:
        """The adapter's response for one finished command: parsed rows, or an error class that says why not."""
        combined = f"{stdout}\n{stderr}".lower()
        if return_code != 0 or self._looks_like_not_found(combined) or self._looks_like_auth_required(combined):
            if self._looks_like_not_found(combined):
                error_class = "command_not_found"
            elif self._looks_like_auth_required(combined):
                error_class = "command_not_authenticated"
            else:
                error_class = "command_error"
            return {
                "error": f"command_failed:{return_code}",
                "error_class": error_class,
                "command": safe_command,
                "return_code": return_code,
                "stdout": redact_output(stdout, sensitive_values),
                "stderr": redact_output(stderr, sensitive_values),
            }

        if not stdout.strip():
            return {
                "command": safe_command,
                "error": "command_output_empty",
                "error_class": "command_output_empty",
                "stdout": redact_output(stdout, sensitive_values),
                "stderr": redact_output(stderr, sensitive_values),
            }

        if self._looks_like_help_output(stdout):
            return {
                "command": safe_command,
                "error": "command_output_invalid_help",
                "error_class": "command_parse_error",
                "stdout": redact_output(stdout, sensitive_values),
                "stderr": redact_output(stderr, sensitive_values),
            }

        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            return {
                "command": safe_command,
                "error": "command_output_parse_error",
                "error_class": "command_parse_error",
                "stdout": redact_output(stdout, sensitive_values),
                "stderr": redact_output(stderr, sensitive_values),
            }

        response = self._normalize_payload(parsed)
        response["command"] = safe_command
        return response

    def dependency_check(self) -> bool:
        # The CLI for Microsoft 365 is no longer a dependency of any audit (DEC-108 D2).
        return False

    def run(
        self,
        command: str,
        log_event: Callable[[str, str, dict[str, Any] | None], None] | None = None,
    ) -> dict[str, Any]:
        """Never starts ``m365``: Microsoft 365 audits read only with the reader app's certificate (DEC-107).

        A command off the read allowlist is still refused and logged first, as by every adapter. Any other answer is
        a ``command_not_found`` error, the same class a machine without ``m365`` gave, so a collector that falls back
        to Microsoft Graph still does. The output classifier above stays for replaying old bundles.
        """
        safe_command = redact_command_string(command)
        try:
            check_command(self.name, command)
        except CommandRefused as exc:
            if log_event:
                log_event(
                    "command.refused",
                    "Command refused before execution: not on the read allowlist",
                    {"adapter": self.name, "command": safe_command, "reason": exc.reason},
                )
            return refusal_response(safe_command, exc)
        return {
            "error": M365_CLI_NOT_USED,
            "error_class": "command_not_found",
            "command": safe_command,
            "source": "command",
        }
