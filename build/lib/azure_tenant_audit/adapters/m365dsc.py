from __future__ import annotations

import re
import shutil
from typing import Any, Callable, Optional

from ..secret_hygiene import redact_command_string
from .base import Adapter, AdapterMetadata
from .powershell_graph import PowerShellGraphAdapter
from .read_guard import CommandRefused, VettedCommand, check_command, refusal_response


# October's resource schema refresh replaces a PIM API that stops returning
# data on 2026-10-28. This is a minimum compatibility gate, not an installer or
# a claim that every resource in a newer module has been validated.
MINIMUM_MODULE_VERSION = "2.26.1007.1"
_MINIMUM_VERSION_PARTS = tuple(int(part) for part in MINIMUM_MODULE_VERSION.split("."))

# Read-only module metadata probe; it goes through the same read allowlist as any other command.
COMPATIBILITY_SCRIPT = (
    "& { $module = Get-Module -ListAvailable Microsoft365DSC | "
    "Sort-Object Version -Descending | Select-Object -First 1; "
    "[pscustomobject]@{ module_version = $(if ($module) { $module.Version.ToString() } else { $null }); "
    "powershell_version = $PSVersionTable.PSVersion.ToString() } }"
)


class M365DSCAdapter(Adapter):
    metadata = AdapterMetadata(
        name="m365dsc",
        auth_requirements=("app_or_delegated",),
        tool_dependencies=("pwsh",),
    )

    def dependency_check(self) -> bool:
        return shutil.which("pwsh") is not None

    @staticmethod
    def _looks_like_module_missing(text: str) -> bool:
        lowered = text.lower()
        return (
            "microsoft365dsc module not installed" in lowered
            or "cannot find path" in lowered
            or "import-module" in lowered and "microsoft365dsc" in lowered and "not" in lowered
        )

    def compatibility_check(
        self,
        *,
        powershell: PowerShellGraphAdapter | None = None,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
    ) -> dict[str, Any]:
        """Read local module metadata without importing or connecting to a tenant."""
        powershell = powershell or PowerShellGraphAdapter()
        response = powershell.run(COMPATIBILITY_SCRIPT, log_event=log_event)
        result: dict[str, Any] = {
            "source": "m365dsc",
            "minimum_module_version": MINIMUM_MODULE_VERSION,
            "resource_schema_baseline": "2026-10-07",
            "export_semantics_verified": False,
        }
        if response.get("error"):
            return {**response, **result, "compatibility": "unverified"}
        rows = response.get("value")
        metadata = rows[0] if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) else {}
        version = metadata.get("module_version")
        result.update(module_version=version, powershell_version=metadata.get("powershell_version"))
        if "module_version" in metadata and version is None:
            return {**result, "compatibility": "unavailable", "error": "module_not_found", "error_class": "module_not_found"}
        if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:\.\d+)?", version):
            return {
                **result,
                "compatibility": "unverified",
                "error": "Microsoft365DSC module version could not be verified.",
                "error_class": "module_compatibility_unverified",
            }
        parts = tuple(int(part) for part in version.split("."))
        parts += (0,) * (4 - len(parts))
        if parts < _MINIMUM_VERSION_PARTS:
            return {
                **result,
                "compatibility": "incompatible",
                "error": (
                    f"Microsoft365DSC {version} predates the {MINIMUM_MODULE_VERSION} resource schema baseline; "
                    "review the selected export resources and October PIM API changes before using this adapter."
                ),
                "error_class": "module_incompatible",
            }
        return {**result, "compatibility": "minimum_version_met"}

    def run(
        self,
        command: str,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
    ) -> dict[str, Any]:
        safe_command = redact_command_string(command)
        try:
            command_words = check_command(self.name, command)
        except CommandRefused as exc:
            if log_event:
                log_event(
                    "command.refused",
                    "Command refused before execution: not on the read allowlist",
                    {"adapter": self.name, "command": safe_command, "reason": exc.reason},
                )
            return refusal_response(safe_command, exc)
        powershell = PowerShellGraphAdapter()
        compatibility = self.compatibility_check(powershell=powershell, log_event=log_event)
        if compatibility.get("error"):
            return {**compatibility, "command": safe_command}
        script = command.replace("'", "''")
        module_guard = (
            f"Import-Module Microsoft365DSC -RequiredVersion '{compatibility['module_version']}' -ErrorAction Stop"
        )
        # The caller's command was checked above; the wrapper is ours and is marked as vetted.
        wrapped = VettedCommand(
            f"{module_guard}; Invoke-Expression '{script}'",
            vetted_text=command,
            source_adapter=self.name,
            command_words=command_words,
        )
        response = powershell.run(wrapped, log_event=log_event)
        if response.get("error"):
            stderr = str(response.get("stderr") or response.get("error") or "")
            if self._looks_like_module_missing(stderr):
                response["error_class"] = "module_not_found"
                response["error"] = "module_not_found"
            response.setdefault("source", "m365dsc")
            response.setdefault("command", command)
            response["module_compatibility"] = compatibility
            return response

        response.setdefault("command", command)
        response.setdefault("source", "m365dsc")
        response["module_compatibility"] = compatibility
        return response
