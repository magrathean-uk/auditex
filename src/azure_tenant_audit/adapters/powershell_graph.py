from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Optional

from ..secret_hygiene import ipps_password_env_allowed, redact_command_string, redact_output
from .base import Adapter, AdapterMetadata
from .read_guard import CommandRefused, VettedCommand, check_command, refusal_response


_ORGANIZATION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)*\.onmicrosoft\.(?:com|us|de|cn)")
_IPPS_MAX_PFX_BYTES = 64 * 1024  # Same cap as the certificate-auth branch.
_IPPS_CHILD_PASSWORD = "AUDITEX_IPPS_CHILD_CERTIFICATE_PASSWORD"


def _ipps_certificate_file_usable(value: str) -> bool:
    """Check metadata only; Python never reads or exports the PFX/private key."""
    try:
        if os.path.realpath(value) != os.path.abspath(value):
            return False
        path = Path(os.path.abspath(value))
        uid = os.getuid() if hasattr(os, "getuid") else None
        for parent in path.parents:
            parent_info = parent.lstat()
            if not stat.S_ISDIR(parent_info.st_mode):
                return False
            if parent_info.st_mode & 0o022 and not (
                parent_info.st_mode & stat.S_ISVTX and parent_info.st_uid in {0, uid}
            ):
                return False
        info = path.lstat()
        return (stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077
                and 0 < info.st_size <= _IPPS_MAX_PFX_BYTES
                and (not hasattr(os, "getuid") or info.st_uid == os.getuid()))
    except (OSError, ValueError):
        return False


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
    def _looks_like_module_missing(text: str) -> bool:
        lowered = text.lower()
        return (
            "microsoft365dsc module not installed" in lowered
            or "cannot find path" in lowered
            or "import-module" in lowered and "microsoft365dsc" in lowered and "not" in lowered
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
    def _json_pipeline(script: str) -> str:
        """The checked script piped to ConvertTo-Json.

        Exchange Online's REST-backed cmdlets return enumerations (an accepted domain's ``DomainType``, for example)
        as objects that ConvertTo-Json writes as their integer value. ``-EnumsAsStrings`` (PowerShell 7.3 and later)
        writes the name instead; an older PowerShell does not have the switch, so it is used only where it exists.
        """
        convert = "ConvertTo-Json -Depth 20 -Compress"
        return (
            "if ((Get-Command ConvertTo-Json).Parameters.ContainsKey('EnumsAsStrings')) "
            f"{{ {script} | {convert} -EnumsAsStrings }} else {{ {script} | {convert} }}"
        )

    @staticmethod
    def _session_prelude(session: Optional[dict[str, Any]], env: dict[str, str]) -> tuple[str, str | None]:
        """Connect step for a fresh pwsh process. IPPS passwords travel over stdin; tokens use the environment."""
        child_input = None
        if session and session.get("kind") == "security_compliance":
            app_id = str(session.get("app_id") or "")
            thumbprint = str(session.get("certificate_thumbprint") or "")
            certificate_file = str(session.get("certificate_file") or "")
            password_env = str(session.get("certificate_password_env") or "")
            organization = str(session.get("organization") or "")
            if (not session.get("enabled") or not re.fullmatch(r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", app_id)
                    or bool(thumbprint) == bool(certificate_file)
                    or not _ORGANIZATION_PATTERN.fullmatch(organization)):
                return "", None
            if thumbprint:
                if sys.platform != "win32" or password_env or not re.fullmatch(r"[0-9A-Fa-f]{40}", thumbprint):
                    return "", None
                env["AUDITEX_IPPS_CERTIFICATE_THUMBPRINT"] = thumbprint
                certificate_argument = "-CertificateThumbprint $env:AUDITEX_IPPS_CERTIFICATE_THUMBPRINT "
                load_certificate = ""
            else:
                if (sys.platform not in {"darwin", "linux"}
                        or not ipps_password_env_allowed(password_env)
                        or not _ipps_certificate_file_usable(certificate_file)):
                    return "", None
                provider = session.get("certificate_password_provider")
                try:
                    password = provider() if callable(provider) else None
                except Exception:  # Credential-provider diagnostics must never escape.
                    return "", None
                if not isinstance(password, str) or not password or any(c in password for c in "\x00\r\n"):
                    return "", None
                env["AUDITEX_IPPS_CERTIFICATE_FILE"] = certificate_file
                child_input = password + "\n"
                # Let ExchangeOnlineManagement handle platform certificate loading.
                # EphemeralKeySet is not portable to common macOS .NET runtimes.
                load_certificate = (
                    "$ippsPassword = [System.Net.NetworkCredential]::new('', [Console]::In.ReadLine()).SecurePassword; "
                )
                certificate_argument = "-CertificateFilePath $env:AUDITEX_IPPS_CERTIFICATE_FILE -CertificatePassword $ippsPassword "
            env.update(AUDITEX_IPPS_APP_ID=app_id, AUDITEX_IPPS_ORGANIZATION=organization)
            return (
                "$ErrorActionPreference = 'Stop'; "
                "try { Import-Module ExchangeOnlineManagement -ErrorAction Stop } "
                "catch { throw 'AUDITEX_IPPS_MODULE_NOT_FOUND' }; "
                "try { " + load_certificate + "Connect-IPPSSession -AppId $env:AUDITEX_IPPS_APP_ID "
                + certificate_argument +
                "-Organization $env:AUDITEX_IPPS_ORGANIZATION -ShowBanner:$false -ErrorAction Stop | Out-Null } "
                "catch { throw 'AUDITEX_IPPS_SESSION_NOT_CONNECTED' }; "
            ), child_input
        if not session or session.get("kind") != "exchange_online":
            return "", None
        token = session.get("access_token")
        organization = str(session.get("organization") or "")
        if not token or not _ORGANIZATION_PATTERN.fullmatch(organization):
            return "", None
        env["AUDITEX_EXO_ACCESS_TOKEN"] = str(token)
        return (
            "Import-Module ExchangeOnlineManagement -ErrorAction Stop; "
            f"Connect-ExchangeOnline -AccessToken $env:AUDITEX_EXO_ACCESS_TOKEN -Organization '{organization}' "
            "-ShowBanner:$false -SkipLoadingFormatData -ErrorAction Stop | Out-Null; "
        ), None

    def run(
        self,
        command: str,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
        session: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        # An adapter that already checked the caller's command (Microsoft365DSC) passes the wrapped
        # text as VettedCommand; the audit log then records the command that was checked.
        vetted = isinstance(command, VettedCommand)
        logged_command = command.vetted_text if vetted else command
        adapter_label = command.source_adapter if vetted else self.name
        command_words: tuple[str, ...] = command.command_words if vetted else ()
        safe_command = redact_command_string(logged_command)
        script = command.strip()
        if script.startswith("pwsh"):
            parts = shlex.split(script)
            script = " ".join(parts[1:]) if len(parts) > 1 else ""

        if not script:
            return {"error": "command_empty", "error_class": "command_parse_error", "command": safe_command}

        if not vetted:
            try:
                command_words = check_command(self.name, script)
            except CommandRefused as exc:
                if log_event:
                    log_event(
                        "command.refused",
                        "Command refused before execution: not on the read allowlist",
                        {"adapter": adapter_label, "command": safe_command, "reason": exc.reason},
                    )
                return refusal_response(safe_command, exc)

        ipps = bool(session and session.get("kind") == "security_compliance")
        env = dict(os.environ)
        # Even direct adapter users must not leak a configured PFX password to
        # unrelated PowerShell children. Collector sessions consume it earlier.
        password_env = os.environ.get("AUDITEX_IPPS_CERTIFICATE_PASSWORD_ENV", "")
        if ipps_password_env_allowed(password_env):
            env.pop(password_env, None)
        if session and ipps_password_env_allowed(str(session.get("certificate_password_env") or "")):
            env.pop(session["certificate_password_env"], None)
        env.pop(_IPPS_CHILD_PASSWORD, None)
        prelude, child_input = self._session_prelude(session, env)
        if ipps and not prelude:
            error_class = "missing_app_credentials" if session.get("enabled") else "session_not_connected"
            return {"error": error_class, "error_class": error_class, "command": safe_command}

        exe = shutil.which("pwsh")
        if exe is None:
            if log_event:
                log_event(
                    "command.failed",
                    "PowerShell executable not found",
                    {"adapter": adapter_label, "command": safe_command, "command_words": list(command_words), "error_class": "command_not_found"},
                )
            return {"error": "command_not_found:pwsh", "error_class": "command_not_found", "command": safe_command}

        prepared = f"{prelude}{self._json_pipeline(script)}"
        try:
            if log_event:
                log_event(
                    "command.started",
                    "PowerShell command started",
                    {
                        "adapter": adapter_label,
                        "command": safe_command,
                        "command_words": list(command_words),
                        "executable": exe,
                    },
                )

            start = time.time()
            # Narrow the path race after providers/log callbacks, just before launch.
            # pwsh still reopens the path: this is not inode pinning.
            if ipps and session.get("certificate_file") and not _ipps_certificate_file_usable(session["certificate_file"]):
                return {"error": "missing_app_credentials", "error_class": "missing_app_credentials", "command": safe_command}
            result = subprocess.run(
                [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prepared],
                input=child_input,
                text=True,
                capture_output=True,
                timeout=180 if prelude else 120,
                env=env,
            )
            duration_ms = round((time.time() - start) * 1000, 2)
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            combined = f"{stdout}\n{stderr}".lower()

            def completed(error_class: str | None) -> None:
                # The outcome is logged with the command words, not only the return code: a command can exit 0 and
                # still return nothing usable, and the observed ledger tells the two apart by ``status``.
                if log_event:
                    log_event(
                        "command.completed",
                        "PowerShell command completed",
                        {
                            "adapter": adapter_label,
                            "command": safe_command,
                            "command_words": list(command_words),
                            "return_code": result.returncode,
                            "status": "ok" if error_class is None else "failed",
                            "error_class": error_class,
                            "duration_ms": duration_ms,
                            "stdout_bytes": len(stdout),
                            "stderr_bytes": len(stderr),
                            **({} if ipps else {"stdout_sample": redact_output(stdout)}),
                        },
                    )

            if result.returncode != 0 or self._looks_like_not_found(combined) or self._looks_like_auth_required(combined):
                module_missing = adapter_label == "m365dsc" and self._looks_like_module_missing(stderr)
                if module_missing:
                    error_class = "module_not_found"
                elif self._looks_like_not_found(combined) and session is not None and not prelude:
                    # Exchange/Teams cmdlets only exist inside a connected session.
                    error_class = "session_not_connected"
                elif self._looks_like_not_found(combined):
                    error_class = "command_not_found"
                elif self._looks_like_auth_required(combined):
                    error_class = "command_not_authenticated"
                else:
                    error_class = "command_error"
                if ipps:
                    if "auditex_ipps_module_not_found" in combined:
                        error_class = "module_not_found"
                    elif "auditex_ipps_session_not_connected" in combined:
                        error_class = "session_not_connected"
                    elif any(marker in combined for marker in ("not licensed", "license required", "licence required", "requires a license")):
                        error_class = "license_required"
                completed(error_class)
                if ipps:
                    return {"error": error_class, "error_class": error_class, "command": safe_command}
                return {
                    "error": "module_not_found" if module_missing else f"command_failed:{result.returncode}",
                    "error_class": error_class,
                    "command": safe_command,
                    "return_code": result.returncode,
                    "stdout": redact_output(stdout),
                    "stderr": redact_output(stderr),
                }

            if not stdout.strip():
                completed("command_output_empty")
                return {
                    "error": "command_output_empty",
                    "error_class": "command_output_empty",
                    "command": safe_command,
                    **({} if ipps else {"stdout": redact_output(stdout), "stderr": redact_output(stderr)}),
                }

            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError:
                completed("command_parse_error")
                return {
                    "error": "command_output_parse_error",
                    "error_class": "command_parse_error",
                    "command": safe_command,
                    **({} if ipps else {"stdout": redact_output(stdout), "stderr": redact_output(stderr)}),
                }

            # IPPS commands explicitly wrap listings in arrays. An unexpected JSON envelope
            # must not smuggle output/credentials into the evidence or look like a clean read.
            if ipps and (not isinstance(parsed, list) or any(not isinstance(row, dict) for row in parsed)):
                completed("command_parse_error")
                return {"error": "command_parse_error", "error_class": "command_parse_error", "command": safe_command}
            completed(None)
            response = self._normalize_payload(parsed)
            response["command"] = safe_command
            return response
        except subprocess.TimeoutExpired:
            if log_event:
                log_event(
                    "command.failed",
                    "PowerShell command timed out",
                    {"adapter": adapter_label, "command": safe_command, "command_words": list(command_words), "error_class": "command_timeout"},
                )
            return {"error": "command_timeout", "error_class": "command_timeout", "command": safe_command}
        except subprocess.CalledProcessError as exc:  # noqa: BLE001
            if log_event:
                log_event(
                    "command.failed",
                    "PowerShell command failed",
                    {"adapter": adapter_label, "command": safe_command, "command_words": list(command_words), "error": "command_error" if ipps else redact_output(str(exc))},
                )
            return {"error": f"command_failed:{exc.returncode}", "error_class": "command_error", "command": safe_command}
        except Exception as exc:  # noqa: BLE001
            if log_event:
                log_event(
                    "command.failed",
                    "PowerShell command exception",
                    {"adapter": adapter_label, "command": safe_command, "command_words": list(command_words), "error": "command_exception" if ipps else redact_output(str(exc))},
                )
            return {"error": "command_exception" if ipps else redact_output(str(exc)), "error_class": "command_exception", "command": safe_command}
