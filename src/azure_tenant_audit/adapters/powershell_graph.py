from __future__ import annotations

import base64
import json
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ..secret_hygiene import redact_command_string, redact_output
from .base import Adapter, AdapterMetadata
from .read_guard import CommandRefused, VettedCommand, check_command, refusal_response

# A signed-in user name (UPN): plain address characters only; it travels in the environment, never in script text.
_ORGANIZATION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)*\.onmicrosoft\.(?:com|us|de|cn)")
# Security & Compliance PowerShell (Connect-IPPSSession): the Microsoft Exchange Online Protection resource, by its
# identifier URI or its application id. Only an app-only token minted from a certificate for it opens the session.
COMPLIANCE_AUDIENCES = frozenset({"https://ps.compliance.protection.outlook.com", "00000007-0000-0ff1-ce00-000000000000"})
# Error class, and the fixed text the compliance prelude throws, when Connect-IPPSSession fails: the original error
# (which can name the tenant, the app or the token) is dropped inside PowerShell and never reaches stderr.
IPPS_SESSION_NOT_OPENED = "ipps_session_not_opened"
# The child pwsh never gets the auditor's credentials: any variable whose name marks a secret (client secrets,
# passwords, PINs, tokens, keys, connection strings) is dropped, including a stale session token from the
# parent; the connect prelude adds the one fresh token the session needs. The read guard already refuses every way a
# checked script could read the environment ($env:, ${env:...}, Get-ChildItem env:, Get-Variable); this keeps the
# secrets out of the child as well. Proxy variables are kept: pwsh needs them to reach Microsoft.
_SECRET_ENV_NAME = re.compile(
    r"SECRET|PASSWORD|PASSWD|PASSPHRASE|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE|CREDENTIAL|"
    r"CONNECTION_STRING|CONNECTIONSTRING|SAS_|_SAS|_KEY$|^KEY_|_KEY_|AUTH|PASS|(?:^|_)(?:PW|PIN)(?:_|$)",
    re.IGNORECASE,
)


def child_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """``source`` (default ``os.environ``) without any credential-named variable, for a pwsh child."""
    items = (os.environ if source is None else source).items()
    return {name: value for name, value in items if not _SECRET_ENV_NAME.search(name)}


# Bounded reads for a sensitive command: stdout chunk size and the stderr kept for failure classification only.
READ_CHUNK = 64 * 1024
STDERR_KEEP = 1024 * 1024


def compliance_certificate_token(token: Any) -> bool:
    """Credential gate for the Security & Compliance session; the service validates the signature.

    Entra v1 ``appidacr`` and v2 ``azpacr`` are ``2`` for a certificate credential (``1`` is a client secret). A delegated
    token (``scp``), a secret-minted, opaque or unreadable token, or one for another audience fails closed: no Microsoft
    source shows a secret-minted token is accepted for app-only Security & Compliance PowerShell.
    """
    try:
        payload = str(token).split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        credential = claims.get("azpacr", claims.get("appidacr"))
        audience = str(claims.get("aud") or "").casefold().rstrip("/")
        return credential == "2" and not claims.get("scp") and audience in COMPLIANCE_AUDIENCES
    except (AttributeError, IndexError, ValueError, TypeError, RecursionError):
        return False


class _BoundedRun:
    """Outcome of ``_run_bounded``. Its repr shows no output."""

    __slots__ = ("returncode", "stdout", "stderr", "stdout_total", "stderr_total", "overflow", "timed_out",
                 "duration_ms", "pid")

    def __repr__(self) -> str:
        return "_BoundedRun()"


def _run_bounded(
    argv: list[str],
    *,
    env: dict[str, str] | None,
    timeout: float,
    stdout_limit: int,
    chunk_size: int = READ_CHUNK,
    stderr_keep: int = STDERR_KEEP,
) -> _BoundedRun:
    """Run ``argv`` reading stdout in ``chunk_size`` reads under ``stdout_limit`` bytes while stderr drains alongside.

    Passing the limit or ``timeout`` stops reading; a child still running is then killed, and every child is reaped
    before return. No byte past the limit is kept, so at most ``stdout_limit`` bytes are buffered. Nothing here
    decodes, logs or echoes output.
    """
    run = _BoundedRun()
    run.stdout = bytearray()
    kept_err = bytearray()
    totals = [0, 0]
    flags = {"overflow": False}
    start = time.monotonic()
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    run.pid = process.pid

    def read_stdout() -> None:
        descriptor = process.stdout.fileno()
        try:
            while True:
                data = os.read(descriptor, chunk_size)
                if not data:
                    return
                totals[0] += len(data)
                if totals[0] > stdout_limit:
                    flags["overflow"] = True
                    return
                run.stdout += data
        except OSError:
            return

    def drain_stderr() -> None:
        descriptor = process.stderr.fileno()
        try:
            while True:
                data = os.read(descriptor, chunk_size)
                if not data:
                    return
                totals[1] += len(data)
                room = stderr_keep - len(kept_err)
                if room > 0:
                    kept_err.extend(data[:room])
        except OSError:
            return

    readers = (threading.Thread(target=read_stdout, daemon=True), threading.Thread(target=drain_stderr, daemon=True))
    timed_out = False
    try:
        for reader in readers:
            reader.start()
        readers[0].join(timeout)
        if readers[0].is_alive():
            timed_out = True
        elif not flags["overflow"]:
            try:
                process.wait(timeout=max(0.0, timeout - (time.monotonic() - start)))
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        for reader, stream in zip(readers, (process.stdout, process.stderr), strict=False):
            if reader.ident is not None:
                reader.join(5)
            if not reader.is_alive():
                stream.close()
    run.returncode = process.returncode
    run.stderr = kept_err.decode("utf-8", "replace")
    run.stdout_total, run.stderr_total = totals
    run.overflow = flags["overflow"]
    run.timed_out = timed_out
    run.duration_ms = round((time.monotonic() - start) * 1000, 2)
    return run



def exchange_session_connectable(exo: Any) -> bool:
    """True when the session ``exo`` gives the adapter an Exchange Online connect step; without one a cmdlet runs
    unconnected."""
    if not isinstance(exo, dict) or exo.get("kind") != "exchange_online" or not exo.get("access_token"):
        return False
    return bool(_ORGANIZATION_PATTERN.fullmatch(str(exo.get("organization") or "")))

class PowerShellGraphAdapter(Adapter):
    metadata = AdapterMetadata(
        name="powershell_graph",
        auth_requirements=("app",),
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
    def _session_prelude(session: dict[str, Any] | None, env: dict[str, str]) -> str:
        """Connect step for a fresh pwsh process. Tokens travel in the environment, never on the command line.

        Every connect passes an app-only access token minted from the reader app's certificate with -Organization
        (DEC-107). Without a usable token there is no connect at all.

        The ``security_compliance`` kind connects Security & Compliance PowerShell (``Connect-IPPSSession``, module
        3.8.0 or later for its access-token parameter) with an app-only certificate token for the compliance audience
        and the initial domain. A failed connect throws only the fixed ``IPPS_SESSION_NOT_OPENED`` text, so no read
        runs outside the session and the failure is named, never a pass.
        """
        if session and session.get("kind") == "security_compliance":
            token = session.get("access_token")
            organization = str(session.get("organization") or "")
            if not token or not _ORGANIZATION_PATTERN.fullmatch(organization) or not compliance_certificate_token(token):
                return ""
            env["AUDITEX_IPPS_ACCESS_TOKEN"] = str(token)
            return (
                "Import-Module ExchangeOnlineManagement -ErrorAction Stop; "
                "try { Connect-IPPSSession -AccessToken $env:AUDITEX_IPPS_ACCESS_TOKEN "
                f"-Organization '{organization}' -ShowBanner:$false -ErrorAction Stop | Out-Null }} "
                f"catch {{ throw '{IPPS_SESSION_NOT_OPENED}' }}; "
            )
        if not exchange_session_connectable(session):
            return ""
        token, organization = session["access_token"], str(session["organization"])
        env["AUDITEX_EXO_ACCESS_TOKEN"] = str(token)
        return (
            "Import-Module ExchangeOnlineManagement -ErrorAction Stop; "
            f"Connect-ExchangeOnline -AccessToken $env:AUDITEX_EXO_ACCESS_TOKEN -Organization '{organization}' "
            "-ShowBanner:$false -SkipLoadingFormatData -ErrorAction Stop | Out-Null; "
        )

    @staticmethod
    def _child_argv(exe: str, prepared: str) -> list[str]:
        return [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prepared]

    def run(
        self,
        command: str,
        log_event: Callable[[str, str, dict[str, Any] | None], None] | None = None,
        session: dict[str, Any] | None = None,
        response_transform: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Run one checked read. ``response_transform`` is honoured only for the sensitive anti-phish read.

        The process timeout is 180 s with a connect step, else 120 s; a whole-tenant enumeration (``-ResultSize
        Unlimited``) gets UNBOUNDED_READ_TIMEOUT_SECONDS, as it walks every mailbox before answering (R047).

        ``Get-AntiPhishPolicy`` is recognised as sensitive from the command itself, so a caller that passes no
        transform still gets rows without targeted users (summarised ``not_collected``) and no output text.
        """
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

        exe = shutil.which("pwsh")
        if exe is None:
            if log_event:
                log_event(
                    "command.failed",
                    "PowerShell executable not found",
                    {"adapter": adapter_label, "command": safe_command, "command_words": list(command_words), "error_class": "command_not_found"},
                )
            return {"error": "command_not_found:pwsh", "error_class": "command_not_found", "command": safe_command}

        env = child_environment()
        prelude = self._session_prelude(session, env)
        compliance = _session_kind(session) == "security_compliance"
        if compliance and not prelude:
            # The compliance session needs its certificate token and initial domain; without them no process starts.
            if log_event:
                log_event(
                    "command.failed",
                    "Security & Compliance session not opened",
                    {"adapter": adapter_label, "command": safe_command, "command_words": list(command_words),
                     "error_class": IPPS_SESSION_NOT_OPENED},
                )
            return {"error": IPPS_SESSION_NOT_OPENED, "error_class": IPPS_SESSION_NOT_OPENED, "command": safe_command}
        prepared = f"$ErrorActionPreference = 'Stop'; {prelude}{self._json_pipeline(script)}"
        process_timeout = (UNBOUNDED_READ_TIMEOUT_SECONDS if "-resultsize unlimited" in script.lower()
                           else 180 if prelude else 120)
        if _sensitive(script):
            return self._run_sensitive(
                exe=exe, prepared=prepared, env=env, timeout=process_timeout, script=script,
                adapter_label=adapter_label, safe_command=safe_command, command_words=command_words,
                has_session=session is not None, prelude=bool(prelude), log_event=log_event,
                response_transform=response_transform,
            )
        try:
            if log_event:
                log_event(
                    "command.started",
                    "PowerShell command started",
                    {
                        "adapter": adapter_label,
                        "command": safe_command,
                        "command_words": list(command_words),
                        "executable": Path(exe).name,
                    },
                )

            start = time.time()
            result = subprocess.run(
                [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prepared],
                text=True,
                capture_output=True,
                timeout=process_timeout,
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
                            "stdout_sample": redact_output(stdout),
                        },
                    )

            if _json_success(result.returncode, stdout):
                # Tenant rows are never searched for refusal text (R020): a zero exit with JSON is classified from
                # stderr alone, which still names a refused or missing command.
                combined = stderr.lower()
            if (result.returncode != 0 or self._looks_like_not_found(combined)
                    or self._looks_like_auth_required(combined)):
                module_missing = adapter_label == "m365dsc" and self._looks_like_module_missing(stderr)
                if module_missing:
                    error_class = "module_not_found"
                elif compliance and result.returncode != 0 and IPPS_SESSION_NOT_OPENED in stderr:
                    # The prelude's fixed text: Connect-IPPSSession failed, so the read never ran.
                    error_class = IPPS_SESSION_NOT_OPENED
                elif self._looks_like_not_found(combined) and session is not None and not prelude:
                    # Exchange/Teams cmdlets only exist inside a connected session.
                    error_class = "session_not_connected"
                elif self._looks_like_not_found(combined):
                    error_class = "command_not_found"
                elif self._looks_like_auth_required(combined):
                    error_class = "command_not_authenticated"
                else:
                    error_class = "command_error"
                completed(error_class)
                return {
                    "error": ("module_not_found" if module_missing else IPPS_SESSION_NOT_OPENED
                              if error_class == IPPS_SESSION_NOT_OPENED else f"command_failed:{result.returncode}"),
                    "error_class": error_class,
                    "command": safe_command,
                    "return_code": result.returncode,
                    "stdout": redact_output(stdout),
                    "stderr": redact_output(stderr),
                }

            if not stdout.strip() and not stderr.strip() and script.startswith(",@(") and script.endswith(")"):
                # Only explicitly declared collection reads may legitimately return no rows.
                completed(None)
                return {"value": [], "command": safe_command}

            if not stdout.strip():
                error_class = "command_error" if stderr.strip() else "command_output_empty"
                completed(error_class)
                return {
                    "error": error_class,
                    "error_class": error_class,
                    "command": safe_command,
                    "stdout": redact_output(stdout),
                    "stderr": redact_output(stderr),
                }

            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError:
                completed("command_parse_error")
                return {
                    "error": "command_output_parse_error",
                    "error_class": "command_parse_error",
                    "command": safe_command,
                    "stdout": redact_output(stdout),
                    "stderr": redact_output(stderr),
                }

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
                    {"adapter": adapter_label, "command": safe_command, "command_words": list(command_words), "error": redact_output(str(exc))},
                )
            return {"error": f"command_failed:{exc.returncode}", "error_class": "command_error", "command": safe_command}
        except Exception as exc:  # noqa: BLE001
            if log_event:
                log_event(
                    "command.failed",
                    "PowerShell command exception",
                    {"adapter": adapter_label, "command": safe_command, "command_words": list(command_words), "error": redact_output(str(exc))},
                )
            return {"error": redact_output(str(exc)), "error_class": "command_exception", "command": safe_command}

    def _run_sensitive(
        self,
        *,
        exe: str,
        prepared: str,
        env: dict[str, str],
        timeout: float,
        script: str,
        adapter_label: str,
        safe_command: str,
        command_words: tuple[str, ...],
        has_session: bool,
        prelude: bool,
        log_event: Callable[[str, str, dict[str, Any] | None], None] | None,
        response_transform: Callable[[dict[str, Any]], dict[str, Any]] | None,
    ) -> dict[str, Any]:
        """A read whose output can hold targeted users' names and addresses (``Get-AntiPhishPolicy``).

        The privacy boundary sits here, before any event or return: stdout is read in bounded chunks under the
        aggregate limit, and the rows are rebuilt by ``targeted_users_coverage`` (through the caller's transform,
        or with no binding when there is none) and checked against its closed shape. Success, failure, warning,
        parse, timeout, overflow and exception paths keep only fixed classes, the command and numbers: never
        stdout, stderr, a sample, an exception message or a traceback. Classification reads output in memory
        exactly as for every other command.
        """
        from ..collectors import targeted_users_coverage as boundary

        base: dict[str, Any] = {"adapter": adapter_label, "command": safe_command, "command_words": list(command_words)}

        def event(kind: str, message: str, details: dict[str, Any]) -> None:
            if log_event:
                log_event(kind, message, {**base, **details})

        def failure(error: str, error_class: str, numbers: dict[str, Any]) -> dict[str, Any]:
            return {"error": error, "error_class": error_class, "command": safe_command, **numbers}

        numbers: dict[str, Any] = {}
        try:
            event("command.started", "PowerShell command started", {"executable": Path(exe).name})
            run = _run_bounded(self._child_argv(exe, prepared), env=env, timeout=timeout,
                               stdout_limit=boundary.STDOUT_LIMIT)
            numbers = {"duration_ms": run.duration_ms, "stdout_bytes": run.stdout_total, "stderr_bytes": run.stderr_total}
            if run.timed_out:
                event("command.failed", "PowerShell command timed out", {"error_class": "command_timeout", **numbers})
                return failure("command_timeout", "command_timeout", numbers)
            if run.overflow:
                # Over the aggregate limit: the child is already killed and reaped, and nothing it wrote is kept.
                event("command.failed", "PowerShell command output over limit",
                      {"error_class": "command_error", "state": "over_limit", **numbers})
                return {**failure("command_output_over_limit", "command_error", numbers), "state": "over_limit"}
            numbers["return_code"] = run.returncode
            try:
                stdout: str | None = str(run.stdout, "utf-8")
            except UnicodeDecodeError:
                stdout = None
            run.stdout = bytearray()
            stderr = run.stderr
            combined = f"{stdout or ''}\n{stderr}".lower()

            def completed(error_class: str | None) -> None:
                event("command.completed", "PowerShell command completed", {
                    "return_code": numbers["return_code"], "status": "ok" if error_class is None else "failed",
                    "error_class": error_class, "duration_ms": numbers["duration_ms"],
                    "stdout_bytes": numbers["stdout_bytes"], "stderr_bytes": numbers["stderr_bytes"],
                })

            if _json_success(run.returncode, stdout):
                combined = stderr.lower()  # never the tenant rows (R020)
            if run.returncode != 0 or self._looks_like_not_found(combined) or self._looks_like_auth_required(combined):
                module_missing = adapter_label == "m365dsc" and self._looks_like_module_missing(stderr)
                if module_missing:
                    error_class = "module_not_found"
                elif self._looks_like_not_found(combined) and has_session and not prelude:
                    error_class = "session_not_connected"
                elif self._looks_like_not_found(combined):
                    error_class = "command_not_found"
                elif self._looks_like_auth_required(combined):
                    error_class = "command_not_authenticated"
                else:
                    error_class = "command_error"
                completed(error_class)
                return failure("module_not_found" if module_missing else f"command_failed:{run.returncode}",
                               error_class, numbers)
            if stdout is None:
                completed("command_parse_error")
                return failure("command_output_parse_error", "command_parse_error", numbers)
            if not stdout.strip() and not stderr.strip() and script.startswith(",@(") and script.endswith(")"):
                parsed: Any = []
            elif not stdout.strip():
                error_class = "command_error" if stderr.strip() else "command_output_empty"
                completed(error_class)
                return failure(error_class, error_class, numbers)
            else:
                try:
                    parsed = json.loads(stdout)
                except (ValueError, RecursionError):
                    completed("command_parse_error")
                    return failure("command_output_parse_error", "command_parse_error", numbers)
            del stdout, combined, stderr
            from ..collectors.anti_phish_admission import (
                ADMITTED,
                REFUSED,
                SUCCESS_KEYS,
                admit_response,
            )
            # A wire object declaring operation metadata is an envelope, even when its value is missing or invalid.
            # Generic normalisation would otherwise wrap it as a policy row and hide its original refusal semantics.
            envelope_keys = SUCCESS_KEYS | {"chunk_files", "chunk_count", "details", "exception", "traceback",
                                           "warning", "warnings"}
            response = parsed if isinstance(parsed, dict) and any(key in envelope_keys for key in parsed) else self._normalize_payload(parsed)
            del parsed
            # Validate before a transform can mutate the original response, on the no-callback path as well.
            original_admission = admit_response(response, observed=True)
            if original_admission == REFUSED:
                completed("command_parse_error")
                return failure("command_output_parse_error", "command_parse_error", numbers)
            try:
                if response_transform is None:
                    shaped = boundary.sanitise_response(response, None, None, observed=True, command=safe_command)
                else:
                    shaped = boundary.enforce_response(response_transform(response), command=safe_command)
                    if original_admission != ADMITTED and shaped.get("error") is None and shaped.get("error_class") is None:
                        shaped = None
            except Exception:  # noqa: BLE001 - a transform failure never carries its message out
                shaped = None
            if shaped is None:
                completed("command_exception")
                return failure("command_exception", "command_exception", numbers)
            if shaped.get("error_class"):
                completed(str(shaped["error_class"]))
                return {**shaped, **numbers}
            completed(None)
            return shaped
        except Exception:  # noqa: BLE001 - fixed class only: no str(exc), repr or traceback for this command
            event("command.failed", "PowerShell command exception", {"error_class": "command_exception", **numbers})
            return failure("command_exception", "command_exception", numbers)


# A read that enumerates every mailbox in the tenant before answering outlasts the default timeout on a large tenant.
UNBOUNDED_READ_TIMEOUT_SECONDS = 600


def _json_success(returncode: int | None, stdout: str | None) -> bool:
    """A zero exit whose stdout parses as JSON is a read that ran (R020): tenant rows such as a rule named 'Block
    unauthorized sharing' must never be searched for refusal text, so only stderr is."""
    if returncode != 0 or not stdout or not stdout.strip():
        return False
    try:
        json.loads(stdout)
    except (ValueError, RecursionError):
        return False
    return True


def _session_kind(value: Any) -> str | None:
    return value.get("kind") if isinstance(value, dict) else None


def _sensitive(script: str) -> bool:
    """``targeted_users_coverage.is_sensitive_command`` without importing it for every other command."""
    folded = script.casefold()
    return "get-antiphishpolicy" in folded or "targeteduserstoprotect" in folded
