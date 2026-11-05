from __future__ import annotations

import argparse
import subprocess
import json
import logging
import os
from collections import defaultdict
from typing import Any, Callable, Optional
import sys
import time
from pathlib import Path

from .collectors import REGISTRY
from .collectors.base import CollectorResult
from .config import AuthConfig, CollectorConfig, RunConfig
from .graph import GraphClient
from .output import AuditWriter
from .utils import load_env_file, parse_csv_list

try:
    from .secret_hygiene import redact_argv as _redact_argv
except ModuleNotFoundError as exc:
    if exc.name != f"{__package__}.secret_hygiene":
        raise

    def _redact_argv(command_line: list[str], *, sensitive_flags: set[str]) -> list[str]:
        """Standalone kit fallback for the shared prefix-aware argv scrubber."""
        scrubbed: list[str] = []
        skip_next = False
        for item in command_line:
            if skip_next:
                scrubbed.append("***redacted***")
                skip_next = False
                continue
            option, separator, _value = item.partition("=")
            sensitive = option in sensitive_flags or (
                option.startswith("--")
                and len(option) > 2
                and any(flag.startswith(option) for flag in sensitive_flags)
            )
            if sensitive:
                scrubbed.append(f"{option}=***redacted***" if separator else item)
                skip_next = not separator
            else:
                scrubbed.append(item)
        if skip_next:
            scrubbed.append("***redacted***")
        return scrubbed

LOG = logging.getLogger("azure_tenant_audit")

SENSITIVE_CLI_ARGS = {"--client-secret", "--access-token"}

AUDITOR_PROFILE_ENTERPRISE = "enterprise"
AUDITOR_PROFILE_GLOBAL_READER = "global-reader"
AUDITOR_PROFILE_AUTO = "auto"
GLOBAL_READER_DEFAULT_COLLECTORS = ("identity", "security", "teams", "intune")


def _scrub_command_line(command_line: list[str]) -> list[str]:
    """Remove token values from command history before writing into logs/manifest."""
    return _redact_argv(command_line, sensitive_flags=SENSITIVE_CLI_ARGS)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Run Microsoft tenant audit collection.")
    parser.add_argument("--tenant-name", default="tenant", help="Label for the output folder.")
    parser.add_argument("--tenant-id", default=None, help="Entra tenant ID.")
    parser.add_argument("--client-id", default=None, help="App registration ID.")
    parser.add_argument("--client-secret", default=None, help="App secret.")
    parser.add_argument("--access-token", default=None, help="Optional preissued Graph access token.")
    parser.add_argument(
        "--use-azure-cli-token",
        action="store_true",
        help="Use an existing Azure CLI Graph token if available (no app credentials required).",
    )
    parser.add_argument("--authority", default="https://login.microsoftonline.com/", help="Identity authority URL.")
    parser.add_argument("--graph-scope", default="https://graph.microsoft.com/.default", help="Graph scope.")
    parser.add_argument("--interactive", action="store_true", help="Use delegated browser login.")
    parser.add_argument("--scopes", default=None, help="Comma-separated delegated Graph scopes for interactive login.")
    parser.add_argument("--browser-command", default="firefox", help="Browser command used by interactive auth.")
    parser.add_argument("--out", default="audit-output", help="Base output directory.")
    parser.add_argument("--config", default="configs/collector-definitions.json", help="Collector configuration file.")
    parser.add_argument("--collectors", default=None, help="Comma-separated collectors to run.")
    parser.add_argument("--exclude", default=None, help="Comma-separated collectors to skip.")
    parser.add_argument("--include-exchange", action="store_true", help="Enable optional exchange collectors.")
    parser.add_argument(
        "--auditor-profile",
        default=AUDITOR_PROFILE_AUTO,
        choices=[AUDITOR_PROFILE_AUTO, AUDITOR_PROFILE_ENTERPRISE, AUDITOR_PROFILE_GLOBAL_READER],
        help="Runtime profile ('auto'|'enterprise'|'global-reader').",
    )
    parser.add_argument("--top", type=int, default=500, help="Per-endpoint row cap.")
    parser.add_argument("--run-name", default=None, help="Optional run subfolder identifier.")
    parser.add_argument("--offline", action="store_true", help="Use offline sample bundle.")
    parser.add_argument("--sample", default="examples/sample_audit_bundle/sample_result.json", help="Sample bundle path when offline.")
    parser.add_argument(
        "--permission-hints",
        default="configs/collector-permissions.json",
        help="Optional collector-permission matrix file for diagnostics.",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose logs.")
    parser.add_argument("--env", default=None, help="Optional .env-like file to load.")
    return parser


def _acquire_azure_cli_access_token(
    tenant_id: str | None, log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None
) -> str:
    """Load a Microsoft Graph token from Azure CLI for environments without app registration."""

    command = [
        "az",
        "account",
        "get-access-token",
        "--resource",
        "https://graph.microsoft.com",
        "--output",
        "json",
    ]
    if tenant_id:
        command.extend(["--tenant", tenant_id])

    start = time.time()
    if log_event:
        log_event(
            "auth.cli.token.requested",
            "Requesting Microsoft Graph token from Azure CLI",
            {"tenant_id": tenant_id or "organizations", "resource": "https://graph.microsoft.com"},
        )
    try:
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=120,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Azure CLI is not available. Install azure-cli and sign in with 'az login'.") from exc

    duration_ms = round((time.time() - start) * 1000, 2)

    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "").strip() or "Azure CLI token command failed."
        if "Please run 'az login'" in message or "Please run: az login" in message:
            if log_event:
                log_event(
                    "auth.cli.token.failed",
                    "Azure CLI token acquisition failed because login is required.",
                    {"tenant_id": tenant_id or "organizations", "duration_ms": duration_ms},
                )
            raise RuntimeError("Azure CLI is not signed in. Run 'az login' in a browser first, then retry.") from None
        if log_event:
            log_event(
                "auth.cli.token.failed",
                "Azure CLI token acquisition failed.",
                {
                    "tenant_id": tenant_id or "organizations",
                    "duration_ms": duration_ms,
                    "error": message,
                },
            )
        raise RuntimeError(f"Azure CLI token fetch failed: {message}")

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        if log_event:
            log_event(
                "auth.cli.token.failed",
                "Azure CLI token response was not valid JSON.",
                {
                    "tenant_id": tenant_id or "organizations",
                    "duration_ms": duration_ms,
                },
            )
        raise RuntimeError("Azure CLI returned non-JSON token response.") from exc

    token = payload.get("accessToken") or payload.get("access_token")
    if not token:
        if log_event:
            log_event(
                "auth.cli.token.failed",
                "Azure CLI token response missing access token field.",
                {"tenant_id": tenant_id or "organizations", "duration_ms": duration_ms},
            )
        raise RuntimeError("Azure CLI token response was missing accessToken.")

    if log_event:
        log_event(
            "auth.cli.token.acquired",
            "Azure CLI token acquired.",
            {
                "tenant_id": tenant_id or "organizations",
                "duration_ms": duration_ms,
            },
        )
    return token


def _resolve_audit_profile(profile: str | None, auth_mode: str) -> str:
    if profile in (AUDITOR_PROFILE_ENTERPRISE, AUDITOR_PROFILE_GLOBAL_READER):
        return profile
    if auth_mode == "app":
        return AUDITOR_PROFILE_ENTERPRISE
    return AUDITOR_PROFILE_GLOBAL_READER


def _apply_profile_collector_defaults(
    selected: list[str] | None,
    profile: str,
    available: list[str],
) -> list[str]:
    if profile != AUDITOR_PROFILE_GLOBAL_READER:
        return selected
    if selected:
        return selected
    profile_defaults = [name for name in GLOBAL_READER_DEFAULT_COLLECTORS if name in available]
    return profile_defaults


def _capture_signed_in_context(
    client: GraphClient, log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None
) -> dict[str, Any]:
    """Best-effort capture of the current delegated identity and directory roles."""

    try:
        me = client.get_json("/me")
        roles = client.get_all(
            "/me/memberOf/microsoft.graph.directoryRole",
            params={"$select": "id,displayName,roleTemplateId"},
        )
    except Exception as exc:  # noqa: BLE001
        if log_event:
            log_event(
                "auth.session.unavailable",
                "Unable to capture signed-in identity and directory roles.",
                {"error": str(exc)},
            )
        return {}

    role_names = sorted(
        {
            role.get("displayName")
            for role in roles
            if isinstance(role, dict) and role.get("displayName")
        }
    )
    context = {
        "display_name": me.get("displayName"),
        "user_principal_name": me.get("userPrincipalName"),
        "object_id": me.get("id"),
        "roles": role_names,
    }
    if log_event:
        log_event(
            "auth.session.context",
            "Captured signed-in identity and directory roles.",
            context,
        )
    return context


def run_offline(sample_path: Path, out: Path, tenant_name: str, run_name: str | None) -> int:
    if not sample_path.exists():
        LOG.error("Sample file not found: %s", sample_path)
        return 2
    try:
        sample = json.loads(sample_path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        LOG.error("Unable to load sample bundle: %s", exc)
        return 2

    writer = AuditWriter(out, tenant_name=tenant_name, run_name=run_name)
    writer.log_event("run.started", "Offline run started", {"mode": "offline", "sample": str(sample_path)})

    (writer.raw_dir / "sample_input.json").write_text(
        json.dumps(sample, indent=2),
        encoding="utf-8",
    )
    for key, value in sample.items():
        row = {
            "name": key,
            "status": "ok",
            "item_count": len(value.get("value", [])) if isinstance(value, dict) else 0,
            "message": "offline simulation",
        }
        writer.write_summary(row)
        writer.log_event("collector.synthetic", "Offline collector simulated", {"name": key, "item_count": row["item_count"]})
    writer.write_bundle(
        {
            "executed_by": "azure_tenant_audit",
            "collectors": list(sample.keys()),
            "overall_status": "ok",
            "duration_seconds": 0,
            "mode": "offline",
            "auditor_profile": "auto",
            "command_line": [],
        }
    )
    LOG.info("Offline sample written to %s", writer.run_dir)
    return 0


def _load_permission_hints(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        LOG.warning("Permission hints file not found: %s", path)
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        LOG.warning("Failed to load permission hints file %s: %s", path, exc)
        return {}
    raw = payload.get("collector_permissions") or {}
    if not isinstance(raw, dict):
        return {}
    return {str(name): dict(value) if isinstance(value, dict) else {} for name, value in raw.items()}


def _build_diagnostics(
    result_rows: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
    permission_hints: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    by_collector = defaultdict(list)
    for row in coverage_rows:
        collector_name = row.get("collector")
        if isinstance(collector_name, str):
            by_collector[collector_name].append(row)

    for row in result_rows:
        collector_name = row["name"]
        if row["status"] == "ok":
            continue
        hints = permission_hints.get(collector_name, {})
        recommended_scopes = hints.get("graph_scopes", [])
        minimum_roles = hints.get("minimum_role_hints", [])
        command_tools = hints.get("command_tools", [])
        optional_commands = hints.get("optional_commands", [])
        notes = hints.get("notes")
        notes_detail = notes if isinstance(notes, str) else None
        issue_rows = by_collector.get(collector_name, [])
        if not issue_rows:
            failures.append(
                {
                    "collector": collector_name,
                    "status": row["status"],
                    "error": row.get("error"),
                    "error_class": "unknown",
                    "evidence": {
                        "message": row.get("message"),
                    },
                    "recommendations": {
                        "required_graph_scopes": sorted(set(recommended_scopes)),
                        "recommended_roles": sorted(set(minimum_roles)),
                        "command_tools": sorted(set(command_tools)),
                        "optional_commands": sorted(set(optional_commands)),
                        "notes": notes_detail,
                    },
                }
            )
            continue

        for item in issue_rows:
            status = item.get("status")
            if status == "ok":
                continue
            failure: dict[str, Any] = {
                "collector": collector_name,
                "item": item.get("name"),
                "status": status,
                "endpoint": item.get("endpoint"),
                "error_class": item.get("error_class"),
                "error": item.get("error"),
                "top": item.get("top"),
                "command_type": item.get("type"),
            }
            if item.get("type") == "command":
                failure["commands_required"] = optional_commands or [str(item.get("command"))] if item.get("command") else []
                failure["recommendations"] = {
                    "required_tools": sorted(set(command_tools)),
                    "notes": notes_detail,
                }
            elif item.get("type") == "graph":
                failure["recommendations"] = {
                    "required_graph_scopes": sorted(set(recommended_scopes)),
                    "recommended_roles": sorted(set(minimum_roles)),
                    "notes": notes_detail,
                }
            else:
                failure["recommendations"] = {
                    "notes": notes_detail,
                }
            failures.append(failure)

    return failures


def run_live(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    config = CollectorConfig.from_path(Path(args.config))
    permission_hints = _load_permission_hints(Path(args.permission_hints))
    selected_collector_names = parse_csv_list(args.collectors)
    exclude_collector_names = parse_csv_list(args.exclude)

    run_cfg = RunConfig(
        tenant_name=args.tenant_name,
        output_dir=out,
        collectors=selected_collector_names,
        excluded_collectors=exclude_collector_names,
        include_exchange=args.include_exchange,
        offline=args.offline,
        sample_path=Path(args.sample),
        run_name=args.run_name,
        top_items=args.top,
    )
    writer = AuditWriter(run_cfg.output_dir, run_cfg.tenant_name, run_name=run_cfg.run_name)

    if args.use_azure_cli_token:
        if not args.access_token:
            try:
                args.access_token = _acquire_azure_cli_access_token(args.tenant_id, log_event=writer.log_event)
                writer.log_event(
                    "auth.cli.token.selected",
                    "Using Azure CLI cached token for Graph authentication.",
                    {"tenant_id": args.tenant_id or "organizations"},
                )
                LOG.info("Using Azure CLI cached Graph token.")
            except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
                writer.log_event(
                    "auth.cli.token.rejected",
                    "Azure CLI token could not be used.",
                    {"tenant_id": args.tenant_id or "organizations", "error": str(exc)},
                )
                LOG.error("Unable to use Azure CLI token: %s", exc)
                return 2

    has_token_source = bool(args.access_token or args.use_azure_cli_token)
    if args.interactive and not args.client_id and not has_token_source:
        LOG.warning(
            "Interactive mode requested without --client-id. Falling back to Azure CLI token mode. "
            "Run `az login` first; this avoids creating an app registration."
        )
        args.interactive = False
        args.use_azure_cli_token = True
        has_token_source = True
    if not args.interactive and not has_token_source:
        if not args.client_id:
            LOG.error("client-id is required for app authentication.")
            return 2
        if not args.client_secret:
            LOG.error("client-id and client-secret are required for app auth. Use --interactive or --use-azure-cli-token.")
            return 2
        if not args.tenant_id:
            LOG.error("tenant-id is required for app authentication.")
            return 2
    if args.interactive and not args.tenant_id:
        args.tenant_id = "organizations"

    tenant_id = args.tenant_id or "organizations"

    auth_mode = "interactive" if args.interactive else "azure_cli" if args.use_azure_cli_token else "access_token" if args.access_token else "app"
    available = [name for name in config.default_order if config.collectors[name].enabled]
    if args.include_exchange and config.collectors.get("exchange"):
        if "exchange" not in available:
            available.append("exchange")
            available = sorted(set(available), key=lambda name: config.default_order.index(name))

    auditor_profile = _resolve_audit_profile(args.auditor_profile, auth_mode)
    selected_collector_names = _apply_profile_collector_defaults(
        selected_collector_names,
        auditor_profile,
        available,
    )
    run_cfg.collectors = selected_collector_names

    selected = run_cfg.selected_collectors(available)
    if not selected:
        LOG.error("No collectors selected.")
        return 2

    auth_scopes = parse_csv_list(args.scopes)
    if args.interactive and not auth_scopes:
        auth_scopes = sorted({perm for name in selected for perm in config.collectors[name].required_permissions})
    if args.interactive and not auth_scopes:
        auth_scopes = ["User.Read"]

    auth = AuthConfig(
        tenant_id=tenant_id,
        client_id=args.client_id,
        auth_mode=auth_mode,
        client_secret=args.client_secret,
        access_token=args.access_token,
        authority=args.authority,
        graph_scope=args.graph_scope,
        interactive_scopes=auth_scopes,
    )
    client = GraphClient(auth, audit_event=writer.log_event)
    session_context: dict[str, Any] = {}
    if auth_mode in {"azure_cli", "interactive"}:
        session_context = _capture_signed_in_context(client, log_event=writer.log_event)
    command_line = _scrub_command_line(list(sys.argv))
    writer.log_event(
        "run.started",
        "Live run started",
        {
            "tenant_id": args.tenant_id,
            "collectors": selected,
            "top": run_cfg.top_items,
            "include_exchange": args.include_exchange,
            "mode": auth_mode,
            "auditor_profile": auditor_profile,
            "session_context": session_context,
            "command_line": command_line,
        },
    )
    start = time.time()
    result_rows: list[dict[str, object]] = []
    failures = 0
    coverage_rows: list[dict[str, Any]] = []

    for name in selected:
        collector = REGISTRY.get(name)
        if collector is None:
            LOG.warning("Unknown collector requested: %s", name)
            continue
        if name == "exchange" and not args.include_exchange:
            continue

        try:
            writer.log_event("collector.started", "Collector started", {"collector": name})
            result: CollectorResult = collector.run(
                {"client": client, "top": run_cfg.top_items, "audit_logger": writer.log_event}
            )
            collector_coverage = result.coverage or []
            if collector_coverage:
                writer.write_index_records(collector_coverage)
                coverage_rows.extend(collector_coverage)
            writer.log_event(
                "collector.finished",
                "Collector finished",
                {
                    "collector": name,
                    "status": result.status,
                    "item_count": result.item_count,
                    "coverage_rows": len(collector_coverage),
                    "error": result.error,
                },
            )
            writer.write_raw(name, result.payload)
            status = result.status
            if result.status != "ok":
                failures += 1
            if result.error:
                LOG.warning("%s collector error: %s", name, result.error)
            result_rows.append(
                {
                    "name": result.name,
                    "status": status,
                    "item_count": result.item_count,
                    "message": result.message or ("ok" if status == "ok" else "partial"),
                    "error": result.error,
                    "coverage_rows": len(collector_coverage),
                }
            )
        except Exception as exc:  # noqa: BLE001
            failures += 1
            LOG.exception("Collector failed: %s", name)
            writer.log_event(
                "collector.failed",
                "Collector crashed",
                {"collector": name, "error": str(exc)},
            )
            result_rows.append(
                {
                    "name": name,
                    "status": "failed",
                    "item_count": 0,
                    "message": "collector crashed",
                    "error": str(exc),
                    "coverage_rows": 0,
                }
            )

    duration = round(time.time() - start, 2)
    for row in result_rows:
        writer.write_summary(row)
    diagnostics = _build_diagnostics(result_rows=result_rows, coverage_rows=coverage_rows, permission_hints=permission_hints)
    if diagnostics:
        writer.write_diagnostics(diagnostics)
        writer.log_event(
            "run.diagnostics.generated",
            "Failure diagnostics generated",
            {"count": len(diagnostics)},
        )
    writer.log_event(
        "run.complete",
        "Live run completed",
        {"failures": failures, "collectors": len(result_rows), "coverage_rows": len(coverage_rows)},
    )
    writer.write_bundle(
        {
            "executed_by": "azure_tenant_audit",
            "collectors": selected,
            "overall_status": "partial" if failures else "ok",
            "duration_seconds": duration,
            "mode": auth_mode,
            "auditor_profile": auditor_profile,
            "session_context": session_context,
            "command_line": command_line,
            "coverage_count": len(coverage_rows),
        }
    )
    LOG.info("Completed in %.2fs. Output in %s", duration, writer.run_dir)
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s: %(message)s")

    if args.env:
        load_env_file(Path(args.env))

    args.tenant_id = args.tenant_id or None
    args.client_id = args.client_id or None
    args.client_secret = args.client_secret or None
    args.access_token = args.access_token or None

    if args.tenant_id is None:
        args.tenant_id = __import__("os").environ.get("AZURE_TENANT_ID")
    if args.client_id is None:
        args.client_id = __import__("os").environ.get("AZURE_CLIENT_ID")
    if args.client_secret is None:
        args.client_secret = __import__("os").environ.get("AZURE_CLIENT_SECRET")
    if args.access_token is None:
        args.access_token = __import__("os").environ.get("AZURE_ACCESS_TOKEN")
    if args.authority is None:
        args.authority = __import__("os").environ.get("AZURE_AUTHORITY", args.authority)
    if args.graph_scope is None:
        args.graph_scope = __import__("os").environ.get("AZURE_GRAPH_SCOPE", args.graph_scope)
    if args.interactive and args.browser_command:
        os.environ["BROWSER"] = args.browser_command
    if args.scopes:
        args.scopes = args.scopes.strip()

    if args.offline:
        return run_offline(
            Path(args.sample),
            Path(args.out),
            args.tenant_name,
            args.run_name,
        )
    return run_live(args)


if __name__ == "__main__":
    raise SystemExit(main())
