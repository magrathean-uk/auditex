from __future__ import annotations

import argparse
import os
import platform
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from azure_tenant_audit import cli as tenant_cli
from azure_tenant_audit.profiles import profile_choices

from . import auth as auditex_auth
from .bootstrap import build_doctor_report, run_setup
from .operator_flow import flow_choices, flow_plan, guided_choice_options, resolve_auto_flow

REPORT_FORMAT_CHOICES = ("json", "md", "csv", "html", "sarif", "oscal")


def _default_browser_command() -> str:
    if platform.system() == "Darwin":
        return "safari"
    return os.environ.get("BROWSER") or "firefox"


def _prompt(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip()
    return value or (default or "")


def _confirm(label: str, default: bool = True) -> bool:
    default_hint = "Y/n" if default else "y/N"
    value = input(f"{label} [{default_hint}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes"}


def _prompt_choice(label: str, options: list[tuple[str, str]], default: str) -> str:
    print(label)
    for index, (_value, text) in enumerate(options, start=1):
        print(f"  {index}. {text}")
    default_index = next((index for index, (value, _text) in enumerate(options, start=1) if value == default), 1)
    raw = input(f"Choice [{default_index}]: ").strip()
    if not raw:
        return default
    if raw.isdigit():
        picked = int(raw)
        if 1 <= picked <= len(options):
            return options[picked - 1][0]
    for value, _text in options:
        if raw == value:
            return value
    return default


class ProgressRenderer:
    def __init__(self) -> None:
        self.collector_total = 0
        self.collector_done = 0

    def __call__(self, payload: dict[str, Any]) -> None:
        event = payload.get("event")
        details = payload.get("details") or {}
        if event == "preflight.started":
            print("Preflight: checking collector access")
            return
        if event == "preflight.collector.started":
            print(f"Preflight: {details.get('collector')}")
            return
        if event == "preflight.completed":
            print(
                "Preflight: "
                f"run {details.get('run_count', 0)}, "
                f"skip {details.get('skip_count', 0)}"
            )
            return
        if event == "run.started":
            self.collector_total = len(details.get("collectors") or [])
            self.collector_done = 0
            print(f"Run start: {self.collector_total} collectors")
            return
        if event == "collector.started":
            print(f"[{self.collector_done + 1}/{self.collector_total}] {details.get('collector')}")
            return
        if event == "collector.finished":
            self.collector_done += 1
            print(
                f"  {details.get('collector')}: "
                f"{details.get('status')} "
                f"items={details.get('item_count', 0)}"
            )
            return
        if event == "collector.failed":
            self.collector_done += 1
            print(f"  {details.get('collector')}: failed")
            return
        if event == "graph.request.retry":
            print(
                "  wait: "
                f"{details.get('reason') or 'retry'} "
                f"{details.get('backoff_seconds', details.get('retry_after_sec', 0))}s"
            )
            return
        if event == "run.diagnostics.generated":
            print(f"Diagnostics: {details.get('count', 0)}")
            return
        if event == "run.completed":
            print("Run complete")


def _run_azure_login(tenant_id: str, browser_command: str) -> int:
    env = os.environ.copy()
    env["BROWSER"] = browser_command
    return subprocess.run(
        ["az", "login", "--tenant", tenant_id, "--allow-no-subscriptions"],
        env=env,
        check=False,
    ).returncode


def _offer_m365_setup(tenant_id: str) -> int:
    print("Exchange needs m365 app setup")
    if not _confirm("Run one-time m365 setup now?", default=False):
        return 0
    setup_rc = subprocess.run(["m365", "setup"], check=False).returncode
    if setup_rc != 0:
        return setup_rc
    app_id = _prompt("m365 app id", default=os.environ.get("M365_CLI_APP_ID") or "")
    if app_id:
        auth_env = auditex_auth.default_local_auth_env_path()
        auth_env.parent.mkdir(parents=True, exist_ok=True)
        existing = auth_env.read_text(encoding="utf-8") if auth_env.exists() else ""
        lines = [line for line in existing.splitlines() if not line.startswith("M365_CLI_APP_ID=")]
        lines.append(f"M365_CLI_APP_ID={app_id}")
        auth_env.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
        os.environ["M365_CLI_APP_ID"] = app_id
    return 0


def _saved_value(*keys: str) -> str | None:
    for key in keys:
        value = os.environ.get(key)
        if value:
            return value
    return None


def _default_tenant_name(tenant_id: str | None) -> str:
    if not tenant_id or tenant_id == "organizations":
        return "TENANT"
    token = tenant_id.split(".")[0].strip()
    return token.upper() if token else "TENANT"


def _resolve_flow(args: argparse.Namespace) -> str:
    if args.flow != "auto":
        return args.flow
    auto_flow = resolve_auto_flow(auth_mode=args.auth_mode, non_interactive=args.non_interactive)
    if auto_flow:
        return auto_flow
    return _prompt_choice(
        "Flow",
        list(guided_choice_options()),
        default="gr-audit",
    )


def _persist_local_defaults(
    *,
    tenant_id: str,
    tenant_name: str,
    app_id: str | None = None,
    client_secret: str | None = None,
    connection_name: str | None = None,
) -> None:
    values: dict[str, str | None] = {
        "AUDITEX_TENANT_ID": tenant_id,
        "AUDITEX_TENANT_NAME": tenant_name,
        "AZURE_TENANT_ID": tenant_id,
    }
    if app_id:
        values["M365_CLI_APP_ID"] = app_id
        values["M365_CLI_CLIENT_ID"] = app_id
        values["AZURE_CLIENT_ID"] = app_id
    if client_secret:
        values["AZURE_CLIENT_SECRET"] = client_secret
    if connection_name:
        values["AUDITEX_M365_CONNECTION_NAME"] = connection_name
    auditex_auth.save_local_auth_values(values)


def _run_m365_setup() -> int:
    return subprocess.run(["m365", "setup"], check=False).returncode


def _current_m365_state() -> dict[str, Any]:
    try:
        payload = auditex_auth.get_auth_status(include_azure_cli=False, include_exchange=False)
    except TypeError:
        payload = auditex_auth.get_auth_status()
    return (payload.get("m365") or {}) if isinstance(payload, dict) else {}


def _tenant_matches(observed: str | None, expected: str) -> bool:
    if not observed or expected == "organizations":
        return True
    left = observed.strip().lower()
    right = expected.strip().lower()
    return left == right or left.endswith(f".{right}") or right.endswith(f".{left}")


def _ensure_exchange_module(*, non_interactive: bool) -> int:
    exchange = auditex_auth.get_auth_status().get("exchange") or {}
    if exchange.get("status") == "supported":
        return 0
    print("Exchange PowerShell module missing")
    if not non_interactive and not _confirm("Install ExchangeOnlineManagement now?", default=True):
        return 2
    return auditex_auth.ensure_exchange_online_module()


def _ensure_m365_login(
    tenant_id: str,
    browser_command: str,
    *,
    auth_mode: str = "delegated",
    client_id: str | None = None,
    client_secret: str | None = None,
) -> int:
    status = auditex_auth.get_auth_status().get("m365") or {}
    required_auth_type = "secret" if auth_mode == "app" else "browser"
    if (
        status.get("status") == "supported"
        and status.get("active_connection")
        and status.get("authenticated")
        and status.get("auth_type") == required_auth_type
        and _tenant_matches(str(status.get("tenant_id") or ""), tenant_id)
    ):
        return 0
    if auth_mode == "app":
        effective_app_id = client_id or os.environ.get("M365_CLI_APP_ID") or os.environ.get("M365_CLI_CLIENT_ID")
        if not effective_app_id or not client_secret:
            return 2
        rc = auditex_auth.login_connection(
            mode="app",
            tenant_id=tenant_id,
            connection_name=f"auditex-app-{effective_app_id[:8]}",
            app_id=effective_app_id,
            client_secret=client_secret,
        )
        if rc != 0:
            return rc
        refreshed = auditex_auth.get_auth_status().get("m365") or {}
        if (
            refreshed.get("status") != "supported"
            or not refreshed.get("active_connection")
            or not refreshed.get("authenticated")
            or refreshed.get("auth_type") != "secret"
            or not _tenant_matches(str(refreshed.get("tenant_id") or ""), tenant_id)
        ):
            return 5
        return 0
    app_id = os.environ.get("M365_CLI_APP_ID") or os.environ.get("M365_CLI_CLIENT_ID")
    if not app_id:
        setup_rc = _offer_m365_setup(tenant_id)
        if setup_rc != 0:
            return setup_rc
        app_id = os.environ.get("M365_CLI_APP_ID") or os.environ.get("M365_CLI_CLIENT_ID")
    command = [
        "m365",
        "login",
        "--authType",
        "browser",
        "--tenant",
        tenant_id,
    ]
    if app_id:
        command.extend(["--appId", app_id])
    env = os.environ.copy()
    env["BROWSER"] = browser_command
    rc = subprocess.run(command, env=env, check=False).returncode
    if rc != 0:
        return rc
    refreshed = auditex_auth.get_auth_status().get("m365") or {}
    if (
        refreshed.get("status") != "supported"
        or not refreshed.get("active_connection")
        or not refreshed.get("authenticated")
        or not _tenant_matches(str(refreshed.get("tenant_id") or ""), tenant_id)
    ):
        return 5
    return 0


def build_guided_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditex guided-run", description="Interactive guided tenant audit.")
    parser.add_argument("--flow", choices=flow_choices(), default="auto")
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--tenant-name", default=None)
    parser.add_argument("--auth-mode", choices=("delegated", "app"), default="delegated")
    parser.add_argument("--client-id", default=None)
    parser.add_argument("--client-secret", default=None)
    parser.add_argument("--auditor-profile", default="global-reader", choices=profile_choices())
    parser.add_argument("--out", default="outputs/guided")
    parser.add_argument("--run-name", default=None)
    parser.add_argument("--top", type=int, default=500)
    parser.add_argument("--page-size", type=int, default=50)
    parser.add_argument("--browser-command", default=None)
    parser.add_argument("--collectors", default=None)
    parser.add_argument("--include-exchange", action="store_true")
    parser.add_argument("--throttle-mode", choices=("fast", "safe", "ultra-safe"), default="safe")
    parser.add_argument("--include-blocked", action="store_true")
    parser.add_argument("--with-mcp", action="store_true")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--local-mode", action="store_true")
    parser.add_argument("--skip-login-check", action="store_true")
    parser.add_argument("--skip-tool-check", action="store_true")
    parser.add_argument("--report-format", choices=REPORT_FORMAT_CHOICES, default=None)
    parser.add_argument("--probe-first", dest="probe_first", action="store_true", default=True)
    parser.add_argument("--no-probe-first", dest="probe_first", action="store_false")
    return parser


def _run_ga_setup_flow(
    *,
    args: argparse.Namespace,
    tenant_id: str,
    tenant_name: str,
    browser_command: str,
) -> int:
    doctor = build_doctor_report(
        auth_mode="delegated",
        include_exchange=True,
        include_auth_checks=not args.skip_login_check,
    )
    needs_setup = not args.skip_tool_check and (
        not doctor.get("readiness", {}).get("core_ready") or not doctor.get("readiness", {}).get("exchange_ready")
    )
    if needs_setup:
        print("Local tools missing")
        if args.non_interactive or _confirm("Run setup now?", default=True):
            setup_rc = run_setup(with_exchange=True, with_pwsh=True, with_mcp=args.with_mcp)
            if setup_rc != 0:
                return setup_rc
        else:
            return 2

    azure_state = (doctor.get("auth") or {}).get("azure_cli") or {}
    azure_supported = azure_state.get("status") == "supported" and _tenant_matches(
        str(azure_state.get("tenant_id") or ""), tenant_id
    )
    if not args.local_mode and not args.skip_login_check and not azure_supported:
        print("Azure login needed")
        login_rc = _run_azure_login(tenant_id, browser_command)
        if login_rc != 0:
            return login_rc

    module_rc = _ensure_exchange_module(non_interactive=args.non_interactive)
    if module_rc != 0:
        return module_rc

    print("Run one-time m365 setup")
    setup_rc = _run_m365_setup()
    if setup_rc != 0:
        return setup_rc

    app_id = args.client_id or _saved_value("M365_CLI_APP_ID", "M365_CLI_CLIENT_ID", "AZURE_CLIENT_ID")
    client_secret = args.client_secret or _saved_value("AZURE_CLIENT_SECRET")
    if not args.non_interactive:
        app_id = _prompt("App id to save", default=app_id or "")
        if not client_secret and _confirm("Save app secret for later app runs?", default=False):
            client_secret = _prompt("App secret")
    if not app_id:
        print("App id missing")
        return 2

    _persist_local_defaults(
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        app_id=app_id,
        client_secret=client_secret,
    )

    verify_rc = _ensure_m365_login(
        tenant_id,
        browser_command,
        auth_mode="delegated",
        client_id=app_id,
    )
    if verify_rc != 0:
        print("m365 login failed")
        return verify_rc

    m365_state = _current_m365_state()
    _persist_local_defaults(
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        app_id=app_id,
        client_secret=client_secret,
        connection_name=str(m365_state.get("active_connection") or "") or None,
    )
    print("App saved")
    return 0


def run_guided(args: argparse.Namespace) -> int:
    flow = _resolve_flow(args)
    plan = flow_plan(flow)
    auth_mode = plan.auth_mode
    print("Auditex guided run")

    tenant_id = args.tenant_id or _saved_value("AUDITEX_TENANT_ID", "AZURE_TENANT_ID")
    tenant_name = args.tenant_name or _saved_value("AUDITEX_TENANT_NAME")
    browser_command = args.browser_command or _default_browser_command()
    include_exchange = args.include_exchange or plan.include_exchange
    client_id = args.client_id or _saved_value("AZURE_CLIENT_ID", "M365_CLI_APP_ID", "M365_CLI_CLIENT_ID")
    client_secret = args.client_secret or _saved_value("AZURE_CLIENT_SECRET")

    if not args.non_interactive:
        tenant_default = tenant_id or plan.tenant_default
        tenant_id = tenant_id or _prompt("Tenant id or domain", default=tenant_default)
        tenant_name = tenant_name or _prompt("Tenant label", default=_default_tenant_name(tenant_id))
        if plan.requires_app_credentials:
            client_id = client_id or _prompt("Client id")
            client_secret = client_secret or _prompt("Client secret")
        if flow == "gr-audit" and not args.include_exchange:
            include_exchange = _confirm("Include Exchange checks?", default=False)
    else:
        tenant_id = tenant_id or plan.tenant_default
        tenant_name = tenant_name or _default_tenant_name(tenant_id)
    if plan.requires_real_tenant and (not tenant_id or tenant_id == "organizations"):
        print("Real tenant id or domain needed")
        return 2
    if plan.requires_app_credentials and (not client_id or not client_secret):
        print("App credentials missing")
        return 2
    if flow == "ga-setup-app":
        return _run_ga_setup_flow(
            args=args,
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            browser_command=browser_command,
        )

    doctor = build_doctor_report(
        auth_mode=auth_mode,
        include_exchange=include_exchange,
        include_auth_checks=not args.skip_login_check,
    )
    print(f"Machine: {doctor['system']['os']} {doctor['system']['machine']}")

    needs_setup = not args.skip_tool_check and not doctor.get("readiness", {}).get("core_ready")
    if include_exchange and not doctor.get("readiness", {}).get("exchange_ready"):
        needs_setup = not args.skip_tool_check
    if needs_setup:
        print("Local tools missing")
        if args.non_interactive or _confirm("Run setup now?", default=True):
            setup_kwargs: dict[str, bool] = {"with_mcp": args.with_mcp}
            if include_exchange:
                setup_kwargs["with_exchange"] = True
                setup_kwargs["with_pwsh"] = True
            setup_rc = run_setup(**setup_kwargs)
            if setup_rc != 0:
                return setup_rc
            doctor = build_doctor_report(
                auth_mode=args.auth_mode,
                include_exchange=include_exchange,
                include_auth_checks=not args.skip_login_check,
            )
        else:
            return 2

    azure_state = (doctor.get("auth") or {}).get("azure_cli") or {}
    azure_supported = (
        azure_state.get("status") == "supported"
        and _tenant_matches(str(azure_state.get("tenant_id") or ""), tenant_id)
    )
    if auth_mode == "delegated" and not args.local_mode and not args.skip_login_check and not azure_supported:
        print("Azure login needed")
        login_rc = _run_azure_login(tenant_id, browser_command)
        if login_rc != 0:
            return login_rc

    if include_exchange and not args.local_mode and not args.skip_login_check:
        module_rc = _ensure_exchange_module(non_interactive=args.non_interactive)
        if module_rc != 0:
            return module_rc
        m365_rc = _ensure_m365_login(
            tenant_id,
            browser_command,
            auth_mode=auth_mode,
            client_id=client_id,
            client_secret=client_secret,
        )
        if m365_rc != 0:
            print("Exchange login failed")
            return m365_rc

    argv = [
        "--tenant-name",
        tenant_name,
        "--tenant-id",
        tenant_id,
        "--auditor-profile",
        args.auditor_profile,
        "--out",
        args.out,
        "--top",
        str(args.top),
        "--page-size",
        str(args.page_size),
        "--throttle-mode",
        args.throttle_mode,
    ]
    if auth_mode == "delegated":
        argv.append("--use-azure-cli-token")
    else:
        argv.extend(["--client-id", client_id, "--client-secret", client_secret])
    if args.run_name:
        argv.extend(["--run-name", args.run_name])
    if args.collectors:
        argv.extend(["--collectors", args.collectors])
    if include_exchange:
        argv.append("--include-exchange")
    if args.probe_first:
        argv.append("--probe-first")
    else:
        argv.append("--no-probe-first")
    if args.include_blocked:
        argv.append("--include-blocked")

    renderer = ProgressRenderer()
    started = time.time()
    rc = tenant_cli.main(argv, event_listener=renderer)
    duration = round(time.time() - started, 2)
    print(f"Done in {duration}s")
    if include_exchange:
        m365_state = _current_m365_state()
        _persist_local_defaults(
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            app_id=client_id if auth_mode == "app" else str(m365_state.get("app_id") or "") or None,
            client_secret=client_secret if auth_mode == "app" else None,
            connection_name=str(m365_state.get("active_connection") or "") or None,
        )
    else:
        _persist_local_defaults(tenant_id=tenant_id, tenant_name=tenant_name)
    if args.report_format:
        from .reporting import render_report

        latest = sorted(Path(args.out).expanduser().resolve().glob(f"{tenant_name}-*"))
        if latest:
            render_report(run_dir=str(latest[-1]), format_name=args.report_format)
    return rc
