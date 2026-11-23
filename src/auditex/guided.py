from __future__ import annotations

import argparse
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any

from azure_tenant_audit import cli as tenant_cli
from azure_tenant_audit.output_redaction import PROFILE_LOCAL
from azure_tenant_audit.profiles import get_profile, profile_choices
from azure_tenant_audit.secret_hygiene import build_argument_parser

from .bootstrap import build_doctor_report, run_setup
from .operator_flow import flow_choices, flow_plan

REPORT_FORMAT_CHOICES = ("json", "md", "csv", "html", "sarif", "oscal")
# Where the tenant administrator finds every permission, role and setting the reader app needs (DEC-107).
READER_APP_GUIDE = "docs/guides/reader-app-permissions.md"
# Collectors that run through PowerShell 7 and ExchangeOnlineManagement; only these need the Exchange tools.
POWERSHELL_COLLECTORS = frozenset({"exchange_policy", "targeted_users_coverage"})


def _read_prompt(prompt: str) -> str:
    from azure_tenant_audit.guarded_io import read_guarded_stdin
    print(prompt, end="", flush=True)
    return read_guarded_stdin(line=True)


def _prompt(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = _read_prompt(f"{label}{suffix}: ").strip()
    return value or (default or "")


def _confirm(label: str, default: bool = True) -> bool:
    default_hint = "Y/n" if default else "y/N"
    value = _read_prompt(f"{label} [{default_hint}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes"}


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


def _certificate_argv(args: argparse.Namespace) -> list[str]:
    """Pass the certificate options through to the engine unchanged; it loads and checks the key."""
    argv: list[str] = []
    for flag in ("--certificate-path", "--certificate-thumbprint", "--certificate-password-env", "--certificate-password-file"):
        value = getattr(args, flag[2:].replace("-", "_"), None)
        if value:
            argv.extend([flag, str(value)])
    return argv


def _selected_collectors(args: argparse.Namespace) -> set[str]:
    # The same order the engine uses: --collectors, else AUDIT_COLLECTORS, else the profile's defaults.
    chosen = args.collectors or (os.environ.get("AUDIT_COLLECTORS") or "").strip()
    if chosen:
        return {name.strip() for name in str(chosen).split(",") if name.strip()}
    return set(get_profile(args.auditor_profile).default_collectors)


def _missing_tools(readiness: dict[str, Any], *, needs_exchange: bool) -> list[str]:
    missing = [*(readiness.get("core_missing") or ([] if readiness.get("core_ready") else ["core"]))]
    if needs_exchange and not readiness.get("exchange_ready"):
        missing.extend(name for name in (readiness.get("exchange_missing") or ["exchange_online_module"])
                       if name not in missing)
    return missing


def _ensure_local_tools(args: argparse.Namespace, readiness: dict[str, Any]) -> int:
    """Check the local tools this run needs; install them only on an explicit request (prompt or --install-tools)."""
    needs_exchange = bool(_selected_collectors(args) & POWERSHELL_COLLECTORS)
    missing = _missing_tools(readiness, needs_exchange=needs_exchange)
    if not missing:
        return 0
    print(f"Local tools missing: {', '.join(missing)}")
    if args.install_tools:
        install = True
    elif args.non_interactive:
        print("Not installing in a non-interactive run. Run auditex setup, pass --install-tools to install them, "
              "or --skip-tool-check to run without them.")
        return 2
    else:
        install = _confirm("Run setup now?", default=True)
    if not install:
        return 2
    setup_kwargs: dict[str, bool] = {"with_mcp": args.with_mcp}
    if needs_exchange and not readiness.get("exchange_ready"):
        setup_kwargs["with_exchange"] = True
        setup_kwargs["with_pwsh"] = True
    rc = run_setup(**setup_kwargs)
    if rc != 0:
        return rc
    # Setup can succeed without installing anything (an installed package only prints the manual steps), so check
    # again and never start the engine without the tools this run needs.
    still_missing = _missing_tools(build_doctor_report().get("readiness") or {}, needs_exchange=needs_exchange)
    if still_missing:
        print(f"Local tools still missing after setup: {', '.join(still_missing)}. Install them and run auditex doctor, "
              "or pass --skip-tool-check to run without them.")
        return 2
    return 0


def _run_folder_marks(base: Path) -> dict[str, tuple[Path, tuple[int, ...]]]:
    """Run folders under ``base`` keyed by real path, with the identity of their ``run-manifest.json``."""
    marks: dict[str, tuple[Path, tuple[int, ...]]] = {}
    try:
        children = sorted(entry for entry in base.iterdir() if entry.is_dir() and not entry.is_symlink())
    except OSError:
        return marks
    for folder in children:
        try:
            info = (folder / "run-manifest.json").lstat()
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode):
            marks[os.path.realpath(folder)] = (folder, (info.st_dev, info.st_ino, info.st_size,
                                                        info.st_mtime_ns, info.st_ctime_ns))
    return marks


def build_guided_parser() -> argparse.ArgumentParser:
    parser = build_argument_parser(allow_abbrev=False, prog="auditex guided-run", description="Interactive guided tenant audit.")
    parser.add_argument("--flow", choices=flow_choices(), default="auto")
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--tenant-name", default=None)
    parser.add_argument("--client-id", default=None, help="The reader app's application (client) ID (else AZURE_CLIENT_ID).")
    parser.add_argument("--certificate-path", default=None, metavar="FILE",
                        help="The reader app's certificate private key file (PEM or PFX, owner-only).")
    parser.add_argument("--certificate-thumbprint", default=None, metavar="SHA1",
                        help="SHA-1 thumbprint of the certificate on the app registration.")
    certificate_password = parser.add_mutually_exclusive_group()
    certificate_password.add_argument("--certificate-password-env", default=None, metavar="NAME",
                                      help="Name of the environment variable holding the key password.")
    certificate_password.add_argument("--certificate-password-file", default=None, metavar="FILE",
                                      help="Owner-only file holding the key password.")
    parser.add_argument("--auditor-profile", default="global-reader", choices=profile_choices())
    parser.add_argument("--out", default="outputs/guided")
    parser.add_argument("--run-name", default=None)
    parser.add_argument("--sensitive-users", metavar="FILE", help="Local sensitive-user list (else AUDITEX_SENSITIVE_USERS_FILE).")
    parser.add_argument("--partner-domains", metavar="FILE", help="Local partner-domain list (else AUDITEX_PARTNER_DOMAINS_FILE).")
    parser.add_argument("--top", type=int, default=None, help=(
        "Explicit per-list row limit; without it lists are paged to the last row, except identity.users, "
        "which stops at 250,000 users with a pagination_not_followed gap if more remain (also with --top 0 "
        "or a larger --top)."
    ))
    parser.add_argument("--page-size", type=int, default=50)
    parser.add_argument("--collectors", default=None)
    parser.add_argument("--doh-endpoint", default=None, metavar="URL",
                        help="DNS-over-HTTPS resolver for dns_posture (else AUDITEX_DOH_ENDPOINT, else Cloudflare).")
    parser.add_argument("--throttle-mode", choices=("fast", "safe", "ultra-safe"), default="safe")
    parser.add_argument("--include-blocked", action="store_true")
    parser.add_argument("--with-mcp", action="store_true")
    parser.add_argument("--non-interactive", action="store_true",
                        help="Never prompt; missing local tools stop the run unless --install-tools is given.")
    parser.add_argument("--skip-tool-check", action="store_true")
    parser.add_argument("--install-tools", action="store_true", help=(
        "Install missing local tools without asking (scripts/bootstrap-local-tools.sh: may use sudo with the "
        "system package manager and install ExchangeOnlineManagement from PSGallery)."
    ))
    parser.add_argument("--report-format", choices=REPORT_FORMAT_CHOICES, default=None)
    parser.add_argument("--probe-first", dest="probe_first", action="store_true", default=True)
    parser.add_argument("--no-probe-first", dest="probe_first", action="store_false")
    return parser


def run_guided(args: argparse.Namespace) -> int:
    from azure_tenant_audit.partner_domains import (
        PartnerDomainsError,
        load_partner_domains,
    )
    from azure_tenant_audit.sensitive_users import (
        SensitiveUsersError,
        load_sensitive_users,
    )

    try:
        sensitive_users = load_sensitive_users(getattr(args, "sensitive_users", None))
        partner_domains = load_partner_domains(getattr(args, "partner_domains", None))
    except (SensitiveUsersError, PartnerDomainsError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    plan = flow_plan(args.flow)
    print("Auditex guided run: reader app with a certificate")

    tenant_id = args.tenant_id or _saved_value("AZURE_TENANT_ID")
    tenant_name = args.tenant_name
    client_id = args.client_id or _saved_value("AZURE_CLIENT_ID")
    certificate_path = args.certificate_path
    certificate_thumbprint = args.certificate_thumbprint

    if not args.non_interactive:
        tenant_id = tenant_id or _prompt("Tenant id or domain")
        tenant_name = tenant_name or _prompt("Tenant label", default=_default_tenant_name(tenant_id))
        client_id = client_id or _prompt("Reader app client id")
        certificate_path = certificate_path or _prompt("Certificate private key file")
        certificate_thumbprint = certificate_thumbprint or _prompt("Certificate thumbprint")
    else:
        tenant_name = tenant_name or _default_tenant_name(tenant_id)
    if plan.requires_real_tenant and (not tenant_id or tenant_id == "organizations"):
        print("Real tenant id or domain needed")
        return 2
    if not client_id or not certificate_path or not certificate_thumbprint:
        print(
            "The reader app's client id, certificate key file and thumbprint are needed "
            f"(--client-id, --certificate-path, --certificate-thumbprint); see {READER_APP_GUIDE}"
        )
        return 2
    args.certificate_path = certificate_path
    args.certificate_thumbprint = certificate_thumbprint

    doctor = build_doctor_report()
    print(f"Machine: {doctor['system']['os']} {doctor['system']['machine']}")
    if not args.skip_tool_check:
        tool_rc = _ensure_local_tools(args, doctor.get("readiness") or {})
        if tool_rc != 0:
            return tool_rc

    argv = [
        "--tenant-name",
        tenant_name,
        "--tenant-id",
        tenant_id,
        "--auditor-profile",
        args.auditor_profile,
        "--out",
        args.out,
        "--page-size",
        str(args.page_size),
        "--throttle-mode",
        args.throttle_mode,
    ]
    if args.top:
        argv.extend(["--top", str(args.top)])
    argv.extend(["--client-id", client_id, *_certificate_argv(args)])
    if args.run_name:
        argv.extend(["--run-name", args.run_name])
    if args.collectors:
        argv.extend(["--collectors", args.collectors])
    if args.doh_endpoint:
        argv.extend(["--doh-endpoint", args.doh_endpoint])
    argv.append("--probe-first" if args.probe_first else "--no-probe-first")
    if args.include_blocked:
        argv.append("--include-blocked")

    renderer = ProgressRenderer()
    started = time.time()
    input_kwargs = {"sensitive_users": sensitive_users} if sensitive_users.addresses else {}
    if partner_domains.domains:
        input_kwargs["partner_domains"] = partner_domains
    out_dir = Path(args.out).expanduser()
    before = _run_folder_marks(out_dir)
    rc = tenant_cli.main(argv, event_listener=renderer, **input_kwargs)
    duration = round(time.time() - started, 2)
    print(f"Done in {duration}s")
    if args.report_format and rc in (0, 1):  # 1 is a partial run: it still wrote a bundle
        from .reporting import render_report

        after = _run_folder_marks(out_dir)
        written = [folder for key, (folder, mark) in sorted(after.items()) if before.get(key, (None, None))[1] != mark]
        if len(written) == 1:
            render_report(run_dir=str(written[0]), format_name=args.report_format, profile=PROFILE_LOCAL)
            print(f"Report: {written[0]}")
        else:
            print("Could not tell which run folder this run wrote; render it with auditex report render <run folder>.")
    return rc
