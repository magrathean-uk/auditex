"""Guided demo of Auditex against a fictional, fully synthetic tenant.

`auditex demo` walks an operator (or a screen recording) through the audit
flow without contacting any tenant: plan read-only access, run the offline
collectors, read the risk summary, open one finding's evidence, follow the
attack path, then build and tamper-check a customer handoff pack.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, TextIO

from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.resources import resolve_resource_path

from .setup_guide import build_setup_guide

DEMO_SAMPLE = Path("examples/demo_tenant/demo_tenant.json")
FALLBACK_SAMPLE = Path("examples/sample_audit_bundle/known_bad_result.json")
REMEDIATED_SAMPLE = Path("examples/demo_tenant/demo_tenant_remediated.json")
DEMO_TENANT_NAME = "halcyon"
DEMO_RUN_NAME = "demo"
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEVERITY_COLOURS = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "37"}


@dataclass
class DemoOptions:
    out_dir: Path = Path("outputs/demo")
    sample: Path | None = None
    pause: bool = True
    html: bool = True
    stream: TextIO = field(default_factory=lambda: sys.stdout)
    input_fn: Callable[[str], str] = input


class _Console:
    def __init__(self, options: DemoOptions) -> None:
        self.stream = options.stream
        self.pause_enabled = options.pause and _is_tty(options.stream)
        self.colour = _is_tty(options.stream) and not os.environ.get("NO_COLOR")
        self.input_fn = options.input_fn
        self.step = 0

    def style(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.colour else text

    def line(self, text: str = "") -> None:
        print(text, file=self.stream)

    def heading(self, title: str) -> None:
        self.step += 1
        self.line()
        self.line(self.style(f"── Step {self.step}: {title} ", "1;36") + self.style("─" * max(4, 60 - len(title)), "36"))

    def severity(self, severity: str) -> str:
        label = f"{severity.upper():<8}"
        return self.style(label, _SEVERITY_COLOURS.get(severity, "0"))

    def pause(self) -> None:
        if self.pause_enabled:
            try:
                self.input_fn(self.style("\n  Press Enter to continue… ", "2"))
            except EOFError:
                self.pause_enabled = False


def _is_tty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def build_demo_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditex demo",
        description="Walk through Auditex on a fictional, synthetic tenant. No tenant is contacted.",
    )
    parser.add_argument("--out", default="outputs/demo", help="Folder for the demo run, pack and explorer (recreated).")
    parser.add_argument("--sample", default=None, help="Use another offline sample instead of the demo tenant.")
    parser.add_argument("--no-pause", action="store_true", help="Run every step without waiting for Enter.")
    parser.add_argument("--no-html", action="store_true", help="Skip writing the HTML explorer.")
    return parser


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _demo_sample(options: DemoOptions) -> Path:
    if options.sample is not None:
        return resolve_resource_path(options.sample)
    for candidate in (DEMO_SAMPLE, FALLBACK_SAMPLE):
        resolved = resolve_resource_path(candidate)
        if resolved.exists():
            return resolved
    return resolve_resource_path(DEMO_SAMPLE)


def _company_name(sample: dict[str, Any]) -> str:
    organizations = ((sample.get("identity") or {}).get("organization") or {}).get("value") or []
    for organization in organizations:
        if isinstance(organization, dict) and organization.get("displayName"):
            return str(organization["displayName"])
    return "a fictional demo tenant"


def _sorted_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def rank(item: dict[str, Any]) -> tuple[int, str]:
        severity = str(item.get("severity") or "info")
        return (SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER), str(item.get("id")))

    return sorted(findings, key=rank)


def _evidence_record(run_dir: Path, ref: dict[str, Any]) -> dict[str, Any] | None:
    artifact = run_dir / str(ref.get("artifact_path") or "")
    if not artifact.is_file():
        return None
    try:
        payload = _load_json(artifact)
    except (OSError, json.JSONDecodeError):
        return None
    records = payload.get("records") if isinstance(payload, dict) else payload
    if not isinstance(records, list):
        return None
    for record in records:
        if isinstance(record, dict) and record.get("key") == ref.get("record_key"):
            return record
    return None


def _compact(value: Any, limit: int = 96) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _step_plan(console: _Console) -> None:
    console.heading("Plan read-only access before asking an admin for anything")
    guide = build_setup_guide(provider="m365", collector_preset="full")
    permissions = guide.get("graph_permissions") or []
    writable = [name for name in permissions if "Write" in name]
    assertions = guide.get("provider_assertions") or {}
    console.line(f"  Collectors planned:      {len(guide.get('selected_collectors') or [])}")
    console.line(f"  Graph permissions:       {len(permissions)} ({len(writable)} with write access)")
    console.line(f"  Writes to the tenant:    {'no' if not assertions.get('production_writes') else 'YES'}")
    console.line(f"  Reads mail bodies:       {'no' if not assertions.get('mailbox_body_reads') else 'YES'}")
    console.line(f"  Reads file contents:     {'no' if not assertions.get('sharepoint_file_content_reads') else 'YES'}")
    console.line(console.style("  Full plan: auditex setup-guide m365 --collector-preset full --format md", "2"))
    console.pause()


def _step_run(console: _Console, sample_path: Path, sample: dict[str, Any], out_dir: Path) -> Path | None:
    console.heading("Collect evidence (offline replay, nothing leaves this machine)")
    collectors = [key for key in sample if not key.startswith("_")]
    rc = run_offline(sample_path, out_dir / "runs", DEMO_TENANT_NAME, DEMO_RUN_NAME, plane="full")
    run_dir = out_dir / "runs" / f"{DEMO_TENANT_NAME}-{DEMO_RUN_NAME}"
    if rc != 0 or not run_dir.is_dir():
        console.line(console.style(f"  Offline run failed (exit {rc}).", "31"))
        return None
    state = _load_json(run_dir / "checkpoints" / "checkpoint-state.json").get("collectors", {})
    for name in collectors:
        count = (state.get(name) or {}).get("item_count", 0)
        console.line(f"  {console.style('✔', '32')} {name:<22} {count:>4} records")
    validation = _load_json(run_dir / "validation.json")
    status = console.style("valid", "32") if validation.get("valid") else console.style("INVALID", "31")
    console.line(f"\n  Bundle contract: {status}   Run folder: {run_dir}")
    console.pause()
    return run_dir


def _step_summary(console: _Console, report_pack: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    console.heading("Read the risk summary")
    summary = report_pack.get("summary") or {}
    risk = summary.get("risk") or {}
    console.line(f"  Risk grade: {console.severity(str(risk.get('grade') or 'info')).strip()}   score {risk.get('score')}/100")
    counts = summary.get("severity_counts") or {}
    console.line("  " + "   ".join(f"{console.severity(level).strip()} {counts[level]}" for level in SEVERITY_ORDER if counts.get(level)))
    categories: dict[str, int] = {}
    for finding in findings:
        category = str(finding.get("category") or "other")
        categories[category] = categories.get(category, 0) + 1
    console.line()
    for category, count in sorted(categories.items(), key=lambda item: (-item[1], item[0])):
        console.line(f"  {category:<24} {'█' * count} {count}")
    console.line()
    for finding in _sorted_findings(findings)[:6]:
        mappings = finding.get("framework_mappings") or {}
        tags = ", ".join(
            f"{label} {mappings[key][0]}"
            for key, label in (("cis_m365_v7", "CIS"), ("cis_m365_v3", "CIS v3"), ("mitre_attack", "ATT&CK"))
            if mappings.get(key)
        )
        console.line(f"  {console.severity(str(finding.get('severity')))} {_compact(finding.get('title'), 64):<64} {console.style(tags, '2')}")
    console.pause()


def _step_evidence(console: _Console, run_dir: Path, report_pack: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    console.heading("Open one finding and its evidence")
    if not findings:
        console.line("  No findings in this run.")
        return
    finding = _sorted_findings(findings)[0]
    console.line(f"  {console.severity(str(finding.get('severity')))} {finding.get('title')}")
    console.line(f"  Rule:      {finding.get('rule_id')}")
    console.line(f"  Affected:  {_compact(finding.get('affected_objects'))}")
    if finding.get("impact"):
        console.line(f"  Impact:    {_compact(finding.get('impact'), 110)}")
    for ref in (finding.get("evidence_refs") or [])[:1]:
        console.line(f"  Evidence:  {ref.get('artifact_path')}  →  {ref.get('record_key')}")
        record = _evidence_record(run_dir, ref)
        if record:
            shown = [(key, value) for key, value in record.items() if key not in {"id", "key", "kind", "source"}]
            for key, value in shown[:7]:
                console.line(console.style(f"             {key}: {_compact(value, 80)}", "2"))
    proof = next((row for row in report_pack.get("proof_table") or [] if row.get("finding_id") == finding.get("id")), None)
    if proof:
        console.line(f"  Proof row: {proof.get('proof_status', 'supported')} · {proof.get('evidence_count')} evidence ref(s) · confidence {proof.get('confidence')}")
    if finding.get("remediation"):
        console.line(f"  Fix:       {_compact(finding.get('remediation'), 110)}")
    finding_ids = {item.get("id") for item in findings}
    supported = {
        row.get("finding_id")
        for row in report_pack.get("proof_table") or []
        if row.get("finding_id") in finding_ids and row.get("proof_status", "supported") == "supported"
    }
    console.line(console.style(f"\n  {len(supported)} of {len(findings)} findings have a supported proof row.", "1"))
    console.pause()


_BREAKPOINT_ACTIONS = {
    "owns": "remove {from_} as owner of {to}",
    "has_app_role": "revoke {to} from {from_}",
    "consented": "revoke the {to} consent granted to {from_}",
    "has_role": "remove {from_} from {to}",
    "member_of": "remove {from_} from group {to}",
    "no_mfa": "require MFA for {from_}",
}


def _breakpoint_action(breakpoints: list[dict[str, Any]]) -> str | None:
    for breakpoint in breakpoints:
        template = _BREAKPOINT_ACTIONS.get(str(breakpoint.get("edge")))
        if template and breakpoint.get("from") != breakpoint.get("to"):
            return template.format(from_=breakpoint.get("from"), to=breakpoint.get("to"))
    return None


def _step_attack_path(console: _Console, report_pack: dict[str, Any]) -> None:
    console.heading("Follow the attack path an intruder would take")
    paths = report_pack.get("attack_paths") or []
    if not paths:
        console.line("  No multi-stage attack path in this run.")
        console.pause()
        return
    for path in paths[:2]:
        hops = path.get("hops") or []
        if not hops:
            console.line(f"  {console.severity(str(path.get('severity')))} {' → '.join(path.get('chain') or [])}")
            for stage in path.get("findings") or []:
                console.line(f"     {stage.get('stage'):<18} {_compact(stage.get('title'), 70)}")
            continue
        console.line(f"  {console.severity(str(path.get('severity')))} {path.get('source')}  ⇒  {path.get('target')}")
        for hop in hops:
            technique = console.style(f"ATT&CK {hop.get('technique')}", "2") if hop.get("technique") else ""
            console.line(f"     {str(hop.get('edge')).replace('_', ' '):<16} {_compact(hop.get('from'), 34)} → {_compact(hop.get('to'), 40)}  {technique}")
        fix = _breakpoint_action(path.get("breakpoints") or [])
        if fix:
            console.line(console.style(f"     Break it: {fix}", "32"))
        console.line()
    console.pause()


_FRAMEWORK_LABELS = {
    "cis_m365_v7": "CIS M365 v7",
    "cisa_scuba": "CISA SCuBA v1.8",
    "ms_secure_score": "Microsoft Secure Score",
    "ms_zero_trust": "Microsoft Zero Trust",
    "mcsb": "MCSB v2 (preview)",
}


def _step_detection_and_baselines(console: _Console, report_pack: dict[str, Any]) -> None:
    detection = report_pack.get("detection_coverage") or {}
    alignment = report_pack.get("baseline_alignment") or {}
    if not detection.get("signals") and not alignment.get("frameworks"):
        return
    console.heading("Would anyone notice? Detection coverage and baselines")
    marks = {"on": console.style("on ", "32"), "off": console.style("OFF", "1;31"), "unknown": console.style("?  ", "2")}
    for signal in detection.get("signals") or []:
        console.line(f"  {marks.get(signal.get('status'), '   ')} {signal.get('title') or signal.get('name')}")
    if detection.get("signals"):
        console.line(console.style("  ? = not collected in this run, never counted as off", "2"))
    frameworks = alignment.get("frameworks") if isinstance(alignment.get("frameworks"), dict) else {}
    if frameworks:
        console.line()
        for key, framework in frameworks.items():
            counts = framework.get("status_counts") or {}
            name = _compact(_FRAMEWORK_LABELS.get(key) or f"{framework.get('title') or key} {framework.get('version') or ''}".strip(), 24)
            console.line(f"  {name:<24} {console.style(str(counts.get('fail', 0)) + ' fail', '31')}  {console.style(str(counts.get('pass', 0)) + ' pass', '32')}")
    overall = (alignment.get("secure_score") or {}).get("overall") or {}
    if overall:
        console.line(f"  Microsoft Secure Score: {overall.get('current_score')}/{overall.get('max_score')} ({overall.get('percentage')}%)")
    console.pause()


def _step_remediation(console: _Console, sample_path: Path, out_dir: Path, findings: list[dict[str, Any]], risk: dict[str, Any]) -> None:
    remediated_path = sample_path.with_name(REMEDIATED_SAMPLE.name)
    if sample_path.name != DEMO_SAMPLE.name or not remediated_path.is_file():
        return
    console.heading("Fix the worst issues, re-audit, and prove the change")
    remediated = _load_json(remediated_path)
    for change in (remediated.get("_fixture_provenance") or {}).get("remediations") or []:
        console.line(f"  {console.style('•', '32')} {change}")
    if run_offline(remediated_path, out_dir / "runs", DEMO_TENANT_NAME, "after-fixes", plane="full") != 0:
        console.line(console.style("  Re-audit failed.", "31"))
        return
    after_dir = out_dir / "runs" / f"{DEMO_TENANT_NAME}-after-fixes"
    after = _load_json(after_dir / "findings" / "findings.json")
    after_risk = (_load_json(after_dir / "reports" / "report-pack.json").get("summary") or {}).get("risk") or {}
    before_ids = {item.get("id") for item in findings}
    after_ids = {item.get("id") for item in after}
    resolved = [item for item in findings if item.get("id") not in after_ids]
    by_severity: dict[str, int] = {}
    for item in resolved:
        by_severity[str(item.get("severity"))] = by_severity.get(str(item.get("severity")), 0) + 1
    console.line()
    console.line(
        f"  Findings: {len(findings)} → {len(after)}   resolved {len(resolved)}"
        f" ({', '.join(f'{count} {severity}' for severity, count in sorted(by_severity.items(), key=lambda kv: SEVERITY_ORDER.index(kv[0]) if kv[0] in SEVERITY_ORDER else 9))})"
        f"   new {len(after_ids - before_ids)}"
    )
    console.line(
        f"  Risk:     {console.severity(str(risk.get('grade'))).strip()} {risk.get('score')}/100  →  "
        f"{console.severity(str(after_risk.get('grade'))).strip()} {after_risk.get('score')}/100"
    )
    console.line(console.style(f"  Full diff: auditex compare --format md --run-dir {out_dir / 'runs' / (DEMO_TENANT_NAME + '-' + DEMO_RUN_NAME)} --run-dir {after_dir}", "2"))
    console.pause()


def _step_handoff(console: _Console, run_dir: Path, out_dir: Path) -> None:
    from .reporting import verify_enterprise_handoff_pack, write_enterprise_handoff_pack

    console.heading("Hand over a tamper-evident customer pack")
    pack_dir = out_dir / "customer-pack"
    write_enterprise_handoff_pack(str(run_dir), str(pack_dir))
    verified = verify_enterprise_handoff_pack(str(pack_dir))
    console.line(f"  Pack written: {pack_dir}  ({verified.get('checked_file_count')} files checked)")
    console.line(f"  verify-pack:  {console.style('valid', '32') if verified.get('valid') else console.style('INVALID', '31')}")
    target = pack_dir / "handoff.md"
    if target.is_file():
        original = target.read_bytes()
        target.write_bytes(original + b"\nEdited after handover.\n")
        tampered = verify_enterprise_handoff_pack(str(pack_dir))
        codes = sorted({str(issue.get("code")) for issue in tampered.get("issues") or []})
        console.line(f"  Edit one line of handoff.md, verify again: {console.style('INVALID', '31')} ({', '.join(codes)})")
        target.write_bytes(original)
        restored = verify_enterprise_handoff_pack(str(pack_dir))
        console.line(f"  Restore the file, verify again: {console.style('valid', '32') if restored.get('valid') else 'INVALID'}")
    console.pause()


def _step_explorer(console: _Console, run_dir: Path, out_dir: Path) -> None:
    from .explorer import write_explorer

    console.heading("Explore the run in a browser")
    after_dir = out_dir / "runs" / f"{DEMO_TENANT_NAME}-after-fixes"
    runs = [run_dir, after_dir] if (after_dir / "run-manifest.json").is_file() else [run_dir]
    path = write_explorer(runs, out_dir / "explorer.html")
    console.line(f"  Open: {path.resolve().as_uri()}")
    console.line(console.style("  One self-contained HTML file: findings, evidence, attack paths, permissions. No network calls.", "2"))
    if len(runs) > 1:
        console.line(console.style("  Both runs are embedded: switch runs in the header, or open Before / after.", "2"))


def run_demo(options: DemoOptions) -> int:
    console = _Console(options)
    sample_path = _demo_sample(options)
    if not sample_path.exists():
        console.line(f"Demo sample not found: {sample_path}")
        return 2
    sample = _load_json(sample_path)
    provenance = sample.get("_fixture_provenance") or {}
    out_dir = options.out_dir
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    console.line(console.style("Auditex demo", "1"))
    console.line(f"Tenant: {_company_name(sample)}  ·  fixture {provenance.get('fixture_id', sample_path.name)}")
    console.line(console.style("All data is fictional and replayed offline. No Microsoft 365 tenant is contacted.", "33"))
    console.pause()

    _step_plan(console)
    run_dir = _step_run(console, sample_path, sample, out_dir)
    if run_dir is None:
        return 1
    report_pack = _load_json(run_dir / "reports" / "report-pack.json")
    findings = _load_json(run_dir / "findings" / "findings.json")
    _step_summary(console, report_pack, findings)
    _step_evidence(console, run_dir, report_pack, findings)
    _step_attack_path(console, report_pack)
    _step_detection_and_baselines(console, report_pack)
    _step_remediation(console, sample_path, out_dir, findings, (report_pack.get("summary") or {}).get("risk") or {})
    _step_handoff(console, run_dir, out_dir)
    if options.html:
        _step_explorer(console, run_dir, out_dir)

    console.line()
    console.line(console.style("Run it on your own tenant:", "1"))
    console.line("  auditex setup-guide m365 --collector-preset full --format md")
    console.line("  auditex probe live --tenant-name CONTOSO --tenant-id <tenant> --mode delegated --use-azure-cli-token")
    return 0


def main(argv: list[str]) -> int:
    args = build_demo_parser().parse_args(argv)
    return run_demo(
        DemoOptions(
            out_dir=Path(args.out),
            sample=Path(args.sample) if args.sample else None,
            pause=not args.no_pause,
            html=not args.no_html,
        )
    )
