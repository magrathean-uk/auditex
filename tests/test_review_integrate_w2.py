"""Review lane integrate-w2: the cross-lane changes the wave-2 lanes could not make in their own files."""
from __future__ import annotations

import subprocess
from pathlib import Path


def _timeout_run(command, **kwargs):  # noqa: ANN001
    assert kwargs.get("timeout"), "readiness subprocess must carry a timeout"
    raise subprocess.TimeoutExpired(command, kwargs["timeout"])


# R162: auditex doctor's readiness commands always return.
def test_r162_doctor_exchange_check_times_out_to_blocked(monkeypatch) -> None:  # noqa: ANN001
    from auditex import auth_runtime

    monkeypatch.setattr(auth_runtime.shutil, "which", lambda name: "/usr/bin/pwsh")
    monkeypatch.setattr(auth_runtime.subprocess, "run", _timeout_run)

    status = auth_runtime.exchange_module_status()

    assert status["status"] == "blocked" and status["error_class"] == "command_timeout"


def test_r162_default_json_command_times_out_to_blocked(monkeypatch) -> None:  # noqa: ANN001
    from auditex import auth_runtime

    monkeypatch.setattr(auth_runtime.subprocess, "run", _timeout_run)

    result = auth_runtime._default_run_json_command(["pwsh", "--version"])

    assert result["status"] == "blocked" and result["error"] == "command_timeout"


# R123 sibling (impact of the setup-guided-cli lane): an engine run with a mistyped --permission-hints stops, as
# setup-guide does, instead of losing every permission hint without a word.
def test_r123_engine_missing_explicit_permission_hints_is_an_error(tmp_path) -> None:  # noqa: ANN001
    import pytest

    from azure_tenant_audit.diagnostics import load_permission_hints

    assert load_permission_hints(Path("configs/collector-permissions.json"))
    with pytest.raises(FileNotFoundError, match="--permission-hints file was not found"):
        load_permission_hints(tmp_path / "collector-permision.json")


def test_r123_engine_run_with_a_missing_permission_hints_file_exits_2(monkeypatch, tmp_path, caplog) -> None:  # noqa: ANN001
    from support import FAKE_CERTIFICATE_ARGS, use_fake_certificate

    from azure_tenant_audit import cli

    use_fake_certificate(monkeypatch)
    ran: list[str] = []

    class _Collector:
        name = "identity"

        def run(self, context):  # noqa: ANN001
            ran.append("identity")
            raise AssertionError("no collector may run without the permission hints the operator named")

    monkeypatch.setattr(cli, "REGISTRY", {"identity": _Collector()})
    args = cli.build_parser().parse_args([
        "--tenant-name", "acme", "--tenant-id", "contoso.onmicrosoft.com", "--client-id", "app-id",
        *FAKE_CERTIFICATE_ARGS, "--collectors", "identity", "--no-probe-first", "--out", str(tmp_path / "out"),
        "--permission-hints", str(tmp_path / "collector-permision.json"),
    ])

    with caplog.at_level("ERROR"):
        rc = cli.run_live(args)

    assert rc == 2
    assert ran == []
    assert "--permission-hints file was not found" in caplog.text


# R126 (CLI half): report render and export run refuse an unknown section with exit 2 and the valid ids, not a
# traceback.
def _section_run(tmp_path: Path) -> Path:
    from test_review_reporting_exports_disclosure import APP_FINDING, _write_run

    return _write_run(tmp_path / "run-a", [dict(APP_FINDING)])


def test_r126_report_render_refuses_an_unknown_section_with_exit_2(tmp_path, capsys) -> None:  # noqa: ANN001
    from auditex.cli import main

    run = _section_run(tmp_path)
    output = tmp_path / "report.md"

    rc = main(["report", "render", str(run), "--format", "md", "--exclude-section", "normalised",
               "--output", str(output)])

    err = capsys.readouterr().err
    assert rc == 2
    assert "normalised" in err and "Valid sections:" in err and "normalized" in err
    assert "Traceback" not in err
    assert not output.exists()


def test_r126_export_run_refuses_an_unknown_section_with_exit_2(tmp_path, capsys) -> None:  # noqa: ANN001
    from auditex.cli import main

    run = _section_run(tmp_path)
    output = tmp_path / "x.html"

    rc = main(["export", "run", "html", str(run), "--include-section", "sumary", "--output", str(output)])

    err = capsys.readouterr().err
    assert rc == 2
    assert "sumary" in err and "Valid sections:" in err
    assert not output.exists()


# R083 (console half): a Google run shows its DNS notice on the console before collection, as the M365 run does.
def test_r083_google_run_prints_its_dns_notice_before_collection(tmp_path, monkeypatch, capsys) -> None:  # noqa: ANN001
    from test_review_google_workspace_dns import _fake_dns_run

    from auditex.google_workspace.run import GoogleRunConfig, run_google_live
    from azure_tenant_audit.dns_lookup import DEFAULT_DOH_ENDPOINT, DOH_ENDPOINT_ENV

    monkeypatch.delenv(DOH_ENDPOINT_ENV, raising=False)
    contexts = _fake_dns_run(monkeypatch)

    run_google_live(GoogleRunConfig(tenant_name="Example", out=tmp_path, run_name="dns", collectors="google_dns_posture"))

    captured = capsys.readouterr()
    assert contexts, "the DNS collector ran"
    notices = [line for line in captured.err.splitlines() if line.startswith("Collection notice: ")]
    assert len(notices) == 1
    assert DEFAULT_DOH_ENDPOINT in notices[0] and "--exclude google_dns_posture" in notices[0]
    assert "Collection notice" not in captured.out


def test_r083_google_run_without_dns_prints_no_dns_notice(tmp_path, monkeypatch, capsys) -> None:  # noqa: ANN001
    from auditex.google_workspace import run as google_run
    from azure_tenant_audit.collectors.base import CollectorResult

    class _Collector:
        name = "google_directory"
        required_scopes = ("scope://directory",)

        def run(self, context):  # noqa: ANN001
            return CollectorResult(self.name, "ok", {}, 0, coverage=[{"collector": self.name, "name": "x", "status": "ok",
                                                                       "item_count": 0}])

    monkeypatch.setattr(google_run, "REGISTRY", {"google_directory": _Collector()})
    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True, "missing": [], "install_hint": ""})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: object())

    google_run.run_google_live(google_run.GoogleRunConfig(tenant_name="Example", out=tmp_path, run_name="dir",
                                                          collectors="google_directory"))

    assert "DNS" not in capsys.readouterr().err


# X1 (collector half): the M365 DNS collector queries the resolver AUDITEX_DOH_ENDPOINT names when its caller passes
# none, so the data-handling notice (which names that resolver) matches the lookups.
def test_x1_dns_posture_uses_the_configured_resolver_when_the_context_names_none(monkeypatch) -> None:  # noqa: ANN001
    from azure_tenant_audit.collectors import dns_posture
    from azure_tenant_audit.dns_lookup import DOH_ENDPOINT_ENV

    endpoints: list[str] = []

    class _Doh:
        def __init__(self, endpoint, **kwargs):  # noqa: ANN001
            endpoints.append(endpoint)

    monkeypatch.setenv(DOH_ENDPOINT_ENV, "https://dns.example.net/dns-query")
    monkeypatch.setattr(dns_posture, "DohClient", _Doh)
    try:
        dns_posture.DnsPostureCollector().run({"client": None, "public_lookups": False})
    except Exception:  # noqa: BLE001 - only the resolver the collector built matters here
        pass

    assert endpoints == ["https://dns.example.net/dns-query"]


# R121 remainder: a run in which no collector finished is graded blocked in the report pack and in report analyze,
# not only when a caller passes completed_collectors by hand.
def _blocked_ledger() -> list[dict]:
    return [
        {"collector": "identity", "coverage_status": "blocked_permission"},
        {"collector": "security", "coverage_status": "failed_runtime"},
        {"collector": "sharepoint", "coverage_status": "not_applicable"},
    ]


def test_r121_report_pack_grades_a_run_with_no_completed_collector_blocked() -> None:
    from azure_tenant_audit.findings import build_report_pack

    pack = build_report_pack(tenant_name="acme", overall_status="partial", findings=[], evidence_paths=["summary.json"],
                             coverage_ledger=_blocked_ledger())

    assert pack["auditor_score"]["grade"] == "blocked"


def test_r121_report_pack_still_grades_a_run_with_a_completed_collector() -> None:
    from azure_tenant_audit.findings import build_report_pack

    ledger = [*_blocked_ledger(), {"collector": "apps", "coverage_status": "partial_success"}]
    pack = build_report_pack(tenant_name="acme", overall_status="partial", findings=[], evidence_paths=["summary.json"],
                             coverage_ledger=ledger)

    assert pack["auditor_score"]["grade"] != "blocked"


def test_r121_report_analyze_grades_a_run_with_no_completed_collector_blocked(tmp_path) -> None:  # noqa: ANN001
    import json

    from auditex.reporting import analyze_report

    run_dir = tmp_path / "acme-run"
    (run_dir / "reports").mkdir(parents=True)
    (run_dir / "run-manifest.json").write_text(json.dumps(
        {"tenant_name": "acme", "run_id": "run", "platform": "m365", "overall_status": "partial",
         "artifacts": ["reports/report-pack.json"]}), encoding="utf-8")
    (run_dir / "summary.json").write_text(json.dumps(
        {"tenant_name": "acme", "run_id": "run", "overall_status": "partial",
         "collectors": [{"name": "identity", "status": "failed"}, {"name": "security", "status": "failed"}]}),
        encoding="utf-8")
    (run_dir / "reports" / "report-pack.json").write_text(json.dumps(
        {"summary": {"tenant_name": "acme", "overall_status": "partial"}, "findings": [],
         "evidence_paths": ["summary.json"]}), encoding="utf-8")

    result = analyze_report(run_dir)

    assert result["auditor_score"]["grade"] == "blocked"


# Google customer ids (found by the reporting-exports-disclosure review): shareable output masks them like a tenant id.
def test_google_customer_id_is_masked_in_shareable_output() -> None:
    import json

    from azure_tenant_audit.output_redaction import redact_payload

    customer = "C03az79cb"
    payload = {
        "sections": {
            "manifest": {"platform": "google_workspace", "tenant_id": customer, "customer_id": customer},
            "summary": {"tenant_id": customer, "customerId": customer},
        }
    }

    redacted = redact_payload(payload)

    text = json.dumps(redacted)
    assert customer not in text
    manifest = redacted["sections"]["manifest"]
    # One stable pseudonym per id, so the fields still agree with each other.
    assert manifest["tenant_id"] == manifest["customer_id"] == redacted["sections"]["summary"]["tenant_id"]


def test_google_customer_id_masking_keeps_the_alias_and_ordinary_words() -> None:
    from azure_tenant_audit.output_redaction import redact_payload

    redacted = redact_payload({"customer_id": "my_customer", "tenant_id": "Contoso", "status": "Completed"})

    assert redacted["customer_id"] == "my_customer"
    assert redacted["status"] == "Completed"
