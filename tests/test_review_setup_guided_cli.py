"""Regression tests for the setup-guided-cli review lane (R061 onwards)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditex import guided
from auditex.guided import build_guided_parser

_THUMBPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"


def _doctor(*, core: bool = True, exchange: bool = True) -> dict:
    return {
        "system": {"os": "Linux", "machine": "x86_64"},
        "readiness": {
            "core_ready": core,
            "core_missing": [] if core else ["venv"],
            "exchange_ready": exchange,
            "exchange_missing": [] if exchange else ["pwsh", "exchange_online_module"],
            "pwsh_ready": exchange,
        },
    }


def _guided_args(tmp_path: Path, *extra: str) -> list[str]:
    return [
        "--tenant-id", "contoso.onmicrosoft.com", "--tenant-name", "ACME", "--out", str(tmp_path),
        "--client-id", "app-id", "--certificate-path", "reader.key.pem", "--certificate-thumbprint", _THUMBPRINT,
        *extra,
    ]


def _setup_spy(monkeypatch, doctor: dict) -> list[dict]:  # noqa: ANN001
    calls: list[dict] = []
    monkeypatch.setattr(guided, "build_doctor_report", lambda: doctor)
    monkeypatch.setattr(guided, "run_setup", lambda **kwargs: calls.append(kwargs) or 0)
    return calls


def _engine_spy(monkeypatch, *, rc: int = 0, write: str | None = None) -> dict:  # noqa: ANN001
    seen: dict = {}

    def _main(argv, event_listener=None, **_):  # noqa: ANN001
        seen["argv"] = list(argv)
        if write is not None:
            out = Path(argv[argv.index("--out") + 1])
            folder = out / write
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "run-manifest.json").write_text("{}", encoding="utf-8")
        return rc

    monkeypatch.setattr("auditex.guided.tenant_cli.main", _main)
    return seen


# R061: guided-run never installs tools without an explicit request, and only needs Exchange tools for Exchange.

def test_r061_non_interactive_guided_run_never_installs_tools(monkeypatch, tmp_path, capsys) -> None:  # noqa: ANN001
    setup_calls = _setup_spy(monkeypatch, _doctor(exchange=False))
    seen = _engine_spy(monkeypatch)

    rc = guided.run_guided(build_guided_parser().parse_args(
        [*_guided_args(tmp_path, "--collectors", "identity,exchange_policy"), "--non-interactive"]
    ))

    assert setup_calls == []
    assert rc == 2
    assert "argv" not in seen
    out = capsys.readouterr().out
    assert "--install-tools" in out and "exchange_online_module" in out


def test_r061_guided_run_does_not_need_exchange_tools_without_an_exchange_collector(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    setup_calls = _setup_spy(monkeypatch, _doctor(exchange=False))
    seen = _engine_spy(monkeypatch)

    rc = guided.run_guided(build_guided_parser().parse_args(
        [*_guided_args(tmp_path, "--collectors", "identity"), "--non-interactive"]
    ))

    assert setup_calls == []
    assert rc == 0
    assert "argv" in seen


def test_r061_install_tools_flag_runs_setup_without_a_prompt(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    setup_calls = _setup_spy(monkeypatch, _doctor(exchange=False))
    _engine_spy(monkeypatch)

    rc = guided.run_guided(build_guided_parser().parse_args(
        [*_guided_args(tmp_path, "--collectors", "exchange_policy"), "--non-interactive", "--install-tools"]
    ))

    assert rc == 0
    assert setup_calls == [{"with_mcp": False, "with_exchange": True, "with_pwsh": True}]


# R062: the report is rendered into the run folder this run wrote, and only when the run wrote a bundle.

def test_r062_report_goes_into_the_folder_this_run_wrote(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    for older in ("ACME-test-run_20260101_000000", "ACME-weekly"):
        (tmp_path / older).mkdir()
        (tmp_path / older / "run-manifest.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(guided, "build_doctor_report", lambda: _doctor())
    _engine_spy(monkeypatch, write="ACME-run_20261121_090000")
    rendered: list[str] = []
    monkeypatch.setattr("auditex.reporting.render_report",
                        lambda run_dir, format_name, profile: rendered.append(Path(run_dir).name) or {})

    rc = guided.run_guided(build_guided_parser().parse_args(
        [*_guided_args(tmp_path, "--report-format", "html"), "--non-interactive"]
    ))

    assert rc == 0
    assert rendered == ["ACME-run_20261121_090000"]


def test_r062_failed_run_renders_no_report(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    (tmp_path / "ACME-weekly").mkdir()
    (tmp_path / "ACME-weekly" / "run-manifest.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(guided, "build_doctor_report", lambda: _doctor())
    _engine_spy(monkeypatch, rc=2)
    rendered: list[str] = []
    monkeypatch.setattr("auditex.reporting.render_report",
                        lambda run_dir, format_name, profile: rendered.append(run_dir) or {})

    rc = guided.run_guided(build_guided_parser().parse_args(
        [*_guided_args(tmp_path, "--report-format", "html"), "--non-interactive"]
    ))

    assert rc == 2
    assert rendered == []


# R089: a certificate Entra refuses stops the live run with the certificate message, before collection starts.

def test_r089_rejected_certificate_stops_the_live_run(monkeypatch, tmp_path, caplog) -> None:  # noqa: ANN001
    from support import FAKE_CERTIFICATE_ARGS, use_fake_certificate

    from azure_tenant_audit import cli
    from azure_tenant_audit.graph import GraphClient

    use_fake_certificate(monkeypatch)
    monkeypatch.setattr(GraphClient, "_certificate_exchange",
                        lambda self, scope: (None, 0.0, "certificate_token_failed"))
    ran: list[str] = []

    class _Collector:
        name = "identity"

        def run(self, context):  # noqa: ANN001
            ran.append("identity")
            raise AssertionError("no collector may run without a token")

    monkeypatch.setattr(cli, "REGISTRY", {"identity": _Collector()})
    args = cli.build_parser().parse_args([
        "--tenant-name", "acme", "--tenant-id", "contoso.onmicrosoft.com", "--client-id", "app-id",
        *FAKE_CERTIFICATE_ARGS, "--collectors", "identity", "--no-probe-first", "--out", str(tmp_path),
    ])

    with caplog.at_level("ERROR"):
        rc = cli.run_live(args)

    assert rc == 2
    assert ran == []
    assert "A certificate app token could not be acquired." in caplog.text
    events = [
        json.loads(line)["event"]
        for log in tmp_path.glob("acme-*/audit-log.jsonl")
        for line in log.read_text(encoding="utf-8").splitlines() if line
    ]
    assert "run.started" not in events


# R094: the values the shipped example env file sets are honoured when the matching flag is not given.

def _env_file(tmp_path: Path, out: Path) -> Path:
    path = tmp_path / "tenant.env"
    path.write_text(
        "AZURE_AUTHORITY=https://login.microsoftonline.us/\n"
        "AZURE_GRAPH_SCOPE=https://graph.microsoft.us/.default\n"
        f"AUDIT_OUTPUT_DIR={out}\n"
        "AUDIT_COLLECTORS=identity,security\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def _clear_run_env(monkeypatch) -> None:  # noqa: ANN001
    # setenv first so monkeypatch restores the variable's absence after load_env_file writes os.environ directly.
    for name in ("AZURE_AUTHORITY", "AZURE_GRAPH_SCOPE", "AUDIT_OUTPUT_DIR", "AUDIT_COLLECTORS", "AUDIT_SAMPLE_FILE"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)


def test_r094_env_file_values_reach_the_live_run(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    from support import FAKE_CERTIFICATE_ARGS

    from azure_tenant_audit import cli

    _clear_run_env(monkeypatch)
    out = tmp_path / "env-out"
    seen: dict = {}
    monkeypatch.setattr(cli, "run_live", lambda args, **_: seen.update(vars(args)) or 0)

    rc = cli.main([
        "--tenant-name", "acme", "--tenant-id", "contoso.onmicrosoft.com", "--client-id", "app-id",
        *FAKE_CERTIFICATE_ARGS, "--env", str(_env_file(tmp_path, out)),
    ])

    assert rc == 0
    assert seen["authority"] == "https://login.microsoftonline.us/"
    assert seen["graph_scope"] == "https://graph.microsoft.us/.default"
    assert seen["out"] == str(out)
    assert seen["collectors"] == "identity,security"


def test_r094_flags_win_over_env_file_values(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    from support import FAKE_CERTIFICATE_ARGS

    from azure_tenant_audit import cli

    _clear_run_env(monkeypatch)
    seen: dict = {}
    monkeypatch.setattr(cli, "run_live", lambda args, **_: seen.update(vars(args)) or 0)

    rc = cli.main([
        "--tenant-name", "acme", "--tenant-id", "contoso.onmicrosoft.com", "--client-id", "app-id",
        *FAKE_CERTIFICATE_ARGS, "--env", str(_env_file(tmp_path, tmp_path / "env-out")),
        "--authority", "https://login.microsoftonline.com/", "--out", str(tmp_path / "flag-out"),
        "--collectors", "teams",
    ])

    assert rc == 0
    assert seen["authority"] == "https://login.microsoftonline.com/"
    assert seen["graph_scope"] == "https://graph.microsoft.us/.default"
    assert seen["out"] == str(tmp_path / "flag-out")
    assert seen["collectors"] == "teams"


def test_r094_defaults_without_env(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    from support import FAKE_CERTIFICATE_ARGS

    from azure_tenant_audit import cli

    _clear_run_env(monkeypatch)
    seen: dict = {}
    monkeypatch.setattr(cli, "run_live", lambda args, **_: seen.update(vars(args)) or 0)

    assert cli.main(["--tenant-name", "acme", "--tenant-id", "contoso.onmicrosoft.com", "--client-id", "app-id",
                     *FAKE_CERTIFICATE_ARGS]) == 0
    assert seen["authority"] == "https://login.microsoftonline.com/"
    assert seen["graph_scope"] == "https://graph.microsoft.com/.default"
    assert seen["out"] == "audit-output"
    assert seen["collectors"] is None


# R118: google probe is always live, so it refuses --offline and --sample instead of ignoring them.

@pytest.mark.parametrize("flag", [["--offline"], ["--sample", "examples/google_workspace_sample.json"]])
def test_r118_google_probe_refuses_offline_flags(monkeypatch, capsys, flag) -> None:  # noqa: ANN001
    from auditex import cli as product_cli

    probed: list[object] = []
    monkeypatch.setattr(product_cli, "run_google_probe", lambda cfg, **_: probed.append(cfg) or 0)

    with pytest.raises(SystemExit) as exc:
        product_cli.main(["google", "probe", *flag, "--domain", "corp.example", "--subject", "admin@corp.example"])

    assert exc.value.code == 2
    assert probed == []
    assert flag[0] in capsys.readouterr().err


# R120: an unknown auditor profile, or a plane the profile does not support, is refused, never shown as auto.

def test_r120_get_profile_refuses_an_unknown_name() -> None:
    from azure_tenant_audit.profiles import get_profile

    with pytest.raises(ValueError, match="intune_reader"):
        get_profile("intune_reader")


@pytest.mark.parametrize("argv", [
    ["setup-guide", "m365", "--auditor-profile", "intune_reader", "--format", "json"],
    ["probe", "live", "--tenant-name", "acme", "--auditor-profile", "global_reader"],
])
def test_r120_cli_refuses_an_unknown_auditor_profile(capsys, argv) -> None:  # noqa: ANN001
    from auditex import cli as product_cli

    with pytest.raises(SystemExit) as exc:
        product_cli.main(argv)

    assert exc.value.code == 2
    assert "{" not in capsys.readouterr().out


def test_r120_setup_guide_refuses_a_plane_the_profile_does_not_support() -> None:
    from auditex.setup_guide import build_m365_setup_guide

    with pytest.raises(ValueError, match="export"):
        build_m365_setup_guide(auditor_profile="intune-reader", plane="export")


def test_r120_setup_guide_cli_reports_an_unsupported_plane(capsys) -> None:  # noqa: ANN001
    from auditex import cli as product_cli

    with pytest.raises(SystemExit) as exc:
        product_cli.main(["setup-guide", "m365", "--auditor-profile", "intune-reader", "--plane", "export"])

    assert exc.value.code == 2
    assert "export" in capsys.readouterr().err


# R123: an explicit --permission-hints path that does not exist is an error, not a silently thinner guide.

def test_r123_missing_explicit_permission_hints_is_an_error(tmp_path) -> None:  # noqa: ANN001
    from auditex.setup_guide import build_m365_setup_guide

    with pytest.raises(FileNotFoundError):
        build_m365_setup_guide(permission_hints_path=tmp_path / "collector-permision.json")


def test_r123_setup_guide_cli_exits_2_for_a_missing_permission_hints_file(tmp_path, capsys) -> None:  # noqa: ANN001
    from auditex import cli as product_cli

    with pytest.raises(SystemExit) as exc:
        product_cli.main(["setup-guide", "m365", "--permission-hints", str(tmp_path / "collector-permision.json"),
                          "--format", "json"])

    assert exc.value.code == 2
    assert "permission-hints" in capsys.readouterr().err


def test_r123_shipped_default_permission_hints_still_load() -> None:
    from auditex.setup_guide import build_m365_setup_guide

    guide = build_m365_setup_guide()
    assert len(guide["optional_commands"]) > 0 and len(guide["tool_requirements"]) == 3


# R121: a run with no evidence is not graded strong, QA checks are not vacuously true, and the licence profile names
# the reader-app certificate route.

_BLOCKED_GAPS = [{"collector": f"c{index}", "surface": f"s{index}", "status": "blocked"} for index in range(20)]


def test_r121_run_with_every_collector_blocked_is_graded_blocked() -> None:
    from azure_tenant_audit.autopilot import build_auditor_score

    score = build_auditor_score(findings=[], overall_status="partial", evidence_paths=["x"], coverage_gaps=_BLOCKED_GAPS)

    assert score["grade"] == "blocked"
    assert score["components"]["evidence_depth"] < 100 and score["components"]["finding_confidence"] < 100


def test_r121_clean_run_with_no_findings_and_no_gaps_still_scores_high() -> None:
    from azure_tenant_audit.autopilot import build_auditor_score

    score = build_auditor_score(findings=[], overall_status="ok", evidence_paths=["x"], coverage_gaps=[])

    assert score["grade"] == "ultimate"


def test_r121_report_qa_checks_are_not_vacuously_true_without_evidence() -> None:
    from azure_tenant_audit.autopilot import build_report_qa

    qa = build_report_qa([], coverage_gaps=_BLOCKED_GAPS)

    assert qa["checks"]["every_finding_has_evidence"] is False
    assert qa["checks"]["all_findings_high_confidence"] is False
    assert qa["checks"]["limitations_declared"] is True


def test_r121_limitations_declared_is_false_for_an_undescribed_gap() -> None:
    from azure_tenant_audit.autopilot import build_report_qa

    assert build_report_qa([], coverage_gaps=[{"status": "blocked"}])["checks"]["limitations_declared"] is False


def test_r121_m365_licence_profile_names_the_reader_app_certificate() -> None:
    from azure_tenant_audit.autopilot import build_basic_license_intelligence

    pack = build_basic_license_intelligence(tenant_name="acme", platform="m365", overall_status="ok", findings=[],
                                            evidence_paths=["x"], coverage_gaps=[])

    assert pack["license_profile"]["minimum_live_access"] == "reader_app_certificate"


# R124: a default global-reader or auto run is not shown as skipping expected surfaces.

@pytest.mark.parametrize("profile_name", ["global-reader", "app-readonly-full"])
def test_r124_default_profile_run_misses_no_expected_collector(profile_name) -> None:  # noqa: ANN001
    from azure_tenant_audit.autopilot import build_audit_autopilot_plan
    from azure_tenant_audit.profiles import get_profile

    plan = build_audit_autopilot_plan(
        platform="m365",
        selected_collectors=list(get_profile(profile_name).default_collectors),
        capability_rows=[],
    )

    assert plan["missing_expected_collectors"] == []


def test_r124_auto_profile_reports_only_the_surface_it_really_skips() -> None:
    from azure_tenant_audit.autopilot import build_audit_autopilot_plan
    from azure_tenant_audit.profiles import get_profile

    plan = build_audit_autopilot_plan(platform="m365", selected_collectors=list(get_profile("auto").default_collectors),
                                      capability_rows=[])

    assert plan["missing_expected_collectors"] == ["sharepoint_access"]


# R162: a stuck toolchain subprocess becomes a blocked row (probe) or a blocked status (doctor), never a crash or hang.

def _timeout_run(seen: list[dict]):  # noqa: ANN202
    import subprocess

    def _run(command, **kwargs):  # noqa: ANN001
        seen.append(kwargs)
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout") or 0)

    return _run


def test_r162_probe_toolchain_timeout_is_a_blocked_row(monkeypatch) -> None:  # noqa: ANN001
    from azure_tenant_audit import probe

    seen: list[dict] = []
    monkeypatch.setattr(probe.shutil, "which", lambda name: "/usr/bin/pwsh" if name == "pwsh" else None)
    monkeypatch.setattr(probe.subprocess, "run", _timeout_run(seen))

    rows = probe._probe_toolchain_statuses(include_response=True)

    by_name = {row["name"]: row for row in rows}
    for name in ("exchange_online_module", "response_message_trace_cmdlet"):
        assert by_name[name]["status"] == "blocked"
        assert by_name[name]["error_class"] == "command_timeout"
    assert all(call.get("timeout") for call in seen)


def test_r162_bootstrap_json_command_has_a_timeout_and_maps_it_to_blocked(monkeypatch) -> None:  # noqa: ANN001
    from auditex import bootstrap

    seen: list[dict] = []
    monkeypatch.setattr(bootstrap.subprocess, "run", _timeout_run(seen))

    result = bootstrap._run_json_command(["bash", "select-python.sh"])

    assert seen and seen[0].get("timeout")
    assert result["status"] == "blocked" and result["error"] == "command_timeout"


def test_r094_run_explain_looks_for_the_run_under_audit_output_dir(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    from auditex import cli as product_cli

    _clear_run_env(monkeypatch)
    monkeypatch.setenv("AUDIT_OUTPUT_DIR", str(tmp_path / "env-out"))

    bases, _ = product_cli._engine_run_places(["--tenant-name", "acme"])

    assert Path(tmp_path / "env-out") in bases


# X1 (R164 wiring): --doh-endpoint reaches the dns_posture context, is checked before any read, is never abbreviated
# and is redacted from the recorded command line.

def test_x1_doh_endpoint_reaches_the_dns_posture_context(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    from support import FAKE_CERTIFICATE_ARGS, use_fake_certificate

    from azure_tenant_audit import cli
    from azure_tenant_audit.collectors.base import CollectorResult

    use_fake_certificate(monkeypatch)
    monkeypatch.delenv("AUDITEX_DOH_ENDPOINT", raising=False)
    seen: dict = {}

    class _Dns:
        name = "dns_posture"

        def run(self, context):  # noqa: ANN001
            seen["doh_endpoint"] = context.get("doh_endpoint")
            return CollectorResult(name=self.name, status="ok", item_count=0, message="ok", payload={})

    class _Client:
        def __init__(self, auth, **_):  # noqa: ANN001
            self.auth = auth

        def token_claims(self) -> dict:
            return {}

    monkeypatch.setattr(cli, "GraphClient", _Client)
    monkeypatch.setattr(cli, "REGISTRY", {"dns_posture": _Dns()})
    args = cli.build_parser().parse_args([
        "--tenant-name", "acme", "--tenant-id", "contoso.onmicrosoft.com", "--client-id", "app-id",
        *FAKE_CERTIFICATE_ARGS, "--collectors", "dns_posture", "--no-probe-first", "--out", str(tmp_path),
        "--doh-endpoint", "https://dns.corp.example/dns-query",
    ])

    cli.run_live(args)

    assert seen["doh_endpoint"] == "https://dns.corp.example/dns-query"


def test_x1_malformed_doh_endpoint_stops_the_run_before_the_folder_exists(monkeypatch, tmp_path, caplog) -> None:  # noqa: ANN001
    from support import FAKE_CERTIFICATE_ARGS, use_fake_certificate

    from azure_tenant_audit import cli

    use_fake_certificate(monkeypatch)
    monkeypatch.setattr(cli, "GraphClient", lambda *_a, **_k: pytest.fail("no client"))
    canary = "constructed-doh-token-zz9"
    args = cli.build_parser().parse_args([
        "--tenant-name", "acme", "--tenant-id", "contoso.onmicrosoft.com", "--client-id", "app-id",
        *FAKE_CERTIFICATE_ARGS, "--out", str(tmp_path), "--doh-endpoint", f"http://dns.corp.example/{canary}",
    ])

    with caplog.at_level("ERROR"):
        assert cli.run_live(args) == 2
    assert "DNS-over-HTTPS" in caplog.text and canary not in caplog.text
    assert not list(tmp_path.glob("acme-*"))


@pytest.mark.parametrize("builder_name", ["engine", "guided"])
@pytest.mark.parametrize("inline", [False, True])
def test_x1_doh_endpoint_refuses_abbreviations_without_echo(builder_name, inline, capsys) -> None:  # noqa: ANN001
    from azure_tenant_audit import cli

    builder = cli.build_parser if builder_name == "engine" else build_guided_parser
    assert builder().parse_args(["--doh-endpoint", "https://dns.corp.example/q"]).doh_endpoint == "https://dns.corp.example/q"
    canary = "constructed-canary-argv-zz9"
    for length in range(3, len("--doh-endpoint")):
        option = "--doh-endpoint"[:length]
        with pytest.raises(SystemExit) as exc:
            builder().parse_args([f"{option}={canary}"] if inline else [option, canary])
        assert exc.value.code == 2
        assert canary not in capsys.readouterr().err


def test_x1_doh_endpoint_is_redacted_from_the_recorded_command_line() -> None:
    from azure_tenant_audit.auth_runtime import SENSITIVE_CLI_ARGS, scrub_command_line

    assert "--doh-endpoint" in SENSITIVE_CLI_ARGS
    scrubbed = scrub_command_line(["azure-tenant-audit", "--doh-endpoint", "https://dns.corp.example/tok-zz9"])
    assert "https://dns.corp.example/tok-zz9" not in scrubbed


def test_x1_guided_run_passes_the_doh_endpoint_to_the_engine(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    monkeypatch.setattr(guided, "build_doctor_report", lambda: _doctor())
    seen = _engine_spy(monkeypatch)

    rc = guided.run_guided(build_guided_parser().parse_args(
        [*_guided_args(tmp_path, "--doh-endpoint", "https://dns.corp.example/q"), "--non-interactive"]
    ))

    assert rc == 0
    assert seen["argv"][seen["argv"].index("--doh-endpoint") + 1] == "https://dns.corp.example/q"


# X2: native Windows (no descriptor-relative no-follow opens) gets a clear platform message, not "unsafe input".

WINDOWS_MESSAGE = "Auditex needs Linux, macOS or WSL2; native Windows is not supported yet."


def test_x2_unsupported_platform_names_the_supported_systems(monkeypatch) -> None:  # noqa: ANN001
    from azure_tenant_audit import guarded_io

    monkeypatch.setattr(guarded_io, "_supported", lambda: False)

    with pytest.raises(guarded_io.UnsafeRunFileError) as exc:
        with guarded_io.GuardContext():
            pass

    assert str(exc.value) == WINDOWS_MESSAGE


def test_x2_guarded_cli_prints_the_platform_message(monkeypatch, capsys) -> None:  # noqa: ANN001
    from azure_tenant_audit import guarded_io
    from azure_tenant_audit.cli_guard import guarded_cli

    monkeypatch.setattr(guarded_io, "_supported", lambda: False)

    assert guarded_cli(lambda: 0)() == 2
    err = capsys.readouterr().err
    assert WINDOWS_MESSAGE in err and "unsafe input" not in err
