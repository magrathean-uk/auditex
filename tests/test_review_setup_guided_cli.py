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
