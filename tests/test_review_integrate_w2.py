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
