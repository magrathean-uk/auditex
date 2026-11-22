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
