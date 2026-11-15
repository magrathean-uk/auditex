from __future__ import annotations

import json

from support import FakeDoctorToolchain

from auditex import bootstrap
from auditex import cli as auditex_cli


def test_build_doctor_report_includes_versions_and_readiness_split(monkeypatch) -> None:
    FakeDoctorToolchain(blocked_tools={"pwsh"}).install(monkeypatch, bootstrap)

    report = bootstrap.build_doctor_report()

    assert report["system"]["package_manager"] == "brew"
    assert report["python"]["version"] == "Python 3.13.2"
    # DEC-107: no sign-in tool or sign-in state is checked; only PowerShell and the Exchange module.
    assert set(report["tools"]) == {"pwsh"}
    assert "auth" not in report
    assert report["readiness"]["core_ready"] is True
    assert report["readiness"]["core_missing"] == []
    assert report["readiness"]["exchange_ready"] is False
    assert report["readiness"]["exchange_missing"] == ["pwsh"]
    assert report["readiness"]["pwsh_ready"] is False
    assert report["readiness"]["pwsh_missing"] == ["pwsh"]


def test_format_doctor_report_explains_missing_packs() -> None:
    report = {
        "system": {"os": "Darwin", "machine": "arm64", "package_manager": "manual"},
        "python": {"status": "blocked", "path": None, "version": None, "error": "missing"},
        "venv": {"status": "blocked", "path": "/tmp/.venv", "python_path": "/tmp/.venv/bin/python"},
        "tools": {
            "pwsh": {"status": "blocked", "path": None, "version": None, "error": "command_not_found"},
        },
        "exchange_module": {"status": "blocked"},
        "readiness": {
            "core_missing": ["python", "venv"],
            "exchange_missing": ["pwsh", "exchange_online_module"],
            "pwsh_missing": ["pwsh"],
        },
    }

    text = bootstrap.format_doctor_report(report)

    assert "Core ready: no (need python, venv)" in text
    assert "Exchange module: blocked" in text
    assert "Exchange ready: no (need pwsh, exchange_online_module)" in text
    assert "Pwsh ready: no (need pwsh)" in text
    for removed in ("Azure CLI", "Azure auth", "m365", "Node", "npm"):
        assert removed not in text


def test_auditex_setup_dispatches_to_bootstrap(monkeypatch) -> None:
    called = {}

    def _fake_run_setup(*, with_exchange: bool = False, with_pwsh: bool = False, with_mcp: bool = False) -> int:
        called["with_exchange"] = with_exchange
        called["with_pwsh"] = with_pwsh
        called["with_mcp"] = with_mcp
        return 0

    monkeypatch.setattr("auditex.cli.run_setup", _fake_run_setup)

    rc = auditex_cli.main(["setup", "--exchange", "--pwsh", "--mcp"])

    assert rc == 0
    assert called == {"with_exchange": True, "with_pwsh": True, "with_mcp": True}


def test_auditex_doctor_prints_json(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.print_doctor_report",
        lambda json_output=False: print(json.dumps({"json": json_output})) or 0,
    )

    rc = auditex_cli.main(["doctor", "--json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["json"] is True


def test_auditex_guided_run_dispatches(monkeypatch) -> None:
    called = {}

    def _fake_run_guided(args) -> int:  # noqa: ANN001
        called["tenant_id"] = args.tenant_id
        return 0

    monkeypatch.setattr("auditex.cli.run_guided", _fake_run_guided)

    rc = auditex_cli.main(["guided-run", "--tenant-id", "contoso.onmicrosoft.com", "--non-interactive"])

    assert rc == 0
    assert called["tenant_id"] == "contoso.onmicrosoft.com"


def test_build_doctor_report_marks_exchange_not_ready_without_module(monkeypatch) -> None:
    toolchain = FakeDoctorToolchain(exchange_auth={"status": "blocked", "error": "module_not_found"})
    toolchain.install(monkeypatch, bootstrap)

    report = bootstrap.build_doctor_report()

    assert report["readiness"]["exchange_ready"] is False
    assert report["readiness"]["exchange_missing"] == ["exchange_online_module"]


def test_build_doctor_report_never_needs_a_sign_in_tool(monkeypatch) -> None:
    FakeDoctorToolchain(blocked_tools={"az", "m365", "node", "npm"}).install(monkeypatch, bootstrap)

    report = bootstrap.build_doctor_report()

    assert report["readiness"]["core_ready"] is True
    assert report["readiness"]["core_missing"] == []
    assert report["readiness"]["exchange_ready"] is True
