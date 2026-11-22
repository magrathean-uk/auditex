"""Review lane integrate-w2: the cross-lane changes the wave-2 lanes could not make in their own files."""
from __future__ import annotations

import subprocess


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
