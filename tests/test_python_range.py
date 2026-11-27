"""The tested Python range (MAINT-1): one constant, the doctor's three answers and the places that state the range.

Every expected value is a literal; only the parity test at the end reads the files that must follow the constant.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from auditex import auth_runtime, bootstrap
from auditex.auth_runtime import (
    ToolchainRuntime,
    ToolchainRuntimeAdapters,
    classify_python_version,
)

ROOT = Path(__file__).resolve().parents[1]


def test_the_tested_range_is_one_constant_pair():
    assert auth_runtime.PYTHON_MINIMUM == (3, 11)
    assert auth_runtime.PYTHON_NEWEST_TESTED == (3, 15)
    assert auth_runtime.tested_python_range_text() == "3.11 to 3.15"


@pytest.mark.parametrize("text,expected", [
    ("Python 3.9.18", ("blocked", "python_too_old")),
    ("Python 3.10.14", ("blocked", "python_too_old")),
    ("Python 3.10", ("blocked", "python_too_old")),
    ("Python 2.7.18", ("blocked", "python_too_old")),
    ("Python 3.11.0", ("supported", None)),
    ("Python 3.11", ("supported", None)),
    ("3.12.3", ("supported", None)),
    ("Python 3.14.1", ("supported", None)),
    ("Python 3.15.0rc1", ("supported", None)),
    ("Python 3.15.2", ("supported", None)),
    ("Python 3.15.99\n", ("supported", None)),
    ("Python 3.16.0", ("untested", None)),
    ("Python 3.16.0a1", ("untested", None)),
    ("Python 3.20.1", ("untested", None)),
    ("Python 4.0.0", ("untested", None)),
    ("", ("blocked", "python_version_unreadable")),
    ("   ", ("blocked", "python_version_unreadable")),
    ("Python", ("blocked", "python_version_unreadable")),
    ("Python 3", ("blocked", "python_version_unreadable")),
    ("Python x.y.z", ("blocked", "python_version_unreadable")),
    ("not a version 3.12", ("blocked", "python_version_unreadable")),
    ("Python .3.12", ("blocked", "python_version_unreadable")),
    ("Python 3.", ("blocked", "python_version_unreadable")),
    (None, ("blocked", "python_version_unreadable")),
    (312, ("blocked", "python_version_unreadable")),
    ((3, 12), ("blocked", "python_version_unreadable")),
])
def test_classify_python_version_boundaries(text, expected):
    assert classify_python_version(text) == expected


def _source_python(tmp_path, version_text, *, selector_exit=0):
    selector = tmp_path / "select-python.sh"
    selector.touch()

    def run(command):
        if command[0] == "bash":
            return {"status": "supported" if selector_exit == 0 else "blocked", "stdout": "/opt/py/bin/python3\n",
                    "stderr": "", "returncode": selector_exit}
        return {"status": "supported", "stdout": version_text, "stderr": "", "returncode": 0}

    return ToolchainRuntime(ToolchainRuntimeAdapters(run_json_command=run), select_python_script=selector).selected_python()


@pytest.mark.parametrize("version,status,error", [
    ("Python 3.10.14", "blocked", "python_too_old"),
    ("Python 3.11.0", "supported", None),
    ("Python 3.15.2", "supported", None),
    ("Python 3.16.0", "untested", None),
    ("Python 4.0.0", "untested", None),
    ("garbage", "blocked", "python_version_unreadable"),
    ("Python", "blocked", "python_version_unreadable"),
])
def test_source_checkout_path_classifies_the_selected_python(tmp_path, version, status, error):
    result = _source_python(tmp_path, version)
    assert (result["status"], result["error"], result["version"]) == (status, error, version)
    assert result["path"] == "/opt/py/bin/python3"


def test_source_checkout_path_with_no_version_output_is_blocked(tmp_path):
    result = _source_python(tmp_path, "")
    assert result["status"] == "blocked"
    assert result["error"] == "empty_version_output"


@pytest.fixture
def installed(monkeypatch):
    monkeypatch.setattr(bootstrap, "is_source_checkout", lambda: False)

    def use(major, minor, micro=0):
        monkeypatch.setattr(sys, "version_info", (major, minor, micro, "final", 0))
        monkeypatch.setattr(bootstrap.platform, "python_version", lambda: f"{major}.{minor}.{micro}")
    return use


@pytest.mark.parametrize("version,status,error", [
    ((3, 10, 14), "blocked", "python_too_old"),
    ((3, 11, 0), "supported", None),
    ((3, 14, 3), "supported", None),
    ((3, 15, 2), "supported", None),
    ((3, 16, 0), "untested", None),
    ((3, 99, 0), "untested", None),
    ((4, 0, 0), "untested", None),
    ((2, 7, 18), "blocked", "python_too_old"),
])
def test_installed_path_classifies_this_interpreter(installed, version, status, error):
    installed(*version)
    result = bootstrap._selected_python()
    assert (result["status"], result["error"]) == (status, error)
    assert result["version"] == "Python {}.{}.{}".format(*version)
    assert result["selector"] == "installed"


def _report(monkeypatch, python):
    monkeypatch.setattr(bootstrap, "_selected_python", lambda: python)
    monkeypatch.setattr(bootstrap, "_venv_status", lambda: {"status": "supported", "path": "/v", "python_path": "/v/p"})
    monkeypatch.setattr(bootstrap, "detect_package_manager", lambda: "brew")
    monkeypatch.setattr(bootstrap, "_tool_status", lambda name, **_: {"name": name, "status": "supported"})
    monkeypatch.setattr(bootstrap, "exchange_module_status", lambda: {"status": "supported"})
    return bootstrap.build_doctor_report()


def test_an_untested_python_is_a_warning_not_blocked(monkeypatch):
    python = {"status": "untested", "path": "/usr/bin/python3", "version": "Python 3.16.0", "error": None}
    report = _report(monkeypatch, python)
    assert report["readiness"]["core_ready"] is True
    assert report["readiness"]["core_missing"] == []
    assert report["readiness"]["warnings"] == ["python_untested"]
    text = bootstrap.format_doctor_report(report)
    assert "Python: untested Python 3.16.0 [/usr/bin/python3] (newer than the newest tested Python, 3.15)" in text
    assert "Core ready: yes" in text


def test_a_supported_python_has_no_warning_and_a_blocked_one_is_missing(monkeypatch):
    ok = _report(monkeypatch, {"status": "supported", "path": "/p", "version": "Python 3.14.1", "error": None})
    assert ok["readiness"]["warnings"] == [] and ok["readiness"]["core_ready"] is True
    old = _report(monkeypatch, {"status": "blocked", "path": "/p", "version": "Python 3.10.1", "error": "python_too_old"})
    assert old["readiness"]["core_ready"] is False
    assert old["readiness"]["core_missing"] == ["python"]
    assert old["readiness"]["warnings"] == []
    assert "Python: blocked (python_too_old)" in bootstrap.format_doctor_report(old)


def _classifiers() -> list[str]:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    return re.findall(r'"Programming Language :: Python :: (3\.\d+)"', text)


def test_the_places_that_state_the_range_follow_the_constant():
    minors = [f"3.{minor}" for minor in range(11, 16)]
    assert _classifiers() == minors
    assert 'requires-python = ">=3.11"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    phrase = "3.11, 3.12, 3.13, 3.14 or 3.15"
    for name in ("README.md", "docs/guides/install-guide.md", "docs/guides/product-manual.md",
                 "docs/development/runbook.md", ".github/CONTRIBUTING.md"):
        assert phrase in (ROOT / name).read_text(encoding="utf-8"), name
    workflow = (ROOT / ".github/workflows/cleanroom.yml").read_text(encoding="utf-8")
    assert workflow.count('python: ["3.11", "3.15"]') == 2
    assert "python3.15 python3.14 python3.13" in (ROOT / "scripts/select-python.sh").read_text(encoding="utf-8")
