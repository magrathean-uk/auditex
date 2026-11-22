"""PyPI install route (#145) and the packaging review findings on PR #151."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from auditex import bootstrap


@pytest.fixture
def installed_package(monkeypatch, tmp_path: Path) -> Path:
    """Auditex as an installed package (no source checkout) in an environment rooted at tmp_path."""
    monkeypatch.setattr(bootstrap, "is_source_checkout", lambda: False)
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    monkeypatch.setattr(bootstrap, "_extra_installed", lambda extra: False, raising=False)
    return tmp_path


# PR #151 review (greptile): the installed-package hint named bare `python` and no route that matches how Auditex
# was installed. A pipx install keeps its own environment; a plain venv takes the interpreter running Auditex.
def test_setup_hint_in_a_pipx_environment_reinstalls_with_the_extra(installed_package: Path, capsys) -> None:
    (installed_package / "pipx_metadata.json").write_text("{}", encoding="utf-8")
    assert bootstrap.run_setup(with_mcp=True) == 0
    out = capsys.readouterr().out
    assert 'pipx install --force "auditex[mcp]"' in out
    assert "python -m pip" not in out


def test_setup_hint_in_a_plain_environment_uses_the_running_interpreter(installed_package: Path, capsys) -> None:
    assert bootstrap.run_setup(with_mcp=True) == 0
    out = capsys.readouterr().out
    assert f"{sys.executable} -m pip install 'auditex[mcp]'" in out
    assert "-e '." not in out


def test_a_pipx_hint_keeps_the_extras_already_installed(installed_package: Path, monkeypatch) -> None:
    (installed_package / "pipx_metadata.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(bootstrap, "_extra_installed", lambda extra: extra == "google")
    assert bootstrap.extra_install_command("mcp") == 'pipx install --force "auditex[google,mcp]"'


def test_a_source_checkout_keeps_the_editable_install_hint(monkeypatch) -> None:
    monkeypatch.setattr(bootstrap, "is_source_checkout", lambda: True)
    assert bootstrap.extra_install_command("google") == "python -m pip install -e '.[google]'"


def test_google_and_mcp_hints_follow_the_install_route(installed_package: Path, monkeypatch, capsys) -> None:
    from auditex import mcp_server
    from auditex.google_workspace import auth

    (installed_package / "pipx_metadata.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(auth, "_module_available", lambda module: False)
    assert 'pipx install --force "auditex[google]"' in auth.google_dependency_status()["install_hint"]

    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", None)
    assert mcp_server.main([]) == 2
    assert 'pipx install --force "auditex[mcp]"' in capsys.readouterr().err
