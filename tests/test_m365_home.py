from __future__ import annotations

import os
from pathlib import Path

from azure_tenant_audit import m365_home
from azure_tenant_audit.m365_home import is_m365_command, m365_environment, m365_subprocess_kwargs


def test_explicit_folder_wins_over_xdg_data_home(tmp_path: Path) -> None:
    environ = {"AUDITEX_M365_HOME": str(tmp_path / "explicit"), "XDG_DATA_HOME": str(tmp_path / "data")}

    assert m365_home.m365_home(environ) == (tmp_path / "explicit").resolve()


def test_xdg_data_home_is_the_fallback(tmp_path: Path) -> None:
    environ = {"XDG_DATA_HOME": str(tmp_path / "data")}

    assert m365_home.m365_home(environ) == (tmp_path / "data" / "auditex" / "m365").resolve()


def test_nothing_is_routed_without_configuration_or_with_an_empty_folder(tmp_path: Path) -> None:
    assert m365_home.m365_home({}) is None
    assert m365_home.m365_home({"XDG_DATA_HOME": " "}) is None
    assert m365_home.m365_home({"AUDITEX_M365_HOME": "", "XDG_DATA_HOME": str(tmp_path)}) is None


def test_only_m365_commands_get_a_routed_environment(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AUDITEX_M365_HOME", str(tmp_path / "m365-home"))

    assert is_m365_command(["m365", "status"])
    assert is_m365_command(["/opt/bin/m365", "status"])
    assert not is_m365_command(["az", "account", "show"])
    assert not is_m365_command([])
    assert m365_subprocess_kwargs(["az", "account", "show"]) == {}
    assert m365_subprocess_kwargs(None) == {}


def test_m365_environment_redirects_home_and_creates_a_private_folder(tmp_path: Path, monkeypatch) -> None:
    folder = tmp_path / "m365-home"
    monkeypatch.setenv("AUDITEX_M365_HOME", str(folder))
    monkeypatch.setenv("AUDITEX_KEEP_ME", "kept")

    env = m365_environment(["m365", "login"])

    assert env is not None
    assert env["HOME"] == str(folder.resolve())
    assert env["AUDITEX_KEEP_ME"] == "kept"
    assert os.environ["HOME"] != str(folder.resolve())
    assert folder.is_dir()
    assert (folder.stat().st_mode & 0o777) == 0o700
    assert m365_subprocess_kwargs(["m365", "login"]) == {"env": env}


def test_m365_environment_is_unchanged_when_unrouted(monkeypatch) -> None:
    monkeypatch.setenv("AUDITEX_M365_HOME", "")

    assert m365_environment(["m365", "status"]) is None
    assert m365_subprocess_kwargs(["m365", "status"]) == {}
