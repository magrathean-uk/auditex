"""CLI inputs are admitted as parsed, including dash-prefixed and @file names."""
from __future__ import annotations

import os
from pathlib import Path
import re

import pytest

from auditex import cli as product_cli
from azure_tenant_audit import cli as engine_cli
from test_guarded_admission import KEY, private_run  # noqa: F401 - shared fixture


def _invoke(entry: str, argv: list[str]) -> int:
    try:
        return product_cli.main(["run", *argv]) if entry == "product" else engine_cli.main(argv)
    except SystemExit as exc:
        return int(exc.code)


@pytest.mark.parametrize("entry", ["product", "engine"])
@pytest.mark.parametrize("flag", ["--sample", "--break-glass-accounts"])
@pytest.mark.parametrize("name", ["-1", "-1.5", "-a b", "-"])
@pytest.mark.parametrize("inline", [False, True])
@pytest.mark.parametrize("link", ["symlink", "hardlink"])
def test_dash_and_at_file_aliases_are_admitted_and_refused(
    private_run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    entry: str, flag: str, name: str, inline: bool, link: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    alias = tmp_path / name
    key = private_run / "operator-inputs" / "sensitive-users.key"
    if link == "symlink":
        alias.symlink_to(key)
    else:
        os.link(key, alias)
    monkeypatch.setattr(engine_cli, "run_offline", lambda *args, **kwargs: pytest.fail("unsafe input consumed"))
    value = ("@" if flag == "--break-glass-accounts" else "") + name
    option = [f"{flag}={value}"] if inline else [flag, value]
    result = _invoke(entry, ["--offline", *option])
    captured = capsys.readouterr()
    assert result == 2
    assert f"Refusing {flag[2:]}:" in captured.err
    assert KEY.decode() not in captured.out + captured.err


@pytest.mark.parametrize("entry", ["product", "engine"])
@pytest.mark.parametrize("name", ["-1", "-1.5", "-a b", "-"])
@pytest.mark.parametrize("inline", [False, True])
def test_safe_dash_prefixed_sample_is_accepted_as_a_filename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str, name: str, inline: bool,
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / name).write_text("{}", encoding="utf-8")
    seen: list[Path] = []

    def run_offline(sample: Path, *args: object, **kwargs: object) -> int:
        seen.append(sample)
        return 0

    monkeypatch.setattr(engine_cli, "run_offline", run_offline)
    option = [f"--sample={name}"] if inline else ["--sample", name]
    assert _invoke(entry, ["--offline", *option]) == 0
    assert seen == [Path(name)]


_FILE_FLAGS = [
    "--input", "--assessment", "--baseline", "--break-glass-accounts", "--cases", "--compare",
    "--config", "--current", "--env", "--expect-manifest-sha256", "--manifest", "--out", "--output",
    "--output-dir", "--permission-hints", "--responses", "--resume-from", "--run-dir", "--sample",
    "--sensitive-users", "--training-overrides", "--waiver-file",
]
_ENGINE_FLAGS = {"--break-glass-accounts", "--config", "--env", "--out", "--permission-hints",
                 "--resume-from", "--sample", "--sensitive-users", "--waiver-file"}


def test_cli_path_flag_inventory_covers_the_public_parsers() -> None:
    from azure_tenant_audit.cli_guard import _PATH_FLAGS
    from test_cli_abbreviations import BUILDERS, _parsers

    declared = {option for builder in BUILDERS for parser in _parsers(builder())
                for action in parser._actions for option in action.option_strings}
    assert set(_FILE_FLAGS) == _PATH_FLAGS
    assert _PATH_FLAGS <= declared
    # Auth file routes are expressly outside the descriptor guard; the other
    # entries mention a file or path in help but do not select an input file.
    excluded = {"--oauth-client", "--service-account-key", "--token-cache", "--token-file"}
    non_paths = {"--domain", "--path-prefix", "--projection-scan-max-bytes", "--tenant-name", "--token", "--top"}
    for builder in BUILDERS:
        for parser in _parsers(builder()):
            for action in parser._actions:
                if re.search(r"\b(path|file|directory|folder)\b", str(action.help or ""), re.I):
                    for option in action.option_strings:
                        if option.startswith("--"):
                            assert option in _PATH_FLAGS | excluded | non_paths, (parser.prog, option)


def _prefix_for(flag: str, safe_run: Path, safe_file: Path, out_dir: Path) -> list[str]:
    commands = {
        "--input": ["assessment", "import", "--source", "maester"],
        "--assessment": ["assessment", "compare"],
        "--baseline": ["gate-drift", "--current", str(safe_run), "--fail-on", "high"],
        "--current": ["gate-drift", "--baseline", str(safe_run), "--fail-on", "high"],
        "--cases": ["model", "evaluate", "--responses", str(safe_file)],
        "--responses": ["model", "evaluate", "--cases", str(safe_file)],
        "--compare": ["report", "explorer", str(safe_run)],
        "--expect-manifest-sha256": ["compare", "--run-dir", str(safe_run)],
        "--manifest": ["model", "stage", "--output-dir", str(out_dir)],
        "--output": ["assessment", "import", "--source", "maester", "--input", str(safe_file)],
        "--output-dir": ["model", "stage", "--manifest", str(safe_file)],
        "--run-dir": ["compare"],
        "--training-overrides": ["model", "prepare", "--cases", str(safe_file), "--output-dir", str(out_dir)],
    }
    return ["run", "--offline"] if flag in _ENGINE_FLAGS else commands[flag]


@pytest.mark.parametrize("flag", _FILE_FLAGS)
@pytest.mark.parametrize("suffix", [" ", ".", "\u00a0", "\u2003", "\u3000", "\u200b"])
@pytest.mark.parametrize("link", ["symlink", "hardlink"])
@pytest.mark.parametrize("inline", [False, True])
def test_cli_path_alias_matrix(
    private_run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    flag: str, suffix: str, link: str, inline: bool,
) -> None:
    from support import RunBundleBuilder

    alias = tmp_path / ("seemingly-public.json" + suffix)
    key = private_run / "operator-inputs" / "sensitive-users.key"
    if link == "symlink":
        alias.symlink_to(key)
    else:
        os.link(key, alias)
    safe_run = RunBundleBuilder(tmp_path, name="public-run").build()
    safe_file = tmp_path / "ordinary.json"
    safe_file.write_text("{}", encoding="utf-8")
    out_dir = tmp_path / "ordinary-output"
    prefix = _prefix_for(flag, safe_run, safe_file, out_dir)
    value = ("@" if flag == "--break-glass-accounts" else "") + str(alias)
    if flag == "--expect-manifest-sha256":
        value += "=" + "0" * 64
    option = [f"{flag}={value}"] if inline else [flag, value]
    monkeypatch.setattr(engine_cli, "run_offline", lambda *args, **kwargs: pytest.fail("unsafe input reached processing"))
    try:
        result = product_cli.main([*prefix, *option])
    except SystemExit as exc:
        result = exc.code
    captured = capsys.readouterr()
    assert result == 2
    assert f"Refusing {flag[2:]}:" in captured.err
    assert KEY.decode() not in captured.out + captured.err
    assert key.read_bytes() == KEY


@pytest.mark.parametrize("member", ["sensitive-users.key", "sensitive-users.txt"])
@pytest.mark.parametrize("form", ["vol", "vol-double", "vol-symlink", "fd", "fd-symlink", "uppercase-fd"])
def test_registered_pair_special_inode_aliases_across_cli_flags(
    private_run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    member: str, form: str,
) -> None:
    from azure_tenant_audit.guarded_io import GuardContext
    from support import RunBundleBuilder

    source = private_run / "operator-inputs" / member
    safe_run = RunBundleBuilder(tmp_path, name="special-public-run").build()
    safe_file = tmp_path / "special-public.json"
    safe_file.write_text("{}", encoding="utf-8")
    out_dir = tmp_path / "special-output"
    monkeypatch.setattr(engine_cli, "run_offline", lambda *args, **kwargs: pytest.fail("unsafe input consumed"))
    with GuardContext() as context, source.open("rb") as handle:
        context.bind_run(private_run)
        info = os.fstat(handle.fileno())
        alias = f"/.vol/{info.st_dev}/{info.st_ino}" if form.startswith("vol") else f"/dev/fd/{handle.fileno()}"
        if form == "uppercase-fd":
            alias = f"/DEV/fd/{handle.fileno()}"
        if not Path(alias).exists():
            pytest.skip(f"{form} filesystem alias is unavailable")
        if form == "vol-double":
            alias = "/" + alias
        if form.endswith("-symlink"):
            link = tmp_path / "special-inode-alias"
            link.symlink_to(alias)
            alias = str(link)
        for flag in _FILE_FLAGS:
            value = ("@" if flag == "--break-glass-accounts" else "") + alias
            if flag == "--expect-manifest-sha256":
                value += "=" + "0" * 64
            for inline in (False, True):
                option = [f"{flag}={value}"] if inline else [flag, value]
                invocations = [(product_cli.main, [*_prefix_for(flag, safe_run, safe_file, out_dir), *option])]
                if flag in _ENGINE_FLAGS:
                    invocations.append((engine_cli.main, ["--offline", *option]))
                for function, argv in invocations:
                    try:
                        result = function(argv)
                    except SystemExit as exc:
                        result = exc.code
                    output = capsys.readouterr()
                    assert result == 2, (form, flag, inline)
                    assert f"Refusing {flag[2:]}:" in output.err, (form, flag, inline)
                    assert KEY.decode() not in output.out + output.err


@pytest.mark.parametrize("entry", ["engine", "run", "guided-run"])
def test_sensitive_environment_refuses_prior_run_private_list(
    private_run: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], entry: str,
) -> None:
    private = private_run / "operator-inputs/sensitive-users.txt"
    monkeypatch.setenv("AUDITEX_SENSITIVE_USERS_FILE", str(private))
    monkeypatch.setattr(engine_cli, "run_offline", lambda *args, **kwargs: pytest.fail("unsafe input consumed"))
    monkeypatch.setattr(product_cli, "run_guided", lambda *args, **kwargs: pytest.fail("unsafe input consumed"))
    result = (engine_cli.main(["--offline"]) if entry == "engine" else
              product_cli.main(["run", "--offline"]) if entry == "run" else
              product_cli.main(["guided-run", "--non-interactive"]))
    output = capsys.readouterr()
    assert result == 2 and "Refusing sensitive-users:" in output.err
    assert private.read_text().strip() not in output.out + output.err


def test_sensitive_flag_overrides_private_environment(
    private_run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = tmp_path / "selected-sensitive.txt"
    selected.write_text("chosen@example.invalid\n", encoding="utf-8")
    monkeypatch.setenv("AUDITEX_SENSITIVE_USERS_FILE", str(private_run / "operator-inputs/sensitive-users.txt"))
    monkeypatch.setattr(engine_cli, "run_offline", lambda *args, **kwargs: 0)
    monkeypatch.setattr(product_cli, "run_guided", lambda *args, **kwargs: 0)
    assert engine_cli.main(["--offline", "--sensitive-users", str(selected)]) == 0
    assert product_cli.main(["guided-run", "--sensitive-users", str(selected)]) == 0


def test_sensitive_environment_from_guarded_env_file_refuses_private_list(
    private_run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    settings = tmp_path / "settings.env"
    settings.write_text(f"AUDITEX_SENSITIVE_USERS_FILE={private_run / 'operator-inputs/sensitive-users.txt'}\n")
    monkeypatch.delenv("AUDITEX_SENSITIVE_USERS_FILE", raising=False)
    monkeypatch.setattr(engine_cli, "run_offline", lambda *args, **kwargs: pytest.fail("unsafe input consumed"))
    assert engine_cli.main(["--offline", "--env", str(settings)]) == 2
    output = capsys.readouterr()
    assert "Refusing sensitive-users:" in output.err
