"""PyPI install route (#145) and the packaging review findings on PR #151."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from auditex import bootstrap

_REAL_INSTALLED_FROM_FILE = getattr(bootstrap, "_installed_from_file", None)


@pytest.fixture
def installed_package(monkeypatch, tmp_path: Path) -> Path:
    """Auditex as an installed package (no source checkout) in an environment rooted at tmp_path."""
    monkeypatch.setattr(bootstrap, "is_source_checkout", lambda: False)
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    monkeypatch.setattr(bootstrap, "_extra_installed", lambda extra: False, raising=False)
    monkeypatch.setattr(bootstrap, "_installed_from_file", lambda: None, raising=False)
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


# -- #145: the PyPI route. The built wheel carries PyPI-ready metadata, and a pip install of it into a fresh venv
# gives working `auditex` commands outside the source tree (what `pipx install auditex` does). Nothing is uploaded.

@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory) -> Path:
    pytest.importorskip("setuptools.build_meta")
    from test_packaging_install import _build_wheel

    return _build_wheel(tmp_path_factory.mktemp("pypi-wheel"))


def _wheel_metadata(wheel: Path) -> list[tuple[str, str]]:
    import zipfile

    with zipfile.ZipFile(wheel) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        head = archive.read(name).decode("utf-8").split("\n\n", 1)[0]
    return [tuple(part.strip() for part in line.split(":", 1)) for line in head.splitlines() if ":" in line]


def test_the_wheel_metadata_is_fit_for_pypi(built_wheel: Path) -> None:
    fields = _wheel_metadata(built_wheel)
    values = lambda key: [v for k, v in fields if k == key]  # noqa: E731
    assert values("Name") == ["auditex"]
    assert values("Requires-Python") == [">=3.11"]
    assert values("Description-Content-Type") == ["text/markdown"]
    urls = {v.split(",", 1)[0].strip().lower() for v in values("Project-URL")}
    assert {"homepage", "repository", "issues", "changelog"} <= urls
    assert "Homepage, https://magrathean.uk/solutions/auditex/" in values("Project-URL")
    classifiers = values("Classifier")
    assert "Operating System :: POSIX :: Linux" in classifiers and "Operating System :: MacOS" in classifiers
    assert not [c for c in classifiers if "Windows" in c]
    for minor in (11, 12, 13, 14):
        assert f"Programming Language :: Python :: 3.{minor}" in classifiers
    assert values("Keywords")


def test_a_pip_installed_wheel_runs_version_and_doctor_outside_the_source_tree(built_wheel: Path, tmp_path: Path) -> None:
    import json
    import os
    import subprocess
    import sysconfig
    import tomllib
    import venv

    target = tmp_path / "venv"
    venv.EnvBuilder(with_pip=True).create(target)
    python = target / "bin" / "python"
    env = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "AUDITEX_RESOURCE_ROOT", "PIP_INDEX_URL"}}
    install = subprocess.run([str(python), "-m", "pip", "install", "--quiet", "--no-index", "--no-deps",
                              "--disable-pip-version-check", str(built_wheel)],
                             cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    assert install.returncode == 0, install.stderr[-3000:]
    # Third-party dependencies (requests, msal, cryptography) come from the test interpreter, after the venv's own
    # site-packages, so the run stays offline; Auditex itself is only the installed wheel.
    site = Path(subprocess.check_output([str(python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
                                        text=True).strip())
    (site / "zz-test-dependencies.pth").write_text(sysconfig.get_paths()["purelib"] + "\n", encoding="utf-8")

    outside = tmp_path / "elsewhere"
    outside.mkdir()
    auditex = target / "bin" / "auditex"
    version = subprocess.run([str(auditex), "--version"], cwd=outside, env=env, capture_output=True, text=True,
                             timeout=120)
    expected = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    assert version.returncode == 0, version.stderr
    assert version.stdout.strip() == f"auditex {expected['project']['version']}"

    doctor = subprocess.run([str(auditex), "doctor", "--json"], cwd=outside, env=env, capture_output=True, text=True,
                            timeout=120)
    assert doctor.returncode == 0, doctor.stderr
    report = json.loads(doctor.stdout)
    assert report["readiness"]["core_ready"] is True, report["readiness"]
    assert Path(report["python"]["path"]).parent == python.parent
    assert "Traceback" not in doctor.stderr


# PR #151 review (greptile): the runbook ran the reproducible-build check with a system python3, whose `make dist`
# then stops on the pinned-setuptools check even after make install filled .venv.
def test_the_runbook_runs_the_reproducible_build_check_with_the_venv_interpreter() -> None:
    runbook = (Path(__file__).resolve().parents[1] / "docs/development/runbook.md").read_text(encoding="utf-8")
    assert "python3 scripts/check-reproducible-build.py" not in runbook
    assert runbook.count(".venv/bin/python scripts/check-reproducible-build.py") == 2


# -- #145: the install guide. The launch website copies these five commands; the guide must show each as a command
# line, and the README and the docs index must lead to it. Docs are shipped by glob, so the wheel carries it.
WEBSITE_COMMANDS = (
    "pipx install auditex",
    'pipx install "auditex[google,mcp]"',
    "auditex --version",
    "auditex doctor",
    "pipx upgrade auditex",
)


def test_the_install_guide_shows_the_website_commands_and_is_linked_and_shipped() -> None:
    from fnmatch import fnmatch

    from azure_tenant_audit.shipped_content import SHIPPED_CONTENT_AREAS

    root = Path(__file__).resolve().parents[1]
    guide = (root / "docs/guides/install-guide.md").read_text(encoding="utf-8")
    command_lines = {line.strip() for line in guide.splitlines()}
    for command in WEBSITE_COMMANDS:
        assert command in command_lines, command
    for section in ("Linux", "macOS", "WSL2", "Upgrade", "Uninstall", "Troubleshooting", "Where run folders go"):
        assert section in guide, section
    assert "](https://github.com/magrathean-uk/auditex/blob/main/docs/guides/install-guide.md)" in (root / "README.md").read_text(encoding="utf-8")
    assert "](guides/install-guide.md)" in (root / "docs/index.md").read_text(encoding="utf-8")
    patterns = [p for area in SHIPPED_CONTENT_AREAS for p in area.package_patterns]
    assert any(fnmatch("docs/guides/install-guide.md", p) for p in patterns)


# -- Repair round 1 on PR #176.

# Review blocker 1: with the Google libraries missing in a plain environment, the install hint carried the running
# interpreter's path, and the blocked probe wrote it into toolchain-readiness.json and probe-result.json.
def test_a_blocked_google_probe_writes_no_interpreter_path_into_the_bundle(installed_package: Path, monkeypatch,
                                                                         capsys) -> None:
    from auditex.google_workspace import auth
    from auditex.google_workspace.run import GoogleRunConfig, run_google_probe

    interpreter = installed_package / "my env" / "bin" / "python3"
    monkeypatch.setattr(sys, "executable", str(interpreter))
    monkeypatch.setattr(auth, "_module_available", lambda module: False)
    out = installed_package / "out"
    rc = run_google_probe(GoogleRunConfig(
        tenant_name="Example", out=out, run_name="blocked", domain="example.com", customer_id="C123",
        subject="admin@example.com", service_account_key=installed_package / "sa.json", collectors="google_directory",
    ))
    capsys.readouterr()
    assert rc == 2
    leaks = [path.name for path in (out / "Example-blocked").rglob("*")
             if path.is_file() and "my env" in path.read_text(encoding="utf-8", errors="replace")]
    assert leaks == []
    hint = auth.google_dependency_status()["install_hint"]
    assert "auditex[google]" in hint and "my env" not in hint


# Review blocker 2: an Auditex installed from a downloaded wheel was sent to the package index for the MCP extra,
# and an interpreter path with a space broke the pasted command.
def test_the_mcp_hint_quotes_an_interpreter_path_with_a_space(installed_package: Path, monkeypatch, capsys) -> None:
    import shlex

    interpreter = "/opt/my tools/auditex env/bin/python3"
    monkeypatch.setattr(sys, "executable", interpreter)
    assert bootstrap.run_setup(with_mcp=True) == 0
    line = next(row for row in capsys.readouterr().out.splitlines() if "MCP server:" in row)
    assert shlex.split(line.split("MCP server:", 1)[1]) == [interpreter, "-m", "pip", "install", "auditex[mcp]"]


def test_a_wheel_install_hint_names_the_wheel_not_the_package_index(installed_package: Path, monkeypatch) -> None:
    import shlex

    wheel = "/home/me/Down loads/auditex-1.0.0-py3-none-any.whl"
    direct_url = '{"url": "file:///home/me/Down%20loads/auditex-1.0.0-py3-none-any.whl", "archive_info": {}}'

    class _Dist:
        def read_text(self, name: str) -> str | None:
            return direct_url if name == "direct_url.json" else None

    monkeypatch.setattr("importlib.metadata.distribution", lambda name: _Dist())
    monkeypatch.setattr(bootstrap, "_installed_from_file", _REAL_INSTALLED_FROM_FILE, raising=False)
    monkeypatch.setattr(sys, "executable", "/usr/bin/python3")
    assert shlex.split(bootstrap.extra_install_command("mcp")) == ["/usr/bin/python3", "-m", "pip", "install",
                                                                   f"{wheel}[mcp]"]
    (installed_package / "pipx_metadata.json").write_text("{}", encoding="utf-8")
    assert shlex.split(bootstrap.extra_install_command("mcp")) == ["pipx", "install", "--force", f"{wheel}[mcp]"]
    # What a run bundle may hold names no local path.
    assert "/home/me" not in bootstrap.extra_install_command("mcp", for_record=True)


ROOT = Path(__file__).resolve().parents[1]
GITHUB_BLOB = "https://github.com/magrathean-uk/auditex/blob/main/"
GITHUB_RAW = "https://raw.githubusercontent.com/magrathean-uk/auditex/main/"


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    following = [text.find(mark, start + len(heading)) for mark in ("\n## ", "\n### ")]
    ends = [pos for pos in following if pos != -1]
    return text[start:min(ends) if ends else len(text)]


# Review blocker 3: after the base install, `pipx install "auditex[google,mcp]"` stops at "already installed" and
# leaves the extras out. Both documents must give the command that installs extras over an existing install.
def test_readme_and_guide_add_extras_over_an_existing_install() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert 'pipx install --force "auditex[google,mcp]"' in readme
    step7 = _section((ROOT / "docs/guides/install-guide.md").read_text(encoding="utf-8"), "## Step 7")
    first_command = next(line.strip() for line in step7.splitlines() if line.strip().startswith("pipx install"))
    assert first_command == 'pipx install --force "auditex[google,mcp]"'
    from auditex.setup_guide import build_google_setup_guide

    assert 'pipx install --force "auditex[google]"' in build_google_setup_guide()["setup_steps"][0]


# Review blocker 4: PyPI shows the README as the project page, where repository-relative links break.
def test_every_readme_link_resolves_on_the_pypi_project_page() -> None:
    import re

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    targets = re.findall(r"\]\(([^)\s]+)\)", readme) + re.findall(r'(?:href|src)="([^"]+)"', readme)
    relative = [t for t in targets if not re.match(r"[a-z][a-z0-9+.-]*:", t) and not t.startswith("#")]
    assert relative == []
    for target in targets:
        for prefix in (GITHUB_BLOB, GITHUB_RAW):
            if target.startswith(prefix):
                assert (ROOT / target[len(prefix):].split("#", 1)[0]).exists(), target


# Review blocker 5: on Ubuntu 22.04 pipx is called before it is on PATH, and the macOS uninstall step named the
# Linux model cache.
def test_the_ubuntu_2204_steps_never_call_pipx_before_it_is_on_path() -> None:
    section = _section((ROOT / "docs/guides/install-guide.md").read_text(encoding="utf-8"), "### Ubuntu 22.04")
    commands = [line.strip() for line in section.splitlines() if line.strip() and not line.startswith(("`", " "))
                and line.strip().split()[0] in {"pipx", "python3", "sudo"}]
    assert "python3 -m pipx ensurepath" in commands
    assert not [c for c in commands if c.startswith("pipx ")]


def test_the_uninstall_steps_name_the_model_cache_local_answer_uses(monkeypatch) -> None:
    from auditex import local_answer

    uninstall = _section((ROOT / "docs/guides/install-guide.md").read_text(encoding="utf-8"), "## Uninstall")
    monkeypatch.delenv("AUDITEX_MODEL_DIR", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/HOME")))
    for system in ("darwin", "linux"):
        monkeypatch.setattr(sys, "platform", system)
        cache = local_answer.model_cache().as_posix().replace("/HOME", "~")
        assert f"`{cache}`" in uninstall, (system, cache)


# Small: the fixed local-answer reason pointed every user at the editable source-checkout install.
def test_the_local_answer_reasons_give_the_installed_package_command() -> None:
    from auditex import local_answer

    for key in ("runtime_missing", "runtime_version"):
        text = local_answer.REASONS[key]
        assert 'pipx install --force "auditex[local-answer]"' in text, key
        assert "/Users/" not in text and "/home/" not in text


# -- Repair round 2 on PR #176.

def _files_holding(run_dir: Path, needle: str) -> list[str]:
    """Every file under run_dir (text, JSON, SQLite or any other bytes) whose content holds needle.

    The one exception is the documented ``run_dir`` field (output-contract.md: ``run-manifest.json`` records where the
    operator ran the audit and the customer pack reduces it to the run folder name), in the manifest and in the copy the
    SQLite index keeps under ``run_meta``. Every other value is swept.
    """
    import json
    import sqlite3

    hits = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name == "run-manifest.json":
            manifest = json.loads(path.read_text(encoding="utf-8"))
            assert manifest.pop("run_dir") == str(run_dir)
            content = json.dumps(manifest).encode("utf-8")
        elif path.suffix == ".sqlite":
            conn = sqlite3.connect(path)
            try:
                tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
                values = [repr(row) for table in tables for row in conn.execute(f'SELECT * FROM "{table}"')
                          if not (table == "run_meta" and row[0] == "run_dir")]
            finally:
                conn.close()
            content = "\n".join(values).encode("utf-8")
        else:
            content = path.read_bytes()
        if needle.encode("utf-8") in content:
            hits.append(str(path.relative_to(run_dir)))
    return hits


# Review blockers 1 and 2: a blocked Google probe (libraries missing) run with an absolute --out and an absolute,
# missing --service-account-key wrote the key path into probe-result.json and the output path into the manifest and
# the SQLite evidence index. A failed probe (libraries present, the key cannot be read) takes the other branch. Sweep
# every file either run writes so no other absolute path can hide.
@pytest.mark.parametrize("libraries", ["missing", "present"])
def test_a_blocked_or_failed_google_probe_writes_no_absolute_path_anywhere(installed_package: Path, monkeypatch,
                                                                           capsys, libraries: str) -> None:
    from auditex import cli
    from auditex.google_workspace import auth

    root = installed_package / "secret place"
    monkeypatch.setattr(sys, "executable", str(root / "env" / "bin" / "python3"))
    if libraries == "missing":
        monkeypatch.setattr(auth, "_module_available", lambda module: False)
    else:
        pytest.importorskip("google.oauth2.service_account")
    out = root / "out"
    rc = cli.main([
        "google", "probe", "--tenant-name", "Example", "--out", str(out), "--run-name", "blocked",
        "--domain", "example.com", "--customer-id", "C123", "--subject", "admin@example.com",
        "--service-account-key", str(root / "keys" / "sa.json"), "--collectors", "google_directory",
    ])
    capsys.readouterr()
    assert rc != 0
    run_dir = out / "Example-blocked"
    assert (run_dir / "probe-result.json").is_file() and (run_dir / "index" / "evidence.sqlite").is_file()
    assert _files_holding(run_dir, str(root)) == []
    assert _files_holding(run_dir, str(installed_package)) == []
