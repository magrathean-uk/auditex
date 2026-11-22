"""The built wheel, installed outside the checkout, behaves as a customer install (R072, R069, R140)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tomllib
import venv
import zipfile
from pathlib import Path

import pytest

from azure_tenant_audit.shipped_content import SHIPPED_CONTENT_AREAS

ROOT = Path(__file__).resolve().parents[1]


def _build_wheel(tmp: Path) -> Path:
    project = tmp / "project"
    project.mkdir()
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copyfile(ROOT / name, project / name)
    shutil.copytree(ROOT / "src", project / "src", ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    for area in SHIPPED_CONTENT_AREAS:
        for pattern in area.package_patterns:
            for source in ROOT.glob(pattern):
                if source.is_file():
                    dest = project / source.relative_to(ROOT)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, dest)
    dist = tmp / "dist"
    dist.mkdir()
    code = "from setuptools.build_meta import build_wheel; build_wheel(" + repr(str(dist)) + ")"
    built = subprocess.run([sys.executable, "-B", "-I", "-c", code], cwd=project, capture_output=True, text=True, timeout=120)
    assert built.returncode == 0, built.stderr[-3000:]
    return next(dist.glob("*.whl"))


def _install(wheel: Path, target: Path) -> Path:
    """Unpack the wheel by the standard schemes into a fresh venv; no pip and no network."""
    venv.EnvBuilder(with_pip=False).create(target)
    python = target / "bin" / "python"
    paths = json.loads(subprocess.check_output(
        [str(python), "-B", "-I", "-c", "import sysconfig, json; print(json.dumps(sysconfig.get_paths()))"], text=True))
    site = Path(paths["purelib"])
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.namelist():
            if member.endswith("/"):
                continue
            relative = Path(member)
            if ".data" in relative.parts[0]:
                scheme, *tail = relative.parts[1:]
                assert scheme == "data", member
                destination = target.joinpath(*tail)
            else:
                destination = site / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(archive.read(member))
    return python


@pytest.fixture(scope="module")
def installed(tmp_path_factory) -> Path:
    pytest.importorskip("setuptools.build_meta")
    tmp = tmp_path_factory.mktemp("installed-wheel")
    return _install(_build_wheel(tmp), tmp / "venv")


def _run(python: Path, code: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    # Third-party dependencies come from the test interpreter's site-packages, appended after the wheel's own.
    prelude = "import sys; sys.path.append(" + repr(sysconfig.get_paths()["purelib"]) + ")\n"
    env = {key: value for key, value in os.environ.items() if key not in {"AUDITEX_RESOURCE_ROOT", "PYTHONPATH"}}
    return subprocess.run([str(python), "-B", "-I", "-c", prelude + code], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=120)


def test_installed_doctor_reports_core_ready(installed: Path, tmp_path: Path) -> None:
    code = r"""
import json
from pathlib import Path
from auditex import bootstrap, cli
assert Path(bootstrap.__file__).is_relative_to(Path(sys.executable).parents[1]), bootstrap.__file__
report = bootstrap.build_doctor_report()
print(json.dumps({"readiness": report["readiness"], "python": report["python"]["path"]}))
raise SystemExit(cli.main(["doctor"]))
"""
    run = _run(installed, code, tmp_path)
    assert run.returncode == 0, run.stderr
    first, _, text = run.stdout.partition("\n")
    payload = json.loads(first)
    assert payload["readiness"]["core_ready"] is True, payload
    assert payload["readiness"]["core_missing"] == []
    assert Path(payload["python"]).parent == installed.parent
    assert "Core ready: yes" in text


def test_installed_setup_prints_manual_steps_without_a_traceback(installed: Path, tmp_path: Path) -> None:
    code = "from auditex import cli\nraise SystemExit(cli.main(['setup', '--exchange', '--pwsh', '--mcp']))\n"
    run = _run(installed, code, tmp_path)
    assert run.returncode == 0, run.stderr
    assert "Traceback" not in run.stderr
    assert "installed package" in run.stdout
    assert "auditex[mcp]" in run.stdout


def test_installed_resources_ignore_a_checkout_cwd(installed: Path) -> None:
    # R069 / R140: run from the source checkout itself; the installed package must still read only its own data.
    code = r"""
import json
from azure_tenant_audit import resources, versioning
adapters = resources._resource_adapters()
print(json.dumps({"adapters": [a.name for a in adapters], "version": versioning.package_version()}))
"""
    run = _run(installed, code, ROOT)
    assert run.returncode == 0, run.stderr
    payload = json.loads(run.stdout)
    assert payload["adapters"] and set(payload["adapters"]) == {"installed"}, payload
    assert payload["version"] == tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
