"""Deep-review fixes for packaging and release (lane packaging-release-scripts)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from azure_tenant_audit import resources

ROOT = Path(__file__).resolve().parents[1]


def _plant_foreign_checkout(base: Path) -> Path:
    project = base / "foreign"
    (project / "configs").mkdir(parents=True)
    (project / "docs").mkdir()
    (project / "pyproject.toml").write_text('[project]\nname = "someone-else"\nversion = "0.1"\n', encoding="utf-8")
    (project / "configs" / "collector-definitions.json").write_text(json.dumps({"collectors": {}}), encoding="utf-8")
    (project / "docs" / "planted.md").write_text("# planted\n", encoding="utf-8")
    (project / "sub").mkdir()
    return project


# R069 / R119 / R159: a checkout-like folder at or above the cwd must not replace shipped resources.
def test_cwd_ancestor_checkout_does_not_shadow_shipped_resources(tmp_path, monkeypatch):
    monkeypatch.delenv(resources.RESOURCE_ROOT_ENV, raising=False)
    project = _plant_foreign_checkout(tmp_path)
    monkeypatch.chdir(project / "sub")
    planted = project / "configs" / "collector-definitions.json"

    resolved = resources.resolve_resource_path("configs/collector-definitions.json")
    assert resolved.resolve() != planted.resolve(), resolved
    assert all(adapter.root.resolve() != project.resolve() for adapter in resources._resource_adapters())
    assert not resources.is_shipped_resource(planted)
    assert "planted.md" not in {path.name for path in resources.list_resource_files("docs", "*.md")}


def test_resource_root_env_is_the_explicit_override(tmp_path, monkeypatch):
    project = _plant_foreign_checkout(tmp_path)
    monkeypatch.setenv(resources.RESOURCE_ROOT_ENV, str(project))
    resolved = resources.resolve_resource_path("configs/collector-definitions.json")
    assert resolved == project / "configs" / "collector-definitions.json"


def test_own_checkout_is_still_a_dev_root(monkeypatch):
    monkeypatch.delenv(resources.RESOURCE_ROOT_ENV, raising=False)
    if not (ROOT / "pyproject.toml").exists():
        pytest.skip("not running from a source checkout")
    dev_roots = [adapter.root.resolve() for adapter in resources._resource_adapters() if adapter.name == "dev"]
    assert dev_roots == [ROOT.resolve()]


# R071: an editable install whose metadata is stale must still report the source tree's version.
def _source_version() -> str:
    import tomllib

    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def test_source_checkout_version_wins_over_stale_install_metadata(monkeypatch):
    from azure_tenant_audit import versioning

    if not (ROOT / "pyproject.toml").exists():
        pytest.skip("not running from a source checkout")
    monkeypatch.setattr(versioning, "version", lambda name: "0.0.1-stale", raising=False)
    versioning.package_version.cache_clear()
    try:
        assert versioning.package_version() == _source_version()
        assert versioning.package_user_agent() == f"auditex/{_source_version()}"
    finally:
        versioning.package_version.cache_clear()


def test_explorer_generator_label_uses_the_shared_version(monkeypatch):
    from auditex import explorer

    monkeypatch.setattr("azure_tenant_audit.versioning.package_version", lambda: "7.7.7")
    assert explorer._generator_label() == "Auditex 7.7.7"


# R095: the certificate loader uses cryptography 42+ APIs, so the package must declare that floor.
def test_cryptography_floor_is_declared_and_its_apis_exist():
    import re
    import tomllib

    from cryptography import x509

    dependencies = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
    floors = [re.search(r">=\s*(\d+)", dep) for dep in dependencies if re.match(r"cryptography\b", dep)]
    assert floors and floors[0] and int(floors[0].group(1)) >= 42, dependencies
    assert hasattr(x509.Certificate, "not_valid_before_utc") and hasattr(x509.Certificate, "not_valid_after_utc")
    assert callable(x509.load_pem_x509_certificates)


# Impact of R069: a relative path the operator names (a sample of their own) resolves against the cwd once no
# resource root holds it, while shipped resources keep winning over same-named files in the cwd.
def test_relative_operator_file_resolves_against_the_cwd(tmp_path, monkeypatch):
    from azure_tenant_audit.cli import run_offline

    monkeypatch.delenv(resources.RESOURCE_ROOT_ENV, raising=False)
    (tmp_path / "mine.json").write_bytes((ROOT / "examples/sample_audit_bundle/sample_result.json").read_bytes())
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "collector-definitions.json").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert resources.resolve_resource_path("mine.json") == tmp_path / "mine.json"
    assert resources.resolve_resource_path("configs/collector-definitions.json") != tmp_path / "configs" / "collector-definitions.json"
    assert not resources.is_shipped_resource("configs/not-shipped-here.json")
    assert run_offline(Path("mine.json"), tmp_path / "out", "t", "r") == 0
