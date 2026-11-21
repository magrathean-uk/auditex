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
