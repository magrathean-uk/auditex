"""Tenant and run names become part of a run directory name; they must not place a bundle elsewhere."""
from __future__ import annotations

from pathlib import Path

import pytest

from azure_tenant_audit.output import AuditWriter, validate_bundle_name


@pytest.mark.parametrize(
    "name",
    ["../../../escape/pwned", "..", "a/b", "/abs", "a\\b", "..\\..\\x", "x..y", "bad\x00name", "bad\nname", "tab\tname", "del\x7fname"],
)
def test_validate_bundle_name_rejects_traversal_separators_and_control_characters(name: str) -> None:
    with pytest.raises(ValueError):
        validate_bundle_name(name, "tenant name")


@pytest.mark.parametrize("name", ["contoso", "Acme Holdings", "ci-contract", "run_20261022_120000", "a.b", "Contoso (EU)", "ünï"])
def test_validate_bundle_name_accepts_ordinary_names(name: str) -> None:
    assert validate_bundle_name(name, "tenant name") == name


def test_validate_bundle_name_passes_none() -> None:
    assert validate_bundle_name(None, "run name") is None


def test_a_traversing_tenant_name_writes_nothing_outside_the_output_directory(tmp_path: Path) -> None:
    out = tmp_path / "root" / "out"
    out.mkdir(parents=True)

    with pytest.raises(ValueError):
        AuditWriter(out, tenant_name="../../../escape/pwned", run_name="r1")
    with pytest.raises(ValueError):
        AuditWriter(out, tenant_name="contoso", run_name="../../escape")

    assert sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")) == ["root", "root/out"]


def test_an_ordinary_name_still_builds_its_run_directory_under_the_output_directory(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="contoso", run_name="r1")

    assert writer.run_dir == tmp_path / "contoso-r1"
    assert writer.run_dir.is_dir()


def test_an_explicit_run_directory_is_the_callers_choice(tmp_path: Path) -> None:
    run_dir = tmp_path / "chosen"

    writer = AuditWriter(tmp_path, tenant_name="contoso", run_dir=run_dir)

    assert writer.run_dir == run_dir
