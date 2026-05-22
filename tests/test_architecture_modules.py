from __future__ import annotations

import json
import sys
from pathlib import Path

from support import RunBundleBuilder


def test_runtime_resources_resolve_from_non_repo_cwd(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    from azure_tenant_audit.contracts import contract_schema_manifest
    from azure_tenant_audit.resources import open_text_resource, resolve_resource_path, shipped_resource_manifest

    config_path = resolve_resource_path("configs/collector-definitions.json")
    config_text = open_text_resource("configs/collector-definitions.json")
    manifest = contract_schema_manifest("schemas")
    shipped = shipped_resource_manifest()

    assert config_path.exists()
    assert '"collectors"' in config_text
    assert "run_manifest.schema.json" in manifest["schemas"]
    assert "configs/collector-definitions.json" in shipped["resources"]
    assert "schemas/run_manifest.schema.json" in shipped["resources"]


def test_shipped_content_truth_matches_packaging_manifest() -> None:
    import tomllib

    from azure_tenant_audit.shipped_content import data_file_manifest, release_content_labels

    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    checklist = Path("docs/RELEASE_CHECKLIST.md").read_text(encoding="utf-8")

    assert pyproject["tool"]["setuptools"]["data-files"] == data_file_manifest()
    for label in release_content_labels():
        assert f"- {label}" in checklist


def test_catalog_validates_registry_config_profiles() -> None:
    from azure_tenant_audit.catalog import load_catalog

    catalog = load_catalog()

    assert catalog.validate() == []
    assert "identity" in catalog.collectors
    assert "global-reader" in catalog.profiles


def test_core_finalizer_owns_evidence_index_without_product_import() -> None:
    source = Path("src/azure_tenant_audit/finalize.py").read_text(encoding="utf-8")

    assert "auditex.evidence_db" not in source


def test_probe_uses_runtime_modules_instead_of_cli_private_helpers() -> None:
    source = Path("src/azure_tenant_audit/probe.py").read_text(encoding="utf-8")

    assert "from .cli import" not in source


def test_run_bundle_reader_centralizes_legacy_and_contract_artifacts(tmp_path: Path) -> None:
    from auditex.run_bundle import RunBundle

    run_dir = (
        RunBundleBuilder(tmp_path)
        .manifest(auth_context_path="auth-context.json")
        .summary_md("# Summary")
        .report_pack(summary={"overall_status": "partial"}, findings=[])
        .blockers([{"collector": "identity"}])
        .auth_context({"name": "saved"})
        .build()
    )

    bundle = RunBundle(run_dir).read()

    assert bundle["manifest"]["tenant_name"] == "acme"
    assert bundle["summary_md"] == "# Summary"
    assert bundle["report_pack"]["summary"]["overall_status"] == "partial"
    assert bundle["blockers"][0]["collector"] == "identity"
    assert bundle["auth_context"]["name"] == "saved"


def test_run_bundle_metadata_exposes_platform_and_risk(tmp_path: Path) -> None:
    from auditex.run_bundle import RunBundle

    run_dir = (
        RunBundleBuilder(tmp_path)
        .manifest(tenant_name="acme", run_id="run-1", overall_status="partial", platform="google_workspace")
        .summary(tenant_name="acme", run_id="run-1", collectors=[], assurance={"score": 90, "grade": "strong"})
        .report_pack(summary={"overall_status": "partial", "risk": {"score": 40, "grade": "high"}}, findings=[])
        .build()
    )

    metadata = RunBundle(run_dir).metadata()

    assert metadata["platform"] == "google_workspace"
    assert metadata["risk"] == {"score": 40, "grade": "high"}
    assert metadata["assurance"] == {"score": 90, "grade": "strong"}


def test_mcp_command_runner_redacts_sensitive_args() -> None:
    from auditex.command_runner import run_cli_command

    result = run_cli_command(
        [
            sys.executable,
            "-c",
            "import sys; print(' '.join(sys.argv[1:]))",
            "--access-token",
            "secret-token",
            "--client-secret=secret-client",
        ]
    )

    rendered = json.dumps(result)
    assert "secret-token" not in rendered
    assert "secret-client" not in rendered
    assert "***redacted***" in rendered
