from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from support import RunBundleBuilder


# Keep a text scan as a second net alongside the AST scan below.
_PRODUCT_IMPORT = re.compile(
    r"\bfrom\s+auditex\b"
    r"|\bimport\s+(?:[\w.]+(?:\s+as\s+\w+)?\s*,\s*)*auditex\b"
    r"|[\"']auditex\.[\w.]+[\"']"
    r"|\b(?:import_module|__import__)\s*\(\s*[\"']auditex[\"']"
)


# These exact lines use the bare product name as data, never as an import target.
# Exemptions apply only to string constants, not Import or ImportFrom nodes.
_PRODUCT_DATA_LINES = {
    "m365_home.py": {'return (Path(data_home).expanduser() / "auditex" / "m365").resolve()'},
    "resources.py": {
        'installed_candidates.append(Path(data_path) / "auditex")',
        'installed_candidates.extend([Path(sys.prefix) / "auditex", Path(sys.base_prefix) / "auditex"])',
    },
    "versioning.py": {
        'return version("auditex")',
        'def package_user_agent(product_name: str = "auditex") -> str:',
        'def package_version_line(product_name: str = "auditex") -> str:',
    },
}


def _product_references(source: str, *, data_lines: set[str] | None = None) -> list[str]:
    def is_product(value: str) -> bool:
        return value == "auditex" or value.startswith(("auditex.", "auditex:"))

    violations = []
    lines = source.splitlines()
    for node in ast.walk(ast.parse(source)):
        names = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            # ast.walk also visits each literal part of a JoinedStr (f-string).
            if node.value == "auditex" and lines[node.lineno - 1].strip() in (data_lines or set()):
                continue
            names = [node.value]
        for name in names:
            if is_product(name):
                violations.append(f"{node.lineno}: {name}")
    for match in _PRODUCT_IMPORT.finditer(source):
        line = source.count("\n", 0, match.start()) + 1
        violations.append(f"{line}: {match.group()}")
    return violations


def test_engine_source_never_imports_product() -> None:
    engine_root = Path(__file__).resolve().parents[1] / "src" / "azure_tenant_audit"
    paths = sorted(engine_root.rglob("*.py"))
    assert len(paths) > 50, f"Engine scan found only {len(paths)} files in {engine_root}"
    violations = []
    for path in paths:
        source = path.read_text(encoding="utf-8")
        data_lines = _PRODUCT_DATA_LINES.get(path.relative_to(engine_root).as_posix())
        violations.extend(f"{path}:{hit}" for hit in _product_references(source, data_lines=data_lines))
    print(f"Engine source files scanned: {len(paths)} ({engine_root})")
    assert not violations, "Engine imports product:\n" + "\n".join(violations)


@pytest.mark.parametrize("source", [
    "import auditex",
    "import os, auditex.auth as auth",
    "def lazy():\n    from auditex.google_workspace.collectors import REGISTRY",
    'importlib.import_module("auditex.auth")',
    "__import__('auditex')",
    'importlib.import_module(\n    "auditex"\n)',
    'module_name = "auditex.auth"\nimport_module(module_name)',
    'import_module(f"auditex.{x}")',
    'import_module("auditex." + x)',
    'pkg = "auditex"\nimport_module(pkg + ".auth")',
    'resolve_name("auditex.auth:x")',
    'resolve_name("auditex:auth")',
    'import_module(name="auditex")',
    'from auditex import auth',
    'import_module("auditex" ".auth")',
    'import_module(f"{prefix}auditex.{x}")',
])
def test_engine_import_guard_catches_lazy_and_dynamic_imports(source: str) -> None:
    assert _product_references(source)


@pytest.mark.parametrize("catalog", [{}, {"google_users": {"required_scopes": []}}])
def test_google_finalizer_warns_only_when_provider_catalogue_is_empty(monkeypatch, caplog, catalog) -> None:
    from azure_tenant_audit import finalize, provider_registry

    monkeypatch.setattr(provider_registry, "_loaders", {
        "google_workspace": lambda: catalog,
    })
    result = finalize._collector_scope_catalog("google_workspace")

    assert bool(result) == bool(catalog)
    if not catalog:
        assert "google_workspace" in caplog.text
        assert "azure_tenant_audit.provider_registry" in caplog.text
        assert caplog.records[0].levelname == "WARNING"
    else:
        assert not caplog.records


def test_engine_runs_with_product_imports_blocked(tmp_path: Path) -> None:
    script = '''
import base64
import json
import os
import sys
from pathlib import Path

attempted_product_imports = []

class NoProduct:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "auditex" or fullname.startswith("auditex."):
            attempted_product_imports.append(fullname)
            raise AssertionError(f"Product import attempted: {fullname}")

sys.meta_path.insert(0, NoProduct())
from azure_tenant_audit import main, auth_context, auth_runtime, contracts, scope_catalog
from azure_tenant_audit.graph import GraphClient
from azure_tenant_audit import probe, response, finalize

assert scope_catalog.build_google_scope_catalog() == {}
assert finalize._collector_scope_catalog("google_workspace") == {}
issues = []
contracts._validate_finding_collectors([
    {"id": "m365", "collector": "identity"},
    {"id": "unknown", "collector": "not_a_collector"},
], issues)
assert [issue["code"] for issue in issues] == ["unknown_finding_collector"]

# Use only a synthetic context in pytest's temporary directory.
store_path = Path(sys.argv[1]) / "contexts.json"
os.environ["AUDITEX_AUTH_CONTEXTS_PATH"] = str(store_path)
claims = {"tenant_id": "fixture", "audience": "https://graph.microsoft.com",
          "delegated_scopes": ["Directory.Read.All"], "expires_at_utc": "2099-01-01T00:00:00Z"}
context = {"name": "fixture", "tenant_id": "fixture", "token_file": "fixture.token", "token_claims": claims}
store_path.write_text(json.dumps({"active_context": "fixture", "contexts": {"fixture": context}}))
token_path = auth_context.default_token_path("fixture", "fixture.token")
payload = base64.urlsafe_b64encode(json.dumps({"tid": "fixture"}).encode()).decode().rstrip("=")
token = ".".join(("e30", payload, "sig"))
token_path.write_text(token + "\\n")
assert auth_context.resolve_auth_context()["token"] == token
assert auth_runtime.inspect_access_token(token)["tenant_id"] == "fixture"
client = GraphClient.__new__(GraphClient)
client._token_claims = None
client.ensure_token = lambda: token
assert client.token_claims()["tenant_id"] == "fixture"
assert response._resolve_saved_auth_context("fixture")["token"] == token
try:
    main(["--help"])
except SystemExit as exc:
    assert exc.code == 0
assert not any(name == "auditex" or name.startswith("auditex.") for name in sys.modules)
assert not attempted_product_imports, f"Product imports attempted: {attempted_product_imports}"
print("engine standalone: ok")
'''
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "engine standalone: ok" in result.stdout


@pytest.mark.parametrize("entry_point", [
    "auditex", "auditex.cli", "auditex.mcp_server", "auditex.exporters", "auditex.reporting",
])
def test_product_entry_points_register_google_metadata(entry_point: str) -> None:
    script = '''
import importlib
import json
import sys
from azure_tenant_audit.scope_catalog import build_google_scope_catalog
from azure_tenant_audit.contracts import _validate_finding_collectors
from azure_tenant_audit.provider_registry import provider_collectors

assert build_google_scope_catalog() == {}
importlib.import_module(sys.argv[1])
if sys.argv[1] == "auditex":
    assert "auditex.google_workspace.collectors" not in sys.modules
catalog = build_google_scope_catalog()
from auditex.google_workspace.collectors import REGISTRY
assert provider_collectors("google_workspace") is REGISTRY
assert json.dumps(catalog) == json.dumps(build_google_scope_catalog(registry=REGISTRY))
assert build_google_scope_catalog(registry={}) == {}
issues = []
_validate_finding_collectors([{"id": name, "collector": name} for name in REGISTRY], issues)
assert issues == [], issues
'''
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, entry_point],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


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

    from azure_tenant_audit.shipped_content import data_file_manifest, shipped_directories

    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["tool"]["setuptools"]["data-files"] == data_file_manifest()
    for directory in shipped_directories():
        assert Path(directory).exists()


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



def test_release_smoke_script_covers_base_google_and_mcp_matrix() -> None:
    source = Path("scripts/release-smoke.sh").read_text(encoding="utf-8")

    assert "auditex run --offline" in source
    assert "\"${artifact}[google]\"" in source
    assert "\"auditex\", \"google\", \"doctor\", \"--json\"" in source
    assert "\"${artifact}[mcp]\"" in source
    assert "for kind in wheel sdist" in source
    assert "SDIST_PATH" in source
    assert "from mcp.server.fastmcp import FastMCP" in source


def test_graph_user_agent_does_not_hardcode_package_version() -> None:
    source = Path("src/azure_tenant_audit/graph.py").read_text(encoding="utf-8")

    assert "auditex/1.0.0" not in source
    assert "package_user_agent()" in source


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
