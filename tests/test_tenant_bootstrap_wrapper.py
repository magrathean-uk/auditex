from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
LAB_TENANT = "11111111-1111-1111-1111-111111111111"
OTHER_TENANT = "99999999-9999-9999-9999-999999999999"
ZERO_TENANT = "00000000-0000-0000-0000-000000000000"
CERT_PATH = "/lab-secret-dir/reader-key.pem"
THUMBPRINT = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"

FAKE_AZ = """#!/bin/sh
# Test double for the Azure CLI: the signed-in session belongs to $FAKE_AZ_TENANT.
echo "$*" >> "$FAKE_AZ_LOG"
if [ "$1 $2" = "account show" ]; then echo "$FAKE_AZ_TENANT"; exit 0; fi
if [ "$1 $2" = "account get-access-token" ]; then
  wanted=""; prev=""
  for arg in "$@"; do
    if [ "$prev" = "--tenant" ]; then wanted="$arg"; fi
    prev="$arg"
  done
  if [ -n "$wanted" ] && [ "$wanted" != "$FAKE_AZ_TENANT" ]; then echo "no access to tenant" >&2; exit 1; fi
  echo "$FAKE_AZ_TENANT"
  exit 0
fi
exit 1
"""


def test_run_audit_collector_prefers_repo_root_runtime() -> None:
    script = Path("tenant-bootstrap/scripts/run-audit-collector.sh").read_text(encoding="utf-8")
    repo_root_index = script.index('if [[ -f "${REPO_ROOT}/src/azure_tenant_audit/cli.py"')
    bootstrap_index = script.index('elif [[ -f "${TENANT_BOOTSTRAP_ROOT}/azure_tenant_audit/cli.py"')
    assert repo_root_index < bootstrap_index


@pytest.fixture
def kit(tmp_path: Path):
    """A throwaway copy of tenant-bootstrap with a fake az on PATH, so no run touches a tenant or the repo."""
    root = tmp_path / "kit" / "tenant-bootstrap"
    shutil.copytree(
        REPO / "tenant-bootstrap",
        root,
        ignore=shutil.ignore_patterns("runs", "audit-output", ".secrets", "fixture-output", "__pycache__", "tests"),
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "az").write_text(FAKE_AZ, encoding="utf-8")
    (bin_dir / "az").chmod(0o755)
    (bin_dir / "python3").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    (bin_dir / "python3").chmod(0o755)
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "HOME": str(tmp_path / "home"),
        "TMPDIR": str(tmp_path),
        "FAKE_AZ_LOG": str(tmp_path / "az.log"),
        "FAKE_AZ_TENANT": OTHER_TENANT,
        "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
        "AUDITEX_M365_HOME": str(tmp_path / "m365-home"),
    }

    class Kit:
        def __init__(self) -> None:
            self.root = root
            self.env = env
            self.tmp = tmp_path

        def config(self, tenant_id: str) -> Path:
            cfg = json.loads((root / "config.example.json").read_text(encoding="utf-8"))
            cfg["tenant"]["tenantId"] = tenant_id
            path = root / "config.lab.json"
            path.write_text(json.dumps(cfg), encoding="utf-8")
            return path

        def token_env(self) -> Path:
            path = root / ".secrets" / "lab-populator-token.env"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("AZURE_ACCESS_TOKEN=not-a-real-token\n", encoding="utf-8")
            return path

        def run(self, script: str, *args: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                ["bash", str(root / script), *args],
                cwd=tmp_path,
                env=env,
                capture_output=True,
                text=True,
                timeout=300,
            )

        def shell_log(self, run_name: str) -> str:
            path = root / "runs" / run_name / "bootstrap-shell.log"
            return path.read_text(encoding="utf-8") if path.exists() else ""

    return Kit()


def test_bootstrap_dry_run_with_defaults_exits_zero(kit):
    proc = kit.run("run-bootstrap-azurecli.sh", "--dry-run", "--run-name", "dry")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Dry-run complete; no tenant writes occurred." in proc.stdout
    manifest = json.loads((kit.root / "runs" / "dry" / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["finalStatus"] == "completed"


def test_bootstrap_dry_run_with_token_env_and_reader_app_runs_collector_dry_run(kit):
    kit.token_env()
    proc = kit.run(
        "run-bootstrap-azurecli.sh", "--dry-run", "--run-name", "dry-audit",
        "--skip-identity", "--skip-workload", "--skip-verify",
        "--audit-client-id", "22222222-2222-2222-2222-222222222222",
        "--audit-certificate-path", CERT_PATH,
        "--audit-certificate-thumbprint", THUMBPRINT,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Audit dry run command:" in proc.stdout
    assert "--token-env" not in proc.stdout + proc.stderr
    shell_log = kit.shell_log("dry-audit")
    assert "run-audit-collector.sh" in shell_log
    assert CERT_PATH not in shell_log and THUMBPRINT not in shell_log


def test_enterprise_dry_run_with_token_env_exits_zero(kit):
    kit.token_env()
    proc = kit.run("scripts/run-enterprise-audit.sh", "--dry-run", "--run-name", "ent-dry")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "--token-env was removed" not in proc.stdout + proc.stderr


def test_enterprise_dry_run_audit_only_redacts_reader_app_certificate(kit):
    proc = kit.run(
        "scripts/run-enterprise-audit.sh", "--dry-run", "--skip-bootstrap", "--run-name", "ent-audit",
        "--audit-client-id", "22222222-2222-2222-2222-222222222222",
        "--audit-certificate-path", CERT_PATH,
        "--audit-certificate-thumbprint", THUMBPRINT,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Audit dry run command:" in proc.stdout
    assert CERT_PATH not in proc.stdout + proc.stderr
    assert THUMBPRINT not in proc.stdout + proc.stderr


def test_bootstrap_refuses_az_session_in_another_tenant_before_seeding(kit):
    config = kit.config(LAB_TENANT)
    proc = kit.run("run-bootstrap-azurecli.sh", "--config", str(config), "--run-name", "live", "--skip-login", "--skip-audit")
    assert proc.returncode != 0
    assert "tenant_mismatch" in proc.stdout + proc.stderr
    shell_log = kit.shell_log("live")
    assert "identity_seed_az.py" not in shell_log and "seed-workload-az.py" not in shell_log


def test_bootstrap_refuses_placeholder_tenant_before_any_az_call(kit):
    config = kit.config(ZERO_TENANT)
    kit.env["FAKE_AZ_TENANT"] = ZERO_TENANT
    proc = kit.run("run-bootstrap-azurecli.sh", "--config", str(config), "--run-name", "zero", "--skip-login", "--skip-audit")
    assert proc.returncode != 0
    assert "tenant_id_required" in proc.stdout + proc.stderr
    assert "identity_seed_az.py" not in kit.shell_log("zero")
    log = kit.tmp / "az.log"
    assert not log.exists() or log.read_text(encoding="utf-8") == ""


def test_bootstrap_live_audit_without_reader_app_refuses_before_seeding(kit):
    config = kit.config(LAB_TENANT)
    kit.env["FAKE_AZ_TENANT"] = LAB_TENANT
    proc = kit.run("run-bootstrap-azurecli.sh", "--config", str(config), "--run-name", "noaudit", "--skip-login")
    assert proc.returncode != 0
    assert "--audit-certificate-path" in proc.stdout + proc.stderr
    assert "identity_seed_az.py" not in kit.shell_log("noaudit")


def test_enterprise_tenant_id_reaches_bootstrap_and_must_match_config(kit):
    config = kit.config(LAB_TENANT)
    proc = kit.run(
        "scripts/run-enterprise-audit.sh", "--dry-run", "--skip-audit", "--run-name", "ent-tid",
        "--config", str(config), "--tenant-id", OTHER_TENANT,
    )
    assert proc.returncode != 0
    assert "tenant_mismatch" in proc.stdout + proc.stderr
    assert "identity_seed_az.py" not in kit.shell_log("ent-tid")


def test_run_auditor_forwards_only_options_the_collector_accepts(kit):
    recorder = kit.tmp / "python-argv.txt"
    fake_python = kit.tmp / "bin" / "fake-python"
    fake_python.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{recorder}"\nexit 0\n', encoding="utf-8")
    fake_python.chmod(0o755)
    kit.env["PYTHON_BIN"] = str(fake_python)
    proc = kit.run(
        "scripts/run-auditor.sh", "--tenant-id", LAB_TENANT, "--run-name", "auditor",
        "--client-id", "22222222-2222-2222-2222-222222222222",
        "--certificate-path", CERT_PATH, "--certificate-thumbprint", THUMBPRINT,
        "--out", str(kit.tmp / "audit-out"),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    argv = recorder.read_text(encoding="utf-8").splitlines()
    assert argv[argv.index("--tenant-id") + 1] == LAB_TENANT
    assert argv[argv.index("--certificate-thumbprint") + 1] == THUMBPRINT


def test_enterprise_lab_max_default_dry_run_exits_zero(kit):
    proc = kit.run("run-enterprise-lab-max.sh", "--run-name", "labmax-dry")
    assert proc.returncode == 0, proc.stdout + proc.stderr

