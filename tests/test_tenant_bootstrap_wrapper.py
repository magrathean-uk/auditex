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


NO_NETWORK_SHIM = """
import socket

_MESSAGE = "network disabled in tenant-bootstrap wrapper tests"
_connect = socket.socket.connect
_connect_ex = socket.socket.connect_ex


def _inet(sock):
    return sock.family in (socket.AF_INET, socket.AF_INET6)


def _deny_connect(self, address):
    if _inet(self):
        raise OSError(_MESSAGE)
    return _connect(self, address)


def _deny_connect_ex(self, address):
    if _inet(self):
        raise OSError(_MESSAGE)
    return _connect_ex(self, address)


def _deny_getaddrinfo(*args, **kwargs):
    raise OSError(_MESSAGE)


socket.socket.connect = _deny_connect
socket.socket.connect_ex = _deny_connect_ex
socket.getaddrinfo = _deny_getaddrinfo
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
    # Python in the kit imports this before any script, so a real seeder can never reach Graph.
    shim_dir = tmp_path / "no-network"
    shim_dir.mkdir()
    (shim_dir / "sitecustomize.py").write_text(NO_NETWORK_SHIM, encoding="utf-8")
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
        "PYTHONPATH": os.pathsep.join(filter(None, [str(shim_dir), os.environ.get("PYTHONPATH", "")])),
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



def test_kit_python_cannot_open_network_connections(kit):
    """Wrapper tests run real seeders; the kit's Python must never reach Graph or any other host."""
    import socket

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        proc = subprocess.run(
            ["python3", "-c", f"import socket; socket.create_connection(('127.0.0.1', {port}), timeout=5); print('connected')"],
            env=kit.env, capture_output=True, text=True, timeout=60,
        )
    finally:
        server.close()
    assert "connected" not in proc.stdout
    assert "network disabled in tenant-bootstrap wrapper tests" in proc.stderr


def _lab_max_config(kit, tenant_id: str) -> None:
    path = kit.root / "config.enterprise-lab-max.json"
    cfg = json.loads(path.read_text(encoding="utf-8"))
    cfg["tenant"]["tenantId"] = tenant_id
    path.write_text(json.dumps(cfg), encoding="utf-8")


def test_enterprise_lab_max_live_reaches_the_seeder_guard_under_bash_3(kit):
    # Bash before 4.4 treats an empty "${MODE_ARGS[@]}" as unbound under set -u; Linux bash would hide it.
    assert '"${MODE_ARGS[@]}"' not in (kit.root / "run-enterprise-lab-max.sh").read_text(encoding="utf-8").replace(
        '${MODE_ARGS[@]+"${MODE_ARGS[@]}"}', ""
    )
    _lab_max_config(kit, LAB_TENANT)
    kit.env["FAKE_AZ_TENANT"] = LAB_TENANT
    proc = kit.run("run-enterprise-lab-max.sh", "--live", "--run-name", "labmax-live", "--skip-workload", "--skip-verify")
    output = proc.stdout + proc.stderr
    assert "unbound variable" not in output
    # The fake az returns no usable token, so the identity seeder must refuse before any write.
    assert "identity_seed_az: refused before any write" in output
    assert proc.returncode != 0


def test_token_env_loader_never_puts_the_token_in_a_process_argv(kit):
    import base64
    import time

    claims = base64.urlsafe_b64encode(json.dumps({"tid": LAB_TENANT, "exp": int(time.time()) + 3600}).encode()).decode().rstrip("=")
    token = f"e30.{claims}.signature-part"
    env_file = kit.tmp / "token.env"
    env_file.write_text(f"AZURE_ACCESS_TOKEN={token}\n", encoding="utf-8")
    argv_log = kit.tmp / "python-argv.log"
    spy = kit.tmp / "bin" / "python3"
    spy.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" >> "{argv_log}"\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    script = f'source "{kit.root / "scripts" / "token-env.sh"}"; load_token_env "{env_file}"; echo "rc=$?"; printf "%s" "$AZURE_ACCESS_TOKEN" > "{kit.tmp / "exported"}"'
    proc = subprocess.run(["bash", "-c", script], env=kit.env, capture_output=True, text=True, timeout=60)
    assert "rc=0" in proc.stdout, proc.stdout + proc.stderr
    assert (kit.tmp / "exported").read_text(encoding="utf-8") == token
    assert argv_log.exists()
    assert token not in argv_log.read_text(encoding="utf-8")


@pytest.mark.parametrize("script", ["run-bootstrap-azurecli.sh", "scripts/run-enterprise-audit.sh"])
def test_both_certificate_password_sources_are_refused_before_seeding(kit, script):
    config = kit.config(LAB_TENANT)
    kit.env["FAKE_AZ_TENANT"] = LAB_TENANT
    (kit.tmp / "pw.txt").write_text("x", encoding="utf-8")
    proc = kit.run(
        script, "--config", str(config), "--run-name", "pwboth", "--skip-login",
        "--audit-client-id", "22222222-2222-2222-2222-222222222222",
        "--audit-certificate-path", CERT_PATH,
        "--audit-certificate-thumbprint", THUMBPRINT,
        "--audit-certificate-password-env", "LAB_CERT_PASSWORD",
        "--audit-certificate-password-file", str(kit.tmp / "pw.txt"),
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 2, output
    assert "only one of --audit-certificate-password-env and --audit-certificate-password-file" in output
    assert "identity_seed_az.py" not in kit.shell_log("pwboth")
    assert "identity_seed_az" not in output


def test_enterprise_dry_run_inspect_on_a_fresh_run_exits_zero(kit):
    proc = kit.run("scripts/run-enterprise-audit.sh", "--dry-run", "--inspect", "--run-name", "ent-inspect")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_enterprise_audit_only_dry_run_inspect_skips_the_bootstrap_inspection(kit):
    proc = kit.run(
        "scripts/run-enterprise-audit.sh", "--dry-run", "--skip-bootstrap", "--inspect", "--run-name", "ent-audit-inspect",
        "--audit-client-id", "22222222-2222-2222-2222-222222222222",
        "--audit-certificate-path", CERT_PATH,
        "--audit-certificate-thumbprint", THUMBPRINT,
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert "Run directory not found" not in output
