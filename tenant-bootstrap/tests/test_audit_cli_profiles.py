from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT))
cli = importlib.import_module("azure_tenant_audit.cli")
output = importlib.import_module("azure_tenant_audit.output")
profiles = importlib.import_module("azure_tenant_audit.profiles")


def test_build_parser_accepts_auditor_profile():
    parser = cli.build_parser()

    args = parser.parse_args(["--auditor-profile", "global-reader"])

    assert args.auditor_profile == "global-reader"


def test_invalid_auditor_profile_fails():
    parser = cli.build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["--auditor-profile", "viewer-only"])


def test_profiles_module_exposes_global_reader_contract():
    assert "global-reader" in profiles.profile_choices()
    profile = profiles.get_profile("global-reader")
    assert profile.name == "global-reader"
    assert "inventory" in profile.supported_planes
    assert "full" in profile.supported_planes


def test_build_parser_accepts_plane_and_time_window():
    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "--auditor-profile",
            "global-reader",
            "--plane",
            "full",
            "--since",
            "2026-04-01T00:00:00Z",
            "--until",
            "2026-04-02T00:00:00Z",
        ]
    )
    assert args.plane == "full"
    assert args.since == "2026-04-01T00:00:00Z"
    assert args.until == "2026-04-02T00:00:00Z"


def test_build_parser_rejects_unimplemented_response_plane():
    parser = cli.build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["--auditor-profile", "global-reader", "--plane", "response"])


def test_run_bundle_records_auditor_profile(tmp_path: Path):
    writer = output.AuditWriter(tmp_path, tenant_name="tenant", run_name="profile-test")
    writer.write_bundle(
        {
            "executed_by": "azure_tenant_audit",
            "collectors": ["identity"],
            "overall_status": "ok",
            "duration_seconds": 0.5,
            "mode": "live",
            "auditor_profile": "global-reader",
            "plane": "inventory",
            "since": "2026-04-01T00:00:00Z",
            "until": "2026-04-02T00:00:00Z",
            "session_context": {},
            "command_line": ["python", "-m", "azure_tenant_audit"],
        }
    )

    manifest = json.loads((writer.run_dir / "run-manifest.json").read_text(encoding="utf-8"))

    assert manifest["auditor_profile"] == "global-reader"
    assert manifest["plane"] == "inventory"
    assert manifest["time_window"]["since"] == "2026-04-01T00:00:00Z"
    assert manifest["time_window"]["until"] == "2026-04-02T00:00:00Z"


def test_audit_command_log_only_records_command_events(tmp_path: Path):
    logger = output.AuditLogger(tmp_path)
    logger.log("command.started", "command start")
    logger.log("graph.request.started", "graph request")
    logger.log("command.completed", "command complete")
    logger.log("collector.started", "collector start")
    logger.log("command.failed", "command failed")

    command_events = [
        json.loads(line)
        for line in (tmp_path / "audit-command-log.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    events = {entry["event"] for entry in command_events}

    assert events == {"command.started", "command.completed", "command.failed"}


# The lab collector script runs only with the reader app's certificate (DEC-107, DEC-108) ----------------------

import os  # noqa: E402
import subprocess  # noqa: E402

COLLECTOR_SCRIPT = ROOT / "scripts" / "run-audit-collector.sh"
LAB_CERTIFICATE = [
    "--tenant-id", "constructed.onmicrosoft.com", "--client-id", "constructed-app",
    "--certificate-path", "lab-reader-app.pem", "--certificate-thumbprint", "0" * 40,
]


# The fake Python boundary: blocks every socket, records what the script really executes, then runs the engine.
BOUNDARY = """
import atexit, json, os, runpy, socket, sys
attempts = []
def refuse(*args, **kwargs):
    attempts.append(repr(args[:2]))
    raise OSError("network blocked in test")
socket.socket.connect = socket.create_connection = socket.getaddrinfo = refuse
record = {"argv": sys.argv[1:], "cwd": os.getcwd(), "pythonpath": os.environ.get("PYTHONPATH", "")}
def write():
    record["attempts"] = attempts
    with open(os.environ["LAB_BOUNDARY_LOG"], "w", encoding="utf-8") as handle:
        json.dump(record, handle)
atexit.register(write)
assert sys.argv[1:3] == ["-m", "azure_tenant_audit"], sys.argv
if os.environ.get("LAB_BOUNDARY_RUN") == "1":
    sys.argv = ["azure_tenant_audit", *sys.argv[3:]]
    runpy.run_module("azure_tenant_audit", run_name="__main__", alter_sys=True)
"""


def _boundary(tmp_path: Path, *, run: bool) -> dict[str, str]:
    script = tmp_path / "boundary.py"
    script.write_text(BOUNDARY, encoding="utf-8")
    fake_python = tmp_path / "fake-python"
    fake_python.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
    fake_python.chmod(0o700)
    return {"PYTHON_BIN": str(fake_python), "LAB_BOUNDARY_LOG": str(tmp_path / "boundary.json"),
            "LAB_BOUNDARY_RUN": "1" if run else "0"}


def _collector(tmp_path: Path, *args: str, dry_run: bool = True,
               extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = {key: value for key, value in os.environ.items() if key not in {"AZURE_TENANT_ID", "AZURE_CLIENT_ID"}}
    env["PYTHON_BIN"] = sys.executable
    env.update(extra_env or {})
    return subprocess.run(
        ["bash", str(COLLECTOR_SCRIPT), "--out", str(tmp_path / "out"), *(["--dry-run"] if dry_run else []), *args],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120, check=False,
    )


def _throwaway_certificate(tmp_path: Path) -> tuple[Path, str]:
    """A fresh self-signed certificate for a constructed subject; never real key material."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "constructed-lab-reader")])
    now = dt.datetime.now(dt.UTC)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
                   .not_valid_after(now + dt.timedelta(days=2)).sign(key, hashes.SHA256()))
    path = tmp_path / "lab-reader-app.pem"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption())
                     + certificate.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o600)
    return path, certificate.fingerprint(hashes.SHA1()).hex().upper()


def test_collector_script_passes_the_certificate_options_to_the_engine(tmp_path: Path):
    result = _collector(tmp_path, *LAB_CERTIFICATE, "--certificate-password-env", "LAB_KEY_PASSWORD",
                        dry_run=False, extra_env=_boundary(tmp_path, run=False))
    assert result.returncode == 0, result.stderr
    record = json.loads((tmp_path / "boundary.json").read_text(encoding="utf-8"))
    engine_argv = record["argv"][2:]
    for removed in ("--interactive", "--use-azure-cli-token", "--access-token", "--client-secret", "--scopes",
                    "--browser-command", "--env", "--auth-context"):
        assert removed not in engine_argv
    args = cli.build_parser().parse_args(engine_argv)
    assert (args.tenant_id, args.client_id) == ("constructed.onmicrosoft.com", "constructed-app")
    assert args.certificate_path == f"{tmp_path.resolve()}/lab-reader-app.pem"
    assert args.certificate_thumbprint == "0" * 40 and args.certificate_password_env == "LAB_KEY_PASSWORD"
    # The configs live at the repository root, not under src/.
    repo_root = ROOT.parent
    assert Path(args.config) == repo_root / "configs" / "collector-definitions.json"
    assert Path(args.permission_hints) == repo_root / "configs" / "collector-permissions.json"
    assert Path(args.config).is_file() and Path(args.permission_hints).is_file()
    assert Path(record["cwd"]).resolve() == (repo_root / "src").resolve()
    assert record["pythonpath"].split(":")[0] == str(repo_root / "src")


@pytest.mark.parametrize("password", [["--certificate-password-env", "CANARY_PASSWORD_ENV_Q7"],
                                      ["--certificate-password-file", "canary-password-file-q7.txt"]])
def test_collector_script_dry_run_redacts_every_certificate_option(tmp_path: Path, password: list[str]):
    certificate = ["--tenant-id", "constructed.onmicrosoft.com", "--client-id", "constructed-app",
                   "--certificate-path", "canary-key-path-q7.pem", "--certificate-thumbprint", "C" * 39 + "7"]
    result = _collector(tmp_path, *certificate, *password)
    assert result.returncode == 0, result.stderr
    printed = result.stdout + result.stderr
    for canary in ("canary-key-path-q7", "C" * 39 + "7", password[1]):
        assert canary not in printed
    shown = result.stdout.splitlines()[1].split()
    for flag in ("--certificate-path", "--certificate-thumbprint", password[0]):
        assert shown[shown.index(flag) + 1] == "\\<redacted\\>"
    assert "constructed-app" in printed


def test_collector_script_loads_its_configs_and_reaches_the_sign_in_boundary(tmp_path: Path):
    key_path, thumbprint = _throwaway_certificate(tmp_path)
    result = _collector(
        tmp_path, "--tenant-id", "constructed.onmicrosoft.com", "--client-id", "constructed-app",
        "--certificate-path", key_path.name, "--certificate-thumbprint", thumbprint, "--collectors", "identity",
        dry_run=False, extra_env=_boundary(tmp_path, run=True),
    )
    output = result.stdout + result.stderr
    assert "FileNotFoundError" not in output and "Traceback" not in output
    record = json.loads((tmp_path / "boundary.json").read_text(encoding="utf-8"))
    # Every connection attempt was a blocked sign-in request: the collection never reached the network.
    assert record["attempts"] and all("login.microsoftonline.com" in attempt for attempt in record["attempts"])
    manifests = list((tmp_path / "out").glob("*/run-manifest.json"))
    assert len(manifests) == 1, output
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["mode"] == "app" and manifest["selected_collectors"] == ["identity"]
    assert thumbprint not in output and str(key_path) not in output


@pytest.mark.parametrize("missing", ["--tenant-id", "--client-id", "--certificate-path", "--certificate-thumbprint"])
def test_collector_script_refuses_a_run_without_the_reader_app_or_certificate(tmp_path: Path, missing: str):
    index = LAB_CERTIFICATE.index(missing)
    result = _collector(tmp_path, *LAB_CERTIFICATE[:index], *LAB_CERTIFICATE[index + 2:])
    assert result.returncode == 2
    assert "reader app with its certificate" in result.stderr


@pytest.mark.parametrize("removed", [["--interactive"], ["--browser-command", "firefox"], ["--token-env", "x.env"],
                                     ["--scopes", "User.Read"]])
def test_collector_script_refuses_the_removed_sign_in_options(tmp_path: Path, removed: list[str]):
    result = _collector(tmp_path, *LAB_CERTIFICATE, *removed)
    assert result.returncode == 1
    assert f"{removed[0]} was removed" in result.stderr and "--certificate-path" in result.stderr
    assert "Audit dry run command" not in result.stdout


def test_collector_script_refuses_two_password_sources(tmp_path: Path):
    result = _collector(tmp_path, *LAB_CERTIFICATE, "--certificate-password-env", "A", "--certificate-password-file", "b")
    assert result.returncode == 2 and "one of" in result.stderr
