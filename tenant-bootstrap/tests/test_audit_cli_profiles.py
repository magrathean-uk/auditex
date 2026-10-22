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
