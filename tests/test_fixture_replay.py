from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "tenant-bootstrap" / "scripts" / "replay-known-bad-fixtures.py"


def test_replay_known_bad_fixtures_generates_validated_bundles(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--out", str(tmp_path), "--clean"],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["kind"] == "known_bad_fixture_replay"
    assert {row["fixture"] for row in payload["fixtures"]} == {"m365", "google"}

    by_fixture = {row["fixture"]: row for row in payload["fixtures"]}
    assert by_fixture["m365"]["contract_status"] == "valid"
    assert by_fixture["m365"]["validation_valid"] is True
    assert by_fixture["m365"]["fixture_provenance"]["fixture_id"] == "m365-known-bad"

    assert by_fixture["google"]["contract_status"] == "valid"
    assert by_fixture["google"]["validation_valid"] is True
    assert by_fixture["google"]["fixture_provenance"]["fixture_id"] == "google-known-bad"

    replay_manifest = tmp_path / "known-bad-fixture-replay.json"
    assert replay_manifest.exists()

    for row in payload["fixtures"]:
        run_dir = Path(row["run_dir"])
        manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
        assert manifest["contract_status"] == "valid"
        assert manifest["fixture_provenance"]["fixture_id"] == row["fixture_provenance"]["fixture_id"]


def test_replay_known_bad_fixtures_attaches_bootstrap_seed_provenance(tmp_path: Path) -> None:
    bootstrap_run = tmp_path / "bootstrap-run"
    bootstrap_run.mkdir(parents=True, exist_ok=True)
    (bootstrap_run / "identity-seed-az-manifest.json").write_text(
        json.dumps(
            {
                "runName": "lab-a",
                "tenantId": "tenant-123",
                "tenantDomain": "example.com",
                "plannedUsers": 108,
                "plannedStaticGroups": 640,
                "plannedDynamicGroups": 64,
                "status": "completed",
                "completedAt": "2026-05-31T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (bootstrap_run / "workload-seed-az-manifest.json").write_text(
        json.dumps(
            {
                "runName": "lab-a",
                "tenantId": "tenant-123",
                "tenantDomain": "example.com",
                "steps": ["licenses", "security", "exchange"],
                "teamIds": ["team-1"],
                "status": "completed",
                "completedAt": "2026-05-31T12:05:00Z",
            }
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--out",
            str(tmp_path / "replay"),
            "--bootstrap-run-dir",
            str(bootstrap_run),
            "--clean",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload["bootstrap_run_dir"] == str(bootstrap_run.resolve())

    for row in payload["fixtures"]:
        bootstrap_seed = row["fixture_provenance"]["bootstrap_seed"]
        assert bootstrap_seed["run_dir"] == str(bootstrap_run.resolve())
        assert bootstrap_seed["identity"]["plannedUsers"] == 108
        assert bootstrap_seed["workload"]["steps"] == ["licenses", "security", "exchange"]

        run_dir = Path(row["run_dir"])
        manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
        assert manifest["fixture_provenance"]["bootstrap_seed"]["identity"]["plannedStaticGroups"] == 640
        assert manifest["fixture_provenance"]["bootstrap_seed"]["workload"]["teamIds"] == ["team-1"]
