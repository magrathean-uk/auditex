"""The two offline endpoint samples: every new rule fires on replay and the bundle stays valid."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit.cli import main as cli_main
from azure_tenant_audit.cli import run_offline

SAMPLES = Path(__file__).resolve().parent.parent / "examples" / "sample_audit_bundle"
POSTURE = SAMPLES / "endpoint_posture_result.json"
NO_RINGS = SAMPLES / "update_rings_missing_result.json"

NEW_RULES = {
    "intune.device_encryption_off",
    "intune.device_jailbroken",
    "intune.device_os_end_of_life",
    "intune.compliance_policy_missing_platform",
    "intune.defender_av_off",
    "intune.defender_realtime_protection_off",
    "intune.defender_signatures_stale",
    "intune_depth.update_ring_not_assigned",
    "intune_depth.update_ring_deferral_excessive",
    "exchange.malware_filter_weakened",
    "exchange.smtp_auth_enabled_tenant_wide",
    "exchange.dkim_signing_disabled",
}


# The samples are judged as of a fixed instant, so what fires (and at what severity) does not depend on the day the
# test runs: Windows 10's Extended Security Updates window, for one, closes in 2028 and would turn a finding high.
AS_OF = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)


def _replay(sample: Path, tmp_path: Path, name: str) -> Path:
    rc = run_offline(sample, tmp_path, "ci", name, auditor_profile="global-reader", plane="inventory", as_of=AS_OF)
    assert rc == 0
    return tmp_path / f"ci-{name}"


def _json(run_dir: Path, relative: str) -> Any:
    return json.loads((run_dir / relative).read_text(encoding="utf-8"))


def _rules(run_dir: Path) -> set[str]:
    return {item["rule_id"] for item in _json(run_dir, "findings/findings.json")}


@pytest.fixture(scope="module")
def runs(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    base = tmp_path_factory.mktemp("endpoint-samples")
    return _replay(POSTURE, base, "posture"), _replay(NO_RINGS, base, "rings")


def test_both_samples_replay_to_valid_bundles(runs: tuple[Path, Path]) -> None:
    for run_dir in runs:
        validation = _json(run_dir, "validation.json")
        assert validation["valid"], validation["issues"]
        assert _json(run_dir, "run-manifest.json")["contract_status"] == "valid"


def test_every_new_rule_fires_in_the_samples_and_the_ring_rules_are_exclusive(runs: tuple[Path, Path]) -> None:
    posture, no_rings = (_rules(run_dir) for run_dir in runs)

    assert NEW_RULES - {"intune_depth.update_ring_not_assigned"} <= posture
    assert "intune_depth.update_ring_not_assigned" not in posture, "an assigned ring and 'no ring assigned' cannot both hold"
    assert "intune_depth.update_ring_not_assigned" in no_rings and "intune_depth.update_ring_deferral_excessive" not in no_rings
    assert NEW_RULES <= posture | no_rings
    assert "intune.device_stale_sync" in posture


def test_each_endpoint_rule_fires_where_the_sample_put_the_problem(runs: tuple[Path, Path]) -> None:
    findings = {item["id"]: item for item in _json(runs[0], "findings/findings.json")}
    expected = {
        "intune:00000000-0000-4000-8000-00000000d002:device_encryption_off": "high",
        "intune:00000000-0000-4000-8000-00000000d003:device_jailbroken": "high",
        "intune:00000000-0000-4000-8000-00000000d001:device_os_end_of_life": "medium",
        "intune:00000000-0000-4000-8000-00000000d004:device_os_end_of_life": "medium",
        "intune:00000000-0000-4000-8000-00000000d001:device_stale_sync": "medium",
        "intune:00000000-0000-4000-8000-00000000d002:defender_av_off": "high",
        "intune:compliance_policy:android:missing": "medium",
        "intune:compliance_policy:macos:missing": "medium",
        "intune_depth:00000000-0000-4000-8000-00000000e001:update_ring_deferral": "medium",
        "exchange_policy:malware_filter:default_weakened": "high",
        "exchange_policy:transport_config:smtp_auth_enabled": "medium",
        "exchange_policy:contoso.example:dkim_signing_disabled": "medium",
    }
    assert {key: findings[key]["severity"] for key in expected} == expected
    # The Mac reports neither encryption nor a sync time: unknown, so no finding for it on those checks.
    mac = "00000000-0000-4000-8000-00000000d005"
    assert not [key for key in findings if f":{mac}:" in key]


def test_unknown_device_state_is_counted_in_the_normalized_summary(runs: tuple[Path, Path]) -> None:
    summary = next(row for row in _json(runs[0], "normalized/device_posture.json")["records"] if row["kind"] == "device_posture_summary")
    assert summary["encryption_unknown"] == 1 and summary["last_sync_unknown"] == 1 and summary["read_state"] == "collected"
    assert summary["device_count"] == 6 and summary["os_lifecycle_table_verified_on"]


def test_the_cyber_essentials_update_and_malware_rows_report_evidence_never_a_pass(runs: tuple[Path, Path]) -> None:
    controls = {row["control_id"]: row for row in _json(runs[0], "reports/report-pack.json")["baseline_alignment"]["frameworks"]["cyber_essentials"]["controls"]}
    assert controls["ce.sum.supported_software"]["status"] == "fail"
    assert controls["ce.sum.vulnerability_fixes_14_days"]["status"] == "fail"
    assert controls["ce.mp.antimalware"]["status"] == "fail"
    assert controls["ce.mp.app_allow_listing"]["status"] == "not_assessed"
    assert controls["ce.sum.automatic_updates"]["status"] == "not_assessed" and controls["ce.sum.automatic_updates"]["reason"] == "partial_requirement_no_gap_found"
    for run_dir in runs:
        statuses = {row["status"] for row in _json(run_dir, "reports/report-pack.json")["baseline_alignment"]["frameworks"]["cyber_essentials"]["controls"]}
        assert "pass" not in statuses


def test_the_stale_sync_option_reaches_the_findings(tmp_path: Path) -> None:
    # Every device in the sample that reports a sync time synced on or before 2026-10-20, so a one-day window flags
    # all of them on any day this test runs; the Mac reports no sync time and stays unknown.
    rc = cli_main(["--offline", "--sample", str(POSTURE), "--tenant-name", "ci", "--run-name", "strict", "--out", str(tmp_path), "--stale-sync-days", "1"])
    assert rc == 0
    stale = {item["id"] for item in _json(tmp_path / "ci-strict", "findings/findings.json") if item["rule_id"] == "intune.device_stale_sync"}
    assert stale == {f"intune:00000000-0000-4000-8000-00000000d00{number}:device_stale_sync" for number in (1, 2, 3, 4, 6)}
    with pytest.raises(SystemExit):
        cli_main(["--offline", "--sample", str(POSTURE), "--tenant-name", "ci", "--out", str(tmp_path), "--stale-sync-days", "0"])


def test_the_samples_use_only_fictional_identifiers_and_reserved_domains() -> None:
    for sample in (POSTURE, NO_RINGS):
        text = sample.read_text(encoding="utf-8")
        data = json.loads(text)
        assert data["_fixture_provenance"]["synthetic"] is True
        assert not re.findall(r"[\w.+-]+@[\w-]+\.(?!example\b)[a-z]{2,}", text)
        for domain in re.findall(r'"(?:DomainName|Domain)":\s*"([^"]+)"', text):
            assert domain.endswith((".example", ".onmicrosoft.com")), domain
        assert "secret" not in text.lower()
