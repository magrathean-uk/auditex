"""Google Workspace device checks: compromised status values and the sync-recency threshold.

CE+ product review action 8. The Directory API describes ``deviceCompromisedStatus`` only as "the
compromised device status" and lists no values, so the classification is by the texts seen in the
Admin console and API output; an unrecognised text is unknown, never a pass and never a failure.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from auditex import cli as auditex_cli
from auditex.google_workspace.findings import DEFAULT_STALE_DEVICE_DAYS, build_google_findings
from auditex.google_workspace.normalize import build_google_normalized_snapshot, compromised_state
from auditex.google_workspace.run import GoogleRunConfig, run_google_offline

REPO = Path(__file__).resolve().parents[1]


def _ago(days: int) -> str:
    return (datetime.now(tz=timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _snapshot(mobile: list[dict[str, Any]] | None = None, chromeos: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_devices": {"mobileDevices": {"value": mobile or []}, "chromeosDevices": {"value": chromeos or []}}
        },
    )


def _by_rule(findings: list[dict[str, Any]], rule_id: str) -> list[dict[str, Any]]:
    return [item for item in findings if item["rule_id"] == rule_id]


@pytest.mark.parametrize(
    ("value", "state"),
    [
        ("Compromised", "compromised"),
        ("COMPROMISED", "compromised"),
        ("Compromise detected", "compromised"),
        ("No compromise detected", "not_compromised"),
        ("NOT_COMPROMISED", "not_compromised"),
        ("UNCOMPROMISED", "not_compromised"),
        ("Not compromised", "not_compromised"),
        ("UNKNOWN", "unknown"),
        ("COMPROMISED_STATE_UNSPECIFIED", "unknown"),
        ("", "unknown"),
        (None, "unknown"),
        ("Possibly compromised", "unknown"),
        ("Compromise suspected", "unknown"),
        ("Mystery", "unknown"),
    ],
)
def test_the_compromised_status_is_classified_by_known_values_only(value: Any, state: str) -> None:
    assert compromised_state(value) == state


def test_the_normalized_device_keeps_the_raw_text_beside_the_state() -> None:
    snapshot = _snapshot(
        mobile=[
            {"resourceId": "a", "deviceCompromisedStatus": "No compromise detected"},
            {"resourceId": "b", "deviceCompromisedStatus": "Mystery"},
            {"resourceId": "c", "compromisedStatus": "Compromised"},
            {"resourceId": "d"},
        ]
    )

    rows = {row["id"]: row for row in snapshot["google_mobile_devices"]["records"]}

    assert (rows["a"]["compromised_status"], rows["a"]["compromised_state"]) == ("No compromise detected", "not_compromised")
    assert (rows["b"]["compromised_status"], rows["b"]["compromised_state"]) == ("Mystery", "unknown")
    assert (rows["c"]["compromised_status"], rows["c"]["compromised_state"]) == ("Compromised", "compromised")
    assert rows["d"]["compromised_state"] == "unknown" and "compromised_status" not in rows["d"]


def test_only_a_recognised_compromised_value_raises_the_compromised_rule() -> None:
    snapshot = _snapshot(
        mobile=[
            {"resourceId": "bad", "deviceCompromisedStatus": "Compromised", "encryptionStatus": "Encrypted", "lastSync": _ago(1)},
            {"resourceId": "clean", "deviceCompromisedStatus": "No compromise detected", "encryptionStatus": "Encrypted", "lastSync": _ago(1)},
            {"resourceId": "odd", "deviceCompromisedStatus": "Possibly compromised", "encryptionStatus": "Encrypted", "lastSync": _ago(1)},
        ]
    )

    findings = build_google_findings(snapshot)

    (compromised,) = _by_rule(findings, "google.mobile_device_compromised")
    assert compromised["affected_objects"] == ["bad"] and compromised["severity"] == "high"


def test_an_unrecognised_or_absent_compromised_value_is_one_unknown_evidence_finding() -> None:
    snapshot = _snapshot(
        mobile=[
            {"resourceId": "odd", "deviceCompromisedStatus": "Possibly compromised", "encryptionStatus": "Encrypted", "lastSync": _ago(1)},
            {"resourceId": "silent", "encryptionStatus": "Encrypted", "lastSync": _ago(1)},
            {"resourceId": "clean", "deviceCompromisedStatus": "No compromise detected", "encryptionStatus": "Encrypted", "lastSync": _ago(1)},
        ]
    )

    findings = build_google_findings(snapshot)

    assert not _by_rule(findings, "google.mobile_device_compromised"), "unknown is never a failure"
    (unknown,) = _by_rule(findings, "google.evidence_unknown")
    assert unknown["id"] == "google.evidence_unknown:mobile_compromised_status"
    value = unknown["returned_value"]
    assert value["rules_not_evaluated"] == ["google.mobile_device_compromised"]
    assert value["objects_total"] == 3 and value["objects_without_field"] == 2
    assert value["unrecognised_values"] == ["Possibly compromised"]
    assert unknown["severity"] == "medium"


def test_a_snapshot_written_before_the_state_existed_still_classifies_from_the_raw_text() -> None:
    snapshot = _snapshot(mobile=[{"resourceId": "bad", "deviceCompromisedStatus": "Compromised", "lastSync": _ago(1)}])
    for record in snapshot["google_mobile_devices"]["records"]:
        record.pop("compromised_state")

    findings = build_google_findings(snapshot)

    assert [item["affected_objects"] for item in _by_rule(findings, "google.mobile_device_compromised")] == [["bad"]]


def test_the_sync_threshold_defaults_to_ninety_days_and_follows_the_setting() -> None:
    assert DEFAULT_STALE_DEVICE_DAYS == 90
    snapshot = _snapshot(
        mobile=[
            {"resourceId": "m60", "deviceCompromisedStatus": "No compromise detected", "encryptionStatus": "Encrypted", "lastSync": _ago(60)},
            {"resourceId": "m120", "deviceCompromisedStatus": "No compromise detected", "encryptionStatus": "Encrypted", "lastSync": _ago(120)},
        ],
        chromeos=[
            {"deviceId": "c60", "status": "ACTIVE", "autoUpdateThrough": _ago(-400), "lastSync": _ago(60)},
            {"deviceId": "c120", "status": "ACTIVE", "autoUpdateThrough": _ago(-400), "lastSync": _ago(120)},
        ],
    )

    def stale(**kwargs: Any) -> dict[str, list[str]]:
        findings = build_google_findings(snapshot, **kwargs)
        return {
            rule: sorted(item["affected_objects"][0] for item in _by_rule(findings, rule))
            for rule in ("google.mobile_device_stale_sync", "google.chromeos_device_stale_sync")
        }

    assert stale() == {"google.mobile_device_stale_sync": ["m120"], "google.chromeos_device_stale_sync": ["c120"]}
    assert stale(stale_device_days=30) == {
        "google.mobile_device_stale_sync": ["m120", "m60"],
        "google.chromeos_device_stale_sync": ["c120", "c60"],
    }
    assert stale(stale_device_days=180) == {"google.mobile_device_stale_sync": [], "google.chromeos_device_stale_sync": []}
    strict = _by_rule(build_google_findings(snapshot, stale_device_days=30), "google.mobile_device_stale_sync")
    assert strict and all("more than 30 days" in item["description"] for item in strict)


def test_the_cli_takes_the_device_threshold_on_run_only(tmp_path: Path) -> None:
    parser = auditex_cli._build_google_parser()

    config = auditex_cli._google_config_from_args(parser.parse_args(["run", "--stale-device-days", "30"]))

    assert config.stale_device_days == 30
    assert auditex_cli._google_config_from_args(parser.parse_args(["run"])).stale_device_days == 90
    assert GoogleRunConfig(tenant_name="T", out=tmp_path).stale_device_days == 90
    for rejected in (["probe", "--stale-device-days", "30"], ["run", "--stale-device-days", "0"], ["run", "--stale-device-days", "soon"]):
        with pytest.raises(SystemExit):
            parser.parse_args(rejected)


def test_an_offline_run_applies_the_device_threshold(tmp_path: Path) -> None:
    sample = json.loads((REPO / "examples" / "google_workspace_sample.json").read_text(encoding="utf-8"))
    sample["google_devices"]["mobileDevices"]["value"].append(
        {
            "resourceId": "mobile-aged",
            "email": ["aged@example.com"],
            "status": "APPROVED",
            "deviceCompromisedStatus": "No compromise detected",
            "encryptionStatus": "Encrypted",
            "devicePasswordStatus": "On",
            "securityPatchLevel": "1760000000",
            "lastSync": _ago(45),
        }
    )
    path = tmp_path / "sample.json"
    path.write_text(json.dumps(sample), encoding="utf-8")

    def stale_ids(days: int, name: str) -> set[str]:
        code = run_google_offline(
            sample_path=path, out=tmp_path, tenant_name="Example", run_name=name, domain="example.com",
            customer_id="C1", stale_device_days=days,
        )
        assert code == 0
        findings = json.loads((tmp_path / f"Example-{name}" / "findings" / "findings.json").read_text(encoding="utf-8"))
        return {item["affected_objects"][0] for item in findings if item["rule_id"] == "google.mobile_device_stale_sync"}

    assert "mobile-aged" not in stale_ids(90, "default")
    assert "mobile-aged" in stale_ids(30, "strict")
