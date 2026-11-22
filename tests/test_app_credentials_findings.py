from __future__ import annotations

from datetime import UTC, datetime, timedelta

from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot


def _iso(delta_days: int) -> str:
    return (datetime.now(tz=UTC) + timedelta(days=delta_days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _snapshot_with_apps(apps: list[dict[str, object]]) -> dict[str, object]:
    payloads = {
        "app_credentials": {
            "applicationCredentials": {"value": apps},
            "servicePrincipalCredentials": {"value": []},
        }
    }
    return build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads=payloads,
    )


def test_normalize_emits_application_credential_records() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Build Bot",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [{"key_id": "k1", "end_date_time": _iso(10)}],
                "key_credentials": [],
                "redirect_uris": [{"uri": "http://example.com/callback", "scheme": "http"}],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    section = snapshot.get("application_credential_objects")
    assert section is not None
    assert section["records"][0]["display_name"] == "Build Bot"


def test_findings_flag_expiring_secret_high() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Build Bot",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [{"key_id": "k1", "end_date_time": _iso(10)}],
                "key_credentials": [],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["id"] == "app_credentials:app-1:secret_expiring"), None)
    assert finding is not None
    assert finding["severity"] == "high"


def test_findings_flag_expired_secret_low() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Build Bot",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [{"key_id": "k1", "end_date_time": _iso(-5)}],
                "key_credentials": [],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["id"] == "app_credentials:app-1:secret_expired"), None)
    assert finding is not None
    # R050: an expired secret cannot authenticate; it is stale-credential hygiene, not a critical exposure.
    assert finding["severity"] == "low"


def test_findings_flag_http_redirect_uri() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Build Bot",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [],
                "key_credentials": [],
                "redirect_uris": [{"uri": "http://example.com/callback", "scheme": "http"}],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["id"] == "app_credentials:app-1:redirect_insecure"), None)
    assert finding is not None
    assert finding["severity"] == "high"


def test_findings_skip_localhost_http() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Dev",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [],
                "key_credentials": [],
                "redirect_uris": [{"uri": "http://localhost:8080/callback", "scheme": "http", "is_localhost": True}],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    redirect_findings = [f for f in findings if "redirect_insecure" in f["id"]]
    assert redirect_findings == []


def test_findings_flag_no_owners() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Orphan App",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [{"key_id": "k1", "end_date_time": _iso(365)}],
                "key_credentials": [],
                "redirect_uris": [],
                "owner_count": 0,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["id"] == "app_credentials:app-1:no_owner"), None)
    assert finding is not None
    assert finding["severity"] == "medium"


def test_findings_flag_multi_tenant_audience() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Wide App",
                "app_id": "1",
                "sign_in_audience": "AzureADMultipleOrgs",
                "password_credentials": [],
                "key_credentials": [],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["id"] == "app_credentials:app-1:multi_tenant_audience"), None)
    assert finding is not None
    assert finding["severity"] == "medium"


# ----- A3: split secret/cert + long-validity + dormant -----


def test_findings_flag_certificate_expired_distinct_from_secret() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "TLS App",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [],
                "key_credentials": [{"key_id": "c1", "end_date_time": _iso(-30)}],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    cert_finding = next(
        (f for f in findings if f["id"] == "app_credentials:app-1:certificate_expired"), None
    )
    secret_finding = next(
        (f for f in findings if f["id"] == "app_credentials:app-1:secret_expired"), None
    )
    assert cert_finding is not None
    assert cert_finding["severity"] == "low"
    # Cert path must NOT bleed into the legacy secret_expired rule_id.
    assert secret_finding is None


def test_findings_flag_certificate_expiring_within_30_days_as_medium() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "TLS App",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [],
                "key_credentials": [{"key_id": "c1", "end_date_time": _iso(20)}],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(
        (f for f in findings if f["id"] == "app_credentials:app-1:certificate_expiring"), None
    )
    assert finding is not None
    assert finding["severity"] == "medium"


def test_findings_skip_certificate_expiring_when_more_than_30_days_remaining() -> None:
    """Cert expiring rule has its own 30-day threshold (tighter than secret default)."""
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "TLS App",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [],
                "key_credentials": [{"key_id": "c1", "end_date_time": _iso(120)}],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    flagged = [f for f in findings if "certificate_expiring" in f["id"]]
    assert flagged == []


def test_findings_flag_secret_long_validity_above_two_years() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Long App",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [
                    {"key_id": "k1", "start_date_time": _iso(-1), "end_date_time": _iso(800)}
                ],
                "key_credentials": [],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(
        (f for f in findings if f["id"] == "app_credentials:app-1:secret_long_validity"), None
    )
    assert finding is not None
    assert finding["severity"] == "high"


def test_findings_flag_secret_open_ended_validity() -> None:
    """Secret with no end_date_time (open-ended) is flagged identically to >2y validity."""
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Forever App",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [{"key_id": "k1", "start_date_time": _iso(-1)}],
                "key_credentials": [],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(
        (f for f in findings if f["id"] == "app_credentials:app-1:secret_long_validity"), None
    )
    assert finding is not None
    assert finding["evidence"]["open_ended"] is True


def test_findings_skip_secret_long_validity_under_two_years() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Reasonable App",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "password_credentials": [
                    {"key_id": "k1", "start_date_time": _iso(-1), "end_date_time": _iso(180)}
                ],
                "key_credentials": [],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    flagged = [f for f in findings if "secret_long_validity" in f["id"]]
    assert flagged == []


def test_findings_flag_credential_dormant_when_signin_data_available_and_old() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Old Bot",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "created_date_time": _iso(-400),
                "last_signin_at": None,
                "signin_data_available": True,
                "password_credentials": [{"key_id": "k1", "end_date_time": _iso(365)}],
                "key_credentials": [],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(
        (f for f in findings if f["id"] == "app_credentials:app-1:credential_dormant"), None
    )
    assert finding is not None
    assert finding["severity"] == "low"


def test_findings_skip_credential_dormant_when_signin_data_unavailable() -> None:
    """Without signInActivity coverage, the dormant rule must stay silent (no false flood)."""
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Old Bot",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "created_date_time": _iso(-400),
                "last_signin_at": None,
                "signin_data_available": False,
                "password_credentials": [{"key_id": "k1", "end_date_time": _iso(365)}],
                "key_credentials": [],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    flagged = [f for f in findings if "credential_dormant" in f["id"]]
    assert flagged == []


def test_findings_skip_credential_dormant_for_recent_apps() -> None:
    snapshot = _snapshot_with_apps(
        [
            {
                "id": "app-1",
                "display_name": "Recent Bot",
                "app_id": "1",
                "sign_in_audience": "AzureADMyOrg",
                "created_date_time": _iso(-30),
                "last_signin_at": None,
                "signin_data_available": True,
                "password_credentials": [{"key_id": "k1", "end_date_time": _iso(365)}],
                "key_credentials": [],
                "redirect_uris": [],
                "owner_count": 1,
                "federated_credentials": [],
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    flagged = [f for f in findings if "credential_dormant" in f["id"]]
    assert flagged == []


# ----- R050: expired credentials are hygiene and never hide expiring ones -----


def _app(passwords: list[dict[str, object]], keys: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "id": "app-1",
        "display_name": "Build Bot",
        "app_id": "1",
        "sign_in_audience": "AzureADMyOrg",
        "password_credentials": passwords,
        "key_credentials": keys or [],
        "redirect_uris": [],
        "owner_count": 1,
        "federated_credentials": [],
    }


def test_r050_expired_secret_does_not_hide_an_expiring_one_or_drive_the_grade_critical() -> None:
    from azure_tenant_audit.findings import build_risk_rollup

    snapshot = _snapshot_with_apps(
        [_app([{"key_id": "old", "end_date_time": _iso(-300)}, {"key_id": "new", "end_date_time": _iso(5)}])]
    )
    findings = {f["id"]: f for f in build_findings([], normalized_snapshot=snapshot) if f["id"].startswith("app_credentials:")}
    assert findings["app_credentials:app-1:secret_expired"]["severity"] == "low"
    assert findings["app_credentials:app-1:secret_expiring"]["severity"] == "high"
    expired_only = [findings["app_credentials:app-1:secret_expired"]]
    assert build_risk_rollup(expired_only)["grade"] != "critical"


def test_r050_expired_certificate_does_not_hide_an_expiring_one() -> None:
    snapshot = _snapshot_with_apps(
        [_app([], [{"key_id": "c-old", "end_date_time": _iso(-30)}, {"key_id": "c-new", "end_date_time": _iso(10)}])]
    )
    ids = {f["id"] for f in build_findings([], normalized_snapshot=snapshot)}
    assert {"app_credentials:app-1:certificate_expired", "app_credentials:app-1:certificate_expiring"} <= ids


def test_r050_an_expired_long_lived_secret_is_not_long_validity() -> None:
    snapshot = _snapshot_with_apps(
        [_app([{"key_id": "old", "start_date_time": _iso(-1400), "end_date_time": _iso(-300)}])]
    )
    ids = {f["id"] for f in build_findings([], normalized_snapshot=snapshot)}
    assert "app_credentials:app-1:secret_long_validity" not in ids
