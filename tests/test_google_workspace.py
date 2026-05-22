from __future__ import annotations

import json
from pathlib import Path
import re

from auditex import cli as auditex_cli


def _sample_payload() -> dict[str, object]:
    return {
        "google_directory": {
            "users": {
                "value": [
                    {
                        "id": "u-admin",
                        "primaryEmail": "admin@example.com",
                        "name": {"fullName": "Admin User"},
                        "isAdmin": True,
                        "isEnforcedIn2Sv": False,
                        "suspended": False,
                    },
                    {
                        "id": "u-user",
                        "primaryEmail": "user@example.com",
                        "name": {"fullName": "Normal User"},
                        "isAdmin": False,
                        "isEnrolledIn2Sv": True,
                    },
                ]
            },
            "groups": {
                "value": [
                    {
                        "id": "g-1",
                        "email": "all@example.com",
                        "name": "All Staff",
                        "whoCanJoin": "ANYONE_CAN_JOIN",
                        "whoCanViewMembership": "ALL_IN_DOMAIN_CAN_VIEW",
                    }
                ]
            },
            "domains": {"value": [{"domainName": "example.com", "verified": True, "isPrimary": True}]},
            "roleAssignments": {"value": [{"roleId": "role-super", "assignedTo": "u-admin"}]},
            "roles": {"value": [{"roleId": "role-super", "roleName": "Super Admin"}]},
            "oauthGrants": {
                "value": [
                    {
                        "userKey": "admin@example.com",
                        "clientId": "oauth-client-1",
                        "displayText": "Risky App",
                        "scopes": [
                            "https://www.googleapis.com/auth/gmail.modify",
                            "https://www.googleapis.com/auth/drive",
                        ],
                    }
                ]
            },
        },
        "google_gmail_settings": {
            "mailboxSettings": {
                "value": [
                    {
                        "userEmail": "admin@example.com",
                        "autoForwarding": {"enabled": True, "emailAddress": "outside@other.test"},
                        "filters": [
                            {
                                "id": "filter-1",
                                "criteria": {"from": "ceo@example.com"},
                                "action": {"forward": "stealth@other.test", "removeLabelIds": ["INBOX"]},
                            }
                        ],
                        "forwardingAddresses": [{"forwardingEmail": "outside@other.test", "verificationStatus": "accepted"}],
                        "sendAs": [{"sendAsEmail": "admin@example.com", "isPrimary": True}],
                        "delegates": [],
                    }
                ]
            }
        },
        "google_alert_center": {
            "alerts": {"value": [{"alertId": "alert-1", "type": "Suspicious login", "severity": "HIGH"}]}
        },
        "google_dns_posture": {
            "domainPosture": {
                "value": [
                    {
                        "domain": "example.com",
                        "spf": {"present": False},
                        "dmarc": {"present": True, "policy": "none"},
                        "dkim": {"selectors_present": [], "selectors_missing": ["google"]},
                    }
                ]
            }
        },
    }


def test_google_offline_run_writes_valid_contract_and_findings(tmp_path: Path) -> None:
    from auditex.google_workspace.run import run_google_offline

    sample_path = tmp_path / "google-sample.json"
    sample_path.write_text(json.dumps(_sample_payload()), encoding="utf-8")

    rc = run_google_offline(
        sample_path=sample_path,
        out=tmp_path,
        tenant_name="Example",
        run_name="google-contract",
        domain="example.com",
        customer_id="C123",
    )

    assert rc == 0
    run_dir = tmp_path / "Example-google-contract"
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    data_handling = json.loads((run_dir / "data-handling.json").read_text(encoding="utf-8"))
    findings = json.loads((run_dir / "findings" / "findings.json").read_text(encoding="utf-8"))

    assert manifest["platform"] == "google_workspace"
    assert manifest["workspace_domain"] == "example.com"
    assert manifest["customer_id"] == "C123"
    assert manifest["data_handling_path"] == "data-handling.json"
    assert data_handling["platform"] == "google_workspace"
    assert data_handling["read_only"] is True
    assert data_handling["content_reads"] is False
    assert data_handling["write_actions"] is False
    assert data_handling["provider_assertions"]["gmail_body_reads"] is False
    assert data_handling["provider_assertions"]["drive_file_content_reads"] is False
    assert data_handling["scope_risk"] == "write_capable_scope_present"
    assert "https://www.googleapis.com/auth/gmail.settings.sharing" in data_handling["write_capable_scopes"]
    assert data_handling["provider_assertions"]["write_capable_scopes_used_for_read_only_methods"] is True
    assert manifest["contract_status"] == "valid"
    assert validation["valid"] is True, validation["issues"]
    assert {item["rule_id"] for item in findings}.issuperset(
        {
            "google.admin_2sv_not_enforced",
            "google.gmail_external_forwarding",
            "google.oauth_high_risk_scope",
            "google.alert_active",
            "google.dns_dmarc_monitor_only",
        }
    )


def test_google_cli_offline_run_dispatches(tmp_path: Path) -> None:
    sample_path = tmp_path / "google-sample.json"
    sample_path.write_text(json.dumps(_sample_payload()), encoding="utf-8")

    rc = auditex_cli.main(
        [
            "google",
            "run",
            "--offline",
            "--sample",
            str(sample_path),
            "--domain",
            "example.com",
            "--customer-id",
            "C123",
            "--tenant-name",
            "Example",
            "--run-name",
            "cli-google",
            "--out",
            str(tmp_path),
        ]
    )

    assert rc == 0
    manifest = json.loads((tmp_path / "Example-cli-google" / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["platform"] == "google_workspace"


def test_google_live_writes_provider_auth_context(tmp_path: Path, monkeypatch) -> None:
    from auditex.google_workspace import run as google_run
    from auditex.google_workspace.run import GoogleRunConfig, run_google_live
    from azure_tenant_audit.collectors.base import CollectorResult

    class _FakeCollector:
        name = "google_directory"
        required_scopes = ("scope://directory.readonly",)

        def run(self, _context):
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"users": {"value": [{"id": "u1", "primaryEmail": "user@example.com"}]}},
                coverage=[
                    {
                        "collector": self.name,
                        "name": "users",
                        "type": "google_api",
                        "status": "ok",
                        "item_count": 1,
                    }
                ],
            )

    monkeypatch.setattr(google_run, "REGISTRY", {"google_directory": _FakeCollector()})
    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True, "missing": [], "install_hint": ""})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: object())
    monkeypatch.setattr(google_run, "GoogleWorkspaceClient", lambda *_args, **_kwargs: object())

    rc = run_google_live(
        GoogleRunConfig(
            tenant_name="Example",
            out=tmp_path,
            run_name="google-live-auth",
            domain="example.com",
            customer_id="C123",
            subject="admin@example.com",
            service_account_key=tmp_path / "service-account.json",
            collectors="google_directory",
        ),
        command_line=["auditex", "google", "run", "--service-account-key", "/secrets/service-account.json"],
    )

    run_dir = tmp_path / "Example-google-live-auth"
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    auth_context = json.loads((run_dir / "auth-context.json").read_text(encoding="utf-8"))
    live_readiness = json.loads((run_dir / "live-readiness.json").read_text(encoding="utf-8"))
    report_pack = json.loads((run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))
    api_inventory = json.loads((run_dir / "api-inventory.json").read_text(encoding="utf-8"))

    assert rc == 0
    assert manifest["auth_context_path"] == "auth-context.json"
    assert manifest["live_readiness_path"] == "live-readiness.json"
    assert auth_context["platform"] == "google_workspace"
    assert auth_context["auth_mode"] == "domain-delegation"
    assert auth_context["subject"] == "admin@example.com"
    assert auth_context["workspace_domain"] == "example.com"
    assert auth_context["customer_id"] == "C123"
    assert auth_context["scopes"] == ["scope://directory.readonly"]
    assert "service-account.json" not in json.dumps(auth_context)
    assert live_readiness["trust_level"] == "live_verified"
    assert "live-readiness.json" in report_pack["evidence_paths"]
    assert manifest["api_inventory_path"] == "api-inventory.json"
    assert api_inventory["observed_calls"][0]["collector"] == "google_directory"
    assert api_inventory["observed_calls"][0]["content_reads"] is False
    assert api_inventory["safety"]["read_only"] is True


def test_google_probe_writes_summarizable_artifacts(tmp_path: Path, monkeypatch, capsys) -> None:
    from auditex.google_workspace import run as google_run
    from auditex.google_workspace.run import GoogleRunConfig, run_google_probe

    class _FakeCollector:
        name = "google_directory"
        required_scopes = ("scope://directory.readonly",)

    monkeypatch.setattr(google_run, "REGISTRY", {"google_directory": _FakeCollector()})
    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True, "missing": [], "install_hint": ""})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: object())
    monkeypatch.setattr(google_run, "GoogleWorkspaceClient", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        google_run,
        "build_google_preflight_rows",
        lambda *_args, **_kwargs: [
            {
                "collector": "google_directory",
                "name": "users",
                "status": "ok",
                "item_count": 1,
                "duration_ms": 1,
                "error_class": None,
                "error": None,
            }
        ],
    )

    rc = run_google_probe(
        GoogleRunConfig(
            tenant_name="Example",
            out=tmp_path,
            run_name="google-probe-artifacts",
            domain="example.com",
            customer_id="C123",
            subject="admin@example.com",
            service_account_key=tmp_path / "service-account.json",
            collectors="google_directory",
        )
    )

    capsys.readouterr()
    run_dir = tmp_path / "Example-google-probe-artifacts"
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    auth_context = json.loads((run_dir / "auth-context.json").read_text(encoding="utf-8"))
    capability_matrix = json.loads((run_dir / "capability-matrix.json").read_text(encoding="utf-8"))
    toolchain = json.loads((run_dir / "toolchain-readiness.json").read_text(encoding="utf-8"))
    live_readiness = json.loads((run_dir / "live-readiness.json").read_text(encoding="utf-8"))
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    report_pack = json.loads((run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))
    api_inventory = json.loads((run_dir / "api-inventory.json").read_text(encoding="utf-8"))

    assert rc == 0
    assert manifest["platform"] == "google_workspace"
    assert manifest["contract_status"] == "valid"
    assert manifest["probe_mode"] == "domain-delegation"
    assert manifest["capability_matrix_path"] == "capability-matrix.json"
    assert manifest["toolchain_readiness_path"] == "toolchain-readiness.json"
    assert manifest["live_readiness_path"] == "live-readiness.json"
    assert manifest["auth_context_path"] == "auth-context.json"
    assert auth_context["scopes"] == ["scope://directory.readonly"]
    assert "service-account.json" not in json.dumps(auth_context)
    assert capability_matrix[0]["collector"] == "google_directory"
    assert toolchain["google_workspace_libraries"]["status"] == "supported"
    assert live_readiness["trust_level"] == "live_verified"
    assert validation["valid"] is True, validation["issues"]
    assert "preflight.json" in report_pack["evidence_paths"]
    assert "toolchain-readiness.json" in report_pack["evidence_paths"]
    assert manifest["api_inventory_path"] == "api-inventory.json"
    assert api_inventory["observed_calls"][0]["endpoint"] == "users"


def test_google_doctor_accepts_run_selection_options(capsys) -> None:
    from auditex.google_workspace.auth import google_dependency_status

    rc = auditex_cli.main(
        [
            "google",
            "doctor",
            "--collector-preset",
            "everything",
            "--exclude",
            "google_reports",
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)

    assert rc in {0, 2}
    assert "google_calendar_posture" in payload["selected_collectors"]
    assert "google_reports" not in payload["selected_collectors"]
    assert payload["auth"]["scopes_csv"]
    assert "," in payload["auth"]["scopes_csv"]
    assert payload["auth"]["scopes_csv"].split(",") == payload["auth"]["scopes"]
    expected_trust = "setup_only" if google_dependency_status()["available"] else "blocked"
    assert payload["live_readiness"]["trust_level"] == expected_trust
    if expected_trust == "setup_only":
        assert "google_calendar_posture" in payload["live_readiness"]["unverified_collectors"]
    else:
        assert "google_calendar_posture" in payload["live_readiness"]["blocked_collectors"]


def test_google_doctor_plain_output_mentions_live_readiness(capsys) -> None:
    from auditex.google_workspace.auth import google_dependency_status

    rc = auditex_cli.main(["google", "doctor", "--collector-preset", "identity"])

    output = capsys.readouterr().out

    assert rc in {0, 2}
    assert "Live readiness:" in output
    expected_trust = "setup_only" if google_dependency_status()["available"] else "blocked"
    assert expected_trust in output
    assert "OAuth scopes:" in output
    assert "https://www.googleapis.com/auth/admin.directory.user.readonly" in output


def test_google_dependency_status_handles_missing_google_namespace(monkeypatch) -> None:
    from auditex.google_workspace import auth as google_auth

    def fake_find_spec(module: str) -> object | None:
        if module == "google.auth":
            raise ModuleNotFoundError("No module named 'google'")
        return None

    monkeypatch.setattr(google_auth.importlib.util, "find_spec", fake_find_spec)

    status = google_auth.google_dependency_status()

    assert status["available"] is False
    assert status["missing"] == [
        "google-api-python-client",
        "google-auth",
        "google-auth-oauthlib",
    ]


def test_google_capability_rows_include_live_readiness() -> None:
    from auditex.google_workspace.run import build_google_capability_rows, build_google_live_readiness

    capability_rows = build_google_capability_rows(
        ["google_directory", "google_drive_posture"],
        auth_mode="domain-delegation",
        dependency_status={"available": True},
        coverage_rows=[
            {"collector": "google_directory", "name": "users", "status": "ok"},
            {
                "collector": "google_drive_posture",
                "name": "driveFiles",
                "status": "failed",
                "error_class": "insufficient_permissions",
            },
        ],
    )
    readiness = build_google_live_readiness(["google_directory", "google_drive_posture"], capability_rows)

    assert readiness["trust_level"] == "partial"
    assert readiness["trusted_collectors"] == ["google_directory"]
    assert readiness["blocked_collectors"] == ["google_drive_posture"]


def test_google_auth_dependency_status_reports_missing_libs(monkeypatch) -> None:
    from auditex.google_workspace.auth import google_dependency_status

    monkeypatch.setattr("importlib.util.find_spec", lambda _name: None)

    status = google_dependency_status()

    assert status["available"] is False
    assert "google-auth" in status["install_hint"]


def test_google_error_classifier_marks_oauth_scope_blockers() -> None:
    from auditex.google_workspace.client import classify_google_error

    error_class, message = classify_google_error(RuntimeError("unauthorized_client: client not authorized for scopes"))

    assert error_class == "insufficient_permissions"
    assert "unauthorized_client" in message


def test_google_collector_selection_accepts_empty_exclude() -> None:
    from auditex.google_workspace.run import GoogleRunConfig, _selected_collectors

    config = GoogleRunConfig(
        tenant_name="Example",
        out=Path("outputs/google"),
        collector_preset="identity",
        exclude=None,
    )

    assert _selected_collectors(config) == ["google_directory", "google_reports", "google_alert_center"]


def test_google_command_line_scrubs_local_secret_paths() -> None:
    from auditex.google_workspace.run import scrub_google_command_line

    scrubbed = scrub_google_command_line(
        [
            "auditex",
            "google",
            "run",
            "--service-account-key",
            "/secrets/key.json",
            "--oauth-client=/secrets/oauth.json",
            "--token-cache",
            "/secrets/token.json",
        ]
    )

    rendered = " ".join(scrubbed)
    assert "/secrets" not in rendered
    assert rendered.count("***redacted***") == 3


def test_google_diagnostic_findings_have_unique_ids() -> None:
    from auditex.google_workspace.findings import build_google_findings

    findings = build_google_findings(
        {"snapshot": {"workspace_domain": "example.com"}},
        diagnostics=[
            {"collector": "google_directory", "name": "users", "error_class": "client_error"},
            {"collector": "google_gmail_settings", "name": "users", "error_class": "client_error"},
        ],
    )

    ids = [item["id"] for item in findings]
    assert len(ids) == len(set(ids))


def test_google_collector_handles_paginated_fake_client() -> None:
    from auditex.google_workspace.collectors import GoogleDirectoryCollector

    class _FakeClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def list_directory(self, resource: str, **_kwargs):
            self.calls.append(("directory", resource))
            if resource == "users":
                return [{"id": "u-1", "primaryEmail": "user@example.com"}]
            if resource == "groups":
                return [{"id": "g-1", "email": "all@example.com"}]
            return []

        def list_group_members(self, group_email: str, **_kwargs):
            self.calls.append(("members", group_email))
            return [{"id": "u-1", "email": "user@example.com"}]

        def list_user_tokens(self, user_key: str, **_kwargs):
            self.calls.append(("tokens", user_key))
            return [{"clientId": "oauth-client-1", "scopes": ["scope-a"]}]

    result = GoogleDirectoryCollector().run({"client": _FakeClient(), "top": 10, "domain": "example.com"})

    assert result.status == "ok"
    assert result.payload["users"]["value"][0]["primaryEmail"] == "user@example.com"
    assert result.payload["groupMembers"]["value"][0]["groupEmail"] == "all@example.com"
    assert result.payload["oauthGrants"]["value"][0]["userKey"] == "user@example.com"


def test_google_collector_top_zero_means_unbounded_collection() -> None:
    from auditex.google_workspace.collectors import GoogleDirectoryCollector

    class _FakeClient:
        def __init__(self) -> None:
            self.top_values: list[int | None] = []

        def list_directory(self, resource: str, **kwargs):
            self.top_values.append(kwargs.get("top"))
            if resource == "users":
                return [{"id": "u-1", "primaryEmail": "user@example.com"}]
            if resource == "groups":
                return [{"id": "g-1", "email": "all@example.com"}]
            return []

        def list_group_members(self, _group_email: str, **kwargs):
            self.top_values.append(kwargs.get("top"))
            return [{"id": "u-1", "email": "user@example.com"}]

        def list_user_aliases(self, _user_key: str, **kwargs):
            self.top_values.append(kwargs.get("top"))
            return []

        def list_user_tokens(self, _user_key: str, **kwargs):
            self.top_values.append(kwargs.get("top"))
            return []

    fake = _FakeClient()
    result = GoogleDirectoryCollector().run({"client": fake, "top": 0, "domain": "example.com"})

    assert result.status == "ok"
    assert fake.top_values
    assert set(fake.top_values) == {None}


def test_google_capability_rows_include_scopes_and_endpoint_failures() -> None:
    from auditex.google_workspace.run import build_google_capability_rows

    rows = build_google_capability_rows(
        ["google_directory", "google_drive_posture"],
        auth_mode="domain-delegation",
        dependency_status={"available": True},
        coverage_rows=[
            {
                "collector": "google_drive_posture",
                "name": "driveFiles",
                "status": "failed",
                "error_class": "insufficient_permissions",
            }
        ],
    )

    by_collector = {row["collector"]: row for row in rows}
    assert "https://www.googleapis.com/auth/admin.directory.user.readonly" in by_collector["google_directory"]["required_permissions"]
    assert "https://www.googleapis.com/auth/drive.metadata.readonly" in by_collector["google_drive_posture"]["required_permissions"]
    assert "https://www.googleapis.com/auth/drive.readonly" in by_collector["google_drive_posture"]["required_permissions"]
    assert by_collector["google_directory"]["status"] == "supported"
    assert by_collector["google_drive_posture"]["status"] == "blocked_by_scope"
    assert by_collector["google_drive_posture"]["blocker_kind"] == "auth_scope"
    assert by_collector["google_drive_posture"]["next_step"]
    assert by_collector["google_drive_posture"]["missing_permissions"] == [
        "https://www.googleapis.com/auth/drive.metadata.readonly",
        "https://www.googleapis.com/auth/drive.readonly",
    ]


def test_google_preflight_checks_real_endpoints_with_fake_client() -> None:
    from auditex.google_workspace.run import build_google_preflight_rows

    class _Resp:
        status = 403

    class _FakeClient:
        def list_directory(self, resource: str, **_kwargs):
            if resource == "users":
                return [{"id": "u-1"}]
            raise AssertionError(resource)

        def list_alerts(self, **_kwargs):
            exc = RuntimeError("denied")
            exc.resp = _Resp()
            raise exc

        def list_drive_files(self, **_kwargs):
            return [{"id": "file-1"}]

        def list_shared_drives(self, **_kwargs):
            return [{"id": "drive-1"}]

    rows = build_google_preflight_rows(
        _FakeClient(),
        ["google_directory", "google_alert_center", "google_drive_posture"],
        domain="example.com",
        top=1,
    )

    by_collector = {row["collector"]: row for row in rows}
    by_name = {row["name"]: row for row in rows}
    assert by_collector["google_directory"]["status"] == "ok"
    assert by_collector["google_alert_center"]["status"] == "failed"
    assert by_collector["google_alert_center"]["error_class"] == "insufficient_permissions"
    assert by_name["driveFiles"]["status"] == "ok"
    assert by_name["sharedDrives"]["status"] == "ok"


def test_google_capability_rows_mark_successful_preflight_exact() -> None:
    from auditex.google_workspace.run import build_google_capability_rows

    rows = build_google_capability_rows(
        ["google_directory"],
        auth_mode="domain-delegation",
        dependency_status={"available": True},
        coverage_rows=[{"collector": "google_directory", "name": "users", "status": "ok"}],
    )

    assert rows[0]["status"] == "supported_exact_scope"
    assert rows[0]["reason"] == "runtime_preflight_ok"


def test_google_normalized_snapshot_marks_top_limited_sections() -> None:
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    snapshot = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        collector_payloads={"google_directory": {"users": {"value": [{"id": "u-1", "primaryEmail": "a@example.com"}]}}},
        domain="example.com",
        customer_id="C123",
        result_rows=[{"name": "google_directory", "status": "ok", "item_count": 500}],
        top_limit=500,
    )["snapshot"]

    assert snapshot["top_limit"] == 500
    assert snapshot["sample_truncated"] is True
    assert snapshot["truncated_sections"] == ["google_directory"]


def test_google_drive_and_group_settings_findings_from_sample() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_drive_posture": {
                "driveFiles": {
                    "value": [
                        {
                            "id": "file-1",
                            "name": "Payroll",
                            "mimeType": "application/vnd.google-apps.spreadsheet",
                            "permissions": [{"type": "anyone", "role": "reader"}],
                        }
                    ]
                },
                "sharedDrives": {"value": []},
            },
            "google_groups_settings": {
                "groupSettings": {
                    "value": [
                        {
                            "email": "all@example.com",
                            "allowExternalMembers": "true",
                            "whoCanPostMessage": "ANYONE_CAN_POST",
                        }
                    ]
                }
            },
        },
    )

    rule_ids = {finding["rule_id"] for finding in build_google_findings(normalized)}

    assert "google.drive_anyone_with_link" in rule_ids
    assert "google.group_external_members_allowed" in rule_ids
    assert "google.group_anyone_can_post" in rule_ids


def test_google_drive_external_permission_finding() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_drive_posture": {
                "driveFiles": {
                    "value": [
                        {
                            "id": "file-1",
                            "name": "Board plan",
                            "permissions": [
                                {"id": "p-internal", "type": "user", "role": "reader", "emailAddress": "alice@example.com"},
                                {"id": "p-external", "type": "user", "role": "writer", "emailAddress": "consultant@other.test"},
                                {"id": "p-domain", "type": "domain", "role": "reader", "domain": "other.test"},
                            ],
                        }
                    ]
                },
            }
        },
    )

    findings = [finding for finding in build_google_findings(normalized) if finding["rule_id"] == "google.drive_external_permission"]

    assert len(findings) == 2
    assert {finding["severity"] for finding in findings} == {"high", "medium"}
    assert all("other.test" in str(finding["returned_value"]) for finding in findings)


def test_google_external_group_member_finding() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_directory": {
                "groupMembers": {
                    "value": [
                        {
                            "groupEmail": "all@example.com",
                            "id": "member-1",
                            "email": "external@other.test",
                            "role": "MEMBER",
                            "type": "USER",
                        }
                    ]
                }
            }
        },
    )

    finding = next(item for item in build_google_findings(normalized) if item["rule_id"] == "google.group_external_member")

    assert finding["severity"] == "medium"
    assert finding["affected_objects"] == ["external@other.test"]


def test_google_gmail_protocol_and_external_send_as_findings() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_gmail_settings": {
                "mailboxSettings": {
                    "value": [
                        {
                            "userEmail": "admin@example.com",
                            "imap": {"enabled": True},
                            "pop": {"accessWindow": "allMail"},
                            "sendAs": [
                                {
                                    "sendAsEmail": "billing@other.test",
                                    "verificationStatus": "accepted",
                                    "isPrimary": False,
                                },
                                {
                                    "sendAsEmail": "ops@other.test",
                                    "verificationStatus": "accepted",
                                    "isPrimary": False,
                                }
                            ],
                        }
                    ]
                }
            }
        },
    )

    findings = build_google_findings(normalized)
    rule_ids = {finding["rule_id"] for finding in findings}
    send_as_ids = [finding["id"] for finding in findings if finding["rule_id"] == "google.gmail_external_send_as"]

    assert "google.gmail_imap_enabled" in rule_ids
    assert "google.gmail_pop_enabled" in rule_ids
    assert "google.gmail_external_send_as" in rule_ids
    assert len(send_as_ids) == 2
    assert len(set(send_as_ids)) == 2


def test_google_gmail_external_forwarding_address_ready_finding() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_gmail_settings": {
                "mailboxSettings": {
                    "value": [
                        {
                            "userEmail": "admin@example.com",
                            "forwardingAddresses": [
                                {"forwardingEmail": "ok@example.com", "verificationStatus": "accepted"},
                                {"forwardingEmail": "ready@other.test", "verificationStatus": "accepted"},
                            ],
                        }
                    ]
                }
            }
        },
    )

    findings = [
        finding
        for finding in build_google_findings(normalized)
        if finding["rule_id"] == "google.gmail_external_forwarding_address_ready"
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert findings[0]["returned_value"] == "ready@other.test"


def test_google_gmail_external_delegate_finding() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_gmail_settings": {
                "mailboxSettings": {
                    "value": [
                        {
                            "userEmail": "alice@example.com",
                            "delegates": [
                                {"delegateEmail": "bob@example.com", "verificationStatus": "accepted"},
                                {"delegateEmail": "assistant@other.test", "verificationStatus": "accepted"},
                            ],
                        }
                    ]
                }
            }
        },
    )

    findings = [finding for finding in build_google_findings(normalized) if finding["rule_id"] == "google.gmail_external_delegate"]

    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["returned_value"] == "assistant@other.test"


def test_google_findings_use_rule_catalog_metadata() -> None:
    from auditex.google_workspace.findings import build_google_findings, google_rule_metadata

    normalized = {
        "snapshot": {"workspace_domain": "example.com"},
        "google_mailbox_settings": {
            "records": [
                {
                    "id": "mailbox:admin@example.com",
                    "user_email": "admin@example.com",
                    "auto_forwarding": {"enabled": True, "emailAddress": "outside@other.test"},
                }
            ]
        },
    }

    finding = next(
        item
        for item in build_google_findings(normalized)
        if item["rule_id"] == "google.gmail_external_forwarding"
    )
    metadata = google_rule_metadata()["google.gmail_external_forwarding"]

    assert finding["description"] == metadata["description"]
    assert finding["impact"] == metadata["impact"]
    assert finding["expected_value"] == metadata["expected_value"]
    assert finding["references"] == metadata["references"]
    assert finding["control_ids"] == metadata["control_ids"]


def test_google_calendar_posture_collector_uses_fake_client() -> None:
    from auditex.google_workspace.collectors import GoogleCalendarPostureCollector

    class _FakeClient:
        def __init__(self) -> None:
            self.acl_calls: list[str] = []

        def list_calendar_resources(self, **_kwargs):
            return [
                {
                    "resourceId": "room-1",
                    "resourceName": "Board Room",
                    "resourceEmail": "room-1@example.com",
                }
            ]

        def list_calendar_list(self, **_kwargs):
            return [{"id": "team@example.com", "summary": "Team Calendar", "accessRole": "owner"}]

        def list_calendar_acl(self, calendar_id: str, **_kwargs):
            self.acl_calls.append(calendar_id)
            return [
                {
                    "id": f"default:{calendar_id}",
                    "scope": {"type": "default"},
                    "role": "reader",
                }
            ]

    client = _FakeClient()
    result = GoogleCalendarPostureCollector().run({"client": client, "top": 10})

    assert result.status == "ok"
    assert result.payload["calendarResources"]["value"][0]["resourceEmail"] == "room-1@example.com"
    assert result.payload["calendarAcls"]["value"][0]["calendarId"] == "team@example.com"
    assert result.payload["calendarAcls"]["value"][1]["calendarId"] == "room-1@example.com"
    assert client.acl_calls == ["team@example.com", "room-1@example.com"]


def test_google_calendar_findings_from_sample() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_calendar_posture": {
                "calendarResources": {
                    "value": [
                        {
                            "resourceId": "room-1",
                            "resourceName": "Board Room",
                            "resourceEmail": "room-1@example.com",
                        }
                    ]
                },
                "calendars": {
                    "value": [{"id": "team@example.com", "summary": "Team Calendar", "accessRole": "owner"}]
                },
                "calendarAcls": {
                    "value": [
                        {
                            "calendarId": "team@example.com",
                            "id": "default",
                            "scope": {"type": "default"},
                            "role": "reader",
                        },
                        {
                            "calendarId": "team@example.com",
                            "id": "user:external@other.test",
                            "scope": {"type": "user", "value": "external@other.test"},
                            "role": "writer",
                        },
                    ]
                },
            }
        },
    )

    rule_ids = {finding["rule_id"] for finding in build_google_findings(normalized)}

    assert "google.calendar_public_acl" in rule_ids
    assert "google.calendar_external_acl" in rule_ids


def test_google_admin_resilience_findings() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    single_admin = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_directory": {
                "users": {
                    "value": [
                        {
                            "id": "admin-1",
                            "primaryEmail": "admin1@example.com",
                            "isAdmin": True,
                            "isEnforcedIn2Sv": True,
                        }
                    ]
                }
            }
        },
    )
    many_admins = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_directory": {
                "users": {
                    "value": [
                        {
                            "id": f"admin-{index}",
                            "primaryEmail": f"admin{index}@example.com",
                            "isAdmin": True,
                            "isEnforcedIn2Sv": True,
                        }
                        for index in range(6)
                    ]
                }
            }
        },
    )

    single_ids = {finding["rule_id"] for finding in build_google_findings(single_admin)}
    many_ids = {finding["rule_id"] for finding in build_google_findings(many_admins)}

    assert "google.super_admin_singleton" in single_ids
    assert "google.super_admin_sprawl" in many_ids


def test_google_stale_admin_login_finding() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_directory": {
                "users": {
                    "value": [
                        {
                            "id": "admin-1",
                            "primaryEmail": "admin1@example.com",
                            "isAdmin": True,
                            "isEnforcedIn2Sv": True,
                            "lastLoginTime": "2020-01-01T00:00:00.000Z",
                        },
                        {
                            "id": "admin-2",
                            "primaryEmail": "admin2@example.com",
                            "isAdmin": True,
                            "isEnforcedIn2Sv": True,
                            "lastLoginTime": "2026-01-01T00:00:00.000Z",
                        },
                    ]
                }
            }
        },
    )

    finding = next(item for item in build_google_findings(normalized) if item["rule_id"] == "google.admin_stale_login")

    assert finding["severity"] == "medium"
    assert finding["affected_objects"] == ["admin1@example.com"]


def test_google_admin_2sv_not_enrolled_finding() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_directory": {
                "users": {
                    "value": [
                        {
                            "id": "admin-1",
                            "primaryEmail": "admin1@example.com",
                            "isAdmin": True,
                            "isEnrolledIn2Sv": False,
                        }
                    ]
                }
            }
        },
    )

    finding = next(item for item in build_google_findings(normalized) if item["rule_id"] == "google.admin_2sv_not_enrolled")

    assert finding["severity"] == "high"
    assert finding["affected_objects"] == ["admin1@example.com"]


def test_google_active_user_2sv_not_enrolled_finding() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_directory": {
                "users": {
                    "value": [
                        {
                            "id": "user-1",
                            "primaryEmail": "user@example.com",
                            "isAdmin": False,
                            "suspended": False,
                            "isEnrolledIn2Sv": False,
                        },
                        {
                            "id": "user-2",
                            "primaryEmail": "suspended@example.com",
                            "isAdmin": False,
                            "suspended": True,
                            "isEnrolledIn2Sv": False,
                        },
                        {
                            "id": "admin-1",
                            "primaryEmail": "admin@example.com",
                            "isAdmin": True,
                            "suspended": False,
                            "isEnrolledIn2Sv": False,
                        },
                    ]
                }
            }
        },
    )

    findings = [
        item
        for item in build_google_findings(normalized)
        if item["rule_id"] == "google.user_2sv_not_enrolled"
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert findings[0]["affected_objects"] == ["user@example.com"]


def test_google_suspicious_login_activity_finding() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_reports": {
                "loginActivities": {
                    "value": [
                        {
                            "id": {"uniqueQualifier": "login-1"},
                            "actor": {"email": "alice@example.com"},
                            "events": [{"name": "suspicious_login"}],
                        },
                        {
                            "id": {"uniqueQualifier": "login-2"},
                            "actor": {"email": "bob@example.com"},
                            "events": [{"name": "login_success"}],
                        },
                    ]
                }
            }
        },
    )

    findings = [item for item in build_google_findings(normalized) if item["rule_id"] == "google.login_suspicious_event"]

    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["affected_objects"] == ["alice@example.com"]


def test_google_admin_privilege_activity_finding() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_reports": {
                "adminActivities": {
                    "value": [
                        {
                            "id": {"uniqueQualifier": "admin-activity-1"},
                            "actor": {"email": "admin@example.com"},
                            "events": [{"name": "ASSIGN_ROLE"}],
                        },
                        {
                            "id": {"uniqueQualifier": "admin-activity-2"},
                            "actor": {"email": "admin@example.com"},
                            "events": [{"name": "UPDATE_USER"}],
                        },
                    ]
                }
            }
        },
    )

    findings = [item for item in build_google_findings(normalized) if item["rule_id"] == "google.admin_privilege_event"]

    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["affected_objects"] == ["admin@example.com"]


def test_google_compromised_mobile_device_finding() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_devices": {
                "mobileDevices": {
                    "value": [
                        {
                            "resourceId": "mobile-1",
                            "email": ["user@example.com"],
                            "model": "iPhone",
                            "os": "iOS",
                            "status": "APPROVED",
                            "compromisedStatus": "Compromised",
                        }
                    ]
                }
            }
        },
    )

    finding = next(item for item in build_google_findings(normalized) if item["rule_id"] == "google.mobile_device_compromised")

    assert finding["severity"] == "high"
    assert finding["affected_objects"] == ["mobile-1"]


def test_google_stale_mobile_device_sync_finding() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain="example.com",
        customer_id="C123",
        collector_payloads={
            "google_devices": {
                "mobileDevices": {
                    "value": [
                        {
                            "resourceId": "mobile-1",
                            "email": ["user@example.com"],
                            "model": "Android",
                            "status": "APPROVED",
                            "lastSync": "2020-01-01T00:00:00.000Z",
                        },
                        {
                            "resourceId": "mobile-2",
                            "email": ["fresh@example.com"],
                            "model": "Android",
                            "status": "APPROVED",
                            "lastSync": "2026-05-20T00:00:00.000Z",
                        },
                    ]
                }
            }
        },
    )

    findings = [item for item in build_google_findings(normalized) if item["rule_id"] == "google.mobile_device_stale_sync"]

    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert findings[0]["affected_objects"] == ["mobile-1"]


def test_google_preflight_checks_calendar_posture() -> None:
    from auditex.google_workspace.run import build_google_preflight_rows

    class _FakeClient:
        def list_calendar_resources(self, **_kwargs):
            return [{"resourceId": "room-1"}]

    rows = build_google_preflight_rows(
        _FakeClient(),
        ["google_calendar_posture"],
        domain="example.com",
        top=1,
    )

    assert rows == [
        {
            "collector": "google_calendar_posture",
            "name": "calendarResources",
            "status": "ok",
            "item_count": 1,
            "duration_ms": rows[0]["duration_ms"],
            "error_class": None,
            "error": None,
        }
    ]


def test_google_rules_have_framework_mapping_floor() -> None:
    from auditex.google_workspace import findings as google_findings

    source = Path(google_findings.__file__).read_text(encoding="utf-8")
    rule_ids = sorted(set(re.findall(r'rule_id="(google\.[a-z0-9_]+)"', source)))

    assert rule_ids
    for rule_id in rule_ids:
        mapping = google_findings._GOOGLE_FRAMEWORK_MAPPINGS.get(rule_id)
        assert mapping is not None, f"{rule_id} missing framework mapping"
        assert mapping.get("google_workspace_baseline"), f"{rule_id} missing Google baseline mapping"
        assert mapping.get("nist_800_53") or mapping.get("iso_27001"), f"{rule_id} missing NIST or ISO mapping"
