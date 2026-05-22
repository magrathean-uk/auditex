from __future__ import annotations

import json

from auditex import cli as auditex_cli
from auditex import guided
from auditex.guided import build_guided_parser


def test_root_help_lists_operator_commands(capsys) -> None:
    rc = auditex_cli.main(["--help"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "guided-run" in output
    assert "compare" in output
    assert "report" in output
    assert "run" in output


def test_setup_cli_accepts_optional_runtime_packs(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_run_setup(**kwargs):  # noqa: ANN003
        seen.update(kwargs)
        return 0

    monkeypatch.setattr("auditex.cli.run_setup", _fake_run_setup)

    rc = auditex_cli.main(["setup", "--mcp", "--exchange", "--pwsh"])

    assert rc == 0
    assert seen == {"with_mcp": True, "with_exchange": True, "with_pwsh": True}


def test_rules_inventory_cli_accepts_routing_filters(monkeypatch, capsys) -> None:
    seen: dict[str, object] = {}

    def _fake_list_rule_inventory(**kwargs):  # noqa: ANN003
        seen.update(kwargs)
        return [{"name": "alpha.rule", "path": "rules/alpha.json"}]

    monkeypatch.setattr("auditex.cli.list_rule_inventory", _fake_list_rule_inventory)

    rc = auditex_cli.main(
        [
            "rules",
            "inventory",
            "--platform",
            "google_workspace",
            "--product-family",
            "identity",
            "--license-tier",
            "p2",
            "--audit-level",
            "deep",
        ]
    )

    assert rc == 0
    assert seen["platform"] == "google_workspace"
    assert seen["product_family"] == "identity"
    assert seen["license_tier"] == "p2"
    assert seen["audit_level"] == "deep"
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 1


def test_compare_cli_dispatches(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.compare_runs",
        lambda run_dirs, allow_cross_tenant=False: {
            "runs": [{"path": path} for path in run_dirs],
            "same_tenant": not allow_cross_tenant,
        },
    )

    rc = auditex_cli.main(["compare", "--run-dir", "run-a", "--run-dir", "run-b"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert [row["path"] for row in payload["runs"]] == ["run-a", "run-b"]


def test_report_render_cli_dispatches(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.render_report",
        lambda **kwargs: {
            "format": kwargs["format_name"],
            "include_sections": kwargs["include_sections"],
        },
    )

    rc = auditex_cli.main(
        [
            "report",
            "render",
            "run-a",
            "--format",
            "html",
            "--include-section",
            "summary",
            "--include-section",
            "findings",
        ]
    )

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["format"] == "html"
    assert payload["include_sections"] == ["summary", "findings"]


def test_report_analyze_cli_dispatches(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.analyze_report",
        lambda run_dir: {"run_dir": run_dir, "auditor_score": {"grade": "usable"}},
    )

    rc = auditex_cli.main(["report", "analyze", "run-a"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["run_dir"] == "run-a"
    assert payload["auditor_score"]["grade"] == "usable"


def test_export_list_cli_dispatches(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.list_exporters",
        lambda: [{"name": "html", "formats": ["html"]}],
    )

    rc = auditex_cli.main(["export", "list"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["exporters"][0]["name"] == "html"


def test_export_run_cli_dispatches(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.run_exporter",
        lambda **kwargs: {"exporter": kwargs["name"], "run_dir": kwargs["run_dir"]},
    )

    rc = auditex_cli.main(["export", "run", "html", "run-a"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["exporter"] == "html"
    assert payload["run_dir"] == "run-a"


def test_notify_send_cli_dispatches(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.send_notification",
        lambda **kwargs: {"sink": kwargs["sink"], "dry_run": kwargs["dry_run"]},
    )

    rc = auditex_cli.main(["notify", "send", "run-a", "--sink", "teams"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sink"] == "teams"
    assert payload["dry_run"] is True


def test_guided_parser_accepts_local_mode_flags() -> None:
    args = build_guided_parser().parse_args(
        [
            "--tenant-id",
            "contoso.onmicrosoft.com",
            "--local-mode",
            "--skip-login-check",
            "--skip-tool-check",
            "--report-format",
            "sarif",
        ]
    )

    assert args.local_mode is True
    assert args.skip_login_check is True
    assert args.skip_tool_check is True
    assert args.report_format == "sarif"


def test_report_render_cli_accepts_security_export_formats(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.render_report",
        lambda **kwargs: {"format": kwargs["format_name"], "output_path": "rendered"},
    )

    rc = auditex_cli.main(["report", "render", "run-a", "--format", "oscal"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["format"] == "oscal"


def test_guided_parser_accepts_app_mode_flags() -> None:
    args = build_guided_parser().parse_args(
        [
            "--tenant-id",
            "contoso.onmicrosoft.com",
            "--auth-mode",
            "app",
            "--client-id",
            "app-id",
            "--client-secret",
            "app-secret",
        ]
    )

    assert args.auth_mode == "app"
    assert args.client_id == "app-id"
    assert args.client_secret == "app-secret"


def test_guided_parser_accepts_flow_flag() -> None:
    args = build_guided_parser().parse_args(
        [
            "--flow",
            "ga-setup-app",
            "--tenant-id",
            "contoso.onmicrosoft.com",
        ]
    )

    assert args.flow == "ga-setup-app"


def test_guided_run_requires_exchange_login_when_requested(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    monkeypatch.setattr(
        guided,
        "build_doctor_report",
        lambda **kwargs: {
            "system": {"os": "Darwin", "machine": "arm64"},
            "auth": {"azure_cli": {"status": "supported"}},
            "readiness": {"core_ready": True, "exchange_ready": True},
        },
    )
    monkeypatch.setattr(guided, "_ensure_exchange_module", lambda **_: 0)
    monkeypatch.setattr(guided, "_ensure_m365_login", lambda tenant_id, browser_command, **kwargs: 5)
    monkeypatch.setattr("auditex.guided.tenant_cli.main", lambda *args, **kwargs: 0)

    rc = guided.run_guided(
        build_guided_parser().parse_args(
            [
                "--tenant-id",
                "contoso.onmicrosoft.com",
                "--tenant-name",
                "CONTOSO",
                "--out",
                str(tmp_path),
                "--include-exchange",
                "--non-interactive",
            ]
        )
    )

    assert rc == 5


def test_guided_run_exchange_setup_adds_pwsh(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    seen: dict[str, object] = {}

    monkeypatch.setattr(
        guided,
        "build_doctor_report",
        lambda **kwargs: {
            "system": {"os": "Darwin", "machine": "arm64"},
            "auth": {"azure_cli": {"status": "supported"}},
            "readiness": {"core_ready": True, "exchange_ready": False},
        },
    )
    monkeypatch.setattr(guided, "run_setup", lambda **kwargs: seen.update(kwargs) or 0)
    monkeypatch.setattr(guided, "_ensure_exchange_module", lambda **_: 0)
    monkeypatch.setattr(guided, "_ensure_m365_login", lambda tenant_id, browser_command, **kwargs: 0)
    monkeypatch.setattr("auditex.guided.tenant_cli.main", lambda *args, **kwargs: 0)

    rc = guided.run_guided(
        build_guided_parser().parse_args(
            [
                "--tenant-id",
                "contoso.onmicrosoft.com",
                "--tenant-name",
                "CONTOSO",
                "--out",
                str(tmp_path),
                "--include-exchange",
                "--non-interactive",
            ]
        )
    )

    assert rc == 0
    assert seen == {"with_mcp": False, "with_exchange": True, "with_pwsh": True}


def test_guided_run_app_mode_skips_azure_login_and_passes_client_credentials(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    seen: dict[str, object] = {}

    monkeypatch.setattr(
        guided,
        "build_doctor_report",
        lambda **kwargs: {
            "system": {"os": "Darwin", "machine": "arm64"},
            "auth": {"azure_cli": {"status": "blocked"}},
            "readiness": {"core_ready": True, "exchange_ready": True},
        },
    )
    monkeypatch.setattr(guided, "_run_azure_login", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not login")))
    monkeypatch.setattr(
        "auditex.guided.tenant_cli.main",
        lambda argv, event_listener=None: seen.update({"argv": list(argv)}) or 0,
    )

    rc = guided.run_guided(
        build_guided_parser().parse_args(
            [
                "--tenant-id",
                "contoso.onmicrosoft.com",
                "--tenant-name",
                "CONTOSO",
                "--out",
                str(tmp_path),
                "--auth-mode",
                "app",
                "--client-id",
                "app-id",
                "--client-secret",
                "app-secret",
                "--non-interactive",
            ]
        )
    )

    assert rc == 0
    assert "--use-azure-cli-token" not in seen["argv"]
    assert "--client-id" in seen["argv"]
    assert "--client-secret" in seen["argv"]


def test_guided_run_app_mode_requires_real_tenant(monkeypatch, tmp_path, capsys) -> None:  # noqa: ANN001
    monkeypatch.delenv("AUDITEX_TENANT_ID", raising=False)
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.delenv("AUDITEX_TENANT_NAME", raising=False)
    monkeypatch.setattr(
        guided,
        "build_doctor_report",
        lambda **kwargs: {
            "system": {"os": "Darwin", "machine": "arm64"},
            "auth": {},
            "readiness": {"core_ready": True, "exchange_ready": True},
        },
    )

    rc = guided.run_guided(
        build_guided_parser().parse_args(
            [
                "--auth-mode",
                "app",
                "--client-id",
                "app-id",
                "--client-secret",
                "app-secret",
                "--out",
                str(tmp_path),
                "--non-interactive",
            ]
        )
    )

    assert rc == 2
    assert "Real tenant id or domain needed" in capsys.readouterr().out


def test_guided_run_ga_setup_flow_saves_app_defaults(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    seen: dict[str, object] = {}

    monkeypatch.setattr(
        guided,
        "build_doctor_report",
        lambda **kwargs: {
            "system": {"os": "Darwin", "machine": "arm64"},
            "auth": {"azure_cli": {"status": "supported", "tenant_id": "contoso.onmicrosoft.com"}},
            "readiness": {"core_ready": True, "exchange_ready": True},
        },
    )
    monkeypatch.setattr(guided, "_ensure_exchange_module", lambda **_: 0)
    monkeypatch.setattr(guided, "_run_m365_setup", lambda: 0)
    monkeypatch.setattr(guided, "_ensure_m365_login", lambda *args, **kwargs: 0)
    monkeypatch.setattr(
        "auditex.guided.auditex_auth.save_local_auth_values",
        lambda payload: seen.setdefault("saved", []).append(dict(payload)),
    )
    monkeypatch.setattr(
        "auditex.guided.auditex_auth.get_auth_status",
        lambda **kwargs: {"m365": {"active_connection": "tenant-user"}},
    )

    rc = guided.run_guided(
        build_guided_parser().parse_args(
            [
                "--flow",
                "ga-setup-app",
                "--tenant-id",
                "contoso.onmicrosoft.com",
                "--tenant-name",
                "CONTOSO",
                "--client-id",
                "app-id",
                "--client-secret",
                "app-secret",
                "--out",
                str(tmp_path),
                "--non-interactive",
            ]
        )
    )

    assert rc == 0
    assert len(seen["saved"]) == 2
    assert seen["saved"][0]["M365_CLI_APP_ID"] == "app-id"
    assert seen["saved"][1]["AUDITEX_M365_CONNECTION_NAME"] == "tenant-user"


def test_guided_run_app_audit_uses_saved_local_defaults(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    seen: dict[str, object] = {}

    monkeypatch.setattr(
        guided,
        "build_doctor_report",
        lambda **kwargs: {
            "system": {"os": "Darwin", "machine": "arm64"},
            "auth": {},
            "readiness": {"core_ready": True, "exchange_ready": True},
        },
    )
    monkeypatch.setenv("AUDITEX_TENANT_ID", "contoso.onmicrosoft.com")
    monkeypatch.setenv("AUDITEX_TENANT_NAME", "CONTOSO")
    monkeypatch.setenv("AZURE_CLIENT_ID", "saved-app-id")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "saved-app-secret")
    monkeypatch.setattr(
        "auditex.guided.tenant_cli.main",
        lambda argv, event_listener=None: seen.update({"argv": list(argv)}) or 0,
    )
    monkeypatch.setattr(
        "auditex.guided.auditex_auth.save_local_auth_values",
        lambda payload: seen.setdefault("saved", []).append(dict(payload)),
    )

    rc = guided.run_guided(
        build_guided_parser().parse_args(
            [
                "--flow",
                "app-audit",
                "--out",
                str(tmp_path),
                "--non-interactive",
            ]
        )
    )

    assert rc == 0
    assert "--client-id" in seen["argv"]
    assert "saved-app-id" in seen["argv"]
    assert "--client-secret" in seen["argv"]
    assert "saved-app-secret" in seen["argv"]


def test_guided_run_delegated_relogs_when_azure_tenant_mismatched(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    seen: dict[str, object] = {}

    monkeypatch.setattr(
        guided,
        "build_doctor_report",
        lambda **kwargs: {
            "system": {"os": "Darwin", "machine": "arm64"},
            "auth": {"azure_cli": {"status": "supported", "tenant_id": "wrong-tenant"}},
            "readiness": {"core_ready": True, "exchange_ready": True},
        },
    )
    monkeypatch.setattr(guided, "_run_azure_login", lambda tenant_id, browser_command: seen.update({"tenant_id": tenant_id}) or 0)
    monkeypatch.setattr("auditex.guided.tenant_cli.main", lambda *args, **kwargs: 0)

    rc = guided.run_guided(
        build_guided_parser().parse_args(
            [
                "--tenant-id",
                "contoso.onmicrosoft.com",
                "--tenant-name",
                "CONTOSO",
                "--out",
                str(tmp_path),
                "--non-interactive",
            ]
        )
    )

    assert rc == 0
    assert seen["tenant_id"] == "contoso.onmicrosoft.com"


def test_guided_run_app_exchange_uses_secret_m365_login(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    seen: dict[str, object] = {}

    monkeypatch.setattr(
        guided,
        "build_doctor_report",
        lambda **kwargs: {
            "system": {"os": "Darwin", "machine": "arm64"},
            "auth": {},
            "readiness": {"core_ready": True, "exchange_ready": True},
        },
    )
    monkeypatch.setattr(guided, "_ensure_exchange_module", lambda **_: 0)
    monkeypatch.setattr(
        guided,
        "_ensure_m365_login",
        lambda tenant_id, browser_command, **kwargs: seen.update(
            {"tenant_id": tenant_id, "auth_mode": kwargs.get("auth_mode"), "client_id": kwargs.get("client_id")}
        )
        or 0,
    )
    monkeypatch.setattr("auditex.guided.tenant_cli.main", lambda *args, **kwargs: 0)

    rc = guided.run_guided(
        build_guided_parser().parse_args(
            [
                "--tenant-id",
                "contoso.onmicrosoft.com",
                "--tenant-name",
                "CONTOSO",
                "--out",
                str(tmp_path),
                "--auth-mode",
                "app",
                "--client-id",
                "app-id",
                "--client-secret",
                "app-secret",
                "--include-exchange",
                "--non-interactive",
            ]
        )
    )

    assert rc == 0
    assert seen == {"tenant_id": "contoso.onmicrosoft.com", "auth_mode": "app", "client_id": "app-id"}


def test_guided_run_delegated_gr_audit_uses_azure_cli_token(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    seen: dict[str, object] = {}

    monkeypatch.setattr(
        guided,
        "build_doctor_report",
        lambda **kwargs: {
            "system": {"os": "Darwin", "machine": "arm64"},
            "auth": {"azure_cli": {"status": "supported", "tenant_id": "contoso.onmicrosoft.com"}},
            "readiness": {"core_ready": True, "exchange_ready": True},
        },
    )
    monkeypatch.setattr(guided, "_run_azure_login", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no login")))
    monkeypatch.setattr(guided, "_ensure_exchange_module", lambda **_: (_ for _ in ()).throw(AssertionError("no exchange")))
    monkeypatch.setattr(guided, "_ensure_m365_login", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no m365")))
    monkeypatch.setattr(
        "auditex.guided.tenant_cli.main",
        lambda argv, event_listener=None: seen.update({"argv": list(argv)}) or 0,
    )

    rc = guided.run_guided(
        build_guided_parser().parse_args(
            [
                "--tenant-id",
                "contoso.onmicrosoft.com",
                "--tenant-name",
                "CONTOSO",
                "--auditor-profile",
                "global-reader",
                "--out",
                str(tmp_path),
                "--non-interactive",
            ]
        )
    )

    assert rc == 0
    assert "--use-azure-cli-token" in seen["argv"]
    assert "--client-id" not in seen["argv"]
    assert "--client-secret" not in seen["argv"]
    assert seen["argv"][seen["argv"].index("--auditor-profile") + 1] == "global-reader"


def test_guided_run_ga_app_setup_writes_local_app_state_and_reuses_it(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    auth_env = tmp_path / "m365-auth.env"
    seen: dict[str, object] = {}
    run_calls: list[list[str]] = []

    monkeypatch.setenv("AUDITEX_LOCAL_AUTH_ENV", str(auth_env))
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("M365_CLI_APP_ID", raising=False)
    monkeypatch.delenv("M365_CLI_CLIENT_ID", raising=False)
    monkeypatch.setattr(
        guided,
        "build_doctor_report",
        lambda **kwargs: {
            "system": {"os": "Darwin", "machine": "arm64"},
            "auth": {"azure_cli": {"status": "supported", "tenant_id": "contoso.onmicrosoft.com"}},
            "readiness": {"core_ready": True, "exchange_ready": True},
        },
    )
    monkeypatch.setattr(guided, "_run_azure_login", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no login")))
    monkeypatch.setattr(guided, "_confirm", lambda label, default=True: True)
    monkeypatch.setattr(
        guided,
        "_prompt",
        lambda label, default=None: "ga-app-id" if label == "App id to save" else (default or ""),
    )
    monkeypatch.setattr(guided, "_ensure_exchange_module", lambda **_: 0)
    monkeypatch.setattr(
        guided.auditex_auth,
        "get_auth_status",
        lambda **kwargs: {
            "m365": {
                "status": "supported",
                "active_connection": "ga-conn",
                "authenticated": True,
                "auth_type": "browser",
                "tenant_id": "contoso.onmicrosoft.com",
            }
        },
    )

    def _fake_run(command, **kwargs):  # noqa: ANN001
        run_calls.append(list(command))
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(guided.subprocess, "run", _fake_run)
    monkeypatch.setattr(
        "auditex.guided.tenant_cli.main",
        lambda argv, event_listener=None: seen.update({"argv": list(argv)}) or 0,
    )

    rc = guided.run_guided(
        build_guided_parser().parse_args(
            [
                "--flow",
                "ga-setup-app",
                "--tenant-id",
                "contoso.onmicrosoft.com",
                "--tenant-name",
                "CONTOSO",
                "--client-id",
                "ga-app-id",
                "--include-exchange",
                "--out",
                str(tmp_path),
                "--non-interactive",
            ]
        )
    )

    assert rc == 0
    rendered = auth_env.read_text(encoding="utf-8")
    assert "M365_CLI_APP_ID=ga-app-id" in rendered
    assert "AUDITEX_M365_CONNECTION_NAME=ga-conn" in rendered


def test_guided_run_reuses_saved_local_app_state(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    auth_env = tmp_path / "m365-auth.env"
    auth_env.write_text("M365_CLI_APP_ID=saved-app-id\n", encoding="utf-8")
    seen: dict[str, object] = {}

    monkeypatch.setenv("AUDITEX_LOCAL_AUTH_ENV", str(auth_env))
    monkeypatch.setattr(
        guided,
        "build_doctor_report",
        lambda **kwargs: {
            "system": {"os": "Darwin", "machine": "arm64"},
            "auth": {
                "azure_cli": {"status": "supported", "tenant_id": "contoso.onmicrosoft.com"},
                "m365": {"status": "supported", "active_connection": "saved-conn", "authenticated": True, "auth_type": "browser", "tenant_id": "contoso.onmicrosoft.com"},
            },
            "readiness": {"core_ready": True, "exchange_ready": True},
        },
    )
    monkeypatch.setattr(guided, "_run_azure_login", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no login")))
    monkeypatch.setattr(guided, "_offer_m365_setup", lambda *_: (_ for _ in ()).throw(AssertionError("no setup")))
    monkeypatch.setattr(guided, "_ensure_exchange_module", lambda **_: 0)
    monkeypatch.setattr(
        guided.auditex_auth,
        "get_auth_status",
        lambda: {
            "m365": {
                "status": "supported",
                "active_connection": "saved-conn",
                "authenticated": True,
                "auth_type": "browser",
                "tenant_id": "contoso.onmicrosoft.com",
            }
        },
    )
    monkeypatch.setattr(
        "auditex.guided.tenant_cli.main",
        lambda argv, event_listener=None: seen.update({"argv": list(argv)}) or 0,
    )

    rc = guided.run_guided(
        build_guided_parser().parse_args(
            [
                "--tenant-id",
                "contoso.onmicrosoft.com",
                "--tenant-name",
                "CONTOSO",
                "--include-exchange",
                "--out",
                str(tmp_path),
                "--non-interactive",
            ]
        )
    )

    assert rc == 0
    rendered = auth_env.read_text(encoding="utf-8")
    assert "M365_CLI_APP_ID=saved-app-id" in rendered
    assert "AUDITEX_TENANT_ID=contoso.onmicrosoft.com" in rendered
    assert "AUDITEX_M365_CONNECTION_NAME=saved-conn" in rendered
    assert "--include-exchange" in seen["argv"]
