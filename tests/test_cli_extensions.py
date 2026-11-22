from __future__ import annotations

import json

import pytest
from support import RunBundleBuilder, make_contract_valid

from auditex import cli as auditex_cli
from auditex import guided
from auditex.guided import build_guided_parser

_SAVED_AUTH_KEYS = (
    "M365_CLI_APP_ID", "M365_CLI_CLIENT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
    "AUDITEX_TENANT_ID", "AZURE_TENANT_ID", "AUDITEX_TENANT_NAME", "AUDITEX_M365_CONNECTION_NAME",
)


@pytest.fixture(autouse=True)
def _no_saved_auth_values(monkeypatch):  # noqa: ANN001
    """Guided runs save auth values into os.environ; each test starts without another test's saved app or tenant."""
    for key in _SAVED_AUTH_KEYS:
        monkeypatch.delenv(key, raising=False)


def _bundle(base, name: str = "run-a") -> str:
    """A real, contract-valid synthetic run bundle: the global run-dir guard stays on for dispatch tests."""
    return str(make_contract_valid(RunBundleBuilder(base, name).manifest(tenant_name="synthetic").build()))


def test_root_help_lists_operator_commands(capsys) -> None:
    rc = auditex_cli.main(["--help"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "guided-run" in output
    assert "compare" in output
    assert "report" in output
    assert "run" in output


def test_root_version_prints_shared_package_version(monkeypatch, capsys) -> None:
    monkeypatch.setattr("auditex.cli.package_version_line", lambda name="auditex": f"{name} 9.9.9")

    rc = auditex_cli.main(["--version"])

    assert rc == 0
    assert capsys.readouterr().out.strip() == "auditex 9.9.9"


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


def test_compare_cli_dispatches(monkeypatch, capsys, tmp_path) -> None:
    run_a, run_b = _bundle(tmp_path, "run-a"), _bundle(tmp_path, "run-b")
    monkeypatch.setattr(
        "auditex.cli.compare_runs",
        lambda run_dirs, allow_cross_tenant=False, classic=False: {
            "runs": [{"path": path} for path in run_dirs],
            "same_tenant": not allow_cross_tenant,
            "classic": classic,
        },
    )

    rc = auditex_cli.main(["compare", "--run-dir", run_a, "--run-dir", run_b])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert [row["path"] for row in payload["runs"]] == [run_a, run_b]


def test_compare_cli_dispatches_classic_flag(monkeypatch, capsys, tmp_path) -> None:
    run_a, run_b = _bundle(tmp_path, "run-a"), _bundle(tmp_path, "run-b")
    seen: dict[str, object] = {}

    def _fake_compare(run_dirs, allow_cross_tenant=False, classic=False):  # noqa: ANN001
        seen["run_dirs"] = run_dirs
        seen["allow_cross_tenant"] = allow_cross_tenant
        seen["classic"] = classic
        return {"runs": [{"path": path} for path in run_dirs], "classic": classic}

    monkeypatch.setattr("auditex.cli.compare_runs", _fake_compare)

    rc = auditex_cli.main(["compare", "--run-dir", run_a, "--run-dir", run_b, "--classic"])

    assert rc == 0
    assert seen["classic"] is True
    assert list(seen["run_dirs"]) == [run_a, run_b]
    payload = json.loads(capsys.readouterr().out)
    assert payload["classic"] is True


def test_report_render_cli_dispatches(monkeypatch, capsys, tmp_path) -> None:
    run_a = _bundle(tmp_path)
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
            run_a,
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


def test_report_analyze_cli_dispatches(monkeypatch, capsys, tmp_path) -> None:
    monkeypatch.setattr(
        "auditex.cli.analyze_report",
        lambda run_dir: {"run_dir": run_dir, "auditor_score": {"grade": "usable"}},
    )

    rc = auditex_cli.main(["report", "analyze", _bundle(tmp_path)])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["run_dir"] == "<run-dir>"
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


def test_export_run_cli_dispatches(monkeypatch, capsys, tmp_path) -> None:
    run_a = _bundle(tmp_path)
    monkeypatch.setattr(
        "auditex.cli.run_exporter",
        lambda **kwargs: {"exporter": kwargs["name"], "run_dir": kwargs["run_dir"]},
    )

    rc = auditex_cli.main(["export", "run", "html", run_a])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["exporter"] == "html"
    assert payload["run_dir"] == run_a


def test_notify_send_cli_dispatches(monkeypatch, capsys, tmp_path) -> None:
    run_a = _bundle(tmp_path)
    monkeypatch.setattr(
        "auditex.cli.send_notification",
        lambda **kwargs: {"sink": kwargs["sink"], "dry_run": kwargs["dry_run"]},
    )

    rc = auditex_cli.main(["notify", "send", run_a, "--sink", "teams"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sink"] == "teams"
    assert payload["dry_run"] is True


def test_report_render_cli_accepts_security_export_formats(monkeypatch, capsys, tmp_path) -> None:
    run_a = _bundle(tmp_path)
    monkeypatch.setattr(
        "auditex.cli.render_report",
        lambda **kwargs: {"format": kwargs["format_name"], "output_path": "rendered"},
    )

    rc = auditex_cli.main(["report", "render", run_a, "--format", "oscal"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["format"] == "oscal"


_THUMBPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"
_READY_DOCTOR = {
    "system": {"os": "Darwin", "machine": "arm64"},
    "readiness": {"core_ready": True, "exchange_ready": True, "pwsh_ready": True},
}


def _certificate_args(tmp_path, *extra: str) -> list[str]:
    return [
        "--tenant-id", "contoso.onmicrosoft.com", "--tenant-name", "CONTOSO", "--out", str(tmp_path),
        "--client-id", "app-id", "--certificate-path", "reader.key.pem", "--certificate-thumbprint", _THUMBPRINT,
        *extra,
    ]


def _capture_engine(monkeypatch) -> dict[str, object]:  # noqa: ANN001
    seen: dict[str, object] = {}
    monkeypatch.setattr(guided, "build_doctor_report", lambda: dict(_READY_DOCTOR))
    monkeypatch.setattr(
        "auditex.guided.tenant_cli.main",
        lambda argv, event_listener=None, **_: seen.update({"argv": list(argv)}) or 0,
    )
    return seen


def test_guided_parser_takes_the_certificate_and_tool_options() -> None:
    args = build_guided_parser().parse_args(
        ["--tenant-id", "contoso.onmicrosoft.com", "--client-id", "app-id", "--certificate-path", "reader.key.pem",
         "--certificate-thumbprint", _THUMBPRINT, "--certificate-password-file", "reader.pw", "--skip-tool-check",
         "--report-format", "sarif"]
    )

    assert (args.flow, args.client_id, args.certificate_path) == ("auto", "app-id", "reader.key.pem")
    assert args.certificate_thumbprint == _THUMBPRINT and args.certificate_password_file == "reader.pw"
    assert args.skip_tool_check is True and args.report_format == "sarif"


@pytest.mark.parametrize("removed", [
    ["--auth-mode", "app"], ["--client-secret", "x"], ["--browser-command", "safari"], ["--local-mode"],
    ["--skip-login-check"], ["--include-exchange"], ["--flow", "gr-audit"], ["--flow", "ga-setup-app"],
])
def test_guided_parser_has_no_removed_sign_in_option(removed: list[str]) -> None:
    with pytest.raises(SystemExit):
        build_guided_parser().parse_args(["--tenant-id", "contoso.onmicrosoft.com", *removed])


@pytest.mark.parametrize("flag", ["--client-secret", "--access-token", "--auth-context", "--interactive"])
def test_guided_run_refuses_a_removed_sign_in_flag_by_name_without_its_value(flag, capsys) -> None:  # noqa: ANN001
    canary = "constructed-guided-canary"
    argv = ["guided-run", "--tenant-id", "contoso.onmicrosoft.com", f"{flag}={canary}"]
    with pytest.raises(SystemExit) as exc:
        auditex_cli.main(argv)

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert f"error: {flag} was removed." in err and "docs/guides/reader-app-permissions.md" in err
    assert canary not in err


def test_guided_run_passes_the_certificate_to_the_engine(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    seen = _capture_engine(monkeypatch)
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "constructed-saved-secret")

    rc = guided.run_guided(build_guided_parser().parse_args(
        [*_certificate_args(tmp_path, "--certificate-password-env", "READER_KEY_PASSWORD"), "--non-interactive"]
    ))

    assert rc == 0
    argv = seen["argv"]
    assert argv[argv.index("--client-id") + 1] == "app-id"
    assert argv[argv.index("--certificate-path") + 1] == "reader.key.pem"
    assert argv[argv.index("--certificate-thumbprint") + 1] == _THUMBPRINT
    assert argv[argv.index("--certificate-password-env") + 1] == "READER_KEY_PASSWORD"
    assert argv[argv.index("--tenant-id") + 1] == "contoso.onmicrosoft.com"
    for removed in ("--client-secret", "--use-azure-cli-token", "--interactive", "--browser-command",
                    "--include-exchange", "--exclude"):
        assert removed not in argv
    assert "constructed-saved-secret" not in argv
    assert "--probe-first" in argv


def test_guided_run_reads_the_tenant_and_client_id_from_the_environment(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    seen = _capture_engine(monkeypatch)
    monkeypatch.setenv("AZURE_TENANT_ID", "fabrikam.onmicrosoft.com")
    monkeypatch.setenv("AZURE_CLIENT_ID", "env-app-id")

    rc = guided.run_guided(build_guided_parser().parse_args(
        ["--out", str(tmp_path), "--certificate-path", "reader.key.pem", "--certificate-thumbprint", _THUMBPRINT,
         "--non-interactive"]
    ))

    assert rc == 0
    argv = seen["argv"]
    assert argv[argv.index("--tenant-id") + 1] == "fabrikam.onmicrosoft.com"
    assert argv[argv.index("--tenant-name") + 1] == "FABRIKAM"
    assert argv[argv.index("--client-id") + 1] == "env-app-id"


def test_guided_run_requires_a_real_tenant(monkeypatch, tmp_path, capsys) -> None:  # noqa: ANN001
    seen = _capture_engine(monkeypatch)

    rc = guided.run_guided(build_guided_parser().parse_args(
        ["--client-id", "app-id", "--certificate-path", "k.pem", "--certificate-thumbprint", _THUMBPRINT,
         "--out", str(tmp_path), "--non-interactive"]
    ))

    assert rc == 2
    assert "Real tenant id or domain needed" in capsys.readouterr().out
    assert "argv" not in seen


@pytest.mark.parametrize("missing", ["--client-id", "--certificate-path", "--certificate-thumbprint"])
def test_guided_run_needs_the_reader_app_values(monkeypatch, tmp_path, capsys, missing) -> None:  # noqa: ANN001
    seen = _capture_engine(monkeypatch)
    args = _certificate_args(tmp_path)
    index = args.index(missing)
    del args[index:index + 2]

    rc = guided.run_guided(build_guided_parser().parse_args([*args, "--non-interactive"]))

    assert rc == 2
    out = capsys.readouterr().out
    assert "--certificate-path" in out and "docs/guides/reader-app-permissions.md" in out
    assert "argv" not in seen


def test_guided_run_prompts_for_the_reader_app_values(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    seen = _capture_engine(monkeypatch)
    answers = iter(["contoso.onmicrosoft.com", "", "app-id", "reader.key.pem", _THUMBPRINT])
    monkeypatch.setattr(guided, "_read_prompt", lambda prompt: next(answers))

    rc = guided.run_guided(build_guided_parser().parse_args(["--out", str(tmp_path)]))

    assert rc == 0
    argv = seen["argv"]
    assert argv[argv.index("--tenant-name") + 1] == "CONTOSO"
    assert argv[argv.index("--certificate-path") + 1] == "reader.key.pem"
    assert argv[argv.index("--certificate-thumbprint") + 1] == _THUMBPRINT


def test_guided_run_installs_exchange_tooling_when_it_is_missing(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    seen = _capture_engine(monkeypatch)
    monkeypatch.setattr(guided, "build_doctor_report", lambda: {
        "system": {"os": "Darwin", "machine": "arm64"},
        "readiness": {"core_ready": True, "exchange_ready": False, "pwsh_ready": False},
    })
    setup: dict[str, object] = {}
    monkeypatch.setattr(guided, "run_setup", lambda **kwargs: setup.update(kwargs) or 0)

    rc = guided.run_guided(build_guided_parser().parse_args([*_certificate_args(tmp_path), "--non-interactive", "--install-tools"]))

    assert rc == 0
    assert setup == {"with_mcp": False, "with_exchange": True, "with_pwsh": True}
    assert "argv" in seen


def test_guided_run_stops_when_tool_setup_fails(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    seen = _capture_engine(monkeypatch)
    monkeypatch.setattr(guided, "build_doctor_report", lambda: {
        "system": {"os": "Darwin", "machine": "arm64"},
        "readiness": {"core_ready": False, "exchange_ready": True},
    })
    monkeypatch.setattr(guided, "run_setup", lambda **kwargs: 7)

    rc = guided.run_guided(build_guided_parser().parse_args([*_certificate_args(tmp_path), "--non-interactive", "--install-tools"]))

    assert rc == 7
    assert "argv" not in seen


def test_guided_explicit_collectors_pass_through_unchanged(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    seen = _capture_engine(monkeypatch)

    rc = guided.run_guided(build_guided_parser().parse_args(
        [*_certificate_args(tmp_path, "--collectors", "identity,exchange_policy"), "--non-interactive"]
    ))

    assert rc == 0
    argv = seen["argv"]
    assert argv[argv.index("--collectors") + 1] == "identity,exchange_policy"
    assert "--exclude" not in argv
