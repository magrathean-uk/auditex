from __future__ import annotations

import pytest

from auditex.command_builders import (
    AuditRunCommandSpec,
    GoogleRunCommandSpec,
    ProbeCommandSpec,
    ResponseCommandSpec,
    build_audit_run_command,
    build_google_run_command,
    build_probe_command,
    build_response_command,
)


def test_offline_audit_command_is_stable_and_does_not_include_auth() -> None:
    command = build_audit_run_command(
        AuditRunCommandSpec(
            tenant_name="demo",
            out_dir="outputs/offline",
            auditor_profile="auto",
            offline=True,
            python_executable="python",
        )
    )
    assert command == [
        "python",
        "-m",
        "azure_tenant_audit",
        "--tenant-name",
        "demo",
        "--out",
        "outputs/offline",
        "--auditor-profile",
        "auto",
        "--plane",
        "inventory",
        "--offline",
        "--sample",
        "examples/sample_audit_bundle/sample_result.json",
    ]
    assert "--access-token" not in command


def test_live_audit_command_carries_the_reader_app_certificate() -> None:
    command = build_audit_run_command(
        AuditRunCommandSpec(
            tenant_name="ACME",
            tenant_id="contoso.onmicrosoft.com",
            out_dir="outputs/live",
            collectors=["identity", "security"],
            client_id="app-id",
            certificate_path="reader.key.pem",
            certificate_thumbprint="A" * 40,
            certificate_password_file="reader.pw",
            python_executable="python",
        )
    )
    assert command[command.index("--collectors") + 1] == "identity,security"
    assert command[-8:] == ["--client-id", "app-id", "--certificate-path", "reader.key.pem",
                            "--certificate-thumbprint", "A" * 40, "--certificate-password-file", "reader.pw"]
    for removed in ("--use-azure-cli-token", "--client-secret", "--access-token", "--include-exchange"):
        assert removed not in command


@pytest.mark.parametrize("certificate", [{}, {"certificate_path": "reader.key.pem"}, {"certificate_thumbprint": "A" * 40}])
def test_live_audit_command_without_the_certificate_is_refused(certificate) -> None:  # noqa: ANN001
    with pytest.raises(ValueError, match="certificate_path and certificate_thumbprint"):
        build_audit_run_command(AuditRunCommandSpec(tenant_name="x", out_dir="o", client_id="app-id", **certificate))


@pytest.mark.parametrize("field", ["use_azure_cli_token", "access_token", "client_secret", "include_exchange"])
def test_audit_run_spec_has_no_removed_sign_in_field(field: str) -> None:
    with pytest.raises(TypeError):
        AuditRunCommandSpec(tenant_name="x", out_dir="o", **{field: "x"})  # type: ignore[arg-type]


def test_invalid_plane_rejected_before_subprocess() -> None:
    with pytest.raises(ValueError):
        build_audit_run_command(AuditRunCommandSpec(tenant_name="x", out_dir="out", plane="unsafe"))


def test_probe_command_runs_as_the_reader_app_with_its_certificate() -> None:
    command = build_probe_command(ProbeCommandSpec(
        tenant_name="x", out_dir="o", client_id="app-id", certificate_path="reader.key.pem",
        certificate_thumbprint="B" * 40, python_executable="python",
    ))
    assert command[command.index("--mode") + 1] == "app"
    assert command[command.index("--certificate-path") + 1] == "reader.key.pem"
    assert "--use-azure-cli-token" not in command and "--auth-context" not in command
    with pytest.raises(ValueError, match="Unsupported probe mode"):
        build_probe_command(ProbeCommandSpec(tenant_name="x", out_dir="o", mode="delegated"))
    with pytest.raises(ValueError, match="certificate_path and certificate_thumbprint"):
        build_probe_command(ProbeCommandSpec(tenant_name="x", out_dir="o", client_id="app-id"))
    for field in ("use_azure_cli_token", "access_token", "auth_context", "client_secret"):
        with pytest.raises(TypeError):
            ProbeCommandSpec(tenant_name="x", out_dir="o", **{field: "x"})  # type: ignore[arg-type]


def test_response_command_rejects_unknown_action() -> None:
    with pytest.raises(ValueError):
        build_response_command(
            ResponseCommandSpec(tenant_name="x", out_dir="o", action="delete_everything"),
            supported_actions={"message_trace"},
        )


def test_response_command_builds_dry_run_plan_by_default() -> None:
    command = build_response_command(
        ResponseCommandSpec(
            tenant_name="LAB",
            out_dir="outputs/response",
            action="message_trace",
            target="user@example.com",
            intent="triage mail flow",
            python_executable="python",
        ),
        supported_actions={"message_trace"},
    )
    assert "--execute" not in command
    assert command[command.index("--intent") + 1] == "triage mail flow"
    assert command[command.index("--target") + 1] == "user@example.com"


def test_response_command_builder_includes_explicit_override_gates() -> None:
    command = build_response_command(
        ResponseCommandSpec(
            tenant_name="LAB",
            out_dir="outputs/response",
            action="message_trace",
            target="user@example.com",
            intent="triage mail flow",
            python_executable="python",
            command_override='Get-MessageTrace -RecipientAddress "admin"',
            adapter_override="m365dsc",
            allow_adapter_override=True,
            allow_command_override=True,
            allow_write=True,
        ),
        supported_actions={"message_trace"},
    )

    assert "--command-override" in command
    assert "--adapter-override" in command
    assert "--allow-command-override" in command
    assert "--allow-adapter-override" in command


def test_google_run_command_builds_domain_delegation_path() -> None:
    command = build_google_run_command(
        GoogleRunCommandSpec(
            tenant_name="example-google",
            out_dir="outputs/google",
            auth="domain-delegation",
            domain="example.com",
            customer_id="my_customer",
            subject="auditor@example.com",
            service_account_key="/creds/key.json",
            collector_preset="core-security",
            collectors=["google_directory", "google_reports"],
            top=500,
            page_size=100,
            python_executable="python",
        )
    )

    assert command[:4] == ["python", "-m", "auditex", "google"]
    assert "run" in command
    assert command[command.index("--auth") + 1] == "domain-delegation"
    assert command[command.index("--service-account-key") + 1] == "/creds/key.json"
    assert command[command.index("--collectors") + 1] == "google_directory,google_reports"
    assert command[command.index("--top") + 1] == "500"
