from __future__ import annotations

import pytest

from auditex.command_builders import (
    AuditRunCommandSpec,
    ProbeCommandSpec,
    ResponseCommandSpec,
    build_audit_run_command,
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


def test_delegated_audit_command_prefers_azure_cli_token() -> None:
    command = build_audit_run_command(
        AuditRunCommandSpec(
            tenant_name="ACME",
            tenant_id="organizations",
            out_dir="outputs/live",
            collectors=["identity", "security"],
            include_exchange=True,
            python_executable="python",
        )
    )
    assert "--use-azure-cli-token" in command
    assert command[command.index("--collectors") + 1] == "identity,security"
    assert "--include-exchange" in command


def test_invalid_plane_rejected_before_subprocess() -> None:
    with pytest.raises(ValueError):
        build_audit_run_command(AuditRunCommandSpec(tenant_name="x", out_dir="out", plane="unsafe"))


def test_probe_command_gates_azure_cli_to_delegated_mode() -> None:
    delegated = build_probe_command(ProbeCommandSpec(tenant_name="x", out_dir="o", mode="delegated", python_executable="python"))
    app = build_probe_command(ProbeCommandSpec(tenant_name="x", out_dir="o", mode="app", python_executable="python"))
    assert "--use-azure-cli-token" in delegated
    assert "--use-azure-cli-token" not in app


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
