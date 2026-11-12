from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from auditex.mcp_registry import register_fastmcp_tools
from auditex.mcp_server import tool_handlers


class FakeFastMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self, **metadata: Any):
        def register(handler: Any) -> Any:
            self.tools[metadata["name"]] = handler
            return handler

        return register


@pytest.fixture
def tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv("AUDITEX_MCP_ROOT", str(tmp_path))
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")
    server = FakeFastMCP()
    register_fastmcp_tools(server, tool_handlers())
    return server.tools


@pytest.fixture
def operator_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    users = tmp_path / "users.txt"
    domains = tmp_path / "partners.txt"
    users.write_text("alice@example.org\n", encoding="utf-8")
    domains.write_text("partner.example.net\n", encoding="utf-8")
    values = {
        "AUDITEX_SENSITIVE_USERS_FILE": str(users),
        "AUDITEX_PARTNER_DOMAINS_FILE": str(domains),
        "AUDITEX_FUTURE_INPUT_FILE": str(users),
        "AUDITEX_X_FILE": str(users),
        "AUDITEX_FOO_DOMAINS": "future.example.net",
        "AUDITEX_BREAK_GLASS_ACCOUNTS": "emergency@example.org",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("AUDITEX_UNRELATED_FILES", "kept")
    monkeypatch.setenv("OTHER_INPUT_FILE", "kept")
    return values


@pytest.mark.parametrize(("sync_days", "guest_days"), [("31", "120"), ("365", "730")])
def test_offline_validation_does_not_copy_operator_inputs(
    tools: dict[str, Any], operator_inputs: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    sync_days: str, guest_days: str,
) -> None:
    repo = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("PYTHONPATH", str(repo / "src"))
    monkeypatch.setenv("PYTHONDONTWRITEBYTECODE", "1")
    monkeypatch.setenv("AUDITEX_STALE_SYNC_DAYS", sync_days)
    monkeypatch.setenv("AUDITEX_STALE_GUEST_DAYS", guest_days)
    result = tools["auditex_run_offline_validation"](tenant_name="sample", out_dir="offline")

    assert result["returncode"] == 0, result
    manifests = list((tmp_path / "offline").glob("*/run-manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["operator_inputs"]["sensitive_users"] == {"supplied": False}
    if "partner_domains" in manifest["operator_inputs"]:
        assert manifest["operator_inputs"]["partner_domains"] == {"supplied": False}
    assert manifest["rule_parameters"]["break_glass_accounts"] == []
    assert manifest["rule_parameters"]["stale_sync_days"] == 14
    assert manifest["rule_parameters"]["stale_guest_days"] == 90
    assert manifest["rule_parameters"]["stale_account_days"] == 90
    assert sorted(path.name for path in (manifests[0].parent / "operator-inputs").iterdir()) == [".gitignore", "pseudonym.key"]
    for value in ("alice@example.org", "partner.example.net", "emergency@example.org"):
        assert value not in json.dumps(result)
    assert os.environ["AUDITEX_SENSITIVE_USERS_FILE"] == operator_inputs["AUDITEX_SENSITIVE_USERS_FILE"]


def test_offline_validation_scrubs_the_child_environment(
    tools: dict[str, Any], operator_inputs: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}
    monkeypatch.setenv("AUDITEX_STALE_SYNC_DAYS", "31")
    monkeypatch.setenv("PYTHONHASHSEED", "137")
    monkeypatch.setenv("auditex_FOO_DOMAINS", "kept")
    monkeypatch.setenv("AUDITEX", "kept")
    parent_env = dict(os.environ)
    # Supply examples where a developer's shell does not define these names.
    for name in ("TMPDIR", "DEVCACHE", "CLEAN_DEV_MODE", "CLEAN_DEV_BUILDS", "PATH", "HOME"):
        parent_env.setdefault(name, f"example-{name}")
    monkeypatch.setattr(os, "environ", parent_env)

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed["env"] = dict(os.environ if kwargs.get("env") is None else kwargs["env"])
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("auditex.command_runner.subprocess.run", run)
    result = tools["auditex_run_offline_validation"](tenant_name="sample", out_dir="offline")

    assert result["returncode"] == 0
    assert not any(name.startswith("AUDITEX_") for name in observed["env"])
    assert observed["env"] == {name: value for name, value in parent_env.items() if not name.startswith("AUDITEX_")}
    for name in ("TMPDIR", "DEVCACHE", "CLEAN_DEV_MODE", "CLEAN_DEV_BUILDS", "PATH", "HOME", "PYTHONHASHSEED"):
        assert observed["env"][name] == parent_env[name]
    assert all(os.environ[name] == value for name, value in operator_inputs.items())


def test_offline_validation_closes_child_stdin(tools: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, Any] = {}

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("auditex.command_runner.subprocess.run", run)
    result = tools["auditex_run_offline_validation"](tenant_name="sample", out_dir="offline")

    assert result["returncode"] == 0
    assert observed.get("stdin") == subprocess.DEVNULL


def test_offline_validation_drops_operator_input_flags(
    tools: dict[str, Any], operator_inputs: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    from auditex import mcp_server

    build = mcp_server.build_cli_command
    observed: dict[str, Any] = {}

    def build_with_inputs(**kwargs: Any) -> list[str]:
        return build(**kwargs) + [
            "--sensitive-users", operator_inputs["AUDITEX_SENSITIVE_USERS_FILE"],
            "--partner-domains=" + operator_inputs["AUDITEX_PARTNER_DOMAINS_FILE"],
            "--partner-domains", operator_inputs["AUDITEX_PARTNER_DOMAINS_FILE"],
            "--break-glass-accounts", operator_inputs["AUDITEX_BREAK_GLASS_ACCOUNTS"],
            "--sensitive-users=" + operator_inputs["AUDITEX_SENSITIVE_USERS_FILE"],
            "--partner-domains", "--verbose",
        ]

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(mcp_server, "build_cli_command", build_with_inputs)
    monkeypatch.setattr("auditex.command_runner.subprocess.run", run)
    result = tools["auditex_run_offline_validation"](tenant_name="sample", out_dir="offline")

    assert result["returncode"] == 0
    assert "--offline" in observed["command"]
    assert "--verbose" in observed["command"]
    for flag in ("--sensitive-users", "--partner-domains", "--break-glass-accounts"):
        assert all(arg != flag and not arg.startswith(flag + "=") for arg in observed["command"])
    for value in operator_inputs.values():
        assert value not in json.dumps(result)


@pytest.mark.parametrize(
    ("tool_name", "arguments", "expected_arg"),
    [
        ("auditex_run_delegated_audit", {"tenant_name": "live"}, "--use-azure-cli-token"),
        ("auditex_google_doctor", {}, "doctor"),
        ("auditex_google_probe", {}, "probe"),
        ("auditex_run_google_workspace_audit", {}, "run"),
        ("auditex_probe_live", {"tenant_name": "live"}, "probe"),
        ("auditex_run_response_action", {"tenant_name": "live", "action": "message_trace"}, "response"),
    ],
)
def test_other_tools_keep_operator_input_environment(
    tool_name: str, arguments: dict[str, str], expected_arg: str, tools: dict[str, Any],
    operator_inputs: dict[str, str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["env"] = dict(os.environ if kwargs.get("env") is None else kwargs["env"])
        observed["stdin"] = kwargs.get("stdin")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("auditex.command_runner.subprocess.run", run)
    result = tools[tool_name](**arguments)

    assert result["returncode"] == 0
    assert expected_arg in observed["command"]
    assert all(observed["env"][name] == value for name, value in operator_inputs.items())
    assert observed["stdin"] is None
