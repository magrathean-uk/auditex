"""MCP tools take no bearer token or client secret, and every filesystem argument is confined to one root."""
from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest

from auditex.mcp_paths import MCP_ROOT_ENV, McpPathError, confine_handler, confine_path, confine_value, mcp_root
from auditex.mcp_registry import TOOL_REGISTRY, McpToolEntry, iter_tool_specs, register_fastmcp_tools
from auditex.mcp_server import tool_handlers

FORBIDDEN_ARGUMENTS = {"token", "access_token", "client_secret", "bearer_token", "refresh_token", "secret", "password"}


class _FakeFastMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self, **metadata: Any):
        def decorator(func: Any) -> Any:
            self.tools[metadata["name"]] = (func, metadata)
            return func

        return decorator


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base = tmp_path / "mcp-root"
    base.mkdir()
    monkeypatch.setenv(MCP_ROOT_ENV, str(base))
    return base.resolve()


@pytest.fixture
def registered(monkeypatch: pytest.MonkeyPatch) -> _FakeFastMCP:
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")
    server = _FakeFastMCP()
    register_fastmcp_tools(server, tool_handlers())
    return server


def test_no_tool_takes_a_bearer_token_or_client_secret() -> None:
    for name, handler in tool_handlers().items():
        offending = FORBIDDEN_ARGUMENTS & set(inspect.signature(handler).parameters)
        assert not offending, f"{name} takes {sorted(offending)}"


def test_every_registry_entry_has_a_handler_and_declared_path_arguments_exist(registered: _FakeFastMCP) -> None:
    handlers = tool_handlers()
    names = {entry.name for entry in TOOL_REGISTRY}
    assert names <= set(handlers), sorted(names - set(handlers))
    assert set(registered.tools) == {item["name"] for item in iter_tool_specs(include_response=True)}
    for entry in TOOL_REGISTRY:
        parameters = inspect.signature(handlers[entry.name]).parameters
        for argument in (*entry.path_args, *entry.resource_args):
            assert argument in parameters, (entry.name, argument)


def test_every_filesystem_argument_of_every_tool_is_declared_for_confinement() -> None:
    suffixes = ("_dir", "_path", "_paths", "_dirs", "_key", "_cache", "oauth_client")
    allowed_unconfined = {
        ("auditex_setup_guide", "service_account_key"),  # rendered into guide text, never opened
        ("auditex_setup_guide", "oauth_client"),
        ("auditex_setup_guide", "token_cache"),
        ("auditex_rules_inventory", "path_prefix"),  # a rule-id prefix, not a filesystem path
    }
    handlers = tool_handlers()
    entries = {entry.name: entry for entry in TOOL_REGISTRY}
    for name, handler in handlers.items():
        declared = set(entries[name].path_args) | set(entries[name].resource_args)
        for argument in inspect.signature(handler).parameters:
            looks_like_path = argument.endswith(suffixes) or argument in {"run_a", "run_b", "oauth_client", "token_cache"}
            if looks_like_path and (name, argument) not in allowed_unconfined:
                assert argument in declared, f"{name}.{argument} is a path argument that is not confined"


def test_read_only_annotations_survive_registration(registered: _FakeFastMCP) -> None:
    for entry in TOOL_REGISTRY:
        _, metadata = registered.tools[entry.name]
        assert metadata["annotations"] == {"readOnlyHint": entry.read_only_hint}
    assert registered.tools["auditex_api_inventory"][1]["annotations"]["readOnlyHint"] is True
    assert registered.tools["auditex_summarize_run"][1]["annotations"]["readOnlyHint"] is True
    assert registered.tools["auditex_run_delegated_audit"][1]["annotations"]["readOnlyHint"] is False


def test_specs_list_the_confined_arguments() -> None:
    by_name = {item["name"]: item for item in iter_tool_specs(include_response=True)}

    assert by_name["auditex_summarize_run"]["pathArguments"] == ["run_dir"]
    assert by_name["auditex_list_profiles"]["pathArguments"] == []
    assert "auditex_auth_import_token" not in by_name and "auditex_auth_inspect_token" not in by_name


# --- confine_path ------------------------------------------------------------------------------


def test_relative_paths_resolve_inside_the_root(root: Path) -> None:
    assert confine_path("runs/a") == str(root / "runs" / "a")
    assert confine_path(".") == str(root)


@pytest.mark.parametrize("value", ["../outside", "runs/../../outside", "a/b/../../../etc", "..", "runs/.."])
def test_traversal_is_rejected(root: Path, value: str) -> None:
    with pytest.raises(McpPathError):
        confine_path(value)


@pytest.mark.parametrize("value", ["/etc/passwd", "/tmp", "/", "~/audits", "~", "\x00x", "runs/\x00"])
def test_absolute_paths_outside_the_root_and_odd_strings_are_rejected(root: Path, value: str) -> None:
    with pytest.raises(McpPathError):
        confine_path(value)


def test_absolute_path_inside_the_root_is_accepted(root: Path) -> None:
    assert confine_path(str(root / "runs" / "a")) == str(root / "runs" / "a")
    assert confine_path(str(root)) == str(root)


def test_a_sibling_directory_with_the_same_prefix_is_outside(root: Path) -> None:
    sibling = root.parent / (root.name + "-evil")
    sibling.mkdir()
    with pytest.raises(McpPathError):
        confine_path(str(sibling))


def test_a_symlink_that_leaves_the_root_is_rejected(root: Path, tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (root / "link").symlink_to(outside)
    with pytest.raises(McpPathError):
        confine_path("link/secret.json")
    with pytest.raises(McpPathError):
        confine_path("link")


def test_a_symlink_inside_the_root_is_followed_and_accepted(root: Path) -> None:
    (root / "real").mkdir()
    (root / "alias").symlink_to(root / "real")
    assert confine_path("alias/x") == str(root / "real" / "x")


def test_default_root_is_the_working_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(MCP_ROOT_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    assert mcp_root() == tmp_path.resolve()
    assert confine_path("outputs/x") == str(tmp_path.resolve() / "outputs" / "x")


def test_confine_value_handles_lists_and_empty_values(root: Path) -> None:
    assert confine_value("") == ""
    assert confine_value(None) is None
    assert confine_value(["a", "b/c"]) == [str(root / "a"), str(root / "b" / "c")]
    with pytest.raises(McpPathError):
        confine_value(["a", "../b"])
    with pytest.raises(McpPathError):
        confine_path(5)  # type: ignore[arg-type]


# --- the registered handlers ---------------------------------------------------------------------


def test_registered_handler_rejects_traversal_and_outside_paths(root: Path, registered: _FakeFastMCP) -> None:
    summarize, _ = registered.tools["auditex_summarize_run"]

    with pytest.raises(McpPathError):
        summarize(run_dir="../../etc")
    with pytest.raises(McpPathError):
        summarize("/etc")
    with pytest.raises(McpPathError):
        summarize(run_dir=str(root.parent))


def test_registered_handler_receives_the_resolved_path(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Any] = []

    def auditex_summarize_run(run_dir: str) -> dict[str, Any]:
        seen.append(run_dir)
        return {}

    entry = next(item for item in TOOL_REGISTRY if item.name == "auditex_summarize_run")
    confine_handler(entry, auditex_summarize_run)("runs/a")
    confine_handler(entry, auditex_summarize_run)(run_dir=str(root / "runs" / "b"))

    assert seen == [str(root / "runs" / "a"), str(root / "runs" / "b")]


def test_defaults_of_path_arguments_are_confined_too(root: Path) -> None:
    seen: dict[str, Any] = {}

    def auditex_run_delegated_audit(tenant_name: str, out_dir: str = "outputs/live") -> dict[str, Any]:
        seen.update(tenant_name=tenant_name, out_dir=out_dir)
        return {}

    entry = next(item for item in TOOL_REGISTRY if item.name == "auditex_run_delegated_audit")
    confine_handler(entry, auditex_run_delegated_audit)("acme")

    assert seen["out_dir"] == str(root / "outputs" / "live")


def test_list_arguments_are_confined_element_by_element(root: Path, registered: _FakeFastMCP) -> None:
    compare, _ = registered.tools["auditex_compare_runs"]

    with pytest.raises(McpPathError):
        compare(run_dirs=["runs/a", "../b"])


def test_shipped_resource_defaults_pass_but_other_values_are_confined(root: Path, registered: _FakeFastMCP) -> None:
    list_collectors, _ = registered.tools["auditex_list_collectors"]
    schema_manifest, _ = registered.tools["auditex_contract_schema_manifest"]

    default_result = list_collectors()  # default config_path is the shipped file, resolved as before
    assert default_result["provider"] == "m365" or "error" in default_result
    with pytest.raises(McpPathError):
        list_collectors(config_path="/etc/passwd")
    with pytest.raises(McpPathError):
        list_collectors(config_path="../configs/collector-definitions.json")
    with pytest.raises(McpPathError):
        schema_manifest(schema_dir="/tmp")


def test_credential_paths_are_confined(root: Path, registered: _FakeFastMCP) -> None:
    doctor, _ = registered.tools["auditex_google_doctor"]

    with pytest.raises(McpPathError):
        doctor(service_account_key="/Users/someone/.secrets/key.json")
    with pytest.raises(McpPathError):
        doctor(oauth_client="../client.json")
    with pytest.raises(McpPathError):
        doctor(token_cache="~/.cache/token.json")


def test_confine_handler_refuses_an_entry_that_names_an_unknown_argument() -> None:
    entry = McpToolEntry(name="x", description="", read_only_hint=True, path_args=("nope",))

    def handler(run_dir: str) -> dict[str, Any]:
        return {}

    with pytest.raises(TypeError):
        confine_handler(entry, handler)


def test_handlers_without_path_arguments_are_returned_unwrapped() -> None:
    entry = McpToolEntry(name="x", description="", read_only_hint=True)

    def handler() -> dict[str, Any]:
        return {}

    assert confine_handler(entry, handler) is handler


def test_confined_handler_keeps_its_signature_for_schema_generation(registered: _FakeFastMCP) -> None:
    wrapped, _ = registered.tools["auditex_summarize_run"]
    original = tool_handlers()["auditex_summarize_run"]

    assert list(inspect.signature(wrapped).parameters) == list(inspect.signature(original).parameters)
    assert wrapped.__name__ == "auditex_summarize_run"


# --- bypasses found in review ---------------------------------------------------------------------


def test_tenant_and_run_names_are_validated_by_the_registered_handlers(root: Path, registered: _FakeFastMCP) -> None:
    from auditex.mcp_paths import confine_name

    seen: list[Any] = []

    def auditex_run_google_workspace_audit(tenant_name: str = "google-workspace", run_name: str = "") -> dict[str, Any]:
        seen.append((tenant_name, run_name))
        return {}

    entry = McpToolEntry(name="auditex_run_google_workspace_audit", description="", read_only_hint=False, name_args=("tenant_name", "run_name"))
    wrapped = confine_handler(entry, auditex_run_google_workspace_audit)

    wrapped(tenant_name="Acme", run_name="2026-10")
    wrapped(tenant_name="Acme")  # an empty run name means none
    assert seen == [("Acme", "2026-10"), ("Acme", "")]
    for bad in ("../../../escape/pwned", "a/b", "..", "x\\y", "bad\x00"):
        with pytest.raises(McpPathError):
            wrapped(tenant_name=bad)
        with pytest.raises(McpPathError):
            wrapped(tenant_name="Acme", run_name=bad)
        with pytest.raises(McpPathError):
            confine_name(bad)
    assert confine_name("") == "" and confine_name("Acme Ltd") == "Acme Ltd"

    registered_tool, _ = registered.tools["auditex_run_offline_validation"]
    with pytest.raises(McpPathError):
        registered_tool(tenant_name="../../../escape/pwned")


def test_every_tool_that_takes_a_tenant_or_run_name_declares_it() -> None:
    handlers = tool_handlers()
    entries = {entry.name: entry for entry in TOOL_REGISTRY}
    for name, handler in handlers.items():
        for argument in inspect.signature(handler).parameters:
            if argument in {"tenant_name", "run_name"} and name != "auditex_setup_guide":  # the guide only renders the name into text
                assert argument in entries[name].name_args, f"{name}.{argument} is not validated as a name"


def test_a_traversing_tenant_name_through_the_handler_creates_nothing_outside_the_root(root: Path, registered: _FakeFastMCP) -> None:
    tool, _ = registered.tools["auditex_run_offline_validation"]

    with pytest.raises(McpPathError):
        tool(tenant_name="../../../escape/pwned", out_dir="outputs/offline")

    assert not (root.parent / "escape").exists()
    assert list(root.iterdir()) == []


def test_the_root_may_not_be_the_filesystem_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(MCP_ROOT_ENV, "/")
    with pytest.raises(McpPathError) as explicit:
        mcp_root()
    assert "confines nothing" in str(explicit.value)

    monkeypatch.delenv(MCP_ROOT_ENV, raising=False)
    monkeypatch.chdir("/")
    with pytest.raises(McpPathError):
        mcp_root()
    with pytest.raises(McpPathError):
        confine_path("etc/passwd")


def test_an_unset_root_may_not_fall_back_to_the_home_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv(MCP_ROOT_ENV, raising=False)
    monkeypatch.chdir(home)

    with pytest.raises(McpPathError) as caught:
        mcp_root()
    assert MCP_ROOT_ENV in str(caught.value)
    with pytest.raises(McpPathError):
        confine_path("audits/run1")

    # A project directory under the home directory is fine, and so is an explicit choice of the home directory.
    project = home / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    assert mcp_root() == project.resolve()
    monkeypatch.chdir(home)
    monkeypatch.setenv(MCP_ROOT_ENV, str(home))
    assert mcp_root() == home.resolve()


def test_the_server_refuses_to_start_with_a_root_that_confines_nothing(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    from auditex.mcp_server import main

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv(MCP_ROOT_ENV, raising=False)
    monkeypatch.chdir(home)

    assert main([]) == 2
    error = capsys.readouterr().err
    assert "auditex-mcp:" in error and MCP_ROOT_ENV in error

    monkeypatch.setenv(MCP_ROOT_ENV, "/")
    assert main([]) == 2


def test_the_server_gets_past_the_root_check_with_a_project_directory(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    from auditex.mcp_server import main

    monkeypatch.setenv(MCP_ROOT_ENV, str(tmp_path))
    monkeypatch.setitem(__import__("sys").modules, "mcp", None)  # the optional extra is absent: main stops at that, after the root check

    assert main([]) == 2
    assert "pip install" in capsys.readouterr().err
