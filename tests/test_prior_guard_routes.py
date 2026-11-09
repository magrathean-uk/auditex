from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from auditex import cli, mcp_server
from auditex.exporters import BUILTIN_EXPORTERS, run_exporter
from auditex.mcp_registry import register_fastmcp_tools
from auditex.reporting import _copy_source_artifact, preview_report, render_report, write_enterprise_handoff_pack
from auditex.run_bundle import RunBundle
from azure_tenant_audit.guarded_io import GuardContext, UnsafeRunFileError, open_guarded_file
from azure_tenant_audit.bundle_integrity import build_bundle_hash_manifest, verify_bundle_hashes
from azure_tenant_audit.output_redaction import PROFILE_SHAREABLE
from azure_tenant_audit.sensitive_users import BUNDLE_PATH, KEY_PATH, SensitiveUsers, verify_sensitive_users
from support import RunBundleBuilder


KEY = ("KEY-CANARY-" + "x" * 21).encode("ascii")
ADDRESSES = ("private-one" + "@example.invalid", "private-two" + "@example.invalid")
IGNORE = "private-ignore-canary"


def _seal(run: Path, **fields: object) -> None:
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest.update(fields)
    manifest["operator_inputs"] = {"sensitive_users": SensitiveUsers(ADDRESSES).manifest((run / KEY_PATH).read_bytes())}
    manifest_path.write_text(json.dumps(manifest))
    (run / "bundle-hashes.json").write_text(json.dumps(build_bundle_hash_manifest(run)))
    assert verify_bundle_hashes(run)["status"] == "verified"


@pytest.fixture
def run(tmp_path: Path) -> Path:
    result = (RunBundleBuilder(tmp_path).summary_md().report_pack().blockers([]).build())
    private = result / "operator-inputs"
    private.mkdir()
    (result / KEY_PATH).write_bytes(KEY)
    (result / BUNDLE_PATH).write_text("\n".join(ADDRESSES) + "\n")
    (private / ".gitignore").write_text(IGNORE)
    manifest_path = result / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["operator_inputs"] = {"sensitive_users": SensitiveUsers(ADDRESSES).manifest(KEY)}
    manifest_path.write_text(json.dumps(manifest))
    return result


def _no_private(value: object) -> None:
    output = str(value)
    assert KEY.decode() not in output
    assert all(address not in output for address in ADDRESSES)
    assert IGNORE not in output


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
def test_real_sensitive_users_run_stays_verifiable_after_alias(tmp_path: Path, monkeypatch, private: str) -> None:
    from azure_tenant_audit import output

    monkeypatch.setattr(output.secrets, "token_bytes", lambda size: KEY)
    writer = output.AuditWriter(tmp_path, "tenant", "sensitive")
    writer.write_sensitive_users(SensitiveUsers(ADDRESSES))
    writer.write_bundle({"collectors": [], "overall_status": "ok"})
    assert verify_sensitive_users(writer.run_dir)
    # The uncompromised bundle remains readable and verifies the private snapshot.
    assert RunBundle(writer.run_dir).summary_md() is not None
    _seal(writer.run_dir, summary_md_path=private)
    assert verify_sensitive_users(writer.run_dir)
    _refused(lambda: mcp_server.summarize_run(str(writer.run_dir)), "summary_md_path")


def _refused(call, field: str) -> str:
    with pytest.raises((UnsafeRunFileError, ValueError)) as error:
        call()
    assert ("Refusing " in str(error.value) or field in str(error.value)
            or "identity discovery was incomplete" in str(error.value))
    _no_private(error.value)
    return str(error.value)


class _FakeMCP:
    def __init__(self) -> None:
        self.handlers = {}

    def tool(self, **metadata):
        def register(handler):
            self.handlers[metadata["name"]] = handler
            return handler
        return register


@pytest.fixture
def mcp(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AUDITEX_MCP_ROOT", str(tmp_path))
    server = _FakeMCP()
    register_fastmcp_tools(server, mcp_server.tool_handlers())
    return server.handlers


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH, "operator-inputs/.gitignore"])
@pytest.mark.parametrize("tool", ["auditex_summarize_run", "auditex_probe_summarize"])
def test_mcp_summary_refuses_verified_manifest_alias(run: Path, mcp, private: str, tool: str) -> None:
    _seal(run, summary_md_path=private)
    _refused(lambda: mcp[tool](run_dir=str(run)), "summary_md_path")


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
@pytest.mark.parametrize("command", [["summarize"], ["probe", "summarize"]])
def test_cli_summary_refuses_verified_manifest_alias(run: Path, capsys, private: str, command: list[str]) -> None:
    _seal(run, summary_md_path=private)
    assert cli.main([*command, str(run)]) == 2
    captured = capsys.readouterr()
    assert "summary_md_path" in captured.err
    _no_private(captured.out + captured.err)


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
def test_cli_report_render_refuses_verified_manifest_alias(run: Path, tmp_path: Path, capsys, private: str) -> None:
    _seal(run, summary_path=private)
    target = tmp_path / "report.json"
    assert cli.main(["report", "render", str(run), "--format", "json", "--output", str(target)]) == 2
    captured = capsys.readouterr()
    assert "summary_path" in captured.err
    assert not target.exists()
    _no_private(captured.out + captured.err)


def test_gate_refusal_keeps_structured_context(run: Path, capsys) -> None:
    _seal(run, summary_md_path=KEY_PATH)
    assert cli.main(["gate", str(run), "--fail-on", "high"]) == 2
    captured = capsys.readouterr()
    assert "Refusing " in captured.err
    _no_private(captured.out + captured.err)


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
@pytest.mark.parametrize("surface", ["preview", "render", "compare", "notify", "blockers"])
def test_other_consumers_refuse_manifest_alias(run: Path, tmp_path: Path, mcp, private: str, surface: str) -> None:
    field = "blockers_path" if surface == "blockers" else "summary_path"
    _seal(run, **{field: private})
    calls = {
        "preview": lambda: mcp["auditex_report_preview"](run_dir=str(run)),
        "render": lambda: render_report(run_dir=str(run), format_name="json", output_path=str(tmp_path / "report.json"), profile=PROFILE_SHAREABLE),
        "compare": lambda: mcp["auditex_compare_runs"](run_dirs=[str(run), str(run)]),
        "notify": lambda: mcp["auditex_notify_preview"](run_dir=str(run)),
        "blockers": lambda: mcp["auditex_list_blockers"](run_dir=str(run)),
    }
    _refused(calls[surface], field)
    assert not (tmp_path / "report.json").exists()


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
@pytest.mark.parametrize("exporter", sorted(BUILTIN_EXPORTERS))
def test_builtin_exporters_refuse_manifest_alias(run: Path, tmp_path: Path, private: str, exporter: str) -> None:
    _seal(run, summary_path=private)
    target = tmp_path / f"export-{exporter}"
    _refused(lambda: run_exporter(name=exporter, run_dir=str(run), output_path=str(target)), "summary_path")
    assert not target.exists()


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH, "operator-inputs/.gitignore"])
def test_customer_pack_copy_refuses_private_inputs(run: Path, tmp_path: Path, private: str) -> None:
    result = _copy_source_artifact(run, tmp_path / "pack", "./" + private, "test")
    assert result["skipped_reason"] == "redacted_operator_input"
    assert not (tmp_path / "pack" / private).exists()
    _no_private(result)


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
def test_customer_pack_refuses_manifest_alias(run: Path, tmp_path: Path, private: str) -> None:
    _seal(run, summary_path=private)
    _refused(lambda: write_enterprise_handoff_pack(run, tmp_path / "pack"), "summary_path")


@pytest.mark.parametrize("field", ["summary_md_path", "auth_context_path", "coverage_path", "unknown_path"])
@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH, "operator-inputs/.gitignore"])
def test_all_manifest_path_fields_refuse_private_inputs(run: Path, field: str, private: str) -> None:
    _seal(run, **{field: "./" + private})
    _refused(lambda: RunBundle(run).manifest(), field)


@pytest.mark.parametrize("field", ["summary_md_path", "summary_path", "coverage_path", "report_pack_path"])
@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
def test_manifest_refusal_precedes_open(run: Path, monkeypatch, field: str, private: str) -> None:
    _seal(run, **{field: private})
    protected = (run / private).resolve()
    original_open = Path.open

    def guarded_open(path: Path, *args, **kwargs):
        if path.resolve() == protected:
            pytest.fail("private input was opened by the bundle reader")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    _refused(lambda: mcp_server.summarize_run(str(run)), field)


@pytest.mark.parametrize("value", [False, 0, [], {}])
def test_manifest_refuses_non_string_path_even_when_falsy(run: Path, value: object) -> None:
    _seal(run, summary_md_path=value)
    _refused(lambda: RunBundle(run).summary_md(), "summary_md_path")


@pytest.mark.parametrize("value", [None, ""])
def test_empty_optional_manifest_path_uses_default(run: Path, value: object) -> None:
    _seal(run, summary_md_path=value)
    assert RunBundle(run).summary_md() == "# Audit Summary"


def test_waiver_source_metadata_allows_an_external_path_but_refuses_private_inputs(run: Path, tmp_path: Path) -> None:
    _seal(run, waiver_path=str(tmp_path / "waivers.json"))
    assert RunBundle(run).summary_md() == "# Audit Summary"
    _seal(run, waiver_path=str(run / KEY_PATH))
    _refused(lambda: RunBundle(run).manifest(), "waiver_path")


@pytest.mark.parametrize("auth_path", ["none", "access_token", "azure_cli", "saved_context", "app"])
def test_probe_auth_path_is_metadata_not_an_artifact(run: Path, mcp, auth_path: str) -> None:
    _seal(run, auth_path=auth_path)
    result = mcp["auditex_probe_summarize"](run_dir=str(run))
    assert result["manifest"]["auth_path"] == auth_path


def test_probe_auth_path_metadata_refuses_private_input(run: Path) -> None:
    _seal(run, auth_path=KEY_PATH)
    _refused(lambda: RunBundle(run).manifest(), "auth_path")


@pytest.mark.parametrize("kind", ["absolute", "traversal", "symlink_file", "symlink_dir", "directory", "missing"])
def test_manifest_paths_are_confined_regular_files(run: Path, tmp_path: Path, kind: str) -> None:
    if kind == "absolute":
        value = str(run / "summary.md")
    elif kind == "traversal":
        value = "reports/../summary.md"
    elif kind == "symlink_file":
        (run / "alias").symlink_to(run / "summary.md")
        value = "alias"
    elif kind == "symlink_dir":
        (run / "alias").symlink_to(run / "reports", target_is_directory=True)
        value = "alias/report-pack.json"
    elif kind == "directory":
        value = "reports"
    else:
        value = "missing.md"
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["summary_md_path"] = value
    manifest_path.write_text(json.dumps(manifest))
    _refused(lambda: RunBundle(run).summary_md(), "summary_md_path")


def test_summary_does_not_walk_unrelated_nested_directories(run: Path) -> None:
    nested = run / "chunks" / "unused"
    nested.mkdir(parents=True)
    (nested / "link").symlink_to(run / "summary.md")
    assert RunBundle(run).summary_md() == "# Audit Summary"


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
@pytest.mark.parametrize("tool,argument", [
    ("auditex_list_collectors", "config_path"),
    ("auditex_normalize_external_assessment", "input_path"),
    ("auditex_compare_external_assessments", "assessment_paths"),
])
def test_mcp_caller_supplied_inputs_refuse_private_files(run: Path, mcp, private: str, tool: str, argument: str) -> None:
    path = str(run / private)
    if argument == "assessment_paths":
        def call():
            return mcp[tool](assessment_paths=[path])
    elif argument == "input_path":
        def call():
            return mcp[tool](source="maester", input_path=path)
    else:
        def call():
            return mcp[tool](config_path=path)
    _refused(call, argument)


def test_mcp_caller_path_symlink_to_private_file_is_refused(run: Path, tmp_path: Path, mcp) -> None:
    alias = tmp_path / "innocent.json"
    alias.symlink_to(run / KEY_PATH)
    _refused(lambda: mcp["auditex_list_collectors"](config_path=str(alias)), "config_path")


@pytest.mark.parametrize("surface", ["preview", "mcp_diff", "cli_diff"])
@pytest.mark.parametrize("link_type", ["symlink", "hardlink"])
def test_normalized_link_to_json_key_is_not_read(
    run: Path, tmp_path: Path, mcp, capsys, surface: str, link_type: str,
) -> None:
    marker = "V" * 24
    json_key = ('{"x":"' + marker + '"}').encode()
    assert len(json_key) == 32
    (run / KEY_PATH).write_bytes(json_key)
    _seal(run)
    normalized = run / "normalized"
    normalized.mkdir()
    if link_type == "symlink":
        (normalized / "users.json").symlink_to(run / KEY_PATH)
    else:
        os.link(run / KEY_PATH, normalized / "users.json")
    other = RunBundleBuilder(tmp_path, name="other").build()
    if surface == "preview":
        def call():
            return preview_report(run_dir=str(run), format_name="json", profile=PROFILE_SHAREABLE)
        assert marker not in _refused(call, "run_dir")
    elif surface == "mcp_diff":
        assert marker not in _refused(lambda: mcp["auditex_diff_runs"](run_a=str(run), run_b=str(other)), "run_a")
    else:
        assert cli.main(["diff", str(run), str(other)]) == 2
        captured = capsys.readouterr()
        assert "Refusing " in captured.err
        assert marker not in captured.out + captured.err


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
def test_cli_explorer_refuses_private_evidence_reference(run: Path, tmp_path: Path, capsys, private: str) -> None:
    json_key = b'{"records":[{"key":"a","v":10}]}'
    assert len(json_key) == 32
    (run / KEY_PATH).write_bytes(json_key)
    findings = run / "findings" / "findings.json"
    findings.parent.mkdir(exist_ok=True)
    findings.write_text(json.dumps([{
        "id": "f1", "title": "Test", "evidence_refs": [{"artifact_path": private, "record_key": "a"}],
    }]))
    _seal(run)
    target = tmp_path / "explorer.html"
    assert cli.main(["report", "explorer", str(run), "--output", str(target)]) == 2
    captured = capsys.readouterr()
    assert "Refusing evidence:" in captured.err
    assert not target.exists()
    _no_private(captured.out + captured.err)


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
def test_cli_assessment_import_refuses_private_input(run: Path, capsys, private: str) -> None:
    assert cli.main(["assessment", "import", "--source", "maester", "--input", str(run / private)]) == 2
    captured = capsys.readouterr()
    assert "input" in captured.err
    _no_private(captured.out + captured.err)


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
@pytest.mark.parametrize("arguments,field", [
    (["run", "--offline", "--sample"], "sample"),
])
def test_other_cli_readers_refuse_private_input(run: Path, tmp_path: Path, capsys, private: str, arguments: list[str], field: str) -> None:
    # Auth/token files are an explicit exclusion of the descriptor-guard design.
    assert cli.main([*arguments, str(run / private)]) == 2
    captured = capsys.readouterr()
    assert field in captured.err
    _no_private(captured.out + captured.err)


def test_cli_equals_syntax_and_symlink_alias_refused(run: Path, tmp_path: Path, capsys) -> None:
    alias = tmp_path / "input.json"
    alias.symlink_to(run / KEY_PATH)
    assert cli.main(["assessment", "import", "--source=maester", f"--input={alias}"]) == 2
    captured = capsys.readouterr()
    assert "input" in captured.err
    _no_private(captured.out + captured.err)


@pytest.mark.parametrize("entrypoint", ["product", "engine"])
@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
def test_cli_break_glass_file_argument_refuses_private_input(
    run: Path, tmp_path: Path, capsys, monkeypatch, entrypoint: str, private: str,
) -> None:
    from azure_tenant_audit import cli as engine_cli

    def must_not_run(*args, **kwargs):
        pytest.fail("private break-glass input reached offline processing")

    monkeypatch.setattr(engine_cli, "run_offline", must_not_run)
    args = ["--offline", "--out", str(tmp_path / "out"), "--tenant-name", "test",
            "--break-glass-accounts", "@" + str(run / private)]
    result = cli.main(["run", *args]) if entrypoint == "product" else engine_cli.main(args)
    assert result == 2
    captured = capsys.readouterr()
    assert "break-glass-accounts" in captured.err
    _no_private(captured.out + captured.err)


@pytest.mark.parametrize("entrypoint", ["product", "engine"])
def test_cli_break_glass_symlink_alias_refused(run: Path, tmp_path: Path, capsys, entrypoint: str) -> None:
    from azure_tenant_audit import cli as engine_cli

    alias = tmp_path / "break-glass.txt"
    alias.symlink_to(run / BUNDLE_PATH)
    args = ["--offline", "--break-glass-accounts", "@" + str(alias)]
    result = cli.main(["run", *args]) if entrypoint == "product" else engine_cli.main(args)
    assert result == 2
    captured = capsys.readouterr()
    assert "break-glass-accounts" in captured.err
    _no_private(captured.out + captured.err)


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
def test_case_insensitive_manifest_alias_is_refused(run: Path, mcp, private: str) -> None:
    alias = private.upper()
    if not (run / alias).is_file():
        pytest.skip("case-sensitive filesystem")
    _seal(run, summary_md_path=alias)
    _refused(lambda: mcp["auditex_summarize_run"](run_dir=str(run)), "summary_md_path")


def test_case_variants_refused_even_on_a_case_sensitive_filesystem(run: Path) -> None:
    path = run / KEY_PATH.upper()
    with GuardContext() as context:
        context.bind_run(run)
        with pytest.raises((UnsafeRunFileError, FileNotFoundError)):
            with open_guarded_file(path, field="input", context=context):
                pytest.fail("private alias was opened")


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
def test_manifest_hardlink_alias_to_private_input_is_refused(run: Path, mcp, private: str) -> None:
    alias = run / "seemingly-public.md"
    _seal(run, summary_md_path=alias.name)
    os.link(run / private, alias)
    _refused(lambda: mcp["auditex_summarize_run"](run_dir=str(run)), "summary_md_path")


def test_caller_supplied_hardlink_to_private_input_is_refused(run: Path, tmp_path: Path, mcp) -> None:
    alias = tmp_path / "external.json"
    os.link(run / KEY_PATH, alias)
    _refused(lambda: mcp["auditex_list_collectors"](config_path=str(alias)), "config_path")


@pytest.mark.parametrize("entrypoint", ["product", "engine"])
def test_cli_break_glass_hardlink_to_private_input_is_refused(run: Path, tmp_path: Path, capsys, entrypoint: str) -> None:
    from azure_tenant_audit import cli as engine_cli

    alias = tmp_path / "break-glass.txt"
    os.link(run / BUNDLE_PATH, alias)
    args = ["--offline", "--break-glass-accounts", "@" + str(alias)]
    result = cli.main(["run", *args]) if entrypoint == "product" else engine_cli.main(args)
    assert result == 2
    captured = capsys.readouterr()
    assert "break-glass-accounts" in captured.err
    _no_private(captured.out + captured.err)


@pytest.mark.parametrize("entrypoint", ["product", "engine"])
def test_case_insensitive_break_glass_alias_is_refused(run: Path, capsys, monkeypatch, entrypoint: str) -> None:
    from azure_tenant_audit import cli as engine_cli

    alias = run / BUNDLE_PATH.upper()
    if not alias.is_file():
        pytest.skip("case-sensitive filesystem")
    monkeypatch.setattr(engine_cli, "run_offline", lambda *a, **kw: pytest.fail("private input was opened"))
    args = ["--offline", "--break-glass-accounts", "@" + str(alias)]
    result = cli.main(["run", *args]) if entrypoint == "product" else engine_cli.main(args)
    assert result == 2
    captured = capsys.readouterr()
    assert "break-glass-accounts" in captured.err
    _no_private(captured.out + captured.err)


@pytest.mark.parametrize("private", [KEY_PATH, BUNDLE_PATH])
def test_engine_cli_refuses_private_sample(run: Path, capsys, private: str) -> None:
    from azure_tenant_audit import cli as engine_cli

    assert engine_cli.main(["--offline", "--sample", str(run / private)]) == 2
    captured = capsys.readouterr()
    assert "sample" in captured.err
    _no_private(captured.out + captured.err)
