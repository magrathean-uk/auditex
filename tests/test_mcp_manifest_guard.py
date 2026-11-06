from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


_SOURCE = Path(__file__).resolve().parents[1] / "src"
_CANARY = "OUTSIDE-RUN-CANARY-7cf620"
_CALL_TOOL = """
import json
import os
import sys
import tempfile
sys.path.insert(0, sys.argv[1])
from auditex.mcp_paths import confine_handler
from auditex.mcp_registry import TOOL_REGISTRY
from auditex.mcp_server import tool_handlers

try:
    if sys.argv[2] == "projection_salt":
        from auditex.scuba_projection import project_run
        result = project_run(*json.loads(sys.argv[3]))
    elif sys.argv[2] == "reference_run_salt":
        from azure_tenant_audit.output_redaction import run_salt
        result = run_salt(*json.loads(sys.argv[3]))
    else:
        os.environ["AUDITEX_MCP_ROOT"] = tempfile.gettempdir()
        entry = next(item for item in TOOL_REGISTRY if item.name == sys.argv[2])
        handler = confine_handler(entry, tool_handlers()[sys.argv[2]])
        result = handler(*json.loads(sys.argv[3]))
except Exception as exc:
    print(json.dumps({"error": type(exc).__name__, "message": str(exc)}))
else:
    print(json.dumps({"result": result}))
"""


def _call_tool(name: str, *args: object) -> dict[str, object]:
    try:
        process = subprocess.run(
            [sys.executable, "-B", "-c", _CALL_TOOL, str(_SOURCE), name, json.dumps(args)],
            text=True, capture_output=True, timeout=10, check=True,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"{name} did not reject the run file within 10 seconds")
    return json.loads(process.stdout)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable")
def test_diff_rejects_fifo_manifest_without_blocking(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    os.mkfifo(left / "run-manifest.json")
    (right / "run-manifest.json").write_text("{}", encoding="utf-8")

    outcome = _call_tool("auditex_diff_runs", str(left), str(right))

    from azure_tenant_audit.run_files import UnsafeRunFileError, read_run_file

    with pytest.raises(UnsafeRunFileError):
        read_run_file(left, "run-manifest.json")
    assert "result" in outcome


_RUN_TOOLS = (
    "auditex_summarize_run",
    "auditex_probe_summarize",
    "auditex_diff_runs:left",
    "auditex_diff_runs:right",
    "auditex_compare_runs:left",
    "auditex_compare_runs:right",
    "auditex_list_blockers",
    "auditex_report_preview",
    "auditex_report_analyze",
    "auditex_api_inventory",
    "auditex_permissions_ledger",
    "auditex_proof_table",
    "auditex_enterprise_handoff",
    "auditex_notify_preview",
    "auditex_compare_external_assessments",
)


def _plant_bad_file(path: Path, kind: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFOs are unavailable")
        os.mkfifo(path)
    elif kind == "symlink":
        target = path.parent / "guard-target"
        target.write_text(json.dumps({"tenant_name": _CANARY, "secret": _CANARY}), encoding="utf-8")
        path.symlink_to(target.name)
    elif kind == "hardlink":
        target = path.parent / "guard-target"
        target.write_text(json.dumps({"tenant_name": _CANARY, "secret": _CANARY}), encoding="utf-8")
        os.link(target, path)
    elif kind == "directory":
        path.mkdir()
    elif kind == "oversize":
        with path.open("wb") as handle:
            handle.truncate(256 * 1024 * 1024 + 1)
    else:
        raise AssertionError(kind)


def _tool_args(tool: str, bad_run: Path, good_run: Path) -> tuple[str, tuple[object, ...]]:
    name, _, side = tool.partition(":")
    if name == "auditex_diff_runs":
        runs = (bad_run, good_run) if side == "left" else (good_run, bad_run)
        return name, tuple(map(str, runs))
    if name == "auditex_compare_runs":
        runs = (bad_run, good_run) if side == "left" else (good_run, bad_run)
        return name, ([str(run) for run in runs],)
    if name == "auditex_compare_external_assessments":
        assessment = good_run / "assessment.json"
        assessment.write_text(json.dumps({
            "schema_version": "2026-10-18",
            "source": "maester",
            "source_version": "1.0",
            "tenant_id": "11111111-1111-4111-8111-111111111111",
            "assessed_at": "2026-10-18T10:00:00Z",
            "provenance": {"input_sha256": "a" * 64, "input_name": "assessment.json", "identity_source": "source"},
            "checks": [],
        }), encoding="utf-8")
        return name, ([str(assessment)], None, str(bad_run))
    return name, (str(bad_run),)


@pytest.mark.parametrize("tool", _RUN_TOOLS)
@pytest.mark.parametrize("kind", ("fifo", "symlink", "hardlink", "directory", "oversize"))
def test_mcp_tools_reject_unsafe_manifests(tmp_path: Path, tool: str, kind: str) -> None:
    from azure_tenant_audit.run_files import UnsafeRunFileError, read_run_file

    bad = tmp_path / "bad"
    good = tmp_path / "good"
    bad.mkdir()
    good.mkdir()
    _plant_bad_file(bad / "run-manifest.json", kind)
    (good / "run-manifest.json").write_text("{}", encoding="utf-8")

    name, args = _tool_args(tool, bad, good)
    outcome = _call_tool(name, *args)

    with pytest.raises(UnsafeRunFileError):
        read_run_file(bad, "run-manifest.json")
    assert _CANARY not in json.dumps(outcome)
    assert outcome.get("error") in (None, "UnsafeRunFileError", "ValueError"), outcome


@pytest.mark.parametrize("tool,relative", (
    ("auditex_summarize_run", "summary.json"),
    ("auditex_summarize_run", "summary.md"),
    ("auditex_summarize_run", "raw/identity.json"),
    ("auditex_summarize_run", "normalized/auth_context.json"),
    ("auditex_summarize_run", "index/evidence.sqlite"),
    ("auditex_diff_runs:left", "normalized/users.json"),
    ("auditex_diff_runs:left", "reports/report-pack.json"),
    ("auditex_report_preview", "normalized/users.json"),
    ("auditex_report_preview", "normalized/snapshot.json"),
    ("auditex_report_preview", "normalized/coverage_ledger.json"),
    ("auditex_api_inventory", "audit-log.jsonl"),
    ("auditex_enterprise_handoff", "bundle-hashes.json"),
    ("auditex_enterprise_handoff", "model_assessment.json"),
    ("auditex_enterprise_handoff", "ai_safe/custom.json"),
    ("auditex_enterprise_handoff", "normalized/custom.json"),
    ("auditex_compare_runs:left", "bundle-hashes.json"),
))
@pytest.mark.parametrize("kind", ("fifo", "symlink", "hardlink", "directory", "oversize"))
def test_mcp_tools_reject_unsafe_bundle_files(tmp_path: Path, tool: str, relative: str, kind: str) -> None:
    from azure_tenant_audit.run_files import UnsafeRunFileError, read_run_file

    bad = tmp_path / "bad"
    good = tmp_path / "good"
    bad.mkdir()
    good.mkdir()
    (bad / "run-manifest.json").write_text('{"mode": "offline"}', encoding="utf-8")
    (good / "run-manifest.json").write_text("{}", encoding="utf-8")
    _plant_bad_file(bad / relative, kind)

    name, args = _tool_args(tool, bad, good)
    outcome = _call_tool(name, *args)

    with pytest.raises(UnsafeRunFileError):
        read_run_file(bad, relative)
    assert _CANARY not in json.dumps(outcome)
    assert outcome.get("error") in (None, "UnsafeRunFileError", "ValueError", "ContextIncompleteError"), outcome
    if outcome.get("error") == "ContextIncompleteError":
        assert "result" not in outcome


@pytest.mark.parametrize("kind", ("fifo", "symlink", "directory", "oversize"))
def test_projection_salt_rejects_unsafe_manifest(tmp_path: Path, kind: str) -> None:
    _plant_bad_file(tmp_path / "run-manifest.json", kind)
    outcome = _call_tool("projection_salt", str(tmp_path))
    assert outcome.get("error") == "UnsafeRunFileError", outcome


def test_reference_run_salt_does_not_read_the_manifest(tmp_path: Path) -> None:
    import hashlib

    for kind in ("fifo", "symlink", "directory", "oversize"):
        run = tmp_path / kind
        run.mkdir()
        _plant_bad_file(run / "run-manifest.json", kind)
        outcome = _call_tool("reference_run_salt", str(run))
        assert outcome == {"result": hashlib.sha256(os.path.realpath(run).encode()).hexdigest()}


@pytest.mark.parametrize("relative", ("users.json", "snapshot.json", "coverage_ledger.json"))
@pytest.mark.parametrize("kind", ("symlink", "hardlink"))
def test_shareable_normalized_read_and_snapshot_refuse_links(tmp_path: Path, relative: str, kind: str) -> None:
    from azure_tenant_audit.output_redaction import ContextIncompleteError, read_normalized_sections, snapshot_run

    normalized = tmp_path / "run" / "normalized"
    normalized.mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"secret": _CANARY}), encoding="utf-8")
    target = normalized / relative
    if kind == "symlink":
        inside = normalized / "inside"
        inside.write_text(outside.read_text(encoding="utf-8"), encoding="utf-8")
        target.symlink_to(inside.name)
    else:
        os.link(outside, target)
    for reader in (read_normalized_sections, snapshot_run):
        with pytest.raises(ContextIncompleteError) as caught:
            reader(normalized.parent)
        assert relative in str(caught.value) and _CANARY not in str(caught.value)


def test_discovery_refuses_a_hard_link_added_during_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit import output_redaction as redaction

    normalized = tmp_path / "run" / "normalized"
    normalized.mkdir(parents=True)
    source = normalized / "users.json"
    source.write_text(json.dumps({"records": [{"displayName": _CANARY}]}), encoding="utf-8")
    inode = source.stat().st_ino
    original_read = os.read
    linked = False

    def add_link(fd: int, count: int) -> bytes:
        nonlocal linked
        data = original_read(fd, count)
        if data and not linked and os.fstat(fd).st_ino == inode:
            os.link(source, tmp_path / "outside.json")
            linked = True
        return data

    monkeypatch.setattr(redaction.os, "read", add_link)
    context = redaction.context_for_run(normalized.parent)
    assert linked and context.incomplete
    with pytest.raises(redaction.ContextIncompleteError) as caught:
        redaction.redact_output({"value": _CANARY}, context=context)
    assert _CANARY not in str(caught.value)


def test_guard_rejects_device_without_opening_it() -> None:
    from azure_tenant_audit.run_files import UnsafeRunFileError, read_run_file

    if not Path("/dev/null").exists():
        pytest.skip("No local null device")
    with pytest.raises(UnsafeRunFileError, match="regular file"):
        read_run_file("/dev", "null")


def test_guard_rejects_file_growing_past_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit.run_files import UnsafeRunFileError, read_run_file

    path = tmp_path / "growing.json"
    path.write_bytes(b"{}")
    original_read = os.read
    changed = False

    def grow_before_read(fd: int, size: int) -> bytes:
        nonlocal changed
        if not changed:
            changed = True
            with path.open("ab") as handle:
                handle.write(b"12345")
        return original_read(fd, size)

    monkeypatch.setattr(os, "read", grow_before_read)
    with pytest.raises(UnsafeRunFileError, match="size limit"):
        read_run_file(tmp_path, path.name, max_bytes=4)


def test_guarded_jsonl_preserves_unicode_line_separators(tmp_path: Path) -> None:
    from azure_tenant_audit.api_inventory import read_audit_events
    from azure_tenant_audit.evidence_refs import EvidenceIndex

    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({"key": "item-1", "note": "a\u2028b"}, ensure_ascii=False) + "\n", encoding="utf-8")

    assert EvidenceIndex(tmp_path).resolve({"artifact_path": "events.jsonl", "record_key": "item-1"}).resolved
    assert read_audit_events(path, run_dir=tmp_path)[0]["note"] == "a\u2028b"


def test_guard_fallback_rejects_symlinked_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit.run_files import UnsafeRunFileError, read_run_file

    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "file.json").write_text("{}", encoding="utf-8")
    (tmp_path / "linked").symlink_to(actual, target_is_directory=True)
    monkeypatch.setattr(os, "supports_dir_fd", set())

    assert read_run_file(tmp_path, "actual/file.json") == b"{}"
    with pytest.raises(UnsafeRunFileError, match="symlinks"):
        read_run_file(tmp_path, "linked/file.json")


def test_closed_wal_mode_index_is_read_without_changing_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sqlite3
    from contextlib import closing
    from azure_tenant_audit.contracts import _validate_evidence_db
    from azure_tenant_audit.evidence_db import load_run_index_summary

    run = tmp_path / "runs" / "run"
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setenv("TMPDIR", str(scratch))
    index = run / "index" / "evidence.sqlite"
    index.parent.mkdir(parents=True)
    with closing(sqlite3.connect(index)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE run_meta (key TEXT, value TEXT)")
        conn.execute("CREATE TABLE section_stats (section_name TEXT, item_count INTEGER, source_path TEXT)")
        conn.execute("CREATE TABLE normalized_records (record TEXT)")
        conn.execute("INSERT INTO run_meta VALUES ('run_id', 'synthetic')")
        conn.commit()

    before = index.read_bytes()
    assert load_run_index_summary(run)["run_id"] == "synthetic"
    issues: list[dict[str, object]] = []
    _validate_evidence_db(run, issues, read_only=True)
    assert issues == []
    assert index.read_bytes() == before
    assert sorted(path.name for path in index.parent.iterdir()) == ["evidence.sqlite"]
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("kind", ("fifo", "symlink"))
def test_guard_rejects_replacement_between_stat_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    from azure_tenant_audit.run_files import UnsafeRunFileError, read_run_file

    if not hasattr(os, "O_NONBLOCK") or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "mkfifo"):
        pytest.skip("Descriptor flags or FIFOs are unavailable")
    if os.open not in os.supports_dir_fd:
        pytest.skip("Descriptor-relative opens are unavailable")
    original = tmp_path / "run-manifest.json"
    original.write_text("{}", encoding="utf-8")
    replacement = tmp_path / "replacement"
    if kind == "fifo":
        os.mkfifo(replacement)
    else:
        target = tmp_path / "target"
        target.write_text("{}", encoding="utf-8")
        replacement.symlink_to(target.name)
    original_open = os.open

    def replace_then_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if path == original.name:
            assert flags & os.O_NONBLOCK
            assert flags & os.O_NOFOLLOW
            os.replace(replacement, original)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", replace_then_open)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {replace_then_open})
    with pytest.raises(UnsafeRunFileError):
        read_run_file(tmp_path, original.name)


def test_manifest_artifact_cannot_use_symlinked_directory(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "summary.md").write_text("ordinary text", encoding="utf-8")
    (tmp_path / "linked").symlink_to(actual, target_is_directory=True)
    (tmp_path / "run-manifest.json").write_text('{"summary_md_path": "linked/summary.md"}', encoding="utf-8")
    outcome = _call_tool("auditex_summarize_run", str(tmp_path))
    assert outcome.get("error") == "UnsafeRunFileError", outcome
    assert "symlinks" in str(outcome.get("message"))


@pytest.mark.parametrize("kind", ("fifo", "symlink", "directory", "oversize"))
def test_mcp_rejects_unsafe_manifest_selected_index(tmp_path: Path, kind: str) -> None:
    (tmp_path / "run-manifest.json").write_text('{"evidence_db_path": "index/custom.sqlite"}', encoding="utf-8")
    _plant_bad_file(tmp_path / "index" / "custom.sqlite", kind)
    outcome = _call_tool("auditex_summarize_run", str(tmp_path))
    if kind == "oversize":
        assert "result" in outcome
    else:
        assert outcome.get("error") == "UnsafeRunFileError", outcome


@pytest.mark.parametrize("kind", ("fifo", "symlink", "directory", "oversize"))
@pytest.mark.parametrize("source", ("hash_manifest", "evidence_ref"))
def test_handoff_rejects_unsafe_referenced_artifact(tmp_path: Path, kind: str, source: str) -> None:
    (tmp_path / "run-manifest.json").write_text("{}", encoding="utf-8")
    relative = "custom/evidence.json"
    _plant_bad_file(tmp_path / relative, kind)
    if source == "hash_manifest":
        (tmp_path / "bundle-hashes.json").write_text(json.dumps({
            "artifacts": [{"path": relative, "sha256": "a" * 64}],
        }), encoding="utf-8")
    else:
        findings = tmp_path / "findings" / "findings.json"
        findings.parent.mkdir()
        findings.write_text(json.dumps([{
            "id": "finding-1", "evidence_refs": [{"artifact_path": relative, "record_key": "item-1"}],
        }]), encoding="utf-8")

    outcome = _call_tool("auditex_enterprise_handoff", str(tmp_path))

    assert _CANARY not in json.dumps(outcome)
    if source == "hash_manifest":
        assert outcome["result"]["integrity"]["status"] == "mismatch", outcome
        if kind == "oversize":
            assert relative in outcome["result"]["integrity"]["modified_paths"], outcome
            assert relative not in outcome["result"]["integrity"]["missing_paths"], outcome
        else:
            assert relative in outcome["result"]["integrity"]["missing_paths"], outcome
    else:
        assert outcome.get("error") in (None, "UnsafeRunFileError"), outcome


@pytest.mark.parametrize("kind", ("fifo", "symlink", "directory", "oversize"))
@pytest.mark.parametrize("relative", (
    "pack-manifest.json", "checksums.sha256", "source-artifacts/run-manifest.json",
    "source-artifacts/bundle-hashes.json",
))
def test_mcp_pack_verification_rejects_unsafe_bundle_files(tmp_path: Path, kind: str, relative: str) -> None:
    if relative != "pack-manifest.json":
        (tmp_path / "pack-manifest.json").write_text("{}", encoding="utf-8")
    _plant_bad_file(tmp_path / relative, kind)

    outcome = _call_tool("auditex_verify_customer_pack", str(tmp_path))

    assert _CANARY not in json.dumps(outcome)
    if "result" in outcome:
        assert outcome["result"]["valid"] is False, outcome
    else:
        assert outcome.get("error") == "UnsafeRunFileError", outcome
