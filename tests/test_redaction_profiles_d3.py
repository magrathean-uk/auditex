"""The D3 output boundary, using synthetic values only."""
from __future__ import annotations

import json
import os
import signal
from pathlib import Path

import pytest
from test_reporting import _write_run

GUID = "b0b0b0b0-1234-4567-8abc-0123456789ab"
OWNER = "PRIVATE OWNER 726"
NOTES = "PRIVATE NOTES 726"
ADDRESS = "private.person@example.test"
NAME = "Priya Privateperson"


@pytest.fixture
def run(tmp_path: Path) -> Path:
    root = tmp_path / "run"
    _write_run(root)
    report = root / "reports" / "report-pack.json"
    payload = json.loads(report.read_text())
    payload["executive_summary"] = {
        "owner": OWNER, "notes": NOTES, "tenant_id": GUID,
        "email": ADDRESS, "name": NAME, "domain": "example.test",
        "group_name": "Operations Group", "role_name": "Global Administrator",
    }
    report.write_text(json.dumps(payload))
    (root / "normalized" / "users.json").write_text(json.dumps({
        "records": [{"display_name": NAME, "is_privileged": True}]
    }))
    return root


@pytest.mark.parametrize("profile", ["shareable", "customer_pack", "explainer"])
@pytest.mark.parametrize("key", ["owner", "justification", "comment", "comments", "notes"])
def test_d3_free_text_keys_in_nested_values(profile: str, key: str) -> None:
    from azure_tenant_audit.output_redaction import redact_output

    result = redact_output({"nested": [{key: [OWNER, {"nested": NOTES}]}]}, profile=profile)
    assert OWNER not in str(result) and NOTES not in str(result)


def test_d3_local_report_retains_values_in_preview_and_file(run: Path, tmp_path: Path) -> None:
    from auditex.reporting import preview_report, render_report

    preview = preview_report(run_dir=str(run), format_name="json", include_sections=["executive_summary"], profile="local")
    target = tmp_path / "local.json"
    render_report(run_dir=str(run), format_name="json", include_sections=["executive_summary"], output_path=str(target), profile="local")
    for value in (OWNER, NOTES, GUID, ADDRESS, NAME, "example.test", "Operations Group", "Global Administrator"):
        assert value in preview["content"]
        assert value in target.read_text()


def test_d3_local_report_does_not_apply_shareable_scan_limits(run: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex.reporting import preview_report
    from azure_tenant_audit import output_redaction as redaction

    (run / "normalized" / "large.json").write_text(json.dumps({"text": "LOCAL-CONTENT-726" * 20}))
    monkeypatch.setattr(redaction, "_MAX_FILE_BYTES", 20)
    result = preview_report(run_dir=str(run), format_name="json", include_sections=["normalized"], profile="local")
    assert "LOCAL-CONTENT-726" in result["content"]


@pytest.mark.parametrize("profile", ["shareable", "customer_pack", "explainer"])
def test_d3_report_profiles_apply_before_rendering(run: Path, profile: str) -> None:
    from auditex.reporting import preview_report

    for fmt in ("json", "md", "html"):
        content = preview_report(run_dir=str(run), format_name=fmt, include_sections=["executive_summary"], profile=profile)["content"]
        for value in (OWNER, NOTES, GUID, ADDRESS, NAME):
            assert value not in content, (fmt, value)
        for value in ("example.test", "Operations Group", "Global Administrator"):
            assert value in content, (fmt, value)


def test_d3_mcp_preview_is_shareable(run: Path) -> None:
    from auditex.mcp_server import preview_report

    result = preview_report(str(run), "json", include_sections="executive_summary")
    for value in (OWNER, NOTES, GUID, ADDRESS, NAME):
        assert value not in json.dumps(result)


@pytest.mark.parametrize("to_file", [False, True])
def test_d3_cli_payload_redacts_structure(run: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], to_file: bool) -> None:
    from auditex.cli import _emit_report_payload

    target = tmp_path / "payload.json"
    _emit_report_payload(payload={"owner": OWNER, "notes": NOTES, "id": GUID}, format_name="json",
                         output_path=str(target) if to_file else None, run_dir=str(run))
    output = target.read_text() if to_file else capsys.readouterr().out
    assert all(value not in output for value in (OWNER, NOTES, GUID))


def test_d3_exporter_uses_shareable_profile(run: Path, tmp_path: Path) -> None:
    from auditex.exporters import run_exporter

    target = tmp_path / "export.json"
    run_exporter(name="json", run_dir=str(run), include_sections=["executive_summary"], output_path=str(target))
    assert all(value not in target.read_text() for value in (OWNER, NOTES, GUID, ADDRESS, NAME))


def test_d3_incomplete_discovery_refuses_shareable_output(run: Path) -> None:
    from auditex.reporting import preview_report
    from azure_tenant_audit.output_redaction import ContextIncompleteError

    (run / "normalized" / "broken.json").write_text("not JSON")
    with pytest.raises(ContextIncompleteError, match="incomplete"):
        preview_report(run_dir=str(run), format_name="json", profile="shareable")


def test_d3_transient_failure_during_report_load_refuses_output(run: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex.reporting import preview_report
    from azure_tenant_audit import output_redaction as redaction

    original = redaction._read_file_at
    failed = False

    def fail_once(parent_fd, name, expected, cap=redaction._MAX_FILE_BYTES):
        nonlocal failed
        if name == "users.json" and not failed:
            failed = True
            raise redaction._Unsafe(redaction.REASON_UNREADABLE)
        return original(parent_fd, name, expected, cap)

    monkeypatch.setattr(redaction, "_read_file_at", fail_once)
    with pytest.raises(redaction.ContextIncompleteError, match="incomplete"):
        preview_report(run_dir=str(run), format_name="json", profile="shareable")


def test_d3_snapshot_refuses_new_fifo(run: Path) -> None:
    from azure_tenant_audit.output_redaction import (
        ContextIncompleteError,
        assert_snapshot_stable,
        context_for_run,
    )

    context = context_for_run(run)
    assert not context.incomplete
    os.mkfifo(run / "normalized" / "new-person.json")
    with pytest.raises(ContextIncompleteError, match="incomplete"):
        assert_snapshot_stable(run, context.snapshot)


def test_d3_mcp_diff_refuses_existing_normalised_fifo(run: Path, tmp_path: Path) -> None:
    from auditex.mcp_server import diff_runs
    from azure_tenant_audit.output_redaction import ContextIncompleteError

    other = tmp_path / "other"
    _write_run(other)
    os.mkfifo(run / "normalized" / "fifo.json")

    def timeout(_signum, _frame):
        raise RuntimeError("diff blocked on normalised FIFO")

    previous = signal.signal(signal.SIGALRM, timeout)
    signal.alarm(2)
    try:
        with pytest.raises(ContextIncompleteError, match="incomplete"):
            diff_runs(str(run), str(other))
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def test_d3_snapshot_refuses_new_unreadable_directory(run: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit import output_redaction as redaction

    context = redaction.context_for_run(run)
    (run / "normalized" / "new-directory").mkdir()
    original = redaction._open_dir_at

    def refuse(parent_fd, name, expected=None):
        if name == "new-directory":
            raise redaction._Unsafe(redaction.REASON_UNREADABLE)
        return original(parent_fd, name, expected)

    monkeypatch.setattr(redaction, "_open_dir_at", refuse)
    with pytest.raises(redaction.ContextIncompleteError, match="incomplete"):
        redaction.assert_snapshot_stable(run, context.snapshot)


def test_d3_preview_refuses_fifo_added_after_discovery(run: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex import reporting
    from azure_tenant_audit.output_redaction import ContextIncompleteError

    original = reporting._final_pass

    def add_fifo(*args, **kwargs):
        result = original(*args, **kwargs)
        os.mkfifo(run / "normalized" / "late.json")
        return result

    monkeypatch.setattr(reporting, "_final_pass", add_fifo)
    with pytest.raises(ContextIncompleteError, match="incomplete"):
        reporting.preview_report(run_dir=str(run), format_name="md", profile="shareable")


def test_d3_rejected_reads_debit_aggregate_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit import output_redaction as redaction

    root = tmp_path / "budget"
    normalized = root / "normalized"
    normalized.mkdir(parents=True)
    paths = []
    for index in range(5):
        path = normalized / f"part{index}.json"
        path.write_text(json.dumps({"pad": "x" * 80}))
        paths.append(path)
    by_inode = {path.stat().st_ino: path for path in paths}
    changed: set[int] = set()
    byte_count = 0
    original_read = os.read

    def read_and_change(fd: int, count: int) -> bytes:
        nonlocal byte_count
        result = original_read(fd, count)
        inode = os.fstat(fd).st_ino
        if inode in by_inode:
            byte_count += len(result)
            if result and inode not in changed:
                changed.add(inode)
                path = by_inode[inode]
                path.write_text(path.read_text().replace("x", "y"))
        return result

    monkeypatch.setattr(redaction, "_MAX_SCAN_BYTES", 150)
    monkeypatch.setattr(redaction.os, "read", read_and_change)
    assert redaction.context_for_run(root).incomplete
    assert byte_count <= 150


def test_d3_failed_partial_reads_debit_aggregate_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit import output_redaction as redaction

    root = tmp_path / "failed-budget"
    normalized = root / "normalized"
    normalized.mkdir(parents=True)
    paths = []
    for index in range(5):
        path = normalized / f"part{index}.json"
        path.write_text(json.dumps({"pad": "x" * 80}))
        paths.append(path)
    inodes = {path.stat().st_ino for path in paths}
    read_once: set[int] = set()
    byte_count = 0
    original_read = os.read

    def partial_then_fail(fd: int, count: int) -> bytes:
        nonlocal byte_count
        inode = os.fstat(fd).st_ino
        if inode not in inodes:
            return original_read(fd, count)
        if inode in read_once:
            raise OSError("synthetic read failure")
        read_once.add(inode)
        data = original_read(fd, min(count, 40))
        byte_count += len(data)
        return data

    monkeypatch.setattr(redaction, "_MAX_SCAN_BYTES", 100)
    monkeypatch.setattr(redaction.os, "read", partial_then_fail)
    assert redaction.context_for_run(root).incomplete
    assert byte_count <= 100


def test_d3_docs_disclose_pattern_limits() -> None:
    root = Path(__file__).resolve().parents[1]
    for relative in ("CHANGELOG.md", "docs/reference/security-privacy.md"):
        text = (root / relative).read_text().lower()
        assert "32" in text and "scheme" in text
        assert "immutable" in text and "word" in text and "boundar" in text


def test_d3_url_password_scheme_limit_and_id_boundaries() -> None:
    from azure_tenant_audit.output_redaction import RedactionContext, redact_output

    secret = "D3URLPASSWORDCANARY"
    supported = "s" * 32 + f"://user:{secret}@host.invalid"
    unsupported = "s" * 33 + f"://user:{secret}:tail@host.invalid"
    assert secret not in redact_output(supported)
    assert secret in redact_output(unsupported)
    context = RedactionContext(protected_ids=frozenset({"abcde", "abc"}))
    assert "abcde" not in redact_output("id=abcde", context=context)
    assert redact_output("xabcde abcdex by abc", context=context) == "xabcde abcdex by abc"
    assert redact_output({"immutable_id": "abc"}, context=context)["immutable_id"].startswith("Id ")


def test_d3_unknown_profile_is_refused(run: Path) -> None:
    from auditex.reporting import preview_report

    with pytest.raises(KeyError):
        preview_report(run_dir=str(run), format_name="json", profile="shareble")


@pytest.mark.parametrize("profile", ["shareable", "customer_pack", "explainer"])
def test_d3_guid_that_matches_old_pseudonym_prefix_is_still_redacted(profile: str) -> None:
    from azure_tenant_audit.output_redaction import redact_output

    guid = "00000000-0000-4000-8000-123456789abc"
    output = redact_output({"tenant_id": guid}, profile=profile)
    assert guid not in json.dumps(output)
    assert redact_output(output, profile=profile) == output


def test_d3_group_and_role_names_mask_a_person_name_inside_lists() -> None:
    # DEC-003 (D5): a person's full name is masked inside group and role names too; the rest of the name remains.
    from azure_tenant_audit.output_redaction import (
        RedactionContext,
        pseudonym,
        redact_output,
    )

    group = f"Team {NAME}"
    role = f"Operations {NAME}"
    payload = {"groups": [{"display_name": group, "email": ADDRESS}], "roles": [role]}
    result = redact_output(payload, context=RedactionContext(protected_names=frozenset({NAME})))
    masked = "User " + pseudonym("", NAME)
    assert result["groups"][0]["display_name"] == f"Team {masked}"
    assert result["roles"] == [f"Operations {masked}"]
    assert ADDRESS not in result["groups"][0]["email"]


def test_d3_free_text_mapping_keys_are_redacted_too() -> None:
    from azure_tenant_audit.output_redaction import redact_output

    payload = {"notes": {"PRIVATE NOTE KEY 726": "PRIVATE NOTE VALUE 726", "PRIVATE SECOND KEY": 2}}
    result = json.dumps(redact_output(payload, profile="shareable"))
    assert "PRIVATE" not in result


def test_d3_missing_run_refuses_shareable_output(tmp_path: Path) -> None:
    from azure_tenant_audit.output_redaction import (
        ContextIncompleteError,
        redact_payload,
    )

    with pytest.raises(ContextIncompleteError, match="incomplete"):
        redact_payload({"notes": NOTES}, run_dirs=[tmp_path / "missing"])


def test_d3_link_target_is_not_opened_and_refusal_hides_path(run: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit import output_redaction as redaction

    (run / "linked-source.json").write_text("{}")
    (run / "normalized" / "linked.json").symlink_to("../linked-source.json")
    original_open = os.open
    def refuse_target_open(path, flags, *args, **kwargs):
        assert os.fspath(path) not in ("linked.json", "linked-source.json", str(run / "linked-source.json"))
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(redaction.os, "open", refuse_target_open)
    context = redaction.context_for_run(run)
    assert context.incomplete
    with pytest.raises(redaction.ContextIncompleteError) as caught:
        redaction.redact_output({"name": NAME}, context=context)
    assert str(run) not in str(caught.value)


@pytest.mark.parametrize("family", [
    "summarize", "blockers", "analyze", "api", "permissions", "proof", "notify_preview", "notify_send",
    "mcp_handoff", "mcp_diff", "mcp_diff_second", "mcp_compare", "mcp_compare_second", "mcp_external",
    "cli_analyze", "cli_api", "cli_permissions", "cli_proof", "cli_handoff",
])
def test_d3_refuses_change_between_payload_build_and_discovery(
    family: str, run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A name read into prose must not outlive the evidence that discovery uses to recognise it."""
    from auditex import assessment_review, cli, compare, mcp_server, notify, reporting
    from azure_tenant_audit.output_redaction import ContextIncompleteError

    target = run / "normalized" / "users.json"
    sent: list[object] = []
    output = tmp_path / "handoff.json"
    other = tmp_path / "other-run"
    if family in {"mcp_diff", "mcp_diff_second", "mcp_compare", "mcp_compare_second"}:
        _write_run(other)
        (other / "normalized" / "users.json").write_text(target.read_text())
        if family.endswith("_second"):
            target = other / "normalized" / "users.json"
    builders = {
        "summarize": (mcp_server, "summarize_run_raw"),
        "blockers": (mcp_server, "list_blockers_raw"),
        "analyze": (reporting, "analyze_report"),
        "api": (reporting, "api_call_inventory"),
        "permissions": (reporting, "permissions_ledger"),
        "proof": (reporting, "proof_table"),
        "notify_preview": (notify, "_build_payload"),
        "notify_send": (notify, "_build_payload"),
        "mcp_handoff": (reporting, "enterprise_handoff"),
        "mcp_diff": (mcp_server, "diff_run_directories"),
        "mcp_diff_second": (mcp_server, "diff_run_directories"),
        "mcp_compare": (compare, "compare_runs"),
        "mcp_compare_second": (compare, "compare_runs"),
        "mcp_external": (assessment_review, "compare_external_assessments"),
        "cli_analyze": (reporting, "analyze_report"),
        "cli_api": (reporting, "api_call_inventory"),
        "cli_permissions": (reporting, "permissions_ledger"),
        "cli_proof": (reporting, "proof_table"),
        "cli_handoff": (reporting, "enterprise_handoff"),
    }
    owner, builder_name = builders[family]
    original = getattr(owner, builder_name)

    def race(*args: object, **kwargs: object) -> dict:
        # The external comparison builder is isolated from its input format; the planted result still models
        # a name read into prose before the corresponding normalised identity disappears.
        result = {} if family == "mcp_external" else original(*args, **kwargs)
        before = target.read_text()
        assert NAME in before
        # Keep the file valid and the same size, while removing the only structured copy of the name.
        after = before.replace(NAME, "Z" * len(NAME))
        assert len(before) == len(after)
        target.write_text(after)
        stat = target.stat()
        os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
        result["race_probe"] = f"Escalate to {NAME} for review"
        return result

    monkeypatch.setattr(owner, builder_name, race)
    monkeypatch.setattr(notify, "_send_webhook", lambda *args: sent.append(args) or {})
    calls = {
        "summarize": lambda: mcp_server.summarize_run(str(run)),
        "blockers": lambda: mcp_server.list_blockers(str(run)),
        "analyze": lambda: mcp_server.analyze_report(str(run)),
        "api": lambda: mcp_server.api_inventory(str(run)),
        "permissions": lambda: mcp_server.permissions_ledger(str(run)),
        "proof": lambda: mcp_server.proof_table(str(run)),
        "notify_preview": lambda: mcp_server.preview_notification(str(run)),
        "notify_send": lambda: notify.send_notification(run_dir=str(run), sink="teams", dry_run=False),
        "mcp_handoff": lambda: mcp_server.enterprise_handoff(str(run)),
        "mcp_diff": lambda: mcp_server.diff_runs(str(run), str(other)),
        "mcp_diff_second": lambda: mcp_server.diff_runs(str(run), str(other)),
        "mcp_compare": lambda: mcp_server.compare_many_runs([str(run), str(other)]),
        "mcp_compare_second": lambda: mcp_server.compare_many_runs([str(run), str(other)]),
        "mcp_external": lambda: mcp_server.compare_external_assessment_files([], run_dir=str(run)),
        "cli_analyze": lambda: cli.main(["report", "analyze", str(run)]),
        "cli_api": lambda: cli.main(["report", "api-calls", str(run), "--output", str(output)]),
        "cli_permissions": lambda: cli.main(["report", "permissions", str(run), "--output", str(output)]),
        "cli_proof": lambda: cli.main(["report", "proof-table", str(run), "--output", str(output)]),
        "cli_handoff": lambda: cli.main(["report", "handoff", str(run), "--output", str(output)]),
    }
    with pytest.raises(ContextIncompleteError, match="changed during scan"):
        calls[family]()
    assert NAME not in capsys.readouterr().out
    assert not output.exists()
    assert not sent
