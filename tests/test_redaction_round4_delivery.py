"""Fourth review, delivery paths: the customer pack (V4-01, V4-02), the MCP diff (V4-07), the notification path (V4-08)
and the notification profile (V4-03). Every identifier is synthetic.
"""
from __future__ import annotations

import json
import os
import signal
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from auditex import reporting
from auditex.reporting import verify_enterprise_handoff_pack, write_enterprise_handoff_pack
from azure_tenant_audit.bundle_integrity import BUNDLE_HASHES_PATH
from azure_tenant_audit.output_redaction import (
    PROFILE_CUSTOMER_PACK,
    PROFILE_SHAREABLE,
    ContextIncompleteError,
)
from gate_support import offline_run, read_json, rehash

OWNER = "PLANTED-OWNER-v401 Priya Nairplanted"
NOTES = "PLANTED-NOTES-v402 revisit in March"
GUID = "3f2a9c1e-7b4d-4e8a-9c3b-1d2e3f4a5b6c"
PLANTED = (OWNER, NOTES, "PLANTED-OWNER-v401", "PLANTED-NOTES-v402", "Nairplanted")


class Blocked(BaseException):
    """Not an ``Exception``: production code that catches ``OSError`` (``TimeoutError`` is one) must not swallow it."""


@contextmanager
def deadline(seconds: int) -> Iterator[None]:
    def _timeout(signum, frame):  # pragma: no cover - only on failure
        raise Blocked(f"blocked for more than {seconds} s")

    previous = signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _plant(run: Path) -> None:
    """Plant free text, an owner and a GUID where the report pack keeps them, then re-finalise the hash manifest."""
    path = run / "reports" / "report-pack.json"
    pack = read_json(path)
    pack.setdefault("summary", {})["owner"] = OWNER
    pack["executive_summary"] = {"owner": OWNER, "notes": NOTES, "headline": "Planted headline", "ref": GUID}
    pack["action_plan"] = [{"id": "finding-1", "title": "Fix sharing", "owner": OWNER, "notes": NOTES, "target": GUID}]
    path.write_text(json.dumps(pack, indent=2), encoding="utf-8")
    rehash(run)


@pytest.fixture(scope="module")
def planted_run(tmp_path_factory: pytest.TempPathFactory) -> Path:
    run = offline_run(tmp_path_factory.mktemp("v4-pack"), "v4")
    _plant(run)
    return run


def _all_text(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): p.read_text(encoding="utf-8", errors="ignore") for p in root.rglob("*") if p.is_file()}


# -- V4-01: the customer-pack report is redacted as structure before it is rendered ---------------------------------------------


def test_v4_01_the_local_report_keeps_the_owner_but_the_customer_profile_never_renders_it(planted_run: Path) -> None:
    local = reporting.preview_report(run_dir=str(planted_run), format_name="md", include_sections=["executive_summary"])
    assert "PLANTED-OWNER-v401" in local["content"], "guard: the shareable report keeps free text"
    for fmt in ("md", "html", "csv", "json"):
        customer = reporting.preview_report(
            run_dir=str(planted_run), format_name=fmt, include_sections=["executive_summary", "action_plan", "summary"],
            profile=PROFILE_CUSTOMER_PACK,
        )["content"]
        for planted in PLANTED:
            assert planted not in customer, (fmt, planted)
        assert GUID not in customer, fmt


def test_v4_01_an_unknown_profile_is_refused_not_downgraded(planted_run: Path) -> None:
    with pytest.raises(KeyError):
        reporting.preview_report(run_dir=str(planted_run), format_name="md", profile="no-such-profile")


def test_v4_01_the_pack_report_md_carries_no_planted_free_text(planted_run: Path, tmp_path: Path) -> None:
    pack = tmp_path / "pack"
    write_enterprise_handoff_pack(planted_run, pack)
    report = (pack / "report.md").read_text(encoding="utf-8")
    for planted in PLANTED:
        assert planted not in report, planted
    assert "<redacted-text>" in report


# -- V4-02: no customer-pack artifact is a verbatim copy of a private original ---------------------------------------------------


def test_v4_02_the_pack_carries_redacted_derivatives_with_source_and_output_hashes(planted_run: Path, tmp_path: Path) -> None:
    pack = tmp_path / "pack"
    manifest = write_enterprise_handoff_pack(planted_run, pack)
    texts = _all_text(pack)
    for name, text in texts.items():
        for planted in PLANTED:
            assert planted not in text, (name, planted)
        assert GUID not in text, f"{name}: a GUID of the private report pack left in the pack"
    listed = {row["path"]: row["sha256"] for row in read_json(planted_run / BUNDLE_HASHES_PATH)["artifacts"]}
    copied = [row for row in manifest["source_artifacts"] if row.get("present")]
    assert any(row["source_path"] == "reports/report-pack.json" for row in copied)
    for row in copied:
        relative = row["source_path"]
        if relative == BUNDLE_HASHES_PATH:
            assert "transformed" not in row and row["sha256"] == __import__("hashlib").sha256((planted_run / relative).read_bytes()).hexdigest()
            continue
        assert row["transformed"] in {"pack_relative_paths", "customer_pack_redaction"}, relative
        assert row["source_sha256"] == listed[relative] and row["sha256"] != row["source_sha256"], relative
        assert row["customer_safe"] is True
    assert verify_enterprise_handoff_pack(pack)["valid"] is True
    # The private original is untouched: the working report pack keeps its references.
    assert OWNER in (planted_run / "reports" / "report-pack.json").read_text(encoding="utf-8")
    assert GUID in (planted_run / "reports" / "report-pack.json").read_text(encoding="utf-8")


def test_v4_02_an_artifact_that_cannot_be_redacted_is_left_out_not_copied(planted_run: Path, tmp_path: Path) -> None:
    run = tmp_path / "copy-run"
    import shutil

    shutil.copytree(planted_run, run)
    (run / "ai_context.json").write_text("not json at all", encoding="utf-8")
    rehash(run)
    listed = {row["path"] for row in read_json(run / BUNDLE_HASHES_PATH)["artifacts"]}
    row = reporting._copy_source_artifact(run, tmp_path / "out", "ai_context.json", "p", listed)
    assert row["present"] is False and row["customer_safe"] is False and row["skipped_reason"] == "not_redactable_json"
    assert not (tmp_path / "out" / "ai_context.json").exists()


def test_v4_02_a_hash_manifest_that_redaction_would_change_is_left_out(planted_run: Path, tmp_path: Path) -> None:
    run = tmp_path / "copy-run"
    import shutil

    shutil.copytree(planted_run, run)
    hashes = read_json(run / BUNDLE_HASHES_PATH)
    hashes["artifacts"].append({"path": f"x/{GUID}.json", "sha256": "0" * 64})
    (run / BUNDLE_HASHES_PATH).write_text(json.dumps(hashes), encoding="utf-8")
    row = reporting._copy_source_artifact(run, tmp_path / "out", BUNDLE_HASHES_PATH, "p", None)
    assert row["present"] is False and row["skipped_reason"] == "redaction_would_change_hash_manifest"
    assert not (tmp_path / "out" / BUNDLE_HASHES_PATH).exists()


# -- V4-07: the MCP diff never blocks before guarded discovery ------------------------------------------------------------------


def _mini_run(root: Path, name: str) -> Path:
    run = root / name
    (run / "normalized").mkdir(parents=True)
    (run / "reports").mkdir()
    (run / "run-manifest.json").write_text(json.dumps({"run_id": name, "tenant_name": "t"}), encoding="utf-8")
    (run / "normalized" / "devices.json").write_text(json.dumps({"kind": "devices", "records": [{"id": "d1"}]}), encoding="utf-8")
    return run


@pytest.mark.parametrize("relative", ["normalized/pipe.json", "normalized/snapshot.json", "normalized/devices.json"])
def test_v4_07_a_fifo_in_normalized_makes_diff_refuse_instead_of_blocking(tmp_path: Path, relative: str) -> None:
    from auditex import mcp_server
    from azure_tenant_audit.diffing import diff_run_directories

    left, right = _mini_run(tmp_path, "left"), _mini_run(tmp_path, "right")
    target = right / relative
    if target.exists():
        target.unlink()
    os.mkfifo(target)
    with deadline(5):
        with pytest.raises(ContextIncompleteError) as caught:
            diff_run_directories(left, right)
    assert str(tmp_path) not in str(caught.value)
    with deadline(5):
        with pytest.raises(ContextIncompleteError):
            mcp_server.diff_runs(str(left), str(right))


@pytest.mark.parametrize("relative", ["run-manifest.json", "reports/report-pack.json"])
def test_v4_07_a_fifo_where_diff_reads_a_run_file_never_blocks(tmp_path: Path, relative: str) -> None:
    from azure_tenant_audit.diffing import diff_run_directories

    left, right = _mini_run(tmp_path, "left"), _mini_run(tmp_path, "right")
    target = right / relative
    if target.exists():
        target.unlink()
    os.mkfifo(target)
    with deadline(5):
        result = diff_run_directories(left, right)
    assert result["summary"]["changed"] == 0


def test_v4_07_a_clean_diff_still_works_and_a_changed_record_is_reported(tmp_path: Path) -> None:
    from azure_tenant_audit.diffing import diff_run_directories

    left, right = _mini_run(tmp_path, "left"), _mini_run(tmp_path, "right")
    (right / "normalized" / "devices.json").write_text(
        json.dumps({"kind": "devices", "records": [{"id": "d1"}, {"id": "d2"}]}), encoding="utf-8"
    )
    result = diff_run_directories(left, right)
    assert result["summary"]["added"] == 1 and result["compared_files"] == ["devices.json"]


# -- V4-08: the notification path is linear -------------------------------------------------------------------------------------


def _notify_run(root: Path, title: str) -> Path:
    run = root / "run"
    (run / "reports").mkdir(parents=True)
    (run / "run-manifest.json").write_text(json.dumps({"tenant_name": "acme"}), encoding="utf-8")
    (run / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")
    (run / "reports" / "report-pack.json").write_text(
        json.dumps({"summary": {"tenant_name": "acme", "overall_status": "partial"}, "findings": [], "action_plan": [{"id": "f1", "title": title}]}),
        encoding="utf-8",
    )
    return run


class _Response:
    status_code = 200
    text = "ok"


@pytest.mark.parametrize("unit", ["eyJ", "eyJ" + "a" * 14 + ".", "Bearer ", "a" * 199 + "/"])
def test_v4_08_the_real_send_path_is_linear_on_overlapping_token_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unit: str
) -> None:
    import auditex.notify as notify

    monkeypatch.setenv(notify.WEBHOOK_ENV["teams"], "https://hooks.example.invalid/x")
    sent: list[Any] = []
    monkeypatch.setattr(notify.requests, "post", lambda url, json=None, **kw: sent.append(json) or _Response())
    timings = []
    for count in (5_000, 40_000):
        run = _notify_run(tmp_path / str(count), unit * count)
        started = time.monotonic()
        with deadline(30):
            result = notify.send_notification(run_dir=str(run), sink="teams", dry_run=False)
        timings.append(time.monotonic() - started)
        assert result["status"] == "sent" and sent
    # Eight times the input: linear is about eight times; the quadratic case is sixty-four times or the deadline.
    assert timings[1] < max(timings[0] * 24, 3.0), timings


def test_v4_08_the_notify_patterns_have_a_left_boundary_and_no_backtracking() -> None:
    import auditex.notify as notify

    started = time.monotonic()
    with deadline(10):
        notify._redact_string("eyJ" * 200_000)
        notify._redact_string("eyJabcdefghijklmnop." * 50_000)
    assert time.monotonic() - started < 5
    assert notify._redact_string("x eyJabcdefghijklmnop.abcdefghijklmnop.sig y") == "x [REDACTED-JWT] y"
    assert notify._redact_string("Authorization: Bearer abcdefgh12345678") == "Authorization: Bearer [REDACTED]"
    assert notify._redact_string("k=" + "A" * 250) == "k=[REDACTED-BLOB]"


# -- V4-03: every notification uses the customer-pack profile (done in the previous commit; confirmed here) ----------------------


def test_v4_03_the_notification_profile_is_customer_pack_and_the_planted_owner_never_leaves(
    planted_run: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import auditex.notify as notify

    assert notify.NOTIFY_PROFILE == PROFILE_CUSTOMER_PACK != PROFILE_SHAREABLE
    sent: list[Any] = []
    monkeypatch.setenv(notify.WEBHOOK_ENV["slack"], "https://hooks.example.invalid/x")
    monkeypatch.setattr(notify.requests, "post", lambda url, json=None, **kw: sent.append(json) or _Response())
    result = notify.send_notification(run_dir=str(planted_run), sink="slack", dry_run=False)
    dumped = __import__("json").dumps([sent, result], default=str)
    for planted in PLANTED:
        assert planted not in dumped, planted
    assert GUID not in dumped


# -- V4-12: the documents describe the final behaviour ---------------------------------------------------------------------------


def test_v4_12_the_documents_state_the_final_behaviour_and_the_honest_limits() -> None:
    root = Path(__file__).resolve().parents[1]
    privacy = (root / "docs" / "reference" / "security-privacy.md").read_text(encoding="utf-8")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    unreleased = changelog[changelog.index("## [Unreleased]"):changelog.index("### Rule-only SCuBA assessment")]
    assert "Decisions left to product are one constant" not in unreleased
    assert "verbatim source artifacts are unchanged" not in unreleased
    assert "nine verbatim" not in privacy and "Verbatim, integrity-bound copies, not redacted" not in privacy
    assert "_PUBLIC_SECTION_LABELS" in privacy and "alice_smith.json" in privacy  # filenames are opaque, said plainly
    assert "_ID_DEFINITIONS" in privacy and "_ID_NAMESPACES" not in privacy
    assert "at least 4 characters" in privacy and "redacted derivatives" in privacy.lower()
    assert "—" not in privacy and "—" not in changelog
