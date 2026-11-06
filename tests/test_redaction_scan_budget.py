"""Size limits and fail-closed discovery, using synthetic and sparse files."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from azure_tenant_audit import output_redaction as redaction
from test_reporting import _write_run


def _sparse_run(root: Path, sizes: tuple[int, ...]) -> None:
    normalized = root / "normalized"
    normalized.mkdir(parents=True)
    for index, size in enumerate(sizes):
        with (normalized / f"private-name-{index}.json").open("wb") as stream:
            stream.truncate(size)


def test_shareable_preview_preserves_local_structure_after_redaction(tmp_path: Path) -> None:
    from auditex.reporting import preview_report

    root = tmp_path / "run"
    _write_run(root)
    report = root / "reports" / "report-pack.json"
    payload = json.loads(report.read_text())
    payload["executive_summary"]["owner"] = "private content"
    payload["executive_summary"]["ordinary_count"] = 42
    report.write_text(json.dumps(payload))
    options = {"run_dir": str(root), "format_name": "json", "include_sections": ["executive_summary"]}
    local = preview_report(**options, profile="local")
    shareable = preview_report(**options, profile="shareable")
    local_sections = json.loads(local["content"])["sections"]
    expected = redaction.settle_citations(redaction.redact_output(local_sections, context=redaction.context_for_run(root)))
    assert json.loads(shareable["content"]) == {"sections": expected}
    assert "private content" not in shareable["content"]
    assert expected["executive_summary"]["ordinary_count"] == 42


@pytest.mark.parametrize("sizes", [
    (46_281_912, 41_546_181),  # the largest files of the synthetic 90k-user run
    (48 * 1024 * 1024,) * 3,  # more than the old aggregate limit
])
def test_scan_accepts_large_synthetic_file_sizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sizes: tuple[int, ...]
) -> None:
    root = tmp_path / "run"
    _sparse_run(root, sizes)
    assert redaction._MAX_FILE_BYTES == 64 * 1024 * 1024
    assert redaction._MAX_SCAN_BYTES == 256 * 1024 * 1024
    # NUL-filled sparse files are not JSON. Exercise the real reader and budget, skipping only parsing.
    read_sizes: list[int] = []
    monkeypatch.setattr(redaction._Scan, "collect", lambda self, parts, data: read_sizes.append(len(data)))
    assert len(redaction.snapshot_run(root)) == len(sizes)
    context = redaction.context_for_run(root)
    assert not context.incomplete, context.incomplete_reasons
    assert read_sizes == list(sizes)
    for profile in (redaction.PROFILE_SHAREABLE, redaction.PROFILE_CUSTOMER_PACK, redaction.PROFILE_EXPLAINER):
        assert redaction.redact_output({"owner": "private"}, profile=profile, context=context)["owner"] == "<redacted-text>"


@pytest.fixture
def low_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redaction, "_MAX_FILE_BYTES", 100)
    monkeypatch.setattr(redaction, "_MAX_SCAN_BYTES", 150)


def _message(exc: pytest.ExceptionInfo[redaction.ContextIncompleteError], root: Path) -> str:
    message = str(exc.value)
    assert "shareable output" in message.lower()
    assert "100 bytes" in message and "150 bytes" in message
    assert "private-name" not in message and str(root) not in message
    assert "private content" not in message
    return message


@pytest.mark.usefixtures("low_limits")
def test_scan_accepts_exact_file_and_aggregate_limits(tmp_path: Path) -> None:
    root = tmp_path / "run"
    _sparse_run(root, (100, 50))
    for path, size in zip(sorted((root / "normalized").iterdir()), (100, 50)):
        path.write_bytes(b'{"pad":"' + b'x' * (size - 10) + b'"}')
    assert len(redaction.snapshot_run(root)) == 2
    assert len(redaction.read_normalized_sections(root)) == 2
    assert not redaction.context_for_run(root).incomplete


@pytest.mark.usefixtures("low_limits")
@pytest.mark.parametrize("sizes", [(101,), (80, 80)])
def test_over_budget_refuses_all_profiles_without_naming_files(tmp_path: Path, sizes: tuple[int, ...]) -> None:
    root = tmp_path / "run"
    _sparse_run(root, sizes)
    # For the aggregate case each file is valid JSON and individually within the file cap.
    if len(sizes) > 1:
        for path in (root / "normalized").iterdir():
            path.write_bytes(b'{"pad":"' + b'x' * 70 + b'"}')
            assert path.stat().st_size == 80
    with pytest.raises(redaction.ContextIncompleteError) as snapshot_error:
        redaction.snapshot_run(root)
    expected = _message(snapshot_error, root)
    with pytest.raises(redaction.ContextIncompleteError) as sections_error:
        redaction.read_normalized_sections(root)
    assert _message(sections_error, root) == expected
    context = redaction.context_for_run(root)
    for profile in (redaction.PROFILE_SHAREABLE, redaction.PROFILE_CUSTOMER_PACK, redaction.PROFILE_EXPLAINER):
        with pytest.raises(redaction.ContextIncompleteError) as output_error:
            redaction.redact_output({"owner": "private content"}, profile=profile, context=context)
        assert _message(output_error, root) == expected


@pytest.mark.usefixtures("low_limits")
@pytest.mark.parametrize("command", ["export", "analyze"])
def test_cli_over_budget_prints_only_the_safe_refusal(tmp_path: Path, command: str) -> None:
    root = tmp_path / "private-run"
    _write_run(root)
    (root / "normalized" / "private-name.json").write_text('{"text":"private content' + 'x' * 100 + '"}')
    script = (
        "import sys; from azure_tenant_audit import output_redaction as r; "
        "r._MAX_FILE_BYTES=100; r._MAX_SCAN_BYTES=150; "
        "from auditex.cli import main; "
        "main({'export': ['export', 'run', 'json', sys.argv[1]], "
        "'analyze': ['report', 'analyze', sys.argv[1]]}[sys.argv[2]])"
    )
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    result = subprocess.run([sys.executable, "-B", "-c", script, str(root), command], env=env, capture_output=True, text=True, timeout=10)
    expected = str(redaction.ContextIncompleteError((("<ignored>", redaction.REASON_OVERSIZE),)))
    assert result.returncode != 0 and result.stdout == ""
    assert result.stderr == expected + "\n"
    assert str(root) not in result.stderr and "private content" not in result.stderr
    assert not (root / "reports" / "rendered-report.json").exists()


@pytest.mark.usefixtures("low_limits")
def test_size_refusal_survives_truncated_and_multi_run_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "run"
    _sparse_run(root, (101,))
    (root / "normalized" / "aaa.json").write_text("not JSON")
    other = tmp_path / "other"
    _sparse_run(other, (101,))
    monkeypatch.setattr(redaction, "_MAX_REASONS", 1)
    context = redaction.context_for_runs([root, other])
    assert context.incomplete_omitted
    with pytest.raises(redaction.ContextIncompleteError) as error:
        redaction.redact_output({}, context=context)
    assert str(other) not in _message(error, root)


@pytest.mark.usefixtures("low_limits")
def test_failed_partial_read_debits_budget_and_refuses_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "run"
    _sparse_run(root, (90, 90, 90))
    inode = (root / "normalized" / "private-name-0.json").stat().st_ino
    original_read = os.read
    total = 0

    def fail_after_partial_read(fd: int, count: int) -> bytes:
        nonlocal total
        assert os.fstat(fd).st_ino == inode  # later files no longer fit the remaining budget
        if total:
            raise OSError("private content")
        data = original_read(fd, min(count, 70))
        total += len(data)
        return data

    monkeypatch.setattr(redaction.os, "read", fail_after_partial_read)
    context = redaction.context_for_run(root)
    assert total == 70 and len(context.incomplete_files) == 3
    with pytest.raises(redaction.ContextIncompleteError) as error:
        redaction.redact_output({}, context=context)
    _message(error, root)


@pytest.mark.usefixtures("low_limits")
def test_failed_close_after_read_debits_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "run"
    _sparse_run(root, (90, 90, 90))
    inodes = {(root / "normalized" / f"private-name-{index}.json").stat().st_ino for index in range(3)}
    first_inode = (root / "normalized" / "private-name-0.json").stat().st_ino
    original_read, original_close = os.read, os.close
    total = 0

    def count_read(fd: int, count: int) -> bytes:
        nonlocal total
        data = original_read(fd, count)
        if os.fstat(fd).st_ino in inodes:
            total += len(data)
        return data

    def fail_close(fd: int) -> None:
        inode = os.fstat(fd).st_ino
        original_close(fd)
        if inode == first_inode:
            raise OSError("synthetic close failure")

    monkeypatch.setattr(redaction.os, "read", count_read)
    monkeypatch.setattr(redaction.os, "close", fail_close)
    context = redaction.context_for_run(root)
    assert total == 90 and context.incomplete
    with pytest.raises(redaction.ContextIncompleteError) as error:
        redaction.redact_output({}, context=context)
    _message(error, root)


@pytest.mark.usefixtures("low_limits")
@pytest.mark.parametrize("partial_failure", [False, True])
def test_failed_symlink_parent_close_debits_read_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, partial_failure: bool
) -> None:
    root = tmp_path / "run"
    normalized, targets = root / "normalized", root / "targets"
    normalized.mkdir(parents=True)
    targets.mkdir()
    target, other = targets / "target.json", normalized / "b.json"
    for file in (target, other):
        with file.open("wb") as stream:
            stream.truncate(90)
    (normalized / "a.json").symlink_to("../targets/target.json")
    target_inode, other_inode, directory_inode = target.stat().st_ino, other.stat().st_ino, targets.stat().st_ino
    original_read, original_close = os.read, os.close
    total = 0
    target_read = False

    def read_with_optional_failure(fd: int, count: int) -> bytes:
        nonlocal total, target_read
        inode = os.fstat(fd).st_ino
        if partial_failure and inode == target_inode:
            if target_read:
                raise OSError("synthetic partial read failure")
            target_read = True
            count = min(count, 70)
        data = original_read(fd, count)
        if inode in (target_inode, other_inode):
            total += len(data)
        return data

    def fail_parent_close(fd: int) -> None:
        inode = os.fstat(fd).st_ino
        original_close(fd)
        if inode == directory_inode:
            raise OSError("synthetic directory close failure")

    monkeypatch.setattr(redaction.os, "read", read_with_optional_failure)
    monkeypatch.setattr(redaction.os, "close", fail_parent_close)
    context = redaction.context_for_run(root)
    assert total == (70 if partial_failure else 90) and context.incomplete
    with pytest.raises(redaction.ContextIncompleteError) as error:
        redaction.redact_output({}, context=context)
    _message(error, root)


@pytest.mark.usefixtures("low_limits")
def test_file_close_failure_preserves_prior_oversize_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "run"
    _sparse_run(root, (90,))
    inode = (root / "normalized" / "private-name-0.json").stat().st_ino
    original_fstat, original_close = os.fstat, os.close

    def grew_before_open(fd: int) -> os.stat_result:
        info = original_fstat(fd)
        if info.st_ino == inode:
            fields = list(info)
            fields[6] = 101
            return os.stat_result(fields)
        return info

    def fail_file_close(fd: int) -> None:
        close_inode = original_fstat(fd).st_ino
        original_close(fd)
        if close_inode == inode:
            raise OSError("synthetic close failure")

    monkeypatch.setattr(redaction.os, "fstat", grew_before_open)
    monkeypatch.setattr(redaction.os, "close", fail_file_close)
    context = redaction.context_for_run(root)
    with pytest.raises(redaction.ContextIncompleteError) as error:
        redaction.redact_output({}, context=context)
    _message(error, root)


@pytest.mark.usefixtures("low_limits")
@pytest.mark.parametrize("reason", [redaction.REASON_OVERSIZE, redaction.REASON_SCAN_BYTES])
def test_symlink_parent_close_failure_preserves_size_reason_and_debit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    root = tmp_path / "run"
    normalized, targets = root / "normalized", root / "targets"
    normalized.mkdir(parents=True)
    targets.mkdir()
    target, other = targets / "target.json", normalized / "b.json"
    target.write_bytes(b'x' * 90)
    other.write_bytes(b'x' * 70)
    (normalized / "a.json").symlink_to("../targets/target.json")
    directory_inode = targets.stat().st_ino
    original_reader, original_close = redaction._read_file_at, os.close
    other_caps: list[int] = []

    def size_failure(parent_fd: int, name: str, info: os.stat_result, cap: int) -> bytes:
        if name == "target.json":
            raise redaction._Unsafe(reason, 70)
        other_caps.append(cap)
        return original_reader(parent_fd, name, info, cap)

    def fail_parent_close(fd: int) -> None:
        inode = os.fstat(fd).st_ino
        original_close(fd)
        if inode == directory_inode:
            raise OSError("synthetic directory close failure")

    monkeypatch.setattr(redaction, "_read_file_at", size_failure)
    monkeypatch.setattr(redaction.os, "close", fail_parent_close)
    context = redaction.context_for_run(root)
    assert other_caps == [80]
    with pytest.raises(redaction.ContextIncompleteError) as error:
        redaction.redact_output({}, context=context)
    _message(error, root)
