"""Read collected endpoint evidence without confusing an inline sample with it.

Chunk manifests are relative to an explicit run directory. No ambient working
directory or path from the payload is used as a fallback evidence root.
"""
from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
from typing import Any, BinaryIO

from .run_files import UnsafeRunFileError


class EndpointEvidenceError(ValueError):
    """An endpoint's collected rows could not be read completely."""

    def __init__(self, issue: dict[str, Any]) -> None:
        self.issue = issue
        super().__init__(f"Incomplete endpoint evidence: {issue['code']}")


# Guard refusal reasons that describe the chunk file itself rather than where it is.
_FILE_REFUSALS = frozenset({"type", "oversize"})


def _refusal_code(exc: UnsafeRunFileError) -> str:
    """A constant issue code for a chunk the descriptor guard did not admit.

    Nothing was read from a refused file. The guard refuses with field ``input``
    only when it cannot start (no descriptor-relative no-follow opens on this
    platform, or no working directory): a runtime condition, not a verdict on
    the chunk, so it is reported as unreadable. Every other refusal (outside
    the run, link, alias, owner, private input, change, or an unclassified
    failure to prove the chunk safe) is an unsafe path or an invalid file.
    """
    if exc.field == "input":
        return "unreadable_chunk"
    return "invalid_chunk_file" if exc.reason in _FILE_REFUSALS else "unsafe_chunk_path"


def _issue(issues: list[dict[str, Any]] | None, code: str, **details: Any) -> None:
    issue = {"code": code, **details}
    if issues is None:
        raise EndpointEvidenceError(issue)
    issues.append(issue)


@contextmanager
def _open_chunk(run_dir: Path, relative: str) -> Iterator[BinaryIO]:
    """Read the admitted chunk descriptor without reopening its pathname."""
    from .run_files import open_run_file

    with open_run_file(run_dir, relative, field="evidence") as descriptor:
        with os.fdopen(os.dup(descriptor), "rb") as handle:
            yield handle


def iter_endpoint_records(
    section: Mapping[str, Any],
    run_dir: str | Path | None = None,
    *,
    issues: list[dict[str, Any]] | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield the endpoint's rows, in collection order, one JSONL row at a time.

    Nonempty ``chunk_files`` are authoritative: the inline ``value`` sample is
    never appended or used as fallback when a chunk is missing. Unchunked
    inline/offline payloads retain their existing behavior. A truncated inline
    sample without chunks is usable partial evidence, with an explicit issue.

    By default an invalid manifest, missing/unreadable/invalid chunk, a chunk
    the descriptor guard refuses (outside the run, a link, a multiply-linked or
    private file, a special file), duplicate chunk or count mismatch raises
    :class:`EndpointEvidenceError`. Guarded reads need descriptor-relative
    no-follow opens; without them every chunk is ``unreadable_chunk`` and no
    pathname read is attempted. Pass an
    ``issues`` list to retain readable rows and collect structured issues
    instead. Consume the iterator fully to validate final counts. No exception
    message or issue contains raw row contents. Collection limits are metadata,
    not read errors: this helper reads *collected* rows, not a whole tenant.
    """
    if not isinstance(section, Mapping):
        _issue(issues, "invalid_endpoint_section")
        return

    expected_count = section.get("item_count")
    if expected_count is not None and (type(expected_count) is not int or expected_count < 0):
        _issue(issues, "invalid_item_count")
        expected_count = None
    chunk_files = section.get("chunk_files", [])
    if not isinstance(chunk_files, list):
        _issue(issues, "invalid_chunk_manifest")
        return
    expected_chunks = section.get("chunk_count")
    if expected_chunks is not None and (type(expected_chunks) is not int or expected_chunks != len(chunk_files)):
        _issue(issues, "chunk_count_mismatch", observed_count=len(chunk_files))

    observed_count = 0
    if chunk_files:
        if run_dir is None:
            _issue(issues, "run_dir_required")
            return
        root = Path(run_dir)
        seen_files: set[tuple[int, int]] = set()
        for index, relative in enumerate(chunk_files):
            if not isinstance(relative, str):
                _issue(issues, "invalid_chunk_path")
                continue
            try:
                with _open_chunk(root, relative) as handle:
                    file_stat = os.fstat(handle.fileno())
                    file_key = (file_stat.st_dev, file_stat.st_ino)
                    if file_key in seen_files:
                        _issue(issues, "duplicate_chunk", chunk_file=relative)
                        continue
                    seen_files.add(file_key)
                    for line_number, line in enumerate(handle, start=1):
                        if not line.strip():
                            continue
                        try:
                            row = json.loads(line.decode("utf-8"))
                        except (UnicodeError, ValueError):
                            _issue(issues, "invalid_chunk_json", chunk_file=relative, line_number=line_number)
                            continue
                        if not isinstance(row, dict):
                            _issue(issues, "invalid_chunk_record", chunk_file=relative, line_number=line_number)
                            continue
                        observed_count += 1
                        yield row
            except UnsafeRunFileError as exc:
                # Refused before any byte was read. The issue names the manifest
                # position, never the refused path, and no fallback is tried.
                _issue(issues, _refusal_code(exc), chunk_index=index)
            except EndpointEvidenceError as exc:
                if issues is None:
                    raise
                issues.append(exc.issue)
            except (OSError, ValueError) as exc:
                code = "unreadable_chunk"
                if isinstance(exc, FileNotFoundError):
                    code = "missing_chunk"
                elif isinstance(exc, OSError) and exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    code = "unsafe_chunk_path"
                _issue(issues, code, chunk_file=relative)
    else:
        values = section.get("value", [])
        if not isinstance(values, list):
            _issue(issues, "invalid_inline_records")
            return
        for index, row in enumerate(values):
            if not isinstance(row, dict):
                _issue(issues, "invalid_inline_record", record_index=index)
                continue
            observed_count += 1
            yield row
        if section.get("sample_truncated") or (expected_count is not None and expected_count > observed_count):
            _issue(issues, "missing_chunks")

    if expected_count is not None and observed_count != expected_count:
        _issue(issues, "item_count_mismatch", expected_count=expected_count, observed_count=observed_count)
    elif section.get("sample_truncated") and expected_count is None:
        _issue(issues, "missing_item_count")
