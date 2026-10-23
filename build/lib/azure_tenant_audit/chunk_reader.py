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
import stat
from typing import Any, BinaryIO


class EndpointEvidenceError(ValueError):
    """An endpoint's collected rows could not be read completely."""

    def __init__(self, issue: dict[str, Any]) -> None:
        self.issue = issue
        super().__init__(f"Incomplete endpoint evidence: {issue['code']}")


def _issue(issues: list[dict[str, Any]] | None, code: str, **details: Any) -> None:
    issue = {"code": code, **details}
    if issues is None:
        raise EndpointEvidenceError(issue)
    issues.append(issue)


@contextmanager
def _open_chunk(run_dir: Path, relative: str) -> Iterator[BinaryIO]:
    """Open beneath a trusted root without following file/directory symlinks.

    Directory descriptors keep the containment check effective even if a path
    component is replaced during the read. Reject special files before reading.
    """
    path = Path(relative)
    if not relative or path.anchor or ".." in path.parts or "\\" in relative or not path.parts:
        raise EndpointEvidenceError({"code": "unsafe_chunk_path", "chunk_file": relative})
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        # Windows lacks directory-descriptor opens. Check every component,
        # including junction/reparse-point destinations, before opening it.
        root = run_dir.resolve(strict=True)
        target = root
        for part in path.parts:
            target = target / part
            if target.is_symlink() or not target.resolve(strict=True).is_relative_to(root):
                raise EndpointEvidenceError({"code": "unsafe_chunk_path", "chunk_file": relative})
        if not target.is_file():
            raise EndpointEvidenceError({"code": "invalid_chunk_file", "chunk_file": relative})
        with target.open("rb") as handle:
            yield handle
        return
    descriptors: list[int] = []
    try:
        descriptor = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY)
        descriptors.append(descriptor)
        for part in path.parts[:-1]:
            descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            descriptors.append(descriptor)
        descriptor = os.open(path.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        descriptors.append(descriptor)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise EndpointEvidenceError({"code": "invalid_chunk_file", "chunk_file": relative})
        with os.fdopen(descriptors.pop(), "rb") as handle:
            yield handle
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


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

    By default an invalid manifest, missing/unreadable/invalid chunk, duplicate
    chunk or count mismatch raises :class:`EndpointEvidenceError`. Pass an
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
        for relative in chunk_files:
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
