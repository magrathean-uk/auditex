"""Resolve evidence references against the files of a run bundle.

A finding cites its evidence with ``evidence_refs``. A reference is only traceable when the
artifact it names is a file inside the run directory and the record it names is in that file.
This module answers that question for every reference and, when a bundle is sealed, records the
answer on the reference itself: ``resolved``, ``collected_at`` and ``content_hash``. The proof
table and the confidence of a finding are derived from those answers, not from what the finding
builder asserted.

Resolution rules:

- ``artifact_path`` is relative to the run directory. An absolute path, a ``..`` segment or a
  symlink that leaves the run directory is refused.
- ``json_pointer`` (RFC 6901), when present, must exist in the artifact.
- Without a pointer, ``record_key`` must name a record. A JSON artifact has records in its
  ``records`` list (normalized sections) or is itself a list of rows; a JSONL artifact has one
  row per line (``jsonl_line`` is 1-based). A row is named by its ``key`` or ``id``, or, as the
  evidence index names it, ``<section>:<value>`` for ``id``, ``display_name``, ``name``,
  ``collector`` and ``surface``.
- ``content_hash`` is the SHA-256 of the artifact bytes. ``collected_at`` is the record's own
  ``collected_at`` or ``observed_at`` when it has one, otherwise the run's ``created_utc``.
"""
from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

HASH_ALGORITHM = "sha256"

REASON_ARTIFACT_MISSING = "artifact_missing"
REASON_OUTSIDE_RUN = "artifact_outside_run_dir"
REASON_UNREADABLE = "artifact_unreadable"
REASON_NOT_ADDRESSABLE = "artifact_not_addressable"
REASON_RECORD_NOT_FOUND = "record_not_found"
REASON_POINTER_NOT_FOUND = "json_pointer_not_found"
REASON_LINE_NOT_FOUND = "jsonl_line_not_found"

# Reasons that mean the artifact itself is not usable, as opposed to a record missing from it.
ARTIFACT_REASONS = frozenset({REASON_ARTIFACT_MISSING, REASON_OUTSIDE_RUN, REASON_UNREADABLE})

_KEY_FIELDS = ("key", "id", "display_name", "name", "collector", "surface")
_TIMESTAMP_FIELDS = ("collected_at", "observed_at")
_CHUNK = 1024 * 1024


def file_sha256(path: str | Path) -> str:
    """SHA-256 of a file, streamed. Raises ``OSError`` when the file cannot be read."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def confined_file(run_dir: str | Path, relative: Any) -> tuple[Path | None, str | None]:
    """The regular file ``relative`` names inside ``run_dir``, or ``(None, reason)``."""
    text = str(relative or "").strip().replace("\\", "/")
    if not text:
        return None, REASON_ARTIFACT_MISSING
    candidate = PurePosixPath(text)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None, REASON_OUTSIDE_RUN
    root = Path(os.path.realpath(run_dir))
    path = Path(os.path.realpath(root / candidate.as_posix()))
    try:
        path.relative_to(root)
    except ValueError:
        return None, REASON_OUTSIDE_RUN
    if not path.is_file():
        return None, REASON_ARTIFACT_MISSING
    return path, None


def resolve_json_pointer(document: Any, pointer: str) -> tuple[bool, Any]:
    """Follow an RFC 6901 pointer. ``(False, None)`` when any step is missing."""
    if pointer == "":
        return True, document
    if not pointer.startswith("/"):
        return False, None
    current = document
    for part in pointer[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if part not in current:
                return False, None
            current = current[part]
        elif isinstance(current, list):
            if not part.isdigit() or (len(part) > 1 and part.startswith("0")) or int(part) >= len(current):
                return False, None
            current = current[int(part)]
        else:
            return False, None
    return True, current


def record_identifiers(record: Mapping[str, Any], section: str, index: int) -> set[str]:
    """Every string that names ``record``: its own ``key``/``id`` and the evidence index keys."""
    names: set[str] = {f"{section}:{index}"}
    for field in _KEY_FIELDS:
        value = record.get(field)
        if value is None or not str(value).strip():
            continue
        text = str(value)
        if field in ("key", "id"):
            names.add(text)
        if field != "key":
            names.add(f"{section}:{text}")
    return names


def _find_records(rows: Iterable[Any], section: str, wanted: set[str]) -> dict[str, Any]:
    """The first record that carries each wanted name; stops reading once every name is found.

    Only the wanted names are kept, so a section of a hundred thousand rows costs one pass and
    memory in proportion to the references, not to the rows.
    """
    found: dict[str, Any] = {}
    if not wanted:
        return found
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            continue
        for name in record_identifiers(row, section, index) & wanted:
            found.setdefault(name, row)
        if len(found) == len(wanted):
            break
    return found


def _rows(document: Any) -> tuple[str | None, list[Any]]:
    """The addressable rows of a JSON document and the section name they sit in."""
    if isinstance(document, Mapping):
        records = document.get("records")
        if isinstance(records, list):
            return (str(document.get("kind") or "") or None), records
        return None, []
    if isinstance(document, list):
        return None, document
    return None, []


@dataclass(frozen=True)
class RefResolution:
    resolved: bool
    reason: str | None = None
    content_hash: str | None = None
    collected_at: str | None = None


def _signature(ref: Mapping[str, Any]) -> tuple[str, str, str, int | None]:
    line = ref.get("jsonl_line")
    return (
        str(ref.get("artifact_path") or ""),
        str(ref.get("record_key") or ""),
        str(ref.get("json_pointer") or ""),
        line if isinstance(line, int) and not isinstance(line, bool) else None,
    )


def _record_time(record: Any) -> str | None:
    if isinstance(record, Mapping):
        for field in _TIMESTAMP_FIELDS:
            value = record.get(field)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


class EvidenceIndex:
    """Resolves references against one run directory, loading each artifact once.

    ``prime`` takes every reference that will be asked about, groups them by artifact and
    resolves each group from a single read of that artifact, so memory holds one artifact at a
    time. ``resolve`` answers from that work, and falls back to a one-reference prime.
    """

    def __init__(self, run_dir: str | Path) -> None:
        self.run_dir = Path(run_dir)
        self._results: dict[tuple[str, str, str, int | None], RefResolution] = {}

    def prime(self, refs: Iterable[Any]) -> None:
        groups: dict[str, dict[tuple[str, str, str, int | None], Mapping[str, Any]]] = {}
        for ref in refs:
            if not isinstance(ref, Mapping):
                continue
            signature = _signature(ref)
            if signature in self._results:
                continue
            groups.setdefault(signature[0], {})[signature] = ref
        for artifact, items in groups.items():
            self._resolve_artifact(artifact, items)

    def resolve(self, ref: Mapping[str, Any]) -> RefResolution:
        signature = _signature(ref)
        if signature not in self._results:
            self.prime([ref])
        return self._results[signature]

    def _resolve_artifact(
        self, artifact: str, items: dict[tuple[str, str, str, int | None], Mapping[str, Any]]
    ) -> None:
        path, reason = confined_file(self.run_dir, artifact)
        if path is None:
            for signature in items:
                self._results[signature] = RefResolution(False, reason)
            return
        try:
            digest = file_sha256(path)
        except OSError:
            for signature in items:
                self._results[signature] = RefResolution(False, REASON_UNREADABLE)
            return

        suffix = path.suffix.lower()
        if suffix == ".json":
            try:
                document: Any = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                for signature in items:
                    self._results[signature] = RefResolution(False, REASON_UNREADABLE, digest)
                return
            self._resolve_json(path, document, digest, items)
        elif suffix == ".jsonl":
            self._resolve_jsonl(path, digest, items)
        else:
            for signature in items:
                self._results[signature] = RefResolution(False, REASON_NOT_ADDRESSABLE, digest)

    def _resolve_json(
        self,
        path: Path,
        document: Any,
        digest: str,
        items: dict[tuple[str, str, str, int | None], Mapping[str, Any]],
    ) -> None:
        by_name: dict[str, Any] | None = None
        for signature in items:
            _, record_key, pointer, _line = signature
            if pointer:
                found, value = resolve_json_pointer(document, pointer)
                if found:
                    self._results[signature] = RefResolution(True, None, digest, _record_time(value))
                else:
                    self._results[signature] = RefResolution(False, REASON_POINTER_NOT_FOUND, digest)
                continue
            if by_name is None:
                section, rows = _rows(document)
                by_name = _find_records(
                    rows,
                    section or path.stem,
                    {key for _artifact, key, pointer_, _line_ in items if key and not pointer_},
                )
            if record_key and record_key in by_name:
                self._results[signature] = RefResolution(True, None, digest, _record_time(by_name[record_key]))
            else:
                self._results[signature] = RefResolution(False, REASON_RECORD_NOT_FOUND, digest)

    def _resolve_jsonl(
        self,
        path: Path,
        digest: str,
        items: dict[tuple[str, str, str, int | None], Mapping[str, Any]],
    ) -> None:
        rows: list[Any] = []
        try:
            with path.open("r", encoding="utf-8") as handle:
                for raw_line in handle:
                    text = raw_line.strip()
                    if not text:
                        rows.append(None)
                        continue
                    try:
                        rows.append(json.loads(text))
                    except ValueError:
                        rows.append(None)
        except OSError:
            for signature in items:
                self._results[signature] = RefResolution(False, REASON_UNREADABLE, digest)
            return
        by_name: dict[str, Any] | None = None
        for signature in items:
            _, record_key, _pointer, line = signature
            if line is not None:
                if 1 <= line <= len(rows) and rows[line - 1] is not None:
                    self._results[signature] = RefResolution(True, None, digest, _record_time(rows[line - 1]))
                else:
                    self._results[signature] = RefResolution(False, REASON_LINE_NOT_FOUND, digest)
                continue
            if by_name is None:
                by_name = _find_records(
                    rows,
                    path.stem,
                    {key for _artifact, key, _pointer_, line_ in items if key and line_ is None},
                )
            if record_key and record_key in by_name:
                self._results[signature] = RefResolution(True, None, digest, _record_time(by_name[record_key]))
            else:
                self._results[signature] = RefResolution(False, REASON_RECORD_NOT_FOUND, digest)


def confidence_for(refs: Iterable[Any]) -> str:
    """``high`` when every reference resolved, ``medium`` when some did, otherwise ``low``."""
    rows = [ref for ref in refs if isinstance(ref, Mapping)]
    if not rows:
        return "low"
    resolved = sum(1 for ref in rows if ref.get("resolved") is True)
    if resolved == len(rows):
        return "high"
    return "medium" if resolved else "low"


def ref_proof_status(ref: Mapping[str, Any]) -> str:
    """``supported`` for a resolved reference, ``unsupported`` for one that did not resolve.

    A reference no one has checked (no ``resolved`` marker, as in bundles from before the
    marker existed) keeps ``supported``; the validator resolves such references itself.
    """
    return "unsupported" if ref.get("resolved") is False else "supported"


def refs_checked(refs: Iterable[Any]) -> bool:
    """Whether any reference carries the ``resolved`` marker."""
    return any(isinstance(ref, Mapping) and isinstance(ref.get("resolved"), bool) for ref in refs)


def _refs_of(finding: Mapping[str, Any]) -> list[Any]:
    refs = finding.get("evidence_refs")
    return refs if isinstance(refs, list) else []


def seal_findings(
    run_dir: str | Path,
    findings: list[dict[str, Any]],
    *,
    created_utc: str | None = None,
) -> list[dict[str, Any]]:
    """Copies of ``findings`` whose references carry what the bundle shows.

    Each reference gets ``resolved`` (and ``unresolved_reason`` when false), ``content_hash``
    (SHA-256 of the artifact bytes) and ``collected_at`` (kept when already set). Each finding's
    ``confidence`` is derived from its references: the builder's own value is replaced.
    """
    index = EvidenceIndex(run_dir)
    index.prime(ref for finding in findings if isinstance(finding, Mapping) for ref in _refs_of(finding))
    sealed: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            sealed.append(finding)
            continue
        item = dict(finding)
        rows: list[Any] = []
        for ref in _refs_of(finding):
            if not isinstance(ref, Mapping):
                rows.append(ref)
                continue
            result = index.resolve(ref)
            row = dict(ref)
            row["resolved"] = result.resolved
            if result.resolved:
                row.pop("unresolved_reason", None)
            else:
                row["unresolved_reason"] = result.reason
            if result.content_hash:
                row["content_hash"] = result.content_hash
                if not str(row.get("collected_at") or "").strip():
                    stamp = result.collected_at or created_utc
                    if stamp:
                        row["collected_at"] = stamp
            else:
                row.pop("content_hash", None)
            rows.append(row)
        if isinstance(finding.get("evidence_refs"), list):
            item["evidence_refs"] = rows
        item["confidence"] = confidence_for(rows)
        sealed.append(item)
    return sealed
