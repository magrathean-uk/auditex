"""The bundle hash manifest: a SHA-256 for every artifact of a finalized run.

``finalize_bundle_contract`` writes ``bundle-hashes.json`` as its last step. Handoff, the explorer
and customer-pack creation recompute the hashes and compare them, so a bundle edited after it was
finalized is reported (and a customer pack is refused) instead of being passed on as it was.

The manifest lists every file under the run directory except itself, the append-only logs (they
grow after finalization by design) and SQLite sidecar files. Files added later, such as an
explorer page written into ``reports/``, are reported as ``unlisted`` and do not fail the check.
"""
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .evidence_refs import HASH_ALGORITHM, confined_file, file_sha256

BUNDLE_HASHES_PATH = "bundle-hashes.json"
BUNDLE_HASHES_SCHEMA_VERSION = "2026-10-22"

# Files that change after finalization by design. They are named in the manifest, not hashed.
_APPEND_ONLY_LOGS = frozenset({"audit-log.jsonl", "audit-command-log.jsonl", "audit-debug.log"})
_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
_IGNORED_NAMES = frozenset({".DS_Store"})
_LIST_LIMIT = 100


def _excluded_reason(relative: str) -> str | None:
    if relative == BUNDLE_HASHES_PATH:
        return "bundle_hash_manifest"
    if relative in _APPEND_ONLY_LOGS:
        return "append_only_log"
    if relative.startswith("index/evidence.sqlite") and relative.endswith(_SIDECAR_SUFFIXES):
        return "sqlite_sidecar"
    if Path(relative).name in _IGNORED_NAMES:
        return "os_metadata"
    return None


def _run_manifest_lists_hashes(run_dir: Path) -> bool:
    try:
        manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    artifacts = manifest.get("artifacts") if isinstance(manifest, Mapping) else None
    return isinstance(artifacts, list) and BUNDLE_HASHES_PATH in artifacts


def _bundle_files(run_dir: Path) -> list[str]:
    """Relative POSIX paths of every regular file below ``run_dir``; symlinks are not followed."""
    found: list[str] = []
    root = str(run_dir)
    for current, directories, names in os.walk(root, followlinks=False):
        directories.sort()
        for name in sorted(names):
            path = Path(current) / name
            if path.is_symlink() or not path.is_file():
                continue
            found.append(path.relative_to(run_dir).as_posix())
    return sorted(found)


def build_bundle_hash_manifest(
    run_dir: str | Path, *, run_id: str | None = None, created_utc: str | None = None
) -> dict[str, Any]:
    """The manifest payload for the files currently in ``run_dir``."""
    root = Path(run_dir)
    artifacts: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    for relative in _bundle_files(root):
        reason = _excluded_reason(relative)
        if reason is not None:
            if reason != "bundle_hash_manifest":
                excluded.append({"path": relative, "reason": reason})
            continue
        path = root / relative
        artifacts.append({"path": relative, "sha256": file_sha256(path), "bytes": path.stat().st_size})
    return {
        "schema_version": BUNDLE_HASHES_SCHEMA_VERSION,
        "algorithm": HASH_ALGORITHM,
        "run_id": run_id,
        "created_utc": created_utc,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "excluded": excluded,
    }


def verify_bundle_hashes(run_dir: str | Path) -> dict[str, Any]:
    """Recompute the hashes of ``run_dir`` and compare them with ``bundle-hashes.json``.

    ``status`` is ``verified`` (every listed file matches), ``mismatch`` (a listed file changed
    or is gone), ``invalid`` (the manifest cannot be read as a hash manifest, or
    ``run-manifest.json`` lists it and it is gone) or ``absent`` (a bundle finalized before the
    manifest existed). Only ``mismatch`` and ``invalid`` say the bundle cannot be trusted as
    written; ``absent`` says it cannot be checked.
    """
    root = Path(run_dir)
    manifest_path = root / BUNDLE_HASHES_PATH
    result: dict[str, Any] = {
        "status": "absent",
        "path": BUNDLE_HASHES_PATH,
        "algorithm": HASH_ALGORITHM,
        "checked_count": 0,
        "modified": [],
        "missing": [],
        "unlisted": [],
        "modified_count": 0,
        "missing_count": 0,
        "unlisted_count": 0,
    }
    if not manifest_path.is_file():
        if _run_manifest_lists_hashes(root):
            # Finalization registers the manifest in run-manifest.json before it writes it, so a
            # bundle that lists it and has none lost it after finalization: that is not "absent".
            result.update(
                status="invalid",
                message="run-manifest.json lists bundle-hashes.json but the file is missing.",
            )
            return result
        result["message"] = "No bundle hash manifest; this bundle was finalized before one was written."
        return result
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        rows = payload.get("artifacts") if isinstance(payload, Mapping) else None
        if not isinstance(rows, list) or any(
            not isinstance(row, Mapping) or not isinstance(row.get("path"), str) or not isinstance(row.get("sha256"), str)
            for row in rows
        ):
            raise ValueError("artifacts is not a list of path and sha256 rows")
    except (OSError, ValueError) as exc:
        result.update(status="invalid", message=f"bundle-hashes.json cannot be read: {exc}")
        return result

    result["created_utc"] = payload.get("created_utc")
    result["run_id"] = payload.get("run_id")
    result["algorithm"] = payload.get("algorithm") or HASH_ALGORITHM
    if result["algorithm"] != HASH_ALGORITHM:
        result.update(status="invalid", message=f"unsupported hash algorithm {result['algorithm']!r}")
        return result

    modified: list[dict[str, str | None]] = []
    missing: list[str] = []
    listed: set[str] = set()
    for row in rows:
        relative = str(row["path"])
        listed.add(relative)
        path, _reason = confined_file(root, relative)
        if path is None or path.is_symlink():
            missing.append(relative)
            continue
        try:
            actual = file_sha256(path)
        except OSError:
            missing.append(relative)
            continue
        if actual != row["sha256"]:
            modified.append({"path": relative, "expected": row["sha256"], "actual": actual})
    unlisted = [
        relative
        for relative in _bundle_files(root)
        if relative not in listed and _excluded_reason(relative) is None
    ]
    result.update(
        {
            "status": "mismatch" if modified or missing else "verified",
            "checked_count": len(rows),
            "modified": modified[:_LIST_LIMIT],
            "missing": missing[:_LIST_LIMIT],
            "unlisted": unlisted[:_LIST_LIMIT],
            "modified_count": len(modified),
            "missing_count": len(missing),
            "unlisted_count": len(unlisted),
            "manifest_sha256": file_sha256(manifest_path),
        }
    )
    return result


def integrity_failed(integrity: Mapping[str, Any] | None) -> bool:
    """Whether a ``verify_bundle_hashes`` result says the bundle differs from what was finalized."""
    return isinstance(integrity, Mapping) and integrity.get("status") in {"mismatch", "invalid"}
