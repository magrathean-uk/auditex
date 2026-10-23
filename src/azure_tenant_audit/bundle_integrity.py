"""The bundle hash manifest: a SHA-256 for every artifact of a finalized run.

``finalize_bundle_contract`` writes ``bundle-hashes.json`` as its last step. Handoff, the explorer
and customer-pack creation recompute the hashes and compare them, so a bundle edited after it was
finalized is reported (and a customer pack is refused) instead of being passed on as it was.

The manifest lists every file under the run directory except itself and the append-only logs (they
grow after finalization by design). Files added later are reported as ``unlisted``. Three kinds of added
file fail the check, because consumers (handoff, the customer pack, the gates, the explorer) would read
them as if the run had produced them:

* a symbolic link anywhere in the run, which is neither hashed nor followed;
* an unlisted file at a path consumers read (the run root, ``normalized/``, ``findings/``,
  ``blockers/``, ``reports/``, ``ai_safe/``), unless it is a named post-finalization output such as the
  explorer page or a rendered report; and
* an unlisted SQLite sidecar (``-wal``, ``-shm``, ``-journal``) beside ``index/evidence.sqlite``. The
  evidence index is closed before it is hashed, so a sidecar that turns up later was not part of the
  hashed index and SQLite would replay it over the hashed file. Consumers open the index read-only and
  refuse to read it while a sidecar sits beside it (``azure_tenant_audit.evidence_db``).

Named post-finalization outputs stay unhashed on purpose: writing them into ``bundle-hashes.json`` would
change the digest of the manifest after it was handed over. The handoff lists them as a limitation instead.
"""
from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .evidence_refs import HASH_ALGORITHM, confined_file, file_sha256

BUNDLE_HASHES_PATH = "bundle-hashes.json"
BUNDLE_HASHES_SCHEMA_VERSION = "2026-10-22"
EVIDENCE_DB_PATH = "index/evidence.sqlite"

# Files that change after finalization by design. They are named in the manifest, not hashed.
_APPEND_ONLY_LOGS = frozenset({"audit-log.jsonl", "audit-command-log.jsonl", "audit-debug.log"})
_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
EVIDENCE_DB_SIDECARS = tuple(f"{EVIDENCE_DB_PATH}{suffix}" for suffix in _SIDECAR_SUFFIXES)
_IGNORED_NAMES = frozenset({".DS_Store"})
_LIST_LIMIT = 100

# Outputs the tooling writes into a finalized run on request. They are not evidence, and nothing reads them back.
_POST_FINALIZATION_OUTPUT = re.compile(
    r"^reports/(?:explorer\.html"
    r"|rendered-report\.(?:json|md|csv|html|sarif\.json|oscal\.json)"
    r"|(?:api-calls|permissions|proof-table|handoff)\.(?:json|md))$"
)
# Directories whose files consumers open by name. A file at the root counts too.
_CONSUMED_DIRECTORIES = ("normalized/", "findings/", "blockers/", "reports/", "ai_safe/")


def is_post_finalization_output(relative: str) -> bool:
    """Whether ``relative`` is a named output written into a run after it was finalized."""
    return bool(_POST_FINALIZATION_OUTPUT.match(relative))


def _read_by_consumers(relative: str) -> bool:
    return "/" not in relative or relative.startswith(_CONSUMED_DIRECTORIES)


def is_evidence_sidecar(relative: str) -> bool:
    """Whether ``relative`` is a SQLite sidecar of the evidence index."""
    return relative in EVIDENCE_DB_SIDECARS


def _excluded_reason(relative: str) -> str | None:
    # A sidecar is not excluded: the index is closed before it is hashed, so one present at that moment is
    # hashed like any file, and one that appears later is an unlisted file the check refuses.
    if relative == BUNDLE_HASHES_PATH:
        return "bundle_hash_manifest"
    if relative in _APPEND_ONLY_LOGS:
        return "append_only_log"
    if Path(relative).name in _IGNORED_NAMES:
        return "os_metadata"
    return None


def _json_object(path: Path) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, Mapping) else {}


def declared_contract_version(run_dir: str | Path) -> str | None:
    """The contract version ``run-manifest.json`` says the run was finalized under, or ``None``."""
    value = _json_object(Path(run_dir) / "run-manifest.json").get("schema_contract_version")
    return value if isinstance(value, str) and value else None


def listed_artifact_paths(run_dir: str | Path) -> set[str] | None:
    """The paths ``bundle-hashes.json`` lists, or ``None`` when there is no readable manifest."""
    rows = _json_object(Path(run_dir) / BUNDLE_HASHES_PATH).get("artifacts")
    if not isinstance(rows, list):
        return None
    return {str(row.get("path")) for row in rows if isinstance(row, Mapping) and isinstance(row.get("path"), str)}


def evidence_index_is_hashed(run_dir: str | Path) -> bool:
    """Whether ``bundle-hashes.json`` lists ``index/evidence.sqlite``, so no sidecar may stand beside it."""
    return EVIDENCE_DB_PATH in (listed_artifact_paths(run_dir) or ())


def evidence_sidecars(run_dir: str | Path) -> list[str]:
    """The SQLite sidecars that exist beside ``index/evidence.sqlite`` (checked by lstat, links included)."""
    root = Path(run_dir)
    found: list[str] = []
    for relative in EVIDENCE_DB_SIDECARS:
        try:
            (root / relative).lstat()
        except OSError:
            continue
        found.append(relative)
    return found


_DIGEST = re.compile(r"[0-9a-f]{64}")


def normalize_digest(value: Any) -> str:
    """A SHA-256 digest as 64 lower-case hex characters, or ``ValueError``."""
    text = str(value or "").strip().lower()
    if not _DIGEST.fullmatch(text):
        raise ValueError(f"{value!r} is not a SHA-256 digest (64 hexadecimal characters)")
    return text


def manifest_digest_problem(integrity: Mapping[str, Any], expected: Any) -> str | None:
    """Why ``integrity`` is not the manifest the caller was sent the digest of, or ``None`` when it is.

    ``expected`` is the SHA-256 of ``bundle-hashes.json`` received through a separate channel. A run whose
    manifest was deleted, or rewritten together with the artifacts, cannot match it. ``None`` for no digest.
    """
    if expected in (None, ""):
        return None
    wanted = normalize_digest(expected)
    actual = integrity.get("manifest_sha256")
    if not actual:
        return f"{BUNDLE_HASHES_PATH} is missing, so it cannot be the manifest with SHA-256 {wanted}"
    if str(actual) != wanted:
        return f"{BUNDLE_HASHES_PATH} has SHA-256 {actual}, not the expected {wanted}"
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


def _bundle_symlinks(run_dir: Path) -> list[str]:
    """Relative POSIX paths of every symbolic link below ``run_dir`` (to files or directories), found by lstat."""
    found: list[str] = []
    for current, directories, names in os.walk(str(run_dir), followlinks=False):
        directories.sort()
        for name in sorted([*directories, *names]):
            path = Path(current) / name
            if name in _IGNORED_NAMES or not path.is_symlink():
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

    ``status`` is ``verified`` (every listed file matches), ``mismatch`` (a listed file changed or is
    gone, a symbolic link sits in the run, an unlisted file sits at a path consumers read, or an unlisted
    SQLite sidecar sits beside the evidence index), ``invalid`` (the manifest cannot be read as a hash
    manifest, ``run-manifest.json`` lists it and it is gone, or the run was finalized under a contract that
    writes it and it is missing: ``manifest_missing`` is true and ``manifest_missing_reason`` says which) or
    ``absent`` (a bundle finalized before the manifest existed). Only ``mismatch`` and ``invalid`` say the
    bundle cannot be trusted as written; ``absent`` says it cannot be checked. ``symlinks`` names every
    link, ``unexpected`` the unlisted files that fail the check, and ``unlisted`` every file the manifest
    does not name (including named post-finalization outputs such as the explorer page).
    ``manifest_sha256`` is the digest of ``bundle-hashes.json`` whenever the file exists.
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
        "symlinks": [],
        "unexpected": [],
        "modified_count": 0,
        "missing_count": 0,
        "unlisted_count": 0,
        "symlink_count": 0,
        "unexpected_count": 0,
        "manifest_missing": False,
        "manifest_missing_reason": None,
    }
    symlinks = _bundle_symlinks(root)
    result["symlinks"] = symlinks[:_LIST_LIMIT]
    result["symlink_count"] = len(symlinks)
    if manifest_path.is_file():
        try:
            result["manifest_sha256"] = file_sha256(manifest_path)
        except OSError:
            pass
    else:
        if _run_manifest_lists_hashes(root):
            # Finalization registers the manifest in run-manifest.json before it writes it, so a
            # bundle that lists it and has none lost it after finalization: that is not "absent".
            result.update(
                status="invalid",
                manifest_missing=True,
                manifest_missing_reason="listed_in_run_manifest",
                message="run-manifest.json lists bundle-hashes.json but the file is missing.",
            )
            return result
        version = declared_contract_version(root)
        if version is not None and version >= BUNDLE_HASHES_SCHEMA_VERSION:
            # A bundle finalized under a contract that writes the manifest and has none lost it (or never had
            # it): it is missing, not "from before it existed". The version is read from the bundle itself,
            # so only a digest received separately settles a bundle that was rewritten to look older.
            result.update(
                status="invalid",
                manifest_missing=True,
                manifest_missing_reason="required_by_contract",
                message=(
                    f"bundle-hashes.json is missing: this run was finalized under contract {version}, "
                    "which writes it, so its artifacts cannot be checked."
                ),
            )
            return result
        result["message"] = "No bundle hash manifest; this bundle was finalized before one was written."
        if symlinks:
            # A link needs no manifest to be wrong: consumers would follow it out of the run.
            result.update(status="mismatch", message="The run contains symbolic links, which are never followed or trusted.")
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
    unexpected = [
        relative
        for relative in unlisted
        if is_evidence_sidecar(relative) or (_read_by_consumers(relative) and not is_post_finalization_output(relative))
    ]
    result.update(
        {
            "status": "mismatch" if modified or missing or symlinks or unexpected else "verified",
            "checked_count": len(rows),
            "modified": modified[:_LIST_LIMIT],
            "missing": missing[:_LIST_LIMIT],
            "unlisted": unlisted[:_LIST_LIMIT],
            "unexpected": unexpected[:_LIST_LIMIT],
            "modified_count": len(modified),
            "missing_count": len(missing),
            "unlisted_count": len(unlisted),
            "unexpected_count": len(unexpected),
        }
    )
    return result


def integrity_failed(integrity: Mapping[str, Any] | None) -> bool:
    """Whether a ``verify_bundle_hashes`` result says the bundle differs from what was finalized."""
    return isinstance(integrity, Mapping) and integrity.get("status") in {"mismatch", "invalid"}
