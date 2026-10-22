from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import tempfile
from collections import Counter
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path
from typing import Any

from .collection_gaps import list_truncations
from .evidence_refs import ARTIFACT_REASONS, EvidenceIndex
from .resources import list_resource_files, resolve_resource_path
from .tenant_identity import IDENTITY_FIELDS, decode_identity_metadata, reconcile_tenant_identity
from .waivers import has_matching_waiver, is_accepted_status

CONTRACT_VERSION = "2026-10-22"
# The contract version from which every evidence reference must resolve. It is fixed: a bundle finalized
# under 2026-10-22 must keep failing on an unresolved reference after later contract bumps, so the legacy
# cut-off is tied to the version a bundle was finalized under and never to the current CONTRACT_VERSION.
REFS_MUST_RESOLVE_SINCE = "2026-10-22"

ROOT_REQUIRED_ARTIFACTS = (
    "run-manifest.json",
    "summary.json",
    "reports/report-pack.json",
    "index/evidence.sqlite",
    "ai_context.json",
    "validation.json",
)

_REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "run-manifest.json": (
        "schema_version",
        "tenant_name",
        "run_id",
        "overall_status",
        "mode",
        "auditor_profile",
        "selected_collectors",
        "artifacts",
        "evidence_db_path",
        "ai_context_path",
        "validation_path",
    ),
    "summary.json": ("schema_version", "tenant_name", "run_id", "collectors"),
    "reports/report-pack.json": ("schema_version", "summary", "findings", "evidence_paths"),
    "ai_context.json": ("schema_version", "run", "privacy", "counts", "coverage", "findings", "artifacts", "read_order"),
}

_EVIDENCE_REF_REQUIRED = ("artifact_path", "artifact_kind", "collector", "record_key")
# A reference that does not resolve in a bundle finalized before references had to resolve.
LEGACY_UNRESOLVED_REF = "legacy_unresolved_ref"
_AI_SAFE_SENSITIVE_KEYS = re.compile(
    r"(access[_-]?token|refresh[_-]?token|client[_-]?secret|secret|password|credential|authorization|raw_claims)",
    re.IGNORECASE,
)
# Identifier patterns that contain a sensitive-key token but refer to legitimate
# non-secret Microsoft 365 resources (``authorization_policy`` /
# ``credential_method`` / etc.). Live audits of real tenants surfaced
# ``authorization_policy`` and friends as false positives on 2026-05-09; the
# allowlist neutralises them without weakening the underlying regex.
_AI_SAFE_KEY_ALLOWLIST = re.compile(
    r"^(authorization|credential)_"
    r"(?:policy|policies|context|contexts|method|methods|metric|metrics|"
    r"setting|settings|level|type|kind|state|status|class|admin|grant|grants|"
    r"provider|providers|flow|flows)$"
    r"|^(?:password|key|application|service_principal)_credentials$"
    r"|^app_credentials$"
    r"|^federated_credentials$"
    r"|^is_passwordless_capable$"
    r"|^(?:application|service_principal)_credential_objects$",
    re.IGNORECASE,
)
_AI_SAFE_SENSITIVE_VALUES = re.compile(r"(Bearer\s+[A-Za-z0-9._-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.)")
_SENSITIVE_CONTRACT_ARTIFACTS = (
    "run-manifest.json",
    "ai_context.json",
    "reports/report-pack.json",
    "normalized/auth_context.json",
)
_OPTIONAL_MANIFEST_ARTIFACT_FIELDS = (
    "data_handling_path",
    "live_readiness_path",
    "audit_plan_path",
    "api_inventory_path",
)
# Canonical framework keys used by exporters / control-mappings. C3 fails the
# bundle if a finding's framework_mappings drifts from this set, since SARIF/
# OSCAL exporters depend on knowing the framework taxonomy at bundle-build
# time.
#
# ``cis_m365_v3`` is a deprecated legacy key: still accepted so older bundles
# and operator overrides validate, but shipped mappings emit ``cis_m365_v7``.
# configs/framework-catalog.json must list the same keys (tested).
_KNOWN_FRAMEWORK_KEYS = frozenset(
    {
        "cis_m365_v7",
        "cis_m365_v3",
        "cisa_scuba",
        "ms_secure_score",
        "ms_zero_trust",
        "mcsb",
        "cyber_essentials",
        "google_workspace_baseline",
        "nist_800_53",
        "iso_27001",
        "soc2",
        "nis2",
        "dora",
        "mitre_attack",
    }
)
# Provenance markers that are NOT in the audit collector REGISTRY but are
# still legitimate ``collector`` values on findings — they identify
# non-audit planes (response actions, etc.) that produce findings via a
# different runtime path. Keep this list short and explicit.
_KNOWN_NON_COLLECTOR_PROVENANCE = frozenset({"response", "toolchain", "windows365"})


def _read_json(path: Path, fallback: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return fallback


def _issue(code: str, *, path: str | None = None, details: Any = None, severity: str = "error") -> dict[str, Any]:
    payload: dict[str, Any] = {"code": code, "severity": severity}
    if path is not None:
        payload["path"] = path
    if details is not None:
        payload["details"] = details
    return payload


def _validate_required_json_fields(run_dir: Path, issues: list[dict[str, Any]]) -> None:
    for relative, required_fields in _REQUIRED_FIELDS.items():
        path = run_dir / relative
        payload = _read_json(path, fallback=None)
        if not isinstance(payload, Mapping):
            issues.append(_issue("invalid_json_artifact", path=relative))
            continue
        missing = [field for field in required_fields if field not in payload]
        if missing:
            issues.append(_issue("missing_json_required_fields", path=relative, details=missing))


def _load_findings(run_dir: Path, supplied: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if supplied is not None:
        return [dict(item) for item in supplied if isinstance(item, Mapping)]
    payload = _read_json(run_dir / "findings" / "findings.json", fallback=[])
    return [dict(item) for item in payload if isinstance(item, Mapping)] if isinstance(payload, list) else []


# Finding statuses the engine writes: ``open``, and ``accepted_risk`` (with the waiver that matched) only.
# ``accepted`` and ``waived`` are read as accepted spellings; anything else is not a status the engine produces.
_ENGINE_FINDING_STATUSES = frozenset({"open"})


def _validate_finding_statuses(findings: list[dict[str, Any]], issues: list[dict[str, Any]]) -> None:
    """A finding is accepted only by a matching waiver, and only known statuses are read as such.

    An accepted status with no matching waiver (the engine always attaches the waiver it matched) is an
    error: it is the one edit that turns a failing gate into a pass. A status the engine never writes
    (``closed``, ``resolved``, anything else) is a warning; the gates count such a finding as open unless a
    matching waiver stands behind it.
    """
    unwaived: list[str] = []
    unknown: dict[str, list[str]] = {}
    for position, finding in enumerate(findings):
        finding_id = str(finding.get("id") or f"finding:{position}")
        status = str(finding.get("status") or "open").strip().lower()
        if is_accepted_status(status):
            if not has_matching_waiver(finding):
                unwaived.append(finding_id)
        elif status not in _ENGINE_FINDING_STATUSES:
            unknown.setdefault(status, []).append(finding_id)
    if unwaived:
        issues.append(_issue("unwaived_accepted_status", path="findings/findings.json", details=sorted(unwaived)[:20]))
    for status, ids in sorted(unknown.items()):
        issues.append(
            _issue(
                "unknown_finding_status",
                path="findings/findings.json",
                details={"status": status, "findings": sorted(ids)[:20]},
                severity="warning",
            )
        )


def _is_legacy_bundle(manifest: Any) -> bool:
    """Whether the run was finalized under a contract older than ``REFS_MUST_RESOLVE_SINCE``.

    Such a bundle was written before references were required to resolve, so a citation that does
    not resolve in it is the old builders' pattern (for example a raw payload cited for a fan-out
    that has no row there), not a sign that the bundle was edited. The edit is what the hash
    manifest and ``evidence_ref_hash_mismatch`` report. The cut-off is a fixed version, not the
    current ``CONTRACT_VERSION``, so a later contract bump never relabels an edited citation.
    """
    if not isinstance(manifest, Mapping) or not manifest:
        return False
    version = manifest.get("schema_contract_version")
    return not isinstance(version, str) or version < REFS_MUST_RESOLVE_SINCE


def _unresolved_code(reason: str | None, *, legacy: bool, proof_table: bool = False) -> str:
    """The issue code for a reference that does not resolve."""
    if reason in ARTIFACT_REASONS:
        return "broken_report_proof_table_ref" if proof_table else "broken_evidence_ref"
    if legacy:
        return LEGACY_UNRESOLVED_REF
    return "unresolved_report_proof_table_ref" if proof_table else "unresolved_evidence_ref"


def _validate_evidence_refs(
    run_dir: Path,
    findings: list[dict[str, Any]],
    issues: list[dict[str, Any]],
    index: EvidenceIndex,
    *,
    legacy: bool = False,
) -> None:
    """Every finding cites evidence, and every citation resolves inside the run directory.

    A reference resolves when its artifact is a file inside ``run_dir`` and its ``json_pointer`` (or,
    without one, its ``record_key``) exists in that artifact. ``content_hash``, when the reference
    carries one, must still match the artifact bytes.
    """
    ids = [str(item.get("id")) for item in findings if item.get("id")]
    duplicate_ids = sorted(key for key, count in Counter(ids).items() if count > 1)
    if duplicate_ids:
        issues.append(_issue("duplicate_finding_ids", path="findings/findings.json", details=duplicate_ids))

    to_resolve: list[tuple[str, int, Mapping[str, Any]]] = []
    for position, finding in enumerate(findings):
        finding_id = str(finding.get("id") or f"finding:{position}")
        refs = finding.get("evidence_refs")
        if not isinstance(refs, list) or not refs:
            issues.append(_issue("missing_evidence_refs", path="findings/findings.json", details=finding_id))
            continue
        for ref_index, ref in enumerate(refs):
            if not isinstance(ref, Mapping):
                issues.append(
                    _issue(
                        "invalid_evidence_ref",
                        path="findings/findings.json",
                        details={"finding_id": finding_id, "ref_index": ref_index},
                    )
                )
                continue
            missing = [field for field in _EVIDENCE_REF_REQUIRED if not str(ref.get(field) or "").strip()]
            if missing:
                issues.append(
                    _issue(
                        "invalid_evidence_ref",
                        path="findings/findings.json",
                        details={"finding_id": finding_id, "ref_index": ref_index, "missing": missing},
                    )
                )
            if str(ref.get("artifact_path") or ""):
                to_resolve.append((finding_id, ref_index, ref))

    index.prime(ref for _finding, _position, ref in to_resolve)
    for finding_id, ref_index, ref in to_resolve:
        result = index.resolve(ref)
        artifact_path = str(ref.get("artifact_path") or "")
        if not result.resolved:
            code = _unresolved_code(result.reason, legacy=legacy)
            details: dict[str, Any] = {
                "finding_id": finding_id,
                "ref_index": ref_index,
                "artifact_path": artifact_path,
                "reason": result.reason,
            }
            for field in ("record_key", "json_pointer", "jsonl_line"):
                if ref.get(field) not in (None, ""):
                    details[field] = ref.get(field)
            issues.append(_issue(code, path="findings/findings.json", details=details))
            continue
        recorded = str(ref.get("content_hash") or "").strip()
        if recorded and result.content_hash and recorded.lower() != result.content_hash:
            issues.append(
                _issue(
                    "evidence_ref_hash_mismatch",
                    path="findings/findings.json",
                    details={
                        "finding_id": finding_id,
                        "ref_index": ref_index,
                        "artifact_path": artifact_path,
                        "expected": recorded,
                        "actual": result.content_hash,
                    },
                )
            )


def _record_key_for_check(record: Mapping[str, Any], section_name: str, index: int) -> str:
    """Mirror of evidence_db._record_key for validation purposes — must stay in
    sync so the contract layer flags the same collisions the evidence DB will hit.
    """
    for key in ("key", "id", "display_name", "name", "collector", "surface"):
        value = record.get(key)
        if value is not None and str(value).strip():
            return f"{section_name}:{value}" if key != "key" else str(value)
    return f"{section_name}:{index}"


def _validate_record_key_uniqueness(run_dir: Path, issues: list[dict[str, Any]]) -> None:
    normalized_dir = run_dir / "normalized"
    if not normalized_dir.exists():
        return
    for path in sorted(normalized_dir.glob("*.json")):
        payload = _read_json(path, fallback={})
        if not isinstance(payload, Mapping):
            continue
        records = payload.get("records")
        if not isinstance(records, list) or not records:
            continue
        section_name = str(payload.get("kind") or path.stem)
        seen: dict[str, int] = {}
        duplicates: list[dict[str, Any]] = []
        for index, record in enumerate(records):
            if not isinstance(record, Mapping):
                continue
            key = _record_key_for_check(record, section_name, index)
            previous = seen.get(key)
            if previous is None:
                seen[key] = index
                continue
            duplicates.append({"record_key": key, "first": previous, "second": index})
        if duplicates:
            issues.append(
                _issue(
                    "duplicate_record_key",
                    path=str(path.relative_to(run_dir)),
                    details=duplicates[:25],
                )
            )


def _validate_finding_collectors(
    findings: list[dict[str, Any]], issues: list[dict[str, Any]]
) -> None:
    """Every finding's ``collector`` field must reference a known collector
    from the registry; otherwise SARIF / OSCAL exporters and notify sinks
    cannot resolve provenance."""
    try:  # lazy import: contracts.py is imported earlier in the boot order
        from .collectors import REGISTRY as _REGISTRY
    except Exception:  # noqa: BLE001 — never let import failure crash validation
        return
    known = set(_REGISTRY.keys()) | set(_KNOWN_NON_COLLECTOR_PROVENANCE)
    try:
        from auditex.google_workspace.collectors import REGISTRY as _GOOGLE_REGISTRY

        known.update(_GOOGLE_REGISTRY.keys())
    except Exception:  # noqa: BLE001
        pass
    for finding in findings:
        collector = finding.get("collector")
        if not isinstance(collector, str) or not collector.strip():
            # Already covered by other validators; don't double-flag here.
            continue
        if collector not in known:
            issues.append(
                _issue(
                    "unknown_finding_collector",
                    path="findings/findings.json",
                    details={
                        "finding_id": str(finding.get("id") or ""),
                        "collector": collector,
                    },
                )
            )


def _validate_finding_framework_mappings(
    findings: list[dict[str, Any]], issues: list[dict[str, Any]]
) -> None:
    """Each finding's ``framework_mappings`` must use canonical framework keys
    and non-empty list-of-strings values. Drift breaks SARIF/OSCAL exporters
    that depend on the framework taxonomy."""
    for finding in findings:
        mappings = finding.get("framework_mappings")
        if mappings is None:
            continue
        finding_id = str(finding.get("id") or "")
        if not isinstance(mappings, Mapping):
            issues.append(
                _issue(
                    "invalid_framework_mapping_value",
                    path="findings/findings.json",
                    details={"finding_id": finding_id, "reason": "framework_mappings is not an object"},
                )
            )
            continue
        for framework, controls in mappings.items():
            if framework not in _KNOWN_FRAMEWORK_KEYS:
                issues.append(
                    _issue(
                        "unknown_framework_mapping_key",
                        path="findings/findings.json",
                        details={
                            "finding_id": finding_id,
                            "framework": framework,
                            "known": sorted(_KNOWN_FRAMEWORK_KEYS),
                        },
                    )
                )
                continue
            if not isinstance(controls, list) or not controls:
                issues.append(
                    _issue(
                        "invalid_framework_mapping_value",
                        path="findings/findings.json",
                        details={
                            "finding_id": finding_id,
                            "framework": framework,
                            "reason": "value is not a non-empty list",
                        },
                    )
                )
                continue
            empty = [
                index
                for index, control in enumerate(controls)
                if not isinstance(control, str) or not control.strip()
            ]
            if empty:
                issues.append(
                    _issue(
                        "invalid_framework_mapping_value",
                        path="findings/findings.json",
                        details={
                            "finding_id": finding_id,
                            "framework": framework,
                            "empty_or_non_string_indexes": empty[:25],
                        },
                    )
                )


def _validate_normalized_records(run_dir: Path, issues: list[dict[str, Any]]) -> None:
    normalized_dir = run_dir / "normalized"
    if not normalized_dir.exists():
        issues.append(_issue("missing_artifact_directory", path="normalized"))
        return
    for path in sorted(normalized_dir.glob("*.json")):
        payload = _read_json(path, fallback={})
        if not isinstance(payload, Mapping):
            issues.append(_issue("invalid_json_artifact", path=str(path.relative_to(run_dir))))
            continue
        records = payload.get("records")
        if records is None:
            continue
        if not isinstance(records, list):
            issues.append(_issue("invalid_records_shape", path=str(path.relative_to(run_dir))))
            continue
        bad: list[int] = []
        for index, record in enumerate(records):
            if not isinstance(record, Mapping):
                bad.append(index)
                continue
            key = (
                record.get("key")
                or record.get("id")
                or record.get("name")
                or record.get("display_name")
                or record.get("collector")
                or record.get("surface")
            )
            if key is None or not str(key).strip():
                bad.append(index)
        if bad:
            issues.append(_issue("bad_record_keys", path=str(path.relative_to(run_dir)), details=bad[:25]))


def _walk_sensitive_ai_safe(value: Any, path: str, hits: list[dict[str, Any]]) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            current = f"{path}/{key_text}" if path else key_text
            if _AI_SAFE_SENSITIVE_KEYS.search(key_text) and not _AI_SAFE_KEY_ALLOWLIST.match(key_text):
                hits.append({"path": current, "reason": "sensitive_key"})
            _walk_sensitive_ai_safe(item, current, hits)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk_sensitive_ai_safe(item, f"{path}[{index}]", hits)
    elif isinstance(value, str) and _AI_SAFE_SENSITIVE_VALUES.search(value):
        hits.append({"path": path, "reason": "sensitive_value"})


def _validate_ai_safe(run_dir: Path, issues: list[dict[str, Any]]) -> None:
    ai_safe_dir = run_dir / "ai_safe"
    if not ai_safe_dir.exists():
        return
    for path in sorted(ai_safe_dir.glob("*.json")):
        payload = _read_json(path, fallback={})
        hits: list[dict[str, Any]] = []
        _walk_sensitive_ai_safe(payload, "", hits)
        if hits:
            issues.append(_issue("unsafe_ai_safe_artifact", path=str(path.relative_to(run_dir)), details=hits[:25]))


def _validate_sensitive_contract_artifacts(run_dir: Path, issues: list[dict[str, Any]]) -> None:
    for relative in _SENSITIVE_CONTRACT_ARTIFACTS:
        path = run_dir / relative
        if not path.exists():
            continue
        payload = _read_json(path, fallback={})
        hits: list[dict[str, Any]] = []
        _walk_sensitive_ai_safe(payload, "", hits)
        if hits:
            issues.append(_issue("unsafe_contract_artifact", path=relative, details=hits[:25]))


def _validate_evidence_db(run_dir: Path, issues: list[dict[str, Any]], *, read_only: bool = False) -> dict[str, Any]:
    db_path = run_dir / "index" / "evidence.sqlite"
    if not db_path.exists():
        issues.append(_issue("missing_required_artifact", path="index/evidence.sqlite"))
        return {}

    metadata: dict[str, Any] = {}

    def inspect(path: Path) -> None:
        nonlocal metadata
        # Connection context managers do not close SQLite connections. Close
        # explicitly before cleaning up the temporary database and sidecars.
        with closing(sqlite3.connect(path)) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            required = {"run_meta", "section_stats", "normalized_records"}
            missing = sorted(required - tables)
            if missing:
                issues.append(_issue("invalid_evidence_sqlite_schema", path="index/evidence.sqlite", details=missing))
            if "run_meta" in tables:
                metadata = decode_identity_metadata(dict(conn.execute("SELECT key, value FROM run_meta")))

    try:
        if read_only:
            # Even SELECT against a WAL database can modify its shared-memory
            # sidecar. Inspect only a private copy, including committed data
            # still in the WAL, without opening the original through SQLite.
            with tempfile.TemporaryDirectory(prefix="auditex-validation-", dir=os.environ.get("TMPDIR")) as temporary:
                copied_path = Path(temporary) / db_path.name
                for suffix in ("", "-wal", "-shm"):
                    source = db_path.with_name(db_path.name + suffix)
                    if source.exists():
                        shutil.copy2(source, copied_path.with_name(copied_path.name + suffix))
                inspect(copied_path)
        else:
            inspect(db_path)
    except (sqlite3.DatabaseError, OSError) as exc:
        issues.append(_issue("invalid_evidence_sqlite", path="index/evidence.sqlite", details=str(exc)))
    return metadata


def _validate_tenant_identity(
    run_dir: Path,
    manifest: Mapping[str, Any],
    ai_context: Any,
    indexed: Mapping[str, Any],
    issues: list[dict[str, Any]],
) -> None:
    summary = _read_json(run_dir / "summary.json", {})
    report = _read_json(run_dir / "reports/report-pack.json", {})
    report_summary = report.get("summary") if isinstance(report, Mapping) else {}
    ai_run = ai_context.get("run") if isinstance(ai_context, Mapping) else {}
    surfaces = {
        "run-manifest.json": manifest,
        "summary.json": summary if isinstance(summary, Mapping) else {},
        "reports/report-pack.json#/summary": report_summary if isinstance(report_summary, Mapping) else {},
        "ai_context.json#/run": ai_run if isinstance(ai_run, Mapping) else {},
        "index/evidence.sqlite#run_meta": indexed,
    }
    if isinstance(report, Mapping) and any(key in report for key in IDENTITY_FIELDS):
        surfaces["reports/report-pack.json"] = report
    resolved = reconcile_tenant_identity(run_dir, surfaces, platform=str(manifest.get("platform") or "m365"))
    if resolved["tenant_identity"]["status"] == "conflict":
        issues.append(_issue("tenant_identity_conflict", path="run-manifest.json", details=resolved["tenant_identity"]["conflicts"]))


def _validate_manifest_artifact_paths(run_dir: Path, issues: list[dict[str, Any]]) -> dict[str, Any]:
    manifest = _read_json(run_dir / "run-manifest.json", fallback={})
    if not isinstance(manifest, Mapping):
        return {}
    for field in _OPTIONAL_MANIFEST_ARTIFACT_FIELDS:
        value = manifest.get(field)
        if not value:
            continue
        relative = str(value)
        if not (run_dir / relative).exists():
            issues.append(_issue("missing_manifest_artifact", path=relative, details=field))
    return dict(manifest)


def _validate_collection_gaps(run_dir: Path, manifest: Mapping[str, Any], issues: list[dict[str, Any]]) -> None:
    """A list cut short is a coverage gap: the run is not ``ok`` and the manifest names the list."""
    coverage_path = manifest.get("coverage_path")
    if not coverage_path:
        return
    coverage = _read_json(run_dir / str(coverage_path), fallback=[])
    # Only rows that name a reason were written by a version that records gaps; bundles from before
    # flagged a cut on an ``ok`` row with no reason and stay valid.
    truncations = list_truncations(coverage if isinstance(coverage, list) else [], require_reason=True)
    if not truncations:
        return
    if manifest.get("overall_status") == "ok":
        issues.append(_issue("truncated_list_reported_ok", path="run-manifest.json", details=truncations[:25]))
    recorded = {
        (str(item.get("collector")), str(item.get("list")))
        for gap in manifest.get("coverage_gaps") or []
        if isinstance(gap, Mapping)
        for item in gap.get("truncated_lists") or []
        if isinstance(item, Mapping)
    }
    missing = [item for item in truncations if (item["collector"], item["list"]) not in recorded]
    if missing:
        issues.append(_issue("collection_gap_not_recorded", path="run-manifest.json", details=missing[:25]))


def _validate_data_handling(run_dir: Path, manifest: Mapping[str, Any], issues: list[dict[str, Any]]) -> None:
    relative = manifest.get("data_handling_path")
    if not relative:
        return
    path = run_dir / str(relative)
    payload = _read_json(path, fallback=None)
    if not isinstance(payload, Mapping):
        issues.append(_issue("invalid_json_artifact", path=str(relative)))
        return
    required = ("schema_version", "platform", "read_only", "content_reads", "write_actions", "provider_assertions")
    missing = [key for key in required if key not in payload]
    if missing:
        issues.append(_issue("missing_json_required_fields", path=str(relative), details=missing))
        return
    if payload.get("read_only") is True and payload.get("write_actions") is True:
        issues.append(_issue("invalid_data_handling_semantics", path=str(relative), details="read_only_with_write_actions"))
    if payload.get("content_reads") is True:
        issues.append(_issue("invalid_data_handling_semantics", path=str(relative), details="content_reads_enabled"))
    assertions = payload.get("provider_assertions")
    if not isinstance(assertions, Mapping):
        issues.append(_issue("missing_json_required_fields", path=str(relative), details=["provider_assertions"]))
        return
    platform = str(payload.get("platform") or manifest.get("platform") or "m365")
    if platform == "google_workspace":
        forbidden = [
            key
            for key in ("gmail_body_reads", "drive_file_content_reads", "body_or_file_content_reads")
            if assertions.get(key) is True
        ]
        if forbidden:
            issues.append(_issue("invalid_data_handling_no_content_assertion", path=str(relative), details=forbidden))
    elif assertions.get("body_or_file_content_reads") is True:
        issues.append(
            _issue("invalid_data_handling_no_content_assertion", path=str(relative), details=["body_or_file_content_reads"])
        )


def _validate_live_readiness(run_dir: Path, manifest: Mapping[str, Any], issues: list[dict[str, Any]]) -> None:
    relative = manifest.get("live_readiness_path")
    if not relative:
        return
    path = run_dir / str(relative)
    payload = _read_json(path, fallback=None)
    if not isinstance(payload, Mapping):
        issues.append(_issue("invalid_json_artifact", path=str(relative)))
        return
    missing = [key for key in ("trust_level", "selected_collectors", "can_trust", "cannot_trust") if key not in payload]
    if missing:
        issues.append(_issue("missing_json_required_fields", path=str(relative), details=missing))


def _validate_audit_plan(run_dir: Path, manifest: Mapping[str, Any], issues: list[dict[str, Any]]) -> None:
    relative = manifest.get("audit_plan_path")
    if not relative:
        return
    path = run_dir / str(relative)
    payload = _read_json(path, fallback=None)
    if not isinstance(payload, Mapping):
        issues.append(_issue("invalid_json_artifact", path=str(relative)))
        return
    missing = [key for key in ("schema_version", "platform", "evidence_gates", "quality_gate") if key not in payload]
    if missing:
        issues.append(_issue("missing_json_required_fields", path=str(relative), details=missing))
    gate = payload.get("quality_gate")
    if not isinstance(gate, Mapping) or gate.get("status") not in {"complete", "partial", "unusable"}:
        issues.append(_issue("invalid_audit_plan_quality_gate", path=str(relative)))


def _validate_api_inventory(run_dir: Path, manifest: Mapping[str, Any], issues: list[dict[str, Any]]) -> None:
    relative = manifest.get("api_inventory_path")
    if not relative:
        return
    path = run_dir / str(relative)
    payload = _read_json(path, fallback=None)
    if not isinstance(payload, Mapping):
        issues.append(_issue("invalid_json_artifact", path=str(relative)))
        return
    missing = [key for key in ("schema_version", "platform", "declared_collectors", "observed_calls", "safety") if key not in payload]
    if missing:
        issues.append(_issue("missing_json_required_fields", path=str(relative), details=missing))
        return
    if not isinstance(payload.get("declared_collectors"), list) or not isinstance(payload.get("observed_calls"), list):
        issues.append(_issue("invalid_api_inventory_shape", path=str(relative)))
    safety = payload.get("safety")
    if not isinstance(safety, Mapping):
        issues.append(_issue("missing_json_required_fields", path=str(relative), details=["safety"]))
        return
    if safety.get("content_reads") is True or safety.get("no_content_reads") is False:
        issues.append(_issue("invalid_api_inventory_safety", path=str(relative), details="content_reads_enabled"))
    if str(manifest.get("plane") or "inventory") != "response" and (
        safety.get("write_actions") is True or safety.get("read_only") is False
    ):
        issues.append(_issue("invalid_api_inventory_safety", path=str(relative), details="write_actions_in_audit_plane"))
    for index, call in enumerate(payload.get("observed_calls") or []):
        if not isinstance(call, Mapping):
            issues.append(_issue("invalid_api_inventory_shape", path=str(relative), details={"observed_call_index": index}))
            continue
        method = str(call.get("method") or "").upper()
        if str(manifest.get("plane") or "inventory") != "response" and method in {"POST", "PUT", "PATCH", "DELETE"}:
            issues.append(
                _issue(
                    "invalid_api_inventory_safety",
                    path=str(relative),
                    details={"observed_call_index": index, "method": method},
                )
            )


def _proof_row_ref(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        field: row.get(field)
        for field in ("artifact_path", "record_key", "json_pointer", "jsonl_line")
        if row.get(field) not in (None, "")
    }


def _proof_rows(payload: Any) -> list[Any]:
    rows = payload.get("proof_table") if isinstance(payload, Mapping) else None
    return rows if isinstance(rows, list) else []


def _report_pack_refs(payload: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    """References the report pack carries outside the findings: attack-path hops and report sections."""
    refs: list[tuple[str, Mapping[str, Any]]] = []
    if not isinstance(payload, Mapping):
        return refs
    attack_paths = payload.get("attack_paths")
    for path_index, path in enumerate(attack_paths if isinstance(attack_paths, list) else []):
        if not isinstance(path, Mapping):
            continue
        hops = path.get("hops")
        for hop_index, hop in enumerate(hops if isinstance(hops, list) else []):
            ref = hop.get("evidence_ref") if isinstance(hop, Mapping) else None
            if isinstance(ref, Mapping):
                refs.append((f"attack_paths[{path_index}].hops[{hop_index}]", ref))
    for section, rows_key in (("detection_coverage", "signals"), ("public_footprint", "domains")):
        block = payload.get(section)
        rows = block.get(rows_key) if isinstance(block, Mapping) else None
        for row_index, row in enumerate(rows if isinstance(rows, list) else []):
            ref = row.get("evidence_ref") if isinstance(row, Mapping) else None
            if isinstance(ref, Mapping):
                refs.append((f"{section}.{rows_key}[{row_index}]", ref))
    return [(where, ref) for where, ref in refs if str(ref.get("artifact_path") or "").strip()]


def _validate_report_pack(
    run_dir: Path, issues: list[dict[str, Any]], index: EvidenceIndex, payload: Any, *, legacy: bool = False
) -> None:
    relative = "reports/report-pack.json"
    if not isinstance(payload, Mapping):
        return
    for where, ref in _report_pack_refs(payload):
        result = index.resolve(ref)
        if not result.resolved:
            issues.append(
                _issue(
                    LEGACY_UNRESOLVED_REF
                    if legacy and result.reason not in ARTIFACT_REASONS
                    else "unresolved_report_evidence_ref",
                    path=relative,
                    details={
                        "location": where,
                        "artifact_path": str(ref.get("artifact_path") or ""),
                        "record_key": ref.get("record_key"),
                        "json_pointer": ref.get("json_pointer"),
                        "reason": result.reason,
                    },
                )
            )
    proof_table = payload.get("proof_table")
    if proof_table is None:
        return
    if not isinstance(proof_table, list):
        issues.append(_issue("invalid_report_proof_table", path=relative, details="proof_table_not_list"))
        return

    findings = [dict(item) for item in payload.get("findings") or [] if isinstance(item, Mapping)]
    finding_ids = {str(item.get("id")) for item in findings if item.get("id")}
    covered_ids: set[str] = set()
    for row_index, row in enumerate(proof_table):
        if not isinstance(row, Mapping):
            issues.append(_issue("invalid_report_proof_table", path=relative, details={"row_index": row_index}))
            continue
        if "proof_status" not in row and "evidence_count" in row and (row.get("finding_id") or row.get("id")):
            covered_ids.add(str(row.get("finding_id") or row.get("id")))
            continue
        finding_id = str(row.get("finding_id") or row.get("id") or "").strip()
        proof_status = str(row.get("proof_status") or "").strip()
        missing = []
        if not finding_id:
            missing.append("finding_id")
        if not proof_status:
            missing.append("proof_status")
        if proof_status == "supported":
            missing.extend(
                field
                for field in ("artifact_path", "artifact_kind", "collector", "record_key")
                if not str(row.get(field) or "").strip()
            )
            artifact_path = str(row.get("artifact_path") or "")
            if artifact_path:
                result = index.resolve(_proof_row_ref(row))
                if not result.resolved:
                    code = _unresolved_code(result.reason, legacy=legacy, proof_table=True)
                    issues.append(
                        _issue(
                            code,
                            path=relative,
                            details={
                                "row_index": row_index,
                                "finding_id": finding_id,
                                "artifact_path": artifact_path,
                                "record_key": row.get("record_key"),
                                "reason": result.reason,
                            },
                        )
                    )
        elif proof_status not in {"missing_evidence", "unsupported"}:
            missing.append("proof_status:supported|missing_evidence|unsupported")
        recorded_hash = str(row.get("content_hash") or "").strip()
        if recorded_hash and str(row.get("artifact_path") or ""):
            actual_hash = index.resolve(_proof_row_ref(row)).content_hash
            if actual_hash and recorded_hash.lower() != actual_hash:
                issues.append(
                    _issue(
                        "evidence_ref_hash_mismatch",
                        path=relative,
                        details={
                            "row_index": row_index,
                            "finding_id": finding_id,
                            "artifact_path": str(row.get("artifact_path")),
                            "expected": recorded_hash,
                            "actual": actual_hash,
                        },
                    )
                )
        if missing:
            issues.append(
                _issue(
                    "invalid_report_proof_table",
                    path=relative,
                    details={"row_index": row_index, "finding_id": finding_id, "missing": missing},
                )
            )
        if finding_id:
            covered_ids.add(finding_id)

    missing_finding_rows = sorted(finding_ids - covered_ids)
    if missing_finding_rows:
        issues.append(
            _issue(
                "missing_report_proof_table_rows",
                path=relative,
                details=missing_finding_rows,
                severity="warning",
            )
        )


def build_validation_report(
    *,
    run_dir: str | Path,
    ai_context: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
    required_artifacts: tuple[str, ...] = ROOT_REQUIRED_ARTIFACTS,
    read_only: bool = False,
) -> dict[str, Any]:
    run_path = Path(run_dir)
    issues: list[dict[str, Any]] = []

    for relative in required_artifacts:
        if not (run_path / relative).exists():
            # validation.json is allowed to be absent while the report itself is being built.
            if relative == "validation.json":
                continue
            issues.append(_issue("missing_required_artifact", path=relative))

    _validate_required_json_fields(run_path, issues)
    loaded_findings = _load_findings(run_path, findings)
    # Each cited artifact is read once for the findings, the proof table and the report sections.
    report_pack = _read_json(run_path / "reports" / "report-pack.json", fallback=None)
    legacy = _is_legacy_bundle(_read_json(run_path / "run-manifest.json", fallback=None))
    evidence_index = EvidenceIndex(run_path)
    evidence_index.prime(
        [
            *(
                ref
                for item in loaded_findings
                for ref in (item["evidence_refs"] if isinstance(item.get("evidence_refs"), list) else [])
            ),
            *(
                _proof_row_ref(row)
                for row in _proof_rows(report_pack)
                if isinstance(row, Mapping)
                and row.get("artifact_path")
                and (row.get("proof_status") == "supported" or row.get("content_hash"))
            ),
            *(ref for _where, ref in _report_pack_refs(report_pack)),
        ]
    )
    _validate_evidence_refs(run_path, loaded_findings, issues, evidence_index, legacy=legacy)
    _validate_normalized_records(run_path, issues)
    _validate_record_key_uniqueness(run_path, issues)
    _validate_finding_collectors(loaded_findings, issues)
    _validate_finding_statuses(loaded_findings, issues)
    _validate_finding_framework_mappings(loaded_findings, issues)
    _validate_ai_safe(run_path, issues)
    _validate_sensitive_contract_artifacts(run_path, issues)
    indexed_identity = _validate_evidence_db(run_path, issues, read_only=read_only)
    manifest = _validate_manifest_artifact_paths(run_path, issues)
    _validate_collection_gaps(run_path, manifest, issues)
    _validate_data_handling(run_path, manifest, issues)
    _validate_live_readiness(run_path, manifest, issues)
    _validate_audit_plan(run_path, manifest, issues)
    _validate_api_inventory(run_path, manifest, issues)
    _validate_report_pack(run_path, issues, evidence_index, report_pack, legacy=legacy)

    context = ai_context if isinstance(ai_context, Mapping) else _read_json(run_path / "ai_context.json", fallback={})
    _validate_tenant_identity(run_path, manifest, context, indexed_identity, issues)
    if not isinstance(context, Mapping):
        issues.append(_issue("invalid_json_artifact", path="ai_context.json"))
    else:
        counts = context.get("counts")
        if not isinstance(counts, Mapping) or not isinstance(counts.get("normalized_counts"), Mapping):
            issues.append(_issue("missing_normalized_counts", path="ai_context.json"))

    errors = [item for item in issues if item.get("severity") == "error"]
    return {
        "schema_version": CONTRACT_VERSION,
        "contract_version": CONTRACT_VERSION,
        "valid": not errors,
        "issue_count": len(issues),
        "error_count": len(errors),
        "warning_count": len(issues) - len(errors),
        "required_artifacts": list(required_artifacts),
        "issues": issues,
    }


def contract_schema_manifest(schema_dir: str | Path = "schemas") -> dict[str, Any]:
    root = resolve_resource_path(schema_dir)
    schemas = [path.name for path in list_resource_files(schema_dir, "*.schema.json")]
    return {"contract_version": CONTRACT_VERSION, "schema_dir": str(root), "schemas": schemas}
