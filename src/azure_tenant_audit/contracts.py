from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .resources import list_resource_files, resolve_resource_path

CONTRACT_VERSION = "2026-04-21"

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
    r"provider|providers|flow|flows)$",
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
_KNOWN_FRAMEWORK_KEYS = frozenset(
    {
        "cis_m365_v3",
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


def _validate_evidence_refs(run_dir: Path, findings: list[dict[str, Any]], issues: list[dict[str, Any]]) -> None:
    ids = [str(item.get("id")) for item in findings if item.get("id")]
    duplicate_ids = sorted(key for key, count in Counter(ids).items() if count > 1)
    if duplicate_ids:
        issues.append(_issue("duplicate_finding_ids", path="findings/findings.json", details=duplicate_ids))

    for index, finding in enumerate(findings):
        finding_id = str(finding.get("id") or f"finding:{index}")
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
            artifact_path = str(ref.get("artifact_path") or "")
            if artifact_path and not (run_dir / artifact_path).exists():
                issues.append(
                    _issue(
                        "broken_evidence_ref",
                        path="findings/findings.json",
                        details={"finding_id": finding_id, "artifact_path": artifact_path},
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


def _validate_evidence_db(run_dir: Path, issues: list[dict[str, Any]]) -> None:
    db_path = run_dir / "index" / "evidence.sqlite"
    if not db_path.exists():
        issues.append(_issue("missing_required_artifact", path="index/evidence.sqlite"))
        return
    try:
        with sqlite3.connect(db_path) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            required = {"run_meta", "section_stats", "normalized_records"}
            missing = sorted(required - tables)
            if missing:
                issues.append(_issue("invalid_evidence_sqlite_schema", path="index/evidence.sqlite", details=missing))
    except sqlite3.DatabaseError as exc:
        issues.append(_issue("invalid_evidence_sqlite", path="index/evidence.sqlite", details=str(exc)))


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


def _validate_report_pack(run_dir: Path, issues: list[dict[str, Any]]) -> None:
    relative = "reports/report-pack.json"
    payload = _read_json(run_dir / relative, fallback=None)
    if not isinstance(payload, Mapping):
        return
    proof_table = payload.get("proof_table")
    if proof_table is None:
        return
    if not isinstance(proof_table, list):
        issues.append(_issue("invalid_report_proof_table", path=relative, details="proof_table_not_list"))
        return

    findings = [dict(item) for item in payload.get("findings") or [] if isinstance(item, Mapping)]
    finding_ids = {str(item.get("id")) for item in findings if item.get("id")}
    covered_ids: set[str] = set()
    for index, row in enumerate(proof_table):
        if not isinstance(row, Mapping):
            issues.append(_issue("invalid_report_proof_table", path=relative, details={"row_index": index}))
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
            if artifact_path and not (run_dir / artifact_path).exists():
                issues.append(
                    _issue(
                        "broken_report_proof_table_ref",
                        path=relative,
                        details={"row_index": index, "finding_id": finding_id, "artifact_path": artifact_path},
                    )
                )
        elif proof_status not in {"missing_evidence", "unsupported"}:
            missing.append("proof_status:supported|missing_evidence|unsupported")
        if missing:
            issues.append(
                _issue(
                    "invalid_report_proof_table",
                    path=relative,
                    details={"row_index": index, "finding_id": finding_id, "missing": missing},
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
    _validate_evidence_refs(run_path, loaded_findings, issues)
    _validate_normalized_records(run_path, issues)
    _validate_record_key_uniqueness(run_path, issues)
    _validate_finding_collectors(loaded_findings, issues)
    _validate_finding_framework_mappings(loaded_findings, issues)
    _validate_ai_safe(run_path, issues)
    _validate_sensitive_contract_artifacts(run_path, issues)
    _validate_evidence_db(run_path, issues)
    manifest = _validate_manifest_artifact_paths(run_path, issues)
    _validate_data_handling(run_path, manifest, issues)
    _validate_live_readiness(run_path, manifest, issues)
    _validate_audit_plan(run_path, manifest, issues)
    _validate_api_inventory(run_path, manifest, issues)
    _validate_report_pack(run_path, issues)

    context = ai_context if isinstance(ai_context, Mapping) else _read_json(run_path / "ai_context.json", fallback={})
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
