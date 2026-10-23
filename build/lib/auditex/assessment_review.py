"""Compare explicitly identified, local assessments without changing their evidence.

Agreement means reported outcomes agree for an exact control identifier. It is
not a ground-truth label, proof of equivalent tests, or a new tenant assessment.
"""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from itertools import combinations
import json
from pathlib import Path
from typing import Any
from uuid import UUID

from .external_assessments import validate_assessment


SCHEMA_VERSION = "2026-10-18"
_DECISIVE_STATUSES = {"pass", "fail"}
_CAVEATS = [
    "Agreement is a comparison of reported outcomes, not independent validation or a gold label.",
    "Only exact control identifiers are joined; labels, aliases and benchmark versions are not inferred.",
    "Matching identifiers do not establish equivalent tests, resource scope or collection completeness.",
    "Assessment timestamps may differ; configuration changes can explain disagreement.",
    "External evidence references identify original input hashes and JSON pointers; original inputs are not reopened or executed.",
]


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> tuple[dict[str, Any], str]:
    try:
        if path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError(f"Assessment artifact exceeds 64 MiB: {path}")
        data = path.read_bytes()
        payload = json.loads(data, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"Cannot read assessment artifact {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Assessment artifact must be a JSON object: {path}")
    return payload, sha256(data).hexdigest()


def _invalid_constant(value: str) -> Any:
    raise ValueError(f"Invalid JSON constant: {value}")


def _tenant_key(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Every assessment must have an explicit tenant_id; import with tenant attribution first")
    try:
        identity = UUID(value.strip())
    except ValueError as exc:
        raise ValueError("Assessment tenant_id must be an immutable tenant UUID") from exc
    if not identity.int:
        raise ValueError("Assessment tenant_id must not be the empty tenant UUID")
    return str(identity)


def _pointer_segment(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _check_explicit_tenant(payload: dict[str, Any], tenant_id: str, location: str) -> None:
    if "tenant_id" not in payload:
        return
    try:
        observed = _tenant_key(payload["tenant_id"])
    except ValueError as exc:
        raise ValueError(f"Invalid tenant ID in Auditex bundle at {location}/tenant_id") from exc
    if observed != tenant_id:
        raise ValueError(f"Conflicting tenant IDs in Auditex bundle at {location}/tenant_id")


def _external_assessment(path: Path, position: int) -> dict[str, Any]:
    payload, digest = _read_json(path)
    assessment = validate_assessment(payload)
    checks = []
    for index, check in enumerate(assessment["checks"]):
        checks.append({
            **check,
            "canonical_ref": {
                "artifact_path": str(path),
                "input_sha256": digest,
                "json_pointer": f"/checks/{index}",
            },
        })
    return {
        "assessment_id": f"external:{position}",
        "source": assessment["source"],
        "source_version": assessment["source_version"],
        "tenant_id": assessment["tenant_id"],
        "assessed_at": assessment["assessed_at"],
        "provenance": dict(assessment["provenance"]),
        "artifact_path": str(path),
        "artifact_sha256": digest,
        "checks": checks,
    }


def _auditex_assessment(run_dir: Path) -> dict[str, Any]:
    from azure_tenant_audit.contracts import ROOT_REQUIRED_ARTIFACTS, build_validation_report

    if not run_dir.is_dir():
        raise ValueError(f"Auditex run directory not found: {run_dir}")
    for relative in ROOT_REQUIRED_ARTIFACTS:
        if not (run_dir / relative).is_file():
            raise ValueError(f"Incomplete Auditex bundle: missing {relative}")
    manifest_path = run_dir / "run-manifest.json"
    manifest, manifest_digest = _read_json(manifest_path)
    validation, _ = _read_json(run_dir / "validation.json")
    if manifest.get("contract_status") != "valid" or validation.get("valid") is not True:
        raise ValueError("Auditex bundle must have completed, valid contract validation")
    if manifest.get("platform", "m365") != "m365":
        raise ValueError("External Microsoft assessments require a Microsoft 365 Auditex bundle")
    tenant_id = _tenant_key(manifest.get("tenant_id"))
    summary, _ = _read_json(run_dir / "summary.json")
    _check_explicit_tenant(summary, tenant_id, "summary.json")
    context, _ = _read_json(run_dir / "ai_context.json")
    if "run" in context:
        if not isinstance(context["run"], dict):
            raise ValueError("Invalid Auditex bundle identity metadata at ai_context.json/run")
        _check_explicit_tenant(context["run"], tenant_id, "ai_context.json/run")
    report_path = run_dir / "reports" / "report-pack.json"
    report, digest = _read_json(report_path)
    # Current report packs identify their tenant by summary.tenant_name only.
    # Honor explicit IDs in either metadata position without treating IDs of
    # partner tenants or affected resources inside findings as bundle identity.
    _check_explicit_tenant(report, tenant_id, "reports/report-pack.json")
    if isinstance(report.get("summary"), dict):
        _check_explicit_tenant(report["summary"], tenant_id, "reports/report-pack.json/summary")
    if not manifest.get("schema_contract_version") or manifest["schema_contract_version"] != validation.get("contract_version"):
        raise ValueError("Auditex manifest and recorded validation contract versions disagree")
    if not build_validation_report(run_dir=run_dir, read_only=True).get("valid"):
        raise ValueError("Auditex bundle no longer passes contract validation")
    baseline = report.get("baseline_alignment")
    limitations = []
    if baseline is None:
        frameworks = {}
        limitations.append("Auditex bundle has no baseline_alignment controls; no Auditex control comparison is available.")
    elif not isinstance(baseline, dict) or not isinstance(baseline.get("frameworks"), dict):
        raise ValueError("Malformed Auditex baseline_alignment framework controls")
    else:
        frameworks = baseline["frameworks"]
    checks = []
    seen_controls: set[tuple[str, str]] = set()
    for framework, details in frameworks.items():
        if not isinstance(details, dict) or not isinstance(details.get("controls"), list):
            raise ValueError(f"Malformed Auditex baseline framework: {framework}")
        for index, row in enumerate(details["controls"]):
            if not isinstance(row, dict) or not isinstance(row.get("control_id"), str) or not row["control_id"].strip():
                raise ValueError(f"Malformed Auditex baseline control in {framework}")
            reported = row.get("status")
            if reported not in {"pass", "fail", "accepted_risk", "not_assessed"}:
                raise ValueError(f"Invalid Auditex baseline status: {reported}")
            control_id = row["control_id"]
            if (framework, control_id) in seen_controls:
                raise ValueError(f"Duplicate Auditex baseline control: {framework}:{control_id}")
            seen_controls.add((framework, control_id))
            for key in ("rule_ids", "finding_ids"):
                if not isinstance(row.get(key, []), list) or any(not isinstance(value, str) or not value for value in row.get(key, [])):
                    raise ValueError(f"Malformed Auditex baseline {key} in {framework}")
            # SCuBA policy IDs already carry product and policy version. Other
            # framework IDs need the framework key to avoid numeric-ID collisions.
            exact_id = control_id if framework == "cisa_scuba" else f"{framework}:{control_id}"
            pointer = f"/baseline_alignment/frameworks/{_pointer_segment(framework)}/controls/{index}"
            checks.append({
                "id": f"{framework}:{control_id}",
                "title": row.get("title") or control_id,
                "status": reported if reported in _DECISIVE_STATUSES else "unknown",
                "reported_status": reported,
                "control_ids": [exact_id],
                "resource_ids": [],
                "rule_ids": list(row.get("rule_ids") or []),
                "finding_ids": list(row.get("finding_ids") or []),
                "evidence_refs": [{
                    "source": "auditex",
                    "input_sha256": digest,
                    "json_pointer": pointer,
                    "artifact_path": str(report_path),
                }],
            })
    return {
        "assessment_id": "auditex",
        "source": "auditex",
        "source_version": None,
        "schema_contract_version": manifest["schema_contract_version"],
        "tenant_id": tenant_id,
        "assessed_at": manifest.get("created_utc"),
        "artifact_path": str(report_path),
        "artifact_sha256": digest,
        "provenance": {
            "identity_source": "run-manifest.json",
            "identity_ref": {"artifact_path": str(manifest_path), "input_sha256": manifest_digest, "json_pointer": "/tenant_id"},
        },
        "validation_mode": "fresh_read_only",
        "limitations": limitations,
        "checks": checks,
    }


def _support(assessment: dict[str, Any], checks: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = sorted({check["status"] for check in checks})
    return {
        "assessment_id": assessment["assessment_id"],
        "source": assessment["source"],
        "status": statuses[0] if len(statuses) == 1 else "mixed",
        "statuses": statuses,
        "check_ids": [check["id"] for check in checks],
        "resource_ids": sorted({resource for check in checks for resource in check["resource_ids"]}),
        "checks": checks,
    }


def _compare_pair(left: dict[str, Any], right: dict[str, Any]) -> tuple[str, str]:
    if left["status"] not in _DECISIVE_STATUSES or right["status"] not in _DECISIVE_STATUSES:
        return "coverage_gap", "nondecisive_or_mixed_status"
    if left["resource_ids"] != right["resource_ids"]:
        return "coverage_gap", "different_or_unverified_resource_scope"
    if left["status"] == right["status"]:
        return "agreement", "same_reported_status"
    return "disagreement", "different_reported_status"


def compare_external_assessments(
    assessment_paths: list[str | Path],
    expected_tenant_id: str | None = None,
    run_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Review canonical external JSON, optionally against a finalized M365 run.

    Missing tenant identities are refused, including when an expected identity
    is supplied: an expectation cannot establish which tenant produced a file.
    """
    if not isinstance(assessment_paths, list) or not assessment_paths:
        raise ValueError("Provide at least one normalized external assessment path")
    if any(not isinstance(path, (str, Path)) or not str(path).strip() for path in assessment_paths):
        raise ValueError("Assessment paths must be nonempty paths")
    paths = [Path(path).resolve() for path in assessment_paths]
    if len(set(paths)) != len(paths):
        raise ValueError("Duplicate assessment paths cannot provide independent support")
    assessments = [_external_assessment(path, index) for index, path in enumerate(paths)]
    identities = [(assessment["source"], assessment["provenance"]["input_sha256"]) for assessment in assessments]
    if len(set(identities)) != len(identities):
        raise ValueError("Duplicate assessment source hashes cannot provide independent support")
    if run_dir is not None:
        assessments.append(_auditex_assessment(Path(run_dir).resolve()))
    if len(assessments) < 2:
        raise ValueError("Comparison needs two assessments or one assessment and an Auditex run")
    tenant_ids = {_tenant_key(assessment["tenant_id"]) for assessment in assessments}
    if len(tenant_ids) != 1:
        raise ValueError("Cannot compare assessments from different tenant IDs")
    tenant_id = next(iter(tenant_ids))
    if expected_tenant_id is not None and tenant_id != _tenant_key(expected_tenant_id):
        raise ValueError("Assessment tenant ID does not match expected_tenant_id")

    by_control: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    coverage_gaps: list[dict[str, Any]] = []
    for assessment in assessments:
        if not assessment["checks"]:
            coverage_gaps.append({"reason": "assessment_has_no_checks", "assessment_id": assessment["assessment_id"]})
        for check in assessment["checks"]:
            if not check["control_ids"]:
                coverage_gaps.append({
                    "reason": "check_has_no_explicit_control_id",
                    "assessment_id": assessment["assessment_id"],
                    "check": check,
                })
            for control_id in check["control_ids"]:
                by_control[control_id][assessment["assessment_id"]].append(check)

    controls = []
    agreements = []
    disagreements = []
    for control_id, grouped in sorted(by_control.items()):
        supports = [_support(assessment, grouped[assessment["assessment_id"]])
                    for assessment in assessments if assessment["assessment_id"] in grouped]
        if len(supports) < 2:
            coverage_gaps.append({"control_id": control_id, "reason": "control_not_shared", "assessments": supports})
            continue
        comparisons = []
        for left, right in combinations(supports, 2):
            outcome, reason = _compare_pair(left, right)
            row = {
                "control_id": control_id,
                "left_assessment": left["assessment_id"],
                "right_assessment": right["assessment_id"],
                "left_status": left["status"],
                "right_status": right["status"],
                "left_check_ids": left["check_ids"],
                "right_check_ids": right["check_ids"],
                "outcome": outcome,
                "reason": reason,
            }
            comparisons.append(row)
            {"agreement": agreements, "disagreement": disagreements, "coverage_gap": coverage_gaps}[outcome].append(row)
        absent = [assessment["assessment_id"] for assessment in assessments if assessment["assessment_id"] not in grouped]
        if absent:
            coverage_gaps.append({"control_id": control_id, "reason": "control_absent_from_assessments", "assessment_ids": absent})
        controls.append({"control_id": control_id, "assessments": supports, "comparisons": comparisons})

    caveats = list(_CAVEATS)
    caveats.extend(limit for assessment in assessments for limit in assessment.get("limitations", []))
    if any(assessment["provenance"].get("identity_source") == "operator" for assessment in assessments):
        caveats.append("Some tenant identities were supplied by the operator and were not verified from source metadata.")
    if any(not assessment["assessed_at"] for assessment in assessments):
        caveats.append("At least one assessment has no collection timestamp; contemporaneous evidence is not established.")
    if any(assessment["source"] == "auditex" for assessment in assessments):
        caveats.append("Auditex baseline outcomes cover its mapped rules; they do not establish full benchmark coverage.")
        caveats.append("Auditex contract validation was rerun locally without changing the bundle; it does not establish tenant completeness or independently confirm external results.")
    if not controls:
        caveats.append("No exact shared control IDs were found; no outcome comparison was possible.")
    return {
        "schema_version": SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "assessments": [{key: value for key, value in assessment.items() if key != "checks"} for assessment in assessments],
        "summary": {
            "assessment_count": len(assessments),
            "shared_control_count": len(controls),
            "agreement_pair_count": len(agreements),
            "disagreement_pair_count": len(disagreements),
            "coverage_gap_count": len(coverage_gaps),
        },
        "controls": controls,
        "agreements": agreements,
        "disagreements": disagreements,
        "coverage_gaps": coverage_gaps,
        "caveats": caveats,
        "read_only": True,
    }
