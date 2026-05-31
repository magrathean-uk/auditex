from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .evidence_gates import build_evidence_gate_summary


SCHEMA_VERSION = "2026-04-21"

_EXPECTED_COLLECTORS = {
    "m365": (
        "identity",
        "auth_methods",
        "conditional_access",
        "security",
        "reports_usage",
        "intune",
        "exchange",
        "exchange_policy",
        "mailbox_forwarding",
        "sharepoint_access",
        "onedrive_posture",
        "app_consent",
        "app_credentials",
        "consent_policy",
        "dns_posture",
    ),
    "google_workspace": (
        "google_directory",
        "google_reports",
        "google_alert_center",
        "google_gmail_settings",
        "google_drive_posture",
        "google_groups_settings",
        "google_calendar_posture",
        "google_devices",
        "google_dns_posture",
    ),
}

_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_SEVERITY_POINTS = {
    "info": 1,
    "low": 3,
    "medium": 8,
    "high": 15,
    "critical": 25,
}


def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _gate_reason(collector: str, status: str, missing: list[str], reason: str) -> str:
    if missing:
        return f"{collector}: missing {', '.join(missing)}"
    if reason:
        return f"{collector}: {reason}"
    return f"{collector}: {status}"


def build_audit_autopilot_plan(
    *,
    platform: str,
    selected_collectors: list[str],
    capability_rows: list[dict[str, Any]],
    coverage_gaps: list[dict[str, Any]] | None = None,
    blockers: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    platform_key = platform or "m365"
    selected = [str(item) for item in selected_collectors if str(item)]
    gate_summary = build_evidence_gate_summary(
        selected_collectors=selected_collectors,
        capability_rows=capability_rows,
    )
    evidence_gates = [dict(row) for row in _rows(gate_summary.get("evidence_gates"))]
    required_scopes = sorted(
        {
            scope
            for row in evidence_gates
            for scope in _strings(row.get("required_permissions"))
        }
    )
    reasons: list[str] = []
    for gate in evidence_gates:
        status = str(gate.get("status") or "unverified")
        if status != "complete":
            reasons.append(
                _gate_reason(
                    str(gate.get("collector") or "unknown"),
                    status,
                    _strings(gate.get("missing_permissions")),
                    str(gate.get("reason") or ""),
                )
            )

    trusted_count = len(_strings(gate_summary.get("trusted_collectors")))
    blocked_count = len(_strings(gate_summary.get("blocked_collectors")))
    expected = list(_EXPECTED_COLLECTORS.get(platform_key, _EXPECTED_COLLECTORS["m365"]))
    missing_expected = [item for item in expected if item not in selected]
    gap_rows = _rows(coverage_gaps)
    blocker_rows = _rows(blockers)
    finding_rows = _rows(findings)
    for gap in gap_rows:
        message = str(gap.get("message") or gap.get("surface") or "coverage gap")
        reasons.append(f"coverage gap: {message}")
    if not selected or trusted_count == 0:
        status = "unusable"
        if "No trusted evidence gates completed." not in reasons:
            reasons.insert(0, "No trusted evidence gates completed.")
    elif blocked_count or any(gate["status"] in {"partial", "unverified"} for gate in evidence_gates) or gap_rows or blocker_rows:
        status = "partial"
    else:
        status = "complete"

    return {
        "schema_version": SCHEMA_VERSION,
        "platform": platform_key,
        "aim": "auditor_autopilot",
        "selected_collectors": selected,
        "expected_collectors": expected,
        "missing_expected_collectors": missing_expected,
        "required_scopes": required_scopes,
        "evidence_gates": evidence_gates,
        "quality_gate": {
            "status": status,
            "trusted_gate_count": trusted_count,
            "blocked_gate_count": blocked_count,
            "coverage_gap_count": len(gap_rows),
            "blocker_count": len(blocker_rows),
            "finding_count": len(finding_rows),
            "human_reviewer_required": status != "complete",
            "reasons": list(dict.fromkeys(reasons)),
        },
    }


def enrich_findings_for_autopilot(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for item in _rows(findings):
        finding = dict(item)
        refs = _rows(finding.get("evidence_refs"))
        affected = _strings(finding.get("affected_objects"))
        severity = str(finding.get("severity") or "unknown")
        category = str(finding.get("category") or "general")
        if "confidence" not in finding:
            finding["confidence"] = "high" if refs else "low"
        if "blast_radius" not in finding:
            if len(affected) == 1:
                scope = "single_object"
            elif len(affected) > 1:
                scope = "multiple_objects"
            elif severity in {"critical", "high"}:
                scope = "tenant_surface"
            else:
                scope = "unknown"
            finding["blast_radius"] = {"scope": scope, "affected_count": len(affected), "affected_objects": affected[:25]}
        if "business_impact" not in finding:
            finding["business_impact"] = _business_impact(category, severity, finding.get("impact"))
        if "false_positive_notes" not in finding:
            finding["false_positive_notes"] = (
                "Confirm the affected objects are still in scope and not covered by an approved exception."
                if affected
                else "Confirm the referenced evidence still reflects current tenant state and scope."
            )
        finding["proof"] = {
            "evidence_count": len(refs),
            "artifacts": sorted({str(ref.get("artifact_path")) for ref in refs if ref.get("artifact_path")}),
            "record_keys": [str(ref.get("record_key")) for ref in refs if ref.get("record_key")][:25],
        }
        enriched.append(finding)
    return enriched


def _business_impact(category: str, severity: str, existing_impact: Any) -> str:
    impact = str(existing_impact or "").strip()
    if impact:
        return impact
    if category in {"identity", "security"}:
        return f"{severity.title()} identity or security weakness can increase account takeover and privilege abuse risk."
    if category in {"mail", "collaboration", "data_exposure"}:
        return f"{severity.title()} data exposure weakness can increase leakage, forwarding, or broad sharing risk."
    return f"{severity.title()} tenant weakness can reduce audit assurance until remediated or accepted."


def _score_grade(score: int) -> str:
    if score >= 90:
        return "ultimate"
    if score >= 75:
        return "strong"
    if score >= 55:
        return "usable"
    if score >= 35:
        return "weak"
    return "blocked"


def _open_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in _rows(findings) if str(item.get("status") or "open") == "open"]


def _severity_points(finding: Mapping[str, Any]) -> int:
    return _SEVERITY_POINTS.get(str(finding.get("severity") or "info").lower(), 1)


def _infer_platform(findings: list[dict[str, Any]]) -> str:
    for finding in _rows(findings):
        rule_id = str(finding.get("rule_id") or "")
        collector = str(finding.get("collector") or "")
        if rule_id.startswith("google.") or collector.startswith("google_"):
            return "google_workspace"
    return "m365"


def build_auditor_score(
    *,
    findings: list[dict[str, Any]],
    overall_status: str,
    evidence_paths: list[str],
    coverage_gaps: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    rows = enrich_findings_for_autopilot(findings)
    total = len(rows)
    evidenced = sum(1 for item in rows if _rows(item.get("evidence_refs")))
    high_confidence = sum(1 for item in rows if item.get("confidence") == "high")
    unsupported = total - evidenced
    gaps = _rows(coverage_gaps)

    evidence_depth = int(round((evidenced / total) * 100)) if total else 100
    finding_confidence = int(round((high_confidence / total) * 100)) if total else 100
    coverage = 100 if overall_status == "ok" else 80
    coverage = max(0, coverage - len(gaps) * 15)
    report_usability = 100 if evidence_paths and (rows or not gaps) else 70
    false_positive_resistance = max(0, 100 - unsupported * 25)
    license_fit = 100
    components = {
        "evidence_depth": evidence_depth,
        "coverage": coverage,
        "finding_confidence": finding_confidence,
        "report_usability": report_usability,
        "false_positive_resistance": false_positive_resistance,
        "license_fit": license_fit,
    }
    score = int(
        round(
            evidence_depth * 0.25
            + coverage * 0.20
            + finding_confidence * 0.20
            + report_usability * 0.15
            + false_positive_resistance * 0.10
            + license_fit * 0.10
        )
    )
    return {
        "score": score,
        "grade": _score_grade(score),
        "components": components,
        "finding_count": total,
        "unsupported_claim_count": unsupported,
        "coverage_gap_count": len(gaps),
    }


def _classify_attack_stage(finding: Mapping[str, Any]) -> str | None:
    text = " ".join(
        str(finding.get(key) or "")
        for key in ("rule_id", "category", "title", "description")
    ).lower()
    if any(token in text for token in ("oauth", "consent", "app_", "application", "credential", "token")):
        return "app_access"
    if any(token in text for token in ("mfa", "2sv", "risky", "identity", "admin")):
        return "identity"
    if any(token in text for token in ("forward", "gmail", "mailbox", "transport", "mail")):
        return "mail_exfiltration"
    if any(token in text for token in ("sharepoint", "onedrive", "drive", "external", "broad", "sharing")):
        return "data_exposure"
    if any(token in text for token in ("dns", "spf", "dkim", "dmarc")):
        return "phishing_resilience"
    return None


def build_attack_paths(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    stage_order = ("identity", "app_access", "mail_exfiltration", "data_exposure", "phishing_resilience")
    by_stage: dict[str, list[dict[str, Any]]] = {stage: [] for stage in stage_order}
    for finding in _open_findings(findings):
        stage = _classify_attack_stage(finding)
        if stage:
            by_stage[stage].append(finding)

    chain = [stage for stage in stage_order if by_stage[stage]]
    if len(chain) < 2:
        return []
    stage_findings = [
        {
            "stage": stage,
            "finding_id": by_stage[stage][0].get("id"),
            "title": by_stage[stage][0].get("title"),
            "severity": by_stage[stage][0].get("severity"),
        }
        for stage in chain
    ]
    severity_rank = max((_SEVERITY_RANK.get(str(stage["severity"] or ""), 0) for stage in stage_findings), default=0)
    severity_name = next((name for name, rank in _SEVERITY_RANK.items() if rank == severity_rank), "medium")
    return [
        {
            "id": "attack_path:primary",
            "chain": chain,
            "stage_count": len(chain),
            "severity": severity_name,
            "findings": stage_findings,
            "summary": " -> ".join(chain),
            "requires_premium_license": False,
            "requires_live_tenant": False,
        }
    ]


def build_control_simulator(findings: list[dict[str, Any]]) -> dict[str, Any]:
    open_rows = sorted(_open_findings(findings), key=_severity_points, reverse=True)
    current_score = sum(_severity_points(item) for item in open_rows)
    actions: list[dict[str, Any]] = []
    running_score = current_score
    for item in open_rows:
        reduction = _severity_points(item)
        running_score = max(0, running_score - reduction)
        actions.append(
            {
                "id": item.get("id"),
                "title": item.get("title"),
                "severity": item.get("severity"),
                "remediation": item.get("remediation"),
                "estimated_risk_reduction": reduction,
                "simulated_score_after": running_score,
                "requires_write_access": False,
                "execution": "dry_run_only",
            }
        )
    return {
        "current_risk_score": current_score,
        "simulated_best_score": 0 if actions else current_score,
        "actions": actions,
        "requires_live_tenant": False,
    }


def build_report_qa(findings: list[dict[str, Any]], coverage_gaps: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    rows = enrich_findings_for_autopilot(findings)
    unsupported = [str(item.get("id")) for item in rows if not _rows(item.get("evidence_refs"))]
    low_confidence = [str(item.get("id")) for item in rows if item.get("confidence") != "high"]
    gaps = _rows(coverage_gaps)
    status = "pass"
    if unsupported:
        status = "fail"
    elif low_confidence or gaps:
        status = "warn"
    return {
        "status": status,
        "unsupported_claims": unsupported,
        "low_confidence_findings": low_confidence,
        "coverage_gap_count": len(gaps),
        "checks": {
            "every_finding_has_evidence": not unsupported,
            "all_findings_high_confidence": not low_confidence,
            "limitations_declared": bool(gaps) or not gaps,
        },
    }


def build_proof_table(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in enrich_findings_for_autopilot(findings):
        refs = _rows(item.get("evidence_refs"))
        artifacts = (item.get("proof") or {}).get("artifacts", [])
        common = {
            "finding_id": item.get("id"),
            "id": item.get("id"),
            "rule_id": item.get("rule_id"),
            "title": item.get("title"),
            "severity": item.get("severity"),
            "confidence": item.get("confidence"),
            "blast_radius": item.get("blast_radius"),
            "affected_objects": item.get("affected_objects") or [],
            "evidence_count": len(refs),
            "artifacts": artifacts if isinstance(artifacts, list) else [],
        }
        if not refs:
            rows.append({**common, "proof_status": "missing_evidence"})
            continue
        for index, ref in enumerate(refs):
            rows.append(
                {
                    **common,
                    "proof_status": "supported",
                    "evidence_ref_index": index,
                    "collector": ref.get("collector") or item.get("collector"),
                    "artifact_path": ref.get("artifact_path"),
                    "artifact_kind": ref.get("artifact_kind"),
                    "record_key": ref.get("record_key"),
                    "json_pointer": ref.get("json_pointer"),
                    "source_name": ref.get("source_name"),
                    "endpoint": ref.get("endpoint"),
                    "response_status": ref.get("response_status"),
                }
            )
    return rows


def _build_reviewer_index(
    *,
    top_findings: list[dict[str, Any]],
    proof_table: list[dict[str, Any]],
    limitations: list[dict[str, Any]],
    report_qa: dict[str, Any],
    blocker_count: int,
) -> dict[str, Any]:
    proof_by_finding: dict[str, dict[str, Any]] = {}
    for row in proof_table:
        finding_id = str(row.get("finding_id") or row.get("id") or "").strip()
        if not finding_id or finding_id in proof_by_finding:
            continue
        proof_by_finding[finding_id] = row

    prove_this = []
    for finding in top_findings:
        finding_id = str(finding.get("id") or "").strip()
        if not finding_id:
            continue
        proof = proof_by_finding.get(finding_id, {})
        prove_this.append(
            {
                "finding_id": finding_id,
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "collector": proof.get("collector") or finding.get("collector"),
                "proof_status": proof.get("proof_status") or "missing_evidence",
                "artifact_path": proof.get("artifact_path"),
                "record_key": proof.get("record_key"),
                "json_pointer": proof.get("json_pointer"),
            }
        )

    known_limits = [dict(item) for item in limitations if isinstance(item, Mapping)]
    unsupported_claims = _strings(report_qa.get("unsupported_claims"))
    if unsupported_claims:
        known_limits.append(
            {
                "surface": "proof",
                "status": "unsupported_claim",
                "message": "Some findings do not yet have supporting evidence refs.",
                "finding_ids": unsupported_claims,
            }
        )
    low_confidence = _strings(report_qa.get("low_confidence_findings"))
    if low_confidence:
        known_limits.append(
            {
                "surface": "confidence",
                "status": "low_confidence",
                "message": "Some findings are below high confidence and need extra reviewer care.",
                "finding_ids": low_confidence,
            }
        )
    if blocker_count:
        known_limits.append(
            {
                "surface": "collection",
                "status": "blocked",
                "message": "One or more selected collectors were blocked during collection.",
                "blocker_count": blocker_count,
            }
        )

    return {
        "start_here": [
            {
                "section": "executive_summary",
                "artifact_path": "reports/report-pack.json",
                "reason": "Start with posture, risk, and top open findings.",
            },
            {
                "section": "reviewer_index",
                "artifact_path": "reports/report-pack.json",
                "reason": "Use this index to jump from claims to proof and known limits.",
            },
            {
                "section": "report_qa",
                "artifact_path": "reports/report-pack.json",
                "reason": "Check unsupported claims, confidence, and declared gaps before trusting conclusions.",
            },
            {
                "section": "proof_table",
                "artifact_path": "reports/report-pack.json",
                "reason": "Verify each important claim against exact artifacts and record keys.",
            },
            {
                "section": "limitations",
                "artifact_path": "reports/report-pack.json",
                "reason": "Review blocked or partial surfaces before treating the audit as complete coverage.",
            },
        ],
        "prove_this": prove_this,
        "known_limits": known_limits,
    }


def build_basic_license_intelligence(
    *,
    tenant_name: str,
    platform: str,
    overall_status: str,
    findings: list[dict[str, Any]],
    evidence_paths: list[str],
    coverage_gaps: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    enriched = enrich_findings_for_autopilot(findings)
    return {
        "tenant_name": tenant_name,
        "platform": platform or "m365",
        "license_profile": {
            "minimum_live_access": "delegated_read_login",
            "requires_premium_license": False,
            "works_from_saved_bundle": True,
            "supports_synthetic_evidence": True,
            "production_writes": False,
        },
        "auditor_score": build_auditor_score(
            findings=enriched,
            overall_status=overall_status,
            evidence_paths=evidence_paths,
            coverage_gaps=coverage_gaps,
        ),
        "attack_paths": build_attack_paths(enriched),
        "control_simulator": build_control_simulator(enriched),
        "report_qa": build_report_qa(enriched, coverage_gaps=coverage_gaps),
        "replay_context": {
            "requires_live_tenant": False,
            "requires_premium_license": False,
            "input": "saved_bundle_or_synthetic_evidence",
            "evidence_paths": list(dict.fromkeys(evidence_paths)),
        },
    }


def build_board_report_sections(
    *,
    tenant_name: str,
    overall_status: str,
    findings: list[dict[str, Any]],
    evidence_paths: list[str],
    blocker_count: int,
    coverage_gaps: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    rows = enrich_findings_for_autopilot(findings)
    open_findings = [item for item in rows if str(item.get("status") or "open") == "open"]
    severity_counts: dict[str, int] = {}
    for item in rows:
        key = str(item.get("severity") or "unknown")
        severity_counts[key] = severity_counts.get(key, 0) + 1
    gaps = _rows(coverage_gaps)
    quality = "complete" if overall_status == "ok" and not blocker_count and not gaps else "partial"
    top_findings = sorted(open_findings, key=lambda item: _SEVERITY_RANK.get(str(item.get("severity") or ""), -1), reverse=True)[:5]
    proof_table = build_proof_table(rows)
    next_actions = [
        {
            "id": item.get("id"),
            "title": item.get("title"),
            "severity": item.get("severity"),
            "category": item.get("category"),
            "remediation": item.get("remediation"),
            "confidence": item.get("confidence"),
            "affected_objects": item.get("affected_objects") or [],
        }
        for item in top_findings
    ]
    limitations = [
        {
            "surface": gap.get("surface"),
            "status": gap.get("status"),
            "message": gap.get("message") or "Coverage gap limits assurance for this surface.",
            "collectors": gap.get("collectors") or [],
        }
        for gap in gaps
    ]
    intelligence = build_basic_license_intelligence(
        tenant_name=tenant_name,
        platform=_infer_platform(rows),
        overall_status=overall_status,
        findings=rows,
        evidence_paths=evidence_paths,
        coverage_gaps=gaps,
    )
    reviewer_index = _build_reviewer_index(
        top_findings=top_findings,
        proof_table=proof_table,
        limitations=limitations,
        report_qa=dict(intelligence.get("report_qa") or {}),
        blocker_count=blocker_count,
    )
    return {
        "findings": rows,
        "executive_summary": {
            "tenant_name": tenant_name,
            "overall_status": overall_status,
            "quality": quality,
            "finding_count": len(rows),
            "open_count": len(open_findings),
            "blocker_count": blocker_count,
            "coverage_gap_count": len(gaps),
            "severity_counts": severity_counts,
            "top_findings": [
                {
                    "id": item.get("id"),
                    "title": item.get("title"),
                    "severity": item.get("severity"),
                    "confidence": item.get("confidence"),
                }
                for item in top_findings
            ],
        },
        "technical_appendix": {
            "evidence_path_count": len(list(dict.fromkeys(evidence_paths))),
            "evidence_paths": list(dict.fromkeys(evidence_paths)),
            "proof_table_count": len(proof_table),
            "data_handling": "read_only_audit_default",
        },
        "reviewer_index": reviewer_index,
        "limitations": limitations,
        "proof_table": proof_table,
        "next_actions": next_actions,
        **{
            key: intelligence[key]
            for key in (
                "license_profile",
                "auditor_score",
                "attack_paths",
                "control_simulator",
                "report_qa",
                "replay_context",
            )
        },
    }
