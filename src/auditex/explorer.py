"""Self-contained interactive HTML explorer for one or more finalized Auditex runs.

The page embeds each run's summary, findings, proof rows, attack paths, the
evidence records that findings, attack-path hops and detection signals point at,
detection coverage, baseline alignment, collector coverage and the run's
data-handling assertions. With two or more runs of the same tenant it also
embeds a before/after comparison (oldest against newest).

The output is one HTML file with an inline stylesheet, one inline script that a
strict Content-Security-Policy pins by SHA-256 hash, and the data as a JSON
script block. It makes no network requests, contains no ``http(s)://`` URL, and
the same input runs produce the same bytes. It contains tenant evidence, so
share it the same way as the run folder itself.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import re
from collections.abc import Iterable, Sequence
from datetime import datetime
from importlib import resources as importlib_resources
from pathlib import Path
from typing import Any

from azure_tenant_audit.resources import load_json_resource, resolve_resource_path

FORMAT_VERSION = 2
_EVIDENCE_LIMIT = 500
_SEVERITIES = ("critical", "high", "medium", "low", "info")
# Mirrors azure_tenant_audit.findings._RISK_BAND_FLOORS so the grade scale on the
# page matches how the engine assigns grades.
_RISK_BANDS = (("clean", 0, 1), ("low", 1, 15), ("medium", 15, 40), ("high", 40, 70), ("critical", 70, 100))
_ACCEPTED_STATUSES = {"accepted_risk", "accepted", "waived"}

_AREA_LABELS = {
    "identity": "Identity",
    "application": "Applications",
    "mail_flow": "Mail flow",
    "exposure": "Sharing & exposure",
    "external_access": "External access",
    "device_management": "Devices",
    "governance": "Governance",
    "collaboration": "Collaboration",
    "service": "Service health",
    "posture": "Posture",
    "security": "Security",
}
_SURFACE_LABELS = {
    "apps": "Applications",
    "collaboration": "Collaboration",
    "data_exposure": "Sharing & exposure",
    "devices": "Devices",
    "dns": "DNS",
    "external_access": "External access",
    "governance": "Governance",
    "identity": "Identity",
    "mail": "Mail flow",
    "operations": "Operations",
    "security": "Security",
}
_FRAMEWORK_LABELS = {
    "cis_m365_v7": "CIS M365 v7",
    "cisa_scuba": "CISA SCuBA",
    "ms_secure_score": "Secure Score",
    "ms_zero_trust": "Zero Trust",
    "mcsb": "MCSB",
    "nist_800_53": "NIST 800-53",
    "iso_27001": "ISO 27001",
    "mitre_attack": "MITRE ATT&CK",
    "soc2": "SOC 2",
    "nis2": "NIS2",
    "dora": "DORA",
    "google_workspace_baseline": "Google Workspace",
    "cis_m365_v3": "CIS M365 v3 (legacy)",
}
_EDGE_LABELS = {
    "owns": "owns",
    "owns_group": "owns group",
    "has_app_role": "has app role",
    "has_role": "has role",
    "guest_with_role": "has role",
    "member_of": "member of",
    "consented": "consented",
    "can_reset": "can reset",
    "no_mfa": "password only",
    "third_party": "controlled by",
    "authenticates_as": "signs in as",
    "credential": "credential for",
}
_TECHNIQUE_NAMES = {
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1098": "Account Manipulation",
    "T1098.001": "Additional Cloud Credentials",
    "T1098.003": "Additional Cloud Roles",
    "T1199": "Trusted Relationship",
    "T1528": "Steal Application Access Token",
    "T1550.001": "Application Access Token",
    "T1552": "Unsecured Credentials",
}
_FOOTHOLD_LABELS = {
    "ordinary_user": "Ordinary user",
    "no_mfa": "User without MFA",
    "guest": "Guest",
    "third_party_app": "Third-party app",
    "multi_tenant_app": "Multi-tenant app",
    "expired_secret": "App with an expired secret",
    "long_lived_secret": "App with a long-lived secret",
}
_FOOTHOLD_PHRASES = {
    "ordinary_user": "one ordinary user’s password",
    "no_mfa": "the password of one user without MFA",
    "guest": "one partner guest account",
    "third_party_app": "control of one third-party app",
    "multi_tenant_app": "control of one multi-tenant app",
    "expired_secret": "one leaked app secret",
    "long_lived_secret": "one leaked app secret",
}
_BREAK_TEMPLATES = {
    "owns": "Remove {from_} as owner of {to}",
    "owns_group": "Remove {from_} as owner of {to}",
    "has_app_role": "Revoke {to} from {from_}",
    "consented": "Revoke the {to} consent granted to {from_}",
    "has_role": "Remove {from_} from {to}",
    "guest_with_role": "Remove the guest {from_} from {to}",
    "member_of": "Remove {from_} from group {to}",
    "no_mfa": "Require MFA for {to}",
    "authenticates_as": "Remove the client secrets and certificates of {from_}",
    "credential": "Rotate and remove the credential of {to}",
    "can_reset": "Remove the reset rights {from_} holds over {to}",
}
_DETECTION_DETAILS = {
    "ingestion_enabled": "Audit log ingestion is on",
    "ingestion_disabled": "Audit log ingestion is off",
    "audit_on_by_default": "Mailbox auditing is on by default",
    "audit_disabled": "Mailbox auditing is turned off for the organisation",
    "no_bypass_associations": "No account has an audit bypass",
    "no_enabled_alert_policies": "No alert policy is enabled",
    "no_enabled_risk_policies": "No enabled policy acts on sign-in or user risk",
    "license_required": "Needs a licence this tenant does not have",
    "risk_detection_available": "Risk detections are available",
    "alerts_api_reachable": "The alerts API answered",
    "directory_audits_readable": "Directory audit logs were readable",
    "signin_logs_readable": "Sign-in logs were readable",
    "not_collected": "the source collector did not run",
    "not_collected_arm_diagnostic_settings": "diagnostic settings live in Azure Resource Manager, which Auditex does not read",
    "empty_output": "the collector returned no usable value",
    "property_missing": "the setting was missing from the response",
    "policy_sample_truncated": "the policy sample was truncated",
}
_EXCHANGE_COLLECTORS = {"exchange", "exchange_policy", "mailbox_forwarding"}
_LICENCE_PRODUCTS = {
    "intune": "Microsoft Intune",
    "intune_depth": "Microsoft Intune",
    "identity_governance": "Microsoft Entra ID P2",
    "identity_protection": "Microsoft Entra ID P2",
    "defender_cloud_apps": "Microsoft Defender for Cloud Apps",
}
_MS_STATE_LABELS = {"implemented": "Completed", "partial": "Partial", "not_implemented": "To address", "no_data": "No data"}


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return default


def _records(payload: Any) -> list[dict[str, Any]]:
    rows = payload.get("records") if isinstance(payload, dict) else payload
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _humanise(code: Any) -> str:
    text = _text(code).replace("_", " ").strip()
    return text[:1].upper() + text[1:] if text else ""


def _severity(value: Any) -> str:
    text = _text(value).lower()
    return text if text in _SEVERITIES else "info"


def _collected_label(created: Any) -> str:
    text = _text(created)
    if not text:
        return "Unknown date"
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    return f"{moment.day} {moment.strftime('%b %Y, %H:%M')} UTC"


# --------------------------------------------------------------------------- evidence


def _ref_key(ref: Any) -> tuple[str, str] | None:
    if not isinstance(ref, dict):
        return None
    artifact, key = ref.get("artifact_path"), ref.get("record_key")
    if isinstance(artifact, str) and isinstance(key, str) and artifact and key:
        return artifact, key
    return None


def _evidence_records(run_dir: Path, refs: Iterable[tuple[str, str]]) -> dict[str, dict[str, Any]]:
    wanted: dict[str, list[str]] = {}
    for artifact, key in refs:
        keys = wanted.setdefault(artifact, [])
        if key not in keys:
            keys.append(key)
    records: dict[str, dict[str, Any]] = {}
    for artifact, keys in wanted.items():
        candidate = (run_dir / artifact).resolve()
        try:
            candidate.relative_to(run_dir.resolve())
        except ValueError:
            continue
        index = {row.get("key"): row for row in _records(_read_json(candidate, {}))}
        for key in keys:
            if key in index and len(records) < _EVIDENCE_LIMIT:
                records[f"{artifact}#{key}"] = index[key]
    return records


# --------------------------------------------------------------------------- tenant metadata


def _organization(run_dir: Path) -> dict[str, Any]:
    for candidate in (run_dir / "raw" / "identity.json", run_dir / "raw" / "sample_input.json"):
        payload = _read_json(candidate, {})
        if not isinstance(payload, dict):
            continue
        if "identity" in payload and isinstance(payload["identity"], dict):
            payload = payload["identity"]
        organization = payload.get("organization")
        if isinstance(organization, dict):
            values = organization.get("value") or organization.get("records") or []
            if isinstance(values, list):
                for row in values:
                    if isinstance(row, dict):
                        return row
    return {}


def _tenant_meta(run_dir: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    organization = _organization(run_dir)
    domain = ""
    for row in _records(_read_json(run_dir / "normalized" / "domain_hybrid_objects.json", {})):
        if row.get("is_default"):
            domain = _text(row.get("id"))
            break
    if not domain:
        for row in organization.get("verifiedDomains") or []:
            if isinstance(row, dict) and row.get("isDefault"):
                domain = _text(row.get("name"))
                break
    users = _read_json(run_dir / "normalized" / "users.json", None)
    return {
        "display_name": _text(organization.get("displayName")) or _text(manifest.get("tenant_name")) or "Unknown tenant",
        "tenant_id": _text(manifest.get("tenant_id") or organization.get("id")),
        "domain": domain or _text(manifest.get("tenant_domain") or manifest.get("primary_domain")),
        "users": len(_records(users)) if users is not None else None,
    }


# --------------------------------------------------------------------------- collectors


def _collector_reason(name: str, coverage: dict[str, Any], capability: dict[str, Any]) -> str:
    kind = _text(capability.get("blocker_kind"))
    missing = [str(item) for item in capability.get("missing_permissions") or [] if item]
    if kind == "license":
        product = _LICENCE_PRODUCTS.get(name)
        return f"Licence missing: {product}" if product else f"Licence missing: {_text(capability.get('blocker_reason')) or 'service not licensed'}"
    if kind == "local_tool":
        if name in _EXCHANGE_COLLECTORS:
            return "No Exchange Online session"
        if name.startswith("teams"):
            return "No Teams PowerShell session"
        return "No authorised command-line session"
    if kind == "auth_scope":
        return f"Missing permission: {', '.join(missing)}" if missing else "Missing read permission"
    if kind == "admin_role":
        return "Admin role cannot read this surface"
    if kind == "tenant_policy":
        return "Blocked by tenant policy"
    if kind == "service_absent":
        return "Service not enabled in this tenant"
    status = _text(coverage.get("coverage_status"))
    return {
        "partial_success": "Partially collected: some endpoints failed",
        "blocked_permission": "Blocked by a permission or sign-in error",
        "failed_runtime": "Collector failed at run time",
        "not_run": "Collector did not run",
        "not_applicable": "Skipped: not applicable to this tenant",
    }.get(status, "No coverage record for this collector")


def _collector_rows(run_dir: Path, manifest: dict[str, Any], data_handling: dict[str, Any]) -> list[dict[str, Any]]:
    selected = [str(name) for name in manifest.get("selected_collectors") or data_handling.get("collectors") or []]
    definitions = (load_json_resource("configs/collector-definitions.json", default={}) or {}).get("collectors", {})
    preset = _text(manifest.get("collector_preset"))
    universe = list(selected)
    if preset and _text(manifest.get("platform") or "m365") == "m365":
        for name, definition in definitions.items():
            if isinstance(definition, dict) and definition.get("enabled") and name not in universe:
                universe.append(name)
    coverage = {_text(row.get("collector")): row for row in _records(_read_json(run_dir / "normalized" / "coverage_ledger.json", {}))}
    capability = {_text(row.get("collector")): row for row in _records(_read_json(run_dir / "normalized" / "capability_matrix.json", {}))}
    offline = _text(manifest.get("mode")) == "offline"
    rows = []
    for name in universe:
        definition = definitions.get(name) if isinstance(definitions.get(name), dict) else {}
        ledger = coverage.get(name, {})
        if name not in selected:
            status, reason = "not_selected", f'Not in preset "{preset}"' if preset else "Not selected for this run"
        elif _text(ledger.get("coverage_status")).startswith("complete"):
            status, reason = "verified", "Replayed from the offline sample" if offline else "Collected"
        else:
            status, reason = "not_verified", _collector_reason(name, ledger, capability.get(name, {}))
        rows.append(
            {
                "collector": name,
                "description": _text(definition.get("description")),
                "permissions": [str(item) for item in definition.get("required_permissions") or []],
                "status": status,
                "reason": reason,
            }
        )
    return rows


def _nv_areas(manifest: dict[str, Any], collectors: list[dict[str, Any]]) -> list[dict[str, str]]:
    by_name = {row["collector"]: row for row in collectors}
    areas = []
    for surface in manifest.get("surface_coverage") or []:
        if not isinstance(surface, dict):
            continue
        names = [str(name) for name in surface.get("collectors") or []]
        gaps = [by_name[name] for name in names if name in by_name and by_name[name]["status"] != "verified"]
        if not gaps or len(gaps) < len(names):
            continue
        key = _text(surface.get("surface"))
        areas.append({"key": key, "label": _SURFACE_LABELS.get(key, _humanise(key)), "reason": gaps[0]["reason"]})
    return areas


# --------------------------------------------------------------------------- findings


def _finding_rows(findings: list[dict[str, Any]], proof_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keep = (
        "id", "rule_id", "category", "title", "collector", "affected_objects", "description", "impact",
        "remediation", "references", "framework_mappings", "evidence_refs", "waiver",
    )
    proof = {_text(row.get("finding_id")): _text(row.get("proof_status") or "supported") for row in proof_rows}
    rows = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        row = {key: finding.get(key) for key in keep if key in finding}
        row["severity"] = _severity(finding.get("severity"))
        accepted = _text(finding.get("status")).lower() in _ACCEPTED_STATUSES
        row["status"] = "accepted" if accepted else "open"
        objects = [str(item) for item in finding.get("affected_objects") or [] if item is not None]
        row["affected_objects"] = objects
        row["object"] = objects[0] if objects else ""
        category = _text(finding.get("category")) or "other"
        row["area"] = category
        row["area_label"] = _AREA_LABELS.get(category, _humanise(category))
        row["proof"] = "supported" if proof.get(_text(finding.get("id")), "supported") == "supported" else "partial"
        refs = [ref for ref in finding.get("evidence_refs") or [] if _ref_key(ref)]
        row["evidence_refs"] = refs
        rows.append(row)
    rows.sort(key=lambda item: (_SEVERITIES.index(item["severity"]), item["status"] != "open", _text(item.get("title")), _text(item.get("id"))))
    for index, row in enumerate(rows, start=1):
        row["n"] = f"F-{index:03d}"
    return rows


# --------------------------------------------------------------------------- attack paths


def _node_type(raw: str, *, guest: bool) -> str:
    if raw == "user":
        return "guest" if guest else "user"
    return raw or "principal"


def _attack_paths(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for index, path in enumerate(paths):
        if not isinstance(path, dict):
            continue
        foothold = _text(path.get("foothold") or "ordinary_user")
        hops = [hop for hop in path.get("hops") or [] if isinstance(hop, dict)]
        if not hops:
            # Legacy chain-of-findings paths: one hop per stage.
            hops = [
                {"from": stage.get("title"), "edge": stage.get("stage"), "to": stage.get("title"), "technique": stage.get("technique")}
                for stage in path.get("findings") or []
                if isinstance(stage, dict)
            ]
        breakpoints = [item for item in path.get("breakpoints") or [] if isinstance(item, dict)]
        break_index, fix = None, ""
        for breakpoint in sorted(breakpoints, key=lambda item: _text(item.get("edge")) not in _BREAK_TEMPLATES):
            for hop_index, hop in enumerate(hops):
                if (hop.get("from"), hop.get("to"), hop.get("edge")) == (breakpoint.get("from"), breakpoint.get("to"), breakpoint.get("edge")):
                    break_index = hop_index
                    break
            if break_index is not None:
                template = _BREAK_TEMPLATES.get(_text(breakpoint.get("edge")))
                fix = template.format(from_=breakpoint.get("from"), to=breakpoint.get("to")) if template else (
                    f"Remove the “{_EDGE_LABELS.get(_text(breakpoint.get('edge')), _humanise(breakpoint.get('edge')))}” link from {breakpoint.get('from')} to {breakpoint.get('to')}"
                )
                break
        hop_rows = []
        for hop_index, hop in enumerate(hops):
            edge = _text(hop.get("edge"))
            technique = _text(hop.get("technique"))
            ref = _ref_key(hop.get("evidence_ref"))
            hop_rows.append(
                {
                    "from": _text(hop.get("from")),
                    "from_type": _node_type(_text(hop.get("from_type")), guest=hop_index == 0 and foothold == "guest"),
                    "to": _text(hop.get("to")),
                    "to_type": _node_type(_text(hop.get("to_type")), guest=False),
                    "edge": edge,
                    "rel": _EDGE_LABELS.get(edge, _humanise(edge).lower()),
                    "technique": technique,
                    "technique_name": _TECHNIQUE_NAMES.get(technique, "ATT&CK technique"),
                    "eligible": bool(hop.get("eligible")),
                    "evidence": {
                        "artifact": ref[0] if ref else "",
                        "key": ref[1] if ref else "",
                        "collector": _text((hop.get("evidence_ref") or {}).get("collector")) if ref else "",
                        "source_name": _text((hop.get("evidence_ref") or {}).get("source_name")) if ref else "",
                    },
                }
            )
        source, target = _text(path.get("source")), _text(path.get("target"))
        rows.append(
            {
                "id": _text(path.get("id") or path.get("finding_id") or f"path-{index + 1}"),
                "severity": _severity(path.get("severity")),
                "summary": _text(path.get("summary")) or " → ".join(_text(item) for item in path.get("chain") or []),
                "headline": _path_headline(foothold, target, len(hop_rows)),
                "source": source,
                "target": target,
                "foothold": foothold,
                "foothold_label": _FOOTHOLD_LABELS.get(foothold, _humanise(foothold)),
                "techniques": [str(item) for item in path.get("techniques") or []],
                "hops": hop_rows,
                "break_index": break_index,
                "fix": fix,
                "fix_detail": (
                    f"Cutting this one link disconnects {source or 'the foothold'} from {target or 'the tier-0 target'}."
                    if fix
                    else "No single link removal closes this route: other routes reach the same tier-0 target. Close the foothold or the target assignment instead."
                ),
                "also": [str(item) for item in path.get("also_reachable_from") or []],
                "finding_id": _text(path.get("finding_id")),
            }
        )
    return rows


# --------------------------------------------------------------------------- detection


def _detection_detail(signal: dict[str, Any], record: dict[str, Any]) -> str:
    status = _text(signal.get("status"))
    reason = _text(signal.get("reason"))
    observed = record.get("observed_value")
    if reason == "bypass_associations_present":
        count = observed if isinstance(observed, int) and not isinstance(observed, bool) else None
        return f"{_plural(count, 'account')} with an audit bypass" if count else "Accounts with an audit bypass were found"
    if reason == "enabled_alert_policies" and isinstance(observed, dict):
        return f"{observed.get('enabled_count')} of {observed.get('policy_count')} alert policies enabled"
    if reason == "enabled_risk_policies" and isinstance(observed, dict):
        names = [str(name) for name in observed.get("policies") or []]
        return f"{_plural(len(names), 'risk-based policy', 'risk-based policies')} enabled" + (f": {', '.join(names)}" if names else "")
    detail = _DETECTION_DETAILS.get(reason, _humanise(reason))
    if status == "unknown":
        return f"Not verified: {detail[:1].lower() + detail[1:]}" if detail else "Not verified"
    return detail or ("Verified on" if status == "on" else "Verified off")


def _detection(coverage: dict[str, Any], run_dir: Path) -> dict[str, Any] | None:
    signals = [item for item in coverage.get("signals") or [] if isinstance(item, dict)]
    if not signals:
        return None
    records = {_text(row.get("key")): row for row in _records(_read_json(run_dir / "normalized" / "detection_signal_objects.json", {}))}
    rows = []
    for signal in signals:
        ref = _ref_key(signal.get("evidence_ref"))
        record = records.get(ref[1], {}) if ref else {}
        status = _text(signal.get("status"))
        rows.append(
            {
                "key": _text(signal.get("name")),
                "title": _text(signal.get("title") or signal.get("name")),
                "why": _text(signal.get("why_it_matters")),
                "status": status if status in {"on", "off"} else "unknown",
                "detail": _detection_detail(signal, record),
                "source": _text((signal.get("evidence_ref") or {}).get("source_name")),
            }
        )
    counts = {key: sum(1 for row in rows if row["status"] == key) for key in ("on", "off", "unknown")}
    score = coverage.get("score")
    return {
        "signals": rows,
        "counts": counts,
        "score": score if isinstance(score, (int, float)) else None,
        "note": (
            f"Weighted over {_plural(counts['on'] + counts['off'], 'verified signal')}"
            if isinstance(score, (int, float))
            else f"{counts['unknown']} of {len(rows)} signals not verified"
        ),
    }


# --------------------------------------------------------------------------- baselines


def _baselines(alignment: dict[str, Any]) -> dict[str, Any] | None:
    frameworks = alignment.get("frameworks") if isinstance(alignment.get("frameworks"), dict) else {}
    cards = []
    for key, framework in frameworks.items():
        if not isinstance(framework, dict):
            continue
        controls = []
        for control in framework.get("controls") or []:
            if not isinstance(control, dict):
                continue
            raw = _text(control.get("status"))
            status = {"accepted_risk": "accepted"}.get(raw, raw if raw in {"fail", "pass", "not_assessed"} else "not_assessed")
            finding_ids = [str(item) for item in control.get("finding_ids") or []]
            controls.append(
                {
                    "id": _text(control.get("control_id")),
                    "title": _text(control.get("title")),
                    "status": status,
                    "linked": int(control.get("open_finding_count") or len(finding_ids)) if status == "fail" else len(finding_ids),
                    "note": (
                        "Accepted risk recorded in the run."
                        if status == "accepted"
                        else "No collector in this run evidences this control." if status == "not_assessed" else ""
                    ),
                }
            )
        counts = {status: sum(1 for row in controls if row["status"] == status) for status in ("fail", "accepted", "pass", "not_assessed")}
        cards.append(
            {
                "key": key,
                "label": _text(framework.get("title")) or _FRAMEWORK_LABELS.get(key, key),
                "short": _FRAMEWORK_LABELS.get(key, _text(framework.get("title")) or key),
                "version": _text(framework.get("version")),
                "controls": controls,
                "counts": counts,
                "total": len(controls),
                "assessed": len(controls) - counts["not_assessed"],
            }
        )
    secure = alignment.get("secure_score") if isinstance(alignment.get("secure_score"), dict) else {}
    secure_view = None
    if secure.get("available"):
        overall = secure.get("overall") or {}
        rows = []
        for control in secure.get("controls") or []:
            if not isinstance(control, dict):
                continue
            agreement = _text(control.get("agreement"))
            findings = int(control.get("auditex_open_finding_count") or 0)
            verdict = {"agrees": "agree", "auditex_only": "disagree", "microsoft_only": "disagree"}.get(agreement, "not_assessed")
            if agreement == "auditex_only":
                note = f"Microsoft scores this control as complete, but Auditex has {_plural(findings, 'open finding')} here."
            elif agreement == "microsoft_only":
                note = "Microsoft reports a gap and Auditex has no open finding; the rule may not have been assessed in this run."
            elif agreement == "agrees":
                note = f"Both flag a gap: {_plural(findings, 'open finding')}." if findings else "Neither Microsoft nor Auditex reports a gap."
            else:
                note = "Microsoft returned no score for this control in this run."
            score, maximum = control.get("microsoft_score"), control.get("microsoft_max_score")
            numeric = isinstance(score, (int, float)) and isinstance(maximum, (int, float)) and maximum
            rows.append(
                {
                    "id": _text(control.get("control_profile_id")),
                    "title": _text(control.get("title")),
                    "score": score,
                    "max": maximum,
                    "ms_status": _MS_STATE_LABELS.get(_text(control.get("microsoft_state")), _humanise(control.get("microsoft_state"))),
                    "verdict": verdict,
                    "agreement": agreement,
                    "highlight": agreement == "auditex_only",
                    "note": note,
                    "pct": round(100 * score / maximum, 1) if numeric else 0,
                }
            )
        secure_view = {
            "pct": overall.get("percentage"),
            "cur": overall.get("current_score"),
            "max": overall.get("max_score"),
            "agree": sum(1 for row in rows if row["verdict"] == "agree"),
            "disagree": sum(1 for row in rows if row["verdict"] == "disagree"),
            "na": sum(1 for row in rows if row["verdict"] == "not_assessed"),
            "rows": rows,
        }
    if not cards and secure_view is None:
        return None
    return {
        "frameworks": cards,
        "secure": secure_view,
        "secure_missing": "" if secure_view else "Secure Score was not collected in this run, so there is nothing to reconcile.",
    }


# --------------------------------------------------------------------------- run summary copy


def _assertions(data_handling: dict[str, Any]) -> list[dict[str, Any]]:
    assertions = data_handling.get("provider_assertions") if isinstance(data_handling.get("provider_assertions"), dict) else {}

    def flag(question: str, value: Any, field: str, yes_ok: bool, pill: str) -> dict[str, Any]:
        if value is None:
            return {"q": question, "a": "?", "status": "not_verified", "pill": "Not recorded", "src": f"{field} not recorded"}
        good = bool(value) == yes_ok
        return {
            "q": question,
            "a": "Yes" if value else "No",
            "status": "pass" if good else "fail",
            "pill": pill if good else "Check run",
            "src": f"{field} = {'true' if value else 'false'}",
        }

    content = data_handling.get("content_reads")
    if content is None:
        content = assertions.get("body_or_file_content_reads")
    scopes = data_handling.get("write_capable_scopes")
    scope_row: dict[str, Any]
    if not isinstance(scopes, list):
        scope_row = {"q": "Write-capable scopes held", "a": "?", "status": "not_verified", "pill": "Not recorded", "src": "write_capable_scopes not recorded"}
    elif scopes:
        scope_row = {"q": "Write-capable scopes held", "a": str(len(scopes)), "status": "fail", "pill": "Held, unused", "src": "write_capable_scopes = " + ", ".join(str(item) for item in scopes)}
    else:
        scope_row = {"q": "Write-capable scopes held", "a": "None", "status": "pass", "pill": "Verified", "src": "write_capable_scopes = []"}
    return [
        flag("Wrote to the tenant", data_handling.get("write_actions"), "data-handling.write_actions", False, "Read-only"),
        flag("Read mail bodies or file contents", content, "provider_assertions.body_or_file_content_reads", False, "Metadata only"),
        scope_row,
        flag("Captured raw secrets", assertions.get("raw_secret_capture"), "provider_assertions.raw_secret_capture", False, "Expiry only"),
    ]


def _verdict(
    grade: str,
    counts: dict[str, int],
    findings: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    coverage: dict[str, Any],
    detection: dict[str, Any] | None,
    nv_areas: list[dict[str, str]],
) -> tuple[str, str]:
    total = sum(counts.values())
    if coverage["not_selected"]:
        found = "Nothing was found" if not total else f"{_plural(total, 'finding')} were found"
        return (
            f"Only {coverage['verified']} of {coverage['all']} collectors ran. {found} in what was checked, but most of the tenant was not checked.",
            "Re-run with a fuller preset before relying on this grade.",
        )
    if grade == "critical":
        critical_paths = [path for path in paths if path["severity"] == "critical"] or paths
        if critical_paths:
            phrase = _FOOTHOLD_PHRASES.get(critical_paths[0]["foothold"], "one compromised account")
            verdict = f"Someone with {phrase} could take full control of this tenant."
        else:
            verdict = f"{_plural(counts['critical'], 'critical issue')} {'is' if counts['critical'] == 1 else 'are'} open in this tenant."
        if any(
            row["severity"] == "critical" and row["area"] == "mail_flow" and row["status"] == "open"
            and any(word in _text(row.get("rule_id")) for word in ("forward", "redirect"))
            for row in findings
        ):
            verdict += " Mail is already being sent outside the company."
        return verdict, f"{_plural(counts['critical'], 'critical issue')} need{'s' if counts['critical'] == 1 else ''} action this week."
    if grade == "high":
        lead = "No critical issues remain." if not counts["critical"] else f"{_plural(counts['critical'], 'critical issue')} remain{'s' if counts['critical'] == 1 else ''}."
        tail = (
            f" {_plural(len(paths), 'route')} to admin control {'is' if len(paths) == 1 else 'are'} still open."
            if paths
            else " No route to admin control was found."
        )
        return lead + tail, f"Next: {_plural(counts['high'], 'high-severity item')}."
    if grade == "medium":
        areas: dict[str, int] = {}
        for row in findings:
            areas[row["area_label"]] = areas.get(row["area_label"], 0) + 1
        top = sorted(areas.items(), key=lambda item: (-item[1], item[0]))[0][0] if areas else "Configuration"
        verdict = f"No critical or high-severity issues are open. {top} needs the most work."
        if nv_areas:
            verdict += " Some areas were not checked, so this grade may be optimistic."
            return verdict, "Re-run with full coverage to confirm the grade."
        return verdict, f"Next: {_plural(counts['medium'], 'medium-severity item')}."
    sees = detection is not None and isinstance(detection.get("score"), (int, float)) and detection["score"] >= 80
    lead = "No route to admin control was found" if not paths else f"{_plural(len(paths), 'route')} to admin control remain"
    verdict = lead + (" and the tenant can see an attack." if sees else ".")
    if total:
        verdict += f" {_plural(total, 'minor item')} to tidy up."
    return verdict, "Keep the quarterly re-audit."


def _banners(synthetic: bool, provenance: dict[str, Any], mode: str, coverage: dict[str, Any], preset: str) -> list[dict[str, str]]:
    banners = []
    if synthetic:
        banners.append(
            {
                "kind": "synthetic",
                "title": "Synthetic demo data · offline replay",
                "text": "Every person, company, domain and event in this run is fictional (reserved .example domains). No live tenant was contacted.",
            }
        )
    elif mode == "offline":
        banners.append(
            {
                "kind": "synthetic",
                "title": "Offline replay",
                "text": _text(provenance.get("description")) or "This run replays a saved sample. No live tenant was contacted.",
            }
        )
    if coverage["not_selected"]:
        banners.append(
            {
                "kind": "partial",
                "title": f'Limited run · preset "{preset}"' if preset else "Limited run",
                "text": f"{coverage['selected']} of {coverage['all']} collectors were selected. Sections with no data say so rather than showing a pass.",
            }
        )
    elif coverage["not_verified"]:
        banners.append(
            {
                "kind": "partial",
                "title": f"Partial run · {coverage['not_verified']} of {coverage['all']} collectors not verified",
                "text": "Areas Auditex could not check are shown as Not verified. They are never counted as passed or failed.",
            }
        )
    return banners


# --------------------------------------------------------------------------- run payload


def _path_headline(foothold: str, target: str, hop_count: int) -> str:
    """Short path title; the engine's full sentence stays in the expanded body."""
    who = _FOOTHOLD_LABELS.get(foothold, _humanise(foothold) or "A foothold")
    reach = target.removeprefix("Microsoft Graph ").strip() or "tier-0 control"
    steps = f"{hop_count} step" + ("" if hop_count == 1 else "s")
    return f"{who} can reach {reach} in {steps}" if hop_count else f"{who} can reach {reach}"


def build_explorer_data(run_dir: Path | str) -> dict[str, Any]:
    """Return the explorer payload for one finalized run directory."""
    run_dir = Path(run_dir)
    manifest = _read_json(run_dir / "run-manifest.json", {})
    manifest = manifest if isinstance(manifest, dict) else {}
    report_pack = _read_json(run_dir / "reports" / "report-pack.json", {})
    report_pack = report_pack if isinstance(report_pack, dict) else {}
    raw_findings = _read_json(run_dir / "findings" / "findings.json", [])
    raw_findings = raw_findings if isinstance(raw_findings, list) else []
    data_handling = _read_json(run_dir / "data-handling.json", {})
    data_handling = data_handling if isinstance(data_handling, dict) else {}
    validation = _read_json(run_dir / "validation.json", {})
    validation = validation if isinstance(validation, dict) else {}
    summary = report_pack.get("summary") if isinstance(report_pack.get("summary"), dict) else {}
    risk = summary.get("risk") if isinstance(summary.get("risk"), dict) else {}
    provenance = manifest.get("fixture_provenance") or report_pack.get("fixture_provenance") or {}
    provenance = provenance if isinstance(provenance, dict) else {}

    proof_rows = [
        {key: row.get(key) for key in ("finding_id", "proof_status", "confidence", "evidence_count", "artifacts", "blast_radius")}
        for row in report_pack.get("proof_table") or []
        if isinstance(row, dict)
    ]
    findings = _finding_rows(raw_findings, proof_rows)
    paths = _attack_paths([path for path in report_pack.get("attack_paths") or [] if isinstance(path, dict)])
    detection_raw = report_pack.get("detection_coverage") if isinstance(report_pack.get("detection_coverage"), dict) else {}
    detection = _detection(detection_raw, run_dir)
    baselines = _baselines(report_pack.get("baseline_alignment") if isinstance(report_pack.get("baseline_alignment"), dict) else {})
    collectors = _collector_rows(run_dir, manifest, data_handling)
    coverage = {
        "verified": sum(1 for row in collectors if row["status"] == "verified"),
        "not_verified": sum(1 for row in collectors if row["status"] == "not_verified"),
        "not_selected": sum(1 for row in collectors if row["status"] == "not_selected"),
        "all": len(collectors),
    }
    coverage["selected"] = coverage["all"] - coverage["not_selected"]
    nv_areas = _nv_areas(manifest, collectors)

    refs: list[tuple[str, str]] = []
    for path in paths:
        refs.extend((hop["evidence"]["artifact"], hop["evidence"]["key"]) for hop in path["hops"] if hop["evidence"]["key"])
    for signal in detection_raw.get("signals") or []:
        ref = _ref_key(signal.get("evidence_ref")) if isinstance(signal, dict) else None
        if ref:
            refs.append(ref)
    for finding in findings:
        refs.extend(ref for ref in (_ref_key(item) for item in finding["evidence_refs"]) if ref)

    counts = {severity: sum(1 for row in findings if row["severity"] == severity) for severity in _SEVERITIES}
    open_counts = {severity: sum(1 for row in findings if row["severity"] == severity and row["status"] == "open") for severity in _SEVERITIES}
    score = risk.get("score") if isinstance(risk.get("score"), (int, float)) else 0
    grade = _text(risk.get("grade")) or "clean"
    verdict, action = _verdict(grade, open_counts, findings, paths, coverage, detection, nv_areas)
    mode = _text(manifest.get("mode"))
    platform = _text(manifest.get("platform") or data_handling.get("platform") or "m365")
    synthetic = bool(provenance.get("synthetic")) or _text(provenance.get("seed_kind")) == "demo"
    preset = _text(manifest.get("collector_preset"))
    attack_graph = report_pack.get("attack_graph") if isinstance(report_pack.get("attack_graph"), dict) else {}

    return {
        "tenant": manifest.get("tenant_name") or summary.get("tenant_name"),
        "run_id": manifest.get("run_id"),
        "run_name": run_dir.name,
        "created_utc": manifest.get("created_utc"),
        "collected_label": _collected_label(manifest.get("created_utc")),
        "mode": mode,
        "mode_label": "Offline replay" if mode == "offline" else "Live, read-only" if mode == "live" else _humanise(mode) or "Unknown",
        "platform": platform,
        "platform_label": {"m365": "Microsoft 365", "google_workspace": "Google Workspace"}.get(platform, _humanise(platform)),
        "plane": _text(manifest.get("plane")),
        "preset": preset,
        "meta": _tenant_meta(run_dir, manifest),
        "synthetic": synthetic,
        "provenance": provenance,
        "contract_valid": bool(validation.get("valid")),
        "risk": {"score": score, "grade": grade if grade in (*_SEVERITIES, "clean") else "info"},
        "verdict": verdict,
        "action": action,
        "summary": summary,
        "counts": counts,
        "open_count": sum(open_counts.values()),
        "accepted_count": sum(1 for row in findings if row["status"] == "accepted"),
        "findings": findings,
        "proof": proof_rows,
        "attack_paths": paths,
        "attack_graph": {key: attack_graph.get(key) for key in ("node_count", "edge_count", "footholds", "tier0_targets", "path_count") if key in attack_graph},
        "evidence": _evidence_records(run_dir, refs),
        "detection": detection,
        "baselines": baselines,
        "data_handling": {
            key: data_handling.get(key)
            for key in ("read_only", "content_reads", "write_actions", "scope_risk", "write_capable_scopes", "provider_assertions")
        },
        "assertions": _assertions(data_handling),
        "collectors": collectors,
        "coverage": coverage,
        "nv_areas": nv_areas,
        "banners": _banners(synthetic, provenance, mode, coverage, preset),
        "public_footprint": report_pack.get("public_footprint"),
    }


# --------------------------------------------------------------------------- multiple runs


class ExplorerCompareError(ValueError):
    """Raised when runs passed to the explorer cannot be compared."""


def _compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    old = {row["id"]: row for row in before["findings"]}
    new = {row["id"]: row for row in after["findings"]}
    resolved = [row for key, row in old.items() if key not in new]
    added = [row for key, row in new.items() if key not in old]
    changed = [
        {"title": new[key].get("title"), "object": new[key]["object"], "severity": old[key]["severity"], "to_severity": new[key]["severity"]}
        for key in old
        if key in new and old[key]["severity"] != new[key]["severity"]
    ]
    rows = []
    for severity in _SEVERITIES:
        rows.append(
            {
                "severity": severity,
                "before": before["counts"][severity],
                "after": after["counts"][severity],
                "resolved": sum(1 for row in resolved if row["severity"] == severity),
                "added": sum(1 for row in added if row["severity"] == severity),
                "changed_out": sum(1 for row in changed if row["severity"] == severity),
                "changed_in": sum(1 for row in changed if row["to_severity"] == severity),
            }
        )

    def brief(row: dict[str, Any]) -> dict[str, Any]:
        return {"title": row.get("title"), "object": row["object"], "severity": row["severity"]}

    def run_ref(run: dict[str, Any]) -> dict[str, Any]:
        return {
            "run_name": run["run_name"],
            "label": run["collected_label"],
            "grade": run["risk"]["grade"],
            "score": run["risk"]["score"],
            "findings": len(run["findings"]),
        }

    def detection_score(run: dict[str, Any]) -> Any:
        return (run.get("detection") or {}).get("score")

    return {
        "a": run_ref(before),
        "b": run_ref(after),
        "rows": rows,
        "resolved": [brief(row) for row in resolved],
        "added": [brief(row) for row in added],
        "changed": changed,
        "paths_before": len(before["attack_paths"]),
        "paths_after": len(after["attack_paths"]),
        "det_before": detection_score(before),
        "det_after": detection_score(after),
    }


def build_explorer_bundle(run_dirs: Path | str | Sequence[Path | str]) -> dict[str, Any]:
    """Return the page payload for one or more runs.

    The first run directory is the run shown on open. Runs are ordered oldest
    first; the comparison is oldest against newest. Runs of different tenants
    or platforms are refused, mirroring ``auditex compare``'s same-tenant gate.
    """
    dirs = [Path(run_dirs)] if isinstance(run_dirs, (str, Path)) else [Path(item) for item in run_dirs]
    if not dirs:
        raise ExplorerCompareError("at least one run directory is required")
    runs = [build_explorer_data(path) for path in dirs]
    if len(runs) > 1:
        from .compare import _tenant_gate

        gate = _tenant_gate(
            [{"tenant_id": run["meta"].get("tenant_id") or None, "tenant_name": run.get("tenant"), "platform": run.get("platform")} for run in runs]
        )
        if gate["gate"] != "same_tenant":
            raise ExplorerCompareError(
                f"refusing to compare runs from different tenants or platforms ({gate['gate']}); "
                "pass runs of one tenant, or write one explorer per tenant"
            )
    primary = runs[0]
    order = sorted(range(len(runs)), key=lambda index: (_text(runs[index].get("created_utc")), runs[index]["run_name"], index))
    ordered = [runs[index] for index in order]
    return {
        "format": "auditex-explorer",
        "format_version": FORMAT_VERSION,
        "generator": _generator_label(),
        "risk_bands": [{"grade": grade, "from": low, "to": high} for grade, low, high in _RISK_BANDS],
        "runs": ordered,
        "default_run": ordered.index(primary),
        "compare": _compare(ordered[0], ordered[-1]) if len(ordered) > 1 else None,
    }


def _generator_label() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return f"Auditex {version('auditex')}"
    except PackageNotFoundError:  # pragma: no cover - running from a bare source tree
        return "Auditex"


# --------------------------------------------------------------------------- rendering


def _asset(name: str) -> str:
    return importlib_resources.files("auditex").joinpath("explorer_assets", name).read_text(encoding="utf-8")


# Barlow and Barlow Condensed (SIL Open Font License 1.1, Google Fonts), embedded so the page
# still makes no network requests. Licence: explorer_assets/fonts/OFL.txt.
_EMBEDDED_FONTS = (
    ("Barlow", 400, "Barlow-400"),
    ("Barlow", 600, "Barlow-600"),
    ("Barlow Condensed", 600, "BarlowCondensed-600"),
)


def _font_faces() -> str:
    fonts = importlib_resources.files("auditex").joinpath("explorer_assets", "fonts")
    rules = ["/* Barlow, Barlow Condensed: Copyright 2017 The Barlow Project Authors, SIL Open Font License 1.1 */"]
    for family, weight, stem in _EMBEDDED_FONTS:
        for subset in ("latin-ext", "latin"):
            data = base64.b64encode(fonts.joinpath(f"{stem}-{subset}.woff2").read_bytes()).decode("ascii")
            unicode_range = fonts.joinpath(f"{stem}-{subset}.woff2.range").read_text(encoding="utf-8").strip()
            rules.append(
                f"@font-face{{font-family:'{family}';font-style:normal;font-weight:{weight};font-display:swap;"
                f"src:url(data:font/woff2;base64,{data}) format('woff2');unicode-range:{unicode_range}}}"
            )
    return "\n".join(rules) + "\n"


def _logo_data_uri() -> str:
    try:
        payload = resolve_resource_path("assets/auditex-logo-64.png").read_bytes()
    except OSError:
        return ""
    return "data:image/png;base64," + base64.b64encode(payload).decode("ascii")


def _embed_json(payload: Any) -> str:
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    # "<\/" keeps tenant strings from closing the script element; ":\/\/" keeps
    # tenant URLs out of the page text. Both are plain JSON escapes of "/".
    return text.replace("</", "<\\/").replace("://", ":\\/\\/").replace("<!--", "<\\u0021--")


def script_hash(script: str) -> str:
    """CSP source expression for an inline script body."""
    return "'sha256-" + base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii") + "'"


def render_explorer_html(data: dict[str, Any] | list[dict[str, Any]]) -> str:
    """Render a page from a bundle (``build_explorer_bundle``) or one run payload."""
    if isinstance(data, list):
        bundle = {"runs": data, "default_run": 0, "compare": _compare(data[0], data[-1]) if len(data) > 1 else None}
    elif "runs" in data:
        bundle = data
    else:
        bundle = {"runs": [data], "default_run": 0, "compare": None}
    bundle = {
        "format": "auditex-explorer",
        "format_version": FORMAT_VERSION,
        "generator": _generator_label(),
        "risk_bands": [{"grade": grade, "from": low, "to": high} for grade, low, high in _RISK_BANDS],
        **bundle,
    }
    script = _asset("explorer.js")
    style = _font_faces() + _asset("explorer.css")
    primary = bundle["runs"][bundle.get("default_run") or 0]
    tenant = (primary.get("meta") or {}).get("display_name") or primary.get("tenant") or "run"
    csp = f"default-src 'none'; script-src {script_hash(script)}; style-src 'unsafe-inline'; img-src data:; font-src data:; base-uri 'none'; form-action 'none'"
    logo = _logo_data_uri()
    replacements = {
        "__CSP__": html.escape(csp, quote=True),
        "__TITLE__": html.escape(f"Auditex run explorer · {tenant}").replace("://", "&#58;//"),
        "__STYLE__": style,
        "__LOGO__": f'<img class="ax-logo" src="{logo}" alt="" width="28" height="28">' if logo else "",
        "__DATA__": _embed_json(bundle),
        "__SCRIPT__": script,
    }
    # One pass over the template: substituted text (which carries tenant data)
    # is never scanned for markers again.
    return re.sub(r"__(?:CSP|TITLE|STYLE|LOGO|DATA|SCRIPT)__", lambda match: replacements[match.group(0)], _asset("explorer.html"))


def write_explorer(run_dirs: Path | str | Sequence[Path | str], output_path: Path | str) -> Path:
    """Write the explorer for one run, or several runs of one tenant, to ``output_path``."""
    bundle = build_explorer_bundle(run_dirs)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_explorer_html(bundle), encoding="utf-8", newline="\n")
    return output
