"""Rule-only SCuBA assessment: the deterministic writer of ``model_assessment.json``.

Every verdict comes from the value rules (``azure_tenant_audit.value_rules``) through ``precheck_policy``; the explainer
is a template over the rule answer and never decides a verdict. Nothing here calls a model or the network.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import logging
import os
from pathlib import Path
import re
from typing import Any

from azure_tenant_audit.collection_markers import NOT_COLLECTED
from azure_tenant_audit.explainer import explain as render_explanation
from azure_tenant_audit.external_sharing import ENUM_NAME_KEYS, annotate_enum_names
from azure_tenant_audit.guarded_io import UnsafeRunFileError, current_context, guarded_operation, read_guarded_bytes
from azure_tenant_audit.output_redaction import PROFILE_EXPLAINER, RedactionContext, context_for_run, redact_output
from azure_tenant_audit.private_io import make_private_dirs, write_private_text
from azure_tenant_audit.resources import open_text_resource
from azure_tenant_audit.scuba_assessment import validate_explainer, value_rule_verdict
from azure_tenant_audit.scuba_precheck import optional_collection_entry, precheck_policy, precheck_response

from .scope_postcheck import collect_scope_evidence
from .scuba_projection import (
    DEFAULT_MAX_CHARS, DEFAULT_MAX_ITEMS, DEFAULT_SCAN_MAX_BYTES, DEFAULT_SCAN_MAX_CHUNKS, DEFAULT_SCAN_MAX_ROWS,
    policy_section, project_run, rule_policy_section,
)

SCHEMA_VERSION = "2026-11-05"
PROMPT_CONVENTION = "named-enums-v1"
# The recorded SHA-256 of the retired P1 system prompt. The assessment schema and older readers expect the envelope
# key, so it stays a pinned literal; no prompt is built or sent.
SYSTEM_PROMPT_SHA256 = "cce70bf27aa2f844ce4d2aa79d52473b295c657102199538985f1edef14fd776"
RULE_NOT_IMPLEMENTED_TEXT = "Not assessed: Auditex has no rule for this policy yet."
ASSESSMENT_FILENAME = "model_assessment.json"
_POLICY_ID = re.compile(r"MS\.[A-Z]+\.\d+\.\d+v\d+")
LOG = logging.getLogger(__name__)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def policy_catalogue() -> dict[str, Any]:
    return json.loads(open_text_resource("configs/scuba-policy-sections.json"))


class PolicyUnavailable(ValueError):
    """A policy absent from the catalogue cannot be assessed."""


def _identity_view(value: Any) -> Any:
    # conv3 IDs predate enum annotation. Strip only the seven derived names,
    # and only in SPO_tenant, retaining every original numeric value.
    if isinstance(value, list):
        return [_identity_view(item) for item in value]
    if isinstance(value, dict):
        names = {f"{key}_name" for key in ENUM_NAME_KEYS if key in value}
        return {key: _identity_view(item) for key, item in value.items() if key not in names}
    return value


def build_case(policy_id: str, projection: dict[str, Any], as_of: str, *,
               catalogue: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build exactly the training user object; serialise with :func:`canonical`.

    ``as_of`` belongs to the assessment envelope, not the training user shape.
    Case IDs are serving-generated and are not reproducible for pack rows,
    whose IDs also depend on generator inputs unavailable in a serving run.
    No timestamp or additional user-message field is introduced.
    """
    data = catalogue if catalogue is not None else policy_catalogue()
    if policy_id not in data["policies"]:
        raise PolicyUnavailable("policy_not_in_catalogue")
    entry = data["policies"][policy_id]
    item = entry["policy_item"]
    observed = {section: policy_section(projection, policy_id, section) for section in entry["sections"]}
    identity = {section: _identity_view(value) if section == "SPO_tenant" else value
                for section, value in observed.items()}
    view_hash = sha256(f"conv3:{canonical(identity)}".encode("utf-8", "surrogatepass")).hexdigest()[:10]
    product = policy_id.split(".")[1].lower()
    case_id = f"scuba-{product}-{policy_id.lower().replace('.', '-')}-{view_hash}"
    evidence = [{"id": "e0", "observed": dict(item), "section": "policy"}]
    evidence.extend({"id": f"e{index}", "observed": annotate_enum_names(section, value), "section": section}
                    for index, (section, value) in enumerate(observed.items(), start=1))
    # Round-trip sorts every nested key just as the training samples do.
    return json.loads(canonical({
        "case_id": case_id, "evidence": evidence, "limitation_ids": data["limitation_ids"],
        "policy_id": policy_id, "recommendation_ids": data["recommendation_ids"],
        "requested_claims": [
            {"id": "requirement_met", "question": f"Does this tenant meet {policy_id}?"},
            {"id": "policy_criticality", "question": "What criticality does the baseline assign to this policy?"},
        ],
    }))


def precheck_case(case: dict[str, Any], *, skip_absent_sections: bool = False,
                  named_limitations: bool = True, absent_fields: bool = False,
                  empty_lists: bool = False, value_rules: bool = False,
                  rule_projection: dict[str, Any] | None = None, explain: bool = False,
                  redaction_context: RedactionContext | None = None) -> dict[str, Any] | None:
    sections = [item["section"] for item in case["evidence"][1:]]
    projection = {item["section"]: item["observed"] for item in case["evidence"][1:]}
    detail = None
    optional = optional_collection_entry()
    optional_policy = optional["policies"].get(case["policy_id"])
    if optional_policy and rule_projection is not None:
        missing = [s for s in sections if s in optional_policy["sections"]
                   and isinstance(rule_projection.get(s), dict)
                   and rule_projection[s].get("collection_status") == "not_collected"
                   and rule_projection[s].get("reason") == optional["reason_code"]]
        if missing:
            detail = {"class": "absent_section", "rule_id": "required_sections_present",
                      "section": missing, "field": None, "value": None,
                      "reason_code": optional["reason_code"], "reason_text": optional["reason_text"]}
    row = None
    if value_rules:
        from azure_tenant_audit.value_rules.catalogue import row_for
        row = row_for(case["policy_id"])
    if row is not None and detail is None:
        # A value-rule policy: the rule view when serving supplies one, else the case evidence.
        rule_input, rule_sections = ((rule_projection, list(row["sections"])) if rule_projection is not None
                                     else (projection, sections))
        try:
            candidate = precheck_policy(case["policy_id"], rule_input, rule_sections,
                                        skip_absent_sections=skip_absent_sections, value_rules=True,
                                        absent_fields=absent_fields, empty_lists=empty_lists)
        except (UnsafeRunFileError, MemoryError):
            raise
        except Exception as exc:
            # Log the rule id and the exception class name only: the message and repr can hold tenant evidence.
            LOG.warning("Value rule %s failed (%s); the row is answered not assessed",
                        row["rule_id"], type(exc).__name__)
            # The fault is ours, not the evidence's (main, 5 Nov 07:12 GMT): the catalogued rule_evaluation_failed
            # answer, a constant text and the report_product_fault recommendation. Never render the exception.
            from azure_tenant_audit.value_rules import rule_failure
            failed = rule_failure(case["policy_id"])
            candidate = {"class": "value_rule", "rule_id": row["rule_id"], "section": failed["cited_sections"],
                         "field": None, "value": None, "cell": failed["cell"],
                         "reason_code": failed["reason_code"], "reason_text": failed["reason_text"]}
        if rule_projection is None or candidate is not None and candidate["class"] in {"value_rule", "closed_gate"}:
            detail = candidate
    if detail is None and (row is None or rule_projection is not None):
        detail = precheck_policy(case["policy_id"], projection, sections,
                                 skip_absent_sections=skip_absent_sections, absent_fields=absent_fields,
                                 empty_lists=empty_lists, value_rules=False)
    if detail is None:
        return None
    record = {**precheck_response(detail, case["evidence"][0]["observed"], sections,
                                  named_limitations=named_limitations),
              "policy_id": case["policy_id"], "rule_precheck": detail,
              "validation_status": "valid", "reason": "rule_precheck", "latency_ms": 0,
              "attempts": 0, "prompt_sha256": None, "response_sha256": None,
              "thinking_disabled": False, "thinking_stripped": False}
    if explain and detail["class"] == "value_rule":
        try:
            # The case must carry the complete fixed read set, even if this cell cites only a subset.
            if row is None or not set(row["sections"]) <= set(sections):
                return record
            # Only the public rule answer and the case's redacted model-view evidence cross this boundary.
            public = {"policy_id": record["policy_id"], "verdict": value_rule_verdict(record),
                      "cell": detail["cell"], "reason_code": detail["reason_code"],
                      "reason_text": detail["reason_text"], "cited_sections": list(detail["section"])}
            explanation = render_explanation(public, deepcopy(projection), list(sections))
            safe = redact_output(explanation, profile=PROFILE_EXPLAINER, context=redaction_context)
            validate_explainer(record, safe)
            record["explainer"] = safe
        except (UnsafeRunFileError, MemoryError):
            raise
        except Exception as exc:
            LOG.debug("Explainer %s failed (%s)", case["policy_id"], type(exc).__name__)
    return record


def _comparison(policy_id: str, record: dict[str, Any], baseline: dict[str, str]) -> dict[str, Any]:
    rule_status = baseline.get(policy_id)
    match = "exact" if policy_id in baseline else "none"
    if match == "none":
        unversioned = re.sub(r"v\d+$", "", policy_id)
        candidates = [status for pid, status in baseline.items() if re.sub(r"v\d+$", "", pid) == unversioned]
        if len(candidates) == 1:
            rule_status, match = candidates[0], "version_mismatch"
    requirement = next((claim for claim in record["claims"] if claim["id"] == "requirement_met"), {})
    model_status = None
    if record["validation_status"] == "valid" and requirement.get("status") == "confirmed":
        model_status = "pass" if requirement.get("value") is True else "fail"
    agreement = "not_assessed"
    if rule_status in {"pass", "fail"} and model_status is not None:
        agreement = "agree" if rule_status == model_status else "disagree"
    return {"baseline_status": rule_status, "baseline_match": match, "model_status": model_status, "result": agreement}


def _baseline_statuses(pack_path: Path) -> dict[str, str]:
    """Ignore malformed optional report-pack comparison data."""
    try:
        node = json.loads(read_guarded_bytes(pack_path, field="input").decode("utf-8"))
        for key in ("baseline_alignment", "frameworks", "cisa_scuba", "controls"):
            node = node.get(key) if isinstance(node, dict) else None
        if not isinstance(node, list):
            return {}
        return {row["control_id"]: row["status"] for row in node if isinstance(row, dict)
                and isinstance(row.get("control_id"), str)
                and row.get("status") in ("pass", "fail", "accepted_risk", "not_assessed")}
    except UnsafeRunFileError:
        raise
    except (OSError, ValueError, RecursionError):
        return {}


def _uncovered_record(case: dict[str, Any]) -> dict[str, Any]:
    return {"policy_id": case["policy_id"],
            "claims": [{"id": item["id"], "status": "unknown", "value": None, "evidence_ids": []}
                       for item in case["requested_claims"]],
            "limitations": [], "recommendations": [], "validation_status": "unknown",
            "reason": "rule_not_implemented", "reason_text": RULE_NOT_IMPLEMENTED_TEXT,
            "latency_ms": 0, "attempts": 0, "prompt_sha256": None, "response_sha256": None,
            "thinking_disabled": False, "thinking_stripped": False}


def _skipped_record(policy_id: str) -> dict[str, Any]:
    return {"policy_id": policy_id, "claims": [], "limitations": [], "recommendations": [],
            "validation_status": "skipped", "reason": "policy_not_in_catalogue", "latency_ms": 0,
            "attempts": 0, "prompt_sha256": None, "response_sha256": None,
            "thinking_disabled": False, "thinking_stripped": False}


def _assess_policies(projection: dict[str, Any], selected: list[str], catalogue: dict[str, Any], generated_at: str, *,
                     baseline: dict[str, str], explainer_context: RedactionContext | None = None,
                     explainer_context_error: str | None = None) -> list[dict[str, Any]]:
    records = []
    for policy_id in selected:
        try:
            case = build_case(policy_id, projection, generated_at, catalogue=catalogue)
        except PolicyUnavailable:
            record = _skipped_record(policy_id)
        else:
            from azure_tenant_audit.value_rules.catalogue import row_for
            row = row_for(policy_id)
            rule_projection = None
            if hasattr(projection, "rule_sections"):
                if row:
                    rule_projection = {section: deepcopy(projection.rule_sections.get(section, NOT_COLLECTED))
                                       for section in row["sections"] if section != "scuba_config"}
                    # stage 4: optional evidence informs the rule without becoming required or cited.
                    rule_projection.update({section: deepcopy(projection.rule_sections[section])
                                            for section in row.get("optional_sections", [])
                                            if section in projection.rule_sections})
                    if "scuba_config" in row["sections"]:
                        rule_projection["scuba_config"] = deepcopy(rule_policy_section(projection, policy_id, "scuba_config"))
            record = (precheck_case(case, absent_fields=True, empty_lists=True, value_rules=True,
                                    rule_projection=rule_projection, explain=explainer_context is not None,
                                    redaction_context=explainer_context) if row else None)
            if record is None:
                record = _uncovered_record(case)
            elif explainer_context_error and record["rule_precheck"]["class"] == "value_rule":
                LOG.debug("Explainer %s failed (%s)", policy_id, explainer_context_error)
        record["comparison"] = _comparison(policy_id, record, baseline)
        records.append(record)
    return records


def _totals(records: list[dict[str, Any]]) -> dict[str, int]:
    # Keep the historical total in current output; row-level scope metadata is no longer produced.
    totals = {"answered": 0, "unknown": 0, "invalid": 0, "skipped": 0, "rule_answered": 0,
              "scope_narrowed": 0}
    for record in records:
        totals["rule_answered"] += record["reason"] == "rule_precheck"
        state = record["validation_status"]
        if state in {"invalid", "skipped"}:
            totals[state] += 1
        elif state == "unknown" or any(c["id"] == "requirement_met" and c["status"] == "unknown" for c in record["claims"]):
            totals["unknown"] += 1
        else:
            totals["answered"] += 1
    return totals


def _selected_policies(catalogue: dict[str, Any], policies: list[str] | None) -> list[str]:
    selected = list(catalogue["policies"]) if policies is None else policies
    if not selected or len(set(selected)) != len(selected) or any(not _POLICY_ID.fullmatch(pid) for pid in selected):
        raise ValueError("Policies must be unique SCuBA policy IDs")
    return selected


def _admit_run(run_dir: str | Path, policies: list[str] | None,
               filename: str) -> tuple[Path, dict[str, Any], dict[str, Any], list[str]]:
    """Bind the run, check its manifest and the selection, and refuse a sealed or linked output file."""
    root = Path(os.path.abspath(os.path.expanduser(run_dir)))
    current_context().bind_run(root)
    from azure_tenant_audit.run_files import read_run_file
    manifest = json.loads(read_run_file(root, "run-manifest.json").decode("utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("run_id"), str) or not manifest["run_id"]:
        raise ValueError("Run manifest requires a run_id")
    catalogue = policy_catalogue()
    selected = _selected_policies(catalogue, policies)
    # Never replace a file already sealed into the original bundle.
    from azure_tenant_audit.bundle_integrity import listed_artifact_paths
    if filename in (listed_artifact_paths(root) or ()):
        raise ValueError("Model output is already sealed in this bundle; use a fresh run copy")
    if (root / filename).is_symlink():
        raise ValueError("Model output must not be a symbolic link")
    return root, manifest, catalogue, selected


def _envelope(projection: Any, records: list[dict[str, Any]], scope: Any, *, generated_at: str,
              run_id: str) -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "generated_at": generated_at, "run_id": run_id,
            "endpoint_host": "none", "model_name": "rules-only",
            "prompt_convention": PROMPT_CONVENTION, "system_prompt_sha256": SYSTEM_PROMPT_SHA256,
            "totals": _totals(records), "policies": records,
            "projection": projection.report, "scope_post_check": scope.summary,
            "limitations": [] if any(v != NOT_COLLECTED for v in projection.values()) else ["projection_not_implemented"]}


@guarded_operation
def assess_run(run_dir: str | Path, *, policies: list[str] | None = None,
               projection_max_items: int = DEFAULT_MAX_ITEMS, projection_max_chars: int = DEFAULT_MAX_CHARS,
               projection_scan_max_rows: int = DEFAULT_SCAN_MAX_ROWS,
               projection_scan_max_bytes: int = DEFAULT_SCAN_MAX_BYTES,
               projection_scan_max_chunks: int = DEFAULT_SCAN_MAX_CHUNKS) -> dict[str, Any]:
    """Write ``model_assessment.json`` for a finished run from the value rules alone."""
    root, manifest, catalogue, selected = _admit_run(run_dir, policies, ASSESSMENT_FILENAME)
    target = root / ASSESSMENT_FILENAME
    generated_at = datetime.now(timezone.utc).isoformat()
    projection = project_run(root, redact=True, max_items=projection_max_items,
                             max_chars=projection_max_chars, scan_max_rows=projection_scan_max_rows,
                             scan_max_bytes=projection_scan_max_bytes, scan_max_chunks=projection_scan_max_chunks)
    baseline = _baseline_statuses(root / "reports" / "report-pack.json")
    # Read-only and verdict-independent: which enabled Conditional Access policies carry a scope condition the
    # pinned Rego ignores. The envelope carries this caveat.
    scope = collect_scope_evidence(
        root, projection, redact=True, max_items=projection_max_items,
        scan_max_rows=projection_scan_max_rows, scan_max_bytes=projection_scan_max_bytes,
        scan_max_chunks=projection_scan_max_chunks)
    explainer_context = None
    explainer_context_error = None
    try:
        explainer_context = context_for_run(root)
    except (UnsafeRunFileError, MemoryError):
        raise
    except Exception as exc:
        explainer_context_error = type(exc).__name__
    records = _assess_policies(projection, selected, catalogue, generated_at, baseline=baseline,
                               explainer_context=explainer_context, explainer_context_error=explainer_context_error)
    result = _envelope(projection, records, scope, generated_at=generated_at, run_id=manifest["run_id"])
    from azure_tenant_audit.scuba_assessment import validate_assessment
    validate_assessment(result)
    write_private_text(target, json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
    return result


def _export_view(export_path: str | Path, output_dir: str | Path, *, results_path: str | Path | None,
                 policies: list[str] | None, projection_max_items: int, projection_max_chars: int,
                 verdict_map: dict[str, str]) -> dict[str, Any]:
    """Load, project and read the verdicts of a ScubaGear export; shared by every export writer."""
    from .scubagear_export import (
        build_baseline, load_export, load_results, project_export, resolve_output_directory, scubaresults_layout_ok,
    )
    target_dir = resolve_output_directory(output_dir)
    catalogue = policy_catalogue()
    selected = _selected_policies(catalogue, policies)
    loaded = load_export(export_path)
    projection, extras = project_export(loaded, catalogue["policies"], redact=True,
                                        max_items=projection_max_items, max_chars=projection_max_chars)
    verdict_error = False
    if results_path is not None:
        try:
            verdict_rows, verdict_kind = load_results(results_path)
        except UnsafeRunFileError:
            raise
        except (OSError, ValueError):
            verdict_rows, verdict_kind, verdict_error = None, "none", True
        verdict_source = "results_file"
    elif loaded.kind == "scubaresults":
        verdict_rows, verdict_kind = loaded.results, "scubaresults"
        verdict_source = "embedded"
    else:
        verdict_rows, verdict_kind, verdict_source = None, "none", "none"
    layout_error = verdict_kind == "scubaresults" and not scubaresults_layout_ok(verdict_rows)
    if ("Results" in loaded.repaired_keys and results_path is None) or layout_error:
        verdict_rows, verdict_kind = None, "none"
    baseline, reasons, unmappable = build_baseline(
        verdict_rows, loaded.raw, kind=verdict_kind, repaired_keys=loaded.repaired_keys,
        verdict_map=verdict_map, catalogue_ids=set(catalogue["policies"]))
    if "Results" in loaded.repaired_keys and results_path is None:
        verdict_state = "unreadable_repaired"
    elif verdict_error:
        verdict_state = "unreadable_file"
    elif verdict_source == "none":
        verdict_state = "absent"
    elif layout_error:
        verdict_state = "unreadable_layout"
    elif not baseline:
        verdict_state = "empty"
    else:
        verdict_state = "readable"
    return {"target_dir": target_dir, "catalogue": catalogue, "selected": selected, "loaded": loaded,
            "projection": projection, "extras": extras, "baseline": baseline, "reasons": reasons,
            "unmappable": unmappable, "verdict_source": verdict_source, "verdict_state": verdict_state,
            "generated_at": datetime.now(timezone.utc).isoformat()}


def _export_sidecar(view: dict[str, Any], scope: Any, verdict_map: dict[str, str]) -> dict[str, Any]:
    from .scubagear_export import build_sidecar
    return build_sidecar(view["loaded"], view["projection"], view["extras"], view["catalogue"]["policies"],
                         view["selected"], view["baseline"], view["reasons"], view["unmappable"],
                         view["verdict_source"], view["verdict_state"], verdict_map, view["generated_at"], scope)


def _prepare_output_directory(target_dir: Path) -> None:
    from .scubagear_export import resolve_output_directory
    resolve_output_directory(target_dir)
    make_private_dirs(target_dir)
    from azure_tenant_audit.guarded_io import _safe_directory
    directory_fd = current_context()._directory(target_dir)
    try:
        if not _safe_directory(os.fstat(directory_fd)):
            raise UnsafeRunFileError("output-dir")
        os.fchmod(directory_fd, 0o700)
    finally:
        os.close(directory_fd)


@guarded_operation
def assess_scubagear_export(export_path: str | Path, output_dir: str | Path, *,
                            results_path: str | Path | None = None, policies: list[str] | None = None,
                            projection_max_items: int = DEFAULT_MAX_ITEMS,
                            projection_max_chars: int = DEFAULT_MAX_CHARS,
                            verdict_map: dict[str, str] | None = None) -> dict[str, Any]:
    """Assess a local ScubaGear export without a run bundle or tenant contact."""
    from .scubagear_export import VERDICT_MAP, _valid_map, scope_from_export
    if verdict_map is None:
        verdict_map = VERDICT_MAP
    _valid_map(verdict_map)
    view = _export_view(export_path, output_dir, results_path=results_path, policies=policies,
                        projection_max_items=projection_max_items, projection_max_chars=projection_max_chars,
                        verdict_map=verdict_map)
    projection, target_dir = view["projection"], view["target_dir"]
    scope = scope_from_export(projection, view["extras"]["raw_ca"], redact=True, max_items=projection_max_items)
    records = _assess_policies(projection, view["selected"], view["catalogue"], view["generated_at"],
                               baseline=view["baseline"], explainer_context=RedactionContext())
    sidecar = _export_sidecar(view, scope, verdict_map)
    loaded = view["loaded"]
    result = _envelope(projection, records, scope, generated_at=view["generated_at"],
                       run_id="scubagear-" + (loaded.report_uuid or loaded.sha256[:16]))
    from azure_tenant_audit.scuba_assessment import validate_assessment
    validate_assessment(result)
    content = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    sidecar_text = json.dumps(sidecar, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    _prepare_output_directory(target_dir)
    created: list[Path] = []
    try:
        for name, data in ((ASSESSMENT_FILENAME, content), ("scubagear_adapter_report.json", sidecar_text)):
            path = target_dir / name
            created.append(path)
            write_private_text(path, data)
    except OSError:
        from azure_tenant_audit.guarded_io import remove_guarded_output
        for path in created:
            remove_guarded_output(path)
        raise
    return result
