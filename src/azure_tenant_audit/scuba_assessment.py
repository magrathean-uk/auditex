"""Standard-library validation of the rule-only SCuBA assessment file (``model_assessment.json``).

The engine never imports the product layer. This small checker supports only the
JSON Schema keywords used in the shipped assessment schema; unsupported keywords
fail closed. Cross-field accounting is checked after the structural contract.
"""
from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from typing import Any

from .guarded_io import UnsafeRunFileError
from .resources import open_text_resource
from .scuba_precheck import (
    evidence_sections,
    field_name,
    policy_rule,
    precheck_response,
    rule_catalogue,
)
from .scuba_scope import (
    NAME_LIMIT as SCOPE_NAME_LIMIT,
)
from .scuba_scope import (
    SECTION as SCOPE_SECTION,
)
from .scuba_scope import (
    condition_paths,
    scope_catalogue,
)

# Historical row metadata remains valid; current assessments only write the scope envelope.
SCOPE_LIMITATION = "scope_narrowed"

MODEL_ASSESSMENT_PATH = "model_assessment.json"
MODEL_ASSESSMENT_SCHEMA = "schemas/model_assessment.schema.json"
BASELINE_SCHEMA_VERSION = "2026-11-27"
M365_BASELINE = "cisa-scuba-m365-v3.9.1"
GWS_BASELINE = "cisa-scubagoggles-v1.1.0"
ASSESSMENT_SCHEMAS = {
    "2026-10-27": "schemas/model_assessment-2026-10-27.schema.json",
    "2026-10-27.1": "schemas/model_assessment-2026-10-27.1.schema.json",
    "2026-10-28": "schemas/model_assessment-2026-10-28.schema.json",
    "2026-10-29": "schemas/model_assessment-2026-10-29.schema.json",
    "2026-11-05": "schemas/model_assessment-2026-11-05.schema.json",
    # Review R106: 2026-11-22 adds the optional projection rule_view; nothing else differs from 2026-11-05.
    "2026-11-22": "schemas/model_assessment-2026-11-22.schema.json",
    BASELINE_SCHEMA_VERSION: MODEL_ASSESSMENT_SCHEMA,
}
# The versions that share the 2026-11-05 validation rules.
_CURRENT = frozenset({"2026-11-05", "2026-11-22", BASELINE_SCHEMA_VERSION})
# Bot review wave 2 (item 56): the versions whose value-rule answers cite a late rule section (SS 7.x
# built_in_protection_rules) by its own evidence id after the case's (``scuba_precheck.evidence_sections``). Answers
# that earlier writers of the same version wrote with the case's ids only still validate (repair round 1).
_LATE_EVIDENCE = frozenset({"2026-11-22", BASELINE_SCHEMA_VERSION})


def policy_catalogue(baseline: str = M365_BASELINE) -> dict[str, Any]:
    resource = "configs/scuba-gws-policy-sections.json" if baseline == GWS_BASELINE else "configs/scuba-policy-sections.json"
    return json.loads(open_text_resource(resource))


SCAN_BOUND_FIELDS = frozenset({"scan_max_rows", "scan_max_bytes", "scan_max_chunks"})
# What a policy that reads the synthesised scuba_config sees: its view, or why it was withheld.
SCUBA_CONFIG_OUTCOMES = frozenset({"projected", "operator_input_required", "break_glass_unresolved",
                                   "environment_ambiguous", "unseen_shape", "oversize"})
# The error classes this engine's collectors, adapters, preflight, offline replay and derived fan-out rows write
# (``collectors/base.py`` ``_classify_graph_error`` and the literals elsewhere; a test keeps the two in step), plus the
# classifier's fallback ``graph_http_<status>``. A projection diagnostic echoes only these: any other token, however
# token-shaped, can be a person's name and reads ``unclassified``.
COLLECTOR_ERROR_CLASSES = frozenset({
    "app_missing_reply_url", "bad_request", "client_error", "collection_limit", "command_error", "command_exception",
    "command_not_authenticated", "command_not_available", "command_not_found", "command_optional_failure",
    "command_output_empty", "command_output_parse_error", "command_parse_error", "command_refused", "command_timeout",
    "dns_resolver_error", "graph_transient", "incomplete_evidence", "insufficient_permissions", "invalid_object_id", "ipps_session_not_opened",
    "lab_guard", "license_required", "missing_app_credentials", "missing_argument", "missing_intent",
    "module_compatibility_unverified", "module_incompatible", "module_not_found", "next_link_refused",
    "permission_stop", "preflight_blocked", "profile_not_allowed", "public_lookup_error", "query_page_minimum",
    "resource_not_found", "response_adapter_override_disabled", "response_argument_malformed",
    "response_argument_unsafe", "response_command_override_disabled", "response_invalid_adapter_override",
    "response_write_guard", "section_absent", "service_not_available", "session_not_connected",
    "teams_powershell_not_supported", "teams_token_unavailable", "toolchain_unavailable",
    "unauthenticated", "unknown", "unknown_action", "unsupported_environment", "unsupported_query",
})
_GRAPH_HTTP_ERROR_CLASS = re.compile(r"graph_http_[1-5][0-9]{2}")
UNCLASSIFIED_ERROR = "unclassified"


def collector_error_class(value: Any) -> str:
    """The collector error class to report: ``value`` when the collectors write it, else ``unclassified``."""
    if isinstance(value, str) and (value in COLLECTOR_ERROR_CLASSES or _GRAPH_HTTP_ERROR_CLASS.fullmatch(value)):
        return value
    return UNCLASSIFIED_ERROR


def safe_projection_enum_value(field: str, value: Any) -> bool:
    """Only finite numbers and explicitly recognised enum tokens may be echoed.

    A token-shaped string can still be a person's name. This diagnostic allowlist
    does not expand the frozen pack's accepted evidence domains.
    """
    if type(value) in (int, float):
        return type(value) is int or math.isfinite(value)
    return field == "AllowInvitesFrom" and isinstance(value, str) and value in {
        "everyone", "none", "adminsAndGuestInviters", "adminsGuestInvitersAndAllMembers",
    }


def _check(value: Any, schema: dict[str, Any], root: dict[str, Any], path: str) -> None:
    supported = {"$schema", "$id", "$defs", "title", "description", "$ref", "type", "const", "enum",
                 "required", "properties", "additionalProperties", "items", "uniqueItems", "pattern",
                 "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems", "anyOf", "dependentSchemas"}
    if set(schema) - supported:
        raise ValueError("Unsupported model assessment schema keyword")
    if "anyOf" in schema:
        for option in schema["anyOf"]:
            try:
                _check(value, option, root, path)
                break
            except ValueError:
                continue
        else:
            raise ValueError(f"Invalid model assessment value at {path}")
    if "$ref" in schema:
        name = schema["$ref"].removeprefix("#/$defs/")
        _check(value, root["$defs"][name], root, path)
        return
    types = {"object": isinstance(value, dict), "array": isinstance(value, list),
             "string": isinstance(value, str), "integer": type(value) is int,
             "number": type(value) is int or type(value) is float and math.isfinite(value),
             "boolean": type(value) is bool, "null": value is None}
    allowed = schema.get("type", list(types))
    allowed = [allowed] if isinstance(allowed, str) else allowed
    if not any(types[kind] for kind in allowed):
        raise ValueError(f"Invalid model assessment type at {path}")
    if "const" in schema and value != schema["const"] or "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"Invalid model assessment value at {path}")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if set(schema.get("required", [])) - set(value):
            raise ValueError(f"Missing model assessment fields at {path}")
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            raise ValueError(f"Unexpected model assessment fields at {path}")
        for key, item in value.items():
            if key in properties:
                _check(item, properties[key], root, f"{path}.{key}")
        for key, dependent in schema.get("dependentSchemas", {}).items():
            if key in value:
                _check(value, dependent, root, path)
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            raise ValueError(f"Invalid model assessment array length at {path}")
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            raise ValueError(f"Duplicate model assessment items at {path}")
        for index, item in enumerate(value):
            _check(item, schema.get("items", {}), root, f"{path}[{index}]")
    if isinstance(value, str):
        if (len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", len(value))
                or "pattern" in schema and not re.search(schema["pattern"], value)):
            raise ValueError(f"Invalid model assessment string at {path}")
    if type(value) in (int, float):
        if (type(value) is float and not math.isfinite(value)) or value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise ValueError(f"Invalid model assessment number at {path}")


def _sorted_unique(values: list[str]) -> bool:
    return values == sorted(set(values))


def _validate_scope_record(summary: dict[str, Any], section_projected: bool) -> None:
    """The envelope's scope post-check record: where it was read from and which policies carry a scope condition."""
    policies, count = summary["policies"], summary["count"]
    names = [item["name"] for item in policies]
    if summary["status"] == "evaluated":
        consistent = summary["reason"] is None and summary["source"] == ("projection" if section_projected else "raw")
    else:
        consistent = summary["reason"] is not None and summary["source"] is None and count == 0 and not policies
    scope_paths = set(condition_paths().values()) - {condition_paths()["operator"]}
    if (not consistent or not _sorted_unique(names) or len(policies) > count or (count == 0) != (not policies)
            or any(len(name) > SCOPE_NAME_LIMIT for name in names)
            or any(not _sorted_unique(item["conditions"]) or not set(item["conditions"]) <= scope_paths
                   for item in policies)):
        raise ValueError("Invalid scope post-check record")


def _legacy_requirement_met(row: dict[str, Any]) -> bool:
    """The recorded model-row contract, retained solely for historical validation."""
    claim = next((c for c in row.get("claims", []) if c.get("id") == "requirement_met"), None)
    return (row.get("validation_status") == "valid" and row.get("reason") != "rule_precheck"
            and isinstance(claim, dict) and claim.get("status") in {"confirmed", "inferred"}
            and claim.get("value") is True and "policy_not_applicable" not in row.get("limitations", []))


def _validate_post_check(row: dict[str, Any], summary: Any) -> None:
    """A historical row's scope_narrowed mark: a met verdict of a tabled policy, conditions the Rego is known to ignore."""
    post, rule = row["post_check"], scope_catalogue()["policies"].get(row["policy_id"])
    paths = condition_paths()
    allowed = {paths[group] for group in rule["ignored"]} if rule else set()
    if rule and rule["operator"]:
        allowed.add(paths["operator"])
    if (rule is None or not _legacy_requirement_met(row) or not isinstance(summary, dict) or summary["status"] != "evaluated"
            or not _sorted_unique(post["policies"]) or not _sorted_unique(post["conditions"])
            or not set(post["conditions"]) <= allowed or len(post["policies"]) > post["count"]
            or any(len(name) > SCOPE_NAME_LIMIT for name in post["policies"])):
        raise ValueError("Invalid scope post-check")


def value_rule_verdict(row: dict[str, Any]) -> str:
    """Derive the public verdict from the requirement claim of a value-rule row."""
    claim = next(c for c in row["claims"] if c["id"] == "requirement_met")
    if claim["status"] == "unknown" and claim["value"] is None:
        return "not_assessed"
    if claim["status"] == "inferred" and claim["value"] is True and "policy_not_applicable" in row["limitations"]:
        return "not_applicable"
    if claim["status"] == "confirmed" and type(claim["value"]) is bool:
        return "met" if claim["value"] else "not_met"
    raise ValueError("Invalid value-rule verdict")


def _validate_explainer(row: dict[str, Any], requirement: dict[str, Any]) -> None:
    """Check the explanation against the validated rule answer and its citations."""
    from .explainer.textkit import sentences, words

    if row["reason"] != "rule_precheck" or row.get("rule_precheck", {}).get("class") != "value_rule":
        raise ValueError("Explainer requires a value rule")
    result = row["explainer"]
    verdict = value_rule_verdict(row)
    refs = result["evidence_refs"]
    try:
        for text in (result["explanation"], *result["remediation_steps"]):
            text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Invalid value-rule explanation text") from exc
    if (refs[0] != "e0" or not set(refs) <= set(requirement["evidence_ids"])
            or verdict in {"met", "not_applicable"} and result["remediation_steps"]
            or verdict == "not_met" and not result["remediation_steps"]
            or words(result["explanation"]) > 80 or sentences(result["explanation"]) > 3):
        raise ValueError("Invalid value-rule explanation")


def derive_explainer(row: dict[str, Any]) -> dict[str, Any] | None:
    """Re-derive a row's template explanation from its validated public rule fields and evidence references.

    Only the public rule_precheck fields and the requirement claim's evidence ids are read; no evidence content,
    rule_projection or stored explanation. Returns None when the context is incomplete.
    """
    from .explainer import explain

    try:
        detail = row["rule_precheck"]
        if row["reason"] != "rule_precheck" or detail.get("class") != "value_rule":
            return None
        pid = row["policy_id"]
        catalogue = policy_catalogue(GWS_BASELINE if pid.startswith("GWS.") else M365_BASELINE)["policies"]
        order = list(catalogue[pid]["sections"])
        requirement = next(c for c in row["claims"] if c["id"] == "requirement_met")
        present = set(requirement["evidence_ids"])
        # Placeholders only mark which cited sections the case carried; the explainer never renders their content.
        sections = {s: {} for i, s in enumerate(order, 1) if f"e{i}" in present}
        public = {"policy_id": pid, "verdict": value_rule_verdict(row), "cell": detail["cell"],
                  "reason_code": detail["reason_code"], "reason_text": detail["reason_text"],
                  "cited_sections": list(detail["section"])}
        return explain(public, sections, order)
    except (UnsafeRunFileError, MemoryError):
        raise
    except Exception:
        return None


@lru_cache(maxsize=1)
def _explainer_schema() -> dict[str, Any]:
    return json.loads(open_text_resource("schemas/explainer.schema.json"))


def validate_explainer(row: dict[str, Any], result: Any) -> None:
    """Validate a redacted explainer before it is attached to its rule answer."""
    schema = _explainer_schema()
    _check(result, schema, schema, "explainer")
    requirement = next((claim for claim in row["claims"] if claim["id"] == "requirement_met"), {})
    _validate_explainer({**row, "explainer": result}, requirement)


# Review R099 (repair): SS 7.1 to 7.3 read built_in_protection_rules since lane rules-followup. Answers the earlier writer
# emitted cite the five sections it read, and empty rule lists answered the since-retired no_rules_configured cell; both
# still validate, but only with that exact earlier citation and only in a file that advertises 2026-11-05 (repair
# round 2: a 2026-11-22 file cites what the current rule reads). A rule fault (null cell) is read the same way.
_SAFELINKS_LEGACY_POLICIES = frozenset({"MS.SECURITYSUITE.7.1v1", "MS.SECURITYSUITE.7.2v1", "MS.SECURITYSUITE.7.3v1"})
_SAFELINKS_LEGACY_SECTIONS = ["atp_policy_rules", "defender_license", "protection_policy_rules", "safe_links_policies",
                              "safe_links_rules"]


def _legacy_safelinks_cell(version: str, policy_id: str, detail: dict[str, Any], value_row: dict[str, Any] | None,
                           cell: dict[str, Any] | None) -> dict[str, Any] | None:
    if (version != "2026-11-05" or policy_id not in _SAFELINKS_LEGACY_POLICIES or value_row is None
            or detail.get("section") != _SAFELINKS_LEGACY_SECTIONS):
        return cell
    if cell is None and detail["cell"] == "no_rules_configured":
        what = value_row["params"]["what"]
        return {"verdict": "not_met", "reason_code": "no_rules_configured", "cited": list(_SAFELINKS_LEGACY_SECTIONS),
                "reason_texts": ["Requirement not met: no preset security policy rule and no Safe Links rule exists, so no "
                                 f"Standard, Strict or custom Safe Links policy applies ({what})."]}
    if cell is not None and "cited_variants" not in cell and cell.get("cited") == list(value_row["sections"]):
        return {**cell, "cited": list(_SAFELINKS_LEGACY_SECTIONS)}
    return cell


def validate_assessment(payload: Any) -> None:
    version = payload.get("schema_version") if isinstance(payload, dict) else None
    if not isinstance(version, str) or version not in ASSESSMENT_SCHEMAS:
        raise ValueError("Unsupported model assessment schema_version")
    schema = json.loads(open_text_resource(ASSESSMENT_SCHEMAS[version]))
    _check(payload, schema, schema, "assessment")
    google = payload.get("baseline", M365_BASELINE) == GWS_BASELINE
    catalogue = policy_catalogue(GWS_BASELINE if google else M365_BASELINE)["policies"]
    prefix = "GWS." if google else "MS."
    from .scuba_precheck import optional_collection_entry
    optional = optional_collection_entry()
    optional_sections = {s for policy in optional["policies"].values() for s in policy["sections"]}
    if version == "2026-10-29" or version in _CURRENT:
        projection = payload["projection"]
        sections = projection["sections"]
        if set(sections) != {s for policy in catalogue.values() for s in policy["sections"]}:
            raise ValueError("Invalid projection section catalogue")
        for section, detail in sections.items():
            if google:
                _check(detail, schema["$defs"]["gws_projection_section"], schema, "assessment.projection.sections")
            if detail["reason"] == optional["reason_code"] and (
                    version not in _CURRENT or section not in optional_sections
                    or detail["status"] != "not_collected"):
                raise ValueError("Invalid optional-collection projection reason")
            if ((detail["status"] == "projected") != (detail["reason"] is None)
                    or detail["status"] == "projected" and not detail["source"]):
                raise ValueError("Inconsistent projection status or source")
            synthesis = detail.get("synthesis")
            if synthesis is not None:
                readers = {p for p, policy in catalogue.items() if section in policy["sections"]}
                outcomes = synthesis["policies"]
                if (section != "scuba_config" or detail["status"] != "projected" or set(outcomes) != readers
                        or not set(outcomes.values()) <= SCUBA_CONFIG_OUTCOMES or "projected" not in outcomes.values()):
                    raise ValueError("Inconsistent scuba_config synthesis")
            elif section == "scuba_config" and detail["status"] == "projected":
                raise ValueError("Inconsistent scuba_config synthesis")
            # Review R106: a withheld section whose private rule view was still built says how; a projected one never does.
            if "rule_view" in detail and detail["status"] != "not_collected":
                raise ValueError("Inconsistent projection rule view")
            unsupported = detail.get("unsupported_conditions", [])
            if unsupported and (section != "conditional_access_policies" or detail["reason"] != "incomplete_shape"
                                or unsupported != sorted(set(unsupported))):
                raise ValueError("Inconsistent unsupported projection conditions")
            ignored_fields = detail.get("ignored_fields", [])
            if not _sorted_unique(ignored_fields):
                raise ValueError("Unsorted ignored projection fields")
            if not _sorted_unique(detail.get("rule_view_omitted_fields", [])):
                raise ValueError("Unsorted rule view omitted fields")
            for name in ("dropped_conditions", "null_lists_read_as_empty"):
                if name in detail and (section != "conditional_access_policies" or detail["status"] != "projected"
                                       or not _sorted_unique(detail[name])):
                    raise ValueError("Inconsistent projection Conditional Access record")
            diagnostic = detail.get("detail")
            if detail["reason"] == "collector_error" and not google:
                # A failed read names its cause: the collector's error class, and the operation when known.
                if (detail["status"] != "not_collected" or diagnostic is None or "error_class" not in diagnostic
                        or not set(diagnostic) <= {"error_class", "operation"}):
                    raise ValueError("Inconsistent projection diagnostic")
                if diagnostic["error_class"] not in {collector_error_class(diagnostic["error_class"]), UNCLASSIFIED_ERROR}:
                    raise ValueError("Unknown projection error class")
            elif diagnostic is not None:
                if "kind" not in diagnostic:
                    raise ValueError("Inconsistent projection diagnostic")
                # A scan bound that ran out is the one diagnostic an oversize section carries.
                scan_bound = diagnostic["kind"] == "scan_bound"
                if (detail["status"] != "not_collected"
                        or detail["reason"] != ("oversize" if scan_bound else "incomplete_shape")
                        or scan_bound and diagnostic["field"] not in SCAN_BOUND_FIELDS):
                    raise ValueError("Inconsistent projection diagnostic")
                if "value" in diagnostic and (
                    diagnostic["kind"] != "unseen_enum_value"
                    or not safe_projection_enum_value(diagnostic["field"], diagnostic["value"])
                ):
                    raise ValueError("Unsafe projection diagnostic value")
            for source in detail["source"]:
                if any(p in {"..", ".secrets"} or p.startswith(".env") for p in source.split("/")):
                    raise ValueError("Unsafe projection source")
        projected = any(s["status"] == "projected" for s in sections.values())
        if payload["limitations"] != ([] if projected else ["projection_not_implemented"]):
            raise ValueError("Inconsistent projection limitations")
        if "scope_post_check" in payload and not google:
            _validate_scope_record(payload["scope_post_check"], sections[SCOPE_SECTION]["status"] == "projected")
        redaction = projection["redaction"]
        if not redaction["enabled"]:
            from ipaddress import ip_address
            host = payload["endpoint_host"].lower().rstrip(".")
            try:
                loopback = ip_address(host).is_loopback
            except ValueError:
                loopback = host == "localhost"
            if not loopback or any(redaction[k] for k in ("user_display_names", "email_addresses", "immutable_ids")):
                raise ValueError("Invalid unredacted projection")
    counts = {"answered": 0, "unknown": 0, "invalid": 0, "skipped": 0}
    if version in {"2026-10-28", "2026-10-29"} or version in _CURRENT:
        counts["rule_answered"] = 0
    # A rules-only file (2026-11-05) is marked by its envelope or by an uncovered row; any marker binds all of
    # them: no endpoint, no model name, no serving block, no model-answered or shadow row. Legacy files unchanged.
    if google or any(row["reason"] == "rule_not_implemented" for row in payload["policies"]) or (
            version in _CURRENT and (payload["endpoint_host"] == "none" or payload["model_name"] == "rules-only")):
        if (payload["endpoint_host"] != "none" or payload["model_name"] != "rules-only"
                or "serving" in payload or any(
                    row["reason"] not in {"rule_precheck", "rule_not_implemented", "policy_not_in_catalogue"}
                    or "model_shadow" in row for row in payload["policies"])):
            raise ValueError("Inconsistent rules-only assessment")
    ids = set()
    scope_rows = 0
    for row in payload["policies"]:
        if not row["policy_id"].startswith(prefix):
            raise ValueError("Assessment policy does not match baseline")
        if row["policy_id"] in ids:
            raise ValueError("Duplicate model assessment policy")
        ids.add(row["policy_id"])
        if row["policy_id"] not in catalogue and not (
            row["validation_status"] == "skipped" and row["reason"] == "policy_not_in_catalogue"
        ):
            raise ValueError("Unsupported model assessment policy")
        policy = catalogue.get(row["policy_id"])
        if "reason_text" in row and row["reason"] != "rule_not_implemented":
            raise ValueError("Unexpected uncovered-policy text")
        is_rule = row["reason"] == "rule_precheck"
        if optional["reason_code"] in row["limitations"] and (
                not is_rule or row.get("rule_precheck", {}).get("reason_code") != optional["reason_code"]):
            raise ValueError("Optional-collection limitation requires its pre-check")
        if version in {"2026-10-28", "2026-10-29"} or version in _CURRENT:
            counts["rule_answered"] += is_rule
            if ("rule_precheck" in row) != is_rule or "model_shadow" in row and not is_rule:
                raise ValueError("Invalid rule pre-check metadata")
        late = not google and version in _LATE_EVIDENCE
        evidence_order = policy["sections"] if policy else []
        criticality = (policy["criticality"] if google else policy["policy_item"]["criticality"]) if policy else None
        if policy and late and is_rule and row.get("rule_precheck", {}).get("class") == "value_rule":
            evidence_order = evidence_sections(row["policy_id"], policy["sections"])
        allowed_evidence = {f"e{index}" for index in range(len(evidence_order) + 1)} if policy else set()
        status = row["validation_status"]
        requirement = next((c for c in row["claims"] if c["id"] == "requirement_met"), {})
        model_status = None
        if status == "valid" and requirement.get("status") == "confirmed":
            model_status = "pass" if requirement.get("value") is True else "fail"
        comparison = row["comparison"]
        if google and (comparison["baseline_status"] is not None or comparison["baseline_match"] != "none"):
            raise ValueError("Unexpected Google Workspace baseline comparison")
        agreement = "not_assessed"
        if model_status is not None and comparison["baseline_status"] in {"pass", "fail"}:
            agreement = "agree" if comparison["baseline_status"] == model_status else "disagree"
        if comparison["model_status"] != model_status or comparison["result"] != agreement:
            raise ValueError("Inconsistent model assessment comparison")
        if ("post_check" in row) != (SCOPE_LIMITATION in row["limitations"]):
            raise ValueError("Inconsistent scope post-check")
        if "post_check" in row:
            _validate_post_check(row, payload.get("scope_post_check"))
            scope_rows += 1
        if status in {"invalid", "skipped"}:
            counts[status] += 1
        elif status == "unknown" or any(c["id"] == "requirement_met" and c["status"] == "unknown" for c in row["claims"]):
            counts["unknown"] += 1
        else:
            counts["answered"] += 1
        if "finish_reason" in row and (is_rule or status == "skipped"):
            raise ValueError("finish_reason belongs to model rows only")
        if status == "skipped":
            skip_reason = "policy_text_unavailable" if version == "2026-10-27" else "policy_not_in_catalogue"
            if (row["reason"] != skip_reason or row["attempts"] != 0 or row["claims"]
                    or row["prompt_sha256"] is not None or row["response_sha256"] is not None
                    or row["limitations"] or row["recommendations"]):
                raise ValueError("Invalid skipped model assessment")
            continue
        claims = row["claims"]
        if len(claims) != 2 or {c["id"] for c in claims} != {"requirement_met", "policy_criticality"}:
            raise ValueError("Invalid model assessment claims")
        for claim in claims:
            if not set(claim["evidence_ids"]) <= allowed_evidence:
                raise ValueError("Unsupported model assessment evidence")
            if claim["status"] == "unknown" and claim["value"] is not None:
                raise ValueError("Unknown model assessment value must be null")
            if claim["status"] != "unknown":
                if not claim["evidence_ids"] or "e0" not in claim["evidence_ids"]:
                    raise ValueError("Known model assessment claims must cite evidence")
                if claim["id"] == "requirement_met" and type(claim["value"]) is not bool:
                    raise ValueError("Known requirement value must be boolean")
                if claim["id"] == "policy_criticality" and (
                    claim["value"] != criticality or claim["evidence_ids"] != ["e0"]
                ):
                    raise ValueError("Invalid policy criticality value")
        if is_rule:
            detail = row["rule_precheck"]
            if (status != "valid" or row["attempts"] != 0 or row["latency_ms"] != 0 or
                    row["prompt_sha256"] is not None or row["response_sha256"] is not None or
                    row["thinking_disabled"] or row["thinking_stripped"]):
                raise ValueError("Invalid rule pre-check provenance")
            sections = policy["sections"]
            value_row = None
            if google and detail["class"] != "value_rule":
                raise ValueError("Google Workspace requires a value rule")
            if detail["class"] == "value_rule":
                if version not in _CURRENT:
                    raise ValueError("Value rule requires current schema")
                from .value_rules.catalogue import (
                    cell_entry,
                    citation_variants,
                    reason_matches,
                    row_for,
                    shared_reason,
                )
                from .value_rules.record import (
                    RULE_FAILURE_CODE,
                    RULE_NOT_IMPLEMENTED_CODE,
                    is_shared_reason,
                )
                if google:
                    from .value_rules.gws import catalogue as gws_catalogue
                    row_for, shared_reason = gws_catalogue.row_for, gws_catalogue.shared_reason
                value_row = row_for(row["policy_id"])
                if not {"cell", "reason_code", "reason_text"} <= detail.keys():
                    raise ValueError("Missing value-rule cell or reason")
                if detail["cell"] in {RULE_FAILURE_CODE, RULE_NOT_IMPLEMENTED_CODE}:
                    raise ValueError("Legacy rule-failure sentinel: a shared reason is not a cell, its cell must be null")
                if detail["cell"] is None:
                    # A1.2: a failed rule, dispatched before any cell lookup. The cell is null, the text is the
                    # catalogued constant and the answer cites every section the rule reads. A policy without a rule
                    # is a row-level reason (rule_not_implemented), never a rule record.
                    if not is_shared_reason(detail["reason_code"]) or value_row is None or (
                            detail["rule_id"] != value_row["rule_id"]):
                        raise ValueError("Unsupported value-rule cell or reason")
                    shared = shared_reason(detail["reason_code"])
                    cell = {"verdict": shared["verdict"], "reason_code": shared["reason_code"],
                            "reason_texts": [shared["reason_text"]], "cited": list(value_row["sections"])}
                else:
                    cell = cell_entry(row["policy_id"], detail["cell"], value_row) if value_row else None
                cell = _legacy_safelinks_cell(version, row["policy_id"], detail, value_row, cell)
                if (value_row is None or cell is None or detail["rule_id"] != value_row["rule_id"]
                        or not reason_matches(cell, detail["reason_code"], detail["reason_text"])
                        or detail["field"] is not None or detail["value"] is not None):
                    raise ValueError("Unsupported value-rule cell or reason")
                allowed_sections = value_row["sections"]
                # A1: the effective contract includes the exact SS 7.x reference order.
                if (detail["section"] != [s for s in allowed_sections if s in detail["section"]]
                        and detail["section"] not in citation_variants(cell)):
                    raise ValueError("Invalid value-rule section order")
            else:
                allowed_sections = sections
                optional_reason = detail.get("reason_code") == optional["reason_code"]
                metadata = {"reason_code", "reason_text"} if optional_reason else set()
                if set(detail) - ({"class", "rule_id", "section", "field", "value"} | metadata):
                    raise ValueError("Unexpected legacy pre-check metadata")
                if optional_reason:
                    entry = optional["policies"].get(row["policy_id"])
                    if (version not in _CURRENT or entry is None
                            or detail["class"] != "absent_section"
                            or detail["rule_id"] != "required_sections_present"
                            or detail.get("reason_text") != optional["reason_text"]
                            or detail["section"] != [s for s in sections if s in detail["section"]]
                            or not set(detail["section"]) <= set(entry["sections"])
                            or any(payload["projection"]["sections"][s]["status"] != "not_collected"
                                   or payload["projection"]["sections"][s]["reason"] != optional["reason_code"]
                                   for s in detail["section"])):
                        raise ValueError("Invalid optional-collection pre-check reason")
            if not set(detail["section"]) <= set(allowed_sections):
                raise ValueError("Unsupported rule pre-check section")
            if detail["class"] == "value_rule":
                if cell["verdict"] == "not_assessed" and detail["cell"] == "section_not_collected":
                    expected_text = ("Data unavailable: required evidence section(s) not collected: "
                                     + ", ".join(detail["section"]) + ".")
                    if detail["reason_text"] != expected_text:
                        raise ValueError("Value-rule missing-section reason differs from citation")
                elif detail["section"] not in citation_variants(cell):
                    raise ValueError("Value-rule decision cites the wrong section")
            elif detail["rule_id"] == "required_sections_present":
                if detail["class"] != "absent_section" or detail["field"] is not None or detail["value"] is not None:
                    raise ValueError("Invalid absent-section pre-check")
            elif detail["class"] == "absent_field":
                # A Rego-read field missing inside a collected section: the rule must be one of the registered field
                # rules of this policy, name its section and field, and carry no value.
                rule = next((r for r in rule_catalogue()["field_rules"] if r["rule_id"] == detail["rule_id"]), None)
                if (rule is None or rule["policy_id"] != row["policy_id"] or detail["section"] != [rule["section"]]
                        or detail["field"] != field_name(rule) or detail["value"] is not None):
                    raise ValueError("Unsupported rule pre-check field rule")
            elif detail["class"] == "empty_required_list":
                # A collected, exactly empty list that every passing verdict of the policy needs an entry of: the rule
                # must be one of the registered list rules of this policy and name only its section.
                rule = next((r for r in rule_catalogue()["list_rules"] if r["rule_id"] == detail["rule_id"]), None)
                if (rule is None or rule["policy_id"] != row["policy_id"] or detail["section"] != [rule["section"]]
                        or detail["field"] is not None or detail["value"] is not None):
                    raise ValueError("Unsupported rule pre-check list rule")
            else:
                rule = policy_rule(row["policy_id"])
                if (rule is None or detail["rule_id"] != rule["rule_id"] or
                        detail["section"] != [rule["section"]] or detail["field"] != field_name(rule)):
                    raise ValueError("Unsupported rule pre-check gate")
                if detail["class"] == "closed_gate":
                    if (type(detail["value"]) is not (int if rule["value_type"] == "integer" else str) or
                            detail["value"] not in rule["closed_values"]):
                        raise ValueError("Invalid closed-gate value")
                elif detail["value"] is not None:
                    raise ValueError("Absent gate input must have null value")
            verdict = cell["verdict"] if detail["class"] == "value_rule" else None
            # Repair round 1 (item 56): 2026-11-22 files written before item 56 cite the case's sections only; a
            # row matches one form or the other as a whole.
            if google:
                from .value_rules.record import as_pack_response
                expected = [as_pack_response({"verdict": verdict, "reason_code": detail["reason_code"],
                                              "cited_sections": detail["section"]}, criticality, sections)]
            else:
                forms = [late, False] if late else [False]
                expected = [precheck_response(detail, policy["policy_item"], sections, verdict=verdict, late_evidence=form)
                            for form in forms]
                if detail["class"] == "value_rule":
                    # Earlier M365 rows used the missing-evidence vocabulary for all abstentions.
                    expected.extend(precheck_response(detail, policy["policy_item"], sections, legacy=True,
                                                      verdict=verdict, late_evidence=form) for form in forms)
            if not any(all(row[key] == answer[key] for key in answer) for answer in expected):
                raise ValueError("Invalid rule pre-check answer")
            if "explainer" in row:
                _validate_explainer(row, requirement)
            if "model_shadow" in row:
                shadow = row["model_shadow"]
                if shadow["policy_id"] != row["policy_id"]:
                    raise ValueError("Shadow policy differs from rule policy")
                # Reuse all model-answer semantic validation, including failures,
                # without allowing it to participate in the product comparison.
                req = next((c for c in shadow["claims"] if c["id"] == "requirement_met"), {})
                known = shadow["validation_status"] == "valid" and req.get("status") == "confirmed"
                comparison = {"baseline_status": None, "baseline_match": "none", "result": "not_assessed",
                              "model_status": ("pass" if req.get("value") is True else "fail") if known else None}
                state = shadow["validation_status"]
                category = state if state in {"invalid", "unknown"} else (
                    "unknown" if req.get("status") == "unknown" else "answered")
                shadow_totals = dict.fromkeys(counts, 0)
                shadow_totals[category] = 1
                validate_assessment({**payload, "totals": shadow_totals,
                                     "policies": [{**shadow, "comparison": comparison}]})
            continue
        if row["reason"] == "rule_not_implemented":
            if (version not in _CURRENT or status != "unknown" or row["attempts"] != 0
                    or row["latency_ms"] != 0 or row["prompt_sha256"] is not None
                    or row["response_sha256"] is not None or row["thinking_disabled"]
                    or row["thinking_stripped"] or "finish_reason" in row
                    or row.get("reason_text") != "Not assessed: Auditex has no rule for this policy yet."
                    or row["limitations"] or row["recommendations"]
                    or any(c["status"] != "unknown" or c["evidence_ids"] for c in claims)):
                raise ValueError("Invalid uncovered-policy assessment")
            continue
        if row["attempts"] < 1 or row["prompt_sha256"] is None:
            raise ValueError("Missing model assessment attempt provenance")
        if status == "invalid" and (row["reason"] != "model_response_invalid" or "model_response_invalid" not in row["limitations"]):
            raise ValueError("Missing model response failure limitation")
        # A reply that never arrived intact (model_transport_failed) is unknown, like an unreachable endpoint; the
        # schema admits that reason only from 2026-10-29.
        if status == "unknown" and (row["reason"] not in {"model_endpoint_unavailable", "model_transport_failed"}
                                    or row["limitations"] != [row["reason"]]):
            raise ValueError("Missing model endpoint failure limitation")
        if status == "unknown" and row["response_sha256"] is not None:
            raise ValueError("An unanswered model row carries no response hash")
        if status == "valid" and (row["reason"] is not None or row["response_sha256"] is None
                                  or set(row["limitations"]) & {"model_response_invalid", "model_endpoint_unavailable",
                                                                "model_transport_failed"}):
            raise ValueError("Invalid validated model assessment provenance")
        if status in {"invalid", "unknown"} and any(c["status"] != "unknown" for c in claims):
            raise ValueError("Failed model responses must abstain")
    totals = dict(payload["totals"])
    # Assessments written before the post-check carry no scope_narrowed total and no marked row.
    if counts != {key: value for key, value in totals.items() if key != "scope_narrowed"} or (
            scope_rows != totals.get("scope_narrowed", 0)):
        raise ValueError("Model assessment totals disagree with policies")
