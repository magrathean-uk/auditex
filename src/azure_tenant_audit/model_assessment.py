"""Standard-library validation of the optional model assessment schema.

The engine never imports the product layer. This small checker supports only the
JSON Schema keywords used in the shipped assessment schema; unsupported keywords
fail closed. Cross-field accounting is checked after the structural contract.
"""
from __future__ import annotations

import json
import math
import re
from typing import Any

from .resources import open_text_resource

MODEL_ASSESSMENT_PATH = "model_assessment.json"
MODEL_ASSESSMENT_SCHEMA = "schemas/model_assessment.schema.json"
ASSESSMENT_SCHEMAS = {
    "2026-10-27": "schemas/model_assessment-2026-10-27.schema.json",
    "2026-10-27.1": MODEL_ASSESSMENT_SCHEMA,
}


def _check(value: Any, schema: dict[str, Any], root: dict[str, Any], path: str) -> None:
    supported = {"$schema", "$id", "$defs", "title", "description", "$ref", "type", "const", "enum",
                 "required", "properties", "additionalProperties", "items", "uniqueItems", "pattern",
                 "minimum", "maximum", "minLength", "minItems", "maxItems"}
    if set(schema) - supported:
        raise ValueError("Unsupported model assessment schema keyword")
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
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            raise ValueError(f"Invalid model assessment array length at {path}")
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            raise ValueError(f"Duplicate model assessment items at {path}")
        for index, item in enumerate(value):
            _check(item, schema.get("items", {}), root, f"{path}[{index}]")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or "pattern" in schema and not re.search(schema["pattern"], value):
            raise ValueError(f"Invalid model assessment string at {path}")
    if type(value) in (int, float):
        if (type(value) is float and not math.isfinite(value)) or value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise ValueError(f"Invalid model assessment number at {path}")


def validate_assessment(payload: Any) -> None:
    version = payload.get("schema_version") if isinstance(payload, dict) else None
    if not isinstance(version, str) or version not in ASSESSMENT_SCHEMAS:
        raise ValueError("Unsupported model assessment schema_version")
    schema = json.loads(open_text_resource(ASSESSMENT_SCHEMAS[version]))
    _check(payload, schema, schema, "assessment")
    catalogue = json.loads(open_text_resource("configs/scuba-policy-sections.json"))["policies"]
    counts = {"answered": 0, "unknown": 0, "invalid": 0, "skipped": 0}
    ids = set()
    for row in payload["policies"]:
        if row["policy_id"] in ids:
            raise ValueError("Duplicate model assessment policy")
        ids.add(row["policy_id"])
        if row["policy_id"] not in catalogue and not (
            row["validation_status"] == "skipped" and row["reason"] == "policy_not_in_catalogue"
        ):
            raise ValueError("Unsupported model assessment policy")
        policy = catalogue.get(row["policy_id"])
        allowed_evidence = {f"e{index}" for index in range(len(policy["sections"]) + 1)} if policy else set()
        status = row["validation_status"]
        requirement = next((c for c in row["claims"] if c["id"] == "requirement_met"), {})
        model_status = None
        if status == "valid" and requirement.get("status") == "confirmed":
            model_status = "pass" if requirement.get("value") is True else "fail"
        comparison = row["comparison"]
        agreement = "not_assessed"
        if model_status is not None and comparison["baseline_status"] in {"pass", "fail"}:
            agreement = "agree" if comparison["baseline_status"] == model_status else "disagree"
        if comparison["model_status"] != model_status or comparison["result"] != agreement:
            raise ValueError("Inconsistent model assessment comparison")
        if status in {"invalid", "skipped"}:
            counts[status] += 1
        elif status == "unknown" or any(c["id"] == "requirement_met" and c["status"] == "unknown" for c in row["claims"]):
            counts["unknown"] += 1
        else:
            counts["answered"] += 1
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
                    claim["value"] != policy["policy_item"]["criticality"] or claim["evidence_ids"] != ["e0"]
                ):
                    raise ValueError("Invalid policy criticality value")
        if row["attempts"] < 1 or row["prompt_sha256"] is None:
            raise ValueError("Missing model assessment attempt provenance")
        if status == "invalid" and (row["reason"] != "model_response_invalid" or "model_response_invalid" not in row["limitations"]):
            raise ValueError("Missing model response failure limitation")
        if status == "unknown" and (row["reason"] != "model_endpoint_unavailable" or row["limitations"] != ["model_endpoint_unavailable"]):
            raise ValueError("Missing model endpoint failure limitation")
        if status == "valid" and (row["reason"] is not None or row["response_sha256"] is None
                                  or set(row["limitations"]) & {"model_response_invalid", "model_endpoint_unavailable"}):
            raise ValueError("Invalid validated model assessment provenance")
        if status in {"invalid", "unknown"} and any(c["status"] != "unknown" for c in claims):
            raise ValueError("Failed model responses must abstain")
    if counts != payload["totals"]:
        raise ValueError("Model assessment totals disagree with policies")
