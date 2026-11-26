"""Assemble Google Workspace policy answers and projection metadata for the assessment writer."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from azure_tenant_audit.guarded_io import UnsafeRunFileError
from azure_tenant_audit.scuba_assessment import (
    BASELINE_SCHEMA_VERSION,
    GWS_BASELINE,
    derive_explainer,
    validate_explainer,
)
from azure_tenant_audit.value_rules import gws

from .google_workspace.scuba_projection import project_gws_run
from .rule_assessment import _comparison, _envelope, _skipped_record, _uncovered_record

LOG = logging.getLogger(__name__)


def _assess_policy(policy_id: str, policy: dict[str, Any], sections: dict[str, Any]) -> dict[str, Any]:
    try:
        answer = gws.assess(policy_id, sections)
    except (UnsafeRunFileError, MemoryError):
        raise
    except Exception as exc:
        LOG.warning("Value rule %s failed (%s); the row is answered not assessed", policy_id, type(exc).__name__)
        answer = gws.rule_failure_gws(policy_id)
    if answer is None:
        return _uncovered_record(policy_id)

    record = {
        **gws.as_pack_response(answer, policy["criticality"], policy["sections"]),
        "policy_id": policy_id,
        "validation_status": "valid", "reason": "rule_precheck", "attempts": 0, "latency_ms": 0,
        "prompt_sha256": None, "response_sha256": None, "thinking_disabled": False, "thinking_stripped": False,
        "rule_precheck": {
            "class": "value_rule", "rule_id": gws.catalogue.row_for(policy_id)["rule_id"],
            "section": policy["sections"] if answer["cited_sections"] is None else answer["cited_sections"],
            "field": None, "value": None, "cell": answer["cell"],
            "reason_code": answer["reason_code"], "reason_text": answer["reason_text"],
        },
    }
    explanation = derive_explainer(record)
    if explanation is not None:
        validate_explainer(record, explanation)
        record["explainer"] = explanation
    return record


def assess_google_run(root: Path, selected: list[str], catalogue: dict[str, Any], *, generated_at: str,
                      run_id: str, **bounds: int) -> dict[str, Any]:
    projection = project_gws_run(root, **bounds)
    records = []
    for policy_id in selected:
        policy = catalogue["policies"].get(policy_id)
        record = _assess_policy(policy_id, policy, projection) if policy is not None else _skipped_record(policy_id)
        record["comparison"] = _comparison(policy_id, record, {})
        records.append(record)
    result = _envelope(projection, records, {"status": "not_applicable"}, generated_at=generated_at,
                       run_id=run_id, schema_version=BASELINE_SCHEMA_VERSION)
    # The rule view and diagnostics stay in memory. Every persisted source is a bundle-relative artefact name.
    result["projection"] = {
        **projection.report,
        "sections": {
            name: {key: item[key] for key in ("status", "source", "reason")}
            for name, item in projection.report["sections"].items()
        },
        "redaction": {key: projection.report["redaction"][key]
                      for key in ("enabled", "strategy", "email_addresses")},
    }
    result["baseline"] = GWS_BASELINE
    return result
