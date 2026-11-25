"""Deterministic Google Workspace explanations from fixed catalogue text."""
import json
from functools import lru_cache

from ..resources import open_text_resource
from ..value_rules.gws.catalogue import row_for
from ..value_rules.gws.record import checked_gws
from .textkit import sentences, words


@lru_cache(maxsize=1)
def _templates():
    return json.loads(open_text_resource("configs/explainer-gws-template.json"))


def explain_gws(record, redacted_sections, section_order):
    """Render a checked record without using any observed evidence value."""
    row = row_for(record["policy_id"])
    if row is None or section_order != row["sections"] or not isinstance(redacted_sections, dict):
        raise ValueError("Invalid GWS explanation context")
    checked_gws(record)
    cites = record["cited_sections"]
    if cites is None:
        cites = row["sections"]
    template = _templates()
    if template["schema_version"] != 1:
        raise ValueError("Unsupported GWS explanation template")
    policy = template["policies"][record["policy_id"]]
    if policy["kind"] != row["kind"]:
        raise ValueError("GWS explanation kind mismatch")
    if record["cell"] is None:
        check = template["shared_reasons"]
    else:
        cell = template["kinds"][row["kind"]][record["cell"]]
        if record["cell"] != "section_not_collected" and record["reason_text"] not in cell["reason_texts"]:
            raise ValueError("GWS explanation reason mismatch")
        check = cell["remediation_steps"]
    refs = ["e0"] + [f"e{i}" for i, section in enumerate(section_order, 1)
                     if section in cites and section in redacted_sections]
    steps = [] if record["verdict"] in ("met", "not_applicable") else [check]
    text = policy["baseline_text"] + " " + record["reason_text"]
    if not steps:
        text += " " + check
    if words(text) > 80 or sentences(text) > 3:
        raise ValueError("GWS explanation exceeds output limits")
    return {"explanation": text, "remediation_steps": steps, "evidence_refs": refs}
