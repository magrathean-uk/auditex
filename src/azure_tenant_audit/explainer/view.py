"""Closed, cited view of already redacted evidence; no I/O or rule evaluation."""
import re
from copy import deepcopy

from .textkit import (
    FAULT,
    canonical,
    collection_lines,
    resolved_units,
    shared_exceptions,
)

FIELDS = ("policy_id", "verdict", "cell", "reason_code", "reason_text")
VIEW_FIELDS = frozenset((*FIELDS, "evidence", "approved_remediation"))
EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
SECTION = re.compile(r"[A-Za-z][A-Za-z0-9_]*\Z")


def mask_emails(value):
    if isinstance(value, str):
        return EMAIL.sub(lambda m: "***@" + m[1], value)
    if isinstance(value, list):
        return [mask_emails(v) for v in value]
    if isinstance(value, dict):
        return {k: mask_emails(v) for k, v in value.items()}
    return value


def shown_section(name, value):
    if name == "scuba_config" and value is not None:
        if not isinstance(value, dict):
            value = {"not_shown": "shape"}
        else:
            value = {k: (v if v is None or isinstance(v, (str, bool, int, float))
                         else {"not_shown": "shape"}) for k, v in value.items()
                     if k in ("M365Environment", "collection_status")}
    value = mask_emails(value)
    return {"not_shown": "size"} if len(canonical(value)) > 6000 else value


def build_view(record, redacted_sections, section_order, *, baselines, collection):
    """Build View from RuleRecord; detail and all other record fields are ignored.

    section_order is the supplied full section order, before citation filtering.
    Absent ordinary evidence stays absent, retaining its original evidence-id gap.
    Exact catalogue validation belongs to render, which has the frozen template.
    """
    if not isinstance(record, dict) or not isinstance(redacted_sections, dict):
        raise ValueError("record and redacted sections must be objects")
    if not isinstance(section_order, list) or any(not isinstance(s, str) or not SECTION.fullmatch(s) for s in section_order):
        raise ValueError("invalid section order")
    if len(set(section_order)) != len(section_order) or "policy" in section_order:
        raise ValueError("duplicate or reserved section")
    try:
        rec = {k: record[k] for k in FIELDS}
    except KeyError as exc:
        raise ValueError("incomplete rule record") from exc
    if rec["verdict"] not in ("met", "not_met", "not_assessed", "not_applicable"):
        raise ValueError("unknown verdict")
    if not all(isinstance(rec[k], str) for k in ("policy_id", "reason_code", "reason_text")):
        raise ValueError("invalid rule fields")
    if rec["cell"] is not None and not isinstance(rec["cell"], str):
        raise ValueError("invalid cell")
    pid = rec["policy_id"]
    entries = [e for e in collection["cells"] if e["policy_id"] == pid]
    if pid not in baselines["policies"] and not entries:
        raise KeyError("unknown policy")
    required = collection["policy_sections"].get(pid)
    if required is None:
        raise KeyError("unknown policy read set")
    cited = record.get("cited_sections")
    cited = list(required) if cited is None else cited
    if (not isinstance(cited, list) or any(not isinstance(s, str) or s not in required or s not in section_order for s in cited)
            or len(set(cited)) != len(cited)):
        raise ValueError("invalid citations")
    shared = shared_exceptions().get(rec["reason_code"])
    if shared:
        if any(rec[k] != shared[k] for k in ("verdict", "cell", "reason_text")) or cited != required:
            raise ValueError("invalid shared exception")
        if rec["reason_code"] == FAULT["reason_code"] and any(s not in redacted_sections or (isinstance(redacted_sections[s], dict)
               and redacted_sections[s].get("collection_status") == "not_collected") for s in cited):
            raise ValueError("shared exception requires collected evidence")
        remediation = list(shared["remediation_steps"])
    elif rec["verdict"] == "not_met":
        remediation = [u["text"] for u in resolved_units(baselines, pid)]
    elif rec["verdict"] == "not_assessed":
        entry = next((e for e in entries if e["cell"] == rec["cell"]), None)
        if entry is None:
            raise KeyError("no collection entry")
        remediation = collection_lines(entry, cited)
    else:
        remediation = []
    public = baselines["policies"].get(pid, {})
    evidence = [{"id": "e0", "section": "policy", "observed": {
        "policy_id": pid, "requirement": public.get("requirement", ""),
        "criticality": public.get("criticality")}}]
    evidence.extend({"id": f"e{i}", "section": s, "observed": shown_section(s, redacted_sections[s])}
                    for i, s in enumerate(section_order, 1) if s in cited and s in redacted_sections)
    rec["reason_text"] = mask_emails(rec["reason_text"])
    return deepcopy(dict(rec, evidence=evidence, approved_remediation=remediation))
