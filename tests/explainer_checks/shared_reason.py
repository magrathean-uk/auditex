"""Closed A1 shared reasons; independent literal assertions for checks a/c/e."""

FAULT_REASON = "Not assessed: Auditex could not evaluate this policy on the collected evidence. This is a product fault, not a tenant setting."
FAULT_ENTRY = {
    "reason_code": "rule_evaluation_failed",
    "verdict": "not_assessed",
    "explanation": "Not assessed: Auditex could not evaluate this policy on the collected evidence. This is a product fault, not a tenant setting.",
    "what_to_collect": [],
    "remediation_steps": ["Report this fault to the product team at contact+auditex@magrathean.uk."],
    "baseline_steps": [],
}
SHARED_CODES = frozenset(("rule_evaluation_failed", "rule_not_implemented"))


def check_shared(ctx, out, *, explanation=False, steps=False):
    failures = []

    def fail(code, text="", detail=""):
        failures.append({"code": code, "klass": "exact", "text": text, "detail": detail})

    entry = ctx.shared
    fault = ctx.reason_code == "rule_evaluation_failed"
    reason = FAULT_REASON if fault else entry["explanation"]
    if ctx.verdict != "not_assessed" or ctx.cell is not None or ctx.reason_text != reason:
        fail("invalid_shared_record", detail=ctx.reason_code)
    for key in ("policy_id", "verdict", "cell", "reason_code", "reason_text"):
        if ctx.data.get(key) != ctx.record.get(key):
            fail("shared_record_view_disagreement", detail=key)
    if fault:
        policy_items = [ev for ev in ctx.data.get("evidence", []) if ev.get("id") == "e0"]
        if (len(policy_items) != 1 or policy_items[0].get("section") != "policy"
                or not isinstance(policy_items[0].get("observed"), dict)
                or policy_items[0]["observed"].get("policy_id") != ctx.policy_id):
            fail("invalid_shared_policy_evidence")
        required = list((ctx.res.pol_meta.get(ctx.policy_id) or {}).get("sections", []))
        if not required or ctx.cited != required:
            fail("invalid_shared_citations", detail="fixed required collected sections in order")
        if ctx.evidence_sections != required:
            fail("invalid_shared_evidence", detail="all required sections must have evidence")
        for ev in ctx.data.get("evidence", [])[1:]:
            observed = ev.get("observed")
            if isinstance(observed, dict) and observed.get("collection_status") == "not_collected":
                fail("shared_evidence_not_collected", detail=ev.get("section", ""))
        if ctx.approved_lines_prompt != entry["remediation_steps"]:
            fail("invalid_shared_approved_steps")
    if explanation and out.explanation != entry["explanation"]:
        fail("shared_explanation_changed", out.explanation, ctx.reason_code)
    if steps and out.steps != entry["remediation_steps"]:
        fail("shared_steps_changed", str(out.steps), "exactly the fixed product step")
    return {"pass": not failures, "klass": "exact", "failures": failures, "notes": []}

NOT_IMPLEMENTED_ENTRY = {
    "reason_code": "rule_not_implemented", "verdict": "not_assessed",
    "explanation": "Not assessed: Auditex has no rule for this policy yet.",
    "what_to_collect": [], "baseline_steps": [],
    "remediation_steps": ["No action is possible until a rule exists for this policy."],
}
