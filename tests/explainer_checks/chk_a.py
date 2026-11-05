"""Check a: the explanation never contradicts the verdict (HEURISTIC; the classifier is validated by unit tests and a planted-error corpus).

Rules per verdict are in verdict_classifier's docstring. This module applies them to the explanation, and to the steps where a step could carry a claim:
not_assessed (every step), not_met (steps, with verbatim baseline text exempt), met and not_applicable (steps must be empty anyway; scanned if present).
"""
from . import verdict_classifier as vc
from .shared_reason import check_shared, FAULT_ENTRY, NOT_IMPLEMENTED_ENTRY


def _fail(code, text, detail=""):
    return {"code": code, "klass": "heuristic", "text": text, "detail": detail}


def check_a(ctx, out):
    if ctx.shared:
        return check_shared(ctx, out, explanation=True, steps=True)
    verdict = ctx.verdict
    fails, notes = [], []
    expl = out.explanation if isinstance(out.explanation, str) else ""
    steps = [s for s in out.steps if isinstance(s, str)]
    if any(expl.startswith(entry["explanation"]) for entry in (FAULT_ENTRY, NOT_IMPLEMENTED_ENTRY)):
        fails.append(_fail("shared_literal_on_ordinary_record", expl, "shared reason code required"))
    exempt_expl = [ctx.requirement, ctx.reason_text]
    exempt_steps = list(ctx.approved_lines_full) + list(ctx.approved_lines_prompt) + [ctx.requirement]

    def scan(text, exempt, where):
        res = vc.analyse(text, exempt_texts=exempt)
        for a in res:
            if a.exempt:
                notes.append({"where": where, "exempt_quote": a.text, "sentence": a.sentence})
                continue
            if verdict == "met":
                if a.sign < 0 and not a.irrealis:
                    fails.append(_fail("met_but_text_negative", a.sentence, f"{a.lemma} x{a.negs} neg ({a.kind}) in {where}"))
                elif a.sign > 0 and a.hedged and not a.irrealis:
                    fails.append(_fail("met_but_text_hedged", a.sentence, f"hedged {a.lemma} in {where}"))
            elif verdict == "not_met":
                if a.sign > 0 and not a.irrealis:
                    fails.append(_fail("not_met_but_text_positive", a.sentence, f"{a.lemma} x{a.negs} pos ({a.kind}) in {where}"))
                elif a.sign < 0 and a.hedged and not a.irrealis:
                    fails.append(_fail("not_met_but_text_hedged", a.sentence, f"hedged {a.lemma} in {where}"))
            elif verdict == "not_assessed":
                fails.append(_fail("not_assessed_but_text_asserts", a.sentence,
                                   f"{a.lemma} ({a.kind}{', conditional' if a.irrealis else ''}) in {where}"))
            elif verdict == "not_applicable":
                if not a.irrealis:
                    fails.append(_fail("not_applicable_but_text_asserts", a.sentence, f"{a.lemma} ({a.kind}) in {where}"))
        return res

    scan(expl, exempt_expl, "explanation")
    for k, s in enumerate(steps):
        if verdict in ("not_assessed", "not_met", "met", "not_applicable"):
            scan(s, exempt_steps if verdict == "not_met" else exempt_steps[-1:] + [ctx.reason_text], f"step {k}")

    vw = vc.verdict_words(expl, exempt_texts=exempt_expl)
    if verdict in ("met", "not_met", "not_applicable") and vw["no_conclusion"]:
        fails.append(_fail("says_no_conclusion_on_" + verdict, expl, "; ".join(vw["no_conclusion"])))
    if verdict in ("met", "not_met", "not_assessed"):
        hits = vw["not_applicable_subject"]
        if hits:
            fails.append(_fail("says_not_applicable_on_" + verdict, expl, "; ".join(hits)))
    if verdict == "not_assessed":
        if not vw["no_conclusion_all"]:
            fails.append(_fail("missing_no_conclusion_phrase", expl, "no 'no conclusion', 'not assessed' or 'cannot be assessed' phrase"))
        if vw["guess"]:
            fails.append(_fail("guess_on_not_assessed", expl, "; ".join(vw["guess"])))
        for k, s in enumerate(steps):
            vws = vc.verdict_words(s)
            if vws["guess"]:
                fails.append(_fail("guess_on_not_assessed", s, f"step {k}: " + "; ".join(vws["guess"])))
    if verdict == "not_applicable" and vw["applies"]:
        fails.append(_fail("says_policy_applies_on_not_applicable", expl, "; ".join(vw["applies"])))
    if verdict == "not_applicable" and not vw["not_applicable_all"]:
        fails.append(_fail("missing_not_applicable_phrase", expl, "no 'does not apply' or 'not applicable' phrase"))
    return {"pass": not fails, "klass": "heuristic", "failures": fails, "notes": notes}
