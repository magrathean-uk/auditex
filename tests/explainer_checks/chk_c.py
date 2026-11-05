"""Check c: says so when evidence is missing (not_assessed only; EXACT on names and non-empty steps, HEURISTIC on verbs).

For a not_assessed prompt the output must: name every cited section verbatim (explanation or steps); say that no conclusion was reached (shared with check a,
re-tested here so c stands alone); say what is missing or unusable (a missing-evidence word); contain no guess or assertion about compliance (check a's classifier,
any compliance predicate fails); carry non-empty steps, each with a collect verb and a cited section name or the word evidence; and no tenant-changing imperative.
For the other verdicts check c passes trivially (no claim is made about missing evidence).
"""
import re

from . import verdict_classifier as vc
from .textnorm import norm
from .shared_reason import check_shared

COLLECT_VERB = re.compile(r"\b(collect|export|run|re-run|rerun|enable|grant|confirm|check|ensure)\b", re.I)
TENANT_CHANGING = re.compile(r"\b(disable|turn\s+off|switch\s+off|delete|remove|set\s+\S+(?:\s+\S+){0,3}\s+to|revoke|block|reset|purge|deactivate|uninstall|wipe|reconfigure|modify|change)\b", re.I)
MISSING_WORD = re.compile(r"\b(missing|unavailable|not\s+available|unusable|cannot\s+be\s+used|can't\s+be\s+used|empty|not\s+collected|absent|incomplete|not\s+provided|lacks?|no\s+data|has\s+no|holds\s+no|contains\s+no|"
                          r"without\s+(?:a\s+)?usable|needed\s+evidence|no\s+usable|unreadable|cannot\s+be\s+read|not\s+usable|not\s+present|did\s+not\s+include|does\s+not\s+include)\b", re.I)


def _f(code, klass, text, detail=""):
    return {"code": code, "klass": klass, "text": text, "detail": detail}


def check_c(ctx, out):
    if ctx.shared:
        return check_shared(ctx, out, explanation=True, steps=True)
    if ctx.verdict != "not_assessed":
        return {"pass": True, "klass": "exact", "failures": [], "notes": ["not applicable to " + ctx.verdict]}
    fails = []
    expl, steps = out.explanation, out.steps
    blob = norm(expl + " " + " ".join(steps))
    for name in ctx.cited:
        if norm(name) not in blob:
            fails.append(_f("section_not_named", "exact", name, "every cited section must appear verbatim in the explanation or the steps"))
    vw = vc.verdict_words(expl)
    if not vw["no_conclusion_all"]:
        fails.append(_f("no_no_conclusion_phrase", "heuristic", expl, "no 'no conclusion', 'not assessed' or 'cannot be assessed' phrase"))
    if not MISSING_WORD.search(expl) and not MISSING_WORD.search(" ".join(steps)):
        fails.append(_f("does_not_say_what_is_missing", "heuristic", expl, "no word saying that evidence is missing, unavailable, empty or unusable"))
    for a in vc.analyse(expl, exempt_texts=[ctx.reason_text, ctx.requirement]):
        if not a.exempt:
            fails.append(_f("guess_about_compliance", "heuristic", a.sentence, f"{a.lemma} ({a.kind})"))
    if vw["guess"]:
        fails.append(_f("guess_words", "heuristic", expl, "; ".join(vw["guess"])))
    if not steps:
        fails.append(_f("no_steps", "exact", "", "not_assessed needs steps that collect or correct the evidence"))
    for i, s in enumerate(steps):
        low = norm(s)
        if not COLLECT_VERB.search(s):
            fails.append(_f("step_without_collect_verb", "heuristic", s, f"step {i}"))
        if not ("evidence" in low or any(norm(n) in low for n in ctx.cited)):
            fails.append(_f("step_names_no_evidence", "exact", s, f"step {i}: no cited section name and not the word evidence"))
        tc = TENANT_CHANGING.search(s)
        if tc:
            fails.append(_f("tenant_changing_step", "heuristic", s, f"step {i}: '{tc.group(0)}'"))
    exact = [f for f in fails if f["klass"] == "exact"]
    return {"pass": not fails, "klass": "exact" if exact else "heuristic", "failures": fails, "notes": []}
