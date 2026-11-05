"""Check e2: a not_met item must carry at least one remediation step (EXACT).

Plan check (e) bounds the steps from above (len(approved_remediation) + 2) and checks what they say; nothing required a step to exist, so an empty list passed S and e
(finding 2 of the step 5 report). For verdict not_met the explainer must give the reader something to do: `remediation_steps` must hold at least one step that is not only
the fixed "the baseline Instructions ... continue with further steps" sentence. Other verdicts: not applicable here (met and not_applicable are held empty by S; not_assessed
is held non-empty by check c).
"""
import re

FIXED_CONTINUE = re.compile(r"^the baseline instructions for ms\.[a-z]+\.\d+\.\d+v\d+ continue with further steps; follow them in order after these\.?$")


def _f(code, text, detail=""):
    return {"code": code, "klass": "exact", "text": text, "detail": detail}


def check_e2(ctx, out):
    if ctx.shared:
        from .shared_reason import check_shared
        return check_shared(ctx, out, steps=True)
    if ctx.verdict != "not_met":
        return {"pass": True, "klass": "exact", "failures": [], "notes": ["not applicable to " + ctx.verdict]}
    steps = [s for s in out.steps if s.strip()]
    if not steps:
        return {"pass": False, "klass": "exact", "failures": [_f("not_met_without_steps", "", "a not_met item must carry at least one remediation step")], "notes": []}
    real = [s for s in steps if not FIXED_CONTINUE.match(" ".join(s.split()).casefold())]
    if not real:
        return {"pass": False, "klass": "exact", "failures": [_f("not_met_only_continue_step", steps[0][:80], "the only step is the fixed 'continue with further steps' sentence")], "notes": []}
    return {"pass": True, "klass": "exact", "failures": [], "notes": []}
