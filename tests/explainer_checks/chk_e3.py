"""Check e3: every step is a full sentence or a command, never a fragment (EXACT on verbatim steps, HEURISTIC on paraphrases).

Quality finding of the step 4 report: the template could leave a tail of a long sentence as a step of its own ("and applications."). A step passes if:
 V  (not_met, the step is verbatim prompt text, first word included case-sensitively: it is covered by order-preserving spans of the prompt's approved_remediation stream, see check e) EVERY span is complete:
      starts at a unit start or right after a token ending in . ! ? (a sentence start) and ends at a unit end or on a token ending in . ! ? : )
      (so a whole sentence, a whole list item or a whole command line, or several of them). One exception, the forced split: a unit longer than the 30-word step limit cannot
      be one step unless it is an executable pre block. Whole approved command
      blocks are indivisible; the forced-split exception applies only to prose.
      A step that is ONE span inside such a prose unit is accepted if it has at least 5 words (the template splits such a unit into balanced pieces, none under 5 words).
      Anything else (a tail, a head cut mid-sentence, a lower-case start in the middle of a unit) is a fragment.
     (all steps: no sentence inside the step starts in lower case after a full stop, unless the step is a command)
 P  (any other step: a paraphrase, a model's own wording, a what_to_collect line) starts with a capital letter, a digit, a quote or bracket, or looks like a command
      (cmdlet, $variable, -Parameter); ends with . ! ? : ) ] a quote, or looks like a command; and has at least two words unless it looks like a command.
"""
import re

from .chk_e import FIXED_CONTINUE, tok_key, verbatim_cover
from .config import LIMITS
from .textnorm import norm

TERMINAL = ".!?"
END_OK = tuple(".!?:)]\"'")
CODEISH = re.compile(r"(?:^|\s)(?:[A-Z][a-z]+-[A-Z][A-Za-z]+|\$[A-Za-z_]|-[A-Z][A-Za-z]+)\b|^\$|^[A-Za-z0-9_.-]+\([^)]*\)$")      # cmdlet, $variable, -Parameter (dash-folded text)
LOWER_AFTER_STOP = re.compile(r"(?<!\be\.g)(?<!\bi\.e)(?<!\betc)(?<!\bvs)(?<!\bapprox)(?<![\s(][a-z])[.!?][\"')\]]*\s+[a-z]")     # "... Sharing. adjust external ..."
START_CODE = re.compile(r"^(?:[A-Za-z]+-[A-Za-z]+\w*|\$[A-Za-z_]|-[A-Z])")      # a command may start with a cmdlet, a $variable or a -Parameter; "run Get-X ..." must start like a sentence
START_OK = re.compile(r"""^[\"'(\[]?[A-Z0-9$@%#]""")


def _f(code, text, detail=""):
    return {"code": code, "klass": "exact", "text": text, "detail": detail}


def _span_complete(stream, s, e):
    toks = stream.toks
    start_ok = stream.b_before[s] or s == 0 or toks[s - 1][-1:] in TERMINAL
    end_ok = stream.b_after[e - 1] or toks[e - 1][-1:] in END_OK or toks[e - 1].endswith('."')
    return start_ok and end_ok


def check_e3(ctx, out):
    fails, notes = [], []
    pol_ids = {x.upper() for x in [ctx.policy_id] + ctx.xref_ids}
    for i, s in enumerate(out.steps):
        if ctx.whole_command(s):
            continue
        if ctx.command_units and START_CODE.match(norm(s, fold=False)):
            fails.append(_f("step_fragment", s, "executable block must be a whole approved unit"))
            continue
        ns = norm(s)
        m = FIXED_CONTINUE.match(ns)
        if m and m.group(1).upper() in pol_ids:
            continue
        where = f"step {i}"
        m_low = next((m for m in LOWER_AFTER_STOP.finditer(s) if re.match(r"[a-z]+[,;:]?(?:\s|$)", s[m.end() - 1:])), None)       # a plain lower-case word (not a label "b.", an address or a host name)
        if m_low and not CODEISH.search(norm(s, fold=False)):
            fails.append(_f("step_fragment", s, f"{where}: a sentence inside the step starts in lower case ({s[max(0, m_low.start() - 8):m_low.end() + 8]!r})"))
            continue
        spans = None
        if ctx.verdict == "not_met":
            core = re.sub(r"\s*\((MS\.[A-Za-z]+\.\d+\.\d+v\d+)\)\s*$", lambda mm: "" if mm.group(1).upper() in pol_ids else mm.group(0), s)
            keys = [tok_key(t) for t in core.split() if tok_key(t)]
            spans = verbatim_cover(ctx.stream_prompt, keys)
            if spans:        # the cover is case-blind; a step whose first word differs in case from the prompt's own text (a lowered capital) is judged as a paraphrase below
                first = s.split()[0].replace(";", "")
                if first != ctx.stream_prompt.toks[spans[0][0]]:
                    spans = None
        if spans:
            st = ctx.stream_prompt
            if any(st.unit_code[st.unit_of[a]] for a, b in spans):
                fails.append(_f("step_fragment", s, f"{where}: executable block must be a whole approved unit"))
                continue
            bad = [(a, b) for a, b in spans if not _span_complete(st, a, b)]
            if not bad:
                continue
            if len(spans) == 1:
                a, b = spans[0]
                u = st.unit_of[a]
                if not st.unit_code[u] and st.unit_of[b - 1] == u and st.unit_words[u] > LIMITS["step_words"] and (b - a) >= 5:
                    notes.append({"forced_split_piece": s[:60], "where": where})
                    continue
            a, b = bad[0]
            fails.append(_f("step_fragment", s, f"{where}: a piece of a sentence or line (tokens {a} to {b}), not a full sentence or command"))
            continue
        # P: a paraphrase or a what_to_collect line
        t = s.strip()
        code = bool(CODEISH.search(norm(t, fold=False)))
        if not START_OK.match(t) and not START_CODE.match(norm(t, fold=False)):
            fails.append(_f("step_fragment", s, f"{where}: does not start like a sentence (capital letter, digit, quote or command)"))
        elif not code and not t.endswith(END_OK):
            fails.append(_f("step_fragment", s, f"{where}: does not end like a sentence"))
        elif not code and len(t.split()) < 2:
            fails.append(_f("step_fragment", s, f"{where}: a single word"))
    return {"pass": not fails, "klass": "exact", "failures": fails, "notes": notes}
