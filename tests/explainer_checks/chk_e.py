"""Check e: remediation only from the approved vocabulary or verbatim baseline text (EXACT on verbatim and on named things; HEURISTIC on paraphrase).

Exact whole executable pre blocks present in the prompt and fixed policy
metadata pass as indivisible commands. Partial/edited commands cannot borrow
prose splitting or paraphrase rules; the step-count limit is unchanged.

Matching rules (all after textnorm.norm; a step is checked on its own):
 E1 verbatim (exact). The step's tokens (case-folded, dashes folded, trailing . , ; : removed from each token, the ';' character dropped) split into one or more
    SPANS, each a contiguous run of the approved baseline token stream (the policy's Instructions, then every cross-referenced policy's), in stream order.
    A span must start and end at a legal cut: a unit boundary (line start/end, sentence start/end), after . , ; : ! ? or '>', or before and/or/then/that/which/so/because;
    and it must be at least 3 tokens long unless it is a whole unit. These are exactly the merges and truncations the template uses (merging units to fit 30 words,
    dropping orientation sentences, splitting a long unit at a clause boundary). Order-preserving; one fixed template sentence about continuing is also allowed.
 E2 not_assessed steps: equal (whitespace-normalised) to a what_to_collect line of the cell, or to a line the prompt carries.
 E3 paraphrase (HEURISTIC, proposed rule). A step that fails E1/E2 passes only if ALL of:
      - it has at least PARAPHRASE_MIN_TOKENS content tokens (shorter steps must be verbatim);
      - every exact-class specific (cmdlet, parameter, snake, camel, quoted, number, identifier) is in the approved text, and every navigation target
        (the capitalised label after select/click/choose/open/navigate to/go to/under, per segment of a '>' path) is in the whitelist or the portal vocabulary;
      - token-level containment: at least PARAPHRASE_THETA (0.85) of its content tokens occur in ONE window of up to three consecutive approved units;
      - state words are preserved: the candidate's polarity words (on, off, enabled, disabled, true, false, not, no, never, none, all, only, allow, block ...)
        are a sub-multiset of the window's, and every approved unit that the candidate covers by at least half keeps its polarity words in the candidate.
 E4 the plan's quantitative limits: at most len(approved_remediation in the prompt) + 2 steps; at least 60 percent of the step's specifics (cmdlets, parameters,
    names, labels) occur in the approved text; navigation phrases whose target is outside the whitelist and the portal vocabulary fail (exact).
 Verdicts met and not_applicable: any step fails (nothing is approved).
"""
import re

from .config import PARAPHRASE_MAX_NOVEL, PARAPHRASE_MIN_TOKENS, PARAPHRASE_THETA, PARAPHRASE_WINDOW_UNITS
from .specifics import extract
from .textnorm import norm, sentence_split

EXACT_CLASSES = ("url", "email", "guid", "ipv4", "domain", "hex", "policy_id", "cmdlet", "parameter", "snake", "camel", "quoted", "number")
CONNECTORS = {"and", "or", "then", "that", "which", "so", "because"}
STOP = {"a", "an", "the", "of", "to", "in", "for", "and", "or", "is", "are", "be", "it", "its", "this", "that", "as", "at", "by", "with", "from", "into", "then", "so", "if",
        "you", "your", "will", "can", "should", "shall", "must", "also", "please", "these", "those", "which", "where", "when", "each", "every", "any", "per", "using", "use"}
STATE = {"on", "off", "enabled", "disabled", "true", "false", "not", "no", "never", "none", "all", "only", "allow", "allowed", "block", "blocked", "enable", "disable", "yes",
         "without", "always", "optional", "required", "high", "medium", "low"}
FIXED_CONTINUE = re.compile(r"^the baseline instructions for (ms\.[a-z]+\.\d+\.\d+v\d+) continue with further steps; follow them in order after these\.?$")
NAV_VERB = r"(?i:\b(?:select|click|choose|navigate\s+to|go\s+to|open|under|tap|press|browse\s+to|expand|switch\s+to|toggle))"
NAV = re.compile(NAV_VERB + r"\s+(?:(?i:the)\s+)?([^.;:\n]+)")
LABEL_RUN = re.compile(r"[A-Z0-9(][\w()'/&.-]*(?:\s+(?:[A-Z0-9(][\w()'/&.-]*|and|of|for|the|in|on|to)(?=\s+[A-Z0-9(]|\s*$|\s*[,)>]))*")


def _f(code, klass, text, detail=""):
    return {"code": code, "klass": klass, "text": text, "detail": detail}


def tok_key(t):
    return norm(t.replace(";", "")).strip(".,;:!?*_`")


def content_tokens(text):
    return [w for w in re.findall(r"[a-z0-9]+", norm(text)) if w not in STOP]


def state_counts(text):
    c = {}
    for w in re.findall(r"[a-z0-9]+", norm(text)):
        if w in STATE:
            c[w] = c.get(w, 0) + 1
    return c


TAIL_STOP = {"and", "or", "then", "to", "in", "on", "for", "of", "from", "with", "by", "so", "if", "as", "at", "the", "a", "an", "is", "are", "be", "that", "which", "until", "when", "where",
             "section", "page", "tab", "button", "menu", "list", "field", "option", "setting", "settings", "policy", "policies", "icon", "link"}


def nav_targets(step):
    """-> list of (label, extended label): the capitalised run after a navigation verb (per segment of a '>' path) and the same run plus up to three lower-case tail words
    (UI labels such as 'Meeting policies' have a lower-case tail; tail words that merely describe the control, like 'button' or 'section', stop the extension)."""
    out = []
    for m in NAV.finditer(norm(step, fold=False)):
        rest = m.group(1)
        for seg in rest.split(">"):
            seg = seg.strip()
            r = LABEL_RUN.match(seg)
            if r and r.group(0).strip():
                lab = r.group(0).strip(" ,")
                if re.fullmatch(r"[A-Z]", lab):
                    continue
                tail = []
                for w in seg[r.end():].split():
                    w2 = w.strip(".,;:)")
                    if not w2 or w2.casefold() in TAIL_STOP or w2[0].isupper() or len(tail) >= 3:
                        break
                    tail.append(w2)
                    if w != w2:
                        break
                out.append((lab, " ".join([lab] + tail)))
    return out


def verbatim_cover(stream, cand_keys):
    """E1: can cand_keys be partitioned into order-preserving spans of the stream at legal cuts? -> list of (start, end) spans or None."""
    n, m = len(cand_keys), len(stream.keys)
    if n == 0:
        return None
    keys, toks, bb, ba = stream.keys, stream.toks, stream.b_before, stream.b_after

    def start_ok(s):
        return bb[s] or s == 0 or toks[s - 1][-1:] in ".,;:!?" or toks[s - 1] == ">" or keys[s] in CONNECTORS

    def end_ok(e):
        return ba[e - 1] or e == m or toks[e - 1][-1:] in ".,;:!?" or toks[e - 1] == ">" or keys[e] in CONNECTORS

    occ = {}
    for i, k in enumerate(keys):
        occ.setdefault(k, []).append(i)
    seen = {}
    frontier = [(0, 0, ())]
    budget = 200000
    while frontier and budget > 0:
        i, pos, spans = frontier.pop()
        if i == n:
            return list(spans)
        if (i, pos) in seen:
            continue
        seen[(i, pos)] = True
        for s in occ.get(cand_keys[i], ()):
            if s < pos or not start_ok(s):
                continue
            L = 0
            while i + L < n and s + L < m and keys[s + L] == cand_keys[i + L]:
                L += 1
                budget -= 1
                if not end_ok(s + L):
                    continue
                whole_unit = bb[s] and ba[s + L - 1]
                if L >= 3 or whole_unit or (i == 0 and i + L == n and ba[s + L - 1]):   # a step that is one tail fragment of a unit (template split) is allowed alone
                    frontier.append((i + L, s + L, spans + ((s, s + L),)))
        # prefer longer spans first: the frontier is a stack, so the longest was pushed last for each start
    return None


def _sentence_eval(sent, units):
    toks = content_tokens(sent)
    if len(toks) < PARAPHRASE_MIN_TOKENS:
        return False, f"sentence with only {len(toks)} content tokens must be verbatim: {sent[:60]!r}"
    cand_states = state_counts(sent)
    cset = set(toks)
    ucontent = [set(content_tokens(u)) for u in units]
    allowed_novel = min(int((1 - PARAPHRASE_THETA) * len(toks) + 1e-9), PARAPHRASE_MAX_NOVEL)
    best = None
    for w in range(1, PARAPHRASE_WINDOW_UNITS + 1):          # the SMALLEST window that contains the sentence decides: no hunting for a window that excuses a changed word
        for a in range(0, len(units) - w + 1):
            win = set().union(*ucontent[a:a + w])
            novel = [t for t in toks if t not in win]
            if len(toks) and (len(toks) - len(novel)) / len(toks) < PARAPHRASE_THETA:
                continue
            best = (a, w, novel)
            break
        if best:
            break
    if not best:
        return False, "containment below %.2f in every window of up to %d approved units: %r" % (PARAPHRASE_THETA, PARAPHRASE_WINDOW_UNITS, sent[:60])
    a, w, novel = best
    if len(novel) > allowed_novel:
        return False, f"{len(novel)} novel content tokens {novel[:4]} exceed the allowance of {allowed_novel}"
    wstates = state_counts(" ".join(units[a:a + w]))
    if any(cand_states[k] > wstates.get(k, 0) for k in cand_states):
        return False, f"state word changed: candidate {sorted(cand_states)} vs window {sorted(wstates)}"
    lost = []
    for u, uc in zip(units[a:a + w], ucontent[a:a + w]):
        if uc and len(uc & cset) / len(uc) >= 0.5:
            for k, v in state_counts(u).items():
                if cand_states.get(k, 0) < v:
                    lost.append(k)
    if lost:
        return False, f"state word dropped: {sorted(set(lost))}"
    return True, f"containment {1 - len(novel) / len(toks):.2f} in a window of {w} unit(s)"


def paraphrase_eval(step, units, stream=None):
    """E3, applied per sentence of the step (so an appended sentence cannot hide inside a long step): -> (ok, detail). units: approved unit strings in order.
    A sentence that is itself verbatim (E1) passes without the similarity rule."""
    notes = []
    for sent in sentence_split(step):
        if stream is not None:
            keys = [tok_key(t) for t in sent.split() if tok_key(t)]
            if keys and verbatim_cover(stream, keys) is not None:
                continue
        ok, d = _sentence_eval(sent, units)
        if not ok:
            return False, d
        notes.append(d)
    return True, "; ".join(notes) or "all sentences verbatim"


def check_e(ctx, out):
    if ctx.shared:
        from .shared_reason import check_shared
        return check_shared(ctx, out, explanation=True, steps=True)
    if ctx.verdict == "not_assessed" and ctx.wtc is None:
        return {"pass": False, "klass": "exact", "failures": [
            _f("unknown_collection_cell", "exact", "", "ordinary not_assessed requires an approved cell entry")], "notes": []}
    fails, notes = [], []
    steps = out.steps
    verdict = ctx.verdict
    if verdict in ("met", "not_applicable"):
        for i, s in enumerate(steps):
            fails.append(_f("step_without_approved_vocabulary", "exact", s, f"step {i}: verdict {verdict} approves no remediation"))
        return {"pass": not fails, "klass": "exact", "failures": fails, "notes": notes}
    limit = len(ctx.approved_lines_prompt) + 2
    if len(steps) > limit:
        fails.append(_f("too_many_steps", "exact", "", f"{len(steps)} steps, limit len(approved_remediation)+2 = {limit}"))
    if verdict == "not_met":
        units = list(ctx.prompt_units)           # what the prompt carries (DF-2); the independent baseline reader is compared against it in test_builder_vs_reader.py
        if not steps:
            notes.append("no steps for not_met (check e2 fails it)")
    else:
        units = list(ctx.approved_lines_full)
    approved_text = norm(" \n ".join(units))
    approved_names = set()
    for sp in extract(" \n ".join(units)):
        approved_names.add(sp.key)
    for c in ctx.cited:
        approved_names.add(norm(c))
    approved_numbers = {sp.key for sp in extract(" \n ".join(units)) if sp.cls == "number"}
    for i, s in enumerate(steps):
        if ctx.whole_command(s):
            continue
        if ctx.command_units and re.match(r"^(?:[A-Za-z]+-[A-Za-z]+\w*|\$[A-Za-z_]|-[A-Z])", s):
            fails.append(_f("partial_command_block", "exact", s, "executable block must be a whole approved unit"))
            continue
        where = f"step {i}"
        ns = norm(s)
        if verdict == "not_met" and FIXED_CONTINUE.match(ns) and FIXED_CONTINUE.match(ns).group(1).upper() in {x.upper() for x in [ctx.policy_id] + ctx.xref_ids}:
            continue
        if verdict == "not_assessed":
            if any(ns == norm(u) for u in units):
                continue
        else:
            core = re.sub(r"\s*\((MS\.[A-Za-z]+\.\d+\.\d+v\d+)\)\s*$", lambda m: "" if m.group(1).upper() in {x.upper() for x in [ctx.policy_id] + ctx.xref_ids} else m.group(0), s)
            keys = [tok_key(t) for t in core.split() if tok_key(t)]
            spans = verbatim_cover(ctx.stream_prompt, keys)
            if spans is not None:
                if any(ctx.stream_prompt.unit_code[ctx.stream_prompt.unit_of[a]] for a, b in spans):
                    fails.append(_f("partial_command_block", "exact", s, f"{where}: executable block must remain whole"))
                    continue
                continue
        # not verbatim: E3 applies. Exact-class specifics first (these fail without any similarity rule)
        specs = extract(s)
        exact_bad = []
        total_spec = in_approved_spec = 0
        for sp in specs:
            if sp.cls in EXACT_CLASSES:
                total_spec += 1
                ok = (sp.key in approved_numbers) if sp.cls == "number" else (sp.key in approved_names or (sp.cls == "quoted" and norm(sp.raw) in approved_text))
                in_approved_spec += ok
                if not ok:
                    exact_bad.append(sp)
        navs = nav_targets(s)
        portal = ctx.res.portal
        nav_bad = []
        for t, ext in navs:
            nt = norm(t)
            if ext != t and norm(ext) not in ctx.W.text and norm(ext) not in portal and (nt in ctx.W.text or nt in portal):
                fails.append(_f("navigation_label_tail_not_in_view", "heuristic", ext, f"{where}: the label's tail is not in the whitelist or the portal vocabulary"))
            total_spec += 1
            if nt in approved_text:
                in_approved_spec += 1
            elif nt in ctx.W.text or nt in portal:
                pass
            if not (nt in ctx.W.text or nt in portal):
                nav_bad.append(t)
        for sp in exact_bad:
            fails.append(_f("invented_" + sp.cls + "_in_step", "exact", sp.raw, f"{where}: not in the approved text"))
        for t in nav_bad:
            fails.append(_f("navigation_target_outside_vocabulary", "exact", t, f"{where}: not in the whitelist or the portal vocabulary"))
        if total_spec and in_approved_spec / total_spec < 0.6:
            fails.append(_f("under_60_percent_specifics_approved", "exact", s, f"{where}: {in_approved_spec} of {total_spec} specifics in the approved text"))
        if exact_bad or nav_bad:
            continue
        ok, detail = paraphrase_eval(s, units, ctx.stream_prompt if verdict == "not_met" else None)
        if ok:
            notes.append({"paraphrase_accepted": s, "detail": detail, "where": where})
        else:
            fails.append(_f("step_not_from_approved_text", "heuristic", s, f"{where}: {detail}"))
    exact = [f for f in fails if f["klass"] == "exact"]
    return {"pass": not fails, "klass": "exact" if exact else ("heuristic" if fails else "exact"), "failures": fails, "notes": notes}
