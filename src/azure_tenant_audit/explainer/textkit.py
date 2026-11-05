"""Shared text helpers for the template explainer (build, render and self-test use the same code).

Pure functions only: no I/O, no network.
"""
import re

PREFIXES = (
    ("Requirement not met: ", "not_met", None),
    ("Requirement met: ", "met", None),
    ("Not applicable: ", "not_applicable", None),
    ("Data unavailable: ", "not_assessed", "unavailable"),
    ("Data unusable: ", "not_assessed", "unusable"),
)
SUFFIXES = ("; the policy was not assessed.", ", so the policy was not assessed.", "; the policy was not assessed", ".")

# Customer wording: the controlled reason texts of a handful of cells name the rule language or a tool pin, or use a compliance
# word inside a not assessed text. (verdicts it applies to, regex, replacement). Applied in order, to the body only.
ALL = ("met", "not_met", "not_assessed", "not_applicable")
SCRUB = []

# Words the explanation must never use about a verdict other than the cell's (self-test lexicon; the plan's check (a) is richer).
POSITIVE = re.compile(r"\b(requirement met|is met|are met|meets|complies|compliant with|satisfies|consistent with|passes|in line with)\b", re.I)
NEGATIVE = re.compile(r"\b(requirement not met|not met|does not meet|fails|violat\w*|non-?compliant|falls short|differs from)\b", re.I)
NOCONCL = re.compile(r"\b(not assessed|no conclusion|cannot be assessed)\b", re.I)
NOTAPPLIC = re.compile(r"\b(does not apply|not applicable)\b", re.I)
COMPLIANCE_ANY = re.compile(r"\b(meets?|complies|compliant|non-?compliant|passes|satisf\w+|fails?|violat\w*|falls short|not met|in line with)\b", re.I)


def split_reason(text):
    """reason_text -> (verdict_from_prefix, lead_kind, body). Raises ValueError for text outside the controlled prefixes."""
    for pre, verdict, lead in PREFIXES:
        if text.startswith(pre):
            body = text[len(pre):]
            for suf in SUFFIXES:
                if body.endswith(suf):
                    body = body[: -len(suf)]
                    break
            return verdict, lead, body.strip()
    raise ValueError("reason_text has no controlled prefix: " + text[:60])


def scrub(body, verdict):
    for verdicts, rx, rep in SCRUB:
        if verdict in verdicts:
            body = re.sub(rx, rep, body)
    return body


def words(s):
    return len(s.split())


_ABBR = (("e.g.", "e\u2024g\u2024"), ("i.e.", "i\u2024e\u2024"), ("U.S.", "U\u2024S\u2024"), ("etc.", "etc\u2024"), ("vs.", "vs\u2024"), ("approx.", "approx\u2024"),
         ("No.", "No\u2024"), ("St.", "St\u2024"), ("Inc.", "Inc\u2024"), ("Ltd.", "Ltd\u2024"))
_SENT = re.compile(r"([.!?][\"')\]]*)\s+(?=[A-Z0-9(\"'])(?!\(MS\.[A-Z]+\.\d)")      # a trailing "(MS.X.1.1v1)" policy tag stays with its sentence
_LABEL = re.compile(r"(?<![\w.])([a-z])\.(?=\s)")                                   # "a. Suspicious ..." list labels are not sentence ends


def sentence_split(text, *, baseline_units=True):
    """Sentences of `text`: a full stop, question or exclamation mark (optionally followed by closing quotes or brackets) and whitespace, then a capital letter,
    digit, bracket or quote ends a sentence; common abbreviations are protected.
    Baseline units retain list labels and trailing policy tags; output counting
    uses the stricter independent checker boundary."""
    t = text.strip()
    for a, b in _ABBR:
        t = t.replace(a, b)
    if baseline_units:
        t = _LABEL.sub("\\1\u2024", t)
    out, last = [], 0
    boundary = _SENT if baseline_units else re.compile(r"([.!?][\"')\]]*)\s+(?=[A-Z0-9(\"'])")
    for m in boundary.finditer(t):
        out.append(t[last:m.end(1)])
        last = m.end()
    out.append(t[last:])
    return [p.replace("\u2024", ".").strip() for p in out if p.strip()]


def sentences(s):
    # Output must satisfy the independent sentence cap, even before a policy tag.
    # Baseline instruction splitting retains the historical policy-tag handling.
    return len(sentence_split(s, baseline_units=False))


CONNECTORS = ("and", "or", "then", "that", "which", "so", "because")


def split_balanced(unit, limit, min_piece=5):
    """Split a unit longer than `limit` words into the fewest pieces, keeping every word verbatim and in order, every piece within [min_piece, limit] words and
    the pieces as even as the boundaries allow. A cut is legal after a word ending in , ; : . ! ? or after '>' (a menu path) or before and, or, then, that, which, so, because;
    punctuation boundaries are preferred, then a connector, then a menu-path arrow. A trailing comma or semicolon is dropped from a piece. Never leaves a tiny tail (a 31-word sentence becomes 15 + 16 words).
    If no legal boundary set exists the cut falls at the even position."""
    toks = unit.split()
    n = len(toks)
    if n <= limit:
        return [unit]
    k = -(-n // limit)

    def legal(i):                      # a cut between toks[i-1] and toks[i]
        if i <= 0 or i >= n or re.fullmatch(r"[a-zA-Z]\.", toks[i - 1]):      # never between a list label ("a.") and its text
            return None
        if toks[i - 1].endswith((",", ";", ":", ".", "!", "?")):
            return 0
        if toks[i] in CONNECTORS:
            return 3
        if toks[i - 1] == ">":                 # inside a menu path: only if nothing better exists
            return 8
        return None

    best = None

    def rec(start, cuts_left, acc, cost):
        nonlocal best
        if cuts_left == 0:
            size = n - start
            if min_piece <= size <= limit:
                c = cost + abs(size - n / k)
                if best is None or c < best[0]:
                    best = (c, acc)
            return
        lo = max(start + min_piece, n - limit * cuts_left)
        hi = min(start + limit, n - min_piece * cuts_left)
        for i in range(lo, hi + 1):
            pen = legal(i)
            if pen is not None:
                rec(i, cuts_left - 1, acc + [i], cost + abs(i - start - n / k) + pen)

    rec(0, k - 1, [], 0.0)
    if best is None:
        cuts = [round(i * n / k) for i in range(1, k)]
    else:
        cuts = best[1]
    out, prev = [], 0
    for c in cuts + [n]:
        out.append(" ".join(toks[prev:c]).rstrip(",;"))
        prev = c
    return out


ACTION_VERBS = frozenset("""sign select click go navigate open run connect enable disable set ensure follow create add configure perform repeat use verify check apply remove assign
validate count divide refer see publish test identify review confirm edit choose find enter expand return log save search turn update scroll determine install grant copy paste type
ensure make leave keep delete remove replace switch toggle start stop restart wait download upload import export register ensure sort filter""".split())
LEAD_WORDS = ("first", "then", "next", "finally", "also", "now", "second", "third", "after")


def actionable(unit):
    """True if the unit instructs the reader to do something: it ends with ':' (a lead-in to the steps) or its first word (after First, Then, Next ...) is an action verb."""
    t = unit.strip()
    if t.endswith(":"):
        return True
    ws = [w.strip(",.;:()\"'").lower() for w in t.split()]
    while ws and ws[0] in LEAD_WORDS:
        ws = ws[1:]
    return bool(ws) and ws[0] in ACTION_VERBS


_MD_CODE = re.compile(r"`")
_MD_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_MD_ITALIC = re.compile(r"(?<![\w*])\*([^*\n]+?)\*(?![\w*])")


def strip_markdown(t):
    """Customer text has no markdown: backticks, **bold** and *italic* markers are removed (the words stay). Applied by the renderer as a last line of defence."""
    t = _MD_CODE.sub("", t)
    t = _MD_BOLD.sub(r"\1", t)
    return _MD_ITALIC.sub(r"\1", t)


STRONG_NEG = {"no", "none", "nothing", "never", "without", "neither", "nor"}
WEAK_NEG = {"not", "cannot"}


def polarity(text):
    """(positive, negative) compliance assertions after a simple negation flip. Quantifier negators (no, none, never, without) flip any lexicon word
    earlier in the same clause; not/cannot/n't flip a positive word anywhere earlier in the clause and a negative word only within three words
    (clauses end at . ! ? ; : or a bracket). A heuristic for this self-test only; the plan's check (a) is validated separately."""
    pos = neg = 0
    for sent in sentence_split(text):
        for clause in re.split(r"[;:()]", sent):
            for rx, sign in ((POSITIVE, 1), (NEGATIVE, -1)):
                for m in rx.finditer(clause):
                    before = [w.lower().strip(",") for w in clause[: m.start()].split()]
                    near = before[-3:]
                    negated = (any(w in STRONG_NEG for w in before) or
                               any(w in WEAK_NEG or w.endswith("n't") for w in (before if sign > 0 else near)))
                    s = -sign if negated else sign
                    pos += s > 0
                    neg += s < 0
    return pos, neg

# Shared mapping adapters; deliberately independent of the baseline/collection loaders.
def canonical(value):
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


# Shipped file form. The generated template repeats the same step, reason and wording values across many cells, so the
# file stores each distinct value once in ``tables`` and a cell refers to it by position. ``expand_template`` is the exact
# inverse of ``compact_template``: loaders and tests see the in-memory TemplateData, whose canonical bytes and digests
# are what the drift gates compare. Step lists are interned per step; every other listed field per value. A cell whose
# full remediation equals its shown remediation stores ``null`` for the full list.
INTERNED_FIELDS = ("area", "cited", "cited_variants", "evidence_kind", "explanation_template",
                   "explanation_template_fallbacks", "kind", "limitations", "placeholders", "reason_codes",
                   "reason_pairs", "reason_patterns", "reason_texts", "reason_texts_by_code", "recommendations",
                   "remediation_source")
STEP_FIELDS = ("remediation_steps", "remediation_steps_full")


def compact_template(template):
    """TemplateData to the shipped form (a new object; the argument is not changed).

    Also omitted when derivable: a cell's ``source`` (``{cell, file, policy_id}`` with one shared file, kept once as
    ``cell_source_file``) and its ``reason_texts`` (when they are exactly the texts of ``reason_pairs`` in order).
    """
    tables = {name: [] for name in (*INTERNED_FIELDS, "steps")}
    index = {name: {} for name in tables}

    def intern(name, value):
        key = canonical(value)
        if key not in index[name]:
            index[name][key] = len(tables[name])
            tables[name].append(value)
        return index[name][key]

    files = {cell["source"]["file"] for cell in template["cells"]}
    shared_file = next(iter(files)) if len(files) == 1 else None
    derivable = shared_file is not None and all(
        cell["source"] == {"cell": cell["cell"], "file": shared_file, "policy_id": cell["policy_id"]}
        for cell in template["cells"])
    cells = []
    for cell in template["cells"]:
        out = {}
        for key, value in cell.items():
            if key == "source" and derivable:
                continue
            if key == "reason_texts" and value == [pair["reason_text"] for pair in cell["reason_pairs"]]:
                continue
            if key in INTERNED_FIELDS:
                out[key] = intern(key, value)
            elif key in STEP_FIELDS:
                out[key] = None if key == "remediation_steps_full" and value == cell["remediation_steps"] else [
                    intern("steps", step) for step in value]
            else:
                out[key] = value
        cells.append(out)
    head = {k: v for k, v in template.items() if k != "cells"}
    if derivable:
        head["cell_source_file"] = shared_file
    return {**head, "tables": tables, "cells": cells}


def expand_template(data):
    """The shipped form back to TemplateData (fresh objects); a document without ``tables`` is returned as is."""
    from copy import deepcopy
    if "tables" not in data:
        return data
    tables = data["tables"]
    shared_file = data.get("cell_source_file")
    cells = []
    for cell in data["cells"]:
        out = {}
        for key, value in cell.items():
            if key in INTERNED_FIELDS:
                out[key] = deepcopy(tables[key][value])
            elif key in STEP_FIELDS:
                out[key] = None if value is None else [deepcopy(tables["steps"][i]) for i in value]
            else:
                out[key] = value
        if out.get("remediation_steps_full", 0) is None:
            out["remediation_steps_full"] = deepcopy(out["remediation_steps"])
        if "source" not in out and shared_file is not None:
            out["source"] = {"cell": out["cell"], "file": shared_file, "policy_id": out["policy_id"]}
        if "reason_texts" not in out:
            out["reason_texts"] = [pair["reason_text"] for pair in out["reason_pairs"]]
        cells.append(out)
    return {**{k: v for k, v in data.items() if k not in ("tables", "cells", "cell_source_file")}, "cells": cells}



def digest(value):
    import hashlib
    return hashlib.sha256(canonical(value).encode()).hexdigest()


FAULT = {
    "reason_code": "rule_evaluation_failed", "verdict": "not_assessed", "cell": None,
    "reason_text": "Not assessed: Auditex could not evaluate this policy on the collected evidence. This is a product fault, not a tenant setting.",
    "explanation": "Not assessed: Auditex could not evaluate this policy on the collected evidence. This is a product fault, not a tenant setting.",
    "what_to_collect": [], "remediation_steps": ["Report this fault to the product team at contact+auditex@magrathean.uk."], "baseline_steps": [],
    "recommendations": ["report_product_fault"],
}

NOT_IMPLEMENTED = {
    "reason_code": "rule_not_implemented", "verdict": "not_assessed", "cell": None,
    "reason_text": "Not assessed: Auditex has no rule for this policy yet.",
    "explanation": "Not assessed: Auditex has no rule for this policy yet.",
    "what_to_collect": [], "baseline_steps": [], "recommendations": [],
    "remediation_steps": ["No action is possible until a rule exists for this policy."],
}


def shared_exceptions():
    return {FAULT["reason_code"]: FAULT, NOT_IMPLEMENTED["reason_code"]: NOT_IMPLEMENTED}


def resolved_units(baselines, policy_id):
    """Own units followed by the pinned XREF range, including nested children."""
    from copy import deepcopy
    rows = list(baselines["policies"].get(policy_id, {}).get("instructions", []))
    for xref in baselines["xrefs"]:
        if xref["policy_id"] != policy_id:
            continue
        enabled = xref["labels"] is None
        for unit in baselines["policies"][xref["target"]]["instructions"]:
            if xref["labels"] is not None and unit["level"] == 0:
                enabled = unit["kind"] == "num" and unit["label"] in xref["labels"]
            if enabled:
                rows.append(unit)
    # Same whole-trailing-unit cap as the reader; never slice customer prose.
    while rows and len(canonical([u["text"] for u in rows])) > 6000:
        rows.pop()
    return deepcopy(rows)


def collection_lines(entry, cited):
    """Expand only the fixed section-name slot; never evidence-derived values."""
    from string import Formatter
    if not entry["applies"]:
        return []
    lines = []
    for key in ("text", "rerun_text"):
        text = entry[key]
        for _, field, spec, conversion in Formatter().parse(text):
            if field is not None and (field != "sections" or spec or conversion):
                raise ValueError("unapproved collection placeholder")
        lines.append(text.format(sections=", ".join(cited)))
    return lines
