"""Check S: strict structure and the constrained form (EXACT).

Parses the candidate as strict JSON (no repair: no code fences, no trailing text, no duplicate keys, no NaN) and enforces the plan's section 2:
Exact whole executable units present in fixed policy metadata and prompt are
exempt only from step_words; comments are PowerShell, not markdown. Prose and
the six-step cap keep their limits.

exactly the keys explanation, remediation_steps, evidence_refs; types; explanation at most 80 words and 3 sentences; at most 6 steps of at most 30 words;
evidence_refs a non-empty subset of the evidence ids in the prompt; empty steps for met and not_applicable; no URL, markdown, HTML, code fence or em dash;
no control characters; no word that mixes Latin with Cyrillic or Greek letters; at most 450 output tokens (estimated at 4.25 characters per token).
En dashes and non-ASCII punctuation other than the em dash are tolerated (reported as notes); UK spelling is a soft check handled outside the gate.
"""
import json
import re

from .config import LIMITS
from .textnorm import mixed_script_words, sentence_split, words

KEYS = ("explanation", "remediation_steps", "evidence_refs")
URL_RX = re.compile(r"(?i)\b(?:https?|ftps?|mailto|file)://|\bwww\.|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+/\S")
MD_RX = [("backtick", re.compile(r"`")), ("bold_or_underscore", re.compile(r"\*\*|__")), ("heading", re.compile(r"(?m)^\s*#{1,6}\s")),
         ("bullet", re.compile(r"(?m)^\s*[-*+•]\s+\S")), ("numbered_list", re.compile(r"(?m)^\s*\d+[.)]\s+\S")), ("link", re.compile(r"\[[^\]]+\]\([^)]*\)")),
         ("html", re.compile(r"</?(?:b|i|u|em|strong|br|p|a|div|span|code|pre|ul|ol|li|h[1-6]|table|tr|td|img)\b[^>]*>", re.I)),
         ("table", re.compile(r"\|\s*-{3,}")), ("strike", re.compile(r"~~")), ("emphasis", re.compile(r"(?<![\w*])\*[^*\s][^*\n]*\*(?![\w*])")),
         ("blockquote", re.compile(r"(?m)^\s*>\s+\S"))]
EMDASH = re.compile("[\u2014―⸺⸻]")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f  ]")


class Output:
    """A parsed candidate. `ok` is False when the text is not strict JSON of the right top-level type (then S fails and other checks see empty fields)."""

    def __init__(self, text=None, obj=None):
        self.raw = text
        self.parse_error = None
        self.obj = obj
        if text is not None:
            self.obj, self.parse_error = strict_parse(text)
        o = self.obj if isinstance(self.obj, dict) else {}
        self.explanation = o.get("explanation") if isinstance(o.get("explanation"), str) else ""
        steps = o.get("remediation_steps")
        self.steps = [s for s in steps if isinstance(s, str)] if isinstance(steps, list) else []
        refs = o.get("evidence_refs")
        self.refs = [r for r in refs if isinstance(r, str)] if isinstance(refs, list) else []

    @property
    def ok(self):
        return isinstance(self.obj, dict) and self.parse_error is None


def _no_dups(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key " + repr(k))
        d[k] = v
    return d


def _no_const(c):
    raise ValueError("non-finite number " + c)


def strict_parse(text):
    if not isinstance(text, str):
        return None, "not a string"
    if text.startswith("﻿"):
        return None, "byte order mark"
    try:
        return json.loads(text, object_pairs_hook=_no_dups, parse_constant=_no_const), None
    except (ValueError, RecursionError) as e:
        return None, str(e)[:120]


def _f(code, text, detail=""):
    return {"code": code, "klass": "exact", "text": text, "detail": detail}


def check_s(ctx, out):
    fails, notes = [], []
    if out.parse_error:
        return {"pass": False, "klass": "exact", "failures": [_f("not_strict_json", (out.raw or "")[:120], out.parse_error)], "notes": notes}
    o = out.obj
    if not isinstance(o, dict):
        return {"pass": False, "klass": "exact", "failures": [_f("top_level_not_object", str(type(o)))], "notes": notes}
    if set(o) != set(KEYS):
        fails.append(_f("keys", "", f"extra {sorted(set(o) - set(KEYS))} missing {sorted(set(KEYS) - set(o))}"))
    expl, steps, refs = o.get("explanation"), o.get("remediation_steps"), o.get("evidence_refs")
    if not isinstance(expl, str) or not expl.strip():
        fails.append(_f("explanation_type", repr(expl)[:60], "explanation must be a non-empty string"))
        expl = ""
    if not isinstance(steps, list) or not all(isinstance(s, str) and s.strip() for s in steps):
        fails.append(_f("steps_type", repr(steps)[:80], "remediation_steps must be a list of non-empty strings"))
        steps = []
    if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
        fails.append(_f("refs_type", repr(refs)[:80], "evidence_refs must be a list of strings"))
        refs = []
    L = LIMITS
    if words(expl) > L["explanation_words"]:
        fails.append(_f("explanation_words", expl[:80], f"{words(expl)} words"))
    ns = len(sentence_split(expl))
    if ns > L["explanation_sentences"]:
        fails.append(_f("explanation_sentences", expl[:80], f"{ns} sentences"))
    if len(steps) > L["max_steps"]:
        fails.append(_f("steps_count", "", f"{len(steps)} steps"))
    for i, s in enumerate(steps):
        if words(s) > L["step_words"] and not ctx.whole_command(s):
            fails.append(_f("step_words", s[:80], f"step {i}: {words(s)} words"))
    if not refs:
        fails.append(_f("refs_empty", "", "evidence_refs must be non-empty"))
    bad = [r for r in refs if r not in set(ctx.evidence_ids)]
    if bad:
        fails.append(_f("refs_not_in_prompt", ",".join(bad), f"prompt ids {ctx.evidence_ids}"))
    if len(set(refs)) != len(refs):
        fails.append(_f("refs_duplicate", ",".join(refs), "evidence_refs must be unique"))
    if refs and all(r in ctx.evidence_ids for r in refs):
        # A1 explicitly preserves three citation lists outside full section
        # order. IDs retain full-view positions; references follow citations.
        by_section = {e.get("section"): e["id"] for e in ctx.data.get("evidence", [])}
        ordered = ["e0"] + [by_section[s] for s in ctx.cited if s in by_section]
        ordered += [eid for eid in ctx.evidence_ids if eid not in ordered]
        positions = [ordered.index(r) for r in refs]
        if positions != sorted(positions):
            fails.append(_f("refs_order", ",".join(refs), "preserve record citation order, with e0 first"))
    if ctx.verdict not in ("met", "not_met", "not_assessed", "not_applicable"):
        fails.append(_f("invalid_verdict", str(ctx.verdict)))
    if ctx.verdict in ("met", "not_applicable") and steps:
        fails.append(_f("steps_for_" + ctx.verdict, steps[0][:80], "remediation_steps must be empty"))
    est = round(len(out.raw or json.dumps(o)) / L["chars_per_token"])
    if est > L["max_output_tokens"]:
        fails.append(_f("output_tokens", "", f"about {est} tokens"))
    for where, txt in [("explanation", expl)] + [(f"step {i}", s) for i, s in enumerate(steps)]:
        if URL_RX.search(txt):
            fails.append(_f("url", URL_RX.search(txt).group(0), where))
        for name, rx in MD_RX:
            if where != "explanation" and ctx.whole_command(txt):
                continue
            m = rx.search(txt)
            if m:
                fails.append(_f("markdown_" + name, m.group(0)[:40], where))
        if EMDASH.search(txt):
            fails.append(_f("em_dash", EMDASH.search(txt).group(0), where))
        if CONTROL.search(txt):
            fails.append(_f("control_character", repr(CONTROL.search(txt).group(0)), where))
        mw = mixed_script_words(txt)
        if mw:
            fails.append(_f("mixed_script_word", mw[0], where))
        if "\u2013" in txt:
            notes.append(f"en dash in {where}")
    return {"pass": not fails, "klass": "exact", "failures": fails, "notes": notes}
