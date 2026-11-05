"""Per-prompt context for the checkers: the whitelist W (check b), approved text (checks c and e), identifier sets (check d).

A *pair record* is one JSON object:
  {"id": str, "prompt": {"data": DATA, "record": {policy_id, verdict, reason_code, reason_text, cell, cited_sections},
                          "full_record_terms": [str]},          # terms of the FULL raw record absent from the view (built offline, see build_pairs.py)
   "output_text": str | "output": object}
DATA is the explainer's closed view exactly as the prompt builder emits it (step 2).

Whitelist W for one prompt (plan section 3 check b), the union of:
  1 the DATA object (keys and values: reason text, evidence view, requirement sentence, approved_remediation);
  2 the rule's reason text and reason code, the cell id;
  3 the cell's documented vocabulary: the template cell record's reason patterns and codes, and the cell's what_to_collect entry (text, re-run text, section names);
  4 the policy's baseline statement and Instructions text, plus the statement and Instructions of every cross-referenced policy;
  5 the section names of the policy (template policies[pid].sections) and the record's cited sections.
Tiers 3 to 5 are wider than what a model sees; they are listed because the task fixes them, and the report counts how often a pass relies on a tier outside the prompt.
"""
import json
import re
from collections import OrderedDict

from . import baseline_text
from .specifics import extract, identifiers
from .textnorm import norm, sentence_split
from .shared_reason import FAULT_ENTRY, NOT_IMPLEMENTED_ENTRY, SHARED_CODES

class Resources:
    """Explicit, read-only checker inputs. No checkout or system-dictionary discovery.

    baselines is this package's independently parsed mapping (baseline_text.load),
    not the runtime BaselineIndex. template/collection keep the frozen JSON shape.
    """

    def __init__(self, baselines, template, collection, train_identifiers, english_words):
        if not english_words or any(not isinstance(w, str) or not w for w in english_words):
            raise ValueError("a non-empty ordinary-word set is required")
        if not isinstance(train_identifiers, (set, frozenset)):
            raise TypeError("train_identifiers must be an explicitly supplied set")
        self.bl = baselines
        self.template = template
        self.collection = collection
        self.cells = {(c["policy_id"], c["cell"]): c for c in template["cells"]}
        self.shared = template.get("shared_exceptions", {})
        self.pol_meta = template["policies"]
        self.wtc = {c["id"]: c for c in collection["cells"]}
        self.portal = baseline_text.portal_vocab(baselines)
        self.train_idents = frozenset(train_identifiers)
        self.english_words = frozenset(w.casefold() for w in english_words)
        self._contexts = OrderedDict()

    def context_for(self, pair):
        # Mutations share prompts but never outputs. Retain bounded contexts
        # keyed by exact JSON, so a caller editing a prompt cannot reuse stale
        # evidence. The cache owns its copy and never retains caller containers.
        key = json.dumps(pair["prompt"], ensure_ascii=False, separators=(",", ":"))
        if key not in self._contexts:
            self._contexts[key] = Context({"prompt": json.loads(key)}, self)
            if len(self._contexts) > 128:
                self._contexts.popitem(last=False)
        self._contexts.move_to_end(key)
        return self._contexts[key]

    def xrefs(self, pid):
        out = []
        meta = (self.pol_meta.get(pid) or {}).get("instructions_cross_reference")
        for x in ([meta] if meta else []) + list(self.bl["policies"].get(pid, {}).get("xref", [])):
            if x and x != pid and x not in out:
                out.append(x)
        return out


def walk_counts(v, acc):
    if isinstance(v, dict):
        acc.add(len(v))
        for x in v.values():
            walk_counts(x, acc)
    elif isinstance(v, list):
        acc.add(len(v))
        for x in v:
            walk_counts(x, acc)


def _all_strings(v, acc):
    if isinstance(v, dict):
        for k, x in v.items():
            acc.append(str(k))
            _all_strings(x, acc)
    elif isinstance(v, list):
        for x in v:
            _all_strings(x, acc)
    elif isinstance(v, str):
        acc.append(v)
    elif v is not None:
        acc.append(str(v))


class Stream:
    """Token stream of the approved baseline Instructions for one policy (then its cross-referenced policies), with unit boundaries (verbatim matching)."""

    def __init__(self, line_groups):
        self.toks, self.keys, self.b_before, self.b_after = [], [], [], []
        self.unit_of, self.unit_words, self.unit_code = [], [], []
        for line, is_code in line_groups:
            units = [line] if is_code else sentence_split(line)
            for u in units:
                ts = [t.replace(";", "") for t in u.split()]
                ts = [t for t in ts if t]
                uid = len(self.unit_words)
                self.unit_words.append(len(u.split()))
                self.unit_code.append(is_code)
                for i, t in enumerate(ts):
                    self.toks.append(t)
                    self.keys.append(self.key(t))
                    self.b_before.append(i == 0)
                    self.b_after.append(i == len(ts) - 1)
                    self.unit_of.append(uid)

    @staticmethod
    def key(tok):
        return norm(tok).strip(".,;:!?*_`")


class Whitelist:
    def __init__(self, texts, extra_counts=()):
        texts = [t for t in texts if isinstance(t, str) and t]
        self.text = norm(" \n ".join(t for t in texts if t))
        self.by_class = {}
        for s in extract(" \n ".join(t for t in texts if t)):
            self.by_class.setdefault(s.cls, set()).add(s.key)
        self.numbers = set(self.by_class.get("number", set()))
        self.names = set()
        for c, ks in self.by_class.items():
            if c != "number":
                self.names |= ks
        self.counts = {str(c) for c in extra_counts}
        words = set(re.findall(r"[a-z0-9]+", self.text))
        for k in self.names:                                   # camel and snake names contribute their words to the prose vocabulary
            words.update(re.findall(r"[a-z0-9]+", k.replace("_", " ")))
        for raw in re.findall(r"[A-Za-z0-9]+(?:[A-Z][a-z0-9]+)+", " ".join(texts)):
            words.update(w.casefold() for w in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", raw))
        self.words = words
        self._tokens = None

    def tokens(self):
        if self._tokens is None:
            self._tokens = re.findall(r"[a-z0-9]+", self.text)
        return self._tokens

    def has_substring(self, s):
        return norm(s) in self.text


class Context:
    def whole_command(self, text):
        # Preserve line boundaries: collapsing them can swallow code after '#'.
        # Existing whitespace/dash/quote normalisation is allowed within lines.
        if not self.command_keys:
            return False
        key = tuple(norm(line, fold=False) for line in text.strip().splitlines() if line.strip())
        return key in self.command_keys

    def __init__(self, pair, res):
        self.res = res
        pr = pair["prompt"]
        self.pair_id = pair.get("id")
        self.data = pr["data"]
        rec = pr["record"]
        self.record = rec
        self.verdict = rec["verdict"]
        self.policy_id = rec["policy_id"]
        self.cell = rec["cell"]
        self.reason_code = rec.get("reason_code")
        # Only these named branches can bypass ordinary evidence checks.
        # Never grant exemptions to arbitrary not_assessed codes in a template.
        self.shared = res.shared.get(self.reason_code) if self.reason_code in SHARED_CODES else None
        if self.reason_code == "rule_evaluation_failed":
            self.shared = FAULT_ENTRY
        elif self.reason_code == "rule_not_implemented":
            self.shared = NOT_IMPLEMENTED_ENTRY
        self.reason_text = rec.get("reason_text") or self.data.get("reason_text") or ""
        self.cited = list(rec.get("cited_sections") or [])
        ev = self.data.get("evidence", [])
        self.evidence_ids = [e["id"] for e in ev]
        self.evidence_sections = [e.get("section") for e in ev if e.get("id") != "e0"]
        e0 = next((e for e in ev if e.get("id") == "e0"), {})
        self.requirement = ((e0.get("observed") or {}).get("requirement")) or ""
        if not self.cited:
            self.cited = list(self.evidence_sections)
        self.approved_lines_prompt = [x for x in self.data.get("approved_remediation", []) if isinstance(x, str)]
        self.full_record_terms = list(pr.get("full_record_terms", []))
        pol = res.bl["policies"].get(self.policy_id, {"statement": "", "lines": [], "units": [], "xref": []})
        self.baseline_policy = pol
        self.xref_ids = res.xrefs(self.policy_id)
        # approved text for remediation
        sections_txt = ", ".join(self.cited)
        wtc = res.wtc.get(f"{self.policy_id}/{self.cell}")
        self.wtc = wtc
        wtc_lines = []
        if wtc and wtc.get("applies"):
            wtc_lines = [wtc["text"].replace("{sections}", sections_txt), wtc["rerun_text"].replace("{sections}", sections_txt)]
        self.wtc_lines = wtc_lines
        if self.shared:
            self.wtc_lines = wtc_lines = list(self.shared["remediation_steps"])
        groups, lines_full = [], []
        for pid in [self.policy_id] + self.xref_ids:
            p = res.bl["policies"].get(pid)
            if not p:
                continue
            for ln, is_code in p["line_groups"]:
                groups.append((ln, is_code))
                lines_full.append(ln)
        self.stream = Stream(groups)
        # What a model arm can actually see: the prompt's approved_remediation lines. For not_met, checks e and e3 match steps against THIS stream (DF-2: a template
        # step must be a subset of what the prompt carries), not against the wider baseline reader's text.
        self.command_units = frozenset((res.pol_meta.get(self.policy_id) or {}).get("command_units", [])) & frozenset(self.approved_lines_prompt)
        self.command_keys = {tuple(norm(line, fold=False) for line in u.strip().splitlines() if line.strip())
                             for u in self.command_units}
        self.prompt_units = [u for ln in self.approved_lines_prompt for u in ([ln] if ln in self.command_units else sentence_split(ln))]
        self.stream_prompt = Stream([(ln, ln in self.command_units) for ln in self.approved_lines_prompt])
        if self.verdict == "not_met":
            self.approved_lines_full = lines_full
        elif self.verdict == "not_assessed":
            self.approved_lines_full = wtc_lines + [x for x in self.approved_lines_prompt if x not in wtc_lines]
        else:
            self.approved_lines_full = []
        # whitelist
        texts = [json.dumps(self.data, ensure_ascii=False), self.reason_text, self.reason_code or "", self.cell or "", " ".join(self.cited)]
        cellrec = res.cells.get((self.policy_id, self.cell))
        if cellrec:
            texts += cellrec.get("reason_patterns", []) + list(cellrec.get("reason_codes", [])) + [cellrec.get("cell", "")]
        if self.shared:
            texts += [self.shared["explanation"]] + list(self.shared["remediation_steps"])
        if wtc:
            texts += [wtc.get("text", ""), wtc.get("rerun_text", "")] + list(wtc.get("collect", [])) + [wtc.get("input_condition") or ""]
        for pid in [self.policy_id] + self.xref_ids:
            p = res.bl["policies"].get(pid)
            if p:
                texts += [pid, p["statement"]] + p["lines"]
        texts += list((res.pol_meta.get(self.policy_id) or {}).get("sections", []))
        self.prompt_strings = []
        _all_strings(self.data, self.prompt_strings)
        counts = set()
        walk_counts([e.get("observed") for e in ev], counts)
        counts.add(len(self.cited))
        counts.add(len(ev) - 1)
        counts.add(len(self.approved_lines_prompt))
        self.W = Whitelist(texts, counts)
        self.W_prompt = None                   # built lazily: prompt-only whitelist (tier 1) for reporting tier reliance
        self._texts = texts
        self.public_text = " \n ".join(t for t in texts[5:] if isinstance(t, str))
        self.prompt_text = json.dumps(self.data, ensure_ascii=False)
        self.prompt_idents = identifiers(" \n ".join(self.prompt_strings))

    def prompt_whitelist(self):
        if self.W_prompt is None:
            self.W_prompt = Whitelist([self.prompt_text, self.reason_text, self.reason_code or "", self.cell or ""], set())
        return self.W_prompt
