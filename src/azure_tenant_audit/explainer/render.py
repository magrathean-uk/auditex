"""Pure fail-closed renderer. Renderer errors never become rule results.

render_full is an expanded-baseline UI result: its steps may exceed six and
contain public baseline URLs. It deliberately sits outside explainer.schema.json.
"""
import json
import re
import unicodedata
from string import Formatter

from . import textkit as tk
from .generate import LIMITS, URL_RX
from .view import FIELDS, VIEW_FIELDS, mask_emails

BAD_PLAIN = re.compile(r"`|\*\*|__|~~|\[[^\]]+\]\([^)]*\)|(?<![\w*])\*[^*\n]+\*(?![\w*])|</?[a-z]+>|[\x00-\x1f\x7f-\x9f\u2013\u2014\u2028\u2029]|^\s*[-*#+•>]\s|^\s*\d+[.)]\s")
PLACEHOLDER = re.compile(r"\{[a-z_]+\}")


def _mixed_script(text):
    if text.isascii():
        return False
    for word in unicodedata.normalize("NFKC", text).split():
        scripts = {unicodedata.name(c, "").split(" ")[0] for c in word if c.isalpha()}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            return True
    return False


def load_templates(read_text):
    """Load TemplateData once using e.g. resources.open_text_resource, outside render."""
    def unique(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError("duplicate template JSON key")
            out[k] = v
        return out
    data = tk.expand_template(json.loads(read_text("configs/explainer-template.json"), object_pairs_hook=unique))
    if data.get("schema_version") != 1 or data.get("rules_spec") != "v3.9.1" or data.get("limits") != LIMITS:
        raise ValueError("unsupported template contract")
    if data.get("shared_exceptions") != tk.shared_exceptions():
        raise ValueError("unsupported shared exception contract")
    keys = [(c["policy_id"], c["cell"]) for c in data["cells"]]
    if len(keys) != len(set(keys)) or any(c["reason_code"] in tk.shared_exceptions() for c in data["cells"]):
        raise ValueError("duplicate cell or fabricated exception cell")
    return data


def _citations(record, policy, cell=None):
    cites = record.get("cited_sections")
    cites = list(policy["sections"]) if cites is None else cites
    if (not isinstance(cites, list) or any(not isinstance(s, str) or s not in policy["sections"] for s in cites)
            or len(cites) != len(set(cites))):
        raise ValueError("invalid citations")
    if cell is None:
        if cites != policy["sections"]:
            raise ValueError("fault requires the fixed collected sections")
    elif cell["cell"] == "section_not_collected":
        expected = [s for s in policy["sections"] if re.search(r"(?<!\w)" + re.escape(s) + r"(?!\w)", record["reason_text"])]
        if not cites or cites != expected:
            raise ValueError("invalid missing-section citations")
    elif cites not in cell.get("cited_variants", [cell["cited"]]):
        raise ValueError("citations outside approved variants")
    return cites


def _view(record, view, policy, cites, shared):
    if not isinstance(view, dict) or set(view) != VIEW_FIELDS:
        raise ValueError("invalid view fields")
    if any(view[k] != (mask_emails(record[k]) if k == "reason_text" else record[k]) for k in FIELDS):
        raise ValueError("record and view disagree")
    evidence = view["evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("missing policy evidence")
    expected = {"id": "e0", "section": "policy", "observed": {"policy_id": record["policy_id"],
                "requirement": policy["requirement"], "criticality": policy["criticality"]}}
    if evidence[0] != expected:
        raise ValueError("policy evidence differs from the frozen baseline")
    by_section, last = {}, 0
    for e in evidence[1:]:
        if not isinstance(e, dict) or set(e) != {"id", "section", "observed"}:
            raise ValueError("invalid evidence fields")
        if not isinstance(e["id"], str) or not re.fullmatch(r"e[1-9][0-9]*", e["id"]):
            raise ValueError("invalid evidence id")
        pos = int(e["id"][1:])
        if pos <= last or e["section"] not in cites or e["section"] in by_section:
            raise ValueError("uncited, repeated or unordered evidence")
        last = pos
        by_section[e["section"]] = e["id"]
        # Serialisability and cap guard; the builder owns projection/redaction.
        if len(tk.canonical(e["observed"])) > 6000 or mask_emails(e["observed"]) != e["observed"]:
            raise ValueError("evidence bypassed the view boundary")
        if shared and isinstance(e["observed"], dict) and e["observed"].get("collection_status") == "not_collected":
            raise ValueError("fault requires collected evidence")
    if shared and any(s not in by_section for s in cites):
        raise ValueError("fault cites absent evidence")
    approved = view["approved_remediation"]
    if not isinstance(approved, list) or any(not isinstance(s, str) for s in approved):
        raise ValueError("invalid approved remediation")
    return ["e0"] + [by_section[s] for s in cites if s in by_section]


def _expand(text, slots):
    try:
        for _, field, spec, conversion in Formatter().parse(text):
            if field is not None and (field not in slots or spec or conversion):
                raise ValueError("unapproved template placeholder")
        result = text.format_map(slots)
    except (KeyError, IndexError) as exc:
        raise ValueError("unfilled template placeholder") from exc
    if PLACEHOLDER.search(result):
        raise ValueError("unfilled placeholder")
    return result


def _validate_output(out, verdict, *, full=False, command_units=()):
    """Structural guard also used for planted source self-test controls."""
    if not isinstance(out, dict) or set(out) != {"explanation", "remediation_steps", "evidence_refs"}:
        raise ValueError("invalid explainer fields")
    text, steps, refs = out["explanation"], out["remediation_steps"], out["evidence_refs"]
    if (not isinstance(text, str) or not text or not isinstance(steps, list) or any(not isinstance(s, str) or not s for s in steps)
            or not isinstance(refs, list) or not refs or any(not isinstance(r, str) or not re.fullmatch(r"e[0-9]+", r) for r in refs)
            or len(set(refs)) != len(refs)):
        raise ValueError("invalid explainer types or references")
    if tk.words(text) > 80 or tk.sentences(text) > 3:
        raise ValueError("explanation exceeds limits")
    if not full and (len(steps) > 6 or any(tk.words(s) > 30 and s not in command_units for s in steps)):
        raise ValueError("remediation exceeds limits")
    if verdict in ("met", "not_applicable") and steps:
        raise ValueError("steps for non-action verdict")
    if verdict == "not_met" and not any(not s.startswith("The baseline Instructions for ") for s in steps):
        raise ValueError("not_met needs a substantive step")
    for s in [text] + steps:
        if s in command_units and s in steps:
            # Exact approved executable units retain PowerShell whitespace,
            # comments, wildcard characters and quoting; no prose transforms.
            if (not full and URL_RX.search(s)) or _mixed_script(s):
                raise ValueError("invalid command unit")
            continue
        if BAD_PLAIN.search(s) or (not full and URL_RX.search(s)) or PLACEHOLDER.search(s) or _mixed_script(s):
            raise ValueError("non-plain text or unfilled placeholder")
    return out


def _render(record, view, templates, *, full):
    if not isinstance(record, dict) or any(k not in record for k in FIELDS):
        raise ValueError("incomplete RuleRecord")
    if any(not isinstance(record[k], str) for k in ("policy_id", "verdict", "reason_code", "reason_text")):
        raise ValueError("invalid rule fields")
    if templates.get("limits") != LIMITS:
        raise ValueError("unsupported output limits")
    pid = record["policy_id"]
    if pid not in templates["policies"]:
        raise KeyError("unknown policy")
    policy = templates["policies"][pid]
    # Dispatch before ordinary cell lookup and controlled-prefix parsing.
    if record["reason_code"] in tk.shared_exceptions():
        shared = templates["shared_exceptions"][record["reason_code"]]
        if shared != tk.shared_exceptions()[record["reason_code"]] or any(record[k] != shared[k] for k in ("verdict", "cell", "reason_text")):
            raise ValueError("invalid shared exception")
        cites = _citations(record, policy)
        refs = _view(record, view, policy, cites, record["reason_code"] == "rule_evaluation_failed")
        if view["approved_remediation"] != shared["remediation_steps"]:
            raise ValueError("invalid shared action")
        return _validate_output({"explanation": shared["explanation"], "remediation_steps": list(shared["remediation_steps"]),
                                 "evidence_refs": refs}, record["verdict"], full=full)
    if not isinstance(record["cell"], str):
        raise ValueError("ordinary record needs a cell")
    cell = next((c for c in templates["cells"] if (c["policy_id"], c["cell"]) == (pid, record["cell"])), None)
    if cell is None:
        raise KeyError("unknown cell")
    if record["verdict"] != cell["verdict"] or {k: record[k] for k in ("reason_code", "reason_text")} not in cell["reason_pairs"]:
        raise ValueError("record outside approved code/text/verdict contract")
    cites = _citations(record, policy, cell)
    refs = _view(record, view, policy, cites, False)
    verdict, lead, body = tk.split_reason(record["reason_text"])
    if verdict != cell["verdict"]:
        raise ValueError("reason prefix disagrees")
    slots = {"finding": tk.scrub(body, verdict), "lead": templates["lead_map"].get(lead, ""),
             "sections": ", ".join(cites), "requirement": policy["requirement"]}
    tiers = [cell["explanation_template"], *cell["explanation_template_fallbacks"]]
    chosen = None
    for tier in tiers:
        if "{requirement}" in tier and not policy["requirement"]:
            continue
        text = _expand(tier, slots)
        if tk.words(text) <= 80 and tk.sentences(text) <= 3:
            chosen = text
            break
    if chosen is None:
        raise ValueError("no complete explanation tier meets limits")
    def steps_from(key):
        return [s["text"] if s.get("command") else tk.strip_markdown(_expand(s["text"], slots) if s.get("template") else s["text"]) for s in cell[key]]
    if verdict == "not_met":
        expected_approved = policy["approved_remediation"]
    elif verdict == "not_assessed":
        expected_approved = steps_from("remediation_steps_full")
    else:
        expected_approved = []
    if view["approved_remediation"] != expected_approved:
        raise ValueError("view remediation differs from approved source")
    output = {"explanation": tk.strip_markdown(chosen), "remediation_steps": steps_from("remediation_steps_full" if full else "remediation_steps"),
              "evidence_refs": refs}
    return _validate_output(output, verdict, full=full, command_units=policy["command_units"])


def render(record, view, *, templates):
    """render(record: RuleRecord, view: View, *, templates: TemplateData) -> Explainer."""
    return _render(record, view, templates, full=False)


def render_full(record, view, *, templates):
    """Expanded-baseline UI result, outside the six-step Explainer schema."""
    return _render(record, view, templates, full=True)
