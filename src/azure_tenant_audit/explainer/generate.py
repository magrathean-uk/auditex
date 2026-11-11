"""Offline, deterministic catalogue-first template generation.

Adapted from frozen S/B/build.py; baseline extraction originates in CISA
ScubaGear (CC0, with Microsoft CC BY 4.0 portions). Attribution is carried in
the injected BaselineIndex. No vector discovery, rule calls or collection writes.
"""
import re
from copy import deepcopy

from . import textkit as tk

LIMITS = {"explanation_words": 80, "explanation_sentences": 3, "max_steps": 6, "step_words": 30,
          "command_units": "whole approved executable pre block is one step; exempt from step_words only"}
BASELINE_COMMIT = "2446ad723b7f55031cc02c8aca244d731d468cba"
URL_RX = re.compile(r"(?i)\b(?:https?|ftps?|mailto|file)://|\bwww\.|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+/\S")
ORIENTATION = (r"^Because the steps for MS\.", r"^Steps that do not strictly apply to MS\.", r"^Each option is described below")


def _is_orientation(text):
    return any(re.search(rx, text) for rx in ORIENTATION)


def _units(rows, drop_preamble):
    segments, dropped, orientation = [], [], []
    for row in rows:
        if not segments or segments[-1][0] != row["source"]["policy_id"]:
            segments.append((row["source"]["policy_id"], []))
        pieces = [row["text"]] if row["kind"] == "pre" else tk.sentence_split(row["text"])
        for sentence in pieces:
            parts = [sentence] if row.get("command") else tk.split_balanced(sentence, 30)
            segments[-1][1].extend({"text": p, "ref": deepcopy(row["source"]), "pre": row["kind"] == "pre",
                                    "forced": len(parts) > 1, "kind": row["kind"], "command": row.get("command", False)} for p in parts)
    out = []
    for _, units in segments:
        n = 0
        if drop_preamble:
            for u in units:
                if u["kind"] != "para" or tk.actionable(u["text"]) or _is_orientation(u["text"]):
                    break
                n += 1
            if n < len(units) and any(tk.actionable(u["text"]) or u["kind"] != "para" for u in units[n:]):
                dropped.extend(dict(u["ref"], text=u["text"]) for u in units[:n])
                units = units[n:]
        for u in units:
            if _is_orientation(u["text"]):
                orientation.append(dict(u["ref"], text=u["text"]))
            else:
                out.append(u)
    return out, dropped, orientation


def _merge_refs(refs):
    out = []
    for r in refs:
        if (out and out[-1]["file"] == r["file"] and out[-1]["policy_id"] == r["policy_id"]
                and r["line_start"] <= out[-1]["line_end"] + 3):
            out[-1]["line_end"] = max(out[-1]["line_end"], r["line_end"])
        else:
            out.append(deepcopy(r))
    return out


def _chunk(units):
    chunks = []
    for u in units:
        last = chunks[-1] if chunks else None
        if (last and not u["command"] and not last.get("command") and not u["forced"] and not last["forced_piece"] and last["pre"] == u["pre"]
                and tk.words(last["text"]) + tk.words(u["text"]) <= 30):
            sep = "; " if u["pre"] else " "
            last["text"] += sep + u["text"]
            last["source"].append(deepcopy(u["ref"]))
            last["units"].append(u["text"])
        else:
            chunks.append({"text": u["text"], "source": [deepcopy(u["ref"])], "pre": u["pre"],
                           "forced_piece": u["forced"], "units": [u["text"]]})
            if u["command"]:
                chunks[-1]["command"] = True
    for ch in chunks:
        ch.pop("pre")
        ch["source"] = _merge_refs(ch["source"])
    return chunks


def _baseline_steps(pid, baselines):
    rows = tk.resolved_units(baselines, pid)
    units, dropped, orientation = _units(rows, False)
    full = _chunk(units)
    if len(full) > 6:
        units2, dropped2, orientation2 = _units(rows, True)
        if units2:
            full, dropped, orientation = _chunk(units2), dropped2, orientation2
    url_at = next((i for i, c in enumerate(full) if URL_RX.search(c["text"])), None)
    keep = 5 if len(full) > 6 else len(full)
    if url_at is not None:
        keep = min(keep, url_at, 5)
    truncated = keep < len(full)
    shown = deepcopy(full[:keep])
    if truncated:
        shown.append({"text": f"The baseline Instructions for {pid} continue with further steps; follow them in order after these.",
                      "source": _merge_refs([r for c in full[keep:] for r in c["source"]]), "units": [], "forced_piece": False})
    return {"full": full, "shown": shown, "truncated": truncated,
            "preamble_units_dropped": dropped, "orientation_units_dropped": orientation,
            "shown_steps_cut_before_url_step": url_at}


def _reason_pairs(pid, name, cell):
    """The closed (code, text) pairs of a cell.

    The product catalogue carries the A1.3 two-code pairing explicitly (``reason_texts_by_code``). The spec's own
    cell-catalogue lists the codes and the texts separately; that one approved cell is paired by its text.
    """
    pairs = cell.get("reason_texts_by_code")
    if pairs is not None:
        if (pid, name) != ("MS.AAD.6.1v1", "orphan_sub_domain") or sorted(pairs.values()) != cell["reason_texts"]:
            raise ValueError("multi-code cell requires an explicit approved pairing")
        return [{"reason_code": code, "reason_text": pairs[code]} for code in sorted(pairs)]
    codes = cell.get("reason_codes", [cell["reason_code"]])
    if len(codes) == 1:
        return [{"reason_code": codes[0], "reason_text": t} for t in cell["reason_texts"]]
    # A1.3 explicitly defines this non-Cartesian pairing. Never pair by index.
    expected = {"data_unusable_sub_domain_root_case", "data_unusable_sub_domain_without_root"}
    if pid != "MS.AAD.6.1v1" or name != "orphan_sub_domain" or set(codes) != expected:
        raise ValueError("multi-code cell requires an explicit approved pairing")
    pairs = []
    for text in cell["reason_texts"]:
        if "only when letter case is ignored" in text:
            code = "data_unusable_sub_domain_root_case"
        elif "has no managed verified root domain in the export" in text:
            code = "data_unusable_sub_domain_without_root"
        else:
            raise ValueError("unrecognised A1 code/text pairing")
        pairs.append({"reason_code": code, "reason_text": text})
    if len(pairs) != 2 or {p["reason_code"] for p in pairs} != expected:
        raise ValueError("incomplete A1 code/text pairing")
    return pairs


def generate_template(catalogue, baselines, collection):
    """generate_template(catalogue, baselines, collection) -> TemplateData.

    Accept the product catalogue wrapper or the v3.9.1 policy mapping. All input
    objects, including unused metadata and shared contracts, enter canonical hashes.
    """
    if baselines["source_commit"] != BASELINE_COMMIT:
        raise ValueError("unexpected baseline commit")
    if "policies" in catalogue and catalogue.get("spec_version", "v3.9.1") != "v3.9.1":
        raise ValueError("product catalogue must be reconciled to v3.9.1 first")
    policies = catalogue.get("policies", catalogue)
    entries = {}
    for entry in collection["cells"]:
        key = (entry["policy_id"], entry["cell"])
        if key in entries:
            raise ValueError("duplicate collection entry")
        entries[key] = entry
    result = {"schema_version": 1, "version": "1", "rules_spec": "v3.9.1",
              "baseline_pin": BASELINE_COMMIT, "input_sha256": {
                  "catalogue": tk.digest(catalogue), "baselines": tk.digest(baselines),
                  "collection": tk.digest(collection), "shared_exceptions": tk.digest(tk.shared_exceptions())},
              "shared_exceptions": deepcopy(tk.shared_exceptions()),
              "baseline_attribution": deepcopy(baselines["attribution"]),
              "baseline_source_sha256": deepcopy(baselines["source_sha256"]),
              "limits": dict(LIMITS), "lead_map": {"unavailable": "The evidence needed is unavailable",
              "unusable": "The evidence cannot be used as it stands"}, "scrub": [], "policies": {}, "cells": []}
    for pid, meta in sorted(policies.items()):
        if meta["sections"] != collection["policy_sections"].get(pid):
            raise ValueError("template and builder policy read sets disagree")
        public = baselines["policies"].get(pid, {})
        bs = _baseline_steps(pid, baselines)
        rows = tk.resolved_units(baselines, pid)
        xref = next((x for x in baselines["xrefs"] if x["policy_id"] == pid), None)
        result["policies"][pid] = {
            "requirement": public.get("requirement", ""), "criticality": public.get("criticality"),
            "sections": list(meta["sections"]), "approved_remediation": [u["text"] for u in rows],
            "command_units": [u["text"] for u in rows if u.get("command")],
            "instructions_cross_reference": xref["target"] if xref else None,
            "instructions_cross_reference_metadata": deepcopy(xref),
            **{k: deepcopy(bs[k]) for k in ("preamble_units_dropped", "orientation_units_dropped", "shown_steps_cut_before_url_step")}}
        for name, cat in sorted(meta["cells"].items()):
            verdict = cat["verdict"]
            pairs = _reason_pairs(pid, name, cat)
            if any(tk.split_reason(p["reason_text"])[0] != verdict for p in pairs):
                raise ValueError("catalogue text/verdict mismatch")
            if verdict == "not_assessed":
                entry = entries[(pid, name)]
                if entry["verdict"] != verdict or not entry["applies"]:
                    raise ValueError("not_assessed needs collection wording")
                # Validate substitution grammar even before rendering.
                tk.collection_lines(entry, meta["sections"])
                steps = [{"text": entry[k], "source": deepcopy(entry["source"]), "template": True}
                         for k in ("text", "rerun_text")]
                full, truncated = deepcopy(steps), False
            elif verdict == "not_met":
                steps, full, truncated = deepcopy(bs["shown"]), deepcopy(bs["full"]), bs["truncated"]
                if not steps or not any(s.get("units") for s in steps):
                    raise ValueError("not_met needs a substantive baseline step")
            else:
                steps, full, truncated = [], [], False
            first = {"met": "What the evidence shows: {finding}.", "not_met": "What the evidence shows: {finding}.",
                     "not_applicable": "This policy does not apply here: {finding}.", "not_assessed": "{lead}: {finding}."}[verdict]
            parts = [first]
            if verdict in ("met", "not_met"):
                parts.append("That " + ("is consistent with" if verdict == "met" else "differs from") + " the baseline requirement: {requirement}")
            elif verdict == "not_assessed":
                parts.append("No conclusion was reached either way, so this policy was not assessed.")
            if verdict == "not_met":
                parts.append("The steps below are taken from the baseline Instructions for this policy.")
            if verdict == "not_assessed" and any(any(s not in tk.split_reason(p["reason_text"])[2] for s in cites)
                    for p in pairs for cites in cat.get("cited_variants", [cat["cited"]])):
                parts.append("Evidence sections concerned: {sections}.")
            tiers = [" ".join(parts[:i]) for i in range(len(parts), 0, -1)]
            cell = {"id": f"{pid}/{name}", "policy_id": pid, "cell": name, **deepcopy(cat),
                    "area": pid.split(".")[1], "kind": meta["kind"],
                    "reason_patterns": sorted({tk.split_reason(p["reason_text"])[2] for p in pairs}),
                    "reason_variants_seen": len(cat["reason_texts"]),
                    "reason_codes": list(cat.get("reason_codes", [cat["reason_code"]])), "reason_pairs": pairs,
                    "explanation_template": tiers[0], "explanation_template_fallbacks": tiers[1:],
                    "placeholders": {s: {"finding": "controlled catalogue reason body", "lead": "controlled reason prefix",
                                        "requirement": "frozen public baseline requirement", "sections": "fixed cited section names"}[s]
                                     for s in ("finding", "lead", "requirement", "sections") if "{" + s + "}" in tiers[0]},
                    "remediation_source": "baseline_instructions" if verdict == "not_met" else "what_to_collect" if verdict == "not_assessed" else "none",
                    "remediation_steps": steps, "remediation_steps_full": full, "remediation_truncated": truncated,
                    "source": {"file": "configs/scuba-value-rules.json", "policy_id": pid, "cell": name}}
            result["cells"].append(cell)
    return result
