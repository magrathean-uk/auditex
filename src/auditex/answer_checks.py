"""Fail-closed checks on a local model's answers, the renderer and the fixed-text fallback (DEC-113, DEC-119).

The model writes no text (DEC-119); it selects and arranges. For each digest item (``answer_digest``) it returns one
JSON object and nothing else, ``{"use": ["is-not-met", "requirement", "step-1"], "show": ["v4"]}``: ``use`` selects
sentences of the item's bank (``answer_digest.item_bank``: the fixed frames of ``answer_frames.json`` whose
preconditions hold on the item's rule facts, the baseline requirement and, for a not met item, the baseline
remediation steps), ``show`` selects values Auditex renders quoted. For the whole run it returns
``{"summary": ["run-counts"], "highlight": [1, 2]}``: run frames whose count preconditions hold
(``answer_digest.run_bank``), their counts filled by Auditex, and the numbers of the items to list first
(``answer_digest.highlightable``). Auditex renders every word; the rules decide every verdict and the order.

Item answer checks (anything else fails and the item shows ``fallback_text``):
1. form: one JSON object (as text, or already parsed) with exactly the keys use and show, strict JSON (a duplicate
   key or a constant such as NaN fails), each a list of strings.
2. use: at least one id (``empty``), at most the ``use`` limit of the frames file (``limit``), no id twice
   (``duplicate``), each id in the item's bank. A frame or catalogue sentence id the bank does not hold for this item
   fails ``precondition`` (``is-met`` on a not met item, ``step-1`` on a met one, ``mandatory`` without a catalogue
   Shall); any other id fails ``unknown``.
3. show: distinct reference ids (``v4``) of this item's values other than its check and verdict, which Auditex always
   renders. Another item's id, an unknown id, a check or verdict id fails ``reference``; a repeat ``duplicate``.
Run summary checks: exactly the keys summary and highlight; summary 1 to the ``summary`` limit of distinct ids of
``run_bank`` (a run frame whose counts do not hold fails ``precondition``); highlight up to the ``highlight`` limit of
distinct item numbers, written as integers, of ``highlightable`` (an item of another verdict fails ``precondition``).

Rendering: the Check and Verdict frames; the selected sentences in the model's order, except that remediation steps
keep their baseline order across the places the model gave steps; then the values listed in show or shown by a
selected frame, in the item's value order, each quoted and escaped under its fixed label (``LABELS``). The summary
renders its frames in the model's order and the highlighted items in the rules' order. ``answer_form`` and
``summary_form`` give M10-T03's decoding grammar the JSON schema with the allowed id enums; every answer the schema
admits passes these checks. Pure and deterministic: no model, no network.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from .answer_digest import (
    CATALOGUE,
    CATALOGUE_ID,
    VERDICT_TEXT,
    frames,
    highlightable,
    item_bank,
    quoted,
    ref_of,
    run_bank,
)

ITEM_KEYS = ("use", "show")
SUMMARY_KEYS = ("summary", "highlight")
ALWAYS_SHOWN = ("check", "verdict")
LABELS = {"check": "Check", "severity": "Severity", "requirement": "Requirement", "reason": "Reason",
          "field": "Field", "setting": "Setting"}
REF_ID = re.compile(r"v[1-9][0-9]*")


class AnswerCheckError(ValueError):
    """An answer that did not pass the checks was given to the renderer."""


def _parse(answer: Any, keys: tuple[str, str]) -> tuple[Mapping[str, Any] | None, str | None]:
    from azure_tenant_audit.strict_json import reject_json_constant, strict_pairs

    if isinstance(answer, str):
        try:
            answer = json.loads(answer, object_pairs_hook=strict_pairs, parse_constant=reject_json_constant)
        except (ValueError, RecursionError):
            return None, "the answer is not one JSON object"
    if not isinstance(answer, Mapping):
        return None, "the answer is not one JSON object"
    if set(answer) != set(keys):
        return None, f"the answer's keys are {sorted(map(str, answer))[:6]}, not {' and '.join(keys)}"
    return answer, None


def _id_list(value: Any, kind: type) -> bool:
    return isinstance(value, list) and all(type(entry) is kind for entry in value)


def showable(item: Mapping[str, Any]) -> list[str]:
    """The reference ids an answer may list in ``show``: the item's values other than its check and verdict."""
    return [value["ref"] for value in item["values"] if value["name"] not in ALWAYS_SHOWN]


def answer_form(item: Mapping[str, Any], digest: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """What a decoding grammar may produce for this item (M10-T03): the JSON schema with the allowed id enums, the
    bank's sentences by id and the reference ids for ``show``. ``digest`` is accepted for symmetry with
    ``check_answer``; an item's form depends on the item alone."""
    bank, ids = item_bank(item), showable(item)
    limit = frames()["limits"]["use"]
    schema = {"type": "object", "additionalProperties": False, "required": list(ITEM_KEYS),
              "properties": {"use": {"type": "array", "minItems": 1, "maxItems": min(limit, len(bank)),
                                     "uniqueItems": True, "items": {"type": "string", "enum": list(bank)}},
                             "show": {"type": "array", "maxItems": len(ids), "uniqueItems": True,
                                      "items": {"type": "string", "enum": ids}}}}
    return {"schema": schema, "sentences": {sid: entry["text"] for sid, entry in bank.items()}, "show": ids,
            "limits": {"use": limit}}


def summary_form(digest: Mapping[str, Any]) -> dict[str, Any]:
    """What a decoding grammar may produce for the run summary: the JSON schema with the run frame and item number
    enums, and the run frames' texts with Auditex's counts."""
    bank, items, limits = run_bank(digest), highlightable(digest), frames()["limits"]
    schema = {"type": "object", "additionalProperties": False, "required": list(SUMMARY_KEYS),
              "properties": {"summary": {"type": "array", "minItems": 1, "maxItems": min(limits["summary"], len(bank)),
                                         "uniqueItems": True, "items": {"type": "string", "enum": list(bank)}},
                             "highlight": {"type": "array", "maxItems": min(limits["highlight"], len(items)),
                                           "uniqueItems": True, "items": {"type": "integer", "enum": items}}}}
    return {"schema": schema, "sentences": bank, "highlight": items,
            "limits": {"summary": limits["summary"], "highlight": limits["highlight"]}}


def _check_use(use: Any, item: Mapping[str, Any], fail) -> None:
    if not _id_list(use, str):
        fail("form", "use is not a list of sentence ids")
        return
    limit, bank = frames()["limits"]["use"], item_bank(item)
    if not use:
        fail("empty", "use selects no sentence")
    if len(use) > limit:
        fail("limit", f"use selects {len(use)} sentences, more than {limit}")
    seen: set[str] = set()
    for sid in use:
        if sid in seen:
            fail("duplicate", f"use lists {sid} twice")
        elif sid not in bank:
            if sid in frames()["item"] or CATALOGUE_ID.fullmatch(sid):
                fail("precondition", f"{sid} is not in this item's bank (verdict {VERDICT_TEXT[item['verdict']]})")
            else:
                fail("unknown", f"use holds {json.dumps(sid)[:40]}, not a sentence id of this item")
        seen.add(sid)


def _check_show(show: Any, item: Mapping[str, Any], digest: Mapping[str, Any] | None, fail) -> None:
    if not _id_list(show, str):
        fail("form", "show is not a list of reference ids")
        return
    own = {value["ref"]: value["name"] for value in item["values"]}
    others = {value["ref"] for entry in (digest["items"] if digest is not None else []) for value in entry["values"]}
    seen: set[str] = set()
    for ref in show:
        if ref in seen:
            fail("duplicate", f"show lists {json.dumps(ref)[:40]} twice")
        elif ref not in own:
            where = ("another item's value" if ref in others else
                     "no value of the digest" if REF_ID.fullmatch(ref) else "not a reference id such as v4")
            fail("reference", f"{json.dumps(ref)[:40]} is {where}, not a value of this item")
        elif own[ref] in ALWAYS_SHOWN:
            fail("reference", f"{ref} is the item's {own[ref]}, which Auditex always shows")
        seen.add(ref)


def check_answer(answer: Any, item: Mapping[str, Any], digest: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """{"pass": bool, "failures": [{"check", "detail"}]} for the model's answer for one digest item.

    Checks: form, empty, limit, duplicate, precondition, unknown (use) and reference (show). Pass the whole digest so
    another item's reference ids are named as such.
    """
    failures: list[dict[str, str]] = []

    def fail(check: str, detail: str) -> None:
        failures.append({"check": check, "detail": detail[:160]})

    parsed, problem = _parse(answer, ITEM_KEYS)
    if parsed is None:
        fail("form", problem or "the answer is not one JSON object")
    else:
        _check_use(parsed["use"], item, fail)
        _check_show(parsed["show"], item, digest, fail)
    return {"pass": not failures, "failures": failures}


def _check_name(item: Mapping[str, Any]) -> str:
    return next(value["text"] for value in item["values"] if value["name"] == "check")


def _render(item: Mapping[str, Any], use: list[str], show: list[str]) -> str:
    bank = item_bank(item)
    lines = [f"Check: {quoted(_check_name(item))}", f"Verdict: {VERDICT_TEXT[item['verdict']]}."]
    steps = iter(sorted((sid for sid in use if bank[sid]["kind"] == "step"), key=lambda sid: int(sid[5:])))
    lines.extend(bank[next(steps) if bank[sid]["kind"] == "step" else sid]["text"] for sid in use)
    shown = set(show) | {ref_of(item, name) for sid in use for name in bank[sid]["shows"]}
    lines.extend(f"{LABELS[value['name']]}: {quoted(value['text'])}" for value in item["values"]
                 if value["ref"] in shown and value["name"] not in ALWAYS_SHOWN)
    return "\n".join(lines)


def render_answer(answer: Any, item: Mapping[str, Any], digest: Mapping[str, Any] | None = None) -> str:
    """The item as Auditex shows it with the model's answer; AnswerCheckError when the answer does not pass."""
    result = check_answer(answer, item, digest)
    if not result["pass"]:
        raise AnswerCheckError("; ".join(f"{f['check']}: {f['detail']}" for f in result["failures"]))
    parsed, _ = _parse(answer, ITEM_KEYS)
    return _render(item, parsed["use"], parsed["show"])


def fallback_text(item: Mapping[str, Any]) -> str:
    """The fixed text an item shows when the model's answer fails the checks: the check and verdict frames, then the
    severity and the reason only when the digest marks them as shipped catalogue text, so tenant data never changes
    it."""
    show = [value["ref"] for value in item["values"]
            if value["name"] in ("severity", "reason") and value.get("source") == CATALOGUE]
    return _render(item, [], show)


def answer_item(answer: Any, item: Mapping[str, Any], digest: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """{"text", "fallback", "failures"}: the item rendered with the model's answer when it passes, else the fixed
    text."""
    result = check_answer(answer, item, digest)
    if result["pass"]:
        parsed, _ = _parse(answer, ITEM_KEYS)
        return {"text": _render(item, parsed["use"], parsed["show"]), "fallback": False, "failures": []}
    return {"text": fallback_text(item), "fallback": True, "failures": result["failures"]}


def check_summary(answer: Any, digest: Mapping[str, Any]) -> dict[str, Any]:
    """{"pass": bool, "failures": [{"check", "detail"}]} for the model's run summary."""
    failures: list[dict[str, str]] = []

    def fail(check: str, detail: str) -> None:
        failures.append({"check": check, "detail": detail[:160]})

    parsed, problem = _parse(answer, SUMMARY_KEYS)
    if parsed is None:
        fail("form", problem or "the answer is not one JSON object")
        return {"pass": False, "failures": failures}
    limits, summary, highlight = frames()["limits"], parsed["summary"], parsed["highlight"]
    if not _id_list(summary, str):
        fail("form", "summary is not a list of run frame ids")
    else:
        bank = run_bank(digest)
        if not summary:
            fail("empty", "summary selects no frame")
        if len(summary) > limits["summary"]:
            fail("limit", f"summary selects {len(summary)} frames, more than {limits['summary']}")
        for index, fid in enumerate(summary):
            if fid in summary[:index]:
                fail("duplicate", f"summary lists {fid} twice")
            elif fid not in bank:
                fail("precondition" if fid in frames()["run"] else "unknown",
                     f"{json.dumps(fid)[:40]} is not a run frame whose counts hold for this run")
    if not _id_list(highlight, int):
        fail("form", "highlight is not a list of item numbers")
    else:
        allowed, numbers = highlightable(digest), {item["item"] for item in digest["items"]}
        if len(highlight) > limits["highlight"]:
            fail("limit", f"highlight lists {len(highlight)} items, more than {limits['highlight']}")
        for index, number in enumerate(highlight):
            if number in highlight[:index]:
                fail("duplicate", f"highlight lists item {number} twice")
            elif number not in allowed:
                fail("precondition" if number in numbers else "unknown",
                     f"item {number} is not an item the summary may highlight")
    return {"pass": not failures, "failures": failures}


def _render_summary(digest: Mapping[str, Any], summary: list[str], highlight: list[int]) -> str:
    bank = run_bank(digest)
    lines = [bank[fid] for fid in summary]
    chosen = [item for item in digest["items"] if item["item"] in set(highlight)]
    if chosen:
        lines.append(frames()["highlight"]["heading"])
        lines.extend(f"Check: {quoted(_check_name(item))}. Verdict: {VERDICT_TEXT[item['verdict']]}."
                     for item in chosen)
    return "\n".join(lines)


def fallback_summary(digest: Mapping[str, Any]) -> str:
    """The fixed run summary: every run frame without a precondition, in the frames file's order."""
    unconditional = [fid for fid, frame in frames()["run"].items() if not frame["min"] and not frame["max"]]
    return _render_summary(digest, unconditional, [])


def render_summary(answer: Any, digest: Mapping[str, Any]) -> str:
    """The run summary as Auditex shows it with the model's answer; AnswerCheckError when it does not pass."""
    result = check_summary(answer, digest)
    if not result["pass"]:
        raise AnswerCheckError("; ".join(f"{f['check']}: {f['detail']}" for f in result["failures"]))
    parsed, _ = _parse(answer, SUMMARY_KEYS)
    return _render_summary(digest, parsed["summary"], parsed["highlight"])


def answer_summary(answer: Any, digest: Mapping[str, Any]) -> dict[str, Any]:
    """{"text", "fallback", "failures"}: the run summary with the model's answer when it passes, else the fixed one."""
    result = check_summary(answer, digest)
    if result["pass"]:
        parsed, _ = _parse(answer, SUMMARY_KEYS)
        return {"text": _render_summary(digest, parsed["summary"], parsed["highlight"]), "fallback": False,
                "failures": []}
    return {"text": fallback_summary(digest), "fallback": True, "failures": result["failures"]}
