"""Red-team candidates re-bound to allowed pool bases at test time.

``tests/fixtures/explainer/redteam/candidates.json`` holds the 50 hand-written candidate texts (40 wrong, 10 benign),
each with a selector instead of a stored prompt. ``pair_for`` resolves the selector over the allowed vector pool
(``corpus.resolve_base``), applies the candidate's constructed evidence edit if it has one, and attaches the
candidate as raw output text. Observed results are recomputed by running the eight checks; the stored
``observed_failure_checks`` pin them, the stored ``expected_failure_checks`` are the independent adjudication.
"""
import json

from . import corpus
from .driver import failing, run_pair
from .support import FIXTURES, corpus_resources, read_json

PATH = FIXTURES / "redteam" / "candidates.json"
IDS = {f"W{n:02d}" for n in range(1, 41)} | {f"B{n:02d}" for n in range(1, 11)}


def load():
    return read_json(PATH)


def pair_for(candidate):
    base = corpus.resolve_base(candidate["selector"], test_id=candidate["id"])
    prompt = json.loads(json.dumps(base["prompt"]))
    for edit in candidate.get("evidence_edit", []):
        evidence = next(e for e in prompt["data"]["evidence"] if e["section"] == edit["section"])
        target = evidence["observed"]
        for key in edit["path"][:-1]:
            target = target[key]
        target[edit["path"][-1]] = edit["value"]
    output = {"explanation": candidate["explanation"], "remediation_steps": candidate["steps"],
              "evidence_refs": base["output"]["evidence_refs"]}
    return {"id": candidate["id"], "vector_id": base["vector_id"], "prompt": prompt,
            "output_text": json.dumps(output, ensure_ascii=True)}


def observed(candidate, resources=None):
    return failing(run_pair(pair_for(candidate), resources or corpus_resources()))


def unresolved(candidate):
    """True when the desired behaviour does not hold: no expected check fires (wrong) or any check fires (benign)."""
    expected, seen = set(candidate["expected_failure_checks"]), set(candidate["observed_failure_checks"])
    return not (expected & seen) if expected else bool(seen)


def tallies(candidates):
    wrong = [c for c in candidates if c["kind"] == "wrong"]
    benign = [c for c in candidates if c["kind"] == "benign"]
    return {"wrong": len(wrong), "benign": len(benign),
            "wrong_let_through": sum(not c["observed_failure_checks"] for c in wrong),
            "wrong_without_expected_check": sum(unresolved(c) for c in wrong),
            "wrong_caught_by_expected_check": sum(not unresolved(c) for c in wrong),
            "benign_false_alarms": sum(bool(c["observed_failure_checks"]) for c in benign),
            "benign_false_alarm_ids": sorted(c["id"] for c in benign if c["observed_failure_checks"]),
            "r_original": {"wrong_let_through": 31, "benign_false_alarms": 4},
            "r_known_gap_rule": {"wrong_without_expected_check": sum(
                not (set(c["expected_failure_checks"]) & set(c["r_observed_failure_checks"])) for c in wrong)}}
