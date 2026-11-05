"""All 40 wrong candidates and 10 benign controls, independently adjudicated, re-bound to allowed pool bases.

The expected checks are the independent adjudication; the observed results are recomputed here and pinned in
tests/fixtures/explainer/redteam/candidates.json. Observed pins are not permissions to accept a wrong answer or
reject a benign one: desired behaviour uses strict xfail for unresolved rows, and an unexpected pass requires
review of the adjudication before the pin is changed.
"""
import hashlib
import json

import pytest

from . import corpus, pool, redteam


def pytest_generate_tests(metafunc):
    if "gap" not in metafunc.fixturenames:
        return
    rows = redteam.load()["candidates"]
    assert {row["id"] for row in rows} == redteam.IDS
    params = []
    for row in rows:
        marks = []
        if redteam.unresolved(row) and metafunc.function.__name__ == "test_desired_behaviour":
            marks = [pytest.mark.xfail(strict=True, reason=row["issue"] + ": " + row["intent"])]
        params.append(pytest.param(row, id=row["id"], marks=marks))
    metafunc.parametrize("gap", params)


def test_observed_results_stay_pinned(gap):
    pair = redteam.pair_for(gap)
    assert set(redteam.observed(gap)) == set(gap["observed_failure_checks"]), gap["intent"]
    assert gap["issue"] and gap["intent"]
    # Bound to an allowed base: the resolved vector is a constructed or pack train/validation row.
    kind = next(v["kind"] for v in pool.pool() if v["vector_id"] == pair["vector_id"])
    assert kind in pool.ALLOWED_KINDS


def test_desired_behaviour(gap):
    failures = set(redteam.observed(gap))
    expected = set(gap["expected_failure_checks"])
    if expected:
        assert failures & expected, gap["intent"]
    else:
        assert not failures, gap["intent"]


def test_texts_are_the_original_texts_unless_marked_adapted():
    canon = lambda v: json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    adapted = set()
    for row in redteam.load()["candidates"]:
        same = hashlib.sha256(canon({"explanation": row["explanation"], "steps": row["steps"]}).encode()).hexdigest() == row["r_text_sha256"]
        if row["adapted"]:
            adapted.add(row["id"])
            assert row["rebinding_note"], row["id"]
        else:
            assert same and "evidence_edit" not in row, row["id"]
    assert adapted == {"W16", "W19", "W34", "W40"}


def test_tallies_are_pinned_and_recomputed():
    doc = redteam.load()
    assert redteam.tallies(doc["candidates"]) == doc["tallies"]
    assert doc["tallies"]["wrong"] == 40 and doc["tallies"]["benign"] == 10
    # Known false alarms are never labelled acceptable.
    assert doc["tallies"]["benign_false_alarm_ids"] == ["B01", "B02", "B03", "B09"]
