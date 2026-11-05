"""Generated harmful/benign mutation replay, partitioned for serial 300-second batches.

The mutation rows are generated in memory (corpus.mutation_rows): the operators of mutants.py applied to the stage-B
base pairs plus the two shared-reason pairs, seeded only by base id and mutant name. Each harmful row counts as
detected only if an EXPECTED check fails; a benign false positive is ANY failure or skip. The expected counts and the
canonical stream hash are pinned in tests/fixtures/explainer/corpus-manifest.json. Run each selection
-k chunk-N independently when a full batch exceeds the cap.
"""
from collections import Counter
from functools import lru_cache
import json
from time import perf_counter

import pytest

from . import corpus
from .driver import run_pair
from .support import corpus_resources, integration_result

CHUNKS = 4


@lru_cache(maxsize=1)
def stream():
    return tuple(corpus.mutation_rows())


@lru_cache(maxsize=1)
def pairs():
    return corpus.all_pairs_by_id()


def replay(rows, resources):
    totals = Counter()
    errors = []
    by_id = pairs()
    for row in rows:
        assert row["base_id"] in by_id, row["id"]
        assert row["expect"] or row["benign"], row["id"]
        pair = {"id": row["id"], "prompt": by_id[row["base_id"]]["prompt"]}
        pair.update({key: row[key] for key in ("output", "output_text") if key in row})
        result = run_pair(pair, resources)
        failed = {check for check, value in result.items() if value["pass"] is False}
        skipped = {check for check, value in result.items() if value["pass"] is None}
        if row["benign"]:
            totals["benign"] += 1
            if failed or skipped:
                totals["false_positives"] += 1
                errors.append((row["id"], sorted(failed), sorted(skipped)))
        else:
            totals["harmful"] += 1
            detected = bool(failed.intersection(row["expect"]))
            totals["detected"] += detected
            if not detected:
                errors.append((row["id"], sorted(failed), sorted(skipped)))
    return totals, errors


def test_stream_matches_manifest():
    manifest = corpus.load_manifest()["mutations"]
    rows = stream()
    assert len(rows) == manifest["rows"]
    assert sum(not r["benign"] for r in rows) == manifest["harmful"]
    assert sum(r["benign"] for r in rows) == manifest["benign"]
    assert dict(sorted(Counter(r["group"] for r in rows).items())) == manifest["by_group"]
    assert len({r["mutant"] for r in rows}) == manifest["types"]
    assert len({r["id"] for r in rows}) == len(rows)
    assert corpus.stream_sha256(rows) == manifest["stream_sha256"]


@pytest.mark.explainer_acceptance
@pytest.mark.parametrize("chunk", range(CHUNKS), ids=lambda n: f"chunk-{n:02d}")
def test_mutation_recall_and_benign(chunk, record_property, tmp_path):
    rows = [row for index, row in enumerate(stream()) if index % CHUNKS == chunk]
    assert rows, "missing generated mutation rows"
    start = perf_counter()
    totals, errors = replay(rows, corpus_resources())
    elapsed = perf_counter() - start
    integration_result(f"mutation-{chunk:02}", {"seconds": elapsed, "totals": dict(totals), "errors": errors}, root=tmp_path)
    record_property("mutation_seconds", elapsed)
    record_property("mutation_totals", json.dumps(dict(totals), sort_keys=True))
    print(f"chunk {chunk}: {dict(totals)}; {elapsed:.3f} s; misses {[e[0] for e in errors]}")
    manifest = corpus.load_manifest()["mutations"]
    assert totals["harmful"] > 0 and totals["benign"] > 0
    # Across the four disjoint chunks the misses stay within the documented set, so recall cannot silently fall.
    assert {ident for ident, _, _ in errors} <= set(manifest["known_misses"]), (totals, errors[:10])
    assert totals["false_positives"] == 0, (totals, errors[:10])


def test_default_mutation_sample():
    """Bounded, stable prefix per type: four harmful and six benign rows of every mutant type."""
    rows, counts = [], Counter()
    types = set()
    for row in stream():
        key = (row["benign"], row["mutant"])
        types.add(key)
        if counts[key] < (6 if row["benign"] else 4):
            rows.append(row)
            counts[key] += 1
    assert set(counts) == types
    totals, errors = replay(rows, corpus_resources())
    print(f"default mutation sample: {dict(totals)}; {len(types)} types")
    assert totals["harmful"] >= 300 and totals["benign"] >= 100
    assert totals["detected"] >= totals["harmful"] - 2, errors
    assert totals["false_positives"] == 0, errors
