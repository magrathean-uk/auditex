"""Regenerate tests/fixtures/explainer/corpus-manifest.json from the generators (a reviewed change, not a test repair).

Usage from the repository root, with the repository venv (no network, nothing else is written):

    .venv/bin/python -B -I tests/explainer_checks/build_manifest.py [--write]

Without --write the manifest is printed. ``known_misses`` and ``known_miss_note`` are kept from the existing file:
they record mutants that no expected check flags, found by the serial mutation replay, and are never added here.
"""
import collections
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

from explainer_checks import corpus, pool  # noqa: E402
from explainer_checks.support import LOCAL, read_bytes  # noqa: E402


def sha(data):
    return hashlib.sha256(data).hexdigest()


def input_pins():
    pins = {f"configs/{name}": sha((ROOT / "configs" / name).read_bytes())
            for name in ("explainer-baselines.json", "explainer-template.json", "explainer-what-to-collect.json",
                         "scuba-value-rules.json")}
    pins["tests/fixtures/explainer/checks/english-words.txt"] = sha((LOCAL / "english-words.txt").read_bytes())
    pins["tests/fixtures/explainer/checks/train-identifiers.json"] = sha(read_bytes(LOCAL / "train-identifiers.json.gz"))
    return pins


def build():
    old = corpus.load_manifest() if corpus.MANIFEST.exists() else {}
    testset = corpus.testset()
    pairs = corpus.base_pairs()
    rows = list(corpus.mutation_rows())
    vectors = pool.pool()
    harmful = [r for r in rows if not r["benign"]]
    return {
        "schema_version": 1,
        "note": "Pins for generated test material. Nothing listed here is stored: the pool is the allowed value-rule vector "
                "fixtures, the test set, pairs and mutants are generated from it (tests/explainer_checks), and the hashes "
                "below detect any drift in the pool, the engine, the template or the generators.",
        "seed": pool.SEED,
        "inputs_sha256": input_pins(),
        "pool": {"vectors": len(vectors), "by_kind": testset["counts"]["pool_by_kind"],
                 "cells": testset["counts"]["cells_in_pool"], "policies": testset["counts"]["policies_in_pool"],
                 "vector_ids_sha256": sha("\n".join(sorted(v["vector_id"] for v in vectors)).encode())},
        "testset": {"counts": testset["counts"], "rows_sha256": corpus.stream_sha256(testset["rows"])},
        "pairs": {"base": len(pairs), "shared": len(corpus.shared_pairs()), "twins_per_pair": 5,
                  "by_verdict": dict(sorted(collections.Counter(p["prompt"]["record"]["verdict"] for p in pairs).items())),
                  "stream_sha256": corpus.stream_sha256(corpus.pair_rows_for_manifest())},
        "mutations": {"rows": len(rows), "harmful": len(harmful), "benign": len(rows) - len(harmful),
                      "types": len({r["mutant"] for r in rows}),
                      "by_group": dict(sorted(collections.Counter(r["group"] for r in rows).items())),
                      "stream_sha256": corpus.stream_sha256(rows),
                      "known_misses": old.get("mutations", {}).get("known_misses", []),
                      "known_miss_note": old.get("mutations", {}).get("known_miss_note", "")},
    }


if __name__ == "__main__":
    text = json.dumps(build(), indent=1, sort_keys=True) + "\n"
    if "--write" in sys.argv:
        corpus.MANIFEST.write_text(text)
    else:
        print(text)
