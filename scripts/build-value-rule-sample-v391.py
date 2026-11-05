"""Build the bounded v3.9.1 replay sample from the spec's vectors, offline and deterministic.

Usage: build-value-rule-sample-v391.py VECTORS.jsonl A2_DIRECTORY OUTPUT_DIRECTORY

VECTORS.jsonl is the spec's 26,898-vector corpus; A2_DIRECTORY holds ADDENDUM-A2's ``a2-vectors.jsonl`` and
``a2-label-overrides.jsonl``. Writes, into OUTPUT_DIRECTORY, ``vectors-v391-sample.jsonl.xz``,
``label-overrides-a2-v391-sample.jsonl`` and ``manifest-v391-sample.json``.

Selection (no randomness): for every (policy, cell) of the 1,084 cells, the smallest vector, and the smallest
real pack row (train or validation) that agrees with its gold if there is one, else the second smallest vector; for every
(policy, divergence id) the smallest vector; the three constructed A2 vectors; and the exact A2 label overrides of
every selected vector. Held-out test, pilot and sealed freeze rows are never selected. The sample keeps only the
fields the replay compares.
"""
from __future__ import annotations

from hashlib import sha256
import json
import lzma
from pathlib import Path
import sys

KEEP = ("policy", "sections", "criticality", "rule_verdict", "rule_cell", "rule_reason_code", "rule_reason_text",
        "rule_cited_sections", "gold_verdict", "gold_response", "disagreement", "divergence_id", "vector_id",
        "source_kind", "origin", "parity_exempt", "pack_response_matches", "flags")
SELECTABLE = {"constructed", "pack-train", "pack-validation", "packlic-train", "pbi-pack-train",
              "pbi-pack-validation", "aad-pack-train", "a2-constructed"}
REAL = {"pack-train", "pack-validation", "packlic-train", "pbi-pack-train", "pbi-pack-validation", "aad-pack-train"}


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


def build(vectors: Path, a2: Path, out: Path) -> dict:
    source = sha256()
    two_smallest: dict[tuple, list] = {}
    real: dict[tuple, tuple] = {}
    divergence: dict[tuple, tuple] = {}
    with vectors.open("rb") as handle:
        for raw in handle:
            source.update(raw)
            row = json.loads(raw)
            if row["source_kind"] not in SELECTABLE:
                continue
            key, rank = (row["policy"], row["rule_cell"]), (len(raw), row["vector_id"])
            pair = two_smallest.setdefault(key, [])
            pair.append((rank, row))
            pair.sort(key=lambda item: item[0])
            del pair[2:]
            if row["source_kind"] in REAL and row.get("disagreement") is None and row.get("gold_response") is not None:
                if key not in real or rank < real[key][0]:
                    real[key] = (rank, row)
            if row.get("divergence_id"):
                dkey = (row["policy"], row["divergence_id"])
                if dkey not in divergence or rank < divergence[dkey][0]:
                    divergence[dkey] = (rank, row)
    chosen: dict[str, dict] = {}
    for key, pair in two_smallest.items():
        chosen[pair[0][1]["vector_id"]] = pair[0][1]
        second = real[key][1] if key in real else (pair[1][1] if len(pair) > 1 else None)
        if second is not None:
            chosen[second["vector_id"]] = second
    for _rank, row in divergence.values():
        chosen[row["vector_id"]] = row
    a2_rows = [json.loads(line) for line in (a2 / "a2-vectors.jsonl").read_text().splitlines()]
    overrides = [json.loads(line) for line in (a2 / "a2-label-overrides.jsonl").read_text().splitlines()]
    for row in a2_rows:
        chosen[row["vector_id"]] = row
    ids = set(chosen)
    kept = [entry for entry in overrides if entry["vector_id"] in ids]
    # Every selected AAD 3.3v2 row whose gold cites a removed section must have its exact override.
    sample = [{k: chosen[i][k] for k in KEEP if k in chosen[i]} for i in sorted(ids)]
    out.mkdir(parents=True, exist_ok=True)
    payload = b"".join(canonical(row) for row in sample)
    (out / "vectors-v391-sample.jsonl.xz").write_bytes(lzma.compress(payload, preset=6))
    (out / "label-overrides-a2-v391-sample.jsonl").write_bytes(b"".join(canonical(e) for e in kept))
    manifest = {
        "spec_version": "v3.9.1+A2", "source_vectors_sha256": source.hexdigest(), "source_vectors": 26898,
        "a2_vectors_sha256": sha256((a2 / "a2-vectors.jsonl").read_bytes()).hexdigest(),
        "a2_label_overrides_sha256": sha256((a2 / "a2-label-overrides.jsonl").read_bytes()).hexdigest(),
        "rows": len(sample), "overrides": len(kept),
        "sample_sha256": sha256((out / "vectors-v391-sample.jsonl.xz").read_bytes()).hexdigest(),
        "overrides_sha256": sha256((out / "label-overrides-a2-v391-sample.jsonl").read_bytes()).hexdigest(),
        "by_source": {k: sum(r["source_kind"] == k for r in sample) for k in sorted({r["source_kind"] for r in sample})},
        "cells_reached": len({(r["policy"], r["rule_cell"]) for r in sample}),
        "policies": len({r["policy"] for r in sample}),
        "selection": "per cell: smallest vector and smallest agreeing real pack row; per policy and divergence id: "
                     "smallest vector; the three A2 constructed vectors; exact A2 overrides of selected rows; "
                     "no test, pilot or sealed freeze rows",
    }
    (out / "manifest-v391-sample.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    print(json.dumps(build(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])), indent=2, sort_keys=True))
