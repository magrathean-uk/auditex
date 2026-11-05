"""Build the stage-5 fixture and manifest from explicit v3.9.1 input paths.

Usage: build-value-rule-fixture-s5.py SOURCE.jsonl OUTPUT.jsonl.xz MANIFEST.json
Includes the held SS 1.1 rule; excludes all held-out test and pilot rows.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
import lzma
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
POLICIES = frozenset({"MS.EXO.1.1v2"} | {
    f"MS.SECURITYSUITE.{major}.{minor}v1"
    for major, minors in ((1, range(1, 4)), (2, range(1, 5)), (3, range(1, 5)))
    for minor in minors
})
HELD = "MS.SECURITYSUITE.1.1v1"
P9_VECTOR = "pack-train:scuba-securitysuite-ms-securitysuite-3-2v1-376939a16c"
P9_RECIPE = "D90/P9: remove unused scuba_config evidence e4 from the SS 3.2 unknown claim; preserve source_gold_response."


def shared_builder():
    spec = importlib.util.spec_from_file_location("value_rule_fixture_builder", ROOT / "scripts/build-value-rule-fixture.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def include_held(row, shared):
    """Apply the provenance gate to every stage row, including held SS 1.1."""
    kind, origin, split = row["source_kind"], row.get("source_file", ""), row.get("split")
    if "origin" not in row:
        raise ValueError("held vector without origin")
    if row["origin"] not in {"v3.7 vectors-base", "v3.8 constructed", "v3.9 constructed"}:
        raise ValueError("unclassified vector origin")
    if kind == "constructed":
        if origin not in shared.V3_CONSTRUCTED or split is not None:
            raise ValueError("constructed held vector of unknown origin")
    elif kind in shared.V3_PACK:
        if not origin.startswith(shared.V3_PACK_PREFIX) or split != shared.V3_PACK[kind]:
            raise ValueError("held vector split differs from origin")
        if split == "test":
            return False
    elif kind in shared.V3_PILOT:
        return False
    else:
        raise ValueError("unclassified held vector origin")
    if row.get("disagreement") and not row["disagreement"].startswith("expected:"):
        raise ValueError("UNEXPECTED or NO GOLD")
    if row.get("gold_verdict") is None:
        raise ValueError("NO GOLD")
    return True


def build(source: Path, target: Path) -> dict:
    shared = shared_builder()
    rows = []
    source_hash = sha256()
    policy_items = json.loads((ROOT / "configs/scuba-policy-sections.json").read_text())["policies"]
    # Filter before writing anything; retain the provenance that the shared
    # builder's older trimmed field set discarded.
    for raw in source.open("rb"):
        source_hash.update(raw)
        row = json.loads(raw)
        if row["policy"] not in POLICIES:
            continue
        if not include_held(row, shared):
            continue
        trimmed = {key: row[key] for key in (*shared.V3_FIELDS, "origin", "source_file", "split", "parity_exempt") if key in row}
        trimmed.setdefault("criticality", policy_items[row["policy"]]["policy_item"]["criticality"])
        if row["vector_id"] == P9_VECTOR:
            if (not row.get("parity_exempt", "").startswith("D90:")
                    or row["gold_response"]["claims"][0]["evidence_ids"] != ["e0", "e3", "e4"]
                    or row["rule_cited_sections"] != ["dlp_compliance_rules"]):
                raise ValueError("P9 source correction no longer matches")
            trimmed["source_gold_response"] = deepcopy(row["gold_response"])
            trimmed["gold_response"] = deepcopy(row["gold_response"])
            trimmed["gold_response"]["claims"][0]["evidence_ids"] = ["e0", "e3"]
        rows.append(trimmed)
    rows.sort(key=lambda row: row["vector_id"])
    if len({row["vector_id"] for row in rows}) != len(rows):
        raise ValueError("duplicate vector IDs")
    rules = json.loads((ROOT / "configs/scuba-value-rules.json").read_text())["policies"]
    rules.update(json.loads((ROOT / "tests/fixtures/value-rules/held-rows-s5.json").read_text()))
    reached = {policy: {row["rule_cell"] for row in rows if row["policy"] == policy} for policy in POLICIES}
    if any(reached[policy] != set(rules[policy]["cells"]) for policy in POLICIES):
        raise ValueError("stage-5 cell coverage is incomplete")
    payload = b"".join((json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
                       for row in rows)
    target.write_bytes(lzma.compress(payload, preset=6))
    return {
        "sha256": sha256(target.read_bytes()).hexdigest(),
        "source_sha256": source_hash.hexdigest(), "spec_version": "v3.9.1+A1",
        "rows": len(rows), "selection": "constructed and pack train/validation (including licensed train twins); no test or pilot rows",
        "held_policies": [HELD],
        "gold_corrections": {P9_VECTOR: P9_RECIPE},
        "replacement_recipes": [],
        "origin_audit": {"constructed": sum(r["source_kind"] == "constructed" for r in rows),
                         "pack-train": sum(r["source_kind"] in {"pack-train", "packlic-train"} for r in rows),
                         "pack-validation": sum(r["source_kind"] == "pack-validation" for r in rows),
                         "pack-test": 0, "pilot": 0},
        "by_policy": dict(sorted(Counter(row["policy"] for row in rows).items())),
        "by_cell": dict(sorted(Counter(f"{row['policy']}:{row['rule_cell']}" for row in rows).items())),
        "by_verdict": dict(sorted(Counter(row["rule_verdict"] for row in rows).items())),
        "by_source": dict(sorted(Counter(row["source_kind"] for row in rows).items())),
        "cells_reached": {policy: len(reached[policy]) for policy in sorted(POLICIES)},
    }


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    manifest = build(Path(sys.argv[1]), Path(sys.argv[2]))
    Path(sys.argv[3]).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: manifest[key] for key in ("rows", "by_policy", "by_source", "cells_reached")}, sort_keys=True))
