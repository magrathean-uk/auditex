"""Build the v3.9.1 FINAL stage-7 fixture with shared origin/split checks.

Usage: build-value-rule-fixture-s7.py SOURCE.jsonl OUTPUT.jsonl.xz
Writes manifest-s7.json beside the fixture; no machine paths are embedded.
"""
from __future__ import annotations

import importlib.util
import json
import lzma
import sys
from collections import Counter
from hashlib import sha256
from pathlib import Path

POLICIES = frozenset({
    *(f"MS.AAD.7.{n}v1" for n in range(4, 10)),
    *(f"MS.AAD.{n}v1" for n in ("1.1", "2.1", "2.3", "3.1", "3.6", "3.7", "3.8", "3.9", "9.1")),
    "MS.AAD.3.2v2",
})


def build(source: Path, target: Path) -> dict:
    spec = importlib.util.spec_from_file_location(
        "shared_value_rule_fixture", Path(__file__).with_name("build-value-rule-fixture.py"))
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    # The final spec adds a new constructed origin; all shared exclusions still apply.
    shared.V3_CONSTRUCTED.add("constructed by v391_vectors.py")
    root = Path(__file__).resolve().parents[1]
    items = json.loads((root / "configs/scuba-policy-sections.json").read_text())["policies"]
    origins = {"v3.7 vectors-base", "v3.8 constructed", "v3.9 constructed", "v3.9.1 constructed"}
    rows, source_hash = [], sha256()
    # Validate before publishing; retain the source provenance as stage 5 does.
    for raw in source.open("rb"):
        source_hash.update(raw)
        row = json.loads(raw)
        if row["policy"] not in POLICIES:
            continue
        if type(row.get("origin")) is not str or row["origin"] not in origins:
            raise ValueError("unclassified vector origin")
        kind, file, split = row["source_kind"], row.get("source_file", ""), row.get("split")
        if kind == "constructed":
            if type(file) is not str or file not in shared.V3_CONSTRUCTED or split is not None:
                raise ValueError("constructed vector of unknown origin")
        elif kind in shared.V3_PACK:
            if not isinstance(file, str) or not file.startswith(shared.V3_PACK_PREFIX) or split != shared.V3_PACK[kind]:
                raise ValueError("vector split differs from origin")
            if split == "test":
                continue
        elif kind in shared.V3_PILOT:
            continue
        else:
            raise ValueError("unclassified vector origin")
        if row.get("disagreement") and not row["disagreement"].startswith("expected:"):
            raise ValueError("UNEXPECTED or NO GOLD")
        if row.get("gold_verdict") is None:
            raise ValueError("NO GOLD")
        trimmed = {key: row[key] for key in (*shared.V3_FIELDS, "source_file", "split") if key in row}
        trimmed.update(origin="pack-train" if kind == "packlic-train" else kind, source_origin=row["origin"])
        trimmed.setdefault("criticality", items[row["policy"]]["policy_item"]["criticality"])
        rows.append(trimmed)
    if len({r["vector_id"] for r in rows}) != len(rows):
        raise ValueError("duplicate vector IDs")
    payload = b"".join((json.dumps(r, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
                       for r in rows)
    target.write_bytes(lzma.compress(payload, preset=6))
    manifest = {
        "sha256": sha256(target.read_bytes()).hexdigest(), "source_sha256": source_hash.hexdigest(),
        "spec_version": "v3.9.1", "stage": 7, "rows": len(rows),
        "selection": ("constructed and training-pack train/validation (licensed twins included); "
                      "held-out test split and pilot rows (sealed AAD v2.1 freeze included) excluded"),
        "by_policy": dict(sorted(Counter(r["policy"] for r in rows).items())),
        "by_cell": dict(sorted(Counter(f"{r['policy']}:{r['rule_cell']}" for r in rows).items())),
        "by_verdict": dict(sorted(Counter(r["rule_verdict"] for r in rows).items())),
        "by_source": dict(sorted(Counter(r["source_kind"] for r in rows).items())),
        "by_origin": dict(sorted(Counter(r["origin"] for r in rows).items())),
    }
    target.with_name("manifest-s7.json").write_text(
        json.dumps({target.name: manifest}, sort_keys=True, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(json.dumps(build(Path(sys.argv[1]), Path(sys.argv[2])), sort_keys=True))
