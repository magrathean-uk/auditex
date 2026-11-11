"""Trim constructed and train/validation value-rule vectors.

Usage: build-value-rule-fixture.py SOURCE.jsonl OUTPUT.jsonl.xz
The source and destination are explicit; this script has no machine paths.

A v2 source (no ``origin`` field) yields the Power BI and AAD 3.4v1 fixture.
A v3.x source (every row has ``origin``) yields the fixture for the other
policies of ``configs/scuba-value-rules.json``; its spec version is the
catalogue's. Both keep constructed rows and training-pack train and
validation rows, and drop every held-out test-split row and every pilot row
(the sealed AAD v2.1 freeze rows included).
"""
from __future__ import annotations

import json
import lzma
import sys
from collections import Counter
from hashlib import sha256
from pathlib import Path

FIELDS = ("vector_id", "policy", "criticality", "sections", "rule_verdict", "rule_cell",
          "rule_reason_code", "rule_reason_text", "rule_cited_sections", "gold_verdict",
          "gold_response", "disagreement", "divergence_id", "flags", "expected_verdict",
          "source_kind")
PACK_PREFIX = "20261030-oracle-pack-v10/training-pack-oracle-v10-ministral3-8b/"
PILOT_PREFIX = {"pbi-": "20261104-pbi-section-pilot/",
                "aad-": "20261104-aad-section-pilot-v2.1/",
                "ss6-": "20261104-ss6-section-pilot/"}
V3_FIELDS = FIELDS + ("gold_source",)
V3_PACK_PREFIX = "20261030-oracle-pack-v10/"
V3_CONSTRUCTED = {"constructed by build_vectors.py", "constructed by v38_vectors.py", "constructed by v39_vectors.py"}
V3_PACK = {"pack-train": "train", "pack-validation": "validation", "packlic-train": "train", "pack-test": "test"}
V3_PILOT = {f"{prefix}-{name}" for prefix in ("aad", "pbi", "ss6") for name in ("frozen", "diagnostic", "dropped")}
PBI_LICENSE_TEXT = {
    "licence_false": "Data unavailable: licence not detected: no Power BI licence was found (a false read can also mean missing permissions or a failed command), so the tenant settings could not be read; the policy was not assessed.",
    "licence_flag_unusable": "Data unavailable: licence not detected: powerbi_license_found is not a boolean, so it is unknown whether a Power BI licence was found and the tenant settings could be read; the policy was not assessed.",
}


def build(source: Path, target: Path) -> dict:
    with source.open("rb") as handle:
        first = json.loads(handle.readline())
    if "origin" in first:
        return build_v3(source, target)
    catalogue = json.loads((Path(__file__).resolve().parents[1] / "configs/scuba-policy-sections.json").read_text())["policies"]
    source_hash = sha256()
    rows = []
    by_policy, by_cell, by_verdict, by_source = Counter(), Counter(), Counter(), Counter()
    for raw in source.open("rb"):
        source_hash.update(raw)
        row = json.loads(raw)
        kind = row["source_kind"]
        source_file = row.get("source_file", "")
        split = row.get("split")
        if kind == "constructed" and source_file == "constructed by build_vectors.py" and split is None:
            pass
        elif kind in {f"{prefix}-pack-{name}" for prefix in ("pbi", "aad")
                     for name in ("train", "validation", "test")} and source_file.startswith(PACK_PREFIX):
            if split != kind.rsplit("-", 1)[-1]:
                raise ValueError(f"vector split differs from origin: {row['vector_id']}")
            if split == "test":
                continue
        elif kind in {f"{prefix}{name}" for prefix in ("pbi-", "aad-", "ss6-")
                     for name in ("frozen", "diagnostic", "dropped")}:
            expected = next(path for prefix, path in PILOT_PREFIX.items() if kind.startswith(prefix))
            if split != "test" or not source_file.startswith(expected):
                raise ValueError(f"vector split differs from pilot origin: {row['vector_id']}")
            continue
        else:
            raise ValueError(f"unclassified vector origin: {row['vector_id']}")
        if row.get("disagreement") and not row["disagreement"].startswith("expected:"):
            raise ValueError(f"UNEXPECTED or NO GOLD: {row['vector_id']}")
        if row.get("gold_verdict") is None:
            raise ValueError(f"NO GOLD: {row['vector_id']}")
        trimmed = {key: row[key] for key in FIELDS if key in row}
        trimmed.setdefault("criticality", catalogue[row["policy"]]["policy_item"]["criticality"])
        if row["policy"].startswith("MS.POWERBI.") and row["rule_cell"] in PBI_LICENSE_TEXT:
            trimmed["rule_reason_text"] = PBI_LICENSE_TEXT[row["rule_cell"]]
        rows.append(trimmed)
        by_policy[row["policy"]] += 1
        by_cell[f"{row['policy']}:{row['rule_cell']}"] += 1
        by_verdict[row["rule_verdict"]] += 1
        by_source[kind] += 1
    if len({r["vector_id"] for r in rows}) != len(rows):
        raise ValueError("duplicate vector IDs")
    payload = b"".join((json.dumps(r, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
                       for r in rows)
    target.write_bytes(lzma.compress(payload, preset=6))
    return {"sha256": sha256(target.read_bytes()).hexdigest(), "source_sha256": source_hash.hexdigest(),
            "spec_version": "v3.6" if "v36" in str(source) else "v2", "rows": len(rows),
            "selection": "constructed and training-pack train/validation; held-out test and pilot rows excluded",
            "licence_text": "v3.6 constant wording replaces the v2 source wording",
            "by_policy": dict(sorted(by_policy.items())), "by_cell": dict(sorted(by_cell.items())),
            "by_verdict": dict(sorted(by_verdict.items())), "by_source": dict(sorted(by_source.items()))}


def build_v3(source: Path, target: Path, *, policies: set[str] | None = None) -> dict:
    root = Path(__file__).resolve().parents[1]
    catalogue = json.loads((root / "configs/scuba-policy-sections.json").read_text())["policies"]
    rules = json.loads((root / "configs/scuba-value-rules.json").read_text())
    selected = {policy for policy, row in rules["policies"].items()
                if not row["kind"].startswith("powerbi.") and policy != "MS.AAD.3.4v1"}
    # stage 4: a stage fixture can include held policies without enabling their config rows.
    if policies is not None:
        selected = policies
    source_hash = sha256()
    rows = []
    by_policy, by_cell, by_verdict, by_source = Counter(), Counter(), Counter(), Counter()
    for raw in source.open("rb"):
        source_hash.update(raw)
        row = json.loads(raw)
        if "origin" not in row:
            raise ValueError(f"vector without origin: {row['vector_id']}")
        if row["policy"] not in selected:
            continue
        kind, source_file, split = row["source_kind"], row.get("source_file", ""), row.get("split")
        if kind == "constructed":
            if source_file not in V3_CONSTRUCTED or split is not None:
                raise ValueError(f"constructed vector of unknown origin: {row['vector_id']}")
        elif kind in V3_PACK:
            if not source_file.startswith(V3_PACK_PREFIX) or split != V3_PACK[kind]:
                raise ValueError(f"vector split differs from origin: {row['vector_id']}")
            if split == "test":
                continue
        elif kind in V3_PILOT:
            continue
        else:
            raise ValueError(f"unclassified vector origin: {row['vector_id']}")
        if row.get("disagreement") and not row["disagreement"].startswith("expected:"):
            raise ValueError(f"UNEXPECTED or NO GOLD: {row['vector_id']}")
        if row.get("gold_verdict") is None:
            raise ValueError(f"NO GOLD: {row['vector_id']}")
        trimmed = {key: row[key] for key in V3_FIELDS if key in row}
        trimmed.setdefault("criticality", catalogue[row["policy"]]["policy_item"]["criticality"])
        rows.append(trimmed)
        by_policy[row["policy"]] += 1
        by_cell[f"{row['policy']}:{row['rule_cell']}"] += 1
        by_verdict[row["rule_verdict"]] += 1
        by_source[kind] += 1
    if len({r["vector_id"] for r in rows}) != len(rows):
        raise ValueError("duplicate vector IDs")
    payload = b"".join((json.dumps(r, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
                       for r in rows)
    target.write_bytes(lzma.compress(payload, preset=6))
    return {"sha256": sha256(target.read_bytes()).hexdigest(), "source_sha256": source_hash.hexdigest(),
            "spec_version": rules["spec_version"], "rows": len(rows),
            "selection": ("constructed and training-pack train/validation (licensed twins included); "
                          "held-out test split and pilot rows (sealed AAD v2.1 freeze included) excluded"),
            "by_policy": dict(sorted(by_policy.items())), "by_cell": dict(sorted(by_cell.items())),
            "by_verdict": dict(sorted(by_verdict.items())), "by_source": dict(sorted(by_source.items()))}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(json.dumps(build(Path(sys.argv[1]), Path(sys.argv[2])), sort_keys=True))
