"""Build the stage-8 Power Platform fixture using the shared origin/split filter.

Usage: build-value-rule-fixture-s8.py SOURCE.jsonl OUTPUT.jsonl.xz
Prints the manifest entry to stdout. No held-out rows are retained.
"""
from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys
import tempfile


def build(source: Path, target: Path) -> dict:
    spec = importlib.util.spec_from_file_location("shared_fixture", Path(__file__).with_name("build-value-rule-fixture.py"))
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    source_hash = sha256()
    # Filter policies only; the shared builder enforces origin, split and gold.
    with tempfile.TemporaryDirectory(prefix="auditex-value-s8-") as scratch:
        subset = Path(scratch) / "power-platform.jsonl"
        with source.open("rb") as incoming, subset.open("wb") as outgoing:
            for raw in incoming:
                source_hash.update(raw)
                if json.loads(raw)["policy"].startswith("MS.POWERPLATFORM."):
                    outgoing.write(raw)
        manifest = shared.build_v3(subset, target)
    manifest["policy_subset_sha256"] = manifest["source_sha256"]
    manifest["source_sha256"] = source_hash.hexdigest()
    manifest["stage"] = 8
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    target = Path(sys.argv[2])
    print(json.dumps({target.name: build(Path(sys.argv[1]), target)}, indent=2, sort_keys=True))
