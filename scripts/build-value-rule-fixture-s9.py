"""Build the stage-9 AAD pilot fixture using the shared origin/split filter.

Usage: build-value-rule-fixture-s9.py SOURCE.jsonl OUTPUT.jsonl.xz
Prints the manifest entry to stdout. No held-out rows are retained.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from hashlib import sha256
from pathlib import Path

POLICIES = frozenset("MS.AAD." + number for number in
                     ("3.3v2", "3.5v2", "5.2v1", "5.3v1", "5.5v1", "5.6v1", "5.7v1", "6.1v1"))


def build(source: Path, target: Path) -> dict:
    spec = importlib.util.spec_from_file_location("shared_fixture", Path(__file__).with_name("build-value-rule-fixture.py"))
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    # v3.9.1 adds constructed final-review probes; the shared filter still owns exclusions.
    shared.V3_CONSTRUCTED.add("constructed by v391_vectors.py")
    source_hash = sha256()
    # Filter policies only; the shared builder enforces origin, split and gold.
    with tempfile.TemporaryDirectory(prefix="auditex-value-s9-") as scratch:
        subset = Path(scratch) / "aad-pilot.jsonl"
        with source.open("rb") as incoming, subset.open("wb") as outgoing:
            for raw in incoming:
                source_hash.update(raw)
                if json.loads(raw)["policy"] in POLICIES:
                    outgoing.write(raw)
        manifest = shared.build_v3(subset, target, policies=POLICIES)
    manifest["policy_subset_sha256"] = manifest["source_sha256"]
    manifest["source_sha256"] = source_hash.hexdigest()
    manifest["stage"] = 9
    manifest["spec_version"] = "v3.9.1"
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    target = Path(sys.argv[2])
    print(json.dumps({target.name: build(Path(sys.argv[1]), target)}, indent=2, sort_keys=True))
