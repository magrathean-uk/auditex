"""Build the v3.9 stage-6 fixture using the shared split and provenance checks.

Usage: build-value-rule-fixture-s6.py SOURCE.jsonl OUTPUT.jsonl.xz
The sibling manifest-s6.json records the compressed and source hashes and counts.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

POLICIES = frozenset({
    "MS.SHAREPOINT.1.1v1", "MS.SHAREPOINT.1.2v1", "MS.SHAREPOINT.1.3v1",
    "MS.SHAREPOINT.2.1v1", "MS.SHAREPOINT.2.2v1", "MS.SHAREPOINT.3.1v1",
    "MS.SHAREPOINT.3.2v1", "MS.SHAREPOINT.3.3v2", "MS.AAD.5.1v1",
    "MS.AAD.8.1v1", "MS.AAD.8.2v1", "MS.AAD.7.1v1", "MS.AAD.7.2v1", "MS.AAD.7.3v1",
})


def build(source: Path, target: Path) -> dict:
    spec = importlib.util.spec_from_file_location(
        "shared_value_rule_fixture", Path(__file__).with_name("build-value-rule-fixture.py"))
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    manifest = shared.build_v3(source, target, policies=set(POLICIES))
    target.with_name("manifest-s6.json").write_text(
        json.dumps({target.name: manifest}, sort_keys=True, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(json.dumps(build(Path(sys.argv[1]), Path(sys.argv[2])), sort_keys=True))
