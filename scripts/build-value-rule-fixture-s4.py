"""Build the v3.9.1 stage-4 subset using the shared origin and split checks.

Usage: build-value-rule-fixture-s4.py SOURCE.jsonl OUTPUT.jsonl.xz
Writes manifest-s4.json alongside OUTPUT; never publishes held-out pilot rows.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

POLICIES = {"MS.EXO.3.1v1", "MS.EXO.4.1v1", "MS.EXO.4.2v1", "MS.EXO.4.3v1", "MS.EXO.4.4v1",
            "MS.SECURITYSUITE.6.1v1", "MS.SECURITYSUITE.6.2v1", "MS.SECURITYSUITE.7.1v1",
            "MS.SECURITYSUITE.7.2v1", "MS.SECURITYSUITE.7.3v1"}


def build(source: Path, target: Path) -> dict:
    spec = importlib.util.spec_from_file_location("value_rule_fixture", Path(__file__).with_name(
        "build-value-rule-fixture.py"))
    shared = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shared)
    manifest = shared.build_v3(source, target, policies=POLICIES)
    # stage 4: this subset adopts v3.9.1; the other stages retain their pinned version.
    manifest["spec_version"] = "v3.9.1"
    target.with_name("manifest-s4.json").write_text(
        json.dumps({target.name: manifest}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(json.dumps(build(Path(sys.argv[1]), Path(sys.argv[2])), sort_keys=True))
