#!/usr/bin/env python3
"""Regenerate the ``packs`` block of configs/rule-packs.json.

Packs are derived from configs/finding-templates.json, configs/control-mappings.json
and the Google Workspace rule mappings. Curated ``rules`` overrides in the same
file are kept as they are. Run after adding a rule or changing its mappings:

    python3 scripts/generate-rule-packs.py

``--check`` writes nothing and exits 1 when the committed packs differ from the
generated ones (used by ``make release-check``).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from auditex.rules import build_rule_packs, list_rule_packs  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if configs/rule-packs.json is stale; write nothing")
    args = parser.parse_args(argv)

    path = REPO / "configs" / "rule-packs.json"
    if args.check:
        expected = sorted(build_rule_packs(), key=lambda row: row["name"])
        if list_rule_packs() != expected:
            print("configs/rule-packs.json is stale; run python3 scripts/generate-rule-packs.py", file=sys.stderr)
            return 1
        print(f"rule packs up to date ({len(expected)} packs)")
        return 0
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["packs"] = build_rule_packs()
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(payload['packs'])} packs to {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
