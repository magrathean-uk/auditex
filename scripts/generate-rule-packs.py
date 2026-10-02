#!/usr/bin/env python3
"""Regenerate the ``packs`` block of configs/rule-packs.json.

Packs are derived from configs/finding-templates.json, configs/control-mappings.json
and the Google Workspace rule mappings. Curated ``rules`` overrides in the same
file are kept as they are. Run after adding a rule or changing its mappings:

    python3 scripts/generate-rule-packs.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from auditex.rules import build_rule_packs  # noqa: E402


def main() -> int:
    path = REPO / "configs" / "rule-packs.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["packs"] = build_rule_packs()
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(payload['packs'])} packs to {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
