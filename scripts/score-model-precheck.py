#!/usr/bin/env python3
"""Score the product rule pre-check locally; never loads or calls a model."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from auditex.model_precheck import evaluate_precheck  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", required=True, help="Frozen oracle cases JSONL, e.g. test-v7.")
    parser.add_argument("--responses", help="Optional case_id/model_id/response JSONL from the checkpoint scorer.")
    args = parser.parse_args()
    try:
        report = evaluate_precheck(args.cases, args.responses)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"Pre-check evaluation failed: {exc}\n")
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
