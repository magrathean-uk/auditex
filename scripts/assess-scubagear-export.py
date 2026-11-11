#!/usr/bin/env python3
"""Assess a local ScubaGear export; internal, experimental; not part of the public CLI."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from auditex.rule_assessment import assess_scubagear_export  # noqa: E402
from azure_tenant_audit.argument_parser import build_argument_parser  # noqa: E402


def main() -> int:
    parser = build_argument_parser(description=__doc__)
    parser.add_argument("export", metavar="EXPORT")
    parser.add_argument("--output-dir", required=True, metavar="DIR")
    parser.add_argument("--results", metavar="FILE")
    parser.add_argument("--policies", metavar="ID,ID")
    parser.add_argument("--projection-max-items", type=int, default=40, metavar="N")
    parser.add_argument("--projection-max-chars", type=int, default=12000, metavar="N")
    args = parser.parse_args()
    try:
        assess_scubagear_export(
            args.export, args.output_dir, results_path=args.results,
            policies=args.policies.split(",") if args.policies else None,
            projection_max_items=args.projection_max_items, projection_max_chars=args.projection_max_chars)
        sidecar_path = Path(args.output_dir).expanduser() / "scubagear_adapter_report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        print(f"ScubaGear assessment failed: {exc}", file=sys.stderr)
        return 2
    ceiling = sidecar["ceiling"]
    print(json.dumps({"assessment_path": str(sidecar_path.parent / "model_assessment.json"), "sidecar_path": str(sidecar_path),
                      "verdict_state": sidecar["verdicts"]["state"], "total": ceiling["overall"]["total"],
                      "assessed": ceiling["overall"]["assessed"],
                      "withheld": ceiling["overall"]["total"] - ceiling["overall"]["assessed"],
                      "ceiling": ceiling}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
