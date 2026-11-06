#!/usr/bin/env python3
"""Assess a local ScubaGear export; internal, experimental; not part of the public CLI."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from azure_tenant_audit.argument_parser import build_argument_parser  # noqa: E402

from auditex.model_serving import assess_scubagear_export  # noqa: E402


def main() -> int:
    parser = build_argument_parser(description=__doc__)
    parser.add_argument("export", metavar="EXPORT")
    parser.add_argument("--output-dir", required=True, metavar="DIR")
    parser.add_argument("--results", metavar="FILE")
    parser.add_argument("--policies", metavar="ID,ID")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-redaction", help=argparse.SUPPRESS, action="store_true")
    parser.add_argument("--projection-max-items", type=int, default=40, metavar="N")
    parser.add_argument("--projection-max-chars", type=int, default=12000, metavar="N")
    parser.add_argument("--endpoint", help=argparse.SUPPRESS, metavar="URL")
    parser.add_argument("--model", help=argparse.SUPPRESS, metavar="NAME")
    args = parser.parse_args()
    try:
        result = assess_scubagear_export(
            args.export, args.output_dir, results_path=args.results,
            legacy_options=(args.endpoint is not None or args.model is not None),
            policies=args.policies.split(",") if args.policies else None,
            dry_run=args.dry_run, no_redaction=args.no_redaction,
            projection_max_items=args.projection_max_items, projection_max_chars=args.projection_max_chars)
        sidecar_path = Path(args.output_dir).expanduser() / "scubagear_adapter_report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        print(f"ScubaGear assessment failed: {exc}", file=sys.stderr)
        return 2
    ceiling = sidecar["ceiling"]
    print(json.dumps({"assessment_path": result["path"] if args.dry_run else str(sidecar_path.parent /
                      "model_assessment.json"), "sidecar_path": str(sidecar_path),
                      "verdict_state": sidecar["verdicts"]["state"], "total": ceiling["overall"]["total"],
                      "assessed": ceiling["overall"]["assessed"],
                      "withheld": ceiling["overall"]["total"] - ceiling["overall"]["assessed"],
                      "ceiling": ceiling}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
