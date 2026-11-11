#!/usr/bin/env python3
"""Regenerate only the explainer template from explicit offline JSON inputs.

Run using the repository venv. Baseline and collection JSON are product-owned
inputs; this command never creates or overwrites them. --check writes nothing.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from azure_tenant_audit.argument_parser import build_argument_parser  # noqa: E402
from azure_tenant_audit.explainer import generate_template  # noqa: E402
from azure_tenant_audit.explainer.textkit import canonical, compact_template  # noqa: E402


def main():
    parser = build_argument_parser(description=__doc__)
    parser.add_argument("--catalogue", type=Path, default=Path("configs/scuba-value-rules.json"))
    parser.add_argument("--baselines", type=Path, default=Path("configs/explainer-baselines.json"))
    parser.add_argument("--collection", type=Path, default=Path("configs/explainer-what-to-collect.json"))
    parser.add_argument("--output", type=Path, default=Path("configs/explainer-template.json"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    inputs = (args.catalogue, args.baselines, args.collection)
    if args.output.resolve() in {p.resolve() for p in inputs}:
        parser.print_usage(sys.stderr)
        print("error: output must not overwrite an input", file=sys.stderr)
        return 2
    try:
        data = generate_template(*(json.loads(p.read_text(encoding="utf-8")) for p in inputs))
        result = (canonical(compact_template(data)) + "\n").encode()
        if args.check:
            if args.output.read_bytes() != result:
                print("explainer template drift; regenerate after reviewing inputs", file=sys.stderr)
                return 1
        else:
            args.output.write_bytes(result)
    except (ValueError, KeyError, OSError) as exc:
        print(f"template generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
