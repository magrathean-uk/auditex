#!/usr/bin/env python3
"""Regenerate only the explainer template from explicit offline JSON inputs.

Run using the repository venv. Baseline and collection JSON are product-owned
inputs; this command never creates or overwrites them. --check writes nothing.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from azure_tenant_audit.explainer import generate_template  # noqa: E402
from azure_tenant_audit.explainer.textkit import canonical, compact_template  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalogue", type=Path, default=Path("configs/scuba-value-rules.json"))
    parser.add_argument("--baselines", type=Path, default=Path("configs/explainer-baselines.json"))
    parser.add_argument("--collection", type=Path, default=Path("configs/explainer-what-to-collect.json"))
    parser.add_argument("--output", type=Path, default=Path("configs/explainer-template.json"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    inputs = (args.catalogue, args.baselines, args.collection)
    if args.output.resolve() in {p.resolve() for p in inputs}:
        parser.error("output must not overwrite an input")
    try:
        data = generate_template(*(json.loads(p.read_text(encoding="utf-8")) for p in inputs))
        result = (canonical(compact_template(data)) + "\n").encode()
        if args.check:
            if args.output.read_bytes() != result:
                parser.exit(1, "explainer template drift; regenerate after reviewing inputs\n")
        else:
            args.output.write_bytes(result)
    except (ValueError, KeyError, OSError) as exc:
        parser.exit(1, f"template generation failed: {exc}\n")


if __name__ == "__main__":
    main()
