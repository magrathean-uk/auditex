#!/usr/bin/env python3
"""Generate vendored public baseline data from an explicitly pinned checkout.

Use the repo venv Python. No checkout path is embedded in the generated data;
runtime consumes only configs/explainer-baselines.json. No network is used.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# -I deliberately ignores editable installs/PYTHONPATH; import this worktree.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from azure_tenant_audit.argument_parser import build_argument_parser  # noqa: E402
from azure_tenant_audit.explainer.baselines import SOURCE_COMMIT, build_baselines  # noqa: E402


def generate_baselines(checkout: Path) -> dict:
    """Verify HEAD and every input against its committed bytes, then extract."""
    checkout = Path(checkout).resolve(strict=True)
    head = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()
    if head != SOURCE_COMMIT:
        raise ValueError(f"ScubaGear must be at {SOURCE_COMMIT}")

    def read_text(relative_path: str) -> str:
        committed = subprocess.run(
            ["git", "-C", str(checkout), "show", f"{SOURCE_COMMIT}:{relative_path}"],
            check=True, capture_output=True,
        ).stdout
        actual = (checkout / relative_path).read_bytes()
        if actual != committed:
            raise ValueError(f"ScubaGear input differs from pinned commit: {relative_path}")
        return actual.decode("utf-8")

    return build_baselines(read_text)


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser(description=__doc__)
    parser.add_argument("--checkout", required=True, type=Path, help="ScubaGear checkout at the full pinned commit")
    parser.add_argument("--output", type=Path, help="write JSON here; default: stdout")
    args = parser.parse_args(argv)
    index = generate_baselines(args.checkout)
    output = json.dumps(index, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
    if args.output is None:
        sys.stdout.write(output)
    else:
        args.output.write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
