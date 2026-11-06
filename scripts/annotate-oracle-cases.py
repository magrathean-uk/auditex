#!/usr/bin/env python3
"""Render enum names in existing oracle prompts without changing case identity or labels.

Set prompt_convention on every row; recompute distinct_prompt_sha256 where present
and add it where absent. Rows use the miner's JSONL encoding; unchanged prompts
with current provenance retain byte-identical lines.
"""
from __future__ import annotations

import copy
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from azure_tenant_audit.argument_parser import build_argument_parser  # noqa: E402

from auditex.model_training import _outside_audit_runs, distinct_prompt_sha256, load_cases, validate_cases  # noqa: E402
from azure_tenant_audit.external_sharing import annotate_enum_names  # noqa: E402


def canonical(value: Any) -> str:
    """The miner's prompt encoding; kept in agreement by test_oracle_cases."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def only_name_keys_added(before: Any, after: Any) -> bool:
    """True if JSON values differ only by added string-valued *_name object keys.

    Equality is allowed. Existing values, key presence, list order and scalar
    types must be preserved, including the distinction between bool and int.
    """
    if type(before) is not type(after):
        return False
    if isinstance(before, dict):
        return (before.keys() <= after.keys()
                and all(isinstance(key, str) and key.endswith("_name") and isinstance(after[key], str)
                        for key in after.keys() - before.keys())
                and all(only_name_keys_added(value, after[key]) for key, value in before.items()))
    if isinstance(before, list):
        return len(before) == len(after) and all(only_name_keys_added(a, b) for a, b in zip(before, after))
    return before == after


def _added_name_keys(before: Any, after: Any) -> Counter:
    added: Counter = Counter()
    if isinstance(before, dict):
        added.update(after.keys() - before.keys())
        for key in before:
            added.update(_added_name_keys(before[key], after[key]))
    elif isinstance(before, list):
        for a, b in zip(before, after):
            added.update(_added_name_keys(a, b))
    return added


def annotate_cases(cases: list[dict]) -> tuple[list[dict], dict]:
    """Copy, annotate and validate all rows before any output file is created."""
    result = copy.deepcopy(cases)
    keys_added: Counter = Counter()
    rows_changed = 0
    digests_added = 0
    for case in result:
        messages = case["messages"]
        if len(messages) < 3 or messages[1]["role"] != "user":
            raise ValueError(f"case {case['id']}: messages[1] must be the JSON user message")
        try:
            before = json.loads(messages[1]["content"])
        except ValueError as exc:
            raise ValueError(f"case {case['id']}: user message must be JSON") from exc
        if not isinstance(before, dict) or not isinstance(before.get("evidence"), list):
            raise ValueError(f"case {case['id']}: user message requires an evidence list")
        after = copy.deepcopy(before)
        for item in after["evidence"]:
            if not isinstance(item, dict):
                raise ValueError(f"case {case['id']}: evidence items must be objects")
            if "section" in item:
                if "observed" not in item:
                    raise ValueError(f"case {case['id']}: section evidence requires observed")
                item["observed"] = annotate_enum_names(item["section"], item["observed"])
        if not only_name_keys_added(before, after):
            raise ValueError(f"case {case['id']}: annotation would change existing values; only added *_name keys are allowed")
        if before != after:
            messages[1]["content"] = canonical(after)
            rows_changed += 1
            keys_added.update(_added_name_keys(before, after))
        # Preserve the exact original user bytes when no annotation was added.
        digests_added += "distinct_prompt_sha256" not in case["provenance"]
        case["provenance"]["distinct_prompt_sha256"] = distinct_prompt_sha256(case)
        case["provenance"]["prompt_convention"] = "named-enums-v1"
    result = validate_cases(result)
    return result, {"rows": len(result), "rows_changed": rows_changed,
                    "digests_added": digests_added, "prompt_convention_set": len(result),
                    "keys_added": dict(sorted(keys_added.items())), "unchanged_rows": len(result) - rows_changed}


def write_outputs(output: Path, report_path: Path | None, cases: list[dict], report: dict) -> None:
    """Create private files exclusively, rolling back only files created here on error."""
    for path in (output, report_path):
        if path is not None:
            _outside_audit_runs(path)
    # Encode every payload before creating either file, including the report.
    payloads = [(output, "".join(json.dumps(case, ensure_ascii=False) + "\n" for case in cases).encode("utf-8"))]
    if report_path is not None:
        payloads.append((report_path, (canonical(report) + "\n").encode("utf-8")))
    created: list[Path] = []
    try:
        for path, payload in payloads:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        cases, report = annotate_cases(load_cases(args.input))
        write_outputs(args.output, args.report, cases, report)
    except (OSError, ValueError) as exc:
        print(f"annotate-oracle-cases: {exc}", file=sys.stderr)
        return 1
    print(canonical(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
