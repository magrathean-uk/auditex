#!/usr/bin/env python3
"""Assign train/validation/test splits to oracle-labelled cases, drop prompt duplicates and write a split report.

Input is the `cases.jsonl` of scripts/build-oracle-cases.py. A split atom is a whole policy group (the case
`family`, one CISA policy group each, `scuba-<product>-<group>`) joined with every reasoning template
(`provenance.template`) that touches it, so neither a family nor a template ever appears in two splits. Per
product the atoms are sorted by name: the last becomes test, the one before it validation, the rest train, so every
product with three or more atoms contributes to every split; products with fewer stay in train. Nothing here
changes a label.

`--sub-family POLICY_ID=FAMILY` moves a policy into its own family within the same product before deduplication
and atom construction. Repeat it for several policies; the report records the original family and input row count.
The CLI requires `--previous-report`. A target must differ from every original family, start with
`<from_family>-` for every original family, with a suffix matching `[a-z0-9]+(?:[.-][a-z0-9]+)*`.
This keeps a sub-family immediately after its source in the atom ordering rather than after the test atom.

Before splitting, cases that share a `provenance.distinct_prompt_sha256` (the id-masked normalized prompt, which
the validator treats as one example) are reduced to the first occurrence. The digest is recomputed from the case;
a stale stored digest, or duplicates whose answers differ (claim order and evidence-id order do not count), are
errors.

`--approve-as-oracle` records the deterministic oracle as reviewer (review_status approved, reviewer
`oracle:cisa-scubagear@<commit>/opa-<version>; deterministic policy evaluation, no human review`, with the
12-character commit the miner records) so that `auditex model prepare` accepts the rows. It is a labelling
convention, not a human review, and it is strict: a case is approved only if its source matches the miner's
`oracle:cisa-scubagear@<hex commit> ...; opa=<x.y.z>; ...` form, it is `synthetic: true` and it names no reviewer
yet. Anything else is an error. Cases that are already approved are left untouched.

`split-oracle-cases.py` writes a new JSONL and `split-report.json` (counts, families and templates per split,
distinct counts, an independent leakage check and the SHA-256 of the test split, the frozen holdout hash). Files
are created exclusively with mode 0600 (parent directories 0700); an existing file, a symlink, the same path for
both outputs, or a location inside a finalized audit run is refused.
`--previous-report` checks the test-ID hash before writing either output. Reports include sorted test_ids for
membership-change diagnostics; older hash-only reports enforce the same invariant without departed-ID details.
When previous split families are available, existing families may change splits only when explicitly named by
`--validation-families` or `--holdout-families`; family_split_changes records those moves. Removed families
must be named by those options or a `--sub-family` target; families_removed and families_added record membership.
test_sha256_previous and test_content_frozen report content equality; changed test content is allowed.
Previous-run comparison fields are null until checked against `--previous-report`.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from azure_tenant_audit.argument_parser import build_argument_parser  # noqa: E402

from auditex.model_training import _answer_key, _outside_audit_runs, distinct_prompt_sha256, load_cases, validate_cases  # noqa: E402

SPLITS = ("train", "validation", "test")
ORACLE_SOURCE = re.compile(r"oracle:cisa-scubagear@([0-9a-f]{12,40}) ")
OPA_VERSION = re.compile(r"; opa=(\d+\.\d+\.\d+);")
ORACLE_FAMILY = re.compile(r"scuba-[a-z0-9]+-[a-z0-9]+(?:[.-][a-z0-9]+)*")


def product_of(family: str) -> str:
    if not ORACLE_FAMILY.fullmatch(family):
        raise ValueError(f"not an oracle family (expected scuba-<product>-<group>): {family}")
    return family.split("-")[1]


def oracle_reviewer(source: str) -> str:
    """The reviewer string for a miner source `oracle:cisa-scubagear@<commit> ...; opa=<x.y.z>; ...`; anything else is refused."""
    head, version = ORACLE_SOURCE.match(source), OPA_VERSION.search(source)
    if not head or not version:
        raise ValueError("refusing to approve a case whose source is not a ScubaGear oracle source "
                         f"(expected 'oracle:cisa-scubagear@<hex commit> ...; opa=<x.y.z>; ...'): {source[:80]!r}")
    return f"oracle:cisa-scubagear@{head.group(1)}/opa-{version.group(1)}; deterministic policy evaluation, no human review"


def prompt_digest(case: dict) -> str:
    """The case's distinct_prompt_sha256, recomputed; a stored digest that disagrees is an error."""
    digest = distinct_prompt_sha256(case)
    stored = case["provenance"].get("distinct_prompt_sha256")
    if stored is not None and stored != digest:
        raise ValueError(f"stale distinct_prompt_sha256 on case {case['id']}")
    return digest


def dedupe(cases: list[dict]) -> tuple[list[dict], list[dict[str, str]]]:
    """Keep the first case of each distinct prompt; duplicates with a different answer are an error."""
    kept: dict[str, dict] = {}
    dropped: list[dict[str, str]] = []
    for case in cases:
        digest = prompt_digest(case)
        first = kept.get(digest)
        if first is None:
            kept[digest] = case
            continue
        if _answer_key(case, mask_id=True) != _answer_key(first, mask_id=True):
            raise ValueError(f"duplicate prompt with conflicting labels: {case['id']} vs {first['id']}")
        dropped.append({"dropped": case["id"], "kept": first["id"]})
    return list(kept.values()), dropped


def apply_sub_families(cases: list[dict], sub_families: Mapping[str, str]) -> dict:
    """Relabel policy rows before deduplication and atom construction; count input rows.

    from_family is a name, or a sorted list if a policy already spans several families.
    Targets must match ORACLE_FAMILY and start with each original family's name plus '-'
    followed by a suffix matching [a-z0-9]+(?:[.-][a-z0-9]+)*.
    All assignments are checked against the original families before any rows change.
    """
    if not sub_families:
        return {}
    by_policy: dict[str, list[dict]] = defaultdict(list)
    family_policies: dict[str, set[str]] = defaultdict(set)
    for case in cases:
        try:
            policy = json.loads(case["messages"][1]["content"])["policy_id"]
            if not isinstance(policy, str) or not policy:
                raise ValueError("policy_id must be non-empty text")
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"case {case.get('id')!r} requires oracle user-message JSON with policy_id") from exc
        by_policy[policy].append(case)
        family_policies[case["family"]].add(policy)
    report = {}
    targets: dict[str, str] = {}
    for policy, family in sub_families.items():
        product = product_of(family)
        rows = by_policy.get(policy, [])
        if not rows:
            raise ValueError(f"unknown policy for sub-family: {policy}")
        previous = sorted({case["family"] for case in rows})
        if any(product_of(old) != product for old in previous):
            raise ValueError(f"sub-family {family} has the wrong product for policy {policy} in {previous}")
        if family in previous:
            raise ValueError(f"no-op sub-family mapping for policy {policy}: {family}")
        if family_policies.get(family, set()) - {policy} or targets.setdefault(family, policy) != policy:
            raise ValueError(f"sub-family collision: {family} is used by another policy")
        if any(not family.startswith(f"{old}-") for old in previous):
            raise ValueError(f"sub-family {family} must start with <from_family>- for every source family: {previous}")
        report[policy] = {"family": family, "from_family": previous[0] if len(previous) == 1 else previous,
                          "rows": len(rows)}
    for policy, family in sub_families.items():
        for case in by_policy[policy]:
            case["family"] = family
    return report


def split_atoms(cases: list[dict]) -> dict[str, str]:
    """Map each family to its atom (the smallest family name in its family/template component)."""
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        parent.setdefault(node, node)
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    for case in cases:
        family = f"family:{case['family']}"
        find(family)
        template = case["provenance"].get("template")
        if template:
            parent[find(family)] = find(f"template:{template}")
    groups: dict[str, list[str]] = defaultdict(list)
    for case in cases:
        groups[find(f"family:{case['family']}")].append(case["family"])
    return {family: min(members) for members in groups.values() for family in members}


def assign_splits(cases: list[dict], holdout_families: Iterable[str] = (), validation_families: Iterable[str] = ()) -> dict[str, str]:
    """Map each family to its split; a family inherits the split of its whole atom."""
    atom_of = split_atoms(cases)
    atom_split: dict[str, str] = {}
    by_product: dict[str, list[str]] = defaultdict(list)
    for atom in sorted(set(atom_of.values())):
        by_product[product_of(atom)].append(atom)
    for atoms in by_product.values():
        if len(atoms) >= 3:
            atom_split[atoms[-1]] = "test"
            atom_split[atoms[-2]] = "validation"
        for atom in atoms:
            atom_split.setdefault(atom, "train")
    chosen: dict[str, str] = {}
    for split, families in (("test", holdout_families), ("validation", validation_families)):
        for family in families:
            if family not in atom_of:
                raise ValueError(f"unknown family: {family}")
            atom = atom_of[family]
            if chosen.setdefault(atom, split) != split:
                raise ValueError(f"family {family} (atom {atom}) is assigned to both test and validation")
            atom_split[atom] = split
    return {family: atom_split[atom] for family, atom in atom_of.items()}


def label_of(case: dict) -> str:
    for claim in case["expected"]["claims"]:
        if claim["id"] == "requirement_met":
            return "unknown" if claim["status"] == "unknown" else json.dumps(claim["value"])
    return "no_requirement_met_claim"


def leakage(cases: list[dict], digests: dict[str, str]) -> dict[str, int]:
    """Count families, templates and distinct prompts that appear in more than one split, from the final cases."""
    seen: dict[str, dict[str, set[str]]] = {"families": defaultdict(set), "templates": defaultdict(set), "distinct_prompts": defaultdict(set)}
    for case in cases:
        seen["families"][case["family"]].add(case["split"])
        if case["provenance"].get("template"):
            seen["templates"][case["provenance"]["template"]].add(case["split"])
        seen["distinct_prompts"][digests[case["id"]]].add(case["split"])
    return {f"{kind}_in_multiple_splits": sum(len(splits) > 1 for splits in index.values()) for kind, index in seen.items()}


def jsonl_line(case: dict) -> str:
    return json.dumps(case, ensure_ascii=False) + "\n"


def _test_ids(cases: Iterable[dict]) -> list[str]:
    return sorted(case["id"] for case in cases if case["split"] == "test")


def _test_ids_sha256(ids: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(sorted(ids)).encode("utf-8")).hexdigest()


def _test_sha256(cases: Iterable[dict]) -> str:
    return hashlib.sha256("".join(jsonl_line(case) for case in cases if case["split"] == "test").encode("utf-8")).hexdigest()


def check_frozen_test_ids(cases: Iterable[dict], previous_report: Mapping) -> dict:
    """Check frozen test membership and return fields to merge into a new split report.

    Older hash-only reports can still enforce the invariant, but cannot identify departed IDs.
    New reports include test_ids so failures can show both directions of membership changes.
    Content equality is reported separately and does not enforce frozen prompts.
    """
    cases = list(cases)
    if not isinstance(previous_report, Mapping):
        raise ValueError("previous report must be a JSON object")
    previous_hash = previous_report.get("test_ids_sha256")
    if not isinstance(previous_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", previous_hash):
        raise ValueError("previous report requires a valid test_ids_sha256")
    previous_ids = previous_report.get("test_ids")
    if previous_ids is not None:
        if not isinstance(previous_ids, list) or any(not isinstance(item, str) for item in previous_ids):
            raise ValueError("previous report test_ids must be a list of strings")
        if _test_ids_sha256(previous_ids) != previous_hash:
            raise ValueError("previous report test_ids disagree with test_ids_sha256")
    current_ids = _test_ids(cases)
    if _test_ids_sha256(current_ids) != previous_hash:
        if previous_ids is None:
            previous_splits = previous_report.get("splits")
            previous_test = previous_splits.get("test") if isinstance(previous_splits, Mapping) else None
            previous_count = previous_test.get("cases", "unavailable") if isinstance(previous_test, Mapping) else "unavailable"
            detail = (f"entered/left IDs unavailable (previous report has no test_ids); "
                      f"current test cases: {len(current_ids)}; previous test cases: {previous_count}")
        else:
            entered = sorted(set(current_ids) - set(previous_ids))
            left = sorted(set(previous_ids) - set(current_ids))
            detail = f"entered test ({len(entered)}): {entered[:5]}; left test ({len(left)}): {left[:5]}"
        raise ValueError(f"frozen test IDs changed: {detail}")
    previous_content_hash = previous_report.get("test_sha256")
    return {"test_ids_sha256_previous": previous_hash, "test_ids_frozen": True,
            "test_sha256_previous": previous_content_hash,
            "test_content_frozen": _test_sha256(cases) == previous_content_hash if previous_content_hash is not None else None}


def check_family_split_changes(cases: Iterable[dict], previous_report: Mapping, *,
                               sub_families: Mapping[str, str] | None = None,
                               validation_families: Iterable[str] = (), holdout_families: Iterable[str] = ()) -> dict:
    """Refuse unrequested moves of existing families; return report fields for kit callers.

    Split changes require explicit validation/holdout selection. Removed families require
    acknowledgement via those selections or a sub-family target. New families are allowed.
    Older reports without families are supported.
    """
    if not isinstance(previous_report, Mapping):
        raise ValueError("previous report must be a JSON object")
    splits = previous_report.get("splits", {})
    if not isinstance(splits, Mapping):
        raise ValueError("previous report splits must be a JSON object")
    previous = {}
    for split in SPLITS:
        data = splits.get(split, {})
        if not isinstance(data, Mapping):
            raise ValueError(f"previous report splits.{split} must be a JSON object")
        families = data.get("families", [])
        if not isinstance(families, list) or any(not isinstance(family, str) for family in families):
            raise ValueError(f"previous report splits.{split}.families must be a list of strings")
        for family in families:
            if previous.setdefault(family, split) != split:
                raise ValueError(f"previous report family {family} appears in multiple splits")
    current = {}
    for case in cases:
        family, split = case["family"], case["split"]
        if current.setdefault(family, split) != split:
            raise ValueError(f"family {family} appears in multiple splits")
    changes = [{"family": family, "from_split": previous[family], "to_split": current[family]}
               for family in sorted(previous.keys() & current.keys()) if previous[family] != current[family]]
    removed = sorted(previous.keys() - current.keys())
    added = sorted(current.keys() - previous.keys())
    allowed = set(validation_families) | set(holdout_families)
    acknowledged = allowed | set((sub_families or {}).values())
    unacknowledged = [family for family in removed if family not in acknowledged]
    if unacknowledged:
        raise ValueError(f"families removed without explicit selection: {unacknowledged}")
    refused = [change for change in changes if change["family"] not in allowed]
    if refused:
        raise ValueError(f"family splits changed without explicit selection: {refused}")
    return {"family_split_changes": changes, "families_removed": removed, "families_added": added}


def _taken(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _make_private_dir(path: Path) -> None:
    """Create `path` and any missing parents with mode 0700; an existing directory is left as it is."""
    missing = []
    while not _taken(path):
        missing.append(path)
        path = path.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)


def _private_open(path: Path):
    # Mode 0600 at creation and O_EXCL: never an existing file or symlink, never briefly world-readable.
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8")


def write_outputs(output: Path, report_path: Path, cases: list[dict], report: dict) -> None:
    """Create both files exclusively; if anything fails the files this call created are removed again."""
    _make_private_dir(output.parent)
    _make_private_dir(report_path.parent)
    created: list[Path] = []
    try:
        with _private_open(output) as out_handle:
            created.append(output)
            with _private_open(report_path) as report_handle:
                created.append(report_path)
                out_handle.writelines(jsonl_line(case) for case in cases)
                report_handle.write(json.dumps(report, indent=1, ensure_ascii=False) + "\n")
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def split_cases(cases: list[dict], *, approve_as_oracle: bool = False, holdout_families: Iterable[str] = (),
                validation_families: Iterable[str] = (), sub_families: Mapping[str, str] | None = None) -> tuple[list[dict], dict]:
    """Dedupe, split, optionally approve and validate; returns the cases (input order) and the split report."""
    cases = copy.deepcopy(cases)
    input_count = len(cases)
    relabelled = apply_sub_families(cases, sub_families or {})
    cases, dropped = dedupe(cases)
    split_of = assign_splits(cases, holdout_families, validation_families)
    already_approved = 0
    for case in cases:
        case["split"] = split_of[case["family"]]
        if not approve_as_oracle:
            continue
        provenance = case["provenance"]
        if provenance["review_status"] == "approved":
            already_approved += 1
            continue
        if "reviewer" in provenance:
            raise ValueError(f"refusing to replace the reviewer of unreviewed case {case['id']}")
        if provenance["synthetic"] is not True:
            raise ValueError(f"refusing to approve case {case['id']}: it is not marked synthetic")
        provenance["review_status"] = "approved"
        provenance["reviewer"] = oracle_reviewer(provenance["source"])
    validated = validate_cases(cases)
    digests = {case["id"]: distinct_prompt_sha256(case) for case in validated}
    check = leakage(validated, digests)
    if any(check.values()):
        raise ValueError(f"split leakage: {check}")
    test_ids = _test_ids(validated)
    per_split = {}
    for split in SPLITS:
        rows = [case for case in validated if case["split"] == split]
        templates = {case["provenance"]["template"] for case in rows if case["provenance"].get("template")}
        per_split[split] = {"cases": len(rows), "families": sorted({case["family"] for case in rows}),
                            "distinct_families": len({case["family"] for case in rows}), "distinct_templates": len(templates),
                            "distinct_prompts": len({digests[case["id"]] for case in rows}),
                            "labels": dict(sorted(Counter(label_of(case) for case in rows).items()))}
    report = {
        "input_cases": input_count, "cases": len(validated),
        "duplicates_dropped": {"count": len(dropped), "pairs": dropped},
        "approve_as_oracle": approve_as_oracle, "already_approved_untouched": already_approved,
        "sub_families": relabelled,
        "family_split_changes": None, "families_removed": None, "families_added": None,
        "splits": per_split,
        "per_product": {product: dict(Counter(case["split"] for case in validated if product_of(case["family"]) == product))
                        for product in sorted({product_of(case["family"]) for case in validated})},
        "leakage": check,
        "test_sha256": _test_sha256(validated),
        "test_sha256_previous": None,
        "test_content_frozen": None,
        "test_ids_sha256_previous": None, "test_ids_frozen": None,
        "test_sha256_basis": "SHA-256 of the test cases as written to the output JSONL (UTF-8 lines in output order)",
        "test_ids": test_ids,
        "test_ids_sha256": _test_ids_sha256(test_ids),
    }
    return validated, report


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cases", type=Path, required=True, help="cases.jsonl from build-oracle-cases.py")
    parser.add_argument("--output", type=Path, required=True, help="new JSONL file; an existing one is refused")
    parser.add_argument("--report", type=Path, help="default: split-report.json beside --output; an existing one is refused")
    parser.add_argument("--approve-as-oracle", action="store_true", help="record the oracle as reviewer of unreviewed cases")
    parser.add_argument("--holdout-families", nargs="*", default=[], help="families to put in test (their whole atom moves)")
    parser.add_argument("--validation-families", nargs="*", default=[], help="families to put in validation (their whole atom moves)")
    parser.add_argument("--sub-family", action="append", default=[], metavar="POLICY_ID=FAMILY",
                        help="move a policy into its own family; repeatable; requires --previous-report; "
                             "FAMILY must start with <from_family>- for every source family, with a suffix matching "
                             "[a-z0-9]+(?:[.-][a-z0-9]+)*")
    parser.add_argument("--previous-report", type=Path,
                        help="freeze test IDs and refuse unrequested family split changes; report test content equality")
    args = parser.parse_args(argv)
    report_path = args.report or args.output.with_name("split-report.json")
    if args.output.resolve() == report_path.resolve():
        print("error: --report must be a different file from --output", file=sys.stderr)
        return 2
    for path in (args.output, report_path):
        if _taken(path):
            print(f"error: refusing to overwrite {path}", file=sys.stderr)
            return 2
        try:
            _outside_audit_runs(path)
        except ValueError:
            print(f"error: {path} is inside a finalized audit run; write model-development output elsewhere", file=sys.stderr)
            return 2
    try:
        if args.sub_family and args.previous_report is None:
            raise ValueError("--sub-family requires --previous-report to freeze test membership")
        sub_families = {}
        for assignment in args.sub_family:
            policy, separator, family = assignment.partition("=")
            if not separator or not policy.strip() or not family.strip():
                raise ValueError("--sub-family requires POLICY_ID=FAMILY")
            policy, family = policy.strip(), family.strip()
            if sub_families.setdefault(policy, family) != family:
                raise ValueError(f"conflicting --sub-family assignments for {policy}")
        cases, report = split_cases(load_cases(args.cases), approve_as_oracle=args.approve_as_oracle,
                                    holdout_families=args.holdout_families, validation_families=args.validation_families,
                                    sub_families=sub_families)
        if args.previous_report is not None:
            previous_report = json.loads(args.previous_report.read_text(encoding="utf-8"))
            report.update(check_frozen_test_ids(cases, previous_report))
            report.update(check_family_split_changes(cases, previous_report, sub_families=sub_families,
                                                    validation_families=args.validation_families,
                                                    holdout_families=args.holdout_families))
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    try:
        write_outputs(args.output, report_path, cases, report)
    except OSError as exc:
        print(f"error: could not write the outputs ({type(exc).__name__}: {exc}); nothing was left behind", file=sys.stderr)
        return 2
    print(json.dumps({"cases": report["cases"], "duplicates_dropped": report["duplicates_dropped"]["count"],
                      "splits": {split: report["splits"][split]["cases"] for split in SPLITS},
                      "families": {split: report["splits"][split]["families"] for split in SPLITS},
                      "approve_as_oracle": args.approve_as_oracle, "test_sha256": report["test_sha256"],
                      "output": str(args.output), "report": str(report_path)}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
