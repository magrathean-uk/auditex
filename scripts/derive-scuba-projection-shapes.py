#!/usr/bin/env python3
"""Derive the complete-shape goldens of the ScubaGear-shaped evidence projection from a training pack.

The shape gate of `auditex.scuba_projection` sends a section to the model only when its whole shape was seen in the pack the pinned model
was trained on (PACK_SHAPE_DIGESTS) and every enum value of a gated field was seen too (PACK_ENUM_DOMAINS). This script is the one derivation
of those goldens: it reads the evidence sections of `train.jsonl` and `test.jsonl` of a pack (the files the v7 fixture was derived from;
`--files` names others), reduces each non-policy section to its structural shape and writes the fixture.

A shape keeps whole-object keys, nesting and scalar types, never the values. List cardinality is ignored, empty and populated lists stay
distinct and the distinct item shapes of a list are kept as a sorted set; numbered `User<N>` collections keep every distinct item shape.
Derived SharePoint enum names (`<Key>_name`) are removed first: they are added only when a prompt is assembled. Only the values of the
fields in PACK_ENUM_FIELDS are kept, as the enum domains. A not-collected marker is no shape. Each shape carries a witness: the first
file, line and evidence id that holds it.

    scripts/derive-scuba-projection-shapes.py --pack PACK_DIR --output FILE [--baseline FIXTURE --diff-output FILE]

The output file must not exist. With `--baseline` the shapes and enum values the pack adds to (or lacks from) the baseline fixture are
counted per section and written to `--diff-output`. The fixture in the repository is never replaced by this script; the shipped gate
follows the model actually pinned, and replacing it is a deliberate change of PACK_SHAPE_DIGESTS and PACK_ENUM_DOMAINS.
"""
from __future__ import annotations

import argparse
import json
import sys
from hashlib import sha256
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from azure_tenant_audit.argument_parser import build_argument_parser  # noqa: E402

from auditex.model_serving import canonical, policy_catalogue  # noqa: E402
from azure_tenant_audit.external_sharing import ENUM_NAME_KEYS  # noqa: E402
from azure_tenant_audit.model_evidence import NOT_COLLECTED  # noqa: E402

PACK_ENUM_FIELDS = frozenset({
    "State", "Operator", "BuiltInControls", "ClientAppTypes", "SignInRiskLevels", "UserRiskLevels",
    "AgentIdRiskLevels", "TransferMethods", "MembershipKind", "GuestOrExternalUserTypes", "AllowInvitesFrom",
    "AutoAdmittedUsers", "NotificationType", "RuleSourceType", "SharingCapability", "ODBSharingCapability",
    "DefaultLinkPermission", "DefaultSharingLinkType", "FileAnonymousLinkType", "FolderAnonymousLinkType",
    "SharingDomainRestrictionMode", "M365Environment", "IncludeUserActions", "AllowedCombinations",
})
DEFAULT_FILES = ("train.jsonl", "test.jsonl")
CANONICALISATION = ("whole-section-v1; list cardinality ignored; empty/populated lists distinct; UserN collections preserve all item shapes; "
                    "derived SharePoint enum names removed")


def derive(pack: Path, filenames: tuple[str, ...] = DEFAULT_FILES) -> dict:
    """Reconstruct complete shape witnesses directly from the pack's JSONL files (read only).

    Array entries are canonical JSON strings of complete item shapes, sorted and deduplicated. This preserves nested shape combinations
    without binding lengths. No evidence values are retained except the explicitly named enum domains."""
    sections = {s: {} for row in policy_catalogue()["policies"].values() for s in row["sections"]}
    domains = {s: {} for s in sections}
    witnesses = {s: {} for s in sections}

    def strip_names(value):
        if isinstance(value, dict):
            return {k: strip_names(v) for k, v in value.items() if k not in {f"{n}_name" for n in ENUM_NAME_KEYS}}
        if isinstance(value, list):
            return [strip_names(v) for v in value]
        return value

    def shape(value):
        if isinstance(value, dict):
            if value and all(k.startswith("User") and k[4:].isdigit() for k in value):
                return {"users": sorted({canonical(shape(v)) for v in value.values()})}
            return {"object": {k: shape(v) for k, v in value.items()}}
        if isinstance(value, list):
            return {"array": sorted({canonical(shape(v)) for v in value})}
        return type(value).__name__

    def enums(value, section, path=""):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in PACK_ENUM_FIELDS:
                    domains[section].setdefault(path + "." + key, set()).update(
                        canonical(v) for v in (child if isinstance(child, list) else [child]))
                enums(child, section, path + "." + key)
        elif isinstance(value, list):
            for child in value:
                enums(child, section, path + "[]")

    source_files = {}
    for filename in filenames:
        path = Path(pack) / filename
        digest = sha256()
        count = 0
        with path.open("rb") as handle:
            for count, line in enumerate(handle, 1):
                digest.update(line)
                row = json.loads(line)
                for message in row.get("messages", row.get("prompt", [])):
                    if message["role"] != "user":
                        continue
                    for evidence in json.loads(message["content"]).get("evidence", [])[1:]:
                        section = evidence.get("section")
                        if section not in sections or evidence["observed"] == NOT_COLLECTED:
                            continue
                        value = strip_names(evidence["observed"])
                        structural = shape(value)
                        encoded = canonical(structural)
                        sections[section][encoded] = structural
                        witnesses[section].setdefault(sha256(encoded.encode()).hexdigest(), {
                            "file": filename, "line": count, "evidence_id": evidence["id"]})
                        enums(value, section)
        source_files[filename] = {"sha256": digest.hexdigest(), "rows": count}
    return {
        "canonicalisation": CANONICALISATION,
        "source_files": source_files,
        "sections": {s: [variants[k] for k in sorted(variants)] for s, variants in sorted(sections.items())},
        "enum_domains": {s: {p: sorted(values) for p, values in sorted(paths.items())} for s, paths in sorted(domains.items())},
        "witnesses": witnesses,
    }


def shape_digests(golden: dict) -> dict[str, set[str]]:
    """The set of shape digests per section, as PACK_SHAPE_DIGESTS stores them."""
    return {s: {sha256(canonical(v).encode()).hexdigest() for v in shapes} for s, shapes in golden["sections"].items()}


def compare(baseline: dict, golden: dict) -> dict:
    """Per section: shapes and enum values the golden adds to the baseline, and those it lacks."""
    old, new = shape_digests(baseline), shape_digests(golden)
    sections = {}
    for section in sorted(set(old) | set(new)):
        before, after = old.get(section, set()), new.get(section, set())
        domains_before = baseline["enum_domains"].get(section, {})
        domains_after = golden["enum_domains"].get(section, {})
        added_values = {path: sorted(set(values) - set(domains_before.get(path, ())))
                        for path, values in domains_after.items() if set(values) - set(domains_before.get(path, ()))}
        lost_values = {path: sorted(set(values) - set(domains_after.get(path, ())))
                       for path, values in domains_before.items() if set(values) - set(domains_after.get(path, ()))}
        sections[section] = {"shapes_before": len(before), "shapes_after": len(after), "shapes_added": len(after - before),
                             "shapes_removed": len(before - after), "added_shape_digests": sorted(after - before),
                             "enum_values_added": added_values, "enum_values_removed": lost_values}
    return {"sections": sections,
            "total_shapes_added": sum(s["shapes_added"] for s in sections.values()),
            "total_shapes_removed": sum(s["shapes_removed"] for s in sections.values()),
            "sections_with_added_shapes": sorted(s for s, v in sections.items() if v["shapes_added"]),
            "sections_with_added_enum_values": sorted(s for s, v in sections.items() if v["enum_values_added"])}


def _write_new(path: Path, payload: dict) -> None:
    with path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pack", type=Path, required=True, help="training pack directory holding the JSONL files (read only)")
    parser.add_argument("--output", type=Path, required=True, help="new fixture file; an existing one is refused")
    parser.add_argument("--files", nargs="+", default=list(DEFAULT_FILES), help=f"pack files to read (default: {' '.join(DEFAULT_FILES)})")
    parser.add_argument("--baseline", type=Path, help="fixture to compare with, for example tests/fixtures/scuba-projection-shapes-v7.json")
    parser.add_argument("--diff-output", type=Path, help="new file for the comparison with --baseline")
    args = parser.parse_args(argv)
    if bool(args.baseline) != bool(args.diff_output):
        parser.error("--baseline and --diff-output go together")
    for path in (args.output, args.diff_output):
        if path is not None and (path.exists() or path.is_symlink()):
            print(f"error: refusing to overwrite {path}", file=sys.stderr)
            return 2
    golden = derive(args.pack, tuple(args.files))
    _write_new(args.output, golden)
    summary = {"output": str(args.output), "source_files": golden["source_files"],
               "shapes_per_section": {s: len(v) for s, v in golden["sections"].items() if v}}
    if args.baseline:
        report = compare(json.loads(args.baseline.read_text(encoding="utf-8")), golden)
        _write_new(args.diff_output, report)
        summary["total_shapes_added"] = report["total_shapes_added"]
        summary["sections_with_added_shapes"] = report["sections_with_added_shapes"]
        summary["sections_with_added_enum_values"] = report["sections_with_added_enum_values"]
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
