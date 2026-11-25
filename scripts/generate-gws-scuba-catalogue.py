#!/usr/bin/env python3
"""Generate configs/scuba-gws-policy-sections.json from the pinned ScubaGoggles baseline Markdown.

    python3 -I scripts/generate-gws-scuba-catalogue.py --source <checkout> --out <file> [--check] [--partial]

The checkout is untrusted data: this script only reads the 11 Markdown files (never follows links, never runs
anything from it). Run it with ``python3 -I``. It works from the Markdown alone; the per-policy kind assignment
(design section 14) is the table below. Exit codes: 0 ok, 1 drift, 2 bad input.

``--check`` regenerates and compares with ``--out``. ``--partial`` (check only) compares just the Markdown files
present in the source, so a small fixture can be checked; a release check runs without it against the full pin.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

REPO = "https://github.com/cisagov/ScubaGoggles"
TAG = "v1.1.0"
COMMIT = "08a08ce145178582284d81ab1f3625987f3ad66b"
LICENCE = "CC0-1.0"
SCHEMA_VERSION = "2026-11-25"
BASELINE_DIR = "scubagoggles/baselines"
FILES = (
    "assuredcontrols.md calendar.md chat.md classroom.md commoncontrols.md drive.md "
    "gemini.md gmail.md groups.md meet.md sites.md"
).split()
EXPECTED_POLICIES = 138
MAX_TEXT = 400

ID_RE = re.compile(r"^GWS\.[A-Z]+\.\d+\.\d+v1$")
HEADING_RE = re.compile(r"^#### (GWS\.\S+)\s*$")
GROUP_RE = re.compile(r"^## \d+\.\s+(\S.*?)\s*$")
CRITICALITY_RE = re.compile(r"\b(SHALL|SHOULD)\b")
SENTENCE_END_RE = re.compile(r"[.!?](?=\s|$)")

LIMITATION_IDS = [
    "required_evidence_section_not_collected",
    "policy_scope_depends_on_licence",
    "policy_not_applicable",
]
RECOMMENDATION_IDS = ["collect_missing_evidence_section", "review_policy_against_baseline_text"]
ATTRIBUTION = "Baseline excerpts: CISA ScubaGoggles (CC0). No CISA endorsement."

_SETTING_PAIR = ["gws_tenant", "gws_policies"]
KIND_SECTIONS = {
    "setting": _SETTING_PAIR,
    "settings_multi": _SETTING_PAIR,
    "twosv": _SETTING_PAIR,
    "lists": _SETTING_PAIR,
    "setting_event": ["gws_tenant", "gws_setting_events"],
    "gws_dns": ["gws_dns"],
    "super_admin_count": ["gws_admins"],
    "admin_sso": ["gws_tenant", "gws_admins", "gws_sso"],
    "manual_only": ["gws_tenant"],
}
# The Gemini service gate reads the policies section as well.
EXTRA_SECTIONS = {"GEMINI.1.1": ["gws_tenant", "gws_policies", "gws_setting_events"]}

# Kind assignment from design section 14 (policy ids without the GWS. prefix and v1 suffix).
_KIND_IDS = {
    "setting": (
        "GMAIL.1.1 GMAIL.5.1 GMAIL.5.2 GMAIL.5.3 GMAIL.5.4 GMAIL.6.1 GMAIL.6.2 GMAIL.6.3 GMAIL.6.4 "
        "GMAIL.7.1 GMAIL.7.2 GMAIL.7.3 GMAIL.7.4 GMAIL.7.5 GMAIL.7.7 GMAIL.8.1 GMAIL.10.1 GMAIL.11.1 "
        "GMAIL.12.1 GMAIL.15.1 COMMONCONTROLS.4.1 COMMONCONTROLS.5.1 COMMONCONTROLS.5.2 "
        "COMMONCONTROLS.5.3 COMMONCONTROLS.5.4 COMMONCONTROLS.5.5 COMMONCONTROLS.5.6 COMMONCONTROLS.7.1 "
        "COMMONCONTROLS.8.1 COMMONCONTROLS.8.2 COMMONCONTROLS.10.3 COMMONCONTROLS.10.4 "
        "COMMONCONTROLS.10.5 COMMONCONTROLS.15.1 COMMONCONTROLS.15.2 COMMONCONTROLS.16.1 "
        "COMMONCONTROLS.16.2 COMMONCONTROLS.17.1 DRIVEDOCS.1.1 DRIVEDOCS.1.6 DRIVEDOCS.1.8 DRIVEDOCS.1.9 "
        "DRIVEDOCS.2.1 DRIVEDOCS.2.2 DRIVEDOCS.4.1 CALENDAR.1.1 CALENDAR.1.2 CALENDAR.2.1 CALENDAR.3.1 "
        "CALENDAR.4.1 CHAT.1.1 CHAT.1.2 CHAT.2.1 CHAT.3.1 MEET.1.1 MEET.2.1 MEET.3.1 MEET.4.1 MEET.5.1 "
        "MEET.5.2 GROUPS.1.1 GROUPS.1.2 GROUPS.1.3 GROUPS.2.1 GROUPS.3.1 SITES.1.1 CLASSROOM.1.1 "
        "CLASSROOM.1.2 CLASSROOM.2.1 CLASSROOM.3.1 CLASSROOM.4.1 CLASSROOM.5.1 ASSUREDCONTROLS.1.1 "
        "ASSUREDCONTROLS.1.2 "
    ).split(),
    "settings_multi": (
        "GMAIL.5.5 GMAIL.7.6 GMAIL.9.1 COMMONCONTROLS.11.1 COMMONCONTROLS.12.1 DRIVEDOCS.1.2 "
        "DRIVEDOCS.1.3 DRIVEDOCS.1.4 DRIVEDOCS.1.5 DRIVEDOCS.1.7 DRIVEDOCS.3.1 DRIVEDOCS.5.1 CHAT.4.1 "
        "GROUPS.4.1 "
    ).split(),
    "twosv": (
        "COMMONCONTROLS.1.1 COMMONCONTROLS.1.2 COMMONCONTROLS.1.3 COMMONCONTROLS.1.4 COMMONCONTROLS.1.5 "
    ).split(),
    "lists": (
        "GMAIL.14.1 GMAIL.17.1 GMAIL.18.1 GMAIL.18.2 GMAIL.18.3 COMMONCONTROLS.10.1 COMMONCONTROLS.10.2 "
        "COMMONCONTROLS.13.1 "
    ).split(),
    "setting_event": (
        "GMAIL.13.1 GMAIL.16.1 COMMONCONTROLS.2.1 COMMONCONTROLS.3.1 COMMONCONTROLS.3.2 CHAT.5.1 CHAT.5.2 "
        "MEET.6.1 MEET.6.2 GEMINI.1.1 GEMINI.2.1 ASSUREDCONTROLS.2.1 "
    ).split(),
    "gws_dns": (
        "GMAIL.2.1 GMAIL.3.1 GMAIL.4.1 GMAIL.4.2 GMAIL.4.3 GMAIL.4.4 "
    ).split(),
    "super_admin_count": (
        "COMMONCONTROLS.6.2 "
    ).split(),
    "admin_sso": (
        "COMMONCONTROLS.6.1 "
    ).split(),
    "manual_only": (
        "COMMONCONTROLS.8.3 COMMONCONTROLS.9.1 COMMONCONTROLS.9.2 COMMONCONTROLS.14.1 COMMONCONTROLS.14.2 "
        "COMMONCONTROLS.16.3 COMMONCONTROLS.16.4 COMMONCONTROLS.18.1 COMMONCONTROLS.18.2 DRIVEDOCS.1.10 "
        "DRIVEDOCS.1.11 DRIVEDOCS.5.2 CALENDAR.3.2 MEET.6.3 GEMINI.3.1 GEMINI.3.2 GEMINI.4.1 "
    ).split(),
}
KIND_OF = {f"GWS.{short}v1": kind for kind, shorts in _KIND_IDS.items() for short in shorts}


class CatalogueError(Exception):
    """Input that cannot be turned into a catalogue; never answered as a value."""


def trim_statement(text: str) -> str:
    text = " ".join(text.split())
    if len(text) <= MAX_TEXT:
        return text
    ends = [m.end() for m in SENTENCE_END_RE.finditer(text) if m.end() <= MAX_TEXT]
    if not ends:
        raise CatalogueError("policy statement over 400 characters has no sentence boundary to trim at")
    return text[: ends[-1]]


def parse_baseline(name: str, text: str) -> list[dict]:
    """Return the policies of one baseline file in document order."""
    lines = text.split("\n")
    group = None
    found = []
    for index, line in enumerate(lines):
        if line.startswith("## "):
            match = GROUP_RE.match(line)
            group = match.group(1) if match else None
            continue
        match = HEADING_RE.match(line)
        if not match:
            continue
        policy_id = match.group(1)
        if not ID_RE.match(policy_id):
            raise CatalogueError(f"{name}: malformed policy heading {policy_id!r}")
        if group is None:
            raise CatalogueError(f"{name}: {policy_id} has no numbered group heading")
        end = index + 1
        while end < len(lines) and not lines[end].startswith("#"):
            end += 1
        block = lines[index + 1 : end]
        statement = []
        position = 0
        while position < len(block) and block[position].strip() and not block[position].startswith("[!["):
            statement.append(block[position].strip())
            position += 1
        if not statement or statement[0].startswith(("[![", "- ", "#")):
            raise CatalogueError(f"{name}: {policy_id} has no statement")
        statement_text = trim_statement(" ".join(statement))
        keywords = set(CRITICALITY_RE.findall(statement_text))
        if len(keywords) != 1:
            raise CatalogueError(f"{name}: {policy_id} statement needs exactly one of SHALL and SHOULD")
        rest = "\n".join(block[position:]).lower()
        found.append(
            {
                "id": policy_id,
                "product": policy_id.split(".")[1],
                "group_title": group,
                "baseline_text": statement_text,
                "criticality": keywords.pop(),
                "manual": "[![manual]" in rest,
                "log_based": "[![log-based check]" in rest,
            }
        )
    return found


def sections_for(policy_id: str) -> list[str]:
    short = policy_id[len("GWS.") : -len("v1")]
    return list(EXTRA_SECTIONS.get(short, KIND_SECTIONS[KIND_OF[policy_id]]))


def read_markdown(source: Path, name: str) -> bytes | None:
    path = source / BASELINE_DIR / name
    if path.parent.resolve() != source.resolve() / BASELINE_DIR:
        raise CatalogueError("baseline folder is a link or is not under the source")
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(mode):
        raise CatalogueError(f"{name}: not a regular file")
    return path.read_bytes()


def build(source: Path, partial: bool) -> dict:
    digests = {}
    policies = {}
    for name in FILES:
        raw = read_markdown(source, name)
        if raw is None:
            if partial:
                continue
            raise CatalogueError(f"{name}: baseline file missing")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CatalogueError(f"{name}: not valid UTF-8") from exc
        digests[name] = hashlib.sha256(raw).hexdigest()
        for item in parse_baseline(name, text):
            policy_id = item.pop("id")
            if policy_id in policies:
                raise CatalogueError(f"{policy_id}: duplicate policy")
            if policy_id not in KIND_OF:
                raise CatalogueError(f"{policy_id}: no kind assignment")
            if item["manual"] != (KIND_OF[policy_id] == "manual_only"):
                raise CatalogueError(f"{policy_id}: Manual badge disagrees with the kind assignment")
            item["sections"] = sections_for(policy_id)
            policies[policy_id] = item
    if not digests:
        raise CatalogueError("no baseline Markdown found in the source")
    if not partial and (len(policies) != EXPECTED_POLICIES or set(policies) != set(KIND_OF)):
        raise CatalogueError(f"expected {EXPECTED_POLICIES} policies, found {len(policies)}")
    return {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "repo": REPO,
            "tag": TAG,
            "commit": COMMIT,
            "licence": LICENCE,
            "path": BASELINE_DIR,
            "files": digests,  # file name -> SHA-256 of its bytes
            "attribution": ATTRIBUTION,
        },
        "limitation_ids": LIMITATION_IDS,
        "recommendation_ids": RECOMMENDATION_IDS,
        "policies": policies,
    }


def render(catalogue: dict) -> str:
    return json.dumps(catalogue, indent=2, ensure_ascii=False) + "\n"


def differences(built: dict, committed: dict) -> list[str]:
    """Compare a partial build with the committed catalogue, file by file."""
    problems = []
    for key in ("schema_version", "limitation_ids", "recommendation_ids"):
        if built[key] != committed.get(key):
            problems.append(key)
    source = committed.get("source", {})
    for key in ("repo", "tag", "commit", "licence", "path", "attribution"):
        if built["source"][key] != source.get(key):
            problems.append(f"source.{key}")
    for name, digest in built["source"]["files"].items():
        if source.get("files", {}).get(name) != digest:
            problems.append(f"source.files.{name}")
    for policy_id, item in built["policies"].items():
        if committed.get("policies", {}).get(policy_id) != item:
            problems.append(policy_id)
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0], allow_abbrev=False)
    parser.add_argument("--source", required=True, type=Path, help="ScubaGoggles checkout (untrusted, read only)")
    parser.add_argument("--out", required=True, type=Path, help="catalogue file to write, or to check")
    parser.add_argument("--check", action="store_true", help="compare with --out instead of writing")
    parser.add_argument("--partial", action="store_true", help="with --check: compare only the files present")
    args = parser.parse_args(argv)
    if args.partial and not args.check:
        print("--partial only applies to --check", file=sys.stderr)
        return 2
    try:
        built = build(args.source, args.partial)
    except (CatalogueError, OSError) as exc:
        print(f"catalogue error: {exc if isinstance(exc, CatalogueError) else type(exc).__name__}", file=sys.stderr)
        return 2
    if not args.check:
        try:
            args.out.write_text(render(built), encoding="utf-8")
        except OSError as exc:
            print(f"catalogue error: cannot write the output ({type(exc).__name__})", file=sys.stderr)
            return 2
        return 0
    try:
        committed_text = args.out.read_text(encoding="utf-8")
        committed = json.loads(committed_text)
    except FileNotFoundError:
        print("drift: the committed catalogue is missing", file=sys.stderr)
        return 1
    except ValueError:
        print("drift: the committed catalogue is not valid JSON", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"catalogue error: cannot read the catalogue ({type(exc).__name__})", file=sys.stderr)
        return 2
    if args.partial:
        problems = differences(built, committed) if isinstance(committed, dict) else ["catalogue"]
    else:
        problems = [] if committed_text == render(built) else ["catalogue"]
    if problems:
        print("drift: " + ", ".join(problems), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
