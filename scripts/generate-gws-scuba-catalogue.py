#!/usr/bin/env python3
"""Generate configs/scuba-gws-policy-sections.json from the pinned ScubaGoggles baseline Markdown.

    python3 -I scripts/generate-gws-scuba-catalogue.py --source <checkout> --out <file> [--check [--partial NAMES]]

The checkout is untrusted data: this script only reads the 11 Markdown files (never follows links, never runs
anything from it). Run it with ``python3 -I``. It works from the Markdown alone; the per-policy kind assignment
(design section 14) is the table below. Exit codes: 0 ok, 1 drift, 2 bad input.

Every baseline file is verified against the SHA-256 pinned below before it is parsed: a cut or edited file is
refused (exit 2) even when every policy id survives. ``--check`` regenerates and compares with ``--out``.
``--partial NAME[,NAME...]`` (check only) compares just the named baseline files, each of which must be present
and match its pinned digest, so a small fixture can be checked; a release check runs without it against the full pin.

Per-policy keys use field names already in the shared redaction registry: ``service`` (product), ``heading``
(group title) and ``events`` (true for a Log-Based Check policy, answered from audit-log events).
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from azure_tenant_audit.argument_parser import build_argument_parser  # noqa: E402

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
# SHA-256 of each baseline file at v1.1.0 (commit above); any other bytes are refused.
PINNED_SHA256 = {
    "assuredcontrols.md": "9f9f3c0e803954010ab90882d463757eb3e5bedaab2d53b1dbbed321369b2388",
    "calendar.md": "2eb9434a25659fec204011f3555a09dacb3648f885be608a97667d2dbad24386",
    "chat.md": "536b616a6c05d51259d42d8b13261730bd993457d1b576f7d3f5700590436114",
    "classroom.md": "ec918f2c2e549eafe41163530b6a0a31fad7fe6897b96fea57352e6ebc4f5806",
    "commoncontrols.md": "7acbe5253a83d0b9292cee8eb5b09ae1475dfc0c8c7792be73039c5dc0463d28",
    "drive.md": "29b37b73556d68c15f8f5360fc398a853247318a6993747566f3698522f2c234",
    "gemini.md": "fa902507384984d72ab533ff344c168d50a8e5c548f2f113c00aac60cce188a8",
    "gmail.md": "33b5cc5b8c31a7ec87ae85af5fa4205f60a5d710cac369a6ebe647da66796b95",
    "groups.md": "b94f1444b1f42e431db27aba4c0b850c198750e949ef8d895784ddb05133f439",
    "meet.md": "b9e25cad07da933c6a7facd12df2e67042780f664f5158b3da61a21049d72e06",
    "sites.md": "3d1617d16aeac86120114eb19c6ea1a1fd0b221ce5936b3afe537f10395d6508",
}
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
    "gws_list_settings": _SETTING_PAIR,
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
    "gws_list_settings": (
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
            raise CatalogueError(f"{name}: line {index + 1}: malformed policy heading")
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
                "service": policy_id.split(".")[1],
                "heading": group,
                "baseline_text": statement_text,
                "criticality": keywords.pop(),
                "manual": "[![manual]" in rest,
                "events": "[![log-based check]" in rest,
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


def build(source: Path, names: tuple[str, ...] = tuple(FILES)) -> dict:
    """Build the catalogue from the named baseline files (all 11 unless a partial check names fewer)."""
    partial = tuple(names) != tuple(FILES)
    digests = {}
    policies = {}
    for name in names:
        raw = read_markdown(source, name)
        if raw is None:
            raise CatalogueError(f"{name}: baseline file missing")
        if hashlib.sha256(raw).hexdigest() != PINNED_SHA256[name]:
            raise CatalogueError(f"{name}: bytes differ from the pinned v1.1.0 digest")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CatalogueError(f"{name}: not valid UTF-8") from exc
        digests[name] = PINNED_SHA256[name]
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


_MISSING = object()


def strict_equal(left: object, right: object) -> bool:
    """JSON equality that tells types apart: ``0``, ``False`` and ``0.0`` are three different values, as in the
    rendered bytes. Python's ``==`` would let ``1`` pass for ``true``."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(strict_equal(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(strict_equal(a, b) for a, b in zip(left, right, strict=True))
    return left == right


class DuplicateKeyError(ValueError):
    """A JSON object names one key twice; ``json.loads`` would silently keep the last value."""


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("duplicate key")
        result[key] = value
    return result


def load_catalogue(text: str) -> object:
    """Parse the committed catalogue, refusing a duplicate key at any depth."""
    return json.loads(text, object_pairs_hook=_no_duplicate_keys)


def differences(built: dict, committed: dict) -> list[str]:
    """Compare a partial build with the committed catalogue, file by file, type for type."""
    problems = []
    for key in ("schema_version", "limitation_ids", "recommendation_ids"):
        if not strict_equal(built[key], committed.get(key, _MISSING)):
            problems.append(key)
    source = committed["source"]
    for key in ("repo", "tag", "commit", "licence", "path", "attribution"):
        if not strict_equal(built["source"][key], source.get(key, _MISSING)):
            problems.append(f"source.{key}")
    for name, digest in built["source"]["files"].items():
        if not strict_equal(digest, source["files"].get(name, _MISSING)):
            problems.append(f"source.files.{name}")
    for policy_id, item in built["policies"].items():
        if not strict_equal(item, committed["policies"].get(policy_id, _MISSING)):
            problems.append(policy_id)
    return problems


def well_formed(committed: object) -> bool:
    """The nested objects a check compares must be objects; anything else is bad input, not drift."""
    return (
        isinstance(committed, dict)
        and isinstance(committed.get("source"), dict)
        and isinstance(committed["source"].get("files"), dict)
        and isinstance(committed.get("policies"), dict)
    )


def partial_names(value: str) -> tuple[str, ...]:
    names = value.split(",")
    if any(part not in FILES for part in names):
        raise CatalogueError("--partial must name baseline files from the pinned set, comma separated")
    return tuple(name for name in FILES if name in names)


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--source", required=True, type=Path, help="ScubaGoggles checkout (untrusted, read only)")
    parser.add_argument("--out", required=True, type=Path, help="catalogue file to write, or to check")
    parser.add_argument("--check", action="store_true", help="compare with --out instead of writing")
    parser.add_argument("--partial", metavar="NAMES", help="with --check: compare only these baseline files (a,b)")
    args = parser.parse_args(argv)
    if args.partial is not None and not args.check:
        print("--partial only applies to --check", file=sys.stderr)
        return 2
    try:
        names = partial_names(args.partial) if args.partial is not None else tuple(FILES)
        built = build(args.source, names)
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
        committed = load_catalogue(committed_text)
    except FileNotFoundError:
        print("drift: the committed catalogue is missing", file=sys.stderr)
        return 1
    except DuplicateKeyError:
        print("drift: the committed catalogue repeats a key", file=sys.stderr)
        return 1
    except (ValueError, RecursionError):
        print("drift: the committed catalogue is not valid JSON", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"catalogue error: cannot read the catalogue ({type(exc).__name__})", file=sys.stderr)
        return 2
    if not well_formed(committed):
        print("catalogue error: the committed catalogue has a malformed structure", file=sys.stderr)
        return 2
    if args.partial is not None:
        problems = differences(built, committed)
    else:
        problems = [] if committed_text == render(built) else ["catalogue"]
    if problems:
        print("drift: " + ", ".join(problems), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
