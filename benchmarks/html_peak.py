#!/usr/bin/env python3
"""HTML report peak-memory harness (frozen interface: D5 design, "Harness interface").

Builds a synthetic run directory offline, renders the HTML report in one child process under the
given profile, measures that child's peak resident memory and counts workload names left in the
report. The JSON result goes to stdout; verdict lines go to stderr with the prefix ``html_peak: ``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

SEED = 213
MAX_RECORDS = 400_000
DEFAULT_MAX_RATIO = 1.15
FIELDS = (
    "records",
    "profile",
    "workload_sha256",
    "peak_rss_bytes",
    "person_names",
    "unmasked_name_hits",
    "commit",
    "python",
)
CONSONANTS = "bdgkmrtv"
VOWELS = "aeiou"
FINALS = "xzq"
TIMESTAMP = "2026-01-01T00:00:00Z"
REPO_ROOT = Path(__file__).resolve().parent.parent


class UsageError(Exception):
    """Exit 2: bad flags, baseline or baseline workload mismatch."""


class RenderError(Exception):
    """Exit 4: the render child failed or wrote no report."""


def _dump(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def _token(rng: random.Random) -> str:
    letters = [
        rng.choice(CONSONANTS), rng.choice(VOWELS),
        rng.choice(CONSONANTS), rng.choice(VOWELS),
        rng.choice(CONSONANTS), rng.choice(VOWELS),
        rng.choice(FINALS),
    ]  # fmt: skip
    return "".join(letters).capitalize()


def _people(rng: random.Random, count: int) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    people: list[tuple[str, str]] = []
    while len(people) < count:
        given, family = _token(rng), _token(rng)
        if given == family or (given, family) in seen:
            continue
        seen.add((given, family))
        people.append((given, family))
    return people


def _guid(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def build_workload(run_dir: Path, records: int) -> tuple[str, int, set[str]]:
    """Write the run directory; return (workload_sha256, people, lower-case name tokens)."""
    rng = random.Random(SEED)
    people_n, events_n, sites_n = records // 2, records // 4, records // 4
    names = _people(rng, people_n)
    guids = [_guid(rng) for _ in range(records)]
    person_ids = guids[:people_n]
    event_ids = guids[people_n : people_n + events_n]
    site_ids = guids[people_n + events_n :]

    def display(i: int) -> str:
        return f"{names[i][0]} {names[i][1]}"

    def local(i: int) -> str:
        return f"{names[i][0]}.{names[i][1]}".lower()

    def address(i: int) -> str:
        return f"{local(i)}@bench.example"

    users = []
    for i in range(people_n):
        user = {
            "kind": "user",
            "source": "identity.users",
            "id": person_ids[i],
            "key": f"user:{person_ids[i]}",
            "display_name": display(i),
            "principal_name": address(i),
            "mail": address(i),
            "user_type": "Member",
            "enabled": True,
        }
        if i % 1000 == 0:
            user["is_privileged"] = True
        users.append(user)

    def ref(i: int) -> dict[str, str]:
        return {"id": person_ids[i], "displayName": display(i), "userPrincipalName": address(i)}

    events = []
    for j in range(events_n):
        target = j + events_n
        text = json.dumps([f"Profile updated for {display(target)} by {display(j)}"])
        events.append(
            {
                "kind": "directory_audit_event",
                "id": event_ids[j],
                "key": f"event:{event_ids[j]}",
                "activity_display_name": "Update user",
                "result": "success",
                "activity_date_time": TIMESTAMP,
                "initiated_by": {"user": ref(j)},
                "target_resources": [
                    {
                        "type": "User",
                        "id": person_ids[target],
                        "displayName": display(target),
                        "userPrincipalName": address(target),
                        "modifiedProperties": [
                            {"displayName": "DisplayName", "oldValue": None, "newValue": text}
                        ],
                    }
                ],
                "additional_details": [{"key": "onPremisesSamAccountName", "value": local(target)}],
            }
        )

    sites = []
    for k in range(sites_n):
        given, family = names[k]
        sites.append(
            {
                "kind": "site",
                "id": site_ids[k],
                "key": f"site:{site_ids[k]}",
                "display_name": display(k),
                "owner_principal_name": address(k),
                "web_url": (
                    f"https://bench-my.sharepoint.com/personal/{given.lower()}_{family.lower()}_bench_example"
                ),
            }
        )

    pack = {
        "summary": {
            "tenant_name": "bench",
            "overall_status": "partial",
            "finding_count": 1,
            "blocker_count": 0,
            "open_count": 1,
            "accepted_count": 0,
            "risk": {"grade": "medium", "score": 50},
        },
        "executive_summary": {
            "tenant_name": "bench",
            "quality": "partial",
            "top_findings": [{"id": "finding-1", "title": "Review sharing", "severity": "medium"}],
        },
        "technical_appendix": {
            "evidence_path_count": 1,
            "proof_table_count": 0,
            "data_handling": "read_only_audit_default",
        },
        "limitations": [],
        "findings": [
            {
                "id": "finding-1",
                "rule_id": "bench.review_sharing",
                "title": "Review sharing",
                "severity": "medium",
                "status": "open",
                "impact": "Synthetic benchmark finding.",
                "remediation": "None.",
            }
        ],
        "action_plan": [{"id": "finding-1", "title": "Review sharing", "severity": "medium"}],
        "next_actions": [],
        "license_profile": {"minimum_live_access": "delegated_read_login", "production_writes": False},
        "proof_table": [],
        "evidence_paths": ["normalized/users.json"],
    }
    files = {
        "run-manifest.json": {
            "tenant_name": "bench",
            "run_id": "bench-run",
            "overall_status": "partial",
        },
        "summary.json": {"collectors": [], "assurance": {"grade": "usable", "score": 75}},
        "reports/report-pack.json": pack,
        "normalized/users.json": {"kind": "users", "records": users},
        "normalized/security_directory_audit_events.json": {"kind": "directory_audit_events", "records": events},
        "normalized/sites.json": {"kind": "sites", "records": sites},
    }
    (run_dir / "findings").mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    for rel in sorted(files):
        path = run_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        data = _dump(files[rel]).encode("utf-8")
        path.write_bytes(data)
        digest.update(f"{rel}\0{hashlib.sha256(data).hexdigest()}\n".encode())
    tokens = {t.lower() for pair in names for t in pair}
    return digest.hexdigest(), people_n, tokens


def count_name_hits(report: str, tokens: set[str]) -> int:
    return sum(1 for word in re.findall(r"[A-Za-z]+", report) if word.lower() in tokens)


def render_child(run_dir: Path, work_dir: Path, profile: str) -> tuple[int, Path]:
    """Render the HTML report in one child; return (peak rss bytes, report path)."""
    out = work_dir / "report.html"
    if profile == "shareable":
        cmd = [sys.executable, "-m", "auditex", "export", "run", "html", str(run_dir), "--output", str(out)]
    else:
        cmd = [
            sys.executable, "-m", "auditex", "report", "render", str(run_dir),
            "--format", "html", "--output", str(out),
        ]  # fmt: skip
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = "0"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    src = str(REPO_ROOT / "src")
    env["PYTHONPATH"] = src + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    err_path = work_dir / "child.stderr"
    with err_path.open("wb") as err, open(os.devnull, "wb") as null:
        child = subprocess.Popen(cmd, cwd=work_dir, env=env, stdout=null, stderr=err)  # noqa: S603
        _, status, usage = os.wait4(child.pid, 0)
        child.returncode = os.waitstatus_to_exitcode(status)
    if child.returncode != 0 or not out.is_file():
        tail = err_path.read_text(encoding="utf-8", errors="replace")[-2000:]
        raise RenderError(tail or f"render child exited {child.returncode} without a report")
    scale = 1 if sys.platform == "darwin" else 1024
    return int(usage.ru_maxrss) * scale, out


def _commit() -> str:
    try:
        done = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=False
        )
    except OSError:
        return "unknown"
    value = done.stdout.strip()
    return value if done.returncode == 0 and value else "unknown"


def _load_baseline(path: str) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UsageError(f"unreadable baseline: {exc}") from exc
    if not isinstance(data, dict) or any(f not in data for f in FIELDS):
        raise UsageError("malformed baseline: missing fields")
    def is_int(value: object, minimum: int) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value >= minimum

    sha = data["workload_sha256"]
    checks = {
        "records": is_int(data["records"], 1),
        "profile": data["profile"] in ("shareable", "local"),
        "workload_sha256": isinstance(sha, str)
        and len(sha) == 64
        and all(c in "0123456789abcdef" for c in sha),
        "peak_rss_bytes": is_int(data["peak_rss_bytes"], 1),
        "person_names": is_int(data["person_names"], 0),
        "unmasked_name_hits": is_int(data["unmasked_name_hits"], 0),
        "commit": isinstance(data["commit"], str) and bool(data["commit"]),
        "python": isinstance(data["python"], str) and bool(data["python"]),
    }
    for key, ok in checks.items():
        if not ok:
            raise UsageError(f"malformed baseline: invalid {key}")
    return data


def _positive_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a number: {text}") from exc
    if not value > 0 or value == float("inf"):
        raise argparse.ArgumentTypeError("must be a positive number")
    return value


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # exit 2, not argparse's default of 2 only by accident
        self.print_usage(sys.stderr)
        print(f"html_peak: {message}", file=sys.stderr)
        raise SystemExit(2)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--records", type=int, required=True)
    parser.add_argument("--profile", choices=("shareable", "local"), required=True)
    parser.add_argument("--baseline")
    parser.add_argument("--max-ratio", type=_positive_float, default=None)
    parser.add_argument("--require-masked", action="store_true")
    return parser


def run(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.records <= 0 or args.records % 4 or args.records > MAX_RECORDS:
            raise UsageError(f"--records must be a positive multiple of 4, at most {MAX_RECORDS}")
        if args.max_ratio is not None and not args.baseline:
            raise UsageError("--max-ratio requires --baseline")
        max_ratio = args.max_ratio if args.max_ratio is not None else DEFAULT_MAX_RATIO
        baseline = _load_baseline(args.baseline) if args.baseline else None
    except UsageError as exc:
        print(f"html_peak: {exc}", file=sys.stderr)
        return 2

    work_dir = Path(tempfile.mkdtemp(prefix="html-peak-"))
    try:
        run_dir = work_dir / "run"
        run_dir.mkdir()
        sha, people, tokens = build_workload(run_dir, args.records)
        if baseline is not None:
            for key, value in (("records", args.records), ("profile", args.profile), ("workload_sha256", sha)):
                if baseline[key] != value:
                    print(f"html_peak: baseline workload differs ({key})", file=sys.stderr)
                    return 2
            if baseline["python"] != platform.python_version():
                print(
                    f"html_peak: warning: baseline python {baseline['python']} differs from "
                    f"{platform.python_version()}",
                    file=sys.stderr,
                )
        try:
            peak, report = render_child(run_dir, work_dir, args.profile)
        except RenderError as exc:
            print(f"html_peak: render failed\n{exc}", file=sys.stderr)
            return 4
        hits = count_name_hits(report.read_text(encoding="utf-8", errors="replace"), tokens)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    result = {
        "records": args.records,
        "profile": args.profile,
        "workload_sha256": sha,
        "peak_rss_bytes": peak,
        "person_names": people,
        "unmasked_name_hits": hits,
        "commit": _commit(),
        "python": platform.python_version(),
    }
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")

    if args.require_masked and hits > 0:
        print(f"html_peak: {hits} workload name tokens left in the report", file=sys.stderr)
        return 3
    if baseline is not None:
        limit = baseline["peak_rss_bytes"] * max_ratio
        print(f"html_peak: peak {peak} limit {limit:.0f} (ratio {max_ratio})", file=sys.stderr)
        if peak > limit:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))
