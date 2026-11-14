#!/usr/bin/env python3
"""Digest the report, projection and explainer artefacts of the contract-smoke runs.

``--write FILE`` records the digests (with the commit they were taken at).
``--digests FILE RUNDIR`` recompares and exits non-zero naming every artefact that differs
or is missing, and on an empty or unreadable digest file.  RUNDIR is the directory holding
the ``ci-*`` run directories (``outputs/ci-contract``).

Volatile fields (run-time timestamps, run ids, durations, absolute paths, and values derived from the run date:
credential expiry day counts and expiry states) are normalised first.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from azure_tenant_audit.argument_parser import build_argument_parser  # noqa: E402

RUNS = (
    "ci-contract",
    "ci-identity-controls",
    "ci-admin-set",
    "ci-endpoint-posture",
    "ci-update-rings-missing",
    "ci-google",
    "ci-partial",
    "ci-projection-demo",
)
JSON_ARTEFACTS = (
    "reports/report-pack.json",
    "reports/action-plan.json",
    "summary.json",
    "findings/findings.json",
)
TEXT_ARTEFACTS = ("summary.md",)
ASSESSMENT = "model_assessment.json"
PROJECTION_RUN = "ci-projection-demo"
SCHEMA = 1

TIMESTAMP_KEYS = {"generated_at", "collected_at", "started_at", "completed_at", "finished_at"}
DURATION_KEYS = {"duration_seconds", "latency_ms"}
RUN_ID_KEYS = {"run_id"}
PATH_KEYS = {"run_dir"}
# Values derived from the current date: credential expiry day counts and expiry states.
RELATIVE_DAY_KEYS = {"expiry_days_remaining"}
RELATIVE_STATE_KEYS = {"expiry_state"}
TS_PLACEHOLDER = "<timestamp>"
RUN_ID_PLACEHOLDER = "<run-id>"
DURATION_PLACEHOLDER = "<duration>"
PATH_PLACEHOLDER = "<path>"
ROOT_PLACEHOLDER = "<root>"
RELATIVE_DAYS_PLACEHOLDER = "<days-from-run-date>"
RELATIVE_STATE_PLACEHOLDER = "<state-from-run-date>"

# Run-time timestamps in free text (summary.md): only those carrying fractional seconds or an
# explicit offset are written at run time; fixed sample-data stamps end in Z with no fraction.
_TEXT_TS = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:\+00:00|Z)?")


class DigestError(Exception):
    pass


def _path_prefixes(run_dir: Path | None) -> list[str]:
    prefixes = {str(ROOT), str(ROOT.resolve())}
    if run_dir is not None:
        prefixes.update({str(run_dir), str(run_dir.resolve()), str(run_dir.absolute())})
    return sorted(prefixes, key=len, reverse=True)


def _scrub_string(value: str, prefixes: list[str]) -> str:
    for prefix in prefixes:
        if prefix in value:
            value = value.replace(prefix, ROOT_PLACEHOLDER)
    return value


def _relative_days(value: Any) -> list[Any]:
    """Every date-relative day count nested in ``value``."""
    if isinstance(value, dict):
        found = [v for k, v in value.items() if k in RELATIVE_DAY_KEYS and v is not None]
        for child in value.values():
            found.extend(_relative_days(child))
        return found
    if isinstance(value, list):
        return [d for child in value for d in _relative_days(child)]
    return []


def normalise(value: Any, prefixes: list[str], key: str | None = None) -> Any:
    if isinstance(value, dict):
        # A finding's returned_value repeats the expiry day count of its evidence.
        derived = _relative_days(value) if "returned_value" in value else []
        out = {}
        for k, v in value.items():
            if k == "returned_value" and v is not None and not isinstance(v, bool) and v in derived:
                out[k] = RELATIVE_DAYS_PLACEHOLDER
            else:
                out[k] = normalise(v, prefixes, k)
        return out
    if isinstance(value, list):
        return [normalise(v, prefixes, key) for v in value]
    if key in TIMESTAMP_KEYS and value is not None:
        return TS_PLACEHOLDER
    if key in RUN_ID_KEYS and value is not None:
        return RUN_ID_PLACEHOLDER
    if key in DURATION_KEYS and value is not None:
        return DURATION_PLACEHOLDER
    if key in PATH_KEYS and value is not None:
        return PATH_PLACEHOLDER
    if key in RELATIVE_DAY_KEYS and value is not None:
        return RELATIVE_DAYS_PLACEHOLDER
    if key in RELATIVE_STATE_KEYS and value is not None:
        return RELATIVE_STATE_PLACEHOLDER
    if isinstance(value, str):
        return _scrub_string(value, prefixes)
    return value


def normalise_text(text: str, prefixes: list[str], run_ids: list[str]) -> str:
    text = _scrub_string(text, prefixes)
    for run_id in run_ids:
        text = text.replace(run_id, RUN_ID_PLACEHOLDER)
    return _TEXT_TS.sub(lambda m: TS_PLACEHOLDER if ("." in m.group(0) or "+" in m.group(0)) else m.group(0), text)


def _digest_json(value: Any) -> str:
    blob = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _run_ids(run: Path) -> list[str]:
    ids = {run.name}
    try:
        value = _read_json(run / "run-manifest.json").get("run_id")
    except (OSError, ValueError, AttributeError):
        value = None
    if isinstance(value, str) and value:
        ids.add(value)
    return sorted(ids, key=len, reverse=True)


def expected_artefacts(run_name: str) -> frozenset[str]:
    """The artefact names the digest of ``run_name`` must carry."""
    names = set(JSON_ARTEFACTS) | set(TEXT_ARTEFACTS)
    if run_name == PROJECTION_RUN:
        names |= {ASSESSMENT, "projection:project_run.report", "explainer:policy_explanations"}
    return frozenset(names)


def inventory_problems(runs: dict[str, Any]) -> list[str]:
    """Where the baseline's run and artefact inventory departs from the runs and artefacts this script digests."""
    problems = [f"{name}: run missing from the baseline" for name in RUNS if name not in runs]
    problems += [f"{name}: run not digested by this script" for name in sorted(runs) if name not in RUNS]
    for name in RUNS:
        if isinstance(runs.get(name), dict):
            want, have = expected_artefacts(name), set(runs[name])
            problems += [f"{name}/{art}: artefact missing from the baseline" for art in sorted(want - have)]
            problems += [f"{name}/{art}: artefact not digested by this script" for art in sorted(have - want)]
    return problems


def digest_run(run: Path) -> dict[str, str | None]:
    """Return artefact name -> digest, or None when the artefact is missing or unreadable."""
    prefixes = _path_prefixes(run)
    out: dict[str, str | None] = {}
    for name in JSON_ARTEFACTS + ((ASSESSMENT,) if run.name == PROJECTION_RUN else ()):
        try:
            out[name] = _digest_json(normalise(_read_json(run / name), prefixes))
        except (OSError, ValueError):
            out[name] = None
    for name in TEXT_ARTEFACTS:
        try:
            out[name] = _digest_text(
                normalise_text((run / name).read_text(encoding="utf-8"), prefixes, _run_ids(run))
            )
        except OSError:
            out[name] = None
    if run.name == PROJECTION_RUN:
        out["projection:project_run.report"] = _in_memory(run, prefixes, _projection)
        out["explainer:policy_explanations"] = _in_memory(run, prefixes, _policy_explanations)
    return out


def _projection(run: Path) -> Any:
    from auditex.scuba_projection import project_run

    return project_run(run).report


def _policy_explanations(run: Path) -> Any:
    from auditex.reporting import load_report_bundle

    return load_report_bundle(run)["sections"].get("policy_explanations")


def _in_memory(run: Path, prefixes: list[str], build: Any) -> str | None:
    try:
        return _digest_json(normalise(build(run), prefixes))
    except Exception:  # noqa: BLE001 - any failure means the artefact cannot be digested
        return None


def _commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def write_digests(rundir: Path, target: Path) -> int:
    runs: dict[str, dict[str, str | None]] = {}
    missing: list[str] = []
    for name in RUNS:
        run = rundir / name
        if not run.is_dir():
            missing.append(f"{name}: run directory missing")
            continue
        runs[name] = digest_run(run)
        missing.extend(f"{name}/{art}: missing or unreadable" for art, d in runs[name].items() if d is None)
    if missing:
        print("cannot record digests:\n  " + "\n  ".join(missing), file=sys.stderr)
        return 1
    payload = {"schema": SCHEMA, "commit": _commit(), "runs": runs}
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {sum(len(v) for v in runs.values())} digests for {len(runs)} runs to {target}")
    return 0


def compare_digests(digest_file: Path, rundir: Path) -> int:
    try:
        recorded = json.loads(digest_file.read_text(encoding="utf-8"))
        runs = recorded["runs"]
        if not isinstance(runs, dict) or not runs or not all(isinstance(v, dict) and v for v in runs.values()):
            raise ValueError("no digests recorded")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"digest file {digest_file} is empty or unreadable: {exc}", file=sys.stderr)
        return 2
    inventory = inventory_problems(runs)
    if inventory:
        print(f"digest file {digest_file} does not match the expected inventory:\n  " + "\n  ".join(inventory), file=sys.stderr)
        return 2
    problems: list[str] = []
    for name, artefacts in sorted(runs.items()):
        run = rundir / name
        if not run.is_dir():
            problems.append(f"{name}: run directory missing")
            continue
        actual = digest_run(run)
        for art, want in sorted(artefacts.items()):
            got = actual.get(art)
            if got is None:
                problems.append(f"{name}/{art}: missing or unreadable")
            elif got != want:
                problems.append(f"{name}/{art}: differs")
    if problems:
        print("run outputs differ from the recorded digests:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 1
    print(f"all {sum(len(v) for v in runs.values())} digests match (baseline commit {recorded.get('commit')})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", metavar="FILE", type=Path, help="record digests of RUNDIR to FILE")
    mode.add_argument("--digests", metavar="FILE", type=Path, help="compare RUNDIR against FILE")
    parser.add_argument("rundir", metavar="RUNDIR", type=Path, help="directory holding the ci-* run directories")
    args = parser.parse_args(argv)
    if args.write:
        return write_digests(args.rundir, args.write)
    return compare_digests(args.digests, args.rundir)


if __name__ == "__main__":
    raise SystemExit(main())
