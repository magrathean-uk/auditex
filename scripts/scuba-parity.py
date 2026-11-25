#!/usr/bin/env python3
"""Compare CISA's SCuBA tool verdicts with Auditex's SCuBA answers, policy by policy; internal, not shipped.

Inputs: a ScubaGear ``ScubaResults_*.json`` or a ScubaGoggles ``ScubaResults*.json`` (auto-detected and validated)
and an Auditex run folder or ``model_assessment.json``. With ``--same-input`` (ScubaGear only) Auditex's rules are run
on the export embedded in the same ScubaResults file, so every difference is a rule difference. Writes
``scuba-parity.json`` and ``scuba-parity.md`` into a new or empty ``--out`` directory; neither copies tenant names,
ids, domains, details text or paths. No tenant contact. In same-input mode ``--out/auditex-same-input/`` also holds
the adapter's own local assessment, which is live evidence like the ScubaResults file it came from.

Exit codes: 0 compared; 1 compared with ``--strict`` and at least one ``disagreement``; 2 unusable input.
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from azure_tenant_audit.argument_parser import build_argument_parser  # noqa: E402

MAX_INPUT_BYTES = 64 * 1024 * 1024
DIVERGENCE_FILE = Path(__file__).with_name("scuba-parity-divergences.json")
OUTPUT_JSON, OUTPUT_MD = "scuba-parity.json", "scuba-parity.md"
SAME_INPUT_DIR = "auditex-same-input"
OUTPUT_SCHEMA = "auditex-scuba-parity/1"

MS_ID = re.compile(r"MS\.[A-Z]+\.\d+\.\d+v\d+", re.ASCII)
GWS_ID = re.compile(r"GWS\.[A-Z]+\.\d+\.\d+v\d+", re.ASCII)
REASON_CODE = re.compile(r"[a-z][a-z0-9_.]{0,63}", re.ASCII)
VERSION = re.compile(r"\d+(?:\.\d+){1,3}", re.ASCII)
CONFIGS = Path(__file__).resolve().parents[1] / "configs"
PRECHECK_CLASSES = frozenset({"closed_gate", "absent_section", "absent_field", "empty_required_list", "value_rule"})
UNLISTED_REASON = "unlisted_reason_code"

# Each CISA tool and the release the Auditex rules are pinned to (ScubaGear v1.8.0 baselines for spec v3.9.1;
# ScubaGoggles v1.1.0 for M13). A result from another release is compared, and flagged.
TOOLS = {
    "ScubaGear": {"platform": "m365", "id": MS_ID, "pinned": "1.8.0"},
    "ScubaGoggles": {"platform": "gws", "id": GWS_ID, "pinned": "1.1.0"},
}

# The CISA "Result" literals, mapped explicitly. pass and fail are decisions; every other class is not.
# Warning is a SHOULD (or MAY) requirement not met: the same answer as Auditex not_met.
CISA_RESULTS = {
    "Pass": "pass",
    "Fail": "fail",
    "Warning": "fail",
    "N/A": "manual",                        # 3rd Party or Not-Implemented criticality: a manual check
    "No events found": "no_events",         # ScubaGoggles: no log event for the setting
    "Error": "error",                       # missing commands, failed prerequisite or malformed description
    "Error - Test results missing": "error",
    "-": "deleted",                         # ScubaGear: a deleted control
}
# Rows whose displayed Result is an operator overlay. The tool's own verdict is in the original-result field.
CISA_OVERLAYS = {"Omitted": "omitted", "Incorrect result": "annotated_incorrect"}
ORIGINAL_RESULT_FIELDS = ("OriginalResult", "OmittedEvaluationResult")
CISA_DECIDED = frozenset({"pass", "fail"})
CISA_CLASSES = frozenset(CISA_RESULTS.values()) | frozenset(CISA_OVERLAYS.values()) | {"conflicting_rows"}

AUDITEX_VERDICTS = ("met", "not_met", "not_applicable", "not_assessed")
RULE_REASONS = {"rule_not_implemented", "policy_not_in_catalogue"}
NOT_A_RULE_ANSWER = "not_a_rule_answer"

CATEGORIES = (
    "disagreement",                 # both decided, opposite answers, not documented: needs a look
    "auditex_not_assessed",         # CISA decided, Auditex did not: unknown is not safe, but find out why
    "auditex_decided",              # CISA could not decide, Auditex did
    "documented_divergence",        # a non-agreement that matches a documented D row
    "cisa_only",                    # policy id only in the CISA result
    "auditex_only",                 # policy id only in the Auditex assessment
    "neither_decided",              # both sides undecided
    "agree",
)

MESSAGES = {
    "cisa": "the CISA result file is not a readable ScubaGear or ScubaGoggles result",
    "cisa_value": "the CISA result file holds an unrecognised Result value",
    "auditex": "the Auditex assessment is not readable",
    "platform": "the CISA result and the Auditex assessment cover different platforms",
    "divergences": "the divergence map is invalid",
    "out": "the output directory must be new or empty and not a link",
    "same_input": "same-input mode needs a ScubaGear result file with its embedded export",
    "adapter": "Auditex could not assess the export embedded in the ScubaGear result",
    "write": "the parity report could not be written",
}


class ParityError(Exception):
    """An unusable input; ``str()`` is a fixed message that never carries a path or input text."""

    def __init__(self, key: str):
        super().__init__(MESSAGES[key])
        self.key = key


def _reject_constant(_: str) -> Any:
    raise ValueError("non-finite number")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _read_json(path: Path, key: str) -> Any:
    """Read one regular file (no links), at most 64 MiB, strict JSON with no duplicate keys or NaN."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        raise ParityError(key) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT_BYTES:
            raise ParityError(key)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            payload = handle.read(MAX_INPUT_BYTES + 1)
    except OSError:
        raise ParityError(key) from None
    finally:
        os.close(fd)
    if len(payload) > MAX_INPUT_BYTES:
        raise ParityError(key)
    try:
        return json.loads(payload.decode("utf-8-sig"), object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise ParityError(key) from None


# ---------------------------------------------------------------------------------------------------------------
# CISA side


def _cisa_class(control: dict[str, Any]) -> tuple[str, str]:
    """(displayed Result literal, verdict class) for one control row."""
    result = control.get("Result")
    if not isinstance(result, str):
        raise ParityError("cisa")
    if result in CISA_RESULTS:
        return result, CISA_RESULTS[result]
    if result in CISA_OVERLAYS:
        for field in ORIGINAL_RESULT_FIELDS:
            original = control.get(field)
            if original is None:
                continue
            if not isinstance(original, str) or original not in CISA_RESULTS:
                raise ParityError("cisa_value")
            return result, CISA_RESULTS[original]
        return result, CISA_OVERLAYS[result]
    raise ParityError("cisa_value")


def _cisa_document(path: Path) -> tuple[Any, bool]:
    """Strict JSON, else the export adapter's one allowed repair: PowerShell writes an empty array as nothing
    (``"key": ,``) inside ``Raw``. A repair that touches ``Results`` leaves the verdicts unreadable and is refused."""
    try:
        return _read_json(path, "cisa"), False
    except ParityError:
        pass
    from auditex.scubagear_export import load_export
    try:
        loaded = load_export(path)
    except Exception:  # noqa: BLE001 - one fixed message; the adapter's text is not shown
        raise ParityError("cisa") from None
    if not loaded.repaired or loaded.kind != "scubaresults" or "Results" in loaded.repaired_keys:
        raise ParityError("cisa")
    metadata = {"ToolVersion": loaded.module_version} if loaded.module_version else {}
    return {"MetaData": metadata, "Results": loaded.results, "Raw": loaded.raw}, True


def load_cisa(path: Path) -> dict[str, Any]:
    """Validate a ScubaResults file and return its tool, version and per-policy verdicts."""
    document, repaired = _cisa_document(path)
    if not isinstance(document, dict) or not isinstance(document.get("MetaData"), dict):
        raise ParityError("cisa")
    results = document.get("Results")
    if not isinstance(results, dict) or not results:
        raise ParityError("cisa")
    rows: dict[str, dict[str, str]] = {}
    for groups in results.values():
        if not isinstance(groups, list):
            raise ParityError("cisa")
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("Controls"), list):
                raise ParityError("cisa")
            for control in group["Controls"]:
                if not isinstance(control, dict):
                    raise ParityError("cisa")
                policy_id = control.get("Control ID")
                if not isinstance(policy_id, str) or not (MS_ID.fullmatch(policy_id) or GWS_ID.fullmatch(policy_id)):
                    raise ParityError("cisa")
                literal, verdict = _cisa_class(control)
                seen = rows.get(policy_id)
                if seen is None:
                    rows[policy_id] = {"result": literal, "verdict": verdict}
                elif seen["verdict"] != verdict:
                    # ScubaGoggles writes one row per Rego test; two tests for one control that disagree are not
                    # a decision.
                    rows[policy_id] = {"result": "conflicting rows", "verdict": "conflicting_rows"}
    if not rows:
        raise ParityError("cisa")
    tool = _detect_tool(document["MetaData"], rows)
    version = document["MetaData"].get("ToolVersion")
    version = version if isinstance(version, str) and VERSION.fullmatch(version) else None
    raw = document.get("Raw")
    return {"tool": tool, "version": version, "rows": rows, "has_raw": isinstance(raw, dict) and bool(raw),
            "repaired": repaired}


def _detect_tool(metadata: dict[str, Any], rows: dict[str, Any]) -> str:
    by_ids = {name for name, tool in TOOLS.items() if all(tool["id"].fullmatch(pid) for pid in rows)}
    if len(by_ids) != 1:
        raise ParityError("cisa")  # mixed or unknown policy id families
    tool = by_ids.pop()
    declared = metadata.get("Tool")
    if declared is not None and declared != tool:
        raise ParityError("cisa")
    return tool


# ---------------------------------------------------------------------------------------------------------------
# Auditex side


def _auditex_verdict(record: dict[str, Any]) -> tuple[str, str]:
    """(verdict, reason code) for one model_assessment policy row. Only value-rule answers count as decided."""
    reason = record.get("reason")
    claims = record.get("claims")
    if not isinstance(claims, list) or not all(isinstance(claim, dict) for claim in claims):
        raise ParityError("auditex")
    if reason is not None and not isinstance(reason, str):
        raise ParityError("auditex")
    if reason in RULE_REASONS:
        return "not_assessed", reason
    if reason != "rule_precheck":
        # A model-era row, an endpoint failure or anything else that is not a value-rule answer.
        return "not_assessed", NOT_A_RULE_ANSWER
    detail = record.get("rule_precheck")
    if not isinstance(detail, dict):
        raise ParityError("auditex")
    code = detail.get("reason_code", detail.get("class"))
    if not isinstance(code, str) or not REASON_CODE.fullmatch(code):
        raise ParityError("auditex")
    requirement = [claim for claim in claims if claim.get("id") == "requirement_met"]
    if len(requirement) != 1:
        raise ParityError("auditex")
    status, value = requirement[0].get("status"), requirement[0].get("value")
    limitations = record.get("limitations")
    if status == "unknown" and value is None:
        return "not_assessed", code
    if (status == "inferred" and value is True and isinstance(limitations, list)
            and "policy_not_applicable" in limitations):
        return "not_applicable", code
    if status == "confirmed" and type(value) is bool:
        return ("met" if value else "not_met"), code
    raise ParityError("auditex")


def known_reason_codes() -> frozenset[str]:
    """Every reason code the shipped rule configs name, the precheck classes and the fixed rule reasons. A code
    outside this set is reported as ``unlisted_reason_code``, so free text in an assessment never reaches the
    report."""
    codes: set[str] = set(PRECHECK_CLASSES) | RULE_REASONS | {NOT_A_RULE_ANSWER}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "reason_code" and isinstance(value, str):
                    codes.add(value)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    try:
        for path in sorted(CONFIGS.glob("*.json")):
            walk(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        raise ParityError("divergences") from None
    return frozenset(codes)


def load_auditex(path: Path) -> dict[str, dict[str, str]]:
    try:
        if path.is_dir() and not path.is_symlink():
            path = path / "model_assessment.json"
    except OSError:
        raise ParityError("auditex") from None
    document = _read_json(path, "auditex")
    if not isinstance(document, dict):
        raise ParityError("auditex")
    policies = document.get("policies")
    if not isinstance(policies, list) or not policies:
        raise ParityError("auditex")
    rows: dict[str, dict[str, str]] = {}
    for record in policies:
        if not isinstance(record, dict):
            raise ParityError("auditex")
        policy_id = record.get("policy_id")
        if (not isinstance(policy_id, str) or policy_id in rows
                or not (MS_ID.fullmatch(policy_id) or GWS_ID.fullmatch(policy_id))):
            raise ParityError("auditex")
        verdict, code = _auditex_verdict(record)
        rows[policy_id] = {"verdict": verdict, "reason_code": code}
    return rows


# ---------------------------------------------------------------------------------------------------------------
# Divergence map


def load_divergences(path: Path = DIVERGENCE_FILE) -> list[dict[str, Any]]:
    try:
        document = _read_json(path, "divergences")
    except ParityError:
        raise ParityError("divergences") from None
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ParityError("divergences")
    sources, entries = document.get("sources"), document.get("entries")
    if not isinstance(sources, dict) or not isinstance(entries, list):
        raise ParityError("divergences")
    cisa_allowed = {"pass", "fail", "not_decided"}
    for entry in entries:
        ok = (isinstance(entry, dict)
              and set(entry) in ({"policy_id", "id", "cite", "cisa", "auditex"},
                                 {"policy_id", "id", "cite", "cisa", "auditex", "reason_codes"})
              and isinstance(entry["policy_id"], str)
              and bool(MS_ID.fullmatch(entry["policy_id"]) or GWS_ID.fullmatch(entry["policy_id"]))
              and isinstance(entry["id"], str) and re.fullmatch(r"D\d{1,3}", entry["id"]) is not None
              and isinstance(entry["cite"], str) and entry["cite"].split(" ", 1)[0] in sources
              and entry["cite"].endswith(" " + entry["id"])
              and isinstance(entry["cisa"], list) and entry["cisa"] and set(entry["cisa"]) <= cisa_allowed
              and isinstance(entry["auditex"], list) and entry["auditex"]
              and set(entry["auditex"]) <= set(AUDITEX_VERDICTS)
              and all(isinstance(code, str) and REASON_CODE.fullmatch(code)
                      for code in entry.get("reason_codes", ["x"])))
        if not ok or ("reason_codes" in entry and not entry["reason_codes"]):
            raise ParityError("divergences")
    return entries


def matching_divergences(entries: list[dict[str, Any]], policy_id: str, cisa: str, auditex: str,
                         reason_code: str) -> list[str]:
    side = cisa if cisa in CISA_DECIDED else "not_decided"
    found = {entry["id"] for entry in entries
             if entry["policy_id"] == policy_id and side in entry["cisa"] and auditex in entry["auditex"]
             and ("reason_codes" not in entry or reason_code in entry["reason_codes"])}
    return sorted(found, key=lambda did: int(did[1:]))


# ---------------------------------------------------------------------------------------------------------------
# Comparison


def categorise(cisa: str, auditex: str, divergences: list[str]) -> str:
    cisa_decided, auditex_decided = cisa in CISA_DECIDED, auditex != "not_assessed"
    if (cisa == "pass" and auditex in {"met", "not_applicable"}) or (cisa == "fail" and auditex == "not_met"):
        return "agree"
    if not cisa_decided and not auditex_decided:
        return "neither_decided"
    if divergences:
        return "documented_divergence"
    if cisa_decided and not auditex_decided:
        return "auditex_not_assessed"
    if auditex_decided and not cisa_decided:
        return "auditex_decided"
    return "disagreement"


def check_platform(cisa: dict[str, Any], auditex: dict[str, dict[str, str]]) -> None:
    if not any(TOOLS[cisa["tool"]]["id"].fullmatch(pid) for pid in auditex):
        raise ParityError("platform")


def compare(cisa: dict[str, Any], auditex: dict[str, dict[str, str]], entries: list[dict[str, Any]],
            *, mode: str) -> dict[str, Any]:
    tool = TOOLS[cisa["tool"]]
    check_platform(cisa, auditex)
    rows = []
    for policy_id in sorted(set(cisa["rows"]) | set(auditex)):
        c, a = cisa["rows"].get(policy_id), auditex.get(policy_id)
        row = {"policy_id": policy_id,
               "cisa_result": c["result"] if c else None, "cisa_verdict": c["verdict"] if c else None,
               "auditex_verdict": a["verdict"] if a else None, "auditex_reason_code": a["reason_code"] if a else None,
               "divergences": []}
        if c is None:
            row["category"] = "auditex_only"
        elif a is None:
            row["category"] = "cisa_only"
        else:
            row["divergences"] = matching_divergences(entries, policy_id, c["verdict"], a["verdict"],
                                                      a["reason_code"])
            row["category"] = categorise(c["verdict"], a["verdict"], row["divergences"])
            if row["category"] != "documented_divergence":
                row["divergences"] = []
        rows.append(row)
    counts = {category: sum(row["category"] == category for row in rows) for category in CATEGORIES}
    return {"schema": OUTPUT_SCHEMA, "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "mode": mode, "cisa_tool": cisa["tool"], "cisa_tool_version": cisa["version"],
            "cisa_input_repaired": cisa["repaired"],
            "pinned_version": tool["pinned"], "version_matches": cisa["version"] == tool["pinned"],
            "counts": counts, "rows": rows}


def render_markdown(report: dict[str, Any]) -> str:
    version = report["cisa_tool_version"] or "unknown"
    lines = [f"# SCuBA parity: {report['cisa_tool']} and Auditex", "",
             f"Mode: {report['mode']}. {report['cisa_tool']} version {version}; Auditex rules are pinned to "
             f"{report['pinned_version']}" + ("." if report["version_matches"] else ", so differences may come "
                                               "from the release gap."),
             "", "| category | policies |", "|---|---|"]
    lines += [f"| {category} | {report['counts'][category]} |" for category in CATEGORIES]
    lines += ["", "| policy | CISA result | CISA verdict | Auditex verdict | Auditex reason | category | divergence |",
              "|---|---|---|---|---|---|---|"]
    order = {category: index for index, category in enumerate(CATEGORIES)}
    for row in sorted(report["rows"], key=lambda r: (order[r["category"]], r["policy_id"])):
        cells = [row["policy_id"], row["cisa_result"], row["cisa_verdict"], row["auditex_verdict"],
                 row["auditex_reason_code"], row["category"], ", ".join(row["divergences"])]
        lines.append("| " + " | ".join("-" if cell in (None, "") else cell for cell in cells) + " |")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------------------------------------------
# Output and entry point


def _prepare_out(out: Path) -> None:
    try:
        if out.is_symlink():
            raise ParityError("out")
        if out.exists():
            if not out.is_dir() or any(out.iterdir()):
                raise ParityError("out")
        else:
            out.mkdir(mode=0o700)
    except OSError:
        raise ParityError("out") from None


def _remove_empty(*paths: Path | None) -> None:
    for path in paths:
        if path is not None:
            try:
                path.rmdir()  # only ever removes an empty directory
            except OSError:
                pass


def _write_private(path: Path, text: str) -> None:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    except OSError:
        raise ParityError("write") from None


def _same_input_assessment(cisa_path: Path, out: Path) -> dict[str, dict[str, str]]:
    from auditex.rule_assessment import assess_scubagear_export
    target = out / SAME_INPUT_DIR
    try:
        assess_scubagear_export(cisa_path, target)
    except Exception:  # noqa: BLE001 - any adapter fault is one fixed message; its text can hold export content
        raise ParityError("adapter") from None
    return load_auditex(target / "model_assessment.json")


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser(description="Compare CISA SCuBA tool verdicts with Auditex's SCuBA answers.")
    parser.add_argument("cisa_results", metavar="CISA_RESULTS")
    parser.add_argument("auditex", metavar="AUDITEX_RUN_OR_ASSESSMENT", nargs="?")
    parser.add_argument("--same-input", action="store_true",
                        help="run Auditex's rules on the export embedded in the ScubaGear result")
    parser.add_argument("--out", required=True, metavar="DIR")
    parser.add_argument("--strict", action="store_true", help="exit 1 when any row is a disagreement")
    args = parser.parse_args(argv)
    if args.same_input == (args.auditex is not None):
        parser.error("give an Auditex run or assessment, or --same-input, not both")
    try:
        entries = load_divergences()
        cisa_path, out = Path(args.cisa_results), Path(args.out)
        cisa = load_cisa(cisa_path)
        if args.same_input and (cisa["tool"] != "ScubaGear" or not cisa["has_raw"]):
            raise ParityError("same_input")
        if args.same_input:
            created = not out.exists()
            _prepare_out(out)
            try:
                auditex = _same_input_assessment(cisa_path, out)
            except ParityError:
                _remove_empty(out / SAME_INPUT_DIR, out if created else None)
                raise
        else:
            auditex = load_auditex(Path(args.auditex))
            check_platform(cisa, auditex)
            _prepare_out(out)
        known = known_reason_codes() | {code for entry in entries for code in entry.get("reason_codes", [])}
        for row in auditex.values():
            if row["reason_code"] not in known:
                row["reason_code"] = UNLISTED_REASON
        report = compare(cisa, auditex, entries, mode="same-input" if args.same_input else "two-input")
        try:
            _write_private(out / OUTPUT_JSON, json.dumps(report, indent=2, sort_keys=True) + "\n")
            _write_private(out / OUTPUT_MD, render_markdown(report))
        except ParityError:
            for name in (OUTPUT_JSON, OUTPUT_MD):
                try:
                    (out / name).unlink()
                except OSError:
                    pass
            raise
    except ParityError as exc:
        print(f"scuba-parity: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"mode": report["mode"], "cisa_tool": report["cisa_tool"], "counts": report["counts"],
                      "version_matches": report["version_matches"]}, sort_keys=True))
    return 1 if args.strict and report["counts"]["disagreement"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
