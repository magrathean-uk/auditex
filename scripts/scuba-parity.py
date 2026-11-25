#!/usr/bin/env python3
"""Compare CISA's SCuBA tool verdicts with Auditex's SCuBA answers, policy by policy; internal, not shipped.

Inputs: a ScubaGear ``ScubaResults_*.json`` or a ScubaGoggles ``ScubaResults*.json`` (auto-detected and validated)
and an Auditex run folder or ``model_assessment.json``. With ``--same-input`` (ScubaGear only) Auditex's rules are run
on the export embedded in the same ScubaResults file, so every difference is a rule difference. Writes
``scuba-parity.json`` and ``scuba-parity.md`` into a new or empty ``--out`` directory; neither copies tenant names,
ids, domains, details text or paths. No tenant contact. Same-input mode runs the adapter in a private temporary
directory, reads its assessment in memory and removes the directory before returning, so nothing from the export
lands in ``--out``.

Exit codes: 0 compared; 1 compared with ``--strict`` and at least one ``disagreement`` or ``auditex_row_invalid``;
2 unusable input.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from azure_tenant_audit.argument_parser import build_argument_parser  # noqa: E402

MAX_INPUT_BYTES = 64 * 1024 * 1024
DIVERGENCE_FILE = Path(__file__).with_name("scuba-parity-divergences.json")
OUTPUT_JSON, OUTPUT_MD = "scuba-parity.json", "scuba-parity.md"
OUTPUT_SCHEMA = "auditex-scuba-parity/2"
REPAIR_MARKER = "__scuba_parity_repair_marker_7c2e__"

MS_ID = re.compile(r"MS\.[A-Z]+\.\d+\.\d+v\d+", re.ASCII)
GWS_ID = re.compile(r"GWS\.[A-Z]+\.\d+\.\d+v\d+", re.ASCII)
REASON_CODE = re.compile(r"[a-z][a-z0-9_.]{0,63}", re.ASCII)
VERSION = re.compile(r"\d+(?:\.\d+){1,3}", re.ASCII)
CONFIGS = Path(__file__).resolve().parents[1] / "configs"
PRECHECK_CLASSES = frozenset({"closed_gate", "absent_section", "absent_field", "empty_required_list", "value_rule"})
UNLISTED_REASON = "unlisted_reason_code"

# Each CISA tool, the release whose verdicts parity compares against, and the rule oracle the Auditex rules were
# written from. The value-rules spec v3.9.1 replays the ScubaGear Rego at commit 2446ad72 (module 2.0.0, an
# ancestor of tag v2.0.0 eight commits behind it, same seven products: AAD, EXO, Security Suite, SharePoint, Teams,
# Power Platform, Power BI). That is not the framework mapping's "ScubaGear v1.8.0 baselines" catalogue entry, whose
# v1.8.0 product set has Defender instead of Security Suite. ScubaGoggles v1.1.0 is the M13 oracle. A result from
# another release is compared, flagged, and never reported as matching.
TOOLS = {
    "ScubaGear": {"platform": "m365", "id": MS_ID, "pinned": "2.0.0",
                  "rule_reference": "cisagov/ScubaGear@2446ad723b7f55031cc02c8aca244d731d468cba"},
    "ScubaGoggles": {"platform": "gws", "id": GWS_ID, "pinned": "1.1.0", "rule_reference": "cisagov/ScubaGoggles@v1.1.0"},
}
# Verdict pairs on which the pinned release is known to differ from the rule oracle, each with a cited reason. A pair is
# labelled release_delta only when the CISA tool's version is the pinned one and the policy, the CISA class and the
# Auditex verdict all match an entry here; every other non-agreement stays a disagreement, and an Error row is never
# matched (name only the classes in DIVERGENCE_CISA). ScubaGear 2446ad72..v2.0.0 changed MS.AAD.3.2v2 (#2515, exclusions
# read), MS.AAD.5.5v1 (#2513, a missing password-addition restriction in either scope), MS.AAD.5.6v1 (the same change
# through the lifetime check) and MS.AAD.9.1v1 (#2522, agent exclusions and the no-licence N/A). Each effect depends on
# the export, not on a verdict pair, so none can be named from verdicts alone: a difference on those policies is a
# disagreement until it is explained against the exact rule revision, and an entry is added only with that proof.
RELEASE_DELTAS: dict[str, tuple[dict[str, Any], ...]] = {"ScubaGear": (), "ScubaGoggles": ()}

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
# The CISA classes a divergence entry may name: the decisions, a manual check (ScubaGear N/A) and no events
# (ScubaGoggles). Error, deleted, overlay and conflicting rows are never a documented divergence.
DIVERGENCE_CISA = frozenset({"pass", "fail", "manual", "no_events"})
CISA_CLASSES = frozenset(CISA_RESULTS.values()) | frozenset(CISA_OVERLAYS.values()) | {"conflicting_rows"}

AUDITEX_VERDICTS = ("met", "not_met", "not_applicable", "not_assessed")
RULE_REASONS = {"rule_not_implemented", "policy_not_in_catalogue"}
NOT_A_RULE_ANSWER = "not_a_rule_answer"
INVALID_ROW, INVALID_CODE = "invalid", "row_invalid"

CATEGORIES = (
    "disagreement",                 # both decided, opposite answers, not documented: needs a look
    "auditex_row_invalid",          # the Auditex row fails the writer's own checks: unusable, never a verdict
    "auditex_not_assessed",         # CISA decided, Auditex did not: unknown is not safe, but find out why
    "auditex_decided",              # CISA could not decide, Auditex did
    "documented_divergence",        # a non-agreement that matches a documented D row
    "release_delta",                # a non-agreement matching a cited release-delta pair of the pinned release
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


def _read_bytes(path: Path, key: str) -> bytes:
    """Read one regular file (no links), at most 64 MiB."""
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
    return payload


def _read_json(path: Path, key: str) -> Any:
    """Strict JSON with no duplicate keys or NaN."""
    payload = _read_bytes(path, key)
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


class _Keys(dict):
    """A JSON object that remembers which keys it saw more than once (the last value wins, as in the adapter)."""

    def __init__(self, pairs: list[tuple[str, Any]]):
        super().__init__()
        self.duplicates: set[str] = set()
        for key, value in pairs:
            if key in self:
                self.duplicates.add(key)
            self[key] = value


def _parse_cisa(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_Keys, parse_constant=_reject_constant)


def _holds(node: Any, marker: str) -> bool:
    if node == marker:
        return True
    if isinstance(node, dict):
        return any(_holds(child, marker) for child in node.values())
    if isinstance(node, list):
        return any(_holds(child, marker) for child in node)
    return False


def _adapter_duplicates(document: Any) -> bool | None:
    """The one duplicate key the adapter accepts: ``accepted_domains`` directly in ``Raw`` (the EXO and Security Suite
    exporters both write it). Any other duplicate, anywhere, is refused (None); else whether the exception was used."""
    used = False
    stack = [(document, False)]
    while stack:
        node, is_raw = stack.pop()
        if isinstance(node, _Keys):
            extra = node.duplicates - ({"accepted_domains"} if is_raw else set())
            if extra:
                return None
            used = used or bool(node.duplicates)
            stack.extend((child, node is document and key == "Raw") for key, child in node.items())
        elif isinstance(node, list):
            stack.extend((child, False) for child in node)
    return used


def _cisa_document(path: Path) -> tuple[Any, bool, bool]:
    """Strict JSON, else the export adapter's one allowed repair: PowerShell writes an empty array as nothing
    (``"key": ,``). The repair is accepted only inside the embedded export ``Raw``; one in ``Results``, ``MetaData`` or
    anywhere else is refused. ``MetaData`` is read from the file itself either way."""
    payload = _read_bytes(path, "cisa")
    try:
        text = payload.decode("utf-8-sig")
        try:
            document, repaired = _parse_cisa(text), False
        except json.JSONDecodeError:
            from auditex.scubagear_export import _REPAIR, _matches_inside_strings
            matches = list(_REPAIR.finditer(text))
            if not matches or REPAIR_MARKER in text or _matches_inside_strings(text, matches):
                raise ParityError("cisa") from None
            marked = _parse_cisa(_REPAIR.sub(lambda match: match[1] + json.dumps(REPAIR_MARKER), text))
            if (not isinstance(marked, dict) or not isinstance(marked.get("Raw"), dict)
                    or any(_holds(value, REPAIR_MARKER) for key, value in marked.items() if key != "Raw")):
                raise ParityError("cisa") from None
            document, repaired = _parse_cisa(_REPAIR.sub(lambda match: match[1] + "[]", text)), True
    except (UnicodeError, ValueError, RecursionError):
        raise ParityError("cisa") from None
    duplicated = _adapter_duplicates(document)
    if duplicated is None:
        raise ParityError("cisa")
    return document, repaired, duplicated


def load_cisa(path: Path) -> dict[str, Any]:
    """Validate a ScubaResults file and return its tool, version and per-policy verdicts."""
    document, repaired, duplicated = _cisa_document(path)
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
    if tool != "ScubaGear" and (repaired or duplicated):
        raise ParityError("cisa")  # the two parser exceptions are the ScubaGear export adapter's, not ScubaGoggles'
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


# The verdicts each rule pre-check class can carry, as ``precheck_response`` renders them: a closed gate is
# inferred not applicable, an empty required list is confirmed not met, an absent section or field is unknown.
CLASS_VERDICTS = {
    "value_rule": frozenset({"met", "not_met", "not_applicable", "not_assessed"}),
    "closed_gate": frozenset({"not_applicable"}),
    "empty_required_list": frozenset({"not_met"}),
    "absent_section": frozenset({"not_assessed"}),
    "absent_field": frozenset({"not_assessed"}),
}


def _claim_verdict(requirement: dict[str, Any], limitations: list[str]) -> str:
    """``value_rule_verdict``: the public verdict from the requirement claim."""
    status, value = requirement["status"], requirement["value"]
    if status == "unknown" and value is None:
        return "not_assessed"
    if status == "inferred" and value is True and "policy_not_applicable" in limitations:
        return "not_applicable"
    if status == "confirmed" and type(value) is bool:
        return "met" if value else "not_met"
    raise ParityError("auditex")


def _auditex_verdict(record: dict[str, Any], version: str) -> tuple[str, str]:
    """(verdict, reason code) for one schema-checked policy row. Only a value-rule answer whose row and provenance
    hold the writer's contract (``validate_assessment``) counts as decided; anything else is refused, never mapped."""
    from azure_tenant_audit.scuba_assessment import _CURRENT
    reason, claims = record["reason"], record["claims"]
    if reason in RULE_REASONS:
        if any(claim["status"] != "unknown" or claim["value"] is not None for claim in claims):
            raise ParityError("auditex")
        return "not_assessed", reason
    if reason != "rule_precheck":
        # A model-era row, an endpoint failure or anything else that is not a value-rule answer.
        return "not_assessed", NOT_A_RULE_ANSWER
    detail = record.get("rule_precheck")
    if (not isinstance(detail, dict) or record["validation_status"] != "valid" or record["attempts"] != 0
            or record["latency_ms"] != 0 or record["prompt_sha256"] is not None or record["response_sha256"] is not None
            or record.get("thinking_disabled") or record.get("thinking_stripped")):
        raise ParityError("auditex")
    rule_class = detail["class"]
    if rule_class == "value_rule" and version not in _CURRENT:
        raise ParityError("auditex")
    code = detail.get("reason_code", rule_class)
    if not isinstance(code, str) or not REASON_CODE.fullmatch(code):
        raise ParityError("auditex")
    if len(claims) != 2 or {claim["id"] for claim in claims} != {"requirement_met", "policy_criticality"}:
        raise ParityError("auditex")
    for claim in claims:
        if claim["status"] == "unknown":
            if claim["value"] is not None:
                raise ParityError("auditex")
        elif "e0" not in claim["evidence_ids"]:
            raise ParityError("auditex")  # a known claim cites its evidence
    requirement = next(claim for claim in claims if claim["id"] == "requirement_met")
    verdict = _claim_verdict(requirement, record["limitations"])
    if verdict not in CLASS_VERDICTS[rule_class]:
        raise ParityError("auditex")
    return verdict, code


def _value_rule_row_holds(record: dict[str, Any], version: str) -> bool:
    """The writer's own semantic and citation checks for one current-schema Microsoft 365 value-rule row
    (``validate_assessment``): the catalogue cell, its reason, its citation, and the claims, limitations and
    recommendations the cell implies, all together. A row that fails them is not a verdict."""
    from azure_tenant_audit.resources import open_text_resource
    from azure_tenant_audit.scuba_assessment import _LATE_EVIDENCE, _legacy_safelinks_cell
    from azure_tenant_audit.scuba_precheck import precheck_response
    from azure_tenant_audit.value_rules.catalogue import cell_entry, citation_variants, reason_matches, row_for, shared_reason
    from azure_tenant_audit.value_rules.record import RULE_FAILURE_CODE, RULE_NOT_IMPLEMENTED_CODE, is_shared_reason
    try:
        detail, policy_id = record["rule_precheck"], record["policy_id"]
        policy = json.loads(open_text_resource("configs/scuba-policy-sections.json"))["policies"].get(policy_id)
        value_row = row_for(policy_id)
        if policy is None or value_row is None or not {"cell", "reason_code", "reason_text"} <= detail.keys():
            return False
        name = detail["cell"]
        if name in {RULE_FAILURE_CODE, RULE_NOT_IMPLEMENTED_CODE}:
            return False
        if name is None:
            if not is_shared_reason(detail["reason_code"]) or detail["rule_id"] != value_row["rule_id"]:
                return False
            shared = shared_reason(detail["reason_code"])
            cell = {"verdict": shared["verdict"], "reason_code": shared["reason_code"],
                    "reason_texts": [shared["reason_text"]], "cited": list(value_row["sections"])}
        else:
            cell = cell_entry(policy_id, name, value_row)
        cell = _legacy_safelinks_cell(version, policy_id, detail, value_row, cell)
        section = detail["section"]
        if (cell is None or detail["rule_id"] != value_row["rule_id"]
                or not reason_matches(cell, detail["reason_code"], detail["reason_text"])
                or detail["field"] is not None or detail["value"] is not None
                or not set(section) <= set(value_row["sections"])
                or (section != [s for s in value_row["sections"] if s in section]
                    and section not in citation_variants(cell))):
            return False
        if cell["verdict"] == "not_assessed" and name == "section_not_collected":
            if detail["reason_text"] != ("Data unavailable: required evidence section(s) not collected: "
                                         + ", ".join(section) + "."):
                return False
        elif section not in citation_variants(cell):
            return False
        late = version in _LATE_EVIDENCE
        for legacy in (False, True):
            for form in ([late, False] if late else [False]):
                answer = precheck_response(detail, policy["policy_item"], policy["sections"], legacy=legacy,
                                           verdict=cell["verdict"], late_evidence=form)
                if all(record[key] == answer[key] for key in answer):
                    return True
        return False
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return False


def known_reason_codes() -> frozenset[str]:
    """Every reason code the shipped rule configs name, the precheck classes and the fixed rule reasons. A code
    outside this set is reported as ``unlisted_reason_code``, so free text in an assessment never reaches the
    report."""
    codes: set[str] = set(PRECHECK_CLASSES) | RULE_REASONS | {NOT_A_RULE_ANSWER, INVALID_CODE}

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


def _row_schema(version: str, gws: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    """The policy-row schema of the assessment's own (possibly historical) contract. The GWS writer lands with M13;
    until then a GWS row is held to the same row contract with the GWS id pattern."""
    from azure_tenant_audit.scuba_assessment import ASSESSMENT_SCHEMAS
    try:
        schema = json.loads((Path(__file__).resolve().parents[1] / ASSESSMENT_SCHEMAS[version]).read_text("utf-8"))
        row = schema["$defs"]["policy"]
        if gws:
            row = {**row, "properties": {**row["properties"], "policy_id": {"type": "string",
                                                                           "pattern": "^" + GWS_ID.pattern + "$"}}}
    except (OSError, ValueError, KeyError, TypeError):
        raise ParityError("auditex") from None
    return schema, row


def load_auditex(path: Path | None = None, *, document: Any = None) -> dict[str, dict[str, str]]:
    from azure_tenant_audit.scuba_assessment import ASSESSMENT_SCHEMAS, _check
    if document is None:
        try:
            if path.is_dir() and not path.is_symlink():
                path = path / "model_assessment.json"
        except OSError:
            raise ParityError("auditex") from None
        document = _read_json(path, "auditex")
    if not isinstance(document, dict):
        raise ParityError("auditex")
    version, policies = document.get("schema_version"), document.get("policies")
    if not isinstance(version, str) or version not in ASSESSMENT_SCHEMAS or not isinstance(policies, list) or not policies:
        raise ParityError("auditex")
    schemas = {}
    rows: dict[str, dict[str, str]] = {}
    for record in policies:
        policy_id = record.get("policy_id") if isinstance(record, dict) else None
        if (not isinstance(policy_id, str) or policy_id in rows
                or not (MS_ID.fullmatch(policy_id) or GWS_ID.fullmatch(policy_id))):
            raise ParityError("auditex")
        gws = bool(GWS_ID.fullmatch(policy_id))
        if gws not in schemas:
            schemas[gws] = _row_schema(version, gws)
        schema, row_schema = schemas[gws]
        try:
            _check(record, row_schema, schema, "policy")
        except (ValueError, KeyError, TypeError, RecursionError):
            raise ParityError("auditex") from None
        verdict, code = _auditex_verdict(record, version)
        # The Google Workspace writer lands with M13; until then its rows meet the row contract above and nothing more.
        if (not gws and record["reason"] == "rule_precheck" and record["rule_precheck"]["class"] == "value_rule"
                and not _value_rule_row_holds(record, version)):
            verdict, code = INVALID_ROW, INVALID_CODE
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
    def strings(value: Any, allowed: Any) -> bool:
        """A non-empty list of strings, each allowed; types are checked before any set or regex use."""
        return (isinstance(value, list) and bool(value) and all(isinstance(item, str) for item in value)
                and all(allowed(item) for item in value))

    for entry in entries:
        ok = (isinstance(entry, dict)
              and set(entry) in ({"policy_id", "id", "cite", "cisa", "auditex"},
                                 {"policy_id", "id", "cite", "cisa", "auditex", "reason_codes"})
              and isinstance(entry["policy_id"], str)
              and bool(MS_ID.fullmatch(entry["policy_id"]) or GWS_ID.fullmatch(entry["policy_id"]))
              and isinstance(entry["id"], str) and re.fullmatch(r"D\d{1,3}", entry["id"]) is not None
              and isinstance(entry["cite"], str) and entry["cite"].split(" ", 1)[0] in sources
              and entry["cite"].endswith(" " + entry["id"])
              and strings(entry["cisa"], DIVERGENCE_CISA.__contains__)
              and strings(entry["auditex"], set(AUDITEX_VERDICTS).__contains__)
              and ("reason_codes" not in entry
                   or strings(entry["reason_codes"], lambda code: REASON_CODE.fullmatch(code) is not None)))
        if not ok:
            raise ParityError("divergences")
    return entries


def matching_divergences(entries: list[dict[str, Any]], policy_id: str, cisa: str, auditex: str,
                         reason_code: str) -> list[str]:
    found = {entry["id"] for entry in entries
             if entry["policy_id"] == policy_id and cisa in entry["cisa"] and auditex in entry["auditex"]
             and ("reason_codes" not in entry or reason_code in entry["reason_codes"])}
    return sorted(found, key=lambda did: int(did[1:]))


# ---------------------------------------------------------------------------------------------------------------
# Comparison


def categorise(cisa: str, auditex: str, divergences: list[str], release_delta: bool = False) -> str:
    if auditex == INVALID_ROW:
        return "auditex_row_invalid"
    cisa_decided, auditex_decided = cisa in CISA_DECIDED, auditex != "not_assessed"
    if (cisa == "pass" and auditex in {"met", "not_applicable"}) or (cisa == "fail" and auditex == "not_met"):
        return "agree"
    if not cisa_decided and not auditex_decided:
        return "neither_decided"
    if divergences:
        return "documented_divergence"
    if release_delta:
        return "release_delta"
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
    version_matches = cisa["version"] == tool["pinned"]
    deltas = RELEASE_DELTAS[cisa["tool"]] if version_matches else ()
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
            delta = any(item["policy_id"] == policy_id and c["verdict"] in item["cisa"]
                        and a["verdict"] in item["auditex"] for item in deltas)
            row["category"] = categorise(c["verdict"], a["verdict"], row["divergences"], delta)
            if row["category"] != "documented_divergence":
                row["divergences"] = []
        rows.append(row)
    counts = {category: sum(row["category"] == category for row in rows) for category in CATEGORIES}
    return {"schema": OUTPUT_SCHEMA, "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "mode": mode, "cisa_tool": cisa["tool"], "cisa_tool_version": cisa["version"],
            "cisa_input_repaired": cisa["repaired"],
            "pinned_version": tool["pinned"], "rule_reference": tool["rule_reference"],
            "version_matches": version_matches, "release_delta_policies": sorted({item["policy_id"] for item in deltas}),
            # Never a claim of full parity when the release differs, ids sit on one side only, or any row is a
            # disagreement or an unusable Auditex row (the same rows that make --strict exit 1).
            "full_parity": (version_matches and not counts["cisa_only"] and not counts["auditex_only"]
                            and not counts["disagreement"] and not counts["auditex_row_invalid"]),
            "counts": counts, "rows": rows}


def render_markdown(report: dict[str, Any]) -> str:
    version = report["cisa_tool_version"] or "unknown"
    lines = [f"# SCuBA parity: {report['cisa_tool']} and Auditex", "",
             f"Mode: {report['mode']}. {report['cisa_tool']} version {version}; parity is pinned to "
             f"{report['pinned_version']} (rule reference {report['rule_reference']})"
             + ("." if report["version_matches"] else ", so differences may come from the release gap and this is "
                                                      "not a parity result."),
             "Policies with a cited release-delta verdict pair: "
             + (", ".join(report["release_delta_policies"]) or "none") + ".",
             "Full parity: " + ("yes" if report["full_parity"] else "no (see disagreement, auditex_row_invalid, "
                                                                   "cisa_only, auditex_only and the version line)") + ".",
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


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())


def _write_outputs(out: Path, files: dict[str, str]) -> None:
    """Each file goes to a unique temporary name, then is linked to its final name, which fails rather than replace
    an existing file (an atomic no-clobber rename). On failure only this invocation's files are removed."""
    created: list[Path] = []
    try:
        for name, text in files.items():
            temporary = out / f".{name}.{secrets.token_hex(8)}.tmp"
            try:
                _write_private(temporary, text)
                os.link(temporary, out / name, follow_symlinks=False)
                created.append(out / name)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
    except OSError:
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        raise ParityError("write") from None


def _same_input_assessment(cisa_path: Path) -> dict[str, dict[str, str]]:
    """Run the adapter in a private temporary directory, keep its assessment in memory only, and remove the
    directory before returning: nothing from the export reaches ``--out``."""
    from auditex.rule_assessment import assess_scubagear_export
    try:
        scratch = Path(tempfile.mkdtemp(prefix="scuba-parity-")).resolve()
    except OSError:
        raise ParityError("adapter") from None
    try:
        try:
            document = assess_scubagear_export(cisa_path, scratch / "assessment")
        except Exception:  # noqa: BLE001 - any adapter fault is one fixed message; its text can hold export content
            raise ParityError("adapter") from None
        return load_auditex(document=document)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser(description="Compare CISA SCuBA tool verdicts with Auditex's SCuBA answers.")
    parser.add_argument("cisa_results", metavar="CISA_RESULTS")
    parser.add_argument("auditex", metavar="AUDITEX_RUN_OR_ASSESSMENT", nargs="?")
    parser.add_argument("--same-input", action="store_true",
                        help="run Auditex's rules on the export embedded in the ScubaGear result")
    parser.add_argument("--out", required=True, metavar="DIR")
    parser.add_argument("--strict", action="store_true", help="exit 1 when any row is a disagreement or an unusable Auditex row")
    args = parser.parse_args(argv)
    if args.same_input == (args.auditex is not None):
        parser.error("give an Auditex run or assessment, or --same-input, not both")
    try:
        entries = load_divergences()
        cisa_path, out = Path(args.cisa_results), Path(args.out)
        cisa = load_cisa(cisa_path)
        if args.same_input and (cisa["tool"] != "ScubaGear" or not cisa["has_raw"]):
            raise ParityError("same_input")
        auditex = _same_input_assessment(cisa_path) if args.same_input else load_auditex(Path(args.auditex))
        check_platform(cisa, auditex)
        _prepare_out(out)
        known = known_reason_codes() | {code for entry in entries for code in entry.get("reason_codes", [])}
        for row in auditex.values():
            if row["reason_code"] not in known:
                row["reason_code"] = UNLISTED_REASON
        report = compare(cisa, auditex, entries, mode="same-input" if args.same_input else "two-input")
        _write_outputs(out, {OUTPUT_JSON: json.dumps(report, indent=2, sort_keys=True) + "\n",
                             OUTPUT_MD: render_markdown(report)})
    except ParityError as exc:
        print(f"scuba-parity: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"mode": report["mode"], "cisa_tool": report["cisa_tool"], "counts": report["counts"],
                      "version_matches": report["version_matches"], "full_parity": report["full_parity"]},
                     sort_keys=True))
    return 1 if args.strict and (report["counts"]["disagreement"] or report["counts"]["auditex_row_invalid"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
