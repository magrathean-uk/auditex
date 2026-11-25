"""Shipped Google Workspace value-rule catalogue (ScubaGoggles v1.1.0, design M13 sections 5.3 and 8).

The main file ``configs/scuba-gws-value-rules.json`` pins the ScubaGoggles release and commit, the 138 policy ids,
the shared reasons, ``section_semantics`` and the fragment list; each fragment adds ``kinds`` and ``policies``. Cells
are defined once per kind. The loader resolves every row's cells through its kind, so a loaded row has the same
``cells`` shape as an M365 row and ``reason_matches``, ``citation_variants`` and ``cell_entry`` apply unchanged.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from functools import lru_cache
from hashlib import sha256
from itertools import combinations
from typing import Any

from azure_tenant_audit.resources import open_text_resource

from ..catalogue import _CELL_KEYS, _ID, _SHARED_REASONS, _check_evidence
from ..record import SECTION_NOT_COLLECTED

MAIN = "configs/scuba-gws-value-rules.json"
SCUBAGOGGLES_VERSION = "v1.1.0"
SCUBAGOGGLES_COMMIT = "08a08ce145178582284d81ab1f3625987f3ad66b"
FRAGMENTS = tuple(f"configs/scuba-gws-rules-{name}.json" for name in (
    "setting-core", "setting-collab", "multi", "identity", "lists", "events", "dns"))
# The projection's six sections (design section 7); a row reads only these.
PROJECTION_SECTIONS = frozenset({"gws_tenant", "gws_policies", "gws_setting_events", "gws_dns", "gws_admins",
                                 "gws_sso"})
REDUCERS = frozenset({"max", "merge", "list", "max_map"})
FIELD_TYPES = frozenset({"bool", "dict", "enum", "int", "list_dict", "list_strings", "state", "string", "duration",
                         "timestamp"})
POLICY_ID = re.compile(r"GWS\.[A-Z]+\.\d+\.\d+v\d+")
# SHA-256 of the sorted 138 ids of ScubaGoggles v1.1.0 (design section 14), compact JSON.
_POLICY_IDS_SHA256 = "aeb10c99ce16c80ebeee9ac326b55c10185820e2863e2f152602fc33c5bce5dc"
_SRC = re.compile(r"SG:scubagoggles/(policy_api\.py|rego/[A-Z][a-z]+\.rego):\d+")
_SECTION_KEY = re.compile(r"[a-z][a-z0-9_]{0,95}")
_MAIN_KEYS = {"schema_version", "scubagoggles_version", "scubagoggles_commit", "source", "shared_reasons",
              "policy_ids", "fragments", "section_semantics", "kinds", "policies"}
_ROW_KEYS = {"kind", "rule_id", "sections", "params"}
_KIND_KEYS = {"cells", "evidence_free"}


def _fail(message: str):
    raise ValueError(message)


def _missing_text(cited: list[str]) -> str:
    return "Data unavailable: required evidence section(s) not collected: " + ", ".join(cited) + "."


def _section_semantics(entries: Any) -> None:
    if not isinstance(entries, dict) or not entries:
        _fail("Invalid GWS section semantics")
    for key, entry in entries.items():
        fields = entry.get("fields") if isinstance(entry, dict) else None
        if (not _SECTION_KEY.fullmatch(key) or not isinstance(entry, dict)
                or set(entry) - {"reducer", "fields", "key", "default", "src", "default_src", "outside_expected_table"}
                or entry.get("reducer") not in REDUCERS or not isinstance(entry.get("src"), str)
                or not _SRC.fullmatch(entry["src"]) or not isinstance(fields, dict) or not fields
                or any(not isinstance(name, str) or kind not in FIELD_TYPES for name, kind in fields.items())
                or ("key" in entry) != (entry["reducer"] == "max_map")
                or (entry["reducer"] == "max_map" and (not isinstance(entry["key"], str) or len(fields) != 1))
                or entry.get("outside_expected_table", False) not in (True, False)):
            _fail("Invalid GWS section semantics")
        if ("default" in entry) != ("default_src" in entry):
            _fail("Invalid GWS section default")
        if "default" in entry and (not isinstance(entry["default"], dict) or not entry["default"]
                                   or set(entry["default"]) - set(fields) or entry["reducer"] not in {"max", "merge"}
                                   or not isinstance(entry["default_src"], str)
                                   or not _SRC.fullmatch(entry["default_src"])):
            _fail("Invalid GWS section default")


def _check_cell(cell: str, entry: Any) -> None:
    if (not re.fullmatch(_ID, cell) or not isinstance(entry, dict) or set(entry) - _CELL_KEYS
            or {"reason_codes", "reason_texts_by_code"} & entry.keys()
            or entry.get("verdict") not in {"met", "not_met", "not_assessed", "not_applicable"}
            or cell in _SHARED_REASONS or not isinstance(entry.get("reason_code"), str)
            or not re.fullmatch(_ID, entry["reason_code"])):
        _fail("Invalid GWS value-rule cell")
    if cell == "section_not_collected":
        if ({"cited", "cited_variants", "reason_texts"} & entry.keys() or entry["verdict"] != "not_assessed"
                or entry["reason_code"] != SECTION_NOT_COLLECTED):
            _fail("Invalid GWS value-rule cell")
        return
    if entry["reason_code"] == SECTION_NOT_COLLECTED:
        _fail("Invalid GWS value-rule cell")
    texts = entry.get("reason_texts")
    if (not isinstance(texts, list) or not texts
            or any(not isinstance(text, str) or not 0 < len(text) <= 400 for text in texts)
            or texts != sorted(set(texts))):
        _fail("Incomplete GWS value-rule cell")
    if "cited_variants" in entry and entry["verdict"] != "not_assessed":
        _fail("Invalid GWS value-rule cell citation")


def _check_kind(name: str, kind: Any) -> None:
    if not re.fullmatch(_ID, name) or not isinstance(kind, dict) or set(kind) - _KIND_KEYS:
        _fail("Invalid GWS value-rule kind")
    cells = kind.get("cells")
    evidence_free = kind.get("evidence_free", False)
    if not isinstance(cells, dict) or not cells or evidence_free not in (True, False):
        _fail("Invalid GWS value-rule kind")
    for cell, entry in cells.items():
        _check_cell(cell, entry)
    # A gated kind answers section_not_collected; an evidence-free kind (manual checks) answers the same way on any
    # evidence and has no gate, so it can never answer anything but not_assessed.
    if evidence_free == ("section_not_collected" in cells):
        _fail("Invalid GWS value-rule kind gate")
    if evidence_free and any(entry["verdict"] != "not_assessed" for entry in cells.values()):
        _fail("Invalid GWS value-rule kind gate")


def _resolve(row: dict, kind: dict) -> dict[str, dict]:
    """The row's cells: the kind's constants with the citations bound to the row's sections."""
    sections = row["sections"]
    resolved = {}
    for cell, entry in kind["cells"].items():
        entry = json.loads(json.dumps(entry))
        if cell == "section_not_collected":
            subsets = [list(chosen) for size in range(1, len(sections) + 1)
                       for chosen in combinations(sections, size)]
            entry["cited"] = list(sections)
            entry["reason_texts"] = sorted(_missing_text(cited) for cited in subsets)
        else:
            entry.setdefault("cited", list(sections))
            variants = entry.get("cited_variants", [entry["cited"]])
            if (not isinstance(variants, list) or not variants or entry["cited"] not in variants
                    or len({tuple(v) if isinstance(v, list) else None for v in variants}) != len(variants)
                    or any(not isinstance(cited, list) or not cited or len(set(cited)) != len(cited)
                           or any(not isinstance(name, str) for name in cited)
                           or cited != [name for name in sections if name in cited] for cited in variants)):
                _fail("Invalid GWS value-rule cell citation")
        _check_evidence(row["rule_id"], cell, entry)
        resolved[cell] = entry
    return resolved


def _load(read: Callable[[str], str]) -> dict[str, Any]:
    data = json.loads(read(MAIN))
    if (not isinstance(data, dict) or set(data) != _MAIN_KEYS or data["schema_version"] != 1
            or data["scubagoggles_version"] != SCUBAGOGGLES_VERSION
            or data["scubagoggles_commit"] != SCUBAGOGGLES_COMMIT):
        _fail("Invalid GWS value-rule catalogue")
    if data["shared_reasons"] != _SHARED_REASONS:
        _fail("Invalid GWS value-rule shared reasons")
    ids = data["policy_ids"]
    if (not isinstance(ids, list) or any(not isinstance(i, str) or not POLICY_ID.fullmatch(i) for i in ids)
            or len(set(ids)) != len(ids)
            or sha256(json.dumps(sorted(ids), separators=(",", ":")).encode()).hexdigest() != _POLICY_IDS_SHA256):
        _fail("Invalid GWS value-rule policy ids")
    if data["fragments"] != list(FRAGMENTS):
        _fail("Invalid GWS value-rule fragments")
    _section_semantics(data["section_semantics"])
    kinds: dict[str, dict] = {}
    rows: dict[str, dict] = {}
    parts = [data] + [json.loads(read(path)) for path in FRAGMENTS]
    for index, part in enumerate(parts):
        if index and (not isinstance(part, dict) or set(part) != {"kinds", "policies"}):
            _fail("Invalid GWS value-rule fragment")
        if not isinstance(part["kinds"], dict) or not isinstance(part["policies"], dict):
            _fail("Invalid GWS value-rule fragment")
        for name, kind in part["kinds"].items():
            if name in kinds:
                _fail("GWS value-rule kind is defined twice")
            _check_kind(name, kind)
            kinds[name] = kind
        for policy_id, row in part["policies"].items():
            if policy_id in rows:
                _fail("GWS value-rule policy is defined twice")
            rows[policy_id] = row
    known = set(ids)
    policies = {}
    for policy_id, row in rows.items():
        if not POLICY_ID.fullmatch(policy_id) or policy_id not in known:
            _fail("Invalid GWS value-rule policy")
        if (not isinstance(row, dict) or set(row) != _ROW_KEYS or row["kind"] not in kinds
                or row["rule_id"] != f"{policy_id}.{row['kind']}" or not isinstance(row["params"], dict)):
            _fail("Invalid GWS value-rule policy")
        sections = row["sections"]
        if (not isinstance(sections, list) or not sections or len(set(sections)) != len(sections)
                or any(name not in PROJECTION_SECTIONS for name in sections)):
            _fail("Invalid GWS value-rule sections")
        policies[policy_id] = {**row, "cells": _resolve(row, kinds[row["kind"]])}
    return {"schema_version": 1, "scubagoggles_version": data["scubagoggles_version"],
            "scubagoggles_commit": data["scubagoggles_commit"], "policy_ids": tuple(ids),
            "shared_reasons": data["shared_reasons"], "section_semantics": data["section_semantics"],
            "kinds": kinds, "policies": policies}


@lru_cache(maxsize=1)
def catalogue() -> dict[str, Any]:
    return _load(open_text_resource)


def row_for(policy_id: str) -> dict[str, Any] | None:
    return catalogue()["policies"].get(policy_id)


def rule_policies() -> tuple[str, ...]:
    return tuple(catalogue()["policies"])


def policy_ids() -> tuple[str, ...]:
    """Every ScubaGoggles v1.1.0 policy id; a policy here without a row answers ``rule_not_implemented``."""
    return catalogue()["policy_ids"]


def cells_for(policy_id: str) -> tuple[str, ...]:
    row = row_for(policy_id)
    return tuple(row["cells"]) if row else ()


def kind_cells(kind: str) -> tuple[str, ...]:
    return tuple(catalogue()["kinds"][kind]["cells"])


def is_evidence_free(kind: str) -> bool:
    return catalogue()["kinds"][kind].get("evidence_free", False) is True


def section_semantics(section: str) -> dict[str, Any]:
    """The pinned reducer, fields and default of one section key; an unknown key is a programming error."""
    entry = catalogue()["section_semantics"].get(section)
    if entry is None:
        raise ValueError("Unknown GWS policy section")
    return entry


def shared_reason(code: str) -> dict[str, Any]:
    return catalogue()["shared_reasons"][code]
