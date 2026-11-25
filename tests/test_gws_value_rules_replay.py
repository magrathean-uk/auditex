"""GWS vectors replay and coverage (design M13 section 10.1), generic over every fragment's vector file.

Each line of ``tests/fixtures/gws-value-rules/*.jsonl`` is ``{"vector_id", "policy", "sections", "verdict", "cell",
"reason_code"}`` with literal expectations. Every vector replays through ``gws.assess`` (which applies
``checked_gws``), ``checked_gws`` again and ``as_pack_response``. Every cell of every catalogued kind is reached by a
vector of a policy using that kind, and every policy with a row has met, not_met and not_assessed vectors; an
evidence-free kind (the manual checks) is exempt from met and not_met.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from azure_tenant_audit.value_rules import gws
from azure_tenant_audit.value_rules.gws.catalogue import catalogue
from azure_tenant_audit.value_rules.record import (
    LIMIT_UNUSABLE,
    REC_BY_KIND,
    SECTION_NOT_COLLECTED,
)

VECTOR_DIR = Path(__file__).parent / "fixtures" / "gws-value-rules"
_KEYS = {"vector_id", "policy", "sections", "verdict", "cell", "reason_code"}
_OPTIONAL = {"divergence", "note"}


def _vectors() -> list[dict]:
    vectors = []
    for path in sorted(VECTOR_DIR.glob("*.jsonl")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip():
                vector = json.loads(line)
                vector["_where"] = f"{path.name}:{number}"
                vectors.append(vector)
    return vectors


VECTORS = _vectors()


def test_vector_files_are_well_formed():
    assert VECTORS
    ids = [vector["vector_id"] for vector in VECTORS]
    assert len(ids) == len(set(ids))
    for vector in VECTORS:
        keys = set(vector) - {"_where"}
        assert _KEYS <= keys and not keys - _KEYS - _OPTIONAL, vector["_where"]
        assert isinstance(vector["sections"], dict), vector["_where"]


@pytest.mark.parametrize("vector", VECTORS, ids=[vector["vector_id"] for vector in VECTORS])
def test_vector_replays(vector):
    record = gws.assess(vector["policy"], json.loads(json.dumps(vector["sections"])))
    assert record is not None, vector["_where"]
    assert (record["verdict"], record["cell"], record["reason_code"]) == (
        vector["verdict"], vector["cell"], vector["reason_code"]), vector["_where"]
    assert gws.checked_gws(record) is record
    row = catalogue()["policies"][vector["policy"]]
    response = gws.as_pack_response(record, "SHOULD", list(row["sections"]))
    claim = response["claims"][0]
    if record["verdict"] == "not_assessed":
        entry = row["cells"][record["cell"]]
        assert claim["status"] == "unknown" and claim["value"] is None
        if entry["evidence_kind"] is None:
            assert response["limitations"] == [SECTION_NOT_COLLECTED]
        else:
            assert response["limitations"] == [LIMIT_UNUSABLE]
            assert response["recommendations"] == [REC_BY_KIND[entry["evidence_kind"]]]
            assert response["recommendations"] == entry["recommendations"]
    else:
        assert claim["status"] in {"confirmed", "inferred"}
    assert response["claims"][1]["value"] == "SHOULD"


def test_every_cell_of_every_kind_is_reached():
    data = catalogue()
    reached = defaultdict(set)
    for vector in VECTORS:
        kind = data["policies"][vector["policy"]]["kind"]
        reached[kind].add(vector["cell"])
    missing = {kind: sorted(set(spec["cells"]) - reached[kind]) for kind, spec in data["kinds"].items()}
    assert {kind: cells for kind, cells in missing.items() if cells} == {}


def test_every_policy_with_a_row_has_the_verdict_vectors():
    data = catalogue()
    seen = defaultdict(set)
    for vector in VECTORS:
        seen[vector["policy"]].add(vector["verdict"])
    gaps = {}
    for policy_id, row in data["policies"].items():
        need = ({"not_assessed"} if data["kinds"][row["kind"]].get("evidence_free")
                else {"met", "not_met", "not_assessed"})
        if need - seen[policy_id]:
            gaps[policy_id] = sorted(need - seen[policy_id])
    assert gaps == {}


def test_no_vector_for_a_policy_without_a_row():
    rows = set(catalogue()["policies"])
    assert sorted({vector["policy"] for vector in VECTORS} - rows) == []
