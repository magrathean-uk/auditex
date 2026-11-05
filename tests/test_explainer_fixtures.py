"""Enforce the public-repository fixture rule on tests/fixtures/explainer, and on the generated test material.

Rule: only constructed rows and pack TRAIN and VALIDATION rows (with vector id and origin); never test-split rows,
sealed pilot rows or diagnostic rows; no machine paths; no file over 1 MB; the whole directory under 1 MB.
The explainer test set, pairs and mutants are not stored: they are generated from the allowed vector fixtures by
tests/explainer_checks (see its README) and pinned by a small manifest.
"""
import hashlib
import json
from pathlib import Path

import pytest

from explainer_checks import corpus, fixture_rules as rules, pool

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests/fixtures/explainer"


def stored_files():
    return sorted(p for p in FIX.rglob("*") if p.is_file() and "__pycache__" not in p.parts)


def test_every_stored_fixture_obeys_the_rule():
    files = stored_files()
    assert files
    broken = {}
    for path in files:
        found = rules.violations(path.name, path.read_bytes())
        if found:
            broken[str(path.relative_to(FIX))] = found
    assert not broken, broken


def test_fixtures_are_small():
    sizes = {str(p.relative_to(FIX)): p.stat().st_size for p in stored_files()}
    assert max(sizes.values()) <= rules.MAX_FILE_BYTES, max(sizes.items(), key=lambda kv: kv[1])
    assert sum(sizes.values()) < rules.MAX_TOTAL_BYTES, sum(sizes.values())


def test_no_expanded_corpus_is_stored():
    names = {p.name for p in stored_files()}
    for stored in ("base-pairs-v391.jsonl.gz", "mutations.jsonl.gz", "benign.jsonl.gz", "selected-vectors.jsonl.gz",
                   "testset-all.jsonl.gz", "prompts.jsonl.gz", "canary-twins.json", "resources.json"):
        assert stored not in names
    assert not [p for p in stored_files() if "corpus/source" in str(p)]


def test_sha256sums_cover_every_file():
    listed = {}
    for line in (FIX / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(None, 1)
        assert name not in listed
        listed[name] = digest
    actual = {str(p.relative_to(FIX)) for p in stored_files() if p.name != "SHA256SUMS"}
    assert set(listed) == actual
    for name, digest in listed.items():
        assert hashlib.sha256((FIX / name).read_bytes()).hexdigest() == digest, name


@pytest.mark.parametrize("name,data,expected", [
    ("rows.jsonl", b'{"vector_id": "pack-test:scuba-aad-ms-aad-1-1v1-0123456789", "source_kind": "pack-test"}\n', "source kind 'pack-test'"),
    ("rows.jsonl", b'{"vector_id": "aad-frozen:scuba-aad-ms-aad-3-3v2-0123456789-nc", "source_kind": "aad-frozen"}\n', "source kind 'aad-frozen'"),
    ("rows.jsonl", b'{"vector_id": "pbi-diagnostic:scuba-powerbi-ms-powerbi-1-1v1-0123456789"}\n', "source kind 'pbi-diagnostic'"),
    ("rows.json", b'[{"vector_id": "constructed:x", "source_kind": "constructed", "split": "test"}]', "split == test"),
    ("rows.json", b'{"origin": "ss6-frozen"}', "origin 'ss6-frozen'"),
    ("note.md", b"run from /" + b"Users" + b"/someone/work", "forbidden path substring " + repr("/" + "Users" + "/")),
    ("note.md", b"see /" + b"Volumes" + b"/disk/x", "forbidden path substring " + repr("/" + "Volumes" + "/")),
    ("note.md", b"the auditex" + b"-data tree", "forbidden path substring " + repr("auditex" + "-data")),
    ("note.md", b"the development" + b"-kit tree", "forbidden path substring " + repr("development" + "-kit")),
    ("big.txt", b"x" * (rules.MAX_FILE_BYTES + 1), "stored file over 1 MB"),
])
def test_scanner_rejects_planted_violations(name, data, expected):
    assert expected in rules.violations(name, data)


def test_scanner_decompresses_and_accepts_allowed_rows():
    import gzip
    import lzma
    row = b'{"vector_id": "pack-train:scuba-aad-ms-aad-1-1v1-0123456789", "source_kind": "pack-train", "split": "train"}\n'
    assert rules.violations("ok.jsonl.gz", gzip.compress(row)) == []
    assert rules.violations("ok.jsonl.xz", lzma.compress(row)) == []
    bad = b'{"vector_id": "pack-test:scuba-aad-ms-aad-1-1v1-0123456789", "source_kind": "pack-test"}\n'
    assert rules.violations("bad.jsonl.gz", gzip.compress(bad))
    assert rules.violations("bad.jsonl.xz", lzma.compress(bad))
    big = b'{"note": "' + b"x" * rules.MAX_FILE_BYTES + b'"}\n'
    assert rules.violations("big.jsonl.gz", gzip.compress(big)) == ["decompressed file over 1 MB"]


def test_generated_test_set_uses_only_allowlisted_kinds():
    ts = corpus.testset()
    assert {row["kind"] for row in ts["rows"]} <= rules.ALLOWED_KINDS
    assert {v["kind"] for v in pool.pool()} <= rules.ALLOWED_KINDS
    assert {p["origin"] for p in corpus.base_pairs()} <= rules.ALLOWED_KINDS
    for vector in pool.pool():
        assert vector["vector_id"].split(":")[0] in rules.ALLOWED_KINDS | set(rules.ALIASES), vector["vector_id"]
    assert not [row for row in ts["rows"] if row["vector_id"].startswith(("pack-test", "aad-frozen", "pbi-frozen", "ss6-frozen"))]


def test_pool_loader_fails_closed_on_a_disallowed_row():
    for row in ({"vector_id": "x", "source_kind": "pack-test"}, {"vector_id": "x", "source_kind": "constructed", "split": "test"},
                {"vector_id": "x", "source_kind": "aad-frozen"}, {"vector_id": "x", "source_kind": "pbi-diagnostic"}):
        with pytest.raises(ValueError):
            pool.normal_kind(row)
    assert pool.normal_kind({"source_kind": "packlic-train"}) == "pack-train"
    assert pool.normal_kind({"source_kind": "pbi-pack-validation", "split": "validation"}) == "pack-validation"


def test_value_rule_fixtures_the_pool_reads_obey_the_rule():
    for path in sorted((ROOT / "tests/fixtures/value-rules").glob("vectors-*")):
        assert not rules.violations(path.name, path.read_bytes(), check_size=False), path.name
