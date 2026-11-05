"""The fixture rule for this public repository, as executable checks.

Fixtures under tests/fixtures/explainer may hold only constructed rows and model-pack TRAIN and VALIDATION rows (each
with a vector id and an origin). They never hold held-out test-split rows (pack or pilot), sealed pilot rows or
diagnostic rows, any machine path, or a file over 1 MB. ``violations`` is the single scanner; the tests run it over
every file (decompressing .gz and .xz) and over planted negative controls.
"""
import gzip
import json
import lzma
import re

ALLOWED_KINDS = frozenset({"constructed", "pack-train", "pack-validation"})
# Assembled from parts so that this file does not itself contain the substrings it forbids elsewhere.
FORBIDDEN_PATHS = ("/" + "Users" + "/", "/" + "Volumes" + "/", "auditex" + "-data", "development" + "-kit")
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024
# Spellings of the same allowed kind in the carried-forward value-rule fixtures.
ALIASES = {"packlic-train": "pack-train", "aad-pack-train": "pack-train", "pbi-pack-train": "pack-train",
           "pbi-pack-validation": "pack-validation", "a2-constructed": "constructed"}
# A vector id is "<kind>:<row id>"; any other kind prefix on such an id is out of bounds.
VECTOR_ID = re.compile(r"\b([a-z0-9]+(?:-[a-z0-9]+)*):((?:scuba|MS\.)[A-Za-z0-9._-]*)")
PROHIBITED_KIND_WORDS = re.compile(r"\b(?:[a-z0-9]+-)*(?:pack-test|frozen|diagnostic)\b")


def logical_bytes(name, data):
    if name.endswith(".gz"):
        return gzip.decompress(data)
    if name.endswith(".xz"):
        return lzma.decompress(data)
    return data


def _walk(value):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def kind_violations(value):
    """Rows (dicts) that carry a vector id, a source kind or a split outside the rule."""
    found = []
    for row in _walk(value):
        if row.get("split") == "test":
            found.append("split == test")
        if "vector_id" in row or "source_kind" in row:
            kind = row.get("source_kind") or str(row.get("vector_id", "")).split(":")[0]
            if ALIASES.get(kind, kind) not in ALLOWED_KINDS:
                found.append("source kind " + repr(kind))
        origin = row.get("origin")
        if isinstance(origin, str) and PROHIBITED_KIND_WORDS.fullmatch(origin):
            found.append("origin " + repr(origin))
    return found


def violations(name, data, *, check_size=True):
    """Every rule broken by one stored file (name decides the decompression); an empty list is a clean file.

    ``check_size=False`` applies only the kind and path rules, for the shared value-rule vector fixtures that the pool
    reads (their size limit is not this directory's).
    """
    found = []
    if check_size and len(data) > MAX_FILE_BYTES:
        found.append("stored file over 1 MB")
    logical = logical_bytes(name, data)
    if check_size and len(logical) > MAX_FILE_BYTES:
        found.append("decompressed file over 1 MB")
    text = logical.decode("utf-8", errors="replace")
    for path in FORBIDDEN_PATHS:
        if path in text:
            found.append("forbidden path substring " + repr(path))
    for match in VECTOR_ID.finditer(text):
        kind = match.group(1)
        if ALIASES.get(kind, kind) not in ALLOWED_KINDS:
            found.append("vector id with kind " + repr(kind))
    base = name[:-3] if name.endswith((".gz", ".xz")) else name
    if base.endswith(".json"):
        found.extend(kind_violations(json.loads(text)))
    elif base.endswith(".jsonl"):
        for line in text.splitlines():
            if line.strip():
                found.extend(kind_violations(json.loads(line)))
    return sorted(set(found))
