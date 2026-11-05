"""Read-only fixture loading shared by these tests, never by product code.

Large fixtures are stored gzip-compressed; every reader decompresses transparently. The checker resources are
assembled at test time from the pinned raw baselines (parsed by this package's own reader) and the shipped
template and collection configs; nothing here stores generated pairs, prompts or mutants.
"""

import gzip
import json
import re
from functools import lru_cache
from pathlib import Path

from . import baseline_text
from .context import Resources

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "explainer"
LOCAL = FIXTURES / "checks"
BASELINES = FIXTURES / "baselines"


def read_bytes(path):
    """Logical bytes of a fixture: a .gz neighbour is decompressed, a plain file is read as stored."""
    path = Path(path)
    if path.suffix == ".gz":
        return gzip.decompress(path.read_bytes())
    if path.exists():
        return path.read_bytes()
    return gzip.decompress(Path(str(path) + ".gz").read_bytes())


def read_text(path):
    return read_bytes(path).decode("utf-8")


def read_json(path):
    return json.loads(read_text(path))


def read_rows(path):
    for line in read_text(path).splitlines():
        if line.strip():
            yield json.loads(line)


def config(name):
    """A shipped config exactly as the product reads it (the repository copy, never a stored duplicate)."""
    data = json.loads((ROOT / "configs" / name).read_text(encoding="utf-8"))
    if name == "explainer-template.json":
        from azure_tenant_audit.explainer.textkit import expand_template
        data = expand_template(data)
    return data


def wordlist(path=None):
    """Missing/empty/malformed lists fail setup; names are not auto-learned."""
    text = (path or LOCAL / "english-words.txt").read_text(encoding="ascii")
    words = text.splitlines()
    if not words or any(not re.fullmatch("[a-z]+", word) for word in words):
        raise ValueError("ordinary-word list must contain lower-case words, one per line")
    if words != sorted(set(words)):
        raise ValueError("ordinary-word list must be sorted and unique")
    return frozenset(words)


def raw_baselines():
    """{file name: markdown} of the pinned ScubaGear baselines (decompressed)."""
    return {p.name[:-3]: read_text(p) for p in sorted((BASELINES / "raw").glob("*.md.gz"))}


@lru_cache(maxsize=1)
def parsed_baselines():
    """This package's independent parse of the pinned markdown, shared read-only by every Resources."""
    raw = {name: text for name, text in raw_baselines().items() if re.search(r"^#{2,4}\s+MS\.", text, re.M)}
    return baseline_text.load(raw)


def train_identifiers():
    return frozenset(read_json(LOCAL / "train-identifiers.json.gz"))


@lru_cache(maxsize=1)
def local_resources():
    return Resources(parsed_baselines(), config("explainer-template.json"), config("explainer-what-to-collect.json"),
                     {"training-only.example"}, wordlist())


@lru_cache(maxsize=1)
def corpus_resources():
    return Resources(parsed_baselines(), config("explainer-template.json"), config("explainer-what-to-collect.json"),
                     train_identifiers(), wordlist())


def integration_result(name, data, *, root):
    """Write optional replay evidence only within the caller's isolated directory."""
    root.mkdir(parents=True, exist_ok=True)
    path = root / (name + (".jsonl" if isinstance(data, str) else ".json"))
    path.write_text(data if isinstance(data, str) else json.dumps(data, sort_keys=True, indent=2) + "\n")
