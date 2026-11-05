"""Offline baseline acceptance; no reference checkout, network or other part needed."""
from __future__ import annotations

from copy import deepcopy
import gzip
import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from azure_tenant_audit.explainer import baselines as bl

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "explainer" / "baselines"
# The pinned baselines are stored gzip-compressed; the generator and the readers below want plain files, so they are
# materialised once per process in a scratch directory (original bytes, original hashes).
_SCRATCH = tempfile.TemporaryDirectory()
RAW = Path(_SCRATCH.name) / "raw"
RAW.mkdir()
for _stored in sorted((FIXTURES / "raw").glob("*.md.gz")):
    (RAW / _stored.name[:-3]).write_bytes(gzip.decompress(_stored.read_bytes()))


def source_reader():
    return json.loads(gzip.decompress((FIXTURES / "source-reader.json.gz").read_bytes()))


POLICIES = sorted(source_reader()["policies"])
# Independently transcribed from the contract, not the runtime XREF mapping.
RANGES = [
    ("MS.EXO.4.2v1", "MS.EXO.4.1v1", None),
    ("MS.EXO.4.3v1", "MS.EXO.4.1v1", None),
    ("MS.EXO.4.4v1", "MS.EXO.4.1v1", None),
    ("MS.EXO.6.2v1", "MS.EXO.6.1v1", ["5"]),
    ("MS.SECURITYSUITE.1.2v1", "MS.SECURITYSUITE.1.1v1", None),
    ("MS.SECURITYSUITE.3.2v1", "MS.SECURITYSUITE.3.1v1", ["9"]),
    ("MS.SECURITYSUITE.3.3v1", "MS.SECURITYSUITE.3.1v1", ["16", "17", "18"]),
    ("MS.SECURITYSUITE.3.4v1", "MS.SECURITYSUITE.3.1v1", ["19", "20"]),
    ("MS.SECURITYSUITE.6.2v1", "MS.SECURITYSUITE.6.1v1", None),
    ("MS.SECURITYSUITE.7.2v1", "MS.SECURITYSUITE.7.1v1", None),
    ("MS.SECURITYSUITE.7.3v1", "MS.SECURITYSUITE.7.1v1", None),
    ("MS.AAD.7.9v1", "MS.AAD.7.8v1", None),
    ("MS.AAD.7.2v1", "MS.AAD.7.1v1", None),
    ("MS.POWERPLATFORM.1.2v1", "MS.POWERPLATFORM.1.1v1", ["1", "2", "3"]),
    ("MS.POWERPLATFORM.2.2v1", "MS.POWERPLATFORM.2.1v1", [str(i) for i in range(1, 12)]),
    ("MS.POWERPLATFORM.3.2v1", "MS.POWERPLATFORM.3.1v1", ["1", "2"]),
]


def fixture_read(path):
    return (FIXTURES / "LICENSE.scubagear.txt" if path == "LICENSE" else RAW / Path(path).name).read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def index():
    return bl.load_baselines(lambda path: (ROOT / path).read_text(encoding="utf-8"))


def _sections():
    """Separate heading scanner; no runtime parsing or cleaning functions used."""
    found = {}
    for path in sorted(RAW.glob("*.md")):
        if path.name == "removedpolicies.md":
            continue
        current = None
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if line.startswith("#"):
                heading = line.lstrip("#").strip()
                match = re.fullmatch(r"(MS\.[A-Z]+\.\d+\.\d+v\d+)( Instructions)?", heading)
                current = None if match is None else (match[1], bool(match[2]))
                if current:
                    found.setdefault(current, [])
            elif current:
                found[current].append((number, line))
    return found


def _clean(raw):
    # Independent comparison of words/digits, as in S's builder-vs-reader check.
    # Strip raw list markers before joining multiline link labels (Office 365).
    raw = re.sub(r"(?m)^\s*(?:\d+\.|[-*])\s+", "", raw)
    raw = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", raw)
    raw = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", raw)
    raw = re.sub(r"<https?://[^>]*>", "", raw)
    raw = re.sub(r"</?(?:pre|b|i|u|em|strong|code|br)\s*/?>", "", raw)
    raw = re.sub(r"(?m)^\s*```[^\n]*$", "", raw)
    return re.sub(r"[^a-z0-9]", "", raw.casefold())


def _raw_target(target, labels):
    rows = _sections()[(target, True)]
    if labels is None:
        return "\n".join(line for _, line in rows)
    # Range endpoints are raw top-level numbered lines; nested lines stay inside.
    starts = [(i, re.match(r"^(\d+)\.\s", line)[1])
              for i, (_, line) in enumerate(rows) if re.match(r"^\d+\.\s", line)]
    selected = []
    for position, (start, label) in enumerate(starts):
        if label in labels:
            stop = starts[position + 1][0] if position + 1 < len(starts) else len(rows)
            selected.extend(line for _, line in rows[start:stop])
    return "\n".join(selected)


def test_worktree_import_and_vendored_loading_only(index):
    assert Path(bl.__file__).resolve() == ROOT / "src/azure_tenant_audit/explainer/baselines.py"
    calls = []

    def read(path):
        calls.append(path)
        return (ROOT / path).read_text()

    assert bl.load_baselines(read) == index
    assert calls == ["configs/explainer-baselines.json"]


def test_regeneration_and_frozen_source_identity(index):
    expected = source_reader()
    assert len(expected["policies"]) == len(index["policies"]) == 109
    overrides = json.loads((ROOT / "tests/fixtures/explainer/integration/baseline-command-units.json").read_text())
    for pid, units in overrides.items():
        replaced, seen = [], set()
        for unit in expected["policies"][pid]["instructions"]:
            if unit["kind"] != "pre":
                replaced.append(unit)
                continue
            key = json.dumps(unit["source"], sort_keys=True)
            if key not in seen:
                replaced.extend(u for u in units if u["source"] == unit["source"])
                seen.add(key)
        expected["policies"][pid]["instructions"] = replaced
    assert index["policies"] == expected["policies"]
    rebuilt = bl.build_baselines(fixture_read)
    assert rebuilt == index
    assert json.dumps(rebuilt, sort_keys=True, ensure_ascii=False, indent=2) + "\n" == (ROOT / bl.RESOURCE).read_text()


@pytest.mark.parametrize("pid", POLICIES)
def test_every_policy_independently_matches_markdown(index, pid):
    sections = _sections()
    requirement_lines = []
    for _, line in sections[(pid, False)]:
        if line.startswith(("[![", "<!--")):
            break
        requirement_lines.append(line)
    assert _clean(bl.requirement(index, pid)) == _clean("\n".join(requirement_lines))
    own = index["policies"][pid]["instructions"]
    assert _clean(" ".join(u["text"] for u in own)) == _clean("\n".join(line for _, line in sections.get((pid, True), [])))
    for unit in own:
        source = unit["source"]
        assert source["policy_id"] == pid
        rows = (RAW / source["file"]).read_text().splitlines()
        assert 0 < source["line_start"] <= source["line_end"] <= len(rows)
        assert _clean(unit["text"]) in _clean("\n".join(rows[source["line_start"] - 1:source["line_end"]]))


@pytest.mark.parametrize("pid,target,labels", RANGES)
def test_all_target_ranges_independently_and_own_first(index, pid, target, labels):
    row = next(x for x in index["xrefs"] if x["policy_id"] == pid)
    assert row == {"policy_id": pid, "target": target, "labels": labels}
    own = index["policies"][pid]["instructions"]
    result = bl.instructions(index, pid)
    assert result[:len(own)] == own
    resolved = result[len(own):]
    assert resolved
    assert all(u["source"]["policy_id"] == target for u in resolved)
    assert _clean(" ".join(u["text"] for u in resolved)) == _clean(_raw_target(target, labels))
    # Compare exact selected units/provenance to the independently frozen S reader.
    expected = source_reader()["policies"][target]["instructions"]
    if labels is not None:
        # Raw line positions define membership; do not reuse runtime unit selection.
        numbered = [(n, re.match(r"^(\d+)\.\s", line)[1])
                    for n, line in _sections()[(target, True)] if re.match(r"^\d+\.\s", line)]
        spans = [(n, numbered[i + 1][0] if i + 1 < len(numbered) else float("inf"))
                 for i, (n, label) in enumerate(numbered) if label in labels]
        expected = [u for u in expected if any(start <= u["source"]["line_start"] < end for start, end in spans)]
    assert [{k: v for k, v in u.items() if k != "command"} for u in resolved] == expected
    assert [u["source"]["line_start"] for u in resolved] == sorted(u["source"]["line_start"] for u in resolved)


def test_nested_children_counting_note_and_uncovered_pp_pointer(index):
    aad = bl.instructions(index, "MS.AAD.7.2v1")
    target = [u for u in aad if u["source"]["policy_id"] == "MS.AAD.7.1v1"]
    assert target[0]["kind"] == "para" and "count" in target[0]["text"].lower()
    assert [u["label"] for u in target if u["kind"] == "num" and u["level"] == 0] == ["1", "2"]
    pp = bl.instructions(index, "MS.POWERPLATFORM.3.2v1")
    target = [u for u in pp if u["source"]["policy_id"] == "MS.POWERPLATFORM.3.1v1"]
    assert target == index["policies"]["MS.POWERPLATFORM.3.1v1"]["instructions"][:len(target)]
    assert any(u["level"] == 1 for u in bl.instructions(index, "MS.SECURITYSUITE.1.2v1"))


def test_no_default_cap_hit_and_all_policies_preserved(index):
    assert len(index["xrefs"]) == 16
    assert all(bl.cap_report(index, pid) is None for pid in POLICIES)
    assert max(len(bl.canon([u["text"] for u in bl.instructions(index, pid)])) for pid in POLICIES) <= 6000
    # Missing public text (including the rule-only PP 2.3 id) never gains prose.
    for pid in ["MS.POWERPLATFORM.2.3v1", "MS.UNKNOWN.1.1v1"]:
        assert bl.requirement(index, pid) == ""
        assert bl.criticality(index, pid) is None
        assert bl.instructions(index, pid) == []
        assert bl.cap_report(index, pid) is None


def _synthetic():
    def unit(text, pid):
        return {"text": text, "kind": "para", "label": None, "level": 0,
                "source": {"file": "synthetic.md", "line_start": 1, "line_end": 1, "policy_id": pid}}
    return {"policies": {"p": {"instructions": [unit('é"\\', "p"), unit("second", "p")]},
                         "q": {"instructions": [unit("target", "q")]}},
            "xrefs": [{"policy_id": "p", "target": "q", "labels": None}]}


def test_cap_exact_json_character_boundary_and_whole_trailing_units():
    index = _synthetic()
    before = deepcopy(index)
    first = index["policies"]["p"]["instructions"][:1]
    size = len(json.dumps([first[0]["text"]], sort_keys=True, ensure_ascii=False, separators=(",", ":")))
    assert bl.instructions(index, "p", cap=size) == first
    assert bl.instructions(index, "p", cap=size - 1) == []
    own_size = len(bl.canon([u["text"] for u in index["policies"]["p"]["instructions"]]))
    assert bl.instructions(index, "p", cap=own_size) == index["policies"]["p"]["instructions"]
    full = bl.instructions(index, "p")
    full_size = len(bl.canon([u["text"] for u in full]))
    assert bl.instructions(index, "p", cap=full_size) == full
    assert bl.cap_report(index, "p", cap=full_size) is None
    report = bl.cap_report(index, "p", cap=size)
    assert {k: v for k, v in report.items() if k != "rule"} == {
        "lines_total": 3, "lines_kept": 1, "own_lines": 2, "chars_full": full_size, "chars_kept": size}
    assert bl.instructions(index, "p", cap=2) == []
    full[0]["source"]["file"] = "changed"
    assert index == before


def test_cap_does_not_skip_an_oversized_unit_to_keep_a_later_short_unit():
    index = _synthetic()
    index["policies"]["p"]["instructions"][0]["text"] = "x" * 40
    assert bl.instructions(index, "p", cap=20) == []
    assert bl.cap_report(index, "p", cap=20)["chars_kept"] == 2


def test_missing_target_label_is_rejected(index):
    data = deepcopy(index)
    row = next(x for x in data["xrefs"] if x["labels"] is not None)
    row["labels"] = ["999"]
    with pytest.raises(ValueError, match="labels missing"):
        bl.instructions(data, row["policy_id"])


@pytest.mark.parametrize("cap", [True, None, 1, -1, 2.5, "6000"])
def test_invalid_cap_rejected(cap):
    with pytest.raises(ValueError, match="cap"):
        bl.instructions(_synthetic(), "p", cap=cap)


def test_code_characters_continuations_and_prose_cleaning():
    raw = '''## MS.TEST.1.1v1
A **requirement**.
<!-- Policy: MS.TEST.1.1v1; Criticality: SHALL -->
### MS.TEST.1.1v1 Instructions
1. Select [**Label**](https://example.com/) and _value_ with \\_literal\\_.
   - Keep nested child.

```powershell
Get-Thing -Name "*_name" | Where-Object { $_.Flag -eq $true } `
  -Other '<a_b>' # inline comment
# Verify settings
```
<pre>Set-Thing -Pattern '*_x' -Path 'C:\\one' &amp;</pre>
'''
    items = bl._parse_all({"synthetic.md": raw})["MS.TEST.1.1v1"]["instructions"]
    assert items[0]["text"] == "Select Label and value with _literal_."
    assert (items[1]["kind"], items[1]["level"], items[1]["label"]) == ("bul", 1, None)
    assert items[2]["lines"] == [
        'Get-Thing -Name "*_name" | Where-Object { $_.Flag -eq $true } -Other \'<a_b>\' # inline comment',
        "# Verify settings",
    ]
    assert items[3]["lines"] == ["Set-Thing -Pattern '*_x' -Path 'C:\\one' &amp;"]
    assert bl.plain(r"> **Bold** *italic* [text](https://example.com) <https://example.com> ![image](url) \\> x").startswith("Bold italic text")
    assert bl.plain_code("Get-X \u2013Flag *_value") == "Get-X -Flag *_value"


def test_fixture_hashes_attribution_and_source_pins(index):
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    assert manifest["source_commit"] == index["source_commit"] == bl.SOURCE_COMMIT
    for path, entry in manifest["files"].items():
        stored = RAW / Path(path).name if path.startswith("raw/") else FIXTURES / path
        data = stored.read_bytes() if stored.exists() else gzip.decompress(Path(str(stored) + ".gz").read_bytes())
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]
        assert entry["licence"]
        if path.startswith("raw/") or path == "LICENSE.scubagear.txt":
            assert index["source_sha256"][entry["source"]] == entry["sha256"]
    attribution = index["attribution"]
    assert attribution["creators"] == ["CISA SCuBA / ScubaGear", "Microsoft"]
    assert {x["name"] for x in attribution["licences"]} == {"CC0 1.0 Universal", "CC BY 4.0"}
    assert "self-pointer" in attribution["changes"]
    for name in ["aad.md", "powerplatform.md", "securitysuite.md"]:
        item = attribution["files"][f"{bl.BASELINE_DIR}/{name}"]
        assert any("Portions of this document are adapted" in notice for notice in item["notices"])
        assert "https://github.com/MicrosoftDocs/azure-docs/blob/main/LICENSE" in item["source_links"]
        assert bl.SOURCE_COMMIT in item["source_url"]


@pytest.mark.parametrize("change", ["version", "commit", "hash", "xref", "unit", "policy", "attribution"])
def test_load_rejects_corrupt_data(index, change):
    data = deepcopy(index)
    if change == "version":
        data["schema_version"] = True
    elif change == "commit":
        data["source_commit"] = "wrong"
    elif change == "hash":
        data["source_sha256"]["LICENSE"] = "bad"
    elif change == "xref":
        data["xrefs"][0]["labels"] = [1]
    elif change == "unit":
        data["policies"][POLICIES[0]]["instructions"][0]["label"] = 1
    elif change == "policy":
        del data["policies"][POLICIES[0]]
    else:
        del data["attribution"]
    with pytest.raises(ValueError):
        bl.load_baselines(lambda _: json.dumps(data))


def _generator():
    spec = importlib.util.spec_from_file_location("generate_explainer_baselines", ROOT / "scripts/generate-explainer-baselines.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generator_checks_commit_bytes_and_returns_same_schema(index, monkeypatch):
    module = _generator()
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        assert args[:2] == ["git", "-C"]
        if args[-2:] == ["rev-parse", "HEAD"]:
            return SimpleNamespace(stdout=bl.SOURCE_COMMIT + "\n")
        assert args[-2] == "show" and args[-1].startswith(bl.SOURCE_COMMIT + ":")
        path = args[-1].split(":", 1)[1]
        return SimpleNamespace(stdout=fixture_read(path).encode())

    original_read = Path.read_bytes

    def read(path):
        if str(path).startswith(str(RAW / bl.BASELINE_DIR)):
            return (RAW / path.name).read_bytes()
        if path == RAW / "LICENSE":
            return (FIXTURES / "LICENSE.scubagear.txt").read_bytes()
        return original_read(path)

    monkeypatch.setattr(module.subprocess, "run", run)
    monkeypatch.setattr(Path, "read_bytes", read)
    assert module.generate_baselines(RAW) == index
    assert len(calls) == 10  # full HEAD plus eight markdown inputs and LICENSE
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="wrong\n"))
    with pytest.raises(ValueError, match="must be at"):
        module.generate_baselines(RAW)
    monkeypatch.setattr(module.subprocess, "run", run)
    monkeypatch.setattr(Path, "read_bytes", lambda _: b"modified")
    with pytest.raises(ValueError, match="differs from pinned commit"):
        module.generate_baselines(RAW)


def test_generator_stdout_is_same_json_without_writing(index, monkeypatch, capsys):
    module = _generator()
    monkeypatch.setattr(module, "generate_baselines", lambda _: index)
    assert module.main(["--checkout", str(RAW)]) == 0
    assert capsys.readouterr().out == (ROOT / bl.RESOURCE).read_text()
