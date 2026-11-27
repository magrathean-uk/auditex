"""Baseline section catalogue for the Google Workspace SCuBA baselines (ScubaGoggles v1.1.0)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate-gws-scuba-catalogue.py"
CATALOGUE = ROOT / "configs" / "scuba-gws-policy-sections.json"
FIXTURE = ROOT / "tests" / "fixtures" / "gws-baselines"
BASELINES = "scubagoggles/baselines"
PARTIAL = "gemini.md,sites.md"
# Literal SHA-256 of the two fixture files (byte-identical to ScubaGoggles v1.1.0 at 08a08ce1).
FIXTURE_DIGESTS = {
    "gemini.md": "fa902507384984d72ab533ff344c168d50a8e5c548f2f113c00aac60cce188a8",
    "sites.md": "3d1617d16aeac86120114eb19c6ea1a1fd0b221ce5936b3afe537f10395d6508",
}

MANUAL_IDS = {
    "GWS.CALENDAR.3.2v1",
    "GWS.COMMONCONTROLS.8.3v1",
    "GWS.COMMONCONTROLS.9.1v1",
    "GWS.COMMONCONTROLS.9.2v1",
    "GWS.COMMONCONTROLS.14.1v1",
    "GWS.COMMONCONTROLS.14.2v1",
    "GWS.COMMONCONTROLS.16.3v1",
    "GWS.COMMONCONTROLS.16.4v1",
    "GWS.COMMONCONTROLS.18.1v1",
    "GWS.COMMONCONTROLS.18.2v1",
    "GWS.DRIVEDOCS.1.10v1",
    "GWS.DRIVEDOCS.1.11v1",
    "GWS.DRIVEDOCS.5.2v1",
    "GWS.GEMINI.3.1v1",
    "GWS.GEMINI.3.2v1",
    "GWS.GEMINI.4.1v1",
    "GWS.MEET.6.3v1",
}
LOG_BASED_IDS = {
    "GWS.ASSUREDCONTROLS.2.1v1",
    "GWS.CHAT.5.1v1",
    "GWS.CHAT.5.2v1",
    "GWS.COMMONCONTROLS.2.1v1",
    "GWS.COMMONCONTROLS.3.1v1",
    "GWS.COMMONCONTROLS.3.2v1",
    "GWS.GEMINI.1.1v1",
    "GWS.GEMINI.2.1v1",
    "GWS.GMAIL.13.1v1",
    "GWS.GMAIL.16.1v1",
    "GWS.MEET.6.1v1",
    "GWS.MEET.6.2v1",
}
PRODUCT_COUNTS = {
    "ASSUREDCONTROLS": 3,
    "CALENDAR": 6,
    "CHAT": 7,
    "CLASSROOM": 6,
    "COMMONCONTROLS": 42,
    "DRIVEDOCS": 17,
    "GEMINI": 5,
    "GMAIL": 36,
    "GROUPS": 6,
    "MEET": 9,
    "SITES": 1,
}


@pytest.fixture(scope="module")
def catalogue() -> dict:
    return json.loads(CATALOGUE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def generator():
    spec = importlib.util.spec_from_file_location("generate_gws_scuba_catalogue", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_generator(*args: str | Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), *map(str, args)], capture_output=True, text=True, check=False
    )


def fixture_copy(tmp_path: Path) -> Path:
    shutil.copytree(FIXTURE, tmp_path / "src")
    return tmp_path / "src"


def test_ids_and_shape(catalogue):
    policies = catalogue["policies"]
    assert len(policies) == 138
    assert all(re.fullmatch(r"GWS\.[A-Z]+\.\d+\.\d+v1", policy_id) for policy_id in policies)
    assert Counter(item["service"] for item in policies.values()) == PRODUCT_COUNTS
    for item in policies.values():
        assert set(item) == {"service", "heading", "baseline_text", "criticality", "manual", "events", "sections"}
        assert item["criticality"] in {"SHALL", "SHOULD"}
        assert 0 < len(item["baseline_text"]) <= 400
        assert item["heading"]


def test_manual_and_log_based_sets(catalogue):
    policies = catalogue["policies"]
    assert {pid for pid, item in policies.items() if item["manual"]} == MANUAL_IDS
    assert {pid for pid, item in policies.items() if item["events"]} == LOG_BASED_IDS


def test_source_block_and_vocabulary(catalogue):
    source = catalogue["source"]
    assert source["repo"] == "https://github.com/cisagov/ScubaGoggles"
    assert source["tag"] == "v1.1.0"
    assert source["commit"] == "08a08ce145178582284d81ab1f3625987f3ad66b"
    assert source["licence"] == "CC0-1.0"
    assert len(source["files"]) == 11
    assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in source["files"].values())
    assert catalogue["limitation_ids"] == [
        "required_evidence_section_not_collected",
        "policy_scope_depends_on_licence",
        "policy_not_applicable",
    ]
    assert catalogue["recommendation_ids"] == ["collect_missing_evidence_section", "review_policy_against_baseline_text"]
    assert "/Users/" not in CATALOGUE.read_text(encoding="utf-8")


def test_spot_checked_baseline_texts(catalogue):
    policies = catalogue["policies"]
    assert policies["GWS.GMAIL.3.1v1"]["baseline_text"] == (
        "An SPF policy SHALL be published for each domain that fails all non-approved senders."
    )
    assert policies["GWS.GMAIL.3.1v1"]["heading"] == "Sender Policy Framework"
    assert policies["GWS.GEMINI.1.1v1"]["baseline_text"] == (
        "Gemini app user access SHALL be set to OFF for everyone without a license."
    )
    assert policies["GWS.GEMINI.1.1v1"]["criticality"] == "SHALL"
    assert policies["GWS.GMAIL.1.1v1"]["criticality"] == "SHOULD"


def test_sections_by_kind(catalogue):
    policies = catalogue["policies"]
    assert policies["GWS.GMAIL.1.1v1"]["sections"] == ["gws_tenant", "gws_policies"]
    assert policies["GWS.GMAIL.5.5v1"]["sections"] == ["gws_tenant", "gws_policies"]
    assert policies["GWS.COMMONCONTROLS.1.4v1"]["sections"] == ["gws_tenant", "gws_policies"]
    assert policies["GWS.COMMONCONTROLS.10.1v1"]["sections"] == ["gws_tenant", "gws_policies"]
    assert policies["GWS.GMAIL.13.1v1"]["sections"] == ["gws_tenant", "gws_setting_events"]
    assert policies["GWS.GEMINI.1.1v1"]["sections"] == ["gws_tenant", "gws_policies", "gws_setting_events"]
    assert policies["GWS.GMAIL.3.1v1"]["sections"] == ["gws_dns"]
    assert policies["GWS.COMMONCONTROLS.6.2v1"]["sections"] == ["gws_admins"]
    assert policies["GWS.COMMONCONTROLS.6.1v1"]["sections"] == ["gws_tenant", "gws_admins", "gws_sso"]
    assert policies["GWS.MEET.6.3v1"]["sections"] == ["gws_tenant"]
    allowed = {"gws_tenant", "gws_policies", "gws_setting_events", "gws_dns", "gws_admins", "gws_sso"}
    assert all(set(item["sections"]) <= allowed for item in policies.values())


def unpinned(generator, monkeypatch, source: Path) -> None:
    """Pin the files under ``source`` at their own digests so a parse rule can be tested on edited text."""
    for path in (source / BASELINES).glob("*.md"):
        monkeypatch.setitem(generator.PINNED_SHA256, path.name, hashlib.sha256(path.read_bytes()).hexdigest())


def test_fixture_is_the_pinned_baseline_pair():
    for name, digest in FIXTURE_DIGESTS.items():
        assert hashlib.sha256((FIXTURE / BASELINES / name).read_bytes()).hexdigest() == digest


def test_pinned_digests_match_the_committed_source_block(generator, catalogue):
    assert generator.PINNED_SHA256 == catalogue["source"]["files"]
    assert generator.PINNED_SHA256["gemini.md"] == FIXTURE_DIGESTS["gemini.md"]
    assert generator.PINNED_SHA256["sites.md"] == FIXTURE_DIGESTS["sites.md"]


def test_check_passes_on_fixture_checkout():
    assert sorted(p.name for p in (FIXTURE / BASELINES).glob("*.md")) == ["gemini.md", "sites.md"]
    result = run_generator("--source", FIXTURE, "--out", CATALOGUE, "--check", "--partial", PARTIAL)
    assert (result.returncode, result.stderr) == (0, "")


def test_partial_check_requires_every_named_file(tmp_path):
    source = fixture_copy(tmp_path)
    (source / BASELINES / "gemini.md").unlink()
    result = run_generator("--source", source, "--out", CATALOGUE, "--check", "--partial", PARTIAL)
    assert result.returncode == 2
    assert "gemini.md: baseline file missing" in result.stderr
    assert str(tmp_path) not in result.stderr


@pytest.mark.parametrize("names", ["", "gemini.md,", "gemini.md,nope.md", "../sites.md", "README.md"])
def test_partial_names_must_be_pinned_baselines(names):
    result = run_generator("--source", FIXTURE, "--out", CATALOGUE, "--check", "--partial", names)
    assert result.returncode == 2
    assert "nope" not in result.stderr and "README" not in result.stderr and ".." not in result.stderr


def test_partial_checks_only_the_named_files():
    result = run_generator("--source", FIXTURE, "--out", CATALOGUE, "--check", "--partial", "sites.md")
    assert (result.returncode, result.stderr) == (0, "")


def test_check_without_partial_refuses_an_incomplete_checkout():
    result = run_generator("--source", FIXTURE, "--out", CATALOGUE, "--check")
    assert result.returncode == 2
    assert "baseline file missing" in result.stderr
    assert str(FIXTURE) not in result.stderr


@pytest.mark.parametrize(
    "edit",
    [
        lambda text: text.replace("SHALL", "SHOULD", 1),
        lambda text: text[: text.index("Sites Service SHOULD be") + len("Sites Service SHOULD be")],
        lambda text: text + "\nSee /Users/synthetic/review for details.\n",
        lambda text: text.rstrip("\n"),
    ],
    ids=["edited-word", "cut-after-last-id", "appended-text", "trailing-newline-lost"],
)
def test_edited_or_cut_baseline_is_refused_not_pinned(tmp_path, edit):
    source = fixture_copy(tmp_path)
    sites = source / BASELINES / "sites.md"
    text = sites.read_text(encoding="utf-8")
    assert edit(text) != text
    sites.write_text(edit(text), encoding="utf-8")
    result = run_generator("--source", source, "--out", CATALOGUE, "--check", "--partial", PARTIAL)
    assert result.returncode == 2
    assert result.stderr == "catalogue error: sites.md: bytes differ from the pinned v1.1.0 digest\n"


def test_generation_refuses_a_cut_baseline_and_writes_nothing(generator, tmp_path):
    source = fixture_copy(tmp_path)
    sites = source / BASELINES / "sites.md"
    text = sites.read_text(encoding="utf-8")
    sites.write_text(text[: text.index("Sites Service SHOULD be") + len("Sites Service SHOULD be")], encoding="utf-8")
    with pytest.raises(generator.CatalogueError, match=r"sites\.md: bytes differ from the pinned"):
        generator.build(source, ("sites.md",))
    out = tmp_path / "out.json"
    result = run_generator("--source", source, "--out", out)
    assert result.returncode == 2
    assert not out.exists()


def test_check_detects_edited_catalogue(tmp_path, catalogue):
    catalogue["policies"]["GWS.SITES.1.1v1"]["baseline_text"] = "edited"
    edited = tmp_path / "edited.json"
    edited.write_text(json.dumps(catalogue), encoding="utf-8")
    result = run_generator("--source", FIXTURE, "--out", edited, "--check", "--partial", PARTIAL)
    assert result.returncode == 1
    assert "GWS.SITES.1.1v1" in result.stderr


def test_check_with_missing_catalogue_is_drift(tmp_path):
    result = run_generator("--source", FIXTURE, "--out", tmp_path / "none.json", "--check", "--partial", PARTIAL)
    assert result.returncode == 1


def test_partial_generation_is_refused(tmp_path):
    result = run_generator("--source", FIXTURE, "--out", tmp_path / "out.json", "--partial", PARTIAL)
    assert result.returncode == 2
    assert not (tmp_path / "out.json").exists()


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("Gemini app user access SHALL be set to OFF for everyone without a license.", "", "no statement"),
        ("SHALL be set to OFF", "is set to OFF", "exactly one of SHALL and SHOULD"),
        ("[![Manual](https://img.shields.io/badge/Manual-046B9A)](#gwsgemini31v1-instructions)", "", "Manual badge"),
        ("#### GWS.GEMINI.1.1v1\n", "#### GWS.GEMINI.1.1v2\n", "malformed policy heading"),
    ],
)
def test_malformed_baseline_is_refused(generator, monkeypatch, tmp_path, old, new, message):
    source = fixture_copy(tmp_path)
    gemini = source / BASELINES / "gemini.md"
    text = gemini.read_text(encoding="utf-8")
    assert old in text
    gemini.write_text(text.replace(old, new, 1), encoding="utf-8")
    unpinned(generator, monkeypatch, source)
    with pytest.raises(generator.CatalogueError, match=message):
        generator.build(source, ("gemini.md",))


def test_malformed_heading_is_reported_by_file_and_line_only(generator):
    text = "## 1. Grp\n\n#### GWS./Users/synthetic/review\nA SHALL b.\n"
    with pytest.raises(generator.CatalogueError) as raised:
        generator.parse_baseline("sites.md", text)
    assert str(raised.value) == "sites.md: line 3: malformed policy heading"


def test_malformed_heading_in_a_checkout_discloses_no_input_text(tmp_path):
    source = fixture_copy(tmp_path)
    sites = source / BASELINES / "sites.md"
    text = sites.read_text(encoding="utf-8")
    sites.write_text(text.replace("#### GWS.SITES.1.1v1", "#### GWS./Users/synthetic/review", 1), encoding="utf-8")
    result = run_generator("--source", source, "--out", CATALOGUE, "--check", "--partial", PARTIAL)
    assert result.returncode == 2
    assert "synthetic" not in result.stderr and "/Users" not in result.stderr and str(tmp_path) not in result.stderr


@pytest.mark.parametrize(
    "content",
    ["null", "[]", "42", '"x"', "{}", '{"source": null}', '{"source": {"files": null}}', '{"source": {}, "policies": {}}',
     '{"source": {"files": {}}, "policies": null}', '{"source": {"files": {}}, "policies": []}'],
)
def test_malformed_catalogue_structure_exits_two_without_a_traceback(tmp_path, content):
    out = tmp_path / "out.json"
    out.write_text(content, encoding="utf-8")
    result = run_generator("--source", FIXTURE, "--out", out, "--check", "--partial", PARTIAL)
    assert result.returncode == 2
    assert result.stderr == "catalogue error: the committed catalogue has a malformed structure\n"


def test_deeply_nested_catalogue_is_drift_not_a_traceback(tmp_path):
    out = tmp_path / "out.json"
    out.write_text("[" * 200000, encoding="utf-8")
    result = run_generator("--source", FIXTURE, "--out", out, "--check", "--partial", PARTIAL)
    assert result.returncode == 1
    assert "Traceback" not in result.stderr


def test_unwritable_output_and_unreadable_catalogue_exit_two(tmp_path):
    result = run_generator("--source", FIXTURE, "--out", tmp_path / "missing" / "x.json", "--partial", PARTIAL, "--check")
    assert result.returncode == 1  # a missing catalogue is drift
    result = run_generator("--source", FIXTURE, "--out", tmp_path, "--check", "--partial", PARTIAL)
    assert result.returncode == 2
    assert str(tmp_path) not in result.stderr


def test_badge_without_blank_line_is_not_statement_text(generator):
    text = "## 1. Grp\n#### GWS.GEMINI.3.1v1\nA SHALL b.\n[![Manual](m)](n)\n[![Log-Based Check](x)](y)\n"
    (item,) = generator.parse_baseline("x.md", text)
    assert (item["baseline_text"], item["manual"], item["events"]) == ("A SHALL b.", True, True)


def test_unnumbered_group_heading_clears_the_group(generator):
    text = "## 1. Grp\n## Appendix\n#### GWS.GEMINI.3.1v1\nA SHALL b.\n"
    with pytest.raises(generator.CatalogueError, match="no numbered group heading"):
        generator.parse_baseline("x.md", text)


def test_statement_with_both_keywords_is_refused(generator):
    text = "## 1. Grp\n#### GWS.GEMINI.3.1v1\nAdmins SHOULD a. Admins SHALL b.\n"
    with pytest.raises(generator.CatalogueError, match="exactly one"):
        generator.parse_baseline("x.md", text)


def test_symlinked_baseline_is_refused(tmp_path):
    source = fixture_copy(tmp_path)
    sites = source / BASELINES / "sites.md"
    sites.unlink()
    sites.symlink_to(source / BASELINES / "gemini.md")
    result = run_generator("--source", source, "--out", CATALOGUE, "--check", "--partial", PARTIAL)
    assert result.returncode == 2
    assert "not a regular file" in result.stderr


def test_statement_trims_at_a_sentence_boundary(generator):
    sentence = "Word " * 30 + "end."
    text = " ".join([sentence] * 4)
    trimmed = generator.trim_statement(text)
    assert trimmed == " ".join([sentence] * 2)
    with pytest.raises(generator.CatalogueError):
        generator.trim_statement("word " * 100)


@pytest.mark.skipif(not os.environ.get("AUDITEX_GWS_SCUBA_CHECKOUT"), reason="needs the pinned ScubaGoggles checkout")
def test_committed_catalogue_matches_pinned_checkout():
    result = run_generator("--source", os.environ["AUDITEX_GWS_SCUBA_CHECKOUT"], "--out", CATALOGUE, "--check")
    assert (result.returncode, result.stderr) == (0, "")


@pytest.mark.parametrize(("person", "key"), [("Group Title", "GroupTitle"), ("Log Based", "LogBased"), ("Product", "Product")])
def test_gws_catalogue_does_not_unmask_m365_mapping_keys(tmp_path, person, key):
    """The catalogue keys reuse registered field names; the shared exemption list is not widened, so an M365 report
    mapping key that spells a person's name is still pseudonymised in the shareable JSON preview."""
    from test_redaction_person_names import _key, _prose, _run, _user

    from auditex.reporting import preview_report
    from azure_tenant_audit import output_redaction

    root = _run(tmp_path / "run", [_user(person, "directory-fixture@example.invalid")], narrative=f"{person} reviewed it")
    report = root / "reports" / "report-pack.json"
    payload = json.loads(report.read_text())
    payload["executive_summary"]["per_reviewer"] = {key: 1}
    report.write_text(json.dumps(payload))

    content = preview_report(run_dir=str(root), format_name="json", include_sections=["executive_summary"],
                             profile="shareable")["content"]

    assert f'"{key}"' not in content
    assert f'"{_prose(_key(root), person)}": 1' in content
    assert key.lower() not in output_redaction._D5_FIELD_NAMES



@pytest.mark.parametrize("field,wrong", [("manual", 0), ("events", 0), ("manual", 0.0), ("events", "false")])
def test_partial_check_tells_false_from_zero_and_other_types(tmp_path, field, wrong):
    # Both partial rows have false here; Python equality would let 0 and 0.0 pass for it.
    catalogue = json.loads(CATALOGUE.read_text(encoding="utf-8"))
    catalogue["policies"]["GWS.SITES.1.1v1"][field] = wrong
    edited = tmp_path / "edited.json"
    edited.write_text(json.dumps(catalogue), encoding="utf-8")
    result = run_generator("--source", FIXTURE, "--out", edited, "--check", "--partial", PARTIAL)
    assert result.returncode == 1
    assert result.stderr == "drift: GWS.SITES.1.1v1\n"


def test_partial_check_tells_true_from_one(tmp_path):
    catalogue = json.loads(CATALOGUE.read_text(encoding="utf-8"))
    catalogue["policies"]["GWS.GEMINI.3.1v1"]["manual"] = 1  # the committed value is true
    edited = tmp_path / "edited.json"
    edited.write_text(json.dumps(catalogue), encoding="utf-8")
    result = run_generator("--source", FIXTURE, "--out", edited, "--check", "--partial", PARTIAL)
    assert result.returncode == 1
    assert result.stderr == "drift: GWS.GEMINI.3.1v1\n"


def test_strict_equal_literals(generator):
    equal = generator.strict_equal
    assert equal(True, True) and equal(0, 0) and equal(1.5, 1.5) and equal("a", "a") and equal(None, None)
    assert not equal(0, False) and not equal(False, 0) and not equal(1, True) and not equal(True, 1)
    assert not equal(1, 1.0) and not equal(1.0, 1) and not equal(0, 0.0)
    assert not equal("1", 1) and not equal(None, False) and not equal([], {})
    assert equal({"a": [1, {"b": False}]}, {"a": [1, {"b": False}]})
    assert not equal({"a": [1, {"b": False}]}, {"a": [1, {"b": 0}]})
    assert not equal({"a": 1}, {"a": 1, "b": 2}) and not equal({"a": 1, "b": 2}, {"a": 1})
    assert not equal([1, 2], [1]) and not equal([1], [1, 2]) and not equal([1, 2], [2, 1])


def test_the_committed_catalogue_still_matches_after_the_strict_comparison(generator):
    committed = generator.load_catalogue(CATALOGUE.read_text(encoding="utf-8"))
    built = generator.build(FIXTURE, ("gemini.md", "sites.md"))
    assert generator.differences(built, committed) == []


@pytest.mark.parametrize("where", ["top", "policy"])
def test_partial_check_refuses_duplicate_keys_in_the_committed_catalogue(tmp_path, where):
    text = CATALOGUE.read_text(encoding="utf-8")
    if where == "top":
        old = '{\n  "schema_version"'
        new = '{\n  "schema_version": "2026-11-25",\n  "schema_version"'
    else:
        old = '"GWS.SITES.1.1v1": {\n      "service": "SITES",'
        new = '"GWS.SITES.1.1v1": {\n      "service": "SITES",\n      "service": "SITES",'
    assert text.count(old) == 1
    edited = tmp_path / "dup.json"
    edited.write_text(text.replace(old, new), encoding="utf-8")
    json.loads(edited.read_text(encoding="utf-8"))  # plain json.loads accepts it, which is the bug
    result = run_generator("--source", FIXTURE, "--out", edited, "--check", "--partial", PARTIAL)
    assert result.returncode == 1
    assert result.stderr == "drift: the committed catalogue repeats a key\n"


def test_load_catalogue_rejects_nested_duplicates_and_keeps_plain_json(generator):
    assert generator.load_catalogue('{"a": {"b": [1, {"c": 2}]}}') == {"a": {"b": [1, {"c": 2}]}}
    with pytest.raises(generator.DuplicateKeyError):
        generator.load_catalogue('{"a": {"b": [1, {"c": 2, "c": 3}]}}')
