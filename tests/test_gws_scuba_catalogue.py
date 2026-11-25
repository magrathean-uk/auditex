"""Baseline section catalogue for the Google Workspace SCuBA baselines (ScubaGoggles v1.1.0)."""

from __future__ import annotations

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
    assert Counter(item["product"] for item in policies.values()) == PRODUCT_COUNTS
    for item in policies.values():
        assert set(item) == {"product", "group_title", "baseline_text", "criticality", "manual", "log_based", "sections"}
        assert item["criticality"] in {"SHALL", "SHOULD"}
        assert 0 < len(item["baseline_text"]) <= 400
        assert item["group_title"]


def test_manual_and_log_based_sets(catalogue):
    policies = catalogue["policies"]
    assert {pid for pid, item in policies.items() if item["manual"]} == MANUAL_IDS
    assert {pid for pid, item in policies.items() if item["log_based"]} == LOG_BASED_IDS


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
    assert policies["GWS.GMAIL.3.1v1"]["group_title"] == "Sender Policy Framework"
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


def test_check_passes_on_fixture_checkout():
    result = run_generator("--source", FIXTURE, "--out", CATALOGUE, "--check", "--partial")
    assert (result.returncode, result.stderr) == (0, "")


def test_check_without_partial_refuses_an_incomplete_checkout():
    result = run_generator("--source", FIXTURE, "--out", CATALOGUE, "--check")
    assert result.returncode == 2
    assert "baseline file missing" in result.stderr
    assert str(FIXTURE) not in result.stderr


def test_check_detects_edited_baseline(tmp_path):
    source = fixture_copy(tmp_path)
    sites = source / BASELINES / "sites.md"
    sites.write_text(sites.read_text(encoding="utf-8").replace("SHALL", "SHOULD", 1), encoding="utf-8")
    result = run_generator("--source", source, "--out", CATALOGUE, "--check", "--partial")
    assert result.returncode == 1
    assert "sites.md" in result.stderr


def test_check_detects_edited_catalogue(tmp_path, catalogue):
    catalogue["policies"]["GWS.SITES.1.1v1"]["baseline_text"] = "edited"
    edited = tmp_path / "edited.json"
    edited.write_text(json.dumps(catalogue), encoding="utf-8")
    result = run_generator("--source", FIXTURE, "--out", edited, "--check", "--partial")
    assert result.returncode == 1
    assert "GWS.SITES.1.1v1" in result.stderr


def test_check_with_missing_catalogue_is_drift(tmp_path):
    result = run_generator("--source", FIXTURE, "--out", tmp_path / "none.json", "--check", "--partial")
    assert result.returncode == 1


def test_partial_generation_is_refused(tmp_path):
    result = run_generator("--source", FIXTURE, "--out", tmp_path / "out.json", "--partial")
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
def test_malformed_baseline_is_refused(tmp_path, old, new, message):
    source = fixture_copy(tmp_path)
    gemini = source / BASELINES / "gemini.md"
    text = gemini.read_text(encoding="utf-8")
    assert old in text
    gemini.write_text(text.replace(old, new, 1), encoding="utf-8")
    result = run_generator("--source", source, "--out", tmp_path / "out.json", "--check", "--partial")
    assert result.returncode == 2
    assert message in result.stderr


def test_unwritable_output_and_unreadable_catalogue_exit_two(tmp_path):
    result = run_generator("--source", FIXTURE, "--out", tmp_path / "missing" / "x.json", "--partial", "--check")
    assert result.returncode == 1  # a missing catalogue is drift
    result = run_generator("--source", FIXTURE, "--out", tmp_path, "--check", "--partial")
    assert result.returncode == 2
    assert str(tmp_path) not in result.stderr


def test_badge_without_blank_line_is_not_statement_text(generator):
    text = "## 1. Grp\n#### GWS.GEMINI.3.1v1\nA SHALL b.\n[![Manual](m)](n)\n[![Log-Based Check](x)](y)\n"
    (item,) = generator.parse_baseline("x.md", text)
    assert (item["baseline_text"], item["manual"], item["log_based"]) == ("A SHALL b.", True, True)


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
    result = run_generator("--source", source, "--out", CATALOGUE, "--check", "--partial")
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
