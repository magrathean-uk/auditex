"""Google Workspace SCuBA answers in reports, the customer pack and the local answer (M13 L16, design section 9.3).

Synthetic runs only: the shipped Google sample replayed offline, and hand-written assessment rows. Expected texts are
literals copied from the shipped catalogues, never computed by the code under test.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_gws_scuba_projection import dns_only, good_domain

from auditex import local_answer as la
from auditex.answer_digest import DigestError, build_digest, digest_from_assessment
from auditex.cli import main
from auditex.google_workspace.run import run_google_offline
from auditex.mcp_registry import TOOL_REGISTRY
from auditex.reporting import (
    _append_policy_explanations_markdown,
    _load_policy_explanations,
    _render_policy_explanations_html,
    preview_report,
    write_enterprise_handoff_pack,
)
from auditex.rule_assessment import assess_run
from azure_tenant_audit.scuba_assessment import validate_assessment

pytest_plugins = ("test_gws_scuba_projection",)

REPO = Path(__file__).resolve().parents[1]
GWS_TITLE = "CISA SCuBA Google Workspace (ScubaGoggles v1.1.0)"
GWS = "cisa-scubagoggles-v1.1.0"
DMARC_POLICY = "GWS.GMAIL.4.1v1"
DMARC_REQUIREMENT = ("A DMARC policy SHALL be published at the full domain or the second-level domain for all Google "
                     "Workspace domains, including user alias domains.")
DMARC_MET = "Requirement met: every domain the policy covers meets it."
DMARC_STEP = ("Correct the failing domain's SPF TXT, DKIM selector or DMARC TXT (at _dmarc) record at its DNS host; "
              "generate DKIM keys in the Admin console, then publish them in DNS.")
NO_RULE = "Not assessed: Auditex has no rule for this policy yet."
M365_MET = "Requirement met: a Conditional Access policy meets every condition."


@pytest.fixture(scope="module")
def google_run(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The shipped synthetic Google sample replayed offline and assessed against all 138 ScubaGoggles policies."""
    out = tmp_path_factory.mktemp("gws-report")
    assert run_google_offline(sample_path=REPO / "examples/google_workspace_sample.json", out=out, tenant_name="ci",
                              run_name="google", domain="example.com", customer_id=None,
                              as_of=datetime(2026, 11, 11, tzinfo=UTC)) == 0
    [run] = [path for path in out.iterdir() if path.is_dir()]
    assert main(["assess", str(run)]) == 0
    assessment = json.loads((run / "model_assessment.json").read_text())
    assert assessment["baseline"] == GWS and len(assessment["policies"]) == 138
    assert sum("explainer" in row for row in assessment["policies"]) == 138
    return run


@pytest.mark.parametrize("profile", ["local", "shareable", "customer_pack"])
@pytest.mark.parametrize("fmt", ["md", "html"])
def test_gws_explanations_render_under_the_scubagoggles_title(google_run: Path, fmt: str, profile: str) -> None:
    output = preview_report(run_dir=str(google_run), format_name=fmt, profile=profile)
    assert "policy_explanations" in output["sections"]
    content = output["content"]
    heading = f"## {GWS_TITLE}\n" if fmt == "md" else f"<section><h2>{GWS_TITLE}</h2>"
    assert content.count(heading) == 1
    assert "Policy explanations" not in content
    assert ("GWS\\.GMAIL\\.4\\.1v1" if fmt == "md" else "GWS.GMAIL.4.1v1") in content
    assert "What this means" in content


def test_gws_json_preview_keeps_the_row_contract(google_run: Path) -> None:
    rows = json.loads(preview_report(run_dir=str(google_run), format_name="json", profile="customer_pack")["content"]
                      )["sections"]["policy_explanations"]
    assert {key for row in rows for key in row} == {"policy_id", "verdict", "explainer"}
    assert all(row["policy_id"].startswith("GWS.") for row in rows)


def test_customer_pack_report_carries_the_gws_section(google_run: Path, tmp_path: Path) -> None:
    write_enterprise_handoff_pack(google_run, tmp_path / "pack")
    report = (tmp_path / "pack" / "report.md").read_text()
    assert f"## {GWS_TITLE}\n" in report and "Policy explanations" not in report


M365_ROW = {"policy_id": "MS.AAD.1.1v1", "verdict": "not_met",
            "explainer": {"explanation": "Something is off.", "remediation_steps": ["Fix it."]}}


def test_m365_policy_section_renders_exactly_as_before() -> None:
    """Without a Google heading (every Microsoft 365 report) the section is byte for byte what it always was."""
    lines: list[str] = []
    _append_policy_explanations_markdown(lines, [M365_ROW])
    assert "\n".join(lines) == ("\n## Policy explanations\n\n### MS\\.AAD\\.1\\.1v1 - Not met\n\n**What this means**\n\n"
                                "Something is off\\.\n\n**What to do**\n\n1. Fix it\\.\n")
    assert _render_policy_explanations_html([M365_ROW]) == (
        "<section><h2>Policy explanations</h2><h3>MS.AAD.1.1v1 - Not met</h3><h4>What this means</h4>"
        "<p>Something is off.</p><h4>What to do</h4><ol><li>Fix it.</li></ol></section>")
    # A heading that is not the Google one changes nothing.
    for heading in (None, {}, {"title": "Policy explanations"}, {"title": GWS_TITLE.upper()}, ["title"]):
        assert _render_policy_explanations_html([M365_ROW], heading) == _render_policy_explanations_html([M365_ROW])


# --- Repair round (review M13-L16): admission, withheld evidence, redacted heading, coverage ----------------------

WITHHELD_DNS = "Data unavailable: required evidence section(s) not collected: gws_dns."
PARTIAL_REPORT = ("Partial: the rules assessed 1 of the 138 SCuBA Google Workspace checks in the shipped catalogue; "
                  "the other 137 are not in this report.")


@pytest.fixture
def dmarc_run(bundle: Path) -> Path:
    """A synthetic Google run with one completely read domain and a valid DMARC TXT record, assessed for
    GWS.GMAIL.4.1v1 only: the rules answer met."""
    dns_only(bundle, good_domain())
    assert main(["assess", str(bundle), "--policies", DMARC_POLICY]) == 0
    [row] = json.loads((bundle / "model_assessment.json").read_text())["policies"]
    assert row["claims"][0] == {"id": "requirement_met", "status": "confirmed", "value": True,
                                "evidence_ids": ["e0", "e1"]}
    return bundle


def _rewrite_assessment(run: Path, change) -> dict:
    path = run / "model_assessment.json"
    payload = json.loads(path.read_text())
    change(payload)
    sections = payload["projection"]["sections"].values()
    payload["limitations"] = [] if any(s["status"] == "projected" for s in sections) else ["projection_not_implemented"]
    validate_assessment(payload)          # the contradiction is schema-valid: only admission can catch it
    path.write_text(json.dumps(payload))
    return payload


def _withhold(name: str):
    def change(payload: dict) -> None:
        payload["projection"]["sections"][name] = {"status": "not_collected", "reason": "oversize",
                                                   "source": ["run-manifest.json"]}
    return change


def test_a_pass_from_withheld_dns_evidence_is_not_assessed(dmarc_run: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _rewrite_assessment(dmarc_run, _withhold("gws_dns"))
    [item] = build_digest(dmarc_run)["items"]
    assert item["verdict"] == "not_assessed"
    values = {value["name"]: (value["text"], value["source"]) for value in item["values"]}
    assert values["reason"] == (WITHHELD_DNS, "catalogue")
    assert _load_policy_explanations(dmarc_run, {"run_id": "synthetic"})[0]["verdict"] == "not_assessed"
    content = preview_report(run_dir=str(dmarc_run), format_name="md", profile="local")["content"]
    assert "GWS\\.GMAIL\\.4\\.1v1 - Not assessed" in content and " - Met" not in content
    monkeypatch.setattr(la, "runtime_version", lambda: None)
    answer = la.explain_run(dmarc_run)
    assert [entry["verdict"] for entry in answer["items"]] == ["not_assessed"]


def test_an_unrelated_withheld_section_keeps_the_dns_answer(dmarc_run: Path) -> None:
    _rewrite_assessment(dmarc_run, _withhold("gws_admins"))
    [item] = build_digest(dmarc_run)["items"]
    assert item["verdict"] == "met"
    assert {value["name"]: value["text"] for value in item["values"]}["reason"] == DMARC_MET


@pytest.mark.parametrize("manifest", [
    {"run_id": "synthetic", "platform": "m365"},
    {"run_id": "synthetic"},
])
def test_a_google_assessment_in_a_microsoft_run_is_refused(dmarc_run: Path, tmp_path: Path, manifest: dict,
                                                            capsys: pytest.CaptureFixture[str]) -> None:
    run = tmp_path / "m365"
    run.mkdir()
    (run / "run-manifest.json").write_text(json.dumps(manifest))
    (run / "model_assessment.json").write_bytes((dmarc_run / "model_assessment.json").read_bytes())
    with pytest.raises(DigestError, match="belongs to another run"):
        build_digest(run)
    assert _load_policy_explanations(run, manifest) == []
    assert main(["explain", str(run)]) == 2
    assert "Met: 1" not in capsys.readouterr().out
    assert not (run / "local_answer.json").exists()


def test_a_microsoft_assessment_in_a_google_run_is_refused(tmp_path: Path) -> None:
    m365 = tmp_path / "m365"
    m365.mkdir()
    (m365 / "run-manifest.json").write_text('{"run_id":"synthetic"}')
    assess_run(m365, policies=["MS.POWERBI.1.1v1"])
    assert build_digest(m365)["catalogue"] == {"policies": 102, "assessed": 1}     # legacy: no baseline, no platform
    google = tmp_path / "google"
    google.mkdir()
    manifest = {"run_id": "synthetic", "platform": "google_workspace"}
    (google / "run-manifest.json").write_text(json.dumps(manifest))
    (google / "model_assessment.json").write_bytes((m365 / "model_assessment.json").read_bytes())
    with pytest.raises(DigestError, match="belongs to another run"):
        build_digest(google)
    assert _load_policy_explanations(google, manifest) == []


@pytest.fixture(scope="module")
def masked_name_run(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The shipped sample with one directory user named "Gws Gmail", assessed for GWS.GMAIL.4.1v1 only."""
    out = tmp_path_factory.mktemp("gws-masked")
    sample = json.loads((REPO / "examples/google_workspace_sample.json").read_text())
    [user] = [u for u in sample["google_directory"]["users"]["value"] if u["id"] == "u-user"]
    user["name"]["fullName"] = "Gws Gmail"
    (out / "sample.json").write_text(json.dumps(sample))
    runs = out / "runs"
    assert run_google_offline(sample_path=out / "sample.json", out=runs, tenant_name="ci", run_name="google",
                              domain="example.com", customer_id=None,
                              as_of=datetime(2026, 11, 11, tzinfo=UTC)) == 0
    [run] = [path for path in runs.iterdir() if path.is_dir()]
    assert main(["assess", str(run), "--policies", DMARC_POLICY]) == 0
    return run


@pytest.mark.parametrize("profile", ["shareable", "customer_pack"])
def test_a_masked_policy_id_keeps_the_google_heading(masked_name_run: Path, profile: str) -> None:
    md = preview_report(run_dir=str(masked_name_run), format_name="md", profile=profile)["content"]
    html = preview_report(run_dir=str(masked_name_run), format_name="html", profile=profile)["content"]
    assert md.count(f"## {GWS_TITLE}\n") == 1 and "Policy explanations" not in md
    assert html.count(f"<section><h2>{GWS_TITLE}</h2>") == 1 and "Policy explanations" not in html


def test_the_customer_pack_keeps_the_google_heading_over_a_masked_id(masked_name_run: Path, tmp_path: Path) -> None:
    write_enterprise_handoff_pack(masked_name_run, tmp_path / "pack")
    report = (tmp_path / "pack" / "report.md").read_text()
    assert f"## {GWS_TITLE}\n\n{PARTIAL_REPORT}\n" in report and "Policy explanations" not in report


@pytest.mark.parametrize("fmt,expected", [
    ("md", f"## {GWS_TITLE}\n\n{PARTIAL_REPORT}\n\n### GWS\\.GMAIL\\.4\\.1v1 - Met\n"),
    ("html", f'<section><h2>{GWS_TITLE}</h2><p class="coverage-note">{PARTIAL_REPORT}</p><h3>GWS.GMAIL.4.1v1 - Met</h3>'),
])
def test_a_one_policy_google_report_states_its_coverage(dmarc_run: Path, fmt: str, expected: str) -> None:
    content = preview_report(run_dir=str(dmarc_run), format_name=fmt, profile="customer_pack",
                             include_sections=["policy_explanations"])["content"]
    assert content.count(expected) == 1


@pytest.mark.parametrize("fmt", ["md", "html"])
def test_a_full_google_report_has_no_partial_note(google_run: Path, fmt: str) -> None:
    content = preview_report(run_dir=str(google_run), format_name=fmt, profile="customer_pack",
                             include_sections=["policy_explanations"])["content"]
    assert "Partial:" not in content and "coverage-note" not in content


def test_gws_digest_builds_from_shipped_text_only(google_run: Path) -> None:
    digest = build_digest(google_run)
    assert digest["baseline"] == GWS
    assert digest["catalogue"] == {"policies": 138, "assessed": 138}
    assert len(digest["items"]) == 138
    # Every shipped text is marked catalogue; a rule's field and value stay tenant data, as for M365.
    assert {value["source"] for item in digest["items"] for value in item["values"]
            if value["name"] in ("check", "verdict", "severity", "requirement", "reason")} == {"catalogue"}
    assert {value["name"] for item in digest["items"] for value in item["values"]
            if value["source"] == "tenant"} <= {"field", "setting"}
    [dmarc] = [item for item in digest["items"] if item["policy_id"] == DMARC_POLICY]
    values = {value["name"]: value["text"] for value in dmarc["values"]}
    assert values["requirement"] == DMARC_REQUIREMENT and values["severity"] == "Shall"


def test_gws_local_answer_is_written_checked_and_reported(google_run: Path, tmp_path: Path,
                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    import shutil

    run = tmp_path / "run"
    shutil.copytree(google_run, run)
    monkeypatch.setattr(la, "runtime_version", lambda: None)
    answer = la.explain_run(run)
    assert answer["status"] == "fixed_text" and answer["counts"]["items"] == 138
    assert "Partial:" not in answer["text"]
    assert la.load_answer(run)["text"] == answer["text"]
    for fmt in ("md", "html"):
        output = preview_report(run_dir=str(run), format_name=fmt, profile="customer_pack")
        assert "local_answer" in output["sections"]
        assert "Local answer" in output["content"]


class Recorder:
    """A backend that records the system prompts and answers nothing (every item shows its fixed text)."""

    def __init__(self) -> None:
        self.systems: list[str] = []

    def answer(self, system: str, intro: str, jobs) -> list[str | None]:
        self.systems.append(system)
        return [None] * len(jobs)


def _gws_rows(*rows: tuple[str, str], severity: str = "SHALL") -> dict:
    policies = [{"policy_id": pid, "reason": "rule_precheck", "validation_status": "valid", "limitations": [],
                 "recommendations": [],
                 "claims": [{"id": "requirement_met", "status": "confirmed", "value": True, "evidence_ids": ["e0"]},
                            {"id": "policy_criticality", "status": "confirmed", "value": severity,
                             "evidence_ids": ["e0"]}],
                 "rule_precheck": {"class": "value_rule", "rule_id": f"{pid}.k", "section": ["gws_dns"],
                                   "field": None, "value": None, "cell": "c", "reason_code": "c",
                                   "reason_text": reason}}
                for pid, reason in rows]
    return {"run_id": "synthetic", "baseline": GWS, "policies": policies}


def test_prompts_name_the_platform_of_the_digest() -> None:
    gws = digest_from_assessment(_gws_rows((DMARC_POLICY, DMARC_MET)))
    m365 = digest_from_assessment({"run_id": "synthetic", "policies": []})
    recorder = Recorder()
    la.run_model(gws, recorder)
    item, summary = recorder.systems
    assert item.startswith("You choose what Auditex tells a user about one security check of their Google "
                           "Workspace tenant.\n")
    assert summary.startswith("You choose the opening of Auditex's answer for a whole audit run of a Google "
                              "Workspace tenant.\n")
    assert "Microsoft 365" not in item and "Microsoft 365" not in summary
    # The Microsoft 365 prompts are unchanged, word for word.
    assert la.item_system(m365) == la.item_system()
    assert la.item_system().startswith("You choose what Auditex tells a user about one security check of their "
                                       "Microsoft 365 tenant.\n")
    assert la.summary_system(m365) == la.SUMMARY_SYSTEM
    assert la.SUMMARY_SYSTEM.startswith("You choose the opening of Auditex's answer for a whole audit run of a "
                                        "Microsoft 365 tenant.\n")
    for other in (None, {}, {"baseline": "cisa-scuba-m365-v3.9.1"}, {"baseline": GWS.upper()}, ["baseline"]):
        assert la.item_system(other) == la.item_system()
        assert la.summary_system(other) == la.SUMMARY_SYSTEM


def test_gws_reasons_are_catalogue_text_only_for_their_own_policy() -> None:
    digest = digest_from_assessment(_gws_rows(
        (DMARC_POLICY, DMARC_MET),                       # the policy's own cell text
        ("GWS.CHAT.1.1v1", DMARC_MET),                   # another kind's text on a policy of a different kind
        ("GWS.GMAIL.2.1v1", M365_MET),                   # a Microsoft 365 cell text on a Google policy
        ("GWS.GMAIL.3.1v1", "Requirement met: trust me."),
        ("GWS.CALENDAR.1.1v1", NO_RULE),                 # a shared reason holds for every policy
        ("GWS.FAKE.1.1v1", NO_RULE),                     # an id outside the catalogue is tenant data
    ))
    sources = {item["policy_id"]: {value["name"]: value["source"] for value in item["values"]}
               for item in digest["items"]}
    assert sources[DMARC_POLICY]["reason"] == "catalogue"
    assert sources["GWS.CHAT.1.1v1"]["reason"] == "tenant"
    assert sources["GWS.GMAIL.2.1v1"]["reason"] == "tenant"
    assert sources["GWS.GMAIL.3.1v1"]["reason"] == "tenant"
    assert sources["GWS.CALENDAR.1.1v1"]["reason"] == "catalogue"
    assert sources["GWS.FAKE.1.1v1"] == {"check": "tenant", "verdict": "catalogue", "severity": "catalogue",
                                         "reason": "tenant"}
    assert digest["catalogue"] == {"policies": 138, "assessed": 5}
    [fake] = [item for item in digest["items"] if item["policy_id"] == "GWS.FAKE.1.1v1"]
    assert "requirement" not in {value["name"] for value in fake["values"]}


def test_gws_bank_holds_the_baseline_text_and_the_kind_step() -> None:
    from auditex.answer_digest import item_bank

    digest = digest_from_assessment(_gws_rows((DMARC_POLICY, DMARC_MET)))
    [item] = digest["items"]
    item = dict(item, verdict="not_met")
    bank = item_bank(item)
    assert bank["requirement"]["text"] == DMARC_REQUIREMENT
    assert bank["step-1"]["text"] == DMARC_STEP and "step-2" not in bank


def test_gws_partial_answer_names_the_google_catalogue(tmp_path: Path) -> None:
    (tmp_path / "run-manifest.json").write_text('{"run_id":"google","platform":"google_workspace"}')
    assess_run(tmp_path, policies=[DMARC_POLICY])
    digest = build_digest(tmp_path)
    assert digest["catalogue"] == {"policies": 138, "assessed": 1}
    answer = la.assemble_answer(digest, {}, None, model=None, runtime=None, reason="runtime_missing")
    assert answer["summary"]["text"].startswith(
        "Partial: the rules assessed 1 of the 138 SCuBA Google Workspace checks in the shipped catalogue; the other "
        "137 are not in this answer.\n")


def test_m365_digest_and_partial_note_are_unchanged(tmp_path: Path) -> None:
    (tmp_path / "run-manifest.json").write_text('{"run_id":"synthetic"}')
    assess_run(tmp_path, policies=["MS.POWERBI.1.1v1"])
    digest = build_digest(tmp_path)
    assert set(digest) == {"digest_version", "run_id", "counts", "skipped", "catalogue", "items"}
    assert digest["catalogue"] == {"policies": 102, "assessed": 1}
    answer = la.assemble_answer(digest, {}, None, model=None, runtime=None, reason="runtime_missing")
    assert answer["summary"]["text"].startswith(
        "Partial: the rules assessed 1 of the 102 SCuBA checks in the shipped catalogue; the other 101 are not in "
        "this answer.\n")


def test_local_answer_tool_description_names_both_platforms() -> None:
    [entry] = [tool for tool in TOOL_REGISTRY if tool.name == "auditex_local_answer"]
    assert entry.description.startswith("Read a completed Microsoft 365 or Google Workspace run's local answer")


def test_gws_severity_uses_the_customer_terms_and_orders_shall_first() -> None:
    should = _gws_rows(("GWS.GMAIL.2.1v1", DMARC_MET), severity="SHOULD")["policies"]
    odd = _gws_rows(("GWS.GMAIL.3.1v1", DMARC_MET), severity="shall")["policies"]
    payload = _gws_rows((DMARC_POLICY, DMARC_MET))
    payload["policies"] = should + odd + payload["policies"]
    digest = digest_from_assessment(payload)
    assert [(item["policy_id"], item["severity"]) for item in digest["items"]] == [
        (DMARC_POLICY, "Shall"), ("GWS.GMAIL.2.1v1", "Should"), ("GWS.GMAIL.3.1v1", "shall")]
    sources = [{value["name"]: value["source"] for value in item["values"]}["severity"] for item in digest["items"]]
    assert sources == ["catalogue", "catalogue", "tenant"]


def test_m365_severity_is_not_renamed() -> None:
    payload = _gws_rows(("MS.AAD.1.1v1", M365_MET))
    del payload["baseline"]
    [item] = digest_from_assessment(payload)["items"]
    assert item["severity"] == "SHALL"
    assert {value["name"]: value["source"] for value in item["values"]}["severity"] == "tenant"


def test_m365_digest_never_reads_the_google_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import auditex.answer_digest as ad
    from auditex.answer_digest import item_bank

    def refuse(*_args):
        raise AssertionError("an M365 digest read a Google file")

    monkeypatch.setattr(ad, "_gws_catalogue", refuse)
    monkeypatch.setattr(ad, "_gws_requirements", refuse)
    monkeypatch.setattr(ad, "_gws_catalogue_sentences", refuse)
    (tmp_path / "run-manifest.json").write_text('{"run_id":"synthetic"}')
    assess_run(tmp_path, policies=["MS.POWERBI.1.1v1"])
    [item] = build_digest(tmp_path)["items"]
    assert "requirement" in item_bank(item)


def test_a_google_reason_on_an_m365_payload_is_tenant_text() -> None:
    payload = _gws_rows((DMARC_POLICY, DMARC_MET))
    del payload["baseline"]
    [item] = digest_from_assessment(payload)["items"]
    sources = {value["name"]: value["source"] for value in item["values"]}
    assert sources["reason"] == "tenant" and sources["check"] == "tenant"
    assert "requirement" not in sources
