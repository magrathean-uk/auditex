"""scripts/scuba-parity.py: CISA tool verdicts against Auditex SCuBA answers, on synthetic example.com fixtures."""
from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scuba-parity.py"
FIXTURES = ROOT / "tests" / "fixtures" / "scuba-parity"
GEAR = FIXTURES / "scubagear-results.json"
GOGGLES = FIXTURES / "scubagoggles-results.json"
M365_ASSESSMENT = FIXTURES / "auditex-m365-assessment.json"
GWS_ASSESSMENT = FIXTURES / "auditex-gws-assessment.json"
SAME_INPUT = ROOT / "tests" / "fixtures" / "scubagear-export" / "mocktenant-scubaresults.json"
SENTINELS = ("SENTINEL-TENANT-ID", "SENTINEL-DISPLAY-NAME", "SENTINEL-DETAILS-TEXT", "admin@example.com",
             "11111111-1111-4111-8111-111111111111", "SENTINEL-NOT-A-SECRET")

_spec = importlib.util.spec_from_file_location("scuba_parity", SCRIPT)
parity = importlib.util.module_from_spec(_spec)
sys.modules["scuba_parity"] = parity
_spec.loader.exec_module(parity)

FIXED = {
    "cisa": "scuba-parity: the CISA result file is not a readable ScubaGear or ScubaGoggles result\n",
    "cisa_value": "scuba-parity: the CISA result file holds an unrecognised Result value\n",
    "auditex": "scuba-parity: the Auditex assessment is not readable\n",
    "platform": "scuba-parity: the CISA result and the Auditex assessment cover different platforms\n",
    "out": "scuba-parity: the output directory must be new or empty and not a link\n",
    "same_input": "scuba-parity: same-input mode needs a ScubaGear result file with its embedded export\n",
    "write": "scuba-parity: the parity report could not be written\n",
}


def _run(argv, capsys):
    code = parity.main([str(item) for item in argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _rows(out_dir: Path) -> dict[str, tuple]:
    report = json.loads((out_dir / "scuba-parity.json").read_text(encoding="utf-8"))
    return {row["policy_id"]: (row["category"], row["divergences"], row["cisa_result"], row["cisa_verdict"],
                               row["auditex_verdict"], row["auditex_reason_code"]) for row in report["rows"]}


def test_vocabularies_are_explicit_literals():
    assert parity.CISA_RESULTS == {
        "Pass": "pass", "Fail": "fail", "Warning": "fail", "N/A": "manual", "No events found": "no_events",
        "Error": "error", "Error - Test results missing": "error", "-": "deleted"}
    assert parity.CISA_OVERLAYS == {"Omitted": "omitted", "Incorrect result": "annotated_incorrect"}
    assert parity.AUDITEX_VERDICTS == ("met", "not_met", "not_applicable", "not_assessed")


def test_shared_scubagear_literals_match_the_export_adapter():
    from auditex.scubagear_export import VERDICT_MAP
    # The adapter's baseline: Pass pass, Fail fail, Warning fail, N/A not_assessed. Parity agrees on each.
    assert VERDICT_MAP == {"Pass": "pass", "Fail": "fail", "Warning": "fail", "N/A": "not_assessed"}
    for literal, status in VERDICT_MAP.items():
        decided = parity.CISA_RESULTS[literal] in parity.CISA_DECIDED
        assert (parity.CISA_RESULTS[literal] if decided else "not_assessed") == status


def test_reason_codes_outside_the_rule_catalogue_are_not_copied(tmp_path, capsys):
    doc = json.loads(M365_ASSESSMENT.read_text(encoding="utf-8"))
    doc["policies"][0]["rule_precheck"]["reason_code"] = "tenant.onmicrosoft.com"
    path = tmp_path / "model_assessment.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert _run([GEAR, path, "--out", tmp_path / "out"], capsys)[0] == 0
    assert _rows(tmp_path / "out")["MS.AAD.7.1v1"][5] == "unlisted_reason_code"
    for name in ("scuba-parity.json", "scuba-parity.md"):
        assert "onmicrosoft" not in (tmp_path / "out" / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("reason", [["rule_precheck"], {"x": 1}, 7])
def test_non_string_reason_exits_2(tmp_path, capsys, reason):
    doc = json.loads(M365_ASSESSMENT.read_text(encoding="utf-8"))
    doc["policies"][0]["reason"] = reason
    path = tmp_path / "model_assessment.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert _run([GEAR, path, "--out", tmp_path / "out"], capsys)[::2] == (2, FIXED["auditex"])


def test_non_ascii_digits_in_ids_are_refused(tmp_path, capsys):
    doc = _gear()
    _controls(doc)[0]["Control ID"] = "MS.AAD.\u0667.1v1"
    source = tmp_path / "results.json"
    source.write_text(json.dumps(doc), encoding="utf-8")
    assert _run([source, M365_ASSESSMENT, "--out", tmp_path / "out"], capsys)[::2] == (2, FIXED["cisa"])


def test_unreadable_auditex_folder_exits_2_without_a_path(tmp_path, capsys):
    locked = tmp_path / "locked"
    (locked / "run").mkdir(parents=True)
    locked.chmod(0)
    try:
        code, stdout, err = _run([GEAR, locked / "run", "--out", tmp_path / "out"], capsys)
    finally:
        locked.chmod(0o700)
    assert (code, stdout, err) == (2, "", FIXED["auditex"])


def test_tilde_paths_are_not_expanded(tmp_path, capsys):
    code, _, err = _run(["~nouser-parity/a.json", M365_ASSESSMENT, "--out", tmp_path / "out"], capsys)
    assert (code, err) == (2, FIXED["cisa"])


def test_a_row_without_limitations_is_refused_not_read_as_unknown(tmp_path, capsys):
    doc = json.loads(M365_ASSESSMENT.read_text(encoding="utf-8"))
    del doc["policies"][4]["limitations"]
    path = tmp_path / "model_assessment.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert _run([GEAR, path, "--out", tmp_path / "out"], capsys)[::2] == (2, FIXED["auditex"])


def test_scubagear_two_input_every_category(tmp_path, capsys):
    out = tmp_path / "out"
    code, stdout, err = _run([GEAR, M365_ASSESSMENT, "--out", out], capsys)
    assert (code, err) == (0, "")
    assert _rows(out) == {
        "MS.AAD.7.1v1": ("agree", [], "Pass", "pass", "met", "unlisted_reason_code"),
        "MS.AAD.7.2v1": ("documented_divergence", ["D107"], "Fail", "fail", "met", "least_privilege_ok"),
        "MS.AAD.7.3v1": ("agree", [], "Warning", "fail", "not_met", "unlisted_reason_code"),
        "MS.AAD.7.4v1": ("auditex_decided", [], "N/A", "manual", "met", "unlisted_reason_code"),
        "MS.AAD.7.5v1": ("neither_decided", [], "Error", "error", "not_assessed", "unlisted_reason_code"),
        "MS.AAD.7.6v1": ("auditex_not_assessed", [], "Pass", "pass", "not_assessed", "unlisted_reason_code"),
        "MS.AAD.7.7v1": ("agree", [], "Pass", "pass", "not_applicable", "unlisted_reason_code"),
        "MS.AAD.7.8v1": ("disagreement", [], "Fail", "fail", "met", "unlisted_reason_code"),
        "MS.EXO.1.1v1": ("agree", [], "Omitted", "pass", "met", "unlisted_reason_code"),
        "MS.EXO.2.2v3": ("agree", [], "Incorrect result", "fail", "not_met", "unlisted_reason_code"),
        "MS.EXO.3.1v1": ("neither_decided", [], "-", "deleted", "not_assessed", "unlisted_reason_code"),
        "MS.EXO.4.1v1": ("auditex_not_assessed", [], "Pass", "pass", "not_assessed", "rule_not_implemented"),
        "MS.EXO.5.1v1": ("auditex_not_assessed", [], "Pass", "pass", "not_assessed", "not_a_rule_answer"),
        "MS.EXO.6.1v1": ("auditex_not_assessed", [], "Pass", "pass", "not_assessed", "absent_section"),
        "MS.EXO.9.9v1": ("cisa_only", [], "Pass", "pass", None, None),
        "MS.TEAMS.1.1v1": ("auditex_only", [], None, None, "met", "unlisted_reason_code"),
    }
    assert json.loads(stdout)["counts"] == {
        "agree": 5, "auditex_decided": 1, "auditex_not_assessed": 4, "auditex_only": 1, "cisa_only": 1,
        "disagreement": 1, "documented_divergence": 1, "neither_decided": 2, "release_delta": 0}
    report = json.loads((out / "scuba-parity.json").read_text(encoding="utf-8"))
    assert (report["cisa_tool"], report["cisa_tool_version"], report["version_matches"], report["mode"]) == (
        "ScubaGear", "2.0.0", True, "two-input")
    assert (report["pinned_version"], report["rule_reference"], report["full_parity"]) == (
        "2.0.0", "cisagov/ScubaGear@2446ad723b7f55031cc02c8aca244d731d468cba", False)
    assert report["release_delta_policies"] == ["MS.AAD.3.2v2", "MS.AAD.5.5v1", "MS.AAD.9.1v1"]
    markdown = (out / "scuba-parity.md").read_text(encoding="utf-8")
    assert "| MS.AAD.7.2v1 | Fail | fail | met | least_privilege_ok | documented_divergence | D107 |" in markdown
    assert "| disagreement | 1 |" in markdown


def test_scubagoggles_two_input_divergences_and_no_events(tmp_path, capsys):
    out = tmp_path / "out"
    code, _, err = _run([GOGGLES, GWS_ASSESSMENT, "--out", out], capsys)
    assert (code, err) == (0, "")
    assert _rows(out) == {
        "GWS.GMAIL.7.5v1": ("documented_divergence", ["D4", "D21"], "Pass", "pass", "not_met", "unlisted_reason_code"),
        "GWS.COMMONCONTROLS.1.4v1": ("documented_divergence", ["D5", "D8"], "Pass", "pass", "not_met",
                                     "unlisted_reason_code"),
        "GWS.CHAT.5.1v1": ("documented_divergence", ["D19"], "No events found", "no_events", "not_met",
                           "unlisted_reason_code"),
        "GWS.CALENDAR.1.1v1": ("neither_decided", [], "No events found", "no_events", "not_assessed",
                               "data_unavailable_no_setting_event"),
        "GWS.MEET.1.1v1": ("auditex_decided", [], "conflicting rows", "conflicting_rows", "met", "unlisted_reason_code"),
        "GWS.DRIVEDOCS.1.1v1": ("agree", [], "Warning", "fail", "not_met", "unlisted_reason_code"),
        # D2 is scoped to its reason code: the same pair with another reason is not documented.
        "GWS.ASSUREDCONTROLS.1.1v1": ("documented_divergence", ["D2"], "Pass", "pass", "not_assessed",
                                      "data_unavailable_setting_absent"),
        "GWS.ASSUREDCONTROLS.1.2v1": ("auditex_not_assessed", [], "Pass", "pass", "not_assessed",
                                      "unlisted_reason_code"),
    }


def test_same_input_mode_runs_the_adapter_on_the_embedded_export(tmp_path, capsys):
    out = tmp_path / "out"
    code, stdout, err = _run([SAME_INPUT, "--same-input", "--out", out], capsys)
    assert (code, err) == (0, "")
    rows = _rows(out)
    assert {pid: rows[pid] for pid in ("MS.AAD.1.1v1", "MS.AAD.7.1v1", "MS.AAD.7.2v1", "MS.AAD.7.3v1",
                                         "MS.AAD.7.4v1")} == {
        "MS.AAD.1.1v1": ("neither_decided", [], "Error", "error", "not_assessed", "data_unusable_policy_set"),
        "MS.AAD.7.1v1": ("agree", [], "Pass", "pass", "met", "ga_count_in_range"),
        "MS.AAD.7.2v1": ("documented_divergence", ["D107"], "Fail", "fail", "met", "least_privilege_ok"),
        "MS.AAD.7.3v1": ("agree", [], "Warning", "fail", "not_met", "federated_admin_found"),
        "MS.AAD.7.4v1": ("neither_decided", [], "N/A", "manual", "not_assessed", "data_unavailable_no_licence"),
    }
    assert {row[0] for pid, row in rows.items() if pid not in {"MS.AAD.1.1v1", "MS.AAD.7.1v1", "MS.AAD.7.2v1",
                                                               "MS.AAD.7.3v1", "MS.AAD.7.4v1"}} == {"auditex_only"}
    assert len(rows) == 102
    report = json.loads((out / "scuba-parity.json").read_text(encoding="utf-8"))
    assert (report["mode"], report["cisa_tool_version"], report["version_matches"]) == ("same-input", "2.0.0", True)
    assert sorted(p.name for p in out.iterdir()) == ["scuba-parity.json", "scuba-parity.md"]
    assert json.loads(stdout)["mode"] == "same-input"


def _private_tmp(tmp_path, monkeypatch) -> Path:
    scratch = tmp_path / "private-tmp"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    return scratch


def test_same_input_mode_writes_nothing_from_the_export(tmp_path, capsys, monkeypatch):
    scratch = _private_tmp(tmp_path, monkeypatch)
    doc = json.loads(SAME_INPUT.read_text(encoding="utf-8"))
    tenant_id = doc["Raw"]["tenant_id"]
    policy = next(p for p in doc["Raw"]["conditional_access_policies"] if p.get("State") == "enabled")
    policy["GrantControls"]["BuiltInControls"] = ["mfa"]
    policy["Conditions"].setdefault("Locations", {})
    policy["Conditions"]["Locations"] = {"IncludeLocations": ["22222222-2222-4222-8222-222222222222"]}
    policy["DisplayName"] = tenant_id
    source = tmp_path / "results.json"
    source.write_text(json.dumps(doc), encoding="utf-8")
    out = tmp_path / "out"
    code, stdout, err = _run([source, "--same-input", "--out", out], capsys)
    assert (code, err) == (0, "")
    assert sorted(p.name for p in out.iterdir()) == ["scuba-parity.json", "scuba-parity.md"]
    for text in [stdout] + [p.read_text(encoding="utf-8") for p in out.iterdir()]:
        assert tenant_id not in text and "22222222-2222-4222-8222-222222222222" not in text
        assert str(tmp_path) not in text
    assert list(scratch.iterdir()) == []


def test_same_input_adapter_failure_leaves_no_scratch_and_no_out(tmp_path, capsys, monkeypatch):
    scratch = _private_tmp(tmp_path, monkeypatch)
    import auditex.rule_assessment as rule_assessment

    def broken(export_path, output_dir, **_):
        Path(output_dir).mkdir(parents=True)
        (Path(output_dir) / "model_assessment.json").write_text("SENTINEL-TENANT-ID", encoding="utf-8")
        raise RuntimeError("SENTINEL-TENANT-ID")
    monkeypatch.setattr(rule_assessment, "assess_scubagear_export", broken)
    code, stdout, err = _run([SAME_INPUT, "--same-input", "--out", tmp_path / "out"], capsys)
    assert (code, stdout, err) == (
        2, "", "scuba-parity: Auditex could not assess the export embedded in the ScubaGear result\n")
    assert list(scratch.iterdir()) == [] and not (tmp_path / "out").exists()


def _gear_with(policy_id: str, version: str) -> dict:
    doc = _gear()
    doc["MetaData"]["ToolVersion"] = version
    for control in _controls(doc):
        if control["Control ID"] == "MS.AAD.7.8v1":
            control["Control ID"] = policy_id
    return doc


def _assessment_with(policy_id: str) -> dict:
    doc = _assessment()
    next(row for row in doc["policies"] if row["policy_id"] == "MS.AAD.7.8v1")["policy_id"] = policy_id
    return doc


@pytest.mark.parametrize(("version", "category", "matches"), [
    ("2.0.0", "release_delta", True), ("1.8.0", "disagreement", False)])
def test_policies_changed_after_the_rule_reference_are_labelled(tmp_path, capsys, version, category, matches):
    source, assessment = tmp_path / "results.json", tmp_path / "model_assessment.json"
    source.write_text(json.dumps(_gear_with("MS.AAD.5.5v1", version)), encoding="utf-8")
    assessment.write_text(json.dumps(_assessment_with("MS.AAD.5.5v1")), encoding="utf-8")
    assert _run([source, assessment, "--out", tmp_path / "out"], capsys)[0] == 0
    assert _rows(tmp_path / "out")["MS.AAD.5.5v1"][:5] == (category, [], "Fail", "fail", "met")
    report = json.loads((tmp_path / "out" / "scuba-parity.json").read_text(encoding="utf-8"))
    assert (report["version_matches"], report["full_parity"]) == (matches, False)
    markdown = (tmp_path / "out" / "scuba-parity.md").read_text(encoding="utf-8")
    assert ("not a parity result" in markdown) is (not matches)


def test_a_v1_8_report_never_claims_parity_for_security_suite_or_power_bi(tmp_path, capsys):
    doc = _gear()
    doc["MetaData"]["ToolVersion"] = "1.8.0"
    _controls(doc).append({"Control ID": "MS.DEFENDER.1.1v1", "Result": "Pass"})
    assessment = _assessment()
    for policy_id in ("MS.SECURITYSUITE.1.1v1", "MS.POWERBI.1.1v1"):
        assessment["policies"].append({**copy.deepcopy(assessment["policies"][0]), "policy_id": policy_id})
    source, path = tmp_path / "results.json", tmp_path / "model_assessment.json"
    source.write_text(json.dumps(doc), encoding="utf-8")
    path.write_text(json.dumps(assessment), encoding="utf-8")
    code, stdout, _ = _run([source, path, "--out", tmp_path / "out"], capsys)
    assert code == 0
    rows = _rows(tmp_path / "out")
    assert (rows["MS.DEFENDER.1.1v1"][0], rows["MS.SECURITYSUITE.1.1v1"][0], rows["MS.POWERBI.1.1v1"][0]) == (
        "cisa_only", "auditex_only", "auditex_only")
    assert (json.loads(stdout)["version_matches"], json.loads(stdout)["full_parity"]) == (False, False)


def _duplicate_accepted_domains(text: str) -> str:
    doc = json.loads(text)
    value = json.dumps(doc["Raw"]["accepted_domains"])
    anchor = '"Raw": {'
    index = text.index(anchor) + len(anchor)
    return text[:index] + f'"accepted_domains": {value},' + text[index:]


def test_duplicate_accepted_domains_in_the_export_is_accepted_like_the_adapter(tmp_path, capsys):
    source = tmp_path / "results.json"
    source.write_text(_duplicate_accepted_domains(SAME_INPUT.read_text(encoding="utf-8")), encoding="utf-8")
    code, _, err = _run([source, "--same-input", "--out", tmp_path / "out"], capsys)
    assert (code, err) == (0, "")
    report = json.loads((tmp_path / "out" / "scuba-parity.json").read_text(encoding="utf-8"))
    assert report["cisa_input_repaired"] is False
    assert _rows(tmp_path / "out")["MS.AAD.7.1v1"][:4] == ("agree", [], "Pass", "pass")


def test_a_duplicate_outside_the_export_is_refused(tmp_path, capsys):
    text = SAME_INPUT.read_text(encoding="utf-8")
    index = text.index('"MetaData": {') + len('"MetaData": {')
    source = tmp_path / "results.json"
    source.write_text(text[:index] + '"accepted_domains": [], "accepted_domains": [],' + text[index:],
                      encoding="utf-8")
    assert _run([source, "--same-input", "--out", tmp_path / "out"], capsys)[::2] == (2, FIXED["cisa"])


def test_a_repaired_file_keeps_its_declared_tool(tmp_path, capsys):
    doc = json.loads(SAME_INPUT.read_text(encoding="utf-8"))
    doc["MetaData"]["Tool"] = "ScubaGoggles"
    source = tmp_path / "results.json"
    source.write_text(_with_null_array(json.dumps(doc, indent=1), '"Raw": {', "transport_rule"), encoding="utf-8")
    assert _run([source, M365_ASSESSMENT, "--out", tmp_path / "out"], capsys)[::2] == (2, FIXED["cisa"])
    assert not (tmp_path / "out").exists()


def test_a_repair_outside_the_export_is_refused(tmp_path, capsys):
    text = SAME_INPUT.read_text(encoding="utf-8")
    index = text.index("{") + 1
    source = tmp_path / "results.json"
    source.write_text(text[:index] + '"SummaryFromReview": ,' + text[index:], encoding="utf-8")
    assert _run([source, M365_ASSESSMENT, "--out", tmp_path / "out"], capsys)[::2] == (2, FIXED["cisa"])
    assert not (tmp_path / "out").exists()


def test_a_scubagoggles_error_is_never_a_documented_divergence(tmp_path, capsys):
    doc = json.loads(GOGGLES.read_text(encoding="utf-8"))
    rows = [c for groups in doc["Results"].values() for g in groups for c in g["Controls"]
            if c["Control ID"] == "GWS.CHAT.5.1v1"]
    assert rows
    for control in rows:
        control["Result"] = "Error"
    source = tmp_path / "results.json"
    source.write_text(json.dumps(doc), encoding="utf-8")
    assert _run([source, GWS_ASSESSMENT, "--out", tmp_path / "out"], capsys)[0] == 0
    assert _rows(tmp_path / "out")["GWS.CHAT.5.1v1"][:5] == ("auditex_decided", [], "Error", "error", "not_met")


def test_a_second_invocation_never_removes_the_first_ones_reports(tmp_path, capsys, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    assert _run([GEAR, M365_ASSESSMENT, "--out", out], capsys)[0] == 0
    before = {p.name: p.read_bytes() for p in out.iterdir()}
    # The race the review found: both invocations passed the empty-directory check before either wrote.
    monkeypatch.setattr(parity, "_prepare_out", lambda _out: None)
    assert _run([GEAR, M365_ASSESSMENT, "--out", out], capsys)[::2] == (2, FIXED["write"])
    assert {p.name: p.read_bytes() for p in out.iterdir()} == before


@pytest.mark.parametrize(("cisa", "auditex"), [(GEAR, M365_ASSESSMENT), (GOGGLES, GWS_ASSESSMENT)])
def test_outputs_hold_no_tenant_text_or_paths(tmp_path, capsys, cisa, auditex):
    out = tmp_path / "out"
    code, stdout, err = _run([cisa, auditex, "--out", out], capsys)
    assert code == 0
    for text in (stdout, err, (out / "scuba-parity.json").read_text(encoding="utf-8"),
                 (out / "scuba-parity.md").read_text(encoding="utf-8")):
        assert not any(sentinel in text for sentinel in SENTINELS)
        assert str(tmp_path) not in text and str(ROOT) not in text and "example.com" not in text
    assert sorted(p.name for p in out.iterdir()) == ["scuba-parity.json", "scuba-parity.md"]
    assert {oct(p.stat().st_mode & 0o777) for p in out.iterdir()} == {"0o600"}


def _gear() -> dict:
    return json.loads(GEAR.read_text(encoding="utf-8"))


def _controls(doc: dict) -> list:
    return doc["Results"]["AAD"][0]["Controls"]


def _set_result(value):
    def mutate(doc):
        _controls(doc)[0]["Result"] = value
    return mutate


def _set_original(value):
    def mutate(doc):
        _controls(doc)[0].update({"Result": "Incorrect result", "OriginalResult": value})
    return mutate


@pytest.mark.parametrize("mutate", [
    _set_result("Passed"), _set_result("pass"), _set_result("PASS"), _set_result(""), _set_result("Manual"),
    _set_result("No Events Found"), _set_original("Passed"), _set_original("SENTINEL-DETAILS-TEXT"),
])
def test_unknown_verdict_strings_are_refused(tmp_path, capsys, mutate):
    doc = _gear()
    mutate(doc)
    source = tmp_path / "results.json"
    source.write_text(json.dumps(doc), encoding="utf-8")
    code, stdout, err = _run([source, M365_ASSESSMENT, "--out", tmp_path / "out"], capsys)
    assert (code, stdout, err) == (2, "", FIXED["cisa_value"])
    assert not (tmp_path / "out").exists()


def _drop(key):
    def mutate(doc):
        del doc[key]
    return mutate


def _cisa_mutations():
    def non_string_result(doc):
        _controls(doc)[0]["Result"] = None

    def bad_id(doc):
        _controls(doc)[0]["Control ID"] = "MS.AAD.7.1 SENTINEL-DETAILS-TEXT"

    def mixed_platforms(doc):
        _controls(doc)[0]["Control ID"] = "GWS.GMAIL.1.1v1"

    def declared_other_tool(doc):
        doc["MetaData"]["Tool"] = "ScubaGoggles"

    def empty_results(doc):
        doc["Results"] = {}

    def no_controls(doc):
        doc["Results"] = {"AAD": [{"GroupName": "Synthetic", "Controls": []}]}

    def controls_not_list(doc):
        doc["Results"]["AAD"][0]["Controls"] = {"MS.AAD.7.1v1": "Pass"}

    def control_not_object(doc):
        _controls(doc)[0] = "Pass"

    def group_not_object(doc):
        doc["Results"]["AAD"] = ["Pass"]

    return [_drop("MetaData"), _drop("Results"), non_string_result, bad_id, mixed_platforms, declared_other_tool,
            empty_results, no_controls, controls_not_list, control_not_object, group_not_object]


@pytest.mark.parametrize("mutate", _cisa_mutations())
def test_malformed_cisa_result_exits_2_with_a_fixed_message(tmp_path, capsys, mutate):
    doc = _gear()
    mutate(doc)
    source = tmp_path / "SENTINEL-DETAILS-TEXT.json"
    source.write_text(json.dumps(doc), encoding="utf-8")
    code, stdout, err = _run([source, M365_ASSESSMENT, "--out", tmp_path / "out"], capsys)
    assert (code, stdout, err) == (2, "", FIXED["cisa"])
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("payload", [
    b"", b"null", b"[]", b"{", b"\xff\xfe", b'{"MetaData": {}, "MetaData": {}, "Results": {}}',
    b'{"MetaData": {}, "Results": {"AAD": [{"Controls": [{"Control ID": "MS.AAD.7.1v1", "Result": "Pass", '
    b'"Score": NaN}]}]}}',
])
def test_unparseable_cisa_result_exits_2(tmp_path, capsys, payload):
    source = tmp_path / "SENTINEL-DETAILS-TEXT.json"
    source.write_bytes(payload)
    code, stdout, err = _run([source, M365_ASSESSMENT, "--out", tmp_path / "out"], capsys)
    assert (code, stdout, err) == (2, "", FIXED["cisa"])


def _with_null_array(text: str, anchor: str, key: str) -> str:
    index = text.index(anchor) + len(anchor)
    return text[:index] + f'"{key}": ,' + text[index:]


def test_powershell_null_array_in_raw_is_repaired_like_the_adapter(tmp_path, capsys):
    source = tmp_path / "results.json"
    source.write_text(_with_null_array(SAME_INPUT.read_text(encoding="utf-8"), '"Raw": {', "transport_rule"),
                      encoding="utf-8")
    code, _, err = _run([source, "--same-input", "--out", tmp_path / "out"], capsys)
    assert (code, err) == (0, "")
    report = json.loads((tmp_path / "out" / "scuba-parity.json").read_text(encoding="utf-8"))
    assert (report["cisa_input_repaired"], report["cisa_tool_version"]) == (True, "2.0.0")
    assert _rows(tmp_path / "out")["MS.AAD.7.1v1"][:4] == ("agree", [], "Pass", "pass")


def test_a_repair_inside_results_is_refused(tmp_path, capsys):
    source = tmp_path / "results.json"
    source.write_text(_with_null_array(SAME_INPUT.read_text(encoding="utf-8"), '"GroupName": "Mock",', "Notes"),
                      encoding="utf-8")
    assert _run([source, "--same-input", "--out", tmp_path / "out"], capsys)[::2] == (2, FIXED["cisa"])
    assert not (tmp_path / "out").exists()


def test_missing_and_linked_inputs_exit_2(tmp_path, capsys):
    missing = tmp_path / "SENTINEL-DETAILS-TEXT.json"
    assert _run([missing, M365_ASSESSMENT, "--out", tmp_path / "o1"], capsys)[2] == FIXED["cisa"]
    link = tmp_path / "link.json"
    link.symlink_to(GEAR)
    assert _run([link, M365_ASSESSMENT, "--out", tmp_path / "o2"], capsys)[::2] == (2, FIXED["cisa"])
    assert _run([tmp_path, M365_ASSESSMENT, "--out", tmp_path / "o3"], capsys)[::2] == (2, FIXED["cisa"])


def _assessment() -> dict:
    return json.loads(M365_ASSESSMENT.read_text(encoding="utf-8"))


def _auditex_mutations():
    def no_policies(doc):
        doc["policies"] = []

    def duplicate_policy(doc):
        doc["policies"].append(copy.deepcopy(doc["policies"][0]))

    def bad_policy_id(doc):
        doc["policies"][0]["policy_id"] = "SENTINEL-DETAILS-TEXT"

    def string_claim_value(doc):
        doc["policies"][0]["claims"][0]["value"] = "true"

    def unknown_with_value(doc):
        doc["policies"][0]["claims"][0].update({"status": "unknown", "value": False})

    def inferred_without_limitation(doc):
        doc["policies"][0]["claims"][0].update({"status": "inferred", "value": True})

    def no_requirement_claim(doc):
        doc["policies"][0]["claims"] = doc["policies"][0]["claims"][1:]

    def reason_code_free_text(doc):
        doc["policies"][0]["rule_precheck"]["reason_code"] = "SENTINEL DETAILS TEXT"

    def no_rule_precheck(doc):
        del doc["policies"][0]["rule_precheck"]

    def claims_not_list(doc):
        doc["policies"][0]["claims"] = None

    def not_applicable_without_limitations(doc):
        doc["policies"][6]["limitations"] = None

    # Review blocker 1: each of these left MS.AAD.7.1v1 a confirmed met before the repair.
    def invalid_row(doc):
        doc["policies"][0]["validation_status"] = "invalid"

    def null_evidence(doc):
        doc["policies"][0]["claims"][0]["evidence_ids"] = None

    def empty_evidence(doc):
        doc["policies"][0]["claims"][0]["evidence_ids"] = []

    def absent_section_with_a_verdict(doc):
        doc["policies"][0]["rule_precheck"].update({"class": "absent_section", "reason_code": "absent_section"})

    def absent_section_not_met(doc):
        absent_section_with_a_verdict(doc)
        doc["policies"][0]["claims"][0]["value"] = False

    def null_precheck_class(doc):
        doc["policies"][0]["rule_precheck"]["class"] = None

    def null_limitations(doc):
        doc["policies"][0]["limitations"] = None

    def list_schema_version(doc):
        doc["schema_version"] = ["2026-11-22"]

    def unknown_schema_version(doc):
        doc["schema_version"] = "2099-01-01"

    def value_rule_in_a_pre_rule_file(doc):
        doc["schema_version"] = "2026-10-29"
        for row in doc["policies"]:
            if "rule_precheck" in row:
                for key in ("cell", "reason_code", "reason_text"):
                    row["rule_precheck"].pop(key, None)

    def model_attempts_on_a_rule_row(doc):
        doc["policies"][0]["attempts"] = 1

    def prompt_hash_on_a_rule_row(doc):
        doc["policies"][0]["prompt_sha256"] = "0" * 64

    def confirmed_claim_on_an_uncovered_row(doc):
        doc["policies"][11]["claims"][0].update({"status": "confirmed", "value": True, "evidence_ids": ["e0"]})

    def third_claim(doc):
        doc["policies"][0]["claims"].append(copy.deepcopy(doc["policies"][0]["claims"][1]))

    return [no_policies, duplicate_policy, bad_policy_id, string_claim_value, unknown_with_value,
            inferred_without_limitation, no_requirement_claim, reason_code_free_text, no_rule_precheck,
            claims_not_list, not_applicable_without_limitations, _drop("policies"), invalid_row, null_evidence,
            empty_evidence, absent_section_with_a_verdict, absent_section_not_met, null_precheck_class,
            null_limitations, list_schema_version, unknown_schema_version, _drop("schema_version"),
            value_rule_in_a_pre_rule_file, model_attempts_on_a_rule_row, prompt_hash_on_a_rule_row,
            confirmed_claim_on_an_uncovered_row, third_claim]


@pytest.mark.parametrize("mutate", _auditex_mutations())
def test_malformed_auditex_assessment_exits_2_and_writes_nothing(tmp_path, capsys, mutate):
    doc = _assessment()
    mutate(doc)
    run = tmp_path / "SENTINEL-DETAILS-TEXT"
    run.mkdir()
    (run / "model_assessment.json").write_text(json.dumps(doc), encoding="utf-8")
    code, stdout, err = _run([GEAR, run, "--out", tmp_path / "out"], capsys)
    assert (code, stdout, err) == (2, "", FIXED["auditex"])
    assert not (tmp_path / "out").exists()


def test_historical_rule_precheck_rows_still_load(tmp_path, capsys):
    """A 2026-10-29 file (pre-value-rule contract): a closed gate reads not_applicable, an empty required list
    not_met and an absent section not_assessed, each with its class as the reason code."""
    doc = _assessment()
    doc["schema_version"] = "2026-10-29"
    base = doc["policies"][0]
    shapes = {
        "MS.AAD.7.1v1": ("closed_gate", "inferred", True, ["policy_not_applicable"]),
        "MS.AAD.7.3v1": ("empty_required_list", "confirmed", False, []),
        "MS.AAD.7.6v1": ("absent_section", "unknown", None, ["required_evidence_section_not_collected"]),
    }
    rows = []
    for policy_id, (rule_class, status, value, limitations) in shapes.items():
        row = copy.deepcopy(base)
        row.update({"policy_id": policy_id, "limitations": limitations,
                    "rule_precheck": {"class": rule_class, "rule_id": "synthetic", "section": ["synthetic_section"],
                                      "field": None, "value": None}})
        row["claims"][0].update({"status": status, "value": value})
        row["comparison"]["model_status"] = {True: "pass", False: "fail"}.get(value) if status == "confirmed" else None
        rows.append(row)
    doc["policies"] = rows
    path = tmp_path / "model_assessment.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert _run([GEAR, path, "--out", tmp_path / "out"], capsys)[0] == 0
    got = {pid: row[4:] for pid, row in _rows(tmp_path / "out").items() if pid in shapes}
    assert got == {"MS.AAD.7.1v1": ("not_applicable", "closed_gate"),
                   "MS.AAD.7.3v1": ("not_met", "empty_required_list"),
                   "MS.AAD.7.6v1": ("not_assessed", "absent_section")}


def test_run_folder_without_assessment_exits_2(tmp_path, capsys):
    assert _run([GEAR, tmp_path, "--out", tmp_path / "out"], capsys)[::2] == (2, FIXED["auditex"])


def test_platform_mismatch_exits_2(tmp_path, capsys):
    code, _, err = _run([GOGGLES, M365_ASSESSMENT, "--out", tmp_path / "out"], capsys)
    assert (code, err) == (2, FIXED["platform"])
    assert not (tmp_path / "out").exists()


def test_same_input_needs_a_scubagear_file_with_raw(tmp_path, capsys):
    assert _run([GOGGLES, "--same-input", "--out", tmp_path / "o1"], capsys)[::2] == (2, FIXED["same_input"])
    assert _run([GEAR, "--same-input", "--out", tmp_path / "o2"], capsys)[::2] == (2, FIXED["same_input"])
    assert not (tmp_path / "o1").exists() and not (tmp_path / "o2").exists()


def test_output_directory_must_be_new_or_empty(tmp_path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "keep.txt").write_text("x", encoding="utf-8")
    assert _run([GEAR, M365_ASSESSMENT, "--out", out], capsys)[::2] == (2, FIXED["out"])
    assert sorted(p.name for p in out.iterdir()) == ["keep.txt"]
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    assert _run([GEAR, M365_ASSESSMENT, "--out", link], capsys)[::2] == (2, FIXED["out"])


def test_strict_exits_1_on_a_disagreement(tmp_path, capsys):
    assert _run([GEAR, M365_ASSESSMENT, "--out", tmp_path / "o1", "--strict"], capsys)[0] == 1
    assert _run([GOGGLES, GWS_ASSESSMENT, "--out", tmp_path / "o2", "--strict"], capsys)[0] == 0


@pytest.mark.parametrize("argv", [
    ["CISA", "AUDITEX", "--out", "OUT", "--stric"],
    ["CISA", "--same-inp", "--out", "OUT"],
    ["CISA", "AUDITEX", "--same-input", "--out", "OUT"],
    ["CISA", "--out", "OUT"],
    ["CISA", "AUDITEX"],
])
def test_parser_refuses_abbreviations_and_ambiguous_inputs(tmp_path, argv):
    names = {"CISA": str(GEAR), "AUDITEX": str(M365_ASSESSMENT), "OUT": str(tmp_path / "out")}
    with pytest.raises(SystemExit) as exc:
        parity.main([names.get(item, item) for item in argv])
    assert exc.value.code == 2
    assert not (tmp_path / "out").exists()


def test_process_exit_code_and_stderr_on_malformed_input(tmp_path):
    source = tmp_path / "SENTINEL-DETAILS-TEXT.json"
    source.write_text('{"MetaData": {}, "Results": {"AAD": [{"Controls": [{"Control ID": "MS.AAD.7.1v1", '
                      '"Result": "SENTINEL-DETAILS-TEXT"}]}]}}', encoding="utf-8")
    proc = subprocess.run([sys.executable, "-B", str(SCRIPT), str(source), str(M365_ASSESSMENT),
                           "--out", str(tmp_path / "out")], capture_output=True, text=True, timeout=120)
    assert (proc.returncode, proc.stdout, proc.stderr) == (2, "", FIXED["cisa_value"])


def test_divergence_map_is_valid_and_cites_its_rows():
    data = json.loads(parity.DIVERGENCE_FILE.read_text(encoding="utf-8"))
    entries = parity.load_divergences()
    assert entries == data["entries"]
    assert set(data["sources"]) == {"gws-design", "m365-spec"}
    gws = [e for e in entries if e["policy_id"].startswith("GWS.")]
    m365 = [e for e in entries if e["policy_id"].startswith("MS.")]
    assert {e["cite"].split(" ")[0] for e in gws} == {"gws-design"}
    assert {e["cite"].split(" ")[0] for e in m365} == {"m365-spec"}
    # D10 (Error against section_not_collected) is neither_decided by construction and needs no entry.
    assert {e["id"] for e in gws} == {f"D{n}" for n in range(1, 23)} - {"D10"}
    assert set(data["rows"]["gws-design"]) == {f"D{n}" for n in range(1, 23)}
    for entry in gws:
        assert entry["cite"] == f"gws-design {'8.3' if int(entry['id'][1:]) <= 10 else '8.3a'} {entry['id']}"
    gws_ids = set(json.loads((ROOT / "configs" / "scuba-gws-value-rules.json").read_text())["policy_ids"])
    m365_ids = set(json.loads((ROOT / "configs" / "scuba-policy-sections.json").read_text())["policies"])
    assert {e["policy_id"] for e in gws} <= gws_ids
    assert {e["policy_id"] for e in m365} <= m365_ids
    pinned = {e["policy_id"]: e for e in gws if e["id"] in {"D4", "D5", "D6", "D9", "D20"}}
    assert pinned["GWS.GMAIL.7.5v1"]["cisa"] == ["fail", "pass"]
    assert pinned["GWS.COMMONCONTROLS.1.4v1"] == {
        "auditex": ["not_met"], "cisa": ["pass"], "cite": "gws-design 8.3 D5", "id": "D5",
        "policy_id": "GWS.COMMONCONTROLS.1.4v1"}


@pytest.mark.parametrize("bad", [
    {"policy_id": "GWS.GMAIL.7.5v1", "id": "D4", "cite": "gws-design 8.3 D4", "cisa": ["Pass"], "auditex": ["met"]},
    {"policy_id": "GWS.GMAIL.7.5v1", "id": "D4", "cite": "elsewhere D4", "cisa": ["pass"], "auditex": ["met"]},
    {"policy_id": "GWS.GMAIL.7.5v1", "id": "D4", "cite": "gws-design 8.3 D5", "cisa": ["pass"], "auditex": ["met"]},
    {"policy_id": "GWS.GMAIL.7.5v1", "id": "D4", "cite": "gws-design 8.3 D4", "cisa": ["pass"], "auditex": ["ok"]},
    {"policy_id": "GWS.GMAIL.7.5v1", "id": "D4", "cite": "gws-design 8.3 D4", "cisa": ["pass"], "auditex": ["met"],
     "reason_codes": []},
    {"policy_id": "x", "id": "D4", "cite": "gws-design 8.3 D4", "cisa": ["pass"], "auditex": ["met"]},
    {"policy_id": "GWS.GMAIL.7.5v1", "id": "D4", "cite": "gws-design 8.3 D4", "cisa": [], "auditex": ["met"]},
    {"policy_id": "GWS.GMAIL.7.5v1", "id": "D4", "cite": "gws-design 8.3 D4", "cisa": ["pass"], "auditex": ["met"],
     "note": "extra"},
    # Review low finding: wrong item and container types raised TypeError instead of the fixed error.
    {"policy_id": "GWS.GMAIL.7.5v1", "id": "D4", "cite": "gws-design 8.3 D4", "cisa": [{}], "auditex": ["met"]},
    {"policy_id": "GWS.GMAIL.7.5v1", "id": "D4", "cite": "gws-design 8.3 D4", "cisa": ["pass"], "auditex": [[]]},
    {"policy_id": "GWS.GMAIL.7.5v1", "id": "D4", "cite": "gws-design 8.3 D4", "cisa": ["pass"], "auditex": ["met"],
     "reason_codes": 1},
    {"policy_id": "GWS.GMAIL.7.5v1", "id": "D4", "cite": "gws-design 8.3 D4", "cisa": "pass", "auditex": ["met"]},
    # An undifferentiated "not decided" would let an Error row match a D row.
    {"policy_id": "GWS.GMAIL.7.5v1", "id": "D4", "cite": "gws-design 8.3 D4", "cisa": ["not_decided"],
     "auditex": ["met"]},
    {"policy_id": "GWS.GMAIL.7.5v1", "id": "D4", "cite": "gws-design 8.3 D4", "cisa": ["error"], "auditex": ["met"]},
])
def test_a_tampered_divergence_map_is_refused(tmp_path, bad):
    path = tmp_path / "map.json"
    path.write_text(json.dumps({"schema_version": 1, "sources": {"gws-design": "x"}, "entries": [bad]}),
                    encoding="utf-8")
    with pytest.raises(parity.ParityError) as exc:
        parity.load_divergences(path)
    assert str(exc.value) == "the divergence map is invalid"
