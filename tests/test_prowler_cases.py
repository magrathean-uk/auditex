"""Prowler consensus oracle: policy map, consensus logic and an offline run of real Prowler checks.

The map, evidence-helper and consensus tests are pure. The tests marked `needs_prowler` import Prowler's own models from a
checkout whose `prowler/providers/m365` is on disk and need Prowler's dependencies in the interpreter (see
docs/guides/model-development.md); they are skipped otherwise. They run real Prowler checks for every product the script
builds evidence for (Entra, Exchange, Defender, Purview, SharePoint, Teams) with network access blocked.
"""
from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.util
import json
import os
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-prowler-cases.py"
MAP_PATH = ROOT / "configs" / "oracle-policy-map.json"
PROWLER_ROOT = Path(os.environ.get("AUDITEX_TEST_PROWLER_ROOT", Path.home() / "dev/opensource/auditex-references/prowler"))
KIT = Path(os.environ.get("AUDITEX_TEST_ORACLE_KIT", Path.home() / "dev/machine/work/auditex-data/development-kit/20261019-oracle-cases"))
PROWLER_DEPENDENCIES = ("pydantic", "msgraph", "kiota_abstractions", "azure.identity", "msal", "colorama", "dns", "dateutil", "yaml", "jsonschema")


def _importable(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


needs_prowler = pytest.mark.skipif(
    not (PROWLER_ROOT / "prowler/providers/m365/services/entra/entra_service.py").is_file()
    or not all(_importable(name) for name in PROWLER_DEPENDENCIES),
    reason="Prowler checkout with prowler/providers/m365 on disk, or its dependencies, not present")
needs_kit = pytest.mark.skipif(not (KIT / "summary.json").is_file(), reason="oracle-case kit not present")


@pytest.fixture(scope="module")
def script():
    spec = importlib.util.spec_from_file_location("build_prowler_cases", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def policy_map(script):
    return script.load_policy_map(MAP_PATH)


# --------------------------------------------------------------------------------------------------------------------
# Policy map
# --------------------------------------------------------------------------------------------------------------------

def _doc(*rows: dict) -> dict:
    return {"confidence": {"exact": "", "partial": "", "none": ""}, "rows": list(rows)}


def _row(policy="MS.AAD.1.1v1", check="entra_legacy_authentication_blocked", confidence="exact", product="AAD") -> dict:
    return {"scubagear_policy": policy, "product": product, "prowler_check": check, "prowler_service": "entra", "confidence": confidence,
            "note": "A note."}


def test_shipped_map_is_valid_and_has_both_kinds_of_row(script, policy_map):
    assert script.validate_policy_map(policy_map) == []
    mapped = [r for r in policy_map["rows"] if r["scubagear_policy"]]
    prowler_only = [r for r in policy_map["rows"] if not r["scubagear_policy"]]
    assert mapped and prowler_only
    assert {r["confidence"] for r in mapped} == {"exact", "partial"}
    assert {r["product"] for r in mapped} <= {"AAD", "EXO", "SecuritySuite", "Sharepoint", "Teams"}
    assert policy_map["scubagear"]["commit"] == "2446ad723b7f55031cc02c8aca244d731d468cba"
    assert all(chr(0x2014) not in r["note"] for r in policy_map["rows"])


def test_map_has_no_duplicate_rows(policy_map):
    pairs = [(r["scubagear_policy"], r["prowler_check"]) for r in policy_map["rows"]]
    assert len(pairs) == len(set(pairs))
    prowler_only = [r["prowler_check"] for r in policy_map["rows"] if not r["scubagear_policy"]]
    assert len(prowler_only) == len(set(prowler_only))
    assert not set(prowler_only) & {r["prowler_check"] for r in policy_map["rows"] if r["scubagear_policy"]}


@needs_kit
def test_every_mapped_policy_exists_in_the_miner_policy_list(script, policy_map):
    summary = json.loads((KIT / "summary.json").read_text(encoding="utf-8"))
    policies = script.known_policies_from_summary(summary)
    assert script.validate_policy_map(policy_map, known_policies=policies) == []
    assert {r["scubagear_policy"] for r in policy_map["rows"] if r["scubagear_policy"]} <= set(policies)


@pytest.mark.skipif(not (PROWLER_ROOT / "prowler/providers/m365/services").is_dir(), reason="Prowler m365 provider not on disk")
def test_every_mapped_check_exists_in_the_prowler_checkout(script, policy_map):
    services = PROWLER_ROOT / "prowler/providers/m365/services"
    checks = {path.name.removesuffix(".metadata.json") for path in services.glob("*/*/*.metadata.json")}
    assert script.validate_policy_map(policy_map, known_checks=checks) == []
    if script.prowler_commit(PROWLER_ROOT) == policy_map["prowler"]["commit"]:
        assert {r["prowler_check"] for r in policy_map["rows"]} == checks, "every Prowler M365 check is mapped or listed as Prowler-only"


def test_validator_flags_bad_rows(script):
    policies = {"MS.AAD.1.1v1": "AAD"}
    assert script.validate_policy_map(_doc(_row()), known_policies=policies) == []
    assert any("not in the miner" in e for e in script.validate_policy_map(_doc(_row(policy="MS.AAD.9.9v1")), known_policies=policies))
    assert any("duplicate pair" in e for e in script.validate_policy_map(_doc(_row(), _row()), known_policies=policies))
    assert any("does not match" in e for e in script.validate_policy_map(_doc(_row(product="EXO")), known_policies=policies))
    assert any("unknown confidence" in e for e in script.validate_policy_map(_doc(_row(confidence="close"))))
    assert any("exact or partial" in e for e in script.validate_policy_map(_doc(_row(confidence="none"))))
    assert any("invalid prowler_check" in e for e in script.validate_policy_map(_doc(_row(check="Not A Check"))))
    assert any("not a Prowler" in e for e in script.validate_policy_map(_doc(_row()), known_checks={"other_check"}))
    only = _row(policy=None, confidence="none")
    only["product"] = None
    assert script.validate_policy_map(_doc(only)) == []
    assert any("both mapped and listed" in e for e in script.validate_policy_map(_doc(_row(), only)))
    assert any("duplicate Prowler-only" in e for e in script.validate_policy_map(_doc(only, copy.deepcopy(only))))
    assert any("one non-empty line" in e for e in script.validate_policy_map(_doc({**_row(), "note": "two\nlines"})))
    assert script.validate_policy_map({"rows": []}) == ["rows must be a non-empty list"]


def test_builders_and_checks_agree_with_the_map(script, policy_map):
    mapped = {r["prowler_check"] for r in policy_map["rows"] if r["scubagear_policy"]}
    assert set(script.CHECK_ATTRIBUTES) == mapped, "every mapped check has a builder and every builder serves a mapped check"
    for groups in script.CHECK_ATTRIBUTES.values():
        assert set(groups) <= set(script.ATTRIBUTE_BUILDERS)
    assert set(script.CHECK_AUDIT_CONFIG) <= mapped
    services = {r["prowler_check"]: r["prowler_service"] for r in policy_map["rows"]}
    assert {services[c] for c in script.CHECK_ATTRIBUTES} == set(script.ProwlerRuntime.SERVICES)
    for check, groups in script.CHECK_ATTRIBUTES.items():
        assert script.ATTRIBUTE_BUILDERS[groups[0]][0] == services[check], f"{check}: builder service differs from the map"


# --------------------------------------------------------------------------------------------------------------------
# Case parsing and consensus logic
# --------------------------------------------------------------------------------------------------------------------

SOURCE = ("oracle:cisa-scubagear@2446ad723b7f AADConfig.rego {policy}; variant={variant}; opa=1.20.2; input_sha256={sha}; "
          "sections=conditional_access_policies; report_details=\"x\"")


def _case(policy="MS.AAD.1.1v1", variant="AADConfig_01_test:NoExclusionsExcludeUsers_Incorrect", sha="a" * 64, status="confirmed", value=True,
          case_id=None) -> dict:
    return {"id": case_id or f"case-{policy}", "provenance": {"source": SOURCE.format(policy=policy, variant=variant, sha=sha)},
            "expected": {"claims": [{"id": "requirement_met", "status": status, "value": value, "evidence_ids": ["e1"]},
                                    {"id": "policy_criticality", "status": "confirmed", "value": "Shall", "evidence_ids": ["e0"]}]}}


def test_parse_case_reads_policy_variant_hash_and_verdict(script):
    facts = script.parse_case(_case())
    assert facts == {"case_id": "case-MS.AAD.1.1v1", "policy": "MS.AAD.1.1v1", "variant_name": "AADConfig_01_test:NoExclusionsExcludeUsers_Incorrect",
                     "input_sha256": "a" * 64, "scubagear_verdict": "met"}
    assert script.parse_case(_case(value=False))["scubagear_verdict"] == "not_met"
    assert script.parse_case(_case(status="unknown", value=None))["scubagear_verdict"] == "unknown"
    assert script.parse_case(_case(variant="base"))["variant_name"] == "base"
    with pytest.raises(ValueError):
        script.parse_case({"id": "x", "provenance": {"source": "nothing useful"}, "expected": {"claims": []}})


def _verdict(status, check="entra_legacy_authentication_blocked", reason=None, confidence="exact") -> dict:
    row = {"scubagear_policy": "MS.AAD.1.1v1", "prowler_check": check, "confidence": confidence, "status": status, "status_extended": status.lower()}
    if reason:
        row["reason"] = reason
    return row


@pytest.mark.parametrize("scuba,prowler,expected", [
    ("met", "PASS", "agree"), ("not_met", "FAIL", "agree"), ("met", "FAIL", "disagree"), ("not_met", "PASS", "disagree")])
def test_consensus_compares_pass_and_fail_with_the_scubagear_label(script, scuba, prowler, expected):
    facts = {"case_id": "c", "policy": "MS.AAD.1.1v1", "variant_name": "base", "scubagear_verdict": scuba}
    row = script.consensus_row(facts, [_row()], [_verdict(prowler)])
    assert row["consensus"] == expected and row["reason"] is None
    assert row["prowler_verdict"] == prowler and row["confidence"] == "exact"
    assert row["prowler_checks"][0]["status"] == prowler


def test_consensus_reports_unmapped_cases_with_a_reason(script):
    facts = {"case_id": "c", "policy": "MS.AAD.1.1v1", "variant_name": "base", "scubagear_verdict": "met"}
    assert script.consensus_row(facts, [], None)["reason"] == "policy_not_mapped"
    assert script.consensus_row({**facts, "scubagear_verdict": "unknown"}, [_row()], [_verdict("PASS")])["reason"] == "scubagear_label_unknown"
    assert script.consensus_row(facts, [_row()], None)["reason"] == "variant_not_found"
    manual = script.consensus_row(facts, [_row()], [_verdict("MANUAL")])
    assert (manual["consensus"], manual["reason"], manual["prowler_verdict"]) == ("unmapped", "prowler_manual", "MANUAL")
    gap = script.consensus_row(facts, [_row()], [_verdict("UNMAPPED", reason="evidence_missing:users")])
    assert (gap["consensus"], gap["reason"]) == ("unmapped", "evidence_missing:users")
    assert all(script.consensus_row(facts, [_row()], [_verdict("PASS")])[k] for k in ("case_id", "variant", "scubagear_policy"))


def test_conjunctive_rows_and_confidence(script):
    facts = {"case_id": "c", "policy": "MS.AAD.3.5v2", "variant_name": "base", "scubagear_verdict": "not_met"}
    rows = [_row(policy="MS.AAD.3.5v2", confidence="partial"), _row(policy="MS.AAD.3.5v2", check="other_check", confidence="exact")]
    both_pass = [_verdict("PASS", confidence="partial"), _verdict("PASS", check="other_check")]
    assert script.combine_statuses(both_pass) == ("PASS", None)
    assert script.combine_statuses([_verdict("PASS"), _verdict("FAIL", check="b")]) == ("FAIL", None)
    # a failing part decides the policy even when the other part could not be evaluated
    assert script.combine_statuses([_verdict("UNMAPPED", reason="no_finding"), _verdict("FAIL", check="b")]) == ("FAIL", None)
    assert script.combine_statuses([_verdict("PASS"), _verdict("UNMAPPED", check="b", reason="no_finding")]) == ("UNMAPPED", "no_finding")
    assert script.combine_statuses([_verdict("PASS"), _verdict("MANUAL", check="b")]) == ("MANUAL", None)
    row = script.consensus_row(facts, rows, both_pass)
    assert row["confidence"] == "partial" and row["consensus"] == "disagree"
    assert script.consensus_row(facts, rows[1:], both_pass)["confidence"] == "exact"


def test_authentication_strength_names(script):
    name = script.authentication_strength_name
    assert name(None) is None and name({"AllowedCombinations": None}) is None and name({"AllowedCombinations": []}) is None
    assert name({"AllowedCombinations": ["fido2", "windowsHelloForBusiness", "x509CertificateMultiFactor"]}) == "Phishing-resistant MFA"
    assert name({"AllowedCombinations": ["fido2", "windowsHelloForBusiness", "x509CertificateMultiFactor", "deviceBasedPush"]}) == "Passwordless MFA"
    assert name({"AllowedCombinations": sorted(script.BUILT_IN_STRENGTHS["Multifactor authentication"])}) == "Multifactor authentication"
    assert name({"AllowedCombinations": ["fido2"]}) == script.CUSTOM_STRENGTH


def test_run_variant_without_a_builder_reports_every_row(script, policy_map):
    rows = [r for r in policy_map["rows"] if r["scubagear_policy"] in ("MS.EXO.5.1v1", "MS.AAD.3.5v2")]
    out = script.run_variant(None, {}, rows)
    assert len(out) == len(rows)
    assert {r["status"] for r in out} == {"UNMAPPED"}
    assert {r["reason"] for r in out} == {"no_builder"}


def test_variant_hashes_keep_the_first_of_identical_inputs(script, tmp_path):
    (tmp_path / "variant-0000.json").write_text('{"a":1}', encoding="utf-8")
    (tmp_path / "variant-0001.json").write_text('{"a":2}', encoding="utf-8")
    (tmp_path / "variant-0002.json").write_text('{"a":1}', encoding="utf-8")
    hashes = script.variant_hashes(tmp_path)
    assert len(hashes) == 3 and hashes[tmp_path / "variant-0000.json"] == hashlib.sha256(b'{"a":1}').hexdigest()
    first = script.first_variant_by_hash(hashes)
    assert len(first) == 2 and first[hashes[tmp_path / "variant-0002.json"]].name == "variant-0000.json"


def test_summary_and_unmapped_report_count_every_row(script):
    consensus = [
        {"scubagear_policy": "P1", "consensus": "agree", "confidence": "exact", "reason": None},
        {"scubagear_policy": "P1", "consensus": "disagree", "confidence": "partial", "reason": None},
        {"scubagear_policy": "P2", "consensus": "unmapped", "confidence": None, "reason": "policy_not_mapped"},
        {"scubagear_policy": "P2", "consensus": "unmapped", "confidence": "exact", "reason": "shape:client_app_type=''"}]
    verdicts = [{"status": "PASS"}, {"status": "UNMAPPED", "reason": "no_finding", "prowler_check": "c1", "variant": "variant-0001"},
                {"status": "UNMAPPED", "reason": "no_finding", "prowler_check": "c1", "variant": "variant-0002"}]
    summary = script.summarise(consensus, verdicts)
    assert summary["consensus"] == {"agree": 1, "disagree": 1, "unmapped": 2}
    assert summary["compared_by_confidence"] == {"exact": {"agree": 1}, "partial": {"disagree": 1}}
    assert summary["unmapped_reasons"] == {"policy_not_mapped": 1, "shape": 1}
    assert summary["by_policy"] == {"P1": {"agree": 1, "disagree": 1}, "P2": {"unmapped": 2}}
    assert summary["verdict_rows"] == {"PASS": 1, "UNMAPPED": 2}
    report = script.unmapped_report(verdicts)
    assert report["by_reason"] == {"no_finding": 2} and report["by_check"] == {"c1": {"no_finding": 2}}
    assert report["example_variants"] == {"no_finding": ["variant-0001", "variant-0002"]}


def test_summary_buckets_detailed_reasons_by_family(script):
    consensus = [{"scubagear_policy": "P", "consensus": "unmapped", "confidence": "partial", "reason": reason} for reason in (
        "not_exported:a", "not_exported:b", "evidence_missing:x.y", "evidence_missing:z", "scubagear_not_applicable:us_government_region",
        "missing_attribute:q", "no_finding")]
    assert script.summarise(consensus, [])["unmapped_reasons"] == {
        "not_exported": 2, "evidence_missing": 2, "scubagear_not_applicable:us_government_region": 1, "missing_attribute": 1, "no_finding": 1}


def test_evidence_helpers_report_gaps_instead_of_guessing(script):
    gap = script.EvidenceGap
    with pytest.raises(gap, match="evidence_missing:transport_config$"):
        script._single({"transport_config": []}, "transport_config")
    with pytest.raises(gap, match="shape:transport_config has 2 entries"):
        script._single({"transport_config": [{"a": 1}, {"b": 2}]}, "transport_config")
    with pytest.raises(gap, match="evidence_missing:transport_config$"):
        script._single({}, "transport_config")
    assert script._entries({"x": [None, {}, {"a": 1}]}, "x") == [{"a": 1}], "PowerShell's empty entries are skipped, as Prowler skips them"
    with pytest.raises(gap, match="shape:x holds entries"):
        script._entries({"x": ["bad-data"]}, "x")
    with pytest.raises(gap, match="evidence_missing:org_config.AuditDisabled"):
        script._need({"Name": "A"}, "AuditDisabled", "org_config")
    assert script._need({"AuditDisabled": False}, "AuditDisabled", "org_config") is False
    with pytest.raises(gap, match="shape:org_config.AuditDisabled is str"):
        script._flag({"AuditDisabled": "no"}, "AuditDisabled", "org_config")
    notes: list[str] = []
    chosen = script._global_entry({"p": [{"Identity": "Tag:A"}, {"Identity": "Global", "v": 1}]}, "p", notes)
    assert chosen["v"] == 1 and notes == ["Prowler reads only the Global entry of p; 1 other entries are not read"]
    with pytest.raises(gap, match="evidence_missing:p.Global"):
        script._global_entry({"p": [{"Identity": "Tag:A"}]}, "p", [])
    assert script._as_list(None) is None and script._as_list("a") == ["a"] and script._as_list(["a", 1]) == ["a", "1"]


def test_not_exported_groups_always_report_why(script):
    with pytest.raises(script.EvidenceGap, match="not_exported:external_in_outlook"):
        script.ATTRIBUTE_BUILDERS["external_in_outlook"][1]({}, None)


def test_scubagear_not_applicable_in_us_government_regions(script):
    gov = {"scuba_config": {"M365Environment": "gcchigh"}}
    assert script.scubagear_not_applicable("MS.TEAMS.2.2v2", gov) == "us_government_region"
    assert script.scubagear_not_applicable("MS.TEAMS.4.1v1", {"scuba_config": {"M365Environment": "dod"}}) == "us_government_region"
    assert script.scubagear_not_applicable("MS.TEAMS.2.1v2", gov) is None, "2.1 has no regional exemption"
    assert script.scubagear_not_applicable("MS.TEAMS.2.2v2", {"scuba_config": {"M365Environment": "commercial"}}) is None
    assert script.scubagear_not_applicable("MS.TEAMS.2.2v2", {"scuba_config": []}) is None
    assert script.scubagear_not_applicable("MS.TEAMS.2.2v2", {}) is None


def test_check_outcomes_separate_executed_checks_from_blocked_ones(script):
    verdicts = [
        {"prowler_check": "ran_everywhere", "status": "PASS"},
        {"prowler_check": "ran_sometimes", "status": "FAIL"},
        {"prowler_check": "ran_sometimes", "status": "UNMAPPED", "reason": "no_finding"},
        {"prowler_check": "only_not_applicable", "status": "UNMAPPED", "reason": "scubagear_not_applicable:us_government_region", "prowler_status": "PASS"},
        {"prowler_check": "never", "status": "UNMAPPED", "reason": "not_exported:x"},
        {"prowler_check": "never", "status": "UNMAPPED", "reason": "not_exported:x"},
        {"prowler_check": "never", "status": "UNMAPPED", "reason": "evidence_missing:y.z"}]
    outcome = script.check_outcomes(verdicts)
    assert outcome["checks_executed"] == ["only_not_applicable", "ran_everywhere", "ran_sometimes"]
    assert outcome["checks_not_evaluated"] == {"never": {"not_exported:x": 2, "evidence_missing:y.z": 1}}


# --------------------------------------------------------------------------------------------------------------------
# Real Prowler checks, offline
# --------------------------------------------------------------------------------------------------------------------

def _policy(**changes) -> dict:
    policy = {"DisplayName": "Block legacy", "State": "enabled",
              "Conditions": {"Applications": {"ExcludeApplications": [], "IncludeApplications": ["All"], "IncludeUserActions": []},
                             "AuthenticationFlows": {"TransferMethods": None}, "ClientAppTypes": ["other", "exchangeActiveSync"],
                             "SignInRiskLevels": [], "UserRiskLevels": [],
                             "Users": {"ExcludeGroups": [], "ExcludeGuestsOrExternalUsers": None, "ExcludeRoles": [], "ExcludeUsers": [], "IncludeUsers": ["All"]}},
              "GrantControls": {"BuiltInControls": ["block"]}}
    policy.update(changes)
    return policy


@pytest.fixture(scope="module")
def runtime(script):
    before = set(sys.modules)
    path_before = list(sys.path)
    rt = script.ProwlerRuntime(PROWLER_ROOT)
    yield rt
    for name in set(sys.modules) - before:
        if name.startswith(("prowler", "tests.providers")):
            sys.modules.pop(name, None)
    sys.path[:] = path_before


def _verdict_for(script, runtime, policy_map, inp, policy_id):
    rows = [r for r in policy_map["rows"] if r["scubagear_policy"] == policy_id]
    return script.run_variant(runtime, inp, rows)


@needs_prowler
def test_real_prowler_check_runs_offline_on_a_scubagear_variant(script, runtime, policy_map, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", no_network)
    blocked = _verdict_for(script, runtime, policy_map, {"conditional_access_policies": [_policy()]}, "MS.AAD.1.1v1")
    assert [(r["prowler_check"], r["status"]) for r in blocked] == [("entra_legacy_authentication_blocked", "PASS")]
    assert "blocks legacy authentication" in blocked[0]["status_extended"]
    open_ = _verdict_for(script, runtime, policy_map, {"conditional_access_policies": []}, "MS.AAD.1.1v1")
    assert open_[0]["status"] == "FAIL"
    reporting = _verdict_for(script, runtime, policy_map, {"conditional_access_policies": [_policy(State="enabledForReportingButNotEnforced")]}, "MS.AAD.1.1v1")
    assert reporting[0]["status"] == "FAIL"
    assert "unmapped" not in {r["status"].lower() for r in blocked + open_ + reporting}


@needs_prowler
def test_unmappable_evidence_is_reported_not_skipped(script, runtime, policy_map):
    missing = _verdict_for(script, runtime, policy_map, {}, "MS.AAD.1.1v1")[0]
    assert (missing["status"], missing["reason"]) == ("UNMAPPED", "evidence_missing:conditional_access_policies")
    blank = _policy()
    blank["Conditions"]["ClientAppTypes"] = [""]
    shaped = _verdict_for(script, runtime, policy_map, {"conditional_access_policies": [blank]}, "MS.AAD.1.1v1")[0]
    assert shaped["status"] == "UNMAPPED" and shaped["reason"].startswith("shape:client_app_type")
    silent = _verdict_for(script, runtime, policy_map, {"privileged_roles": [{"DisplayName": "Global Administrator", "Rules": []}]}, "MS.AAD.7.6v1")[0]
    assert (silent["status"], silent["reason"]) == ("UNMAPPED", "no_finding")


@needs_prowler
def test_conjunctive_policy_and_assumptions(script, runtime, policy_map):
    def methods(sms_state, voice_state, email_state):
        return {"authentication_method": [{"authentication_method_feature_settings": [
            {"Id": "Sms", "State": sms_state}, {"Id": "Voice", "State": voice_state}, {"Id": "Email", "State": email_state}]}]}

    rows = _verdict_for(script, runtime, policy_map, methods("enabled", "disabled", "disabled"), "MS.AAD.3.5v2")
    assert {r["prowler_check"]: r["status"] for r in rows} == {
        "entra_authentication_method_sms_voice_disabled": "FAIL", "entra_authentication_method_email_otp_disabled": "PASS"}
    assert script.combine_statuses(rows)[0] == "FAIL"
    all_off = _verdict_for(script, runtime, policy_map, methods("disabled", "disabled", "disabled"), "MS.AAD.3.5v2")
    assert script.combine_statuses(all_off) == ("PASS", None)
    pim = {"privileged_roles": [{"DisplayName": "Global Administrator", "Rules": [{"Id": "Approval_EndUser_Assignment", "Setting": {"IsApprovalRequired": True}}]}]}
    approval = _verdict_for(script, runtime, policy_map, pim, "MS.AAD.7.6v1")[0]
    assert approval["status"] == "PASS" and any("approvers" in a for a in approval["assumptions"])


@needs_prowler
def test_end_to_end_on_a_synthetic_kit(script, runtime, policy_map, tmp_path):
    kit = tmp_path / "kit"
    (kit / "variants-aad").mkdir(parents=True)
    variants = {"variant-0000.json": {"conditional_access_policies": [_policy()]}, "variant-0001.json": {"conditional_access_policies": []}}
    cases, shas = [], {}
    for index, (name, inp) in enumerate(variants.items()):
        data = json.dumps(inp, sort_keys=True, separators=(",", ":"))
        (kit / "variants-aad" / name).write_text(data, encoding="utf-8")
        shas[name] = hashlib.sha256(data.encode()).hexdigest()
        # both cases are labelled met; the second tenant has no policy at all, so Prowler fails it and the oracles disagree
        cases.append(_case(policy="MS.AAD.1.1v1", variant=f"test_{index}", sha=shas[name], value=True, case_id=f"legacy-{index}"))
    cases.append(_case(policy="MS.AAD.3.4v1", variant="base", sha=shas["variant-0000.json"], case_id="migration"))
    (kit / "cases-aad.jsonl").write_text("".join(json.dumps(c) + "\n" for c in cases), encoding="utf-8")
    policies = {r["scubagear_policy"]: [] for r in policy_map["rows"] if r["product"] == "AAD"} | {"MS.AAD.3.4v1": []}
    (kit / "summary.json").write_text(json.dumps({"products": {"AAD": {"package": "aad", "sections_per_policy": policies}}}), encoding="utf-8")
    out = tmp_path / "out"
    assert script.main(["--kit-dir", str(kit), "--prowler-root", str(PROWLER_ROOT), "--output-dir", str(out), "--products", "AAD"]) == 0
    consensus = {r["case_id"]: r for r in map(json.loads, (out / "consensus.jsonl").read_text(encoding="utf-8").splitlines())}
    assert {k: (v["variant"], v["consensus"]) for k, v in consensus.items() if k.startswith("legacy")} == {
        "legacy-0": ("variant-0000", "agree"), "legacy-1": ("variant-0001", "disagree")}
    assert (consensus["migration"]["consensus"], consensus["migration"]["reason"]) == ("unmapped", "policy_not_mapped")
    verdicts = [json.loads(line) for line in (out / "verdicts.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {(v["variant"], v["prowler_check"], v["status"]) for v in verdicts if v["prowler_check"] == "entra_legacy_authentication_blocked"} == {
        ("variant-0000", "entra_legacy_authentication_blocked", "PASS"), ("variant-0001", "entra_legacy_authentication_blocked", "FAIL")}
    assert {"variant", "scubagear_policy", "prowler_check", "status", "status_extended"} <= set(verdicts[0])
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["products"]["AAD"]["consensus"] == {"agree": 1, "disagree": 1, "unmapped": 1}
    assert "entra_legacy_authentication_blocked" in summary["checks_executed"]
    assert script.main(["--kit-dir", str(kit), "--prowler-root", str(PROWLER_ROOT), "--output-dir", str(out)]) == 2, "an existing output directory is refused"


@pytest.fixture
def offline(monkeypatch):
    """Fail the test on any socket connection or name lookup, so a check that reached for the network cannot pass."""
    def no_network(*args, **kwargs):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket.socket, "sendto", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)


def _statuses(script, runtime, policy_map, inp, policy_id):
    return {r["prowler_check"]: r["status"] for r in _verdict_for(script, runtime, policy_map, inp, policy_id)}


@needs_prowler
def test_exchange_checks_run_offline_on_a_scubagear_variant(script, runtime, policy_map, offline):
    base = {"org_config": [{"AuditDisabled": False, "Identity": "Test name", "Name": "A"}],
            "transport_config": [{"Name": "A", "SmtpClientAuthenticationDisabled": True}],
            "dkim_config": [{"Domain": "test.name", "Enabled": True}],
            "dmarc_records": [{"domain": "test.name", "rdata": ["v=DMARC1; p=reject; pct=100; rua=mailto:reports@dmarc.cyber.dhs.gov"]}]}

    def verdicts(**changes):
        inp = {**base, **changes}
        return {policy: _statuses(script, runtime, policy_map, inp, policy) for policy in
                ("MS.EXO.13.1v1", "MS.EXO.5.1v1", "MS.EXO.3.1v1", "MS.EXO.4.1v1", "MS.EXO.4.2v1")}

    good = verdicts()
    assert good == {"MS.EXO.13.1v1": {"exchange_organization_mailbox_auditing_enabled": "PASS"},
                    "MS.EXO.5.1v1": {"exchange_transport_config_smtp_auth_disabled": "PASS"},
                    "MS.EXO.3.1v1": {"defender_domain_dkim_enabled": "PASS"},
                    "MS.EXO.4.1v1": {"defender_domain_dmarc_records_published": "PASS"},
                    "MS.EXO.4.2v1": {"defender_domain_dmarc_records_published": "PASS"}}
    bad = verdicts(org_config=[{"AuditDisabled": True, "Identity": "x", "Name": "A"}], transport_config=[{"Name": "A", "SmtpClientAuthenticationDisabled": False}],
                   dkim_config=[{"Domain": "test.name", "Enabled": False}], dmarc_records=[{"domain": "test.name", "rdata": []}])
    assert {check: status for statuses in bad.values() for check, status in statuses.items()} == {
        "exchange_organization_mailbox_auditing_enabled": "FAIL", "exchange_transport_config_smtp_auth_disabled": "FAIL",
        "defender_domain_dkim_enabled": "FAIL", "defender_domain_dmarc_records_published": "FAIL"}
    monitoring = _verdict_for(script, runtime, policy_map, {**base, "dmarc_records": [{"domain": "test.name", "rdata": ["v=DMARC1; p=none"]}]}, "MS.EXO.4.1v1")[0]
    assert monitoring["status"] == "FAIL" and "p=none" in monitoring["status_extended"]
    assert any("DNS lookup" in a for a in monitoring["assumptions"])
    quarantine = _verdict_for(script, runtime, policy_map, {**base, "dmarc_records": [{"domain": "test.name", "rdata": ["v=DMARC1; p=quarantine"]}]}, "MS.EXO.4.2v1")[0]
    assert quarantine["status"] == "PASS", "Prowler accepts p=quarantine where ScubaGear 4.2 wants p=reject, which is why the row is partial"
    for policy, reason in (("MS.EXO.1.1v2", "not_exported:outbound_spam_policy"), ("MS.EXO.7.1v1", "not_exported:external_in_outlook"),
                           ("MS.EXO.6.2v1", "not_exported:sharing_policy_enabled")):
        row = _verdict_for(script, runtime, policy_map, base, policy)[0]
        assert (row["status"], row["reason"]) == ("UNMAPPED", reason)
    missing = _verdict_for(script, runtime, policy_map, {**base, "transport_config": [{"Name": "A"}]}, "MS.EXO.5.1v1")[0]
    assert (missing["status"], missing["reason"]) == ("UNMAPPED", "evidence_missing:transport_config.SmtpClientAuthenticationDisabled")
    resolver = runtime.module("defender").dns.asyncresolver
    assert resolver.resolve.__module__.startswith("dns."), "the offline DNS answers are removed again after each build"


def _ss(**changes) -> dict:
    inp = {"anti_malware_policies": [{"EnableFileFilter": True, "FileTypes": ["exe", "cmd", "vbe"], "Identity": "Default", "ZapEnabled": True}],
           "anti_malware_rules": [],
           "conn_filter": [{"EnableSafeList": False, "IPAllowList": [], "Name": "A"}],
           "admin_audit_log_config": [{"Identity": "Admin Audit Log Settings", "UnifiedAuditLogIngestionEnabled": True}],
           "atp_policy_for_o365": [{"EnableATPForSPOTeamsODB": True, "Identity": "Default"}],
           "hosted_content_filter_policies": [{"AllowedSenderDomains": [], "HighConfidencePhishAction": "Quarantine", "HighConfidenceSpamAction": "Quarantine",
                                               "Identity": "Default", "IsDefault": True, "PhishSpamAction": "Quarantine", "RecommendedPolicyType": "Custom",
                                               "SpamAction": "MoveToJmf"}],
           "hosted_content_filter_rules": [],
           "safe_links_policies": [{"DeliverMessageAfterScan": True, "EnableForInternalSenders": True, "EnableSafeLinksForEmail": True,
                                    "EnableSafeLinksForOffice": True, "EnableSafeLinksForTeams": True, "Identity": "Compliant Custom Policy", "ScanUrls": True,
                                    "TrackClicks": True}],
           "safe_links_rules": [{"Identity": "Compliant Custom Policy", "Priority": 0, "RecipientDomainIs": None, "SafeLinksPolicy": "Compliant Custom Policy",
                                 "SentTo": None, "SentToMemberOf": None, "State": "Enabled"}],
           "safe_attachment_policies": [{"Action": "Block", "Identity": "Built-In Protection Policy"}], "safe_attachment_rules": [],
           "anti_phish_policies": [{"EnableFirstContactSafetyTips": True, "EnableSimilarDomainsSafetyTips": True, "EnableSimilarUsersSafetyTips": True,
                                    "EnableUnauthenticatedSender": True, "EnableUnusualCharactersSafetyTips": True, "EnableViaTag": True, "Enabled": True,
                                    "Identity": "Office365 AntiPhish Default", "IsDefault": True, "Name": "Office365 AntiPhish Default"}],
           "anti_phish_rules": []}
    inp.update(changes)
    return inp


@needs_prowler
def test_defender_and_purview_checks_run_offline_on_a_scubagear_variant(script, runtime, policy_map, offline):
    def run(policy, **changes):
        return _verdict_for(script, runtime, policy_map, _ss(**changes), policy)

    everything = ("MS.SECURITYSUITE.1.1v1", "MS.SECURITYSUITE.1.3v1", "MS.SECURITYSUITE.1.4v1", "MS.SECURITYSUITE.2.4v1", "MS.SECURITYSUITE.5.1v1",
                  "MS.SECURITYSUITE.6.2v1", "MS.SECURITYSUITE.7.1v1", "MS.SECURITYSUITE.7.2v1", "MS.SECURITYSUITE.7.3v1", "MS.SECURITYSUITE.8.1v1",
                  "MS.SECURITYSUITE.8.2v1")
    for policy in everything:
        rows = run(policy)
        assert {r["status"] for r in rows} == {"PASS"}, (policy, rows)
    # the extension list is Prowler's own check logic run with the baseline's three types, and the override is recorded
    short = run("MS.SECURITYSUITE.1.1v1", anti_malware_policies=[{"EnableFileFilter": True, "FileTypes": ["exe", "cmd"], "Identity": "Default", "ZapEnabled": True}])
    by_check = {r["prowler_check"]: r for r in short}
    assert by_check["defender_malware_policy_comprehensive_attachments_filter_applied"]["status"] == "FAIL"
    assert "vbe" in by_check["defender_malware_policy_comprehensive_attachments_filter_applied"]["status_extended"]
    assert by_check["defender_malware_policy_common_attachments_filter_enabled"]["status"] == "PASS"
    assert any("recommended_blocked_file_types" in a for a in by_check["defender_malware_policy_comprehensive_attachments_filter_applied"]["assumptions"])
    assert script.combine_statuses(short) == ("FAIL", None)
    assert run("MS.SECURITYSUITE.8.1v1", conn_filter=[{"EnableSafeList": False, "IPAllowList": ["192.0.2.1"], "Name": "A"}])[0]["status"] == "FAIL"
    assert run("MS.SECURITYSUITE.8.2v1", conn_filter=[{"EnableSafeList": True, "IPAllowList": [], "Name": "A"}])[0]["status"] == "FAIL"
    assert run("MS.SECURITYSUITE.5.1v1", admin_audit_log_config=[{"Identity": "x", "UnifiedAuditLogIngestionEnabled": False}])[0]["status"] == "FAIL"
    assert run("MS.SECURITYSUITE.1.4v1", atp_policy_for_o365=[{"EnableATPForSPOTeamsODB": False, "Identity": "Default"}])[0]["status"] == "FAIL"
    domains = [dict(_ss()["hosted_content_filter_policies"][0], AllowedSenderDomains=["example.com"])]
    blocked = run("MS.SECURITYSUITE.6.2v1", hosted_content_filter_policies=domains)[0]
    assert blocked["status"] == "FAIL" and "example.com" in blocked["status_extended"]
    weak = dict(_ss()["safe_links_policies"][0], TrackClicks=False)
    assert {r["status"] for r in run("MS.SECURITYSUITE.7.3v1", safe_links_policies=[weak])} == {"FAIL"}
    assumed = run("MS.SECURITYSUITE.7.1v1")[0]["assumptions"]
    assert any("AllowClickThrough" in a for a in assumed)
    # evidence the variant lacks is reported, never defaulted: a policy without the safety-tip keys cannot be judged
    bare = [{"Identity": "Standard Preset Security Policy1", "IsDefault": False, "Name": "Standard Preset Security Policy"}]
    gap = run("MS.SECURITYSUITE.2.4v1", anti_phish_policies=bare)[0]
    assert (gap["status"], gap["reason"]) == ("UNMAPPED", "evidence_missing:anti_phish_policies.EnableFirstContactSafetyTips")
    silent = run("MS.SECURITYSUITE.6.2v1", hosted_content_filter_policies=[])[0]
    assert (silent["status"], silent["reason"]) == ("UNMAPPED", "no_finding")
    assert run("MS.SECURITYSUITE.1.1v1", anti_malware_rules=[None])[0]["status"] == "PASS", "a null rule list entry is skipped, as Prowler skips it"


@needs_prowler
def test_sharepoint_checks_run_offline_on_a_scubagear_variant(script, runtime, policy_map, offline):
    def run(policy, **tenant):
        base = {"SharingCapability": 0, "SharingDomainRestrictionMode": 0, "ODBSharingCapability": 0}
        base.update(tenant)
        return _verdict_for(script, runtime, policy_map, {"SPO_tenant": [{k: v for k, v in base.items() if v is not None}]}, policy)[0]

    assert [run("MS.SHAREPOINT.1.1v1", SharingCapability=value)["status"] for value in (0, 1, 2, 3)] == ["PASS", "PASS", "FAIL", "PASS"]
    assert run("MS.SHAREPOINT.1.3v1", SharingCapability=0)["status"] == "PASS", "sharing off counts as managed"
    assert run("MS.SHAREPOINT.1.3v1", SharingCapability=2, SharingDomainRestrictionMode=0)["status"] == "FAIL"
    allowed = run("MS.SHAREPOINT.1.3v1", SharingCapability=2, SharingDomainRestrictionMode=1)
    assert allowed["status"] == "PASS" and any("assumed non-empty" in a for a in allowed["assumptions"])
    assert run("MS.SHAREPOINT.1.3v1", SharingCapability=2, SharingDomainRestrictionMode=2)["status"] == "PASS"
    for policy, tenant, reason in (("MS.SHAREPOINT.1.1v1", {"SharingCapability": None}, "evidence_missing:SPO_tenant.SharingCapability"),
                                   ("MS.SHAREPOINT.1.3v1", {"SharingDomainRestrictionMode": None}, "evidence_missing:SPO_tenant.SharingDomainRestrictionMode"),
                                   ("MS.SHAREPOINT.1.1v1", {"SharingCapability": 9}, "shape:SPO_tenant.SharingCapability=9")):
        row = run(policy, **tenant)
        assert (row["status"], row["reason"]) == ("UNMAPPED", reason)
    empty = _verdict_for(script, runtime, policy_map, {"SPO_tenant": []}, "MS.SHAREPOINT.1.1v1")[0]
    assert (empty["status"], empty["reason"]) == ("UNMAPPED", "evidence_missing:SPO_tenant")


def _teams(**changes) -> dict:
    inp = {"meeting_policies": [{"AllowAnonymousUsersToStartMeeting": False, "AllowCloudRecording": False, "AllowExternalParticipantGiveRequestControl": False,
                                 "AllowPSTNUsersToBypassLobby": False, "AutoAdmittedUsers": "EveryoneInCompanyExcludingGuests", "Identity": "Global"}],
           "federation_configuration": [{"AllowFederatedUsers": False, "AllowPublicUsers": False, "AllowTeamsConsumer": False, "AllowTeamsConsumerInbound": False,
                                         "AllowedDomains": [], "Identity": "Global"}],
           "client_configuration": [{"AllowEmailIntoChannel": False, "Identity": "Global"}],
           "scuba_config": {"M365Environment": "commercial"}}
    inp.update(changes)
    return inp


@needs_prowler
def test_teams_checks_run_offline_on_a_scubagear_variant(script, runtime, policy_map, offline):
    policies = ("MS.TEAMS.1.1v1", "MS.TEAMS.1.2v2", "MS.TEAMS.1.3v1", "MS.TEAMS.1.5v1", "MS.TEAMS.1.6v1", "MS.TEAMS.2.1v2", "MS.TEAMS.2.2v2",
                "MS.TEAMS.2.3v2", "MS.TEAMS.4.1v1")
    compliant = {p: _verdict_for(script, runtime, policy_map, _teams(), p)[0]["status"] for p in policies}
    assert set(compliant.values()) == {"PASS"}, compliant
    meeting = _teams()["meeting_policies"][0]
    flipped = {"MS.TEAMS.1.1v1": ("AllowExternalParticipantGiveRequestControl", True), "MS.TEAMS.1.2v2": ("AllowAnonymousUsersToStartMeeting", True),
               "MS.TEAMS.1.3v1": ("AutoAdmittedUsers", "Everyone"), "MS.TEAMS.1.5v1": ("AllowPSTNUsersToBypassLobby", True),
               "MS.TEAMS.1.6v1": ("AllowCloudRecording", True)}
    for policy, (key, value) in flipped.items():
        row = _verdict_for(script, runtime, policy_map, _teams(meeting_policies=[{**meeting, key: value}]), policy)[0]
        assert row["status"] == "FAIL", policy
    federation = _teams()["federation_configuration"][0]
    for policy, key in (("MS.TEAMS.2.1v2", "AllowFederatedUsers"), ("MS.TEAMS.2.2v2", "AllowTeamsConsumerInbound"), ("MS.TEAMS.2.3v2", "AllowTeamsConsumer")):
        assert _verdict_for(script, runtime, policy_map, _teams(federation_configuration=[{**federation, key: True}]), policy)[0]["status"] == "FAIL", policy
    assert _verdict_for(script, runtime, policy_map, _teams(client_configuration=[{"AllowEmailIntoChannel": True, "Identity": "Global"}]), "MS.TEAMS.4.1v1")[0]["status"] == "FAIL"
    # Prowler reads only the Global policy; the others are recorded as unread, and a tenant without a Global policy cannot be judged
    extra = _teams(meeting_policies=[meeting, {**meeting, "Identity": "Tag:Custom", "AllowCloudRecording": True}])
    only_global = _verdict_for(script, runtime, policy_map, extra, "MS.TEAMS.1.6v1")[0]
    assert only_global["status"] == "PASS" and any("1 other entries are not read" in a for a in only_global["assumptions"])
    none = _verdict_for(script, runtime, policy_map, _teams(meeting_policies=[{**meeting, "Identity": "Tag:Custom"}]), "MS.TEAMS.1.6v1")[0]
    assert (none["status"], none["reason"]) == ("UNMAPPED", "evidence_missing:meeting_policies.Global")
    # ScubaGear records 2.2, 2.3 and 4.1 as met in a US Government region without testing them, so they are not compared
    gcc = _teams(scuba_config={"M365Environment": "gcc"}, client_configuration=[{"AllowEmailIntoChannel": True, "Identity": "Global"}])
    row = _verdict_for(script, runtime, policy_map, gcc, "MS.TEAMS.4.1v1")[0]
    assert (row["status"], row["prowler_status"], row["reason"]) == ("UNMAPPED", "FAIL", "scubagear_not_applicable:us_government_region")
    assert _verdict_for(script, runtime, policy_map, gcc, "MS.TEAMS.1.6v1")[0]["status"] == "PASS", "policies without a regional exemption still run"


@needs_prowler
def test_consensus_counts_on_a_synthetic_multi_product_kit(script, runtime, policy_map, tmp_path, offline):
    kit = tmp_path / "kit"
    exo = {"transport_config": [{"Name": "A", "SmtpClientAuthenticationDisabled": True}]}
    exo_open = {"transport_config": [{"Name": "A", "SmtpClientAuthenticationDisabled": False}]}
    ss = _ss(conn_filter=[{"EnableSafeList": False, "IPAllowList": ["192.0.2.1"], "Name": "A"}])
    sharepoint = {"SPO_tenant": [{"SharingCapability": 1, "SharingDomainRestrictionMode": 0}]}
    teams, teams_gcc = _teams(), _teams(scuba_config={"M365Environment": "gcc"})
    plan = {  # product -> package -> [(variant name, input)] and the cases (policy, variant index, ScubaGear label)
        "EXO": ("exo", [exo, exo_open], [("MS.EXO.5.1v1", 0, True), ("MS.EXO.5.1v1", 1, True), ("MS.EXO.1.1v2", 0, True), ("MS.EXO.5.1v1", 0, None)]),
        "SecuritySuite": ("securitysuite", [ss], [("MS.SECURITYSUITE.8.1v1", 0, False)]),
        "Sharepoint": ("sharepoint", [sharepoint], [("MS.SHAREPOINT.1.1v1", 0, False)]),
        "Teams": ("teams", [teams, teams_gcc], [("MS.TEAMS.1.6v1", 0, True), ("MS.TEAMS.4.1v1", 1, True)])}
    products = {}
    for product, (package, variants, cases) in plan.items():
        (kit / f"variants-{package}").mkdir(parents=True)
        shas = []
        for index, inp in enumerate(variants):
            data = json.dumps(inp, sort_keys=True, separators=(",", ":"))
            (kit / f"variants-{package}" / f"variant-{index:04d}.json").write_text(data, encoding="utf-8")
            shas.append(hashlib.sha256(data.encode()).hexdigest())
        rows = [_case(policy=policy, variant=f"test_{n}", sha=shas[index], value=bool(label), status="confirmed" if label is not None else "unknown",
                      case_id=f"{product}-{n}") for n, (policy, index, label) in enumerate(cases)]
        (kit / f"cases-{package}.jsonl").write_text("".join(json.dumps(c) + "\n" for c in rows), encoding="utf-8")
        products[product] = {"package": package, "sections_per_policy": {r["scubagear_policy"]: [] for r in policy_map["rows"] if r["product"] == product}}
    (kit / "summary.json").write_text(json.dumps({"products": products}), encoding="utf-8")
    out = tmp_path / "out"
    assert script.main(["--kit-dir", str(kit), "--prowler-root", str(PROWLER_ROOT), "--output-dir", str(out), "--products", *plan]) == 0
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))["products"]
    assert {p: summary[p]["consensus"] for p in plan} == {
        "EXO": {"agree": 1, "disagree": 1, "unmapped": 2},
        "SecuritySuite": {"agree": 1},
        "Sharepoint": {"disagree": 1},
        "Teams": {"agree": 1, "unmapped": 1}}
    consensus = {r["case_id"]: r for r in map(json.loads, (out / "consensus.jsonl").read_text(encoding="utf-8").splitlines())}
    assert consensus["EXO-1"]["consensus"] == "disagree" and consensus["EXO-1"]["prowler_verdict"] == "FAIL"
    assert consensus["EXO-2"]["reason"] == "not_exported:outbound_spam_policy"
    assert consensus["EXO-3"]["reason"] == "scubagear_label_unknown"
    assert consensus["Sharepoint-0"]["prowler_verdict"] == "PASS", "Prowler accepts New and existing guests where ScubaGear 1.1 does not"
    assert consensus["Teams-1"]["reason"] == "scubagear_not_applicable:us_government_region"
    assert summary["EXO"]["checks_executed"] == ["exchange_transport_config_smtp_auth_disabled"]
    assert "defender_antispam_outbound_policy_forwarding_disabled" in summary["EXO"]["checks_not_evaluated"]
    assert summary["Sharepoint"]["compared_by_confidence"] == {"exact": {}, "partial": {"disagree": 1}}


def test_missing_provider_directory_is_a_clear_error(script, tmp_path):
    with pytest.raises(SystemExit) as error:
        script.ProwlerRuntime(tmp_path)
    assert "prowler/providers/m365/services is missing" in str(error.value)
