"""Prowler consensus oracle: policy map, consensus logic and an offline run of real Prowler checks.

The map and consensus tests are pure. The tests marked `needs_prowler` import Prowler's own models from a checkout whose
`prowler/providers/m365` is on disk and need Prowler's dependencies in the interpreter (see docs/guides/model-development.md);
they are skipped otherwise.
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
    assert set(script.CHECK_ATTRIBUTES) <= mapped
    for groups in script.CHECK_ATTRIBUTES.values():
        assert set(groups) <= set(script.ATTRIBUTE_BUILDERS)
    services = {r["prowler_check"]: r["prowler_service"] for r in policy_map["rows"]}
    assert {services[c] for c in script.CHECK_ATTRIBUTES} <= {"entra", "admincenter"}


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


def test_missing_provider_directory_is_a_clear_error(script, tmp_path):
    with pytest.raises(SystemExit) as error:
        script.ProwlerRuntime(tmp_path)
    assert "prowler/providers/m365/services is missing" in str(error.value)
