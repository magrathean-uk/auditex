"""Policy sub-families and frozen test membership, without OPA or the case miner."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import stat
from pathlib import Path

import pytest

from auditex.model_training import distinct_prompt_sha256, validate_cases

POLICY = "MS.SHAREPOINT.1.3v1"
SOURCE_FAMILY = "scuba-sharepoint-ms-sharepoint-1"
SUB_FAMILY = "scuba-sharepoint-ms-sharepoint-1-3v1"
TEST_FAMILY = "scuba-sharepoint-ms-sharepoint-2"


@pytest.fixture(scope="module")
def splitter():
    path = Path(__file__).resolve().parents[1] / "scripts" / "split-oracle-cases.py"
    spec = importlib.util.spec_from_file_location("split_oracle_cases", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def cases():
    rows = []
    for policy, family in (("MS.SHAREPOINT.1.1v1", SOURCE_FAMILY), (POLICY, SOURCE_FAMILY),
                           ("MS.SHAREPOINT.2.1v1", TEST_FAMILY), ("MS.AAD.1.1v1", "scuba-aad-ms-aad-1")):
        for variant in range(3):
            case_id = f"{policy}-{variant}"
            evidence_id = f"{case_id}:E1"
            response = {"claims": [{"id": "requirement_met", "status": "confirmed", "value": True,
                                     "evidence_ids": [evidence_id]}],
                        "limitations": [], "recommendations": []}
            row = {
                "id": case_id, "family": family, "split": "train",
                "provenance": {"source": "oracle:cisa-scubagear@abcdef123456 fixture; opa=1.20.2; synthetic",
                               "synthetic": True, "review_status": "unreviewed",
                               "template": f"{family.split('-')[1]}/{policy}/base"},
                "messages": [{"role": "system", "content": "Evaluate only the supplied evidence."},
                             {"role": "user", "content": json.dumps({"case_id": case_id, "policy_id": policy,
                              "evidence": [{"id": evidence_id, "observed": {"enabled": True, "variant": variant}}]})},
                             {"role": "assistant", "content": json.dumps(response)}],
                "expected": {**response, "allowed_evidence_ids": [evidence_id]},
            }
            row["provenance"]["distinct_prompt_sha256"] = distinct_prompt_sha256(row)
            rows.append(row)
    return validate_cases(rows)


def _policy(case):
    return json.loads(case["messages"][1]["content"])["policy_id"]


def _write_cases(path, cases):
    path.write_text("".join(json.dumps(case) + "\n" for case in cases), encoding="utf-8")
    return path


def _baseline(splitter, cases):
    return splitter.split_cases(cases, holdout_families=[TEST_FAMILY])


def test_relabel_moves_only_the_requested_policy_and_records_input_rows(splitter, cases):
    original = copy.deepcopy(cases)
    rows, report = splitter.split_cases(cases, sub_families={POLICY: SUB_FAMILY})
    assert len(rows) == 12
    assert [row["id"] for row in rows] == [row["id"] for row in cases]
    for before, after in zip(cases, rows):
        assert after == {**before, "family": SUB_FAMILY if _policy(before) == POLICY else before["family"],
                         "split": after["split"]}
    assert report["sub_families"] == {POLICY: {"family": SUB_FAMILY, "from_family": SOURCE_FAMILY, "rows": 3}}
    assert cases == original
    validate_cases(rows)


def test_relabel_precedes_dedupe_and_counts_dropped_input_rows(splitter, cases):
    first = next(row for row in cases if _policy(row) == POLICY)
    duplicate = json.loads(json.dumps(first).replace(first["id"], "duplicate-policy-row"))
    rows, report = splitter.split_cases(cases + [duplicate], sub_families={POLICY: SUB_FAMILY})
    assert report["sub_families"][POLICY]["rows"] == 4
    assert report["duplicates_dropped"] == {"count": 1, "pairs": [{"dropped": duplicate["id"], "kept": first["id"]}]}
    assert len(rows) == 12
    assert all(row["family"] == SUB_FAMILY for row in rows if _policy(row) == POLICY)


def test_cli_repeated_sub_families_can_move_one_policy_to_validation_and_freeze_test(splitter, cases, tmp_path):
    source = _write_cases(tmp_path / "source.jsonl", cases)
    previous_cases = copy.deepcopy(cases)
    splitter.apply_sub_families(previous_cases, {"MS.AAD.1.1v1": "scuba-aad-ms-aad-1-policy"})
    baseline_source = _write_cases(tmp_path / "baseline-source.jsonl", previous_cases)
    baseline = tmp_path / "baseline.jsonl"
    previous = tmp_path / "baseline-report.json"
    assert splitter.main(["--cases", str(baseline_source), "--output", str(baseline), "--report", str(previous),
                          "--holdout-families", TEST_FAMILY]) == 0
    output = tmp_path / "new" / "cases.jsonl"
    report_path = output.with_name("split-report.json")
    assert splitter.main(["--cases", str(source), "--output", str(output), "--approve-as-oracle",
                          "--sub-family", f"{POLICY}={SUB_FAMILY}",
                          "--sub-family", "MS.AAD.1.1v1=scuba-aad-ms-aad-1-policy",
                          "--validation-families", SUB_FAMILY, "--previous-report", str(previous)]) == 0
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert {row["id"] for row in rows if row["split"] == "validation"} == {
        row["id"] for row in cases if _policy(row) == POLICY}
    assert all(row["split"] == "train" for row in rows if _policy(row) == "MS.SHAREPOINT.1.1v1")
    assert not any(report["leakage"].values())
    assert report["test_ids_frozen"] is True
    assert report["test_ids_sha256_previous"] == report["test_ids_sha256"]
    assert report["family_split_changes"] == []
    assert report["families_removed"] == []
    assert report["families_added"] == [SUB_FAMILY]
    assert report["test_sha256_previous"] == json.loads(previous.read_text())["test_sha256"]
    assert report["test_content_frozen"] is False  # Approval changes test-row provenance.
    assert report["test_ids"] == sorted(row["id"] for row in rows if row["split"] == "test")
    assert all(row["provenance"]["review_status"] == "approved" for row in rows)
    assert all("no human review" in row["provenance"]["reviewer"] for row in rows)
    assert stat.S_IMODE(output.stat().st_mode) == stat.S_IMODE(report_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(output.parent.stat().st_mode) == 0o700
    validate_cases(rows)


@pytest.mark.parametrize(("mapping", "message"), [
    ({POLICY: "scuba-aad-policy-1"}, "wrong product"),
    ({"MS.UNKNOWN.1.1v1": SUB_FAMILY}, "unknown policy"),
    ({POLICY: TEST_FAMILY}, "collision"),
    ({POLICY: SOURCE_FAMILY}, "no-op"),
    ({POLICY: "invalid-family"}, "not an oracle family"),
    ({POLICY: "scuba-sharepoint-"}, "not an oracle family"),
    ({POLICY: "scuba-sharepoint--group"}, "not an oracle family"),
    ({POLICY: "scuba--group"}, "not an oracle family"),
    ({POLICY: f"{SUB_FAMILY}_invalid"}, "not an oracle family"),
    ({POLICY: f"{SOURCE_FAMILY}-"}, "not an oracle family"),
    ({POLICY: f"{SOURCE_FAMILY}-.."}, "not an oracle family"),
    ({POLICY: f"{SOURCE_FAMILY}-.suffix"}, "not an oracle family"),
    ({POLICY: f"{SOURCE_FAMILY}-suffix."}, "not an oracle family"),
    ({POLICY: f"{SOURCE_FAMILY}-suffix..part"}, "not an oracle family"),
    ({POLICY: f"{SOURCE_FAMILY}-suffix--part"}, "not an oracle family"),
    ({POLICY: "scuba-sharepoint-unknown-group"}, "must start with <from_family>-"),
    ({POLICY: "scuba-sharepoint-zz"}, "must start with <from_family>-"),
    ({POLICY: SUB_FAMILY, "MS.SHAREPOINT.1.1v1": SUB_FAMILY}, "collision"),
])
def test_invalid_sub_families_are_rejected_without_mutating_input(splitter, cases, mapping, message):
    before = copy.deepcopy(cases)
    with pytest.raises(ValueError, match=message):
        splitter.split_cases(cases, sub_families=mapping)
    assert cases == before
    with pytest.raises(ValueError, match=message):
        splitter.apply_sub_families(cases, mapping)
    assert cases == before


def test_non_test_policy_relabel_preserves_test_ids_hash(splitter, cases):
    baseline_rows, baseline = _baseline(splitter, cases)
    rows, report = splitter.split_cases(cases, sub_families={POLICY: SUB_FAMILY}, validation_families=[SUB_FAMILY])
    assert report["test_ids_sha256"] == baseline["test_ids_sha256"]
    assert report["test_ids_sha256"] == hashlib.sha256("\n".join(baseline["test_ids"]).encode("utf-8")).hexdigest()
    assert [row for row in rows if row["split"] == "test"] == [row for row in baseline_rows if row["split"] == "test"]
    assert splitter.check_frozen_test_ids(list(reversed(rows)), baseline) == {
        "test_ids_sha256_previous": baseline["test_ids_sha256"], "test_ids_frozen": True,
        "test_sha256_previous": baseline["test_sha256"], "test_content_frozen": False}
    assert splitter.check_frozen_test_ids(iter(rows), baseline)["test_content_frozen"] is True


def test_cli_frozen_test_failure_lists_departed_ids_and_writes_nothing(splitter, cases, tmp_path, capsys):
    _, report = _baseline(splitter, cases)
    previous = tmp_path / "previous.json"
    previous.write_text(json.dumps(report), encoding="utf-8")
    source = _write_cases(tmp_path / "source.jsonl", cases)
    output = tmp_path / "must-not-exist" / "cases.jsonl"
    report_path = tmp_path / "also-must-not-exist" / "report.json"
    assert splitter.main(["--cases", str(source), "--output", str(output), "--report", str(report_path),
                          "--validation-families", TEST_FAMILY, "--previous-report", str(previous)]) == 1
    error = capsys.readouterr().err
    assert "frozen test IDs changed" in error and "left test (3)" in error
    assert all(case_id in error for case_id in report["test_ids"])
    assert not output.parent.exists() and not report_path.parent.exists()


def test_frozen_helper_lists_entered_and_left_ids(splitter, cases):
    rows, previous = _baseline(splitter, cases)
    leaving = next(row for row in rows if row["split"] == "test")
    entering = next(row for row in rows if row["split"] == "train")
    leaving["split"], entering["split"] = "train", "test"
    with pytest.raises(ValueError) as exc:
        splitter.check_frozen_test_ids(rows, previous)
    assert f"entered test (1): ['{entering['id']}']" in str(exc.value)
    assert f"left test (1): ['{leaving['id']}']" in str(exc.value)


def test_legacy_hash_only_reports_still_enforce_frozen_ids(splitter, cases):
    rows, previous = _baseline(splitter, cases)
    previous = {"test_ids_sha256": previous["test_ids_sha256"]}
    assert splitter.check_frozen_test_ids(rows, previous)["test_ids_frozen"] is True
    assert splitter.check_frozen_test_ids(rows, previous)["test_content_frozen"] is None
    with pytest.raises(ValueError, match="previous report has no test_ids"):
        splitter.check_frozen_test_ids([], previous)


def test_hash_only_mismatch_reports_case_counts_instead_of_unrelated_ids(splitter, cases):
    rows, baseline = _baseline(splitter, cases)
    previous = {"test_ids_sha256": baseline["test_ids_sha256"], "splits": {"test": {"cases": 3}}}
    rows[0]["split"] = "test"
    with pytest.raises(ValueError) as exc:
        splitter.check_frozen_test_ids(rows, previous)
    message = str(exc.value)
    assert "current test cases: 4; previous test cases: 3" in message
    assert all(row["id"] not in message for row in rows)


def test_test_content_changes_are_reported_but_allowed(splitter, cases, tmp_path):
    _, previous_report = _baseline(splitter, cases)
    previous = tmp_path / "previous.json"
    previous.write_text(json.dumps(previous_report), encoding="utf-8")
    for row in cases:
        if row["family"] == TEST_FAMILY:
            row["messages"][0]["content"] += " Explain your answer."
            row["provenance"]["distinct_prompt_sha256"] = distinct_prompt_sha256(row)
    source = _write_cases(tmp_path / "source.jsonl", cases)
    output = tmp_path / "new" / "cases.jsonl"
    assert splitter.main(["--cases", str(source), "--output", str(output),
                          "--holdout-families", TEST_FAMILY, "--previous-report", str(previous)]) == 0
    report = json.loads(output.with_name("split-report.json").read_text())
    assert report["test_ids_frozen"] is True
    assert report["test_sha256_previous"] == previous_report["test_sha256"]
    assert report["test_sha256"] != report["test_sha256_previous"]
    assert report["test_content_frozen"] is False


def test_sub_family_supports_list_form_from_family(splitter, cases):
    policy_rows = [row for row in cases if _policy(row) == POLICY]
    other_source = f"{SOURCE_FAMILY}-legacy"
    policy_rows[0]["family"] = other_source
    target = f"{other_source}-policy"
    rows, report = splitter.split_cases(cases, sub_families={POLICY: target})
    assert report["sub_families"][POLICY] == {
        "family": target, "from_family": [SOURCE_FAMILY, other_source], "rows": 3}
    assert {row["family"] for row in rows if _policy(row) == POLICY} == {target}
    with pytest.raises(ValueError, match="must start with <from_family>-"):
        splitter.apply_sub_families(cases, {POLICY: SUB_FAMILY})


def test_cli_sub_family_requires_previous_report_and_documents_rules(splitter, cases, tmp_path, capsys):
    source = _write_cases(tmp_path / "source.jsonl", cases)
    output = tmp_path / "new" / "cases.jsonl"
    assert splitter.main(["--cases", str(source), "--output", str(output),
                          "--sub-family", f"{POLICY}={SUB_FAMILY}"]) == 1
    assert "--sub-family requires --previous-report" in capsys.readouterr().err
    assert not output.parent.exists()
    with pytest.raises(SystemExit) as exc:
        splitter.main(["--help"])
    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "requires --previous-report" in help_text
    assert "<from_family>-" in help_text
    assert "[a-z0-9]+(?:[.-][a-z0-9]+)*" in help_text


def test_cli_sub_family_can_be_explicit_holdout_with_frozen_test(splitter, cases, tmp_path):
    previous_cases = copy.deepcopy(cases)
    splitter.apply_sub_families(previous_cases, {POLICY: SUB_FAMILY})
    _, baseline = splitter.split_cases(previous_cases, holdout_families=[SUB_FAMILY])
    previous = tmp_path / "previous.json"
    previous.write_text(json.dumps(baseline), encoding="utf-8")
    source = _write_cases(tmp_path / "source.jsonl", cases)
    output = tmp_path / "new" / "cases.jsonl"
    assert splitter.main(["--cases", str(source), "--output", str(output),
                          "--sub-family", f"{POLICY}={SUB_FAMILY}", "--holdout-families", SUB_FAMILY,
                          "--previous-report", str(previous)]) == 0
    report = json.loads(output.with_name("split-report.json").read_text())
    assert SUB_FAMILY in report["splits"]["test"]["families"]
    assert report["test_ids_frozen"] is report["test_content_frozen"] is True
    assert report["test_sha256_previous"] == report["test_sha256"]
    assert report["family_split_changes"] == []


def test_cli_refuses_silent_validation_family_drift_before_writing(splitter, cases, tmp_path, capsys):
    _, baseline = _baseline(splitter, cases)
    previous = tmp_path / "previous.json"
    previous.write_text(json.dumps(baseline), encoding="utf-8")
    added = copy.deepcopy(cases[0])
    added["id"] = "new-family-case"
    added["family"] = "scuba-sharepoint-aa"
    added["provenance"]["template"] = "new-policy/base"
    added["messages"][0]["content"] += " New policy group."
    added["provenance"]["distinct_prompt_sha256"] = distinct_prompt_sha256(added)
    source = _write_cases(tmp_path / "source.jsonl", cases + [added])
    output = tmp_path / "new" / "cases.jsonl"
    args = ["--cases", str(source), "--output", str(output), "--previous-report", str(previous)]
    assert splitter.main(args) == 1
    error = capsys.readouterr().err
    assert "family splits changed without explicit selection" in error
    assert SOURCE_FAMILY in error and "train" in error and "validation" in error
    assert not output.parent.exists()
    assert splitter.main(args + ["--validation-families", SOURCE_FAMILY]) == 0
    report = json.loads(output.with_name("split-report.json").read_text())
    assert report["test_ids_frozen"] is True
    assert report["family_split_changes"] == [
        {"family": SOURCE_FAMILY, "from_split": "train", "to_split": "validation"}]


@pytest.mark.parametrize("selection", ["validation_families", "holdout_families"])
def test_family_split_helper_only_allows_explicitly_named_families(splitter, cases, selection):
    rows, previous = _baseline(splitter, cases)
    for row in rows:
        if row["family"] == SOURCE_FAMILY:
            row["split"] = "validation"
    with pytest.raises(ValueError, match="family splits changed"):
        splitter.check_family_split_changes(rows, previous)
    allowed = {selection: [SOURCE_FAMILY]}
    assert splitter.check_family_split_changes(iter(rows), previous, **allowed) == {
        "family_split_changes": [{"family": SOURCE_FAMILY, "from_split": "train", "to_split": "validation"}],
        "families_removed": [], "families_added": []}
    with pytest.raises(ValueError, match="family splits changed"):
        splitter.check_family_split_changes(rows, previous, **{
            selection: [SUB_FAMILY]})


def test_family_split_helper_supports_legacy_reports_and_unchanged_assignments(splitter, cases):
    rows, previous = _baseline(splitter, cases)
    assert previous["family_split_changes"] is None
    assert splitter.check_family_split_changes(rows, previous) == {
        "family_split_changes": [], "families_removed": [], "families_added": []}
    for legacy in ({}, {"splits": {"test": {"cases": 3}}}):
        assert splitter.check_family_split_changes(rows, legacy) == {
            "family_split_changes": [], "families_removed": [],
            "families_added": sorted({row["family"] for row in rows})}


@pytest.mark.parametrize("selection", ["sub_families", "validation_families", "holdout_families"])
def test_removed_families_require_acknowledgement_and_added_families_are_recorded(splitter, selection):
    previous = {"splits": {"validation": {"families": [SUB_FAMILY, SOURCE_FAMILY]}}}
    rows = [{"family": TEST_FAMILY, "split": "train"},
            {"family": "scuba-aad-ms-aad-1", "split": "train"}]
    with pytest.raises(ValueError, match="families removed without explicit selection") as exc:
        splitter.check_family_split_changes(rows, previous)
    assert SOURCE_FAMILY in str(exc.value) and SUB_FAMILY in str(exc.value)
    partial = {selection: {POLICY: SUB_FAMILY} if selection == "sub_families" else [SUB_FAMILY]}
    with pytest.raises(ValueError, match=SOURCE_FAMILY):
        splitter.check_family_split_changes(rows, previous, **partial)
    acknowledgement = {selection: {POLICY: SUB_FAMILY, "other": SOURCE_FAMILY}
                       if selection == "sub_families" else [SUB_FAMILY, SOURCE_FAMILY]}
    assert splitter.check_family_split_changes(iter(rows), previous, **acknowledgement) == {
        "family_split_changes": [], "families_removed": [SOURCE_FAMILY, SUB_FAMILY],
        "families_added": ["scuba-aad-ms-aad-1", TEST_FAMILY]}


@pytest.mark.parametrize("retain_sub_family", [False, True])
def test_cli_refuses_omitted_sub_family_or_validation_selection(splitter, cases, tmp_path, capsys,
                                                              retain_sub_family):
    # A later atom keeps the sub-family in train unless validation is explicitly selected.
    added = copy.deepcopy(cases[0])
    added["id"] = "later-atom-case"
    added["family"] = f"{SOURCE_FAMILY}-later"
    added["provenance"]["template"] = "later-policy/base"
    added["messages"][0]["content"] += " Later policy group."
    added["provenance"]["distinct_prompt_sha256"] = distinct_prompt_sha256(added)
    cases = cases + [added]
    _, baseline = splitter.split_cases(cases, sub_families={POLICY: SUB_FAMILY},
                                       validation_families=[SUB_FAMILY], holdout_families=[TEST_FAMILY])
    previous = tmp_path / "previous.json"
    previous.write_text(json.dumps(baseline), encoding="utf-8")
    source = _write_cases(tmp_path / "source.jsonl", cases)
    output = tmp_path / "new" / "cases.jsonl"
    report_path = tmp_path / "new-report" / "report.json"
    args = ["--cases", str(source), "--output", str(output), "--report", str(report_path),
            "--previous-report", str(previous), "--holdout-families", TEST_FAMILY]
    if retain_sub_family:
        args.extend(["--sub-family", f"{POLICY}={SUB_FAMILY}"])
    assert splitter.main(args) == 1
    error = capsys.readouterr().err
    assert SUB_FAMILY in error
    assert ("family splits changed" if retain_sub_family else "families removed") in error
    assert not output.parent.exists() and not report_path.parent.exists()
    if retain_sub_family:
        assert splitter.main(args + ["--validation-families", SUB_FAMILY]) == 0
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["family_split_changes"] == []
        assert report["families_removed"] == report["families_added"] == []


@pytest.mark.parametrize("suffix", ["a", "3v1", "policy.3-part"])
def test_sub_family_accepts_nonempty_alphanumeric_suffix_segments(splitter, cases, suffix):
    target = f"{SOURCE_FAMILY}-{suffix}"
    rows, _ = splitter.split_cases(cases, sub_families={POLICY: target})
    assert {row["family"] for row in rows if _policy(row) == POLICY} == {target}


def test_cli_without_previous_report_marks_every_comparison_unchecked(splitter, cases, tmp_path):
    source = _write_cases(tmp_path / "source.jsonl", cases)
    output = tmp_path / "new" / "cases.jsonl"
    assert splitter.main(["--cases", str(source), "--output", str(output)]) == 0
    report = json.loads(output.with_name("split-report.json").read_text(encoding="utf-8"))
    for field in ("test_ids_sha256_previous", "test_sha256_previous", "test_content_frozen", "test_ids_frozen",
                  "family_split_changes", "families_removed", "families_added"):
        assert field in report and report[field] is None, field


@pytest.mark.parametrize("previous", [[], {"splits": []}, {"splits": {"test": []}},
                                    {"splits": {"test": {"families": "invalid"}}},
                                    {"splits": {"test": {"families": [None]}}},
                                    {"splits": {"train": {"families": [SOURCE_FAMILY]},
                                                "test": {"families": [SOURCE_FAMILY]}}}])
def test_family_split_helper_rejects_malformed_previous_family_assignments(splitter, cases, previous):
    with pytest.raises(ValueError, match="previous report"):
        splitter.check_family_split_changes(cases, previous)


@pytest.mark.parametrize("previous", [[], {}, {"test_ids_sha256": "invalid"},
                                    {"test_ids_sha256": "0" * 64, "test_ids": "invalid"},
                                    {"test_ids_sha256": "0" * 64, "test_ids": []}])
def test_invalid_previous_reports_fail_closed(splitter, cases, tmp_path, previous, capsys):
    source = _write_cases(tmp_path / "source.jsonl", cases)
    previous_path = tmp_path / "previous.json"
    previous_path.write_text(json.dumps(previous), encoding="utf-8")
    output = tmp_path / "new" / "cases.jsonl"
    assert splitter.main(["--cases", str(source), "--output", str(output),
                          "--previous-report", str(previous_path)]) == 1
    assert "previous report" in capsys.readouterr().err
    assert not output.parent.exists()


@pytest.mark.parametrize("contents", [None, "{invalid JSON"])
def test_unreadable_or_malformed_previous_report_writes_nothing(splitter, cases, tmp_path, contents):
    source = _write_cases(tmp_path / "source.jsonl", cases)
    previous = tmp_path / "previous.json"
    if contents is not None:
        previous.write_text(contents, encoding="utf-8")
    output = tmp_path / "new" / "cases.jsonl"
    assert splitter.main(["--cases", str(source), "--output", str(output), "--previous-report", str(previous)]) == 1
    assert not output.parent.exists()


@pytest.mark.parametrize("assignments", [["missing-equals"], ["=scuba-aad-policy"], [f"{POLICY}="],
                                       [f"{POLICY}={SUB_FAMILY}", f"{POLICY}=scuba-sharepoint-other"]])
def test_cli_rejects_malformed_or_conflicting_sub_family_options(splitter, cases, tmp_path, assignments):
    source = _write_cases(tmp_path / "source.jsonl", cases)
    output = tmp_path / "new" / "cases.jsonl"
    _, baseline = _baseline(splitter, cases)
    previous = tmp_path / "previous.json"
    previous.write_text(json.dumps(baseline), encoding="utf-8")
    args = ["--cases", str(source), "--output", str(output), "--previous-report", str(previous)]
    for assignment in assignments:
        args.extend(["--sub-family", assignment])
    assert splitter.main(args) == 1
    assert not output.parent.exists()
