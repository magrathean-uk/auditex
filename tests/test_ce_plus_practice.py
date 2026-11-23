"""CE+ practice run derivation (src/auditex/ce_plus.py, DEC-146). Expected values are literals from the spec."""
from __future__ import annotations

import ast
import copy
import json
import re
import shutil
from datetime import date
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from auditex.ce_plus import build_practice_run, evidence_age_days, load_catalogue

ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = load_catalogue()
SCHEMA = json.loads((ROOT / "schemas" / "ce_plus_practice.schema.json").read_text(encoding="utf-8"))
STATUSES = {
    control_id: spec["status"]
    for control_id, spec in json.loads((ROOT / "configs" / "framework-catalog.json").read_text(encoding="utf-8"))[
        "frameworks"
    ]["cyber_essentials"]["controls"].items()
}
M365 = {"platform": "m365", "run_id": "practice", "tenant_name": "acme", "created_utc": "2026-11-01T09:30:00Z"}
GOOGLE = {**M365, "platform": "google_workspace"}
AS_OF = date(2026, 11, 2)


def _rule(rule_id: str, status: str, *, confidence: str = "full", reason: str | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {"rule_id": rule_id, "status": status, "evaluated": status != "not_assessed", "confidence": confidence}
    if reason:
        item["reason"] = reason
    return item


def _row(control_id: str, status: str, rules: list[dict[str, Any]] | None = None, *, reason: str | None = None,
         requirement_status: str | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {
        "control_id": control_id,
        "requirement_status": requirement_status or STATUSES.get(control_id, "partial"),
        "status": status,
        "rule_statuses": rules if rules is not None else [],
        "open_finding_count": 0,
        "finding_ids": [],
    }
    if reason:
        row["reason"] = reason
    return row


def _clean(control_id: str, rule_id: str = "clean.rule") -> dict[str, Any]:
    return _row(control_id, "not_assessed", [_rule(rule_id, "pass")], reason="partial_requirement_no_gap_found")


def _section(*rows: Any, version: str = "v3.3") -> dict[str, Any]:
    return {"version": version, "controls": list(rows)}


def _full_section(**overrides: dict[str, Any]) -> dict[str, Any]:
    """Every shipped requirement: outside-tenant rows as the engine writes them, partial rows clean unless overridden."""
    rows = []
    for control_id, status in STATUSES.items():
        if control_id in overrides:
            rows.append(overrides[control_id])
        elif status == "partial":
            rows.append(_clean(control_id))
        else:
            rows.append(_row(control_id, "not_assessed", reason=f"requirement_status:{status}"))
    return _section(*rows)


def _by_id(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["requirement_id"]: row for row in payload["requirements"]}


# -- 1. ranking ----------------------------------------------------------------------------------------------------


def _small_catalogue(actions: list[dict[str, Any]], conflicts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    catalogue = copy.deepcopy(CATALOGUE)
    catalogue["requirements"] = [
        {"requirement_id": rid, "title": rid, "theme": "t", "requirement_status": status, "evidence_limits": "x"}
        for rid, status in (("r1", "partial"), ("r2", "partial"), ("r3", "partial"), ("r4", "manual"), ("r5", "manual"))
    ]
    catalogue["actions"] = actions
    catalogue["conflicts"] = conflicts or []
    catalogue["assessor_tests"] = []
    return catalogue


def _action(action_id: str, trigger: str, effort: str, requirement_ids: list[str], *, rule_ids: list[str] = (),
            states: list[str] = (), conflict_ids: list[str] = (), platforms: list[str] = ("any",)) -> dict[str, Any]:
    return {
        "id": action_id, "title": action_id, "proof_to_gather": "p", "kind": "gather_proof", "effort": effort,
        "platforms": list(platforms), "requirement_ids": requirement_ids, "trigger": trigger,
        "rule_ids": list(rule_ids), "states": list(states), "conflict_ids": list(conflict_ids),
    }


RANKING_ACTIONS = [
    _action("a.recollect", "rule_not_evaluated", "moderate", ["r1", "r2", "r3", "r4", "r5"]),
    _action("a.test", "assessor_test", "quick", ["r4"]),
    _action("a.gather_r1", "requirement_state", "extended", ["r1", "r3"], states=["gap_observed", "evidence_unknown"]),
    _action("a.reconcile", "conflict", "moderate", ["r2"], conflict_ids=["c1"]),
    _action("a.fix_r2_state", "rule_gap", "moderate", ["r2"], rule_ids=["s.rule"]),
    _action("a.gather_outside", "requirement_state", "quick", ["r4", "r5"], states=["outside_tenant_evidence"]),
    _action("a.fix_r1", "rule_gap", "quick", ["r1"], rule_ids=["r1.rule"]),
    _action("a.never", "rule_gap", "quick", ["r1"], rule_ids=["absent.rule"]),
    _action("a.google_only", "rule_gap", "quick", ["r1"], rule_ids=["r1.rule"], platforms=["google_workspace"]),
]
RANKING_CONFLICT = {
    "id": "c1", "requirement_id": "r2", "platforms": ["m365"], "note": "n",
    "policy_rule_ids": ["p.rule"], "state_rule_ids": ["s.rule"],
}
RANKING_SECTION = _section(
    _row("r1", "fail", [_rule("r1.rule", "fail")]),
    _row("r2", "fail", [_rule("p.rule", "pass"), _rule("s.rule", "fail", confidence="partial")]),
    _row("r3", "not_assessed", [_rule("u.rule", "not_assessed", reason="collector_not_complete:intune")], reason="rules_not_evaluated"),
    _row("r4", "not_assessed", requirement_status="manual", reason="requirement_status:manual"),
    _row("r5", "not_assessed", requirement_status="manual", reason="requirement_status:manual"),
)


def test_ranking_orders_by_score_then_effort_then_id() -> None:
    payload = build_practice_run(RANKING_SECTION, M365, _small_catalogue(RANKING_ACTIONS, [RANKING_CONFLICT]), as_of=AS_OF)

    assert [(row["evidence_state"], row["evidence_flags"]) for row in payload["requirements"]] == [
        ("gap_observed", []),
        ("gap_observed", ["conflicting"]),
        ("evidence_unknown", ["missing"]),
        ("outside_tenant_evidence", []),
        ("outside_tenant_evidence", []),
    ]
    assert [
        (row["rank"], row["action_id"], row["coverage_gained"], row["effort_weight"], row["rank_score"])
        for row in payload["next_actions"]
    ] == [
        (1, "a.fix_r1", 3, 1, 12),
        (2, "a.gather_outside", 2, 1, 8),
        (3, "a.fix_r2_state", 4, 2, 8),
        (4, "a.reconcile", 4, 2, 8),
        (5, "a.gather_r1", 5, 4, 5),
        (6, "a.test", 1, 1, 4),
        (7, "a.recollect", 2, 2, 4),
    ]
    reconcile = payload["next_actions"][3]
    assert reconcile["coverage"] == [{"requirement_id": "r2", "evidence_state": "gap_observed", "weight": 4}]
    assert reconcile["triggered_by"] == ["c1"]
    assert payload["next_actions"][6]["triggered_by"] == ["u.rule"]
    assert _by_id(payload)["r1"]["proof_still_needed"] == ["a.fix_r1", "a.gather_r1"]
    assert payload["summary"]["conflict_count"] == 1
    assert payload["summary"]["next_action_count"] == 7


def test_ranking_tie_break_is_effort_then_action_id() -> None:
    actions = [
        _action("b.zulu", "requirement_state", "quick", ["r4"], states=["outside_tenant_evidence"]),
        _action("b.beta", "requirement_state", "moderate", ["r4", "r5"], states=["outside_tenant_evidence"]),
        _action("b.alpha", "requirement_state", "quick", ["r5"], states=["outside_tenant_evidence"]),
    ]
    payload = build_practice_run(RANKING_SECTION, M365, _small_catalogue(actions), as_of=AS_OF)

    assert [(row["action_id"], row["rank_score"], row["effort_weight"]) for row in payload["next_actions"]] == [
        ("b.alpha", 4, 1),
        ("b.zulu", 4, 1),
        ("b.beta", 4, 2),
    ]


# -- 2. unknown is never absent ----------------------------------------------------------------------------------

PARTIAL = "ce.uac.mfa_cloud_services"
MANUAL = "ce.uac.account_approval"


@pytest.mark.parametrize(
    ("section", "state", "reasons"),
    [
        (_section(_clean(PARTIAL), _row(MANUAL, "not_assessed")), "evidence_observed_partial", []),
        (
            _section(
                _row(PARTIAL, "not_assessed", [_rule("ca.mfa_not_enforced", "pass"),
                                               _rule("identity.user_mfa_not_registered", "not_assessed",
                                                     reason="registration_report_incomplete:3")],
                     reason="rules_not_evaluated"),
                _row(MANUAL, "not_assessed"),
            ),
            "evidence_unknown",
            ["registration_report_incomplete:3"],
        ),
        (
            _section(_row(PARTIAL, "not_assessed", [], reason="partial_requirement_no_gap_found"), _row(MANUAL, "not_assessed")),
            "evidence_unknown",
            ["state_unreadable"],
        ),
        (_section(_row(MANUAL, "not_assessed")), "evidence_unknown", ["row_missing_or_malformed"]),
        (_section(None, _row(MANUAL, "not_assessed")), "evidence_unknown", ["row_missing_or_malformed"]),
        (
            _section({**_clean(PARTIAL), "requirement_status": None}, _row(MANUAL, "not_assessed")),
            "evidence_unknown",
            ["row_missing_or_malformed"],
        ),
        (None, "evidence_unknown", ["cyber_essentials_section_missing"]),
    ],
    ids=["a-clean", "b-not-evaluated", "c-empty-rules", "d-row-missing", "e-row-null", "e-status-null", "f-no-section"],
)
def test_unknown_is_never_read_as_observed_or_absent(section: Any, state: str, reasons: list[str]) -> None:
    payload = build_practice_run(section, M365, CATALOGUE, as_of=AS_OF)
    rows = _by_id(payload)

    assert (rows[PARTIAL]["evidence_state"], rows[PARTIAL]["unknown_reasons"]) == (state, reasons)
    assert ("missing" in rows[PARTIAL]["evidence_flags"]) is (state == "evidence_unknown")
    if section is not None and any(isinstance(row, dict) and row.get("control_id") == MANUAL for row in section["controls"]):
        assert rows[MANUAL]["evidence_state"] == "outside_tenant_evidence"


def test_a_rule_status_the_engine_never_writes_is_not_evaluated() -> None:
    row = _row(PARTIAL, "not_assessed", [{"rule_id": "ca.mfa_not_enforced", "status": "maybe", "evaluated": True}],
               reason="partial_requirement_no_gap_found")
    payload = build_practice_run(_section(row), M365, CATALOGUE, as_of=AS_OF)
    result = _by_id(payload)[PARTIAL]

    assert result["evidence_state"] == "evidence_unknown"
    assert result["evidence_observed"]["rule_states"] == [
        {"rule_id": "ca.mfa_not_enforced", "state": "not_evaluated", "confidence": "partial", "reason": "status_unreadable"}
    ]


def test_a_section_without_rows_reads_unknown_everywhere_and_validates() -> None:
    payload = build_practice_run(None, {}, CATALOGUE, as_of=None)

    jsonschema.validate(payload, SCHEMA)
    assert payload["summary"]["by_evidence_state"] == {
        "gap_observed": 0, "evidence_unknown": 30, "gap_accepted": 0, "supporting_only": 0,
        "evidence_observed_partial": 0, "outside_tenant_evidence": 0,
    }
    assert payload["run"] == {
        "run_id": None, "tenant_name": None, "platform": "m365", "evidence_collected_utc": None, "as_of": None,
        "evidence_age_days": None,
    }
    assert payload["next_actions"][0]["action_id"] == "ce.act.run.recollect_missing_evidence"
    assert payload["next_actions"][0]["coverage_gained"] == 60


# -- 3. flags -------------------------------------------------------------------------------------------------------


def test_stale_at_fifteen_days_and_not_at_fourteen() -> None:
    stale = build_practice_run(_full_section(), M365, CATALOGUE, as_of=date(2026, 11, 16))
    fresh = build_practice_run(_full_section(), M365, CATALOGUE, as_of=date(2026, 11, 15))

    assert stale["run"]["evidence_age_days"] == 15 and fresh["run"]["evidence_age_days"] == 14
    assert "stale" in stale["evidence_quality"]["flags"] and "stale" not in fresh["evidence_quality"]["flags"]
    assert "stale" in _by_id(stale)[PARTIAL]["evidence_flags"]
    assert "stale" not in _by_id(stale)[MANUAL]["evidence_flags"]
    assert "ce.act.run.recollect_stale_evidence" in [row["action_id"] for row in stale["next_actions"]]
    assert "ce.act.run.recollect_stale_evidence" not in [row["action_id"] for row in fresh["next_actions"]]


@pytest.mark.parametrize("created", [None, "", "yesterday", 20261101, "2026-13-45T00:00:00Z"])
def test_an_unreadable_evidence_date_gives_no_age(created: Any) -> None:
    manifest = {**M365, "created_utc": created}
    payload = build_practice_run(_full_section(), manifest, CATALOGUE, as_of=date(2027, 6, 1))

    assert payload["run"]["evidence_age_days"] is None
    assert payload["run"]["evidence_collected_utc"] is None
    assert "stale" not in payload["evidence_quality"]["flags"]


def test_age_needs_an_as_of_date_and_is_never_negative() -> None:
    assert evidence_age_days("2026-11-01T09:30:00Z", None) is None
    assert evidence_age_days("2026-11-01T09:30:00Z", date(2026, 10, 31)) is None
    assert evidence_age_days("2026-11-01T23:59:00Z", date(2026, 11, 1)) == 0


def test_a_truncated_list_flags_the_requirements_its_collector_feeds() -> None:
    manifest = {**M365, "coverage_gaps": [{"truncated_lists": [{"collector": "conditional_access", "list": "policies",
                                                              "reason": "result_limit"}]}]}
    section = _full_section(**{PARTIAL: _clean(PARTIAL, "ca.mfa_not_enforced")})
    coverage_rows = [{"collector": "auth_methods", "name": "userRegistrationDetails", "collection_truncated": True,
                      "truncation_reason": "result_limit", "status": "partial"}]
    payload = build_practice_run(section, manifest, CATALOGUE, as_of=AS_OF, coverage_rows=coverage_rows,
                                 collector_coverage={"identity": {"complete": True}, "intune": {"complete": False}})

    assert _by_id(payload)[PARTIAL]["evidence_flags"] == ["truncated"]
    assert _by_id(payload)["ce.uac.mfa_admin_accounts"]["evidence_flags"] == []
    assert payload["evidence_quality"] == {
        "flags": ["truncated"],
        "coverage_data": "available",
        "incomplete_collectors": ["intune"],
        "truncated_lists": [
            {"collector": "auth_methods", "list": "userRegistrationDetails", "reason": "result_limit"},
            {"collector": "conditional_access", "list": "policies", "reason": "result_limit"},
        ],
        "unmapped_requirement_ids": [],
    }


def test_no_coverage_data_is_stated() -> None:
    payload = build_practice_run(_full_section(), M365, CATALOGUE, as_of=AS_OF)
    assert payload["evidence_quality"]["coverage_data"] == "unavailable"


def _mfa_row(policy: str) -> dict[str, Any]:
    return _row(
        PARTIAL,
        "fail",
        [_rule("ca.mfa_not_enforced", policy, reason="collector_not_complete:conditional_access"),
         _rule("identity.user_mfa_not_registered", "fail", confidence="partial")],
    )


def test_a_conflict_holds_only_when_both_sides_were_evaluated() -> None:
    held = build_practice_run(_full_section(**{PARTIAL: _mfa_row("pass")}), M365, CATALOGUE, as_of=AS_OF)
    unknown = build_practice_run(_full_section(**{PARTIAL: _mfa_row("not_assessed")}), M365, CATALOGUE, as_of=AS_OF)

    assert _by_id(held)[PARTIAL]["conflicts"] == [
        {
            "conflict_id": "ce.conflict.mfa_policy_vs_registration_m365",
            "note": "The MFA policy shows no gap, yet users have no MFA method registered.",
        }
    ]
    assert _by_id(held)[PARTIAL]["evidence_flags"] == ["conflicting"]
    assert "ce.act.uac.reconcile_mfa_registration_m365" in [row["action_id"] for row in held["next_actions"]]
    assert _by_id(unknown)[PARTIAL]["conflicts"] == []
    assert _by_id(unknown)[PARTIAL]["evidence_flags"] == ["missing"]
    assert unknown["summary"]["conflict_count"] == 0


def test_a_version_mismatch_and_uncatalogued_rows_are_reported() -> None:
    section = _full_section()
    section["version"] = "v3.2"
    section["controls"].append(_clean("ce.retired.requirement"))
    payload = build_practice_run(section, M365, CATALOGUE, as_of=AS_OF)

    assert payload["evidence_quality"]["flags"] == ["requirements_version_mismatch"]
    assert payload["evidence_quality"]["unmapped_requirement_ids"] == ["ce.retired.requirement"]
    assert len(payload["requirements"]) == 30


# -- 4. both providers -----------------------------------------------------------------------------------------------


def _platform_of(action_id: str) -> str:
    return next(action["platforms"] for action in CATALOGUE["actions"] if action["id"] == action_id)[0]


def test_m365_administrator_outside_the_mfa_policy() -> None:
    section = _full_section(**{
        PARTIAL: _row(PARTIAL, "fail", [_rule("ca.mfa_not_enforced", "fail"), _rule("identity.user_mfa_not_registered", "pass", confidence="partial")]),
        "ce.uac.mfa_admin_accounts": _row("ce.uac.mfa_admin_accounts", "fail", [_rule("ca.admin_mfa_not_enforced", "fail")]),
    })
    payload = build_practice_run(section, M365, CATALOGUE, as_of=AS_OF)
    first = payload["next_actions"][0]

    assert (first["action_id"], first["coverage_gained"], first["rank_score"]) == ("ce.act.uac.resolve_mfa_gap_m365", 6, 24)
    assert {_platform_of(row["action_id"]) for row in payload["next_actions"]} == {"any", "m365"}
    test_4 = payload["assessor_tests"][3]
    assert test_4["witness_status"] == "assessor_witness_required"
    assert test_4["linked_evidence"] == [
        {"requirement_id": PARTIAL, "evidence_state": "gap_observed", "evidence_flags": []},
        {"requirement_id": "ce.uac.mfa_admin_accounts", "evidence_state": "gap_observed", "evidence_flags": []},
    ]
    assert "ce.act.plus.prepare_test_4_mfa" in [row["action_id"] for row in payload["next_actions"]]


def test_google_administrator_not_enrolled_under_an_enforced_policy() -> None:
    enforced = [_rule("google.user_2sv_not_enforced", "pass"), _rule("google.admin_2sv_not_enforced", "pass"),
                _rule("google.org_2sv_policy_not_enforced", "pass"), _rule("google.user_2sv_not_enrolled", "pass", confidence="partial"),
                _rule("google.admin_2sv_not_enrolled", "fail", confidence="partial")]
    section = _full_section(**{
        PARTIAL: _row(PARTIAL, "fail", enforced),
        "ce.uac.mfa_admin_accounts": _row("ce.uac.mfa_admin_accounts", "fail", [rule for rule in enforced if "user" not in rule["rule_id"]]),
        "ce.sc.saas_configuration": _row("ce.sc.saas_configuration", "not_assessed", reason="no_mapped_rules"),
    })
    payload = build_practice_run(section, GOOGLE, CATALOGUE, as_of=AS_OF)
    first = payload["next_actions"][0]

    assert (first["action_id"], first["coverage_gained"], first["rank_score"]) == ("ce.act.uac.resolve_2sv_enrolment_google", 7, 28)
    assert {_platform_of(row["action_id"]) for row in payload["next_actions"]} == {"any", "google_workspace"}
    assert _by_id(payload)["ce.uac.mfa_admin_accounts"]["conflicts"][0]["conflict_id"] == "ce.conflict.admin_2sv_policy_vs_enrolment_google"
    assert _by_id(payload)["ce.sc.saas_configuration"]["evidence_state"] == "supporting_only"
    assert payload["run"]["platform"] == "google_workspace"
    assert payload["assessor_tests"][3]["witness_status"] == "assessor_witness_required"
    assert "ce.act.plus.prepare_test_4_mfa" in [row["action_id"] for row in payload["next_actions"]]


def test_an_unknown_platform_gets_only_platform_neutral_actions() -> None:
    section = _full_section(**{PARTIAL: _row(PARTIAL, "fail", [_rule("ca.mfa_not_enforced", "fail")])})
    payload = build_practice_run(section, {**M365, "platform": "aws"}, CATALOGUE, as_of=AS_OF)

    assert payload["run"]["platform"] == "unknown"
    assert {_platform_of(row["action_id"]) for row in payload["next_actions"]} == {"any"}


def test_an_accepted_gap_is_shown_apart_from_an_observed_gap() -> None:
    section = _full_section(**{PARTIAL: _row(PARTIAL, "accepted_risk", [_rule("ca.mfa_not_enforced", "accepted_risk")])})
    payload = build_practice_run(section, M365, CATALOGUE, as_of=AS_OF)

    assert _by_id(payload)[PARTIAL]["evidence_state"] == "gap_accepted"
    assert _by_id(payload)[PARTIAL]["evidence_observed"]["rule_states"] == [
        {"rule_id": "ca.mfa_not_enforced", "state": "accepted_risk", "confidence": "full"}
    ]
    assert "ce.act.run.record_accepted_gap" in _by_id(payload)[PARTIAL]["proof_still_needed"]


# -- 7. determinism and no model code --------------------------------------------------------------------------------


def test_the_same_inputs_give_byte_identical_json() -> None:
    section = _full_section(**{PARTIAL: _mfa_row("pass")})
    first = json.dumps(build_practice_run(section, M365, load_catalogue(), as_of=AS_OF), indent=2)
    second = json.dumps(build_practice_run(copy.deepcopy(section), dict(M365), load_catalogue(), as_of=AS_OF), indent=2)
    assert first == second


def test_the_practice_run_imports_no_model_code() -> None:
    tree = ast.parse((ROOT / "src" / "auditex" / "ce_plus.py").read_text(encoding="utf-8"))
    modules = {
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in (node.names if isinstance(node, ast.Import) else [None])
        if (node.module if isinstance(node, ast.ImportFrom) else alias.name)
    }
    assert modules == {"__future__", "json", "collections.abc", "datetime", "typing",
                       "azure_tenant_audit.baselines", "azure_tenant_audit.collection_gaps", "azure_tenant_audit.resources"}


# -- 5. end to end through the CLI -------------------------------------------------------------------------------------

NCSC_URL = CATALOGUE["source"]["document_url"]
FORBIDDEN = re.compile(r"\bpass(ed|es|ing)?\b|certif|guarantee|\bcompliant\b|\bA\d\.\d+\b", re.IGNORECASE)


@pytest.fixture(scope="module")
def runs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    from auditex.google_workspace.run import run_google_offline
    from azure_tenant_audit.cli import run_offline

    root = tmp_path_factory.mktemp("ce-plus")
    assert run_offline(ROOT / "examples" / "sample_audit_bundle" / "sample_result.json", root, "ci", "m365") in (0, 1)
    assert run_google_offline(
        sample_path=ROOT / "examples" / "google_workspace_sample.json", out=root, tenant_name="acme", run_name="google",
        domain="example.com", customer_id=None,
    ) in (0, 1)
    return {"m365": root / "ci-m365", "google_workspace": root / "acme-google"}


def _tree(path: Path) -> dict[str, bytes]:
    return {str(item.relative_to(path)): item.read_bytes() for item in sorted(path.rglob("*")) if item.is_file()}


def _report(argv: list[str], capsys: pytest.CaptureFixture) -> tuple[int, str, str]:
    from auditex import cli as auditex_cli

    rc = auditex_cli.main(argv)
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _assert_clean_wording(text: str) -> None:
    assert FORBIDDEN.findall(text) == []
    assert "/Users/" not in text and "/Volumes/" not in text
    links = {link.replace("\\", "") for link in re.findall(r"https?://[^\s)<,|\"']+", text)}
    assert links <= {NCSC_URL}


@pytest.mark.parametrize("platform", ["m365", "google_workspace"])
@pytest.mark.parametrize("fmt", ["json", "md", "html"])
def test_cli_writes_the_practice_run(runs: dict[str, Path], tmp_path: Path, capsys: pytest.CaptureFixture,
                                     platform: str, fmt: str) -> None:
    run = runs[platform]
    before = _tree(run)
    argv = ["report", "ce-plus", str(run), "--format", fmt, "--as-of", "2026-11-30"]

    rc, printed, _ = _report(argv, capsys)
    target = tmp_path / f"ce-plus.{fmt}"
    rc_file, receipt, _ = _report([*argv, "--output", str(target)], capsys)

    assert (rc, rc_file) == (0, 0)
    assert json.loads(receipt)["output_path"] == str(target)
    assert target.read_text(encoding="utf-8") == printed
    assert _tree(run) == before
    assert str(run) not in printed
    _assert_clean_wording(printed)
    if fmt == "json":
        payload = json.loads(printed)
        jsonschema.validate(payload, SCHEMA)
        assert len(payload["requirements"]) == 30 and len(payload["assessor_tests"]) == 5
        assert payload["run"]["platform"] == platform
        assert payload["run"]["as_of"] == "2026-11-30"
        assert isinstance(payload["run"]["evidence_age_days"], int)
    elif fmt == "md":
        assert printed.startswith("# Auditex CE+ practice run\n")
        for heading in ("## Evidence quality", "## Next proof to gather", "## Requirements", "### Firewalls",
                        "## CE+ assessor tests", "## Ranking formula", "## Source"):
            assert "\n" + heading + "\n" in printed
    else:
        assert printed.startswith("<!doctype html>")
        assert "<h2>CE+ assessor tests</h2>" in printed and printed.rstrip().endswith("</body></html>")


def test_the_google_practice_run_ranks_the_enforcement_fix_first(runs: dict[str, Path], capsys: pytest.CaptureFixture) -> None:
    rc, printed, _ = _report(["report", "ce-plus", str(runs["google_workspace"]), "--as-of", "2026-11-30"], capsys)
    payload = json.loads(printed)

    assert rc == 0
    assert [row["action_id"] for row in payload["next_actions"][:3]] == [
        "ce.act.uac.resolve_2sv_enforcement_google",
        "ce.act.uac.resolve_2sv_enrolment_google",
        "ce.act.sc.resolve_stale_accounts_google",
    ]
    assert payload["summary"]["by_evidence_state"] == {
        "gap_observed": 7, "evidence_unknown": 0, "gap_accepted": 0, "supporting_only": 3,
        "evidence_observed_partial": 0, "outside_tenant_evidence": 20,
    }


def test_a_run_without_a_manifest_is_refused(runs: dict[str, Path], tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    run = tmp_path / "copy"
    shutil.copytree(runs["m365"], run)
    (run / "run-manifest.json").unlink()

    rc, printed, error = _report(["report", "ce-plus", str(run)], capsys)

    assert (rc, printed) == (2, "")
    assert error == "Refusing run-dir: unsafe input.\n"


def test_an_unparseable_manifest_is_refused(runs: dict[str, Path], tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    run = tmp_path / "copy"
    shutil.copytree(runs["m365"], run)
    (run / "run-manifest.json").write_text("{not json", encoding="utf-8")

    rc, printed, _ = _report(["report", "ce-plus", str(run)], capsys)

    assert (rc, printed) == (2, "")


def test_a_bad_as_of_date_is_a_usage_error(runs: dict[str, Path], capsys: pytest.CaptureFixture) -> None:
    from auditex import cli as auditex_cli

    with pytest.raises(SystemExit) as caught:
        auditex_cli.main(["report", "ce-plus", str(runs["m365"]), "--as-of", "30/11/2026"])
    assert caught.value.code == 2
    assert capsys.readouterr().out == ""


def test_an_older_bundle_without_the_section_reads_unknown(runs: dict[str, Path], tmp_path: Path,
                                                         capsys: pytest.CaptureFixture) -> None:
    run = tmp_path / "older"
    shutil.copytree(runs["m365"], run)
    pack_path = run / "reports" / "report-pack.json"
    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    del pack["baseline_alignment"]["frameworks"]["cyber_essentials"]
    pack_path.write_text(json.dumps(pack), encoding="utf-8")

    rc, printed, _ = _report(["report", "ce-plus", str(run), "--as-of", "2026-11-30"], capsys)
    payload = json.loads(printed)

    assert rc == 0
    jsonschema.validate(payload, SCHEMA)
    assert {row["evidence_state"] for row in payload["requirements"]} == {"evidence_unknown"}
    assert {tuple(row["unknown_reasons"]) for row in payload["requirements"]} == {("cyber_essentials_section_missing",)}
    assert payload["next_actions"][0]["action_id"] == "ce.act.run.recollect_missing_evidence"


def test_the_customer_pack_carries_the_practice_run_and_still_verifies(runs: dict[str, Path], tmp_path: Path,
                                                                     capsys: pytest.CaptureFixture) -> None:
    run = runs["google_workspace"]
    first, second = tmp_path / "pack-1", tmp_path / "pack-2"

    assert _report(["report", "customer-pack", str(run), "--output-dir", str(first)], capsys)[0] == 0
    assert _report(["report", "customer-pack", str(run), "--output-dir", str(second)], capsys)[0] == 0
    rc, verified, _ = _report(["report", "verify-pack", str(first)], capsys)

    assert rc == 0 and json.loads(verified)["valid"] is True
    manifest = json.loads((first / "pack-manifest.json").read_text(encoding="utf-8"))
    assert {"ce-plus-practice.md", "ce-plus-practice.json"} <= {row["path"] for row in manifest["generated_files"]}
    payload = json.loads((first / "ce-plus-practice.json").read_text(encoding="utf-8"))
    jsonschema.validate(payload, SCHEMA)
    assert (payload["run"]["as_of"], payload["run"]["evidence_age_days"]) == (None, None)
    markdown = (first / "ce-plus-practice.md").read_text(encoding="utf-8")
    assert "- Evidence age: age not established\n" in markdown
    _assert_clean_wording(markdown + json.dumps(payload))
    assert "ce-plus-practice.md" in (first / "README.md").read_text(encoding="utf-8")
    for name in ("ce-plus-practice.md", "ce-plus-practice.json"):
        assert (first / name).read_bytes() == (second / name).read_bytes()


# -- 6. forbidden wording in the catalogue ---------------------------------------------------------------------------


def test_the_shipped_catalogue_and_payload_text_carry_no_forbidden_claims() -> None:
    payload = build_practice_run(None, M365, CATALOGUE, as_of=AS_OF)
    texts = json.dumps(CATALOGUE) + json.dumps(payload)
    _assert_clean_wording(texts)
