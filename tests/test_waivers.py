from __future__ import annotations

import argparse
import json
import logging
from datetime import date, timedelta
from pathlib import Path

import pytest

from azure_tenant_audit.waivers import (
    WaiverFileError,
    accepted_risk_summary,
    apply_waivers,
    is_accepted_status,
    load_waivers,
    validate_waiver_rows,
    waiver_gaps,
    waiver_warnings,
)

FUTURE = (date.today() + timedelta(days=90)).isoformat()
PAST = (date.today() - timedelta(days=1)).isoformat()


def _finding(finding_id: str, **fields: object) -> dict:
    return {"id": finding_id, "severity": "critical", "status": "open", "collector": "identity", **fields}


def _waiver(**fields: object) -> dict:
    return {"owner": "ciso", "reason": "approved", "expires_on": FUTURE, **fields}


def _write(tmp_path: Path, payload: object, name: str = "waivers.json") -> Path:
    path = tmp_path / name
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return path


# ---- matching is an AND across every populated field ---------------------------------------------


def test_one_waiver_cannot_accept_an_unrelated_finding_from_the_same_collector() -> None:
    # The reproduced case: a waiver for finding A plus collector "identity" used to accept finding B.
    findings = [_finding("B", rule_id="identity.global_admin_mfa_not_registered")]

    result = apply_waivers(findings, [_waiver(finding_id="A", collector="identity")])

    assert result[0]["status"] == "open"
    assert "waiver_applied" not in result[0]


def test_a_rule_waiver_does_not_match_another_rule_through_a_shared_category_or_collector() -> None:
    findings = [_finding("f1", rule_id="r2", category="x")]

    result = apply_waivers(findings, [_waiver(rule_id="r1", category="x", collector="identity")])

    assert result[0]["status"] == "open"


def test_a_waiver_matches_only_when_every_populated_field_matches() -> None:
    findings = [
        _finding("f1", rule_id="r1", category="identity"),
        _finding("f2", rule_id="r1", category="mail"),
        _finding("f3", rule_id="r1", category="identity", collector="exchange"),
    ]

    result = apply_waivers(findings, [_waiver(rule_id="r1", category="identity", collector="identity")])

    assert [row["status"] for row in result] == ["accepted_risk", "open", "open"]
    assert result[0]["waiver_applied"] is True
    assert result[0]["waiver"]["matched_fields"] == ["rule_id", "collector", "category"]


def test_a_finding_id_waiver_accepts_exactly_that_finding() -> None:
    findings = [_finding("f1", rule_id="r1"), _finding("f2", rule_id="r1")]

    result = apply_waivers(findings, [_waiver(finding_id="f2")])

    assert [row["status"] for row in result] == ["open", "accepted_risk"]
    assert result[1]["waiver"]["matched_fields"] == ["finding_id"]


@pytest.mark.parametrize("fields", [{"collector": "identity"}, {"category": "x"}, {"collector": "identity", "category": "x"}, {}])
def test_a_waiver_without_finding_id_or_rule_id_never_matches(fields: dict) -> None:
    findings = [_finding("f1", rule_id="r1", category="x")]

    result = apply_waivers(findings, [_waiver(**fields)])

    assert result[0]["status"] == "open"


def test_blank_match_fields_do_not_count_as_populated() -> None:
    findings = [_finding("f1", rule_id="r1")]

    assert apply_waivers(findings, [_waiver(rule_id="r1", collector="  ", category="")])[0]["status"] == "accepted_risk"
    assert apply_waivers(findings, [_waiver(rule_id="  ", collector="identity")])[0]["status"] == "open"


def test_the_most_specific_matching_waiver_is_recorded() -> None:
    findings = [_finding("f1", rule_id="r1")]
    waivers = [_waiver(rule_id="r1", owner="team"), _waiver(finding_id="f1", rule_id="r1", owner="named")]

    assert apply_waivers(findings, waivers)[0]["waiver"]["owner"] == "named"


def test_an_expired_waiver_does_not_match_but_a_valid_one_for_the_same_finding_does() -> None:
    findings = [_finding("f1", rule_id="r1")]

    assert apply_waivers(findings, [_waiver(rule_id="r1", expires_on=PAST)])[0]["status"] == "open"
    both = apply_waivers(findings, [_waiver(rule_id="r1", expires_on=PAST, owner="old"), _waiver(rule_id="r1")])
    assert both[0]["status"] == "accepted_risk"
    assert both[0]["waiver"]["owner"] == "ciso"


def test_a_waiver_that_expires_today_still_matches() -> None:
    findings = [_finding("f1", rule_id="r1")]

    assert apply_waivers(findings, [_waiver(rule_id="r1", expires_on=date.today().isoformat())])[0]["status"] == "accepted_risk"


def test_applying_waivers_does_not_mutate_the_input_findings() -> None:
    findings = [_finding("f1", rule_id="r1")]

    apply_waivers(findings, [_waiver(rule_id="r1")])

    assert findings[0]["status"] == "open"


# ---- missing owner, reason or expiry warns -------------------------------------------------------------


def test_waiver_gaps_names_each_missing_accountability_field() -> None:
    assert waiver_gaps({"rule_id": "r1"}) == ["owner", "reason", "expires_on"]
    assert waiver_gaps({"rule_id": "r1", "owner": "a", "reason": "b", "expires_on": FUTURE}) == []
    assert waiver_gaps({"owner": "a", "comment": "legacy comment", "expires": FUTURE}) == []
    assert waiver_gaps({"owner": " ", "reason": "b", "expires_on": FUTURE}) == ["owner"]
    assert waiver_gaps(None) == ["owner", "reason", "expires_on"]


def test_load_waivers_warns_on_stderr_for_missing_owner_reason_and_expiry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path, {"waivers": [{"rule_id": "r1"}, _waiver(finding_id="f2")]})

    rows = load_waivers(path)

    assert [row.get("rule_id") or row.get("finding_id") for row in rows] == ["r1", "f2"]
    captured = capsys.readouterr()
    assert captured.err.strip() == "warning: waiver #1 (rule_id=r1) has no owner, reason, expires_on"
    assert captured.out == ""


def test_load_waivers_warns_about_an_expired_waiver_and_can_be_silenced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path, [_waiver(rule_id="r1", expires_on=PAST)])

    load_waivers(path)
    assert f"expired on {PAST} and will not match any finding" in capsys.readouterr().err
    load_waivers(path, warn=False)
    assert capsys.readouterr().err == ""


def test_waiver_warnings_are_available_without_printing() -> None:
    rows = [{"rule_id": "r1", "owner": "a"}]

    assert waiver_warnings(rows) == ["waiver #1 (rule_id=r1) has no reason, expires_on"]


def test_an_applied_waiver_records_what_it_lacks() -> None:
    result = apply_waivers([_finding("f1", rule_id="r1")], [{"rule_id": "r1"}])

    assert result[0]["status"] == "accepted_risk"
    assert result[0]["waiver"]["missing_fields"] == ["owner", "reason", "expires_on"]


def test_accepted_risk_summary_counts_and_lists_missing_accountability() -> None:
    findings = apply_waivers(
        [_finding("f1", rule_id="r1"), _finding("f2", rule_id="r2"), _finding("f3", rule_id="r3")],
        [{"rule_id": "r1"}, _waiver(rule_id="r2")],
    )

    summary = accepted_risk_summary(findings)

    assert summary["count"] == 2
    assert summary["without_owner_count"] == 1
    assert summary["without_reason_count"] == 1
    assert summary["without_expiry_count"] == 1
    assert summary["warnings"] == ["accepted risk f1 has no owner, reason, expires_on"]
    by_id = {row["id"]: row for row in summary["accepted_risks"]}
    assert by_id["f2"]["owner"] == "ciso" and by_id["f2"]["reason"] == "approved" and by_id["f2"]["missing_fields"] == []


def test_accepted_risk_summary_flags_a_status_with_no_waiver_record() -> None:
    summary = accepted_risk_summary([_finding("f1", status="accepted_risk")])

    assert summary["warnings"] == ["accepted risk f1 has no owner, reason, expires_on"]


def test_accepted_statuses_are_recognised_consistently() -> None:
    assert all(is_accepted_status(status) for status in ("accepted_risk", "Accepted", " waived "))
    assert not any(is_accepted_status(status) for status in ("open", "resolved", "", None))


# ---- a configured waiver file that cannot be trusted is a hard error -----------------------------------


def test_no_configured_waiver_file_means_no_waivers() -> None:
    assert load_waivers(None) == []


def test_a_missing_waiver_file_is_a_hard_error(tmp_path: Path) -> None:
    with pytest.raises(WaiverFileError, match="waiver file not found"):
        load_waivers(tmp_path / "typo.json")


@pytest.mark.parametrize("content", ["", "not json", "{broken"])
def test_an_unreadable_waiver_file_is_a_hard_error(tmp_path: Path, content: str) -> None:
    with pytest.raises(WaiverFileError, match="unreadable or not valid JSON"):
        load_waivers(_write(tmp_path, content))


@pytest.mark.parametrize("payload", [{"other": []}, {"waivers": "r1"}, "text", 3, None])
def test_a_waiver_file_of_the_wrong_shape_is_a_hard_error(tmp_path: Path, payload: object) -> None:
    with pytest.raises(WaiverFileError, match="JSON list or an object with a 'waivers' list"):
        load_waivers(_write(tmp_path, json.dumps(payload)))


def test_a_waiver_row_that_is_not_an_object_is_a_hard_error(tmp_path: Path) -> None:
    with pytest.raises(WaiverFileError, match=r"waiver #2 is not a JSON object"):
        load_waivers(_write(tmp_path, [_waiver(rule_id="r1"), "r2"]))


def test_a_waiver_without_finding_id_or_rule_id_is_a_hard_error(tmp_path: Path) -> None:
    with pytest.raises(WaiverFileError, match=r"waiver #1: needs finding_id or rule_id"):
        load_waivers(_write(tmp_path, [_waiver(collector="identity")]))


def test_a_waiver_with_a_non_string_match_field_is_a_hard_error(tmp_path: Path) -> None:
    with pytest.raises(WaiverFileError, match=r"waiver #1: rule_id must be a string"):
        load_waivers(_write(tmp_path, [_waiver(rule_id=["r1", "r2"])]))


@pytest.mark.parametrize("field", ["expires_on", "expires"])
def test_an_unparseable_expiry_is_a_hard_error_not_a_waiver_that_never_expires(tmp_path: Path, field: str) -> None:
    with pytest.raises(WaiverFileError, match="is not an ISO date"):
        load_waivers(_write(tmp_path, [{"rule_id": "r1", field: "next year"}]))


def test_validation_reports_every_problem_at_once() -> None:
    errors = validate_waiver_rows(["x", {"collector": "identity"}, {"rule_id": "r1", "expires_on": "soon"}])

    assert len(errors) == 3


def test_a_valid_waiver_file_loads_as_a_list_or_an_object(tmp_path: Path) -> None:
    rows = [_waiver(rule_id="r1"), _waiver(finding_id="f2")]

    assert load_waivers(_write(tmp_path, rows, "list.json"), warn=False) == rows
    assert load_waivers(_write(tmp_path, {"waivers": rows}, "object.json"), warn=False) == rows
    assert load_waivers(_write(tmp_path, [], "empty.json"), warn=False) == []


# ---- the run fails before collecting when the waiver file cannot be trusted -----------------------------


def test_build_findings_raises_for_an_invalid_waiver_file(tmp_path: Path) -> None:
    from azure_tenant_audit.findings import build_findings

    with pytest.raises(WaiverFileError):
        build_findings([], waiver_file=tmp_path / "missing.json")


def test_a_live_run_refuses_an_invalid_waiver_file_before_any_tenant_call(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from azure_tenant_audit.cli import run_live

    bad = _write(tmp_path, [{"collector": "identity"}])
    args = argparse.Namespace(waiver_file=str(bad))  # nothing else is read before the check

    with caplog.at_level(logging.ERROR):
        rc = run_live(args)

    assert rc == 2
    assert "needs finding_id or rule_id" in caplog.text


def test_a_live_run_reads_the_waiver_file_once_and_applies_those_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The file is replaced with garbage while the tenant is being read. The run must still apply the
    # rows it validated at the start instead of re-reading the file and failing after collection.
    from azure_tenant_audit import cli
    from azure_tenant_audit.collectors.base import CollectorResult
    from azure_tenant_audit.findings import _finalize_finding

    waivers = _write(tmp_path, [{"rule_id": "x.rule"}])

    class _Collector:
        name = "identity"

        def run(self, _context: dict) -> CollectorResult:
            waivers.write_text("{ this is not json", encoding="utf-8")
            return CollectorResult(
                name=self.name, status="ok", item_count=1, message="ok", payload={"value": [{"id": "1"}]},
                coverage=[{"collector": "identity", "name": "users", "type": "graph", "status": "ok", "item_count": 1}],
            )

    class _Client:
        def __init__(self, auth, audit_event=None):
            self.audit_event = audit_event

    seen: dict[str, object] = {}

    def fake_build_findings(diagnostics, **kwargs):  # noqa: ANN001
        seen.update(kwargs)
        return [_finalize_finding(
            {"id": "identity:x", "rule_id": "x.rule", "severity": "low", "title": "T", "status": "open",
             "collector": "identity", "category": "identity"}
        )]

    args = cli.build_parser().parse_args(
        ["--tenant-name", "acme", "--tenant-id", "t-123", "--client-id", "app-id", "--client-secret", "secret",
         "--collectors", "identity", "--waiver-file", str(waivers), "--out", str(tmp_path / "out")]
    )
    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _Client(auth, audit_event=kwargs.get("audit_event")))
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _Collector()})
    monkeypatch.setattr(cli, "build_findings", fake_build_findings)
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)

    rc = cli.run_live(args)

    assert rc == 0
    assert "waiver_file" not in seen  # build_findings is not handed the path to read again
    run_dir = next((tmp_path / "out").glob("acme-*"))
    findings = json.loads((run_dir / "findings" / "findings.json").read_text(encoding="utf-8"))
    assert [(row["id"], row["status"]) for row in findings] == [("identity:x", "accepted_risk")]
    assert capsys.readouterr().err.count("warning: waiver #1") == 1
