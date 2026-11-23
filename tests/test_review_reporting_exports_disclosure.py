"""Deep-review lane reporting-exports-disclosure: SARIF/OSCAL, sections, CSV and report wording."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from auditex.reporting import preview_report, render_sarif
from azure_tenant_audit.output_redaction import ensure_pseudonym_key

TENANT_ID = "9a8b7c6d-1111-4222-8333-444455556666"
APP_ID = "11111111-2222-4333-8444-555555555555"
APP_FINDING = {
    "id": f"app_credentials:{APP_ID}:secret_expired",
    "rule_id": "app_credentials.secret_expired",
    "title": "Application secret is expired",
    "severity": "critical",
    "status": "open",
    "category": "application",
    "collector": "app_credentials",
    "affected_objects": [APP_ID],
    "evidence_refs": [
        {"artifact_path": "normalized/users.json", "artifact_kind": "normalized_section", "record_key": f"application_credentials:{APP_ID}"}
    ],
}


def _write_run(run_dir: Path, findings: list[dict[str, Any]], *, tenant_id: str | None = TENANT_ID,
               action_plan: list[dict[str, Any]] | None = None) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {"tenant_name": "acme", "run_id": f"run-{run_dir.name}", "overall_status": "ok"}
    if tenant_id:
        manifest["tenant_id"] = tenant_id
    (run_dir / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")
    for folder in ("reports", "findings", "normalized"):
        (run_dir / folder).mkdir(exist_ok=True)
    pack = {
        "summary": {"tenant_name": "acme", "overall_status": "ok", "finding_count": len(findings)},
        "findings": findings,
        "action_plan": action_plan if action_plan is not None else [],
    }
    (run_dir / "reports" / "report-pack.json").write_text(json.dumps(pack), encoding="utf-8")
    (run_dir / "findings" / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    (run_dir / "normalized" / "users.json").write_text(json.dumps({"kind": "users", "records": []}), encoding="utf-8")
    return run_dir


def _sarif_results(run_dir: Path, profile: str = "shareable") -> list[dict[str, Any]]:
    content = preview_report(run_dir=str(run_dir), format_name="sarif", profile=profile)["content"]
    return json.loads(content)["runs"][0]["results"]


def _oscal(run_dir: Path, profile: str = "shareable") -> dict[str, Any]:
    content = preview_report(run_dir=str(run_dir), format_name="oscal", profile=profile)["content"]
    return json.loads(content)["assessment-results"]["results"][0]


# R066 ---------------------------------------------------------------------------------------------------------------

EXPORT_KEY = "a-private-export-key-for-tests-only"


@pytest.fixture
def export_key(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("AUDITEX_EXPORT_FINGERPRINT_KEY", EXPORT_KEY)
    return EXPORT_KEY


def test_r066_shareable_sarif_fingerprints_are_stable_across_runs_of_one_tenant(tmp_path: Path, export_key: str) -> None:
    runs = [_write_run(tmp_path / name, [dict(APP_FINDING)]) for name in ("run-a", "run-b")]
    for run in runs:
        ensure_pseudonym_key(run)
    first, second = (_sarif_results(run)[0] for run in runs)
    assert first["fingerprints"] == second["fingerprints"]
    assert first["partialFingerprints"] == second["partialFingerprints"]
    # The stable values never carry the raw object id.
    assert APP_ID not in json.dumps(first["fingerprints"]) + json.dumps(first["partialFingerprints"])


def test_r066_shareable_oscal_uuids_are_stable_across_runs_of_one_tenant(tmp_path: Path, export_key: str) -> None:
    runs = [_write_run(tmp_path / name, [dict(APP_FINDING)]) for name in ("run-a", "run-b")]
    for run in runs:
        ensure_pseudonym_key(run)
    first, second = (_oscal(run) for run in runs)
    assert first["observations"][0]["uuid"] == second["observations"][0]["uuid"]
    assert first["findings"][0]["uuid"] == second["findings"][0]["uuid"]
    assert first["observations"][0]["subjects"][0]["subject-uuid"] == second["observations"][0]["subjects"][0]["subject-uuid"]


def test_r066_shareable_fingerprints_differ_between_tenants(tmp_path: Path, export_key: str) -> None:
    run_a = _write_run(tmp_path / "run-a", [dict(APP_FINDING)])
    run_b = _write_run(tmp_path / "run-b", [dict(APP_FINDING)], tenant_id="0f0e0d0c-aaaa-4bbb-8ccc-dddddddddddd")
    for run in (run_a, run_b):
        ensure_pseudonym_key(run)
    assert _sarif_results(run_a)[0]["fingerprints"] != _sarif_results(run_b)[0]["fingerprints"]


def test_r066_a_recipient_who_knows_the_tenant_id_cannot_test_a_guess(tmp_path: Path, export_key: str) -> None:
    import hashlib
    import hmac

    run = _write_run(tmp_path / "run-a", [dict(APP_FINDING)])
    ensure_pseudonym_key(run)
    result = _sarif_results(run)[0]
    guesses = {
        hmac.new(TENANT_ID.encode(), f"auditex|affected|{APP_ID}".encode(), hashlib.sha256).hexdigest(),
        hmac.new(TENANT_ID.encode(), f"auditex|affected|{TENANT_ID}|{APP_ID}".encode(), hashlib.sha256).hexdigest(),
        hashlib.sha256(APP_ID.encode()).hexdigest(),
    }
    assert result["partialFingerprints"]["affected"] not in guesses


def test_r066_without_the_export_key_shareable_ids_stay_per_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUDITEX_EXPORT_FINGERPRINT_KEY", raising=False)
    runs = [_write_run(tmp_path / name, [dict(APP_FINDING)]) for name in ("run-a", "run-b")]
    for run in runs:
        ensure_pseudonym_key(run)
    first, second = (_sarif_results(run)[0] for run in runs)
    assert first["fingerprints"] != second["fingerprints"]
    assert APP_ID not in json.dumps(first)


def test_r066_a_short_export_key_is_refused_without_echoing_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDITEX_EXPORT_FINGERPRINT_KEY", "short-key-9")
    run = _write_run(tmp_path / "run-a", [dict(APP_FINDING)])
    with pytest.raises(ValueError) as caught:
        _sarif_results(run)
    assert "short-key-9" not in str(caught.value)


def test_r066_local_sarif_fingerprint_is_unchanged(tmp_path: Path, export_key: str) -> None:
    run = _write_run(tmp_path / "run-a", [dict(APP_FINDING)])
    direct = render_sarif(findings=[dict(APP_FINDING)], summary={}, manifest={})["runs"][0]["results"][0]
    assert _sarif_results(run, profile="local")[0]["fingerprints"] == direct["fingerprints"]


GOOGLE_FINDING = {
    "id": "google.organization.two_step_not_enforced",
    "rule_id": "google.organization.two_step_not_enforced",
    "title": "2-Step Verification is not enforced",
    "severity": "high",
    "status": "open",
    "category": "identity",
    "collector": "google_workspace",
}


def _write_google_run(
    run_dir: Path, *, domain: str, customer_id: str | None, tenant_id: str | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> Path:
    _write_run(run_dir, findings if findings is not None else [dict(GOOGLE_FINDING)], tenant_id=tenant_id)
    manifest_path = run_dir / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.update({"platform": "google_workspace", "tenant_name": "Google Workspace", "workspace_domain": domain})
    if customer_id is not None:
        manifest["customer_id"] = customer_id
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    ensure_pseudonym_key(run_dir)
    return run_dir


def _export_ids(run: Path) -> tuple[str, str, str]:
    oscal = _oscal(run)
    return (
        _sarif_results(run)[0]["fingerprints"]["auditex/v1"],
        oscal["findings"][0]["uuid"],
        oscal["observations"][0]["uuid"],
    )


@pytest.mark.parametrize(
    ("customer_id", "tenant_id"),
    [(None, None), ("my_customer", None), ("unknown", None), (None, "Google Workspace"), ("n/a", "unknown")],
)
def test_r066_google_runs_without_a_customer_id_never_share_export_ids(
    tmp_path: Path, export_key: str, customer_id: str | None, tenant_id: str | None
) -> None:
    """A missing customer id, the my_customer alias or a placeholder (``unknown``, the tenant label) names no tenant:
    two such Google runs of different domains must not get the same SARIF fingerprint or OSCAL uuids, or one tenant's
    alerts would close the other's."""
    run_a = _write_google_run(tmp_path / "run-a", domain="alpha.example", customer_id=customer_id, tenant_id=tenant_id)
    run_b = _write_google_run(tmp_path / "run-b", domain="beta.example", customer_id=customer_id, tenant_id=tenant_id)
    first, second = _export_ids(run_a), _export_ids(run_b)
    assert all(left != right for left, right in zip(first, second, strict=True))


def test_r066_google_runs_of_one_customer_keep_their_export_ids(tmp_path: Path, export_key: str) -> None:
    run_a = _write_google_run(tmp_path / "run-a", domain="alpha.example", customer_id="C01abcd23")
    run_b = _write_google_run(tmp_path / "run-b", domain="alpha.example", customer_id="C01abcd23")
    other = _write_google_run(tmp_path / "run-c", domain="beta.example", customer_id="C09wxyz87")
    assert _export_ids(run_a) == _export_ids(run_b)
    assert all(left != right for left, right in zip(_export_ids(run_a), _export_ids(other), strict=True))


def test_r066_without_the_export_key_ids_of_an_identifier_free_finding_stay_per_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A finding whose id holds nothing to pseudonymise must not fall back to a fixed id in a shareable export."""
    monkeypatch.delenv("AUDITEX_EXPORT_FINGERPRINT_KEY", raising=False)
    run_a = _write_google_run(tmp_path / "run-a", domain="alpha.example", customer_id="C01abcd23")
    run_b = _write_google_run(tmp_path / "run-b", domain="beta.example", customer_id="C09wxyz87")
    first, second = _export_ids(run_a), _export_ids(run_b)
    assert all(left != right for left, right in zip(first, second, strict=True))
    assert _export_ids(run_a) == first  # per run, not per render


# R125 ---------------------------------------------------------------------------------------------------------------

def _waived(status: str, expires_on: str = "2999-01-01") -> dict[str, Any]:
    return {
        **APP_FINDING,
        "status": status,
        "waiver_applied": True,
        "waiver": {"finding_id": APP_FINDING["id"], "owner": "security", "reason": "Vendor app retired next month",
                   "expires_on": expires_on},
    }


@pytest.mark.parametrize("status", ["accepted_risk", "accepted", "waived"])
def test_r125_sarif_suppresses_accepted_findings(status: str) -> None:
    result = render_sarif(findings=[_waived(status)], summary={}, manifest={})["runs"][0]["results"][0]
    assert result["suppressions"] == [
        {"kind": "external", "status": "accepted", "justification": "Vendor app retired next month"}
    ]


def test_r125_sarif_keeps_an_expired_waiver_open() -> None:
    result = render_sarif(findings=[_waived("accepted_risk", expires_on="2000-01-01")], summary={}, manifest={})
    assert "suppressions" not in result["runs"][0]["results"][0]


@pytest.mark.parametrize("status", ["closed", "resolved"])
def test_r125_sarif_leaves_out_closed_findings(status: str) -> None:
    assert render_sarif(findings=[_waived(status)], summary={}, manifest={})["runs"][0]["results"] == []


@pytest.mark.parametrize("status", ["closed", "resolved", "accepted_risk", "waived"])
def test_r125_a_status_without_a_matching_waiver_stays_an_open_result(status: str) -> None:
    """As in the gate: a status no waiver stands behind is an edit, so the finding stays open."""
    unbacked = {**APP_FINDING, "status": status}
    other = {**_waived(status), "waiver": {"finding_id": "some_other_finding", "reason": "x", "expires_on": "2999-01-01"}}
    for finding in (unbacked, other):
        result = render_sarif(findings=[finding], summary={}, manifest={})["runs"][0]["results"]
        assert len(result) == 1 and "suppressions" not in result[0]


def test_r125_open_finding_has_no_suppression() -> None:
    result = render_sarif(findings=[dict(APP_FINDING)], summary={}, manifest={})["runs"][0]["results"][0]
    assert "suppressions" not in result


def test_r125_oscal_records_the_accepted_status(tmp_path: Path) -> None:
    from auditex.reporting import render_oscal

    finding = render_oscal(findings=[_waived("accepted_risk")], summary={}, manifest={})["assessment-results"]["results"][0]["findings"][0]
    props = {prop["name"]: prop["value"] for prop in finding["props"]}
    assert props["auditex.status"] == "accepted"
    lapsed = render_oscal(findings=[_waived("accepted_risk", expires_on="2000-01-01")], summary={}, manifest={})
    lapsed_props = {prop["name"]: prop["value"] for prop in lapsed["assessment-results"]["results"][0]["findings"][0]["props"]}
    assert lapsed_props["auditex.status"] == "open"
    assert "accepted risk" in finding["target"]["status"]["remarks"].lower()


def _mailbox_waived(waived_id: str) -> dict[str, Any]:
    return {
        **APP_FINDING,
        "id": "mailbox_forwarding:alice@contoso.com",
        "rule_id": "mailbox_forwarding.external",
        "affected_objects": ["alice@contoso.com"],
        "evidence_refs": [],
        "status": "accepted_risk",
        "waiver_applied": True,
        "waiver": {"finding_id": waived_id, "reason": "Approved forwarding", "expires_on": "2999-01-01"},
    }


def _shareable_disposition(run: Path) -> tuple[bool, str]:
    sarif = _sarif_results(run)
    props = {prop["name"]: prop["value"] for prop in _oscal(run)["findings"][0]["props"]}
    return (len(sarif) == 1 and "suppressions" not in sarif[0]), props["auditex.status"]


def test_r125_a_waiver_for_another_mailbox_stays_open_in_shareable_exports(tmp_path: Path) -> None:
    """Masking makes alice@ and bob@ of one domain the same id; the waiver match must use the real ids."""
    run = _write_run(tmp_path / "run-a", [_mailbox_waived("mailbox_forwarding:bob@contoso.com")])
    ensure_pseudonym_key(run)
    assert _shareable_disposition(run) == (True, "open")


def test_r125_a_matching_mailbox_waiver_is_accepted_in_shareable_exports(tmp_path: Path) -> None:
    run = _write_run(tmp_path / "run-a", [_mailbox_waived("mailbox_forwarding:alice@contoso.com")])
    ensure_pseudonym_key(run)
    assert _shareable_disposition(run) == (False, "accepted")


def _google_waived(reason: str) -> dict[str, Any]:
    return {
        **GOOGLE_FINDING,
        "status": "accepted_risk",
        "waiver_applied": True,
        "waiver": {"finding_id": GOOGLE_FINDING["id"], "reason": reason, "expires_on": "2999-01-01"},
    }


_CUSTOMER = "C01abcd23"
# A waiver reason may name the customer id in any spelling: bare, inside an underscore-delimited reference or a URL.
_REASON_SPELLINGS = {
    "bare": f"Accepted for customer {_CUSTOMER} until the rollout",
    "underscore": f"Approved under workspace_{_CUSTOMER}_rollout",
    "url": f"See https://admin.google.com/ac/{_CUSTOMER}/security?ref=waiver-7",
}


def _accepted_text(content: str, format_name: str) -> str:
    """The text a shareable export gives an accepted finding: SARIF's suppression justification or OSCAL's remark."""
    document = json.loads(content)
    if format_name == "sarif":
        (result,) = document["runs"][0]["results"]
        (suppression,) = result["suppressions"]
        assert suppression["status"] == "accepted"
        return suppression["justification"]
    (finding,) = document["assessment-results"]["results"][0]["findings"]
    assert {prop["name"]: prop["value"] for prop in finding["props"]}["auditex.status"] == "accepted"
    return finding["target"]["status"]["remarks"]


@pytest.mark.parametrize("spelling", sorted(_REASON_SPELLINGS))
@pytest.mark.parametrize("declared", [True, False], ids=["declared", "default-selection"])
@pytest.mark.parametrize("sections", [None, ["findings"]])
@pytest.mark.parametrize("format_name", ["sarif", "oscal"])
def test_r125_a_shareable_export_withholds_the_waiver_reason(
    tmp_path: Path, export_key: str, format_name: str, sections: list[str] | None, declared: bool, spelling: str
) -> None:
    """A shareable SARIF or OSCAL export never carries the operator's free-text waiver reason (it can name the
    customer id in any spelling, also when the run never declared it): the finding stays accepted and says the
    reason is withheld."""
    reason = _REASON_SPELLINGS[spelling]
    run = _write_google_run(
        tmp_path / "run-a", domain="alpha.example", customer_id=_CUSTOMER if declared else None,
        findings=[_google_waived(reason)],
    )
    content = preview_report(run_dir=str(run), format_name=format_name, profile="shareable", include_sections=sections)[
        "content"
    ]
    assert _CUSTOMER.lower() not in content.lower()
    text = _accepted_text(content, format_name)
    assert "withheld" in text
    assert "2999-01-01" in text  # the waiver's expiry date stays


@pytest.mark.parametrize("format_name", ["sarif", "oscal"])
def test_r125_a_local_export_keeps_the_waiver_reason(tmp_path: Path, format_name: str) -> None:
    reason = _REASON_SPELLINGS["underscore"]
    run = _write_google_run(tmp_path / "run-a", domain="alpha.example", customer_id=_CUSTOMER,
                            findings=[_google_waived(reason)])
    content = preview_report(run_dir=str(run), format_name=format_name, profile="local")["content"]
    assert reason in _accepted_text(content, format_name)


# R126 ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("argument", ["include_sections", "exclude_sections"])
def test_r126_unknown_section_names_are_refused_with_the_valid_list(tmp_path: Path, argument: str) -> None:
    from auditex.reporting import UnknownReportSectionError

    run = _write_run(tmp_path / "run-a", [dict(APP_FINDING)])
    with pytest.raises(UnknownReportSectionError) as caught:
        preview_report(run_dir=str(run), format_name="md", profile="local", **{argument: ["normalised"]})
    message = str(caught.value)
    assert "normalised" in message and "normalized" in message
    assert isinstance(caught.value, ValueError)


def test_r126_exporter_refuses_a_misspelt_exclusion(tmp_path: Path) -> None:
    from auditex.exporters import run_exporter
    from auditex.reporting import UnknownReportSectionError

    run = _write_run(tmp_path / "run-a", [dict(APP_FINDING)])
    with pytest.raises(UnknownReportSectionError):
        run_exporter(name="html", run_dir=str(run), exclude_sections=["normalised"], output_path=str(tmp_path / "x.html"))
    assert not (tmp_path / "x.html").exists()


def test_r126_known_section_names_still_work(tmp_path: Path) -> None:
    run = _write_run(tmp_path / "run-a", [dict(APP_FINDING)])
    preview = preview_report(run_dir=str(run), format_name="json", profile="local", exclude_sections=["normalized"])
    assert "normalized" not in preview["sections"]


def test_r126_section_registry_lists_every_report_section_in_order() -> None:
    from auditex.reporting import _SECTION_ORDER, load_section_registry

    assert [row["id"] for row in load_section_registry()] == list(_SECTION_ORDER)


# R129 ---------------------------------------------------------------------------------------------------------------

_GAP_ACTION = {"id": "coverage_gap:mail", "title": "Resolve mail coverage gap", "severity": "medium", "status": "open"}


def _csv_rows(run: Path, **kwargs: Any) -> list[list[str]]:
    import csv
    from io import StringIO

    content = preview_report(run_dir=str(run), format_name="csv", profile="local", **kwargs)["content"]
    return list(csv.reader(StringIO(content)))


def test_r129_zero_findings_csv_holds_no_action_plan_rows(tmp_path: Path) -> None:
    run = _write_run(tmp_path / "run-a", [], action_plan=[dict(_GAP_ACTION)])
    rows = _csv_rows(run)
    assert rows[0][0] == "id"
    assert rows[1:] == []


def test_r129_action_plan_fallback_is_marked(tmp_path: Path) -> None:
    run = _write_run(tmp_path / "run-a", [dict(APP_FINDING)], action_plan=[dict(_GAP_ACTION)])
    rows = _csv_rows(run, exclude_sections=["findings"])
    assert [row[0] for row in rows[1:]] == ["coverage_gap:mail", "row_source"]
    assert "action plan" in rows[-1][1].lower() and "not findings" in rows[-1][1].lower()
    assert len(rows[-1]) == len(rows[0])


def test_r129_finding_rows_carry_no_source_notice(tmp_path: Path) -> None:
    run = _write_run(tmp_path / "run-a", [dict(APP_FINDING)], action_plan=[dict(_GAP_ACTION)])
    assert [row[0] for row in _csv_rows(run)[1:]] == [APP_FINDING["id"]]


# L1, L2, L4 ---------------------------------------------------------------------------------------------------------

DISCLAIMER = (
    "This report is evidence from an automated, read-only audit run on the date shown. It is not a certificate, an "
    "assurance opinion or legal advice, and it covers only what the run could read. Coverage gaps are listed and are "
    "part of the result."
)


def test_l1_markdown_and_html_reports_carry_the_disclaimer(tmp_path: Path) -> None:
    run = _write_run(tmp_path / "run-a", [dict(APP_FINDING)])
    markdown = preview_report(run_dir=str(run), format_name="md", profile="local")["content"]
    assert DISCLAIMER in "\n".join(markdown.splitlines()[:6])
    page = preview_report(run_dir=str(run), format_name="html", profile="local")["content"]
    assert DISCLAIMER in page


def test_l1_customer_pack_readme_and_handoff_carry_the_disclaimer() -> None:
    from auditex.reporting import (
        _render_pack_readme,
        render_enterprise_handoff_markdown,
    )

    assert DISCLAIMER in _render_pack_readme({})
    assert DISCLAIMER in render_enterprise_handoff_markdown({})


def test_l1_l3_explorer_page_carries_the_disclaimer_and_run_checks_label() -> None:
    page = (Path(__file__).resolve().parents[1] / "src" / "auditex" / "explorer_assets" / "explorer.html").read_text(
        encoding="utf-8"
    )
    footer = page[page.index('<footer class="ax-footer">'):page.index("</footer>")]
    assert DISCLAIMER in footer
    assert 'aria-label="Run checks"' in page and "Run guarantees" not in page


def test_l2_pack_readme_does_not_call_the_report_client_ready() -> None:
    from auditex.reporting import _render_pack_readme

    readme = _render_pack_readme({})
    assert "client-ready" not in readme
    assert "Review `report.md` for the report and reviewer index." in readme


def test_l4_report_header_says_evidence_coverage_not_assurance(tmp_path: Path) -> None:
    run = _write_run(tmp_path / "run-a", [dict(APP_FINDING)])
    markdown = preview_report(run_dir=str(run), format_name="md", profile="local")["content"]
    assert "- Evidence coverage:" in markdown
    assert "- Assurance:" not in markdown


def test_r088_m365_content_capable_limitation_names_an_m365_scope() -> None:
    from auditex.reporting import _scope_risk_limitation

    m365 = json.dumps(_scope_risk_limitation(platform="m365", scope_risk="content_capable_scope_present", write_capable_scopes=[]))
    google = json.dumps(
        _scope_risk_limitation(platform="google_workspace", scope_risk="content_capable_scope_present", write_capable_scopes=[])
    )
    assert "Sites.Read.All" in m365 and "Drive readonly" not in m365
    assert "Drive readonly" in google
