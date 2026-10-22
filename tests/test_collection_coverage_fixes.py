"""Collection coverage fixes: resolver failures, event-log samples, paging, caps, declarations and fan-out totals (no network)."""
from __future__ import annotations

import ast
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit import exchange_protection
from azure_tenant_audit.adapters.m365_cli import M365CLIAdapter
from azure_tenant_audit.adapters.read_guard import check_command
from azure_tenant_audit.baselines import build_baseline_alignment, rule_inputs_gap
from azure_tenant_audit.collection_gaps import (
    BOUNDED_SAMPLE_SECTION,
    REASON_PAGINATION_NOT_FOLLOWED,
    TRUNCATION_REASONS,
    bounded_sample_gap,
    section_total,
)
from azure_tenant_audit.collector_runner import AuditWriterCollectorAdapter, CollectorRunContext, CollectorRunner
from azure_tenant_audit.collectors.base import run_graph_endpoints
from azure_tenant_audit.collectors.defender import DefenderCollector
from azure_tenant_audit.collectors.dns_posture import DnsPostureCollector
from azure_tenant_audit.collectors.ediscovery import EDiscoveryCollector
from azure_tenant_audit.collectors.exchange_policy import (
    FORWARDING_MAILBOX_LIMIT,
    MAILBOX_FORWARDING_COMMAND,
    ExchangePolicyCollector,
)
from azure_tenant_audit.collectors.intune_depth import IntuneDepthCollector
from azure_tenant_audit.collectors.onedrive_posture import OneDrivePostureCollector
from azure_tenant_audit.collectors.security import LOG_SAMPLE_LIMIT, SecurityCollector
from azure_tenant_audit.dns_lookup import DohClient, DohError, collect_domain_posture
from azure_tenant_audit.endpoint_posture import UPDATE_SECTION, UPDATE_SUMMARY_KIND
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot
from azure_tenant_audit.output import AuditWriter
from azure_tenant_audit.run import build_coverage_ledger

REPO = Path(__file__).resolve().parents[1]


# ---- shared helpers -----------------------------------------------------------------------------------------


def _pipeline(
    collector: str,
    result: Any,
    *,
    findings_from_snapshot: bool = True,
    run_dir: Path | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Normalize one collector's result, raise findings and evaluate every mapped rule the way a run would."""
    result_row = {"name": collector, "status": result.status, "item_count": result.item_count, "message": result.message}
    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads={collector: result.payload},
        coverage_rows=result.coverage,
        result_rows=[result_row],
        run_dir=run_dir,
    )
    findings = build_findings([], normalized_snapshot=snapshot) if findings_from_snapshot else []
    ledger = build_coverage_ledger(
        capability_rows=[{"collector": collector, "status": "supported_exact_scope"}], result_rows=[result_row], diagnostics=[]
    )
    alignment = build_baseline_alignment(findings, normalized_snapshot=snapshot, coverage_ledger=ledger)
    rules = {
        status["rule_id"]: status
        for framework in alignment["frameworks"].values()
        for control in framework["controls"]
        for status in control["rule_statuses"]
    }
    return snapshot, findings, rules


class _Resolver:
    def __init__(self, answers: dict[tuple[str, str], list[str]] | None = None, error: str | None = None) -> None:
        self.answers = answers or {}
        self.error = error

    def query(self, name: str, record_type: str) -> list[str]:
        if self.error:
            raise DohError(self.error)
        return list(self.answers.get((name, record_type), []))


class _GraphDomains:
    def __init__(self, domains: list[dict[str, Any]]) -> None:
        self.domains = domains

    def get_all(self, path: str, params: Any = None) -> list[dict[str, Any]]:
        assert path == "/domains"
        return list(self.domains)


class _Response:
    def __init__(self, payload: Any) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self.payload


class _Session:
    def __init__(self, payload: Any) -> None:
        self.payload = payload

    def get(self, *_args: Any, **_kwargs: Any) -> _Response:
        return _Response(self.payload)


# ---- #20 DNS: a resolver that did not answer is unknown, never "missing" -----------------------------------------


@pytest.mark.parametrize("status", [2, 5, 1, 4])
def test_a_resolver_failure_code_is_an_error_not_an_absent_record(status: int) -> None:
    client = DohClient(session=_Session({"Status": status, "Answer": []}))

    with pytest.raises(DohError):
        client.query("contoso.com", "TXT")


@pytest.mark.parametrize("payload", [{"Status": 3}, {"Status": 3, "Answer": []}, {"Status": 0}, {"Status": 0, "Answer": []}])
def test_nxdomain_and_noerror_without_an_answer_are_absent_records(payload: dict[str, Any]) -> None:
    assert DohClient(session=_Session(payload)).query("contoso.com", "TXT") == []


def test_servfail_makes_the_domain_unknown_and_raises_no_missing_record_finding() -> None:
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": False, "authenticationType": "Managed"}]
    resolver = DohClient(session=_Session({"Status": 2, "Answer": []}))
    result = DnsPostureCollector().run({"client": _GraphDomains(domains), "top": 500, "dns_resolver": resolver})

    record = result.payload["domainPosture"]["value"][0]
    assert record["resolver_error"] and record["spf"]["present"] is None and record["dmarc"]["present"] is None
    assert record["dkim"]["selectors_missing"] == [] and record["dkim"]["selectors_unresolved"]
    # The collector says so: partial, with the resolver error on the coverage row (the run's diagnostic).
    assert result.status == "partial"
    assert any(row.get("error_class") == "dns_resolver_error" and row["status"] == "failed" for row in result.coverage)

    snapshot, findings, rules = _pipeline("dns_posture", result)
    normalized = snapshot["dns_posture_objects"]["records"][0]
    # Unknown, not False: the keys are left out of the compact record rather than written as "not present".
    assert normalized["resolver_error"] and "spf_present" not in normalized and "dmarc_present" not in normalized
    assert not [item for item in findings if item["rule_id"].startswith("dns_posture.")]
    # The collector is partial (the coverage row failed with dns_resolver_error), so the rules say so; the record-level
    # reason is what an offline bundle with a complete collector and a resolver_error record reads.
    for rule in ("dns_posture.spf_missing", "dns_posture.dmarc_missing", "dns_posture.dkim_missing"):
        assert rules[rule]["status"] == "not_assessed" and rules[rule]["reason"] == "collector_not_complete:dns_posture"
        complete = build_baseline_alignment(
            findings,
            normalized_snapshot=snapshot,
            coverage_ledger=[{"collector": "dns_posture", "coverage_status": "complete_exact_scope"}],
        )
        statuses = {
            status["rule_id"]: status
            for framework in complete["frameworks"].values()
            for control in framework["controls"]
            for status in control["rule_statuses"]
        }
        assert statuses[rule]["status"] == "not_assessed" and statuses[rule]["reason"] == "resolver_error"


def test_a_resolver_error_does_not_mute_the_exchange_dkim_rule() -> None:
    errored = {"domain": "contoso.com", "managed_by_microsoft": False, "resolver_error": "SERVFAIL", "dkim_selectors_present": []}
    answered = {"domain": "fabrikam.com", "managed_by_microsoft": False, "resolver_error": None, "dkim_selectors_present": []}

    assert exchange_protection.dns_reports_dkim_missing(errored) is False
    assert exchange_protection.dns_reports_dkim_missing(answered) is True
    snapshot = {"dns_posture_objects": {"records": [errored, answered]}}
    assert exchange_protection.dns_dkim_domains(snapshot) == {"fabrikam.com"}


def test_collect_domain_posture_keeps_a_real_absence_distinct_from_an_error() -> None:
    absent = collect_domain_posture("contoso.com", _Resolver())
    errored = collect_domain_posture("contoso.com", _Resolver(error="SERVFAIL"))

    assert absent["resolver_error"] is None and absent["spf"]["present"] is False
    assert errored["resolver_error"] and errored["spf"]["present"] is None


def test_google_dns_posture_skips_a_domain_the_resolver_did_not_answer_for() -> None:
    from auditex.google_workspace.findings import build_google_findings

    record = {
        "kind": "google_domain_posture",
        "source": "google_dns_posture.domainPosture",
        "id": "example.com",
        "key": "google_domain_posture:example.com",
        "domain": "example.com",
        "resolver_error": "SERVFAIL",
        "spf": {"present": None},
        "dmarc": {"present": None},
        "dkim": {"selectors_present": [], "selectors_missing": [], "selectors_unresolved": ["google"]},
    }
    snapshot = {"snapshot": {}, "google_dns_posture": {"kind": "google_dns_posture", "records": [record]}}
    findings = build_google_findings(snapshot)

    assert not [item for item in findings if str(item.get("rule_id", "")).startswith("google.dns_")]


# ---- #22 event-log samples: a cut sample is not a pass ----------------------------------------------------------


class _LogClient:
    """Graph double that serves sign-in and directory audit logs, newest first, from synthetic rows."""

    def __init__(self, signins: int, audits: int, *, risky_at: int | None = None) -> None:
        self.signins = signins
        self.audits = audits
        self.risky_at = risky_at

    def _rows(self, path: str) -> list[dict[str, Any]]:
        if path == "/auditLogs/signIns":
            return [
                {
                    "id": f"s-{index}",
                    "createdDateTime": f"2026-10-21T{index // 3600 % 24:02d}:{index // 60 % 60:02d}:{index % 60:02d}Z",
                    "userPrincipalName": f"user{index}@example.com",
                    "riskLevelAggregated": "high" if index == self.risky_at else "none",
                    "riskState": "atRisk" if index == self.risky_at else "none",
                }
                for index in range(self.signins)
            ]
        return [
            {"id": f"a-{index}", "activityDateTime": f"2026-10-20T00:{index // 60 % 60:02d}:{index % 60:02d}Z", "activityDisplayName": "Update user", "category": "UserManagement", "result": "success"}
            for index in range(self.audits)
        ]

    def iter_items(self, path: str, params: Any = None, *, result_limit: int | None = None):  # noqa: ANN001
        for index, row in enumerate(self._rows(path)):
            if result_limit is not None and index >= result_limit:
                return
            yield row

    def get_all(self, path: str, params: Any = None) -> list[dict[str, Any]]:
        return list(self.iter_items(path, params))


def _security(signins: int, audits: int, *, risky_at: int | None = None, top: int | None = None) -> Any:
    return SecurityCollector().run({"client": _LogClient(signins, audits, risky_at=risky_at), "top": top, "audit_logger": None})


def test_a_cut_sign_in_sample_is_recorded_and_the_rules_that_read_it_are_not_assessed() -> None:
    result = _security(5000, 400, risky_at=900)

    row = next(item for item in result.coverage if item["name"] == "signIns")
    assert row["bounded_sample"] is True and row["item_count"] == LOG_SAMPLE_LIMIT
    assert result.payload["signIns"]["bounded_sample"] is True
    audits = next(item for item in result.coverage if item["name"] == "directoryAudits")
    assert "bounded_sample" not in audits and "bounded_sample" not in result.payload["directoryAudits"]

    snapshot, findings, rules = _pipeline("security", result)
    record = snapshot[BOUNDED_SAMPLE_SECTION]["records"][0]
    assert (record["collector"], record["list"], record["rows_collected"], record["sample_limit"]) == ("security", "signIns", 500, 500)
    assert record["oldest"] <= record["newest"]
    # The risky sign-in at row 900 was beyond the sample; nothing was found, and "nothing" is not a pass.
    assert not [item for item in findings if item["rule_id"] == "security.risky_signin"]
    assert rules["security.risky_signin"]["status"] == "not_assessed"
    assert rules["security.risky_signin"]["reason"] == "bounded_sample:security.signIns"
    assert rule_inputs_gap("security.risky_signin", snapshot) == "bounded_sample:security.signIns"
    # The directory audit log was read whole (400 rows, no cut): its rule can still pass.
    assert rules["security.privilege_change_event"]["status"] == "pass"


def test_both_event_logs_cut_at_the_bound_read_not_assessed() -> None:
    result = _security(700, 900)
    _snapshot, _findings, rules = _pipeline("security", result)

    assert rules["security.risky_signin"]["reason"] == "bounded_sample:security.signIns"
    assert rules["security.privilege_change_event"]["reason"] == "bounded_sample:security.directoryAudits"


def test_a_finding_raised_from_the_sample_still_fails_the_rule() -> None:
    result = _security(5000, 400, risky_at=100)
    _snapshot, findings, rules = _pipeline("security", result)

    assert [item for item in findings if item["rule_id"] == "security.risky_signin"]
    assert rules["security.risky_signin"]["status"] == "fail"


def test_a_log_read_whole_is_not_a_bounded_sample_and_can_pass() -> None:
    result = _security(400, 300)
    snapshot, _findings, rules = _pipeline("security", result)

    assert BOUNDED_SAMPLE_SECTION not in snapshot
    assert rules["security.risky_signin"]["status"] == "pass"


def test_an_offline_section_marked_as_a_bounded_sample_is_not_assessed_without_a_coverage_row() -> None:
    payloads = {"security": {"signIns": {"value": [{"id": "s-1", "createdDateTime": "2026-10-21T10:00:00Z"}], "bounded_sample": True, "result_limit": 500, "item_count": 1}}}
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="run-1", collector_payloads=payloads, coverage_rows=[], result_rows=[])

    assert bounded_sample_gap("security.risky_signin", snapshot) == "bounded_sample:security.signIns"
    assert bounded_sample_gap("security.privilege_change_event", snapshot) is None
    assert bounded_sample_gap("identity.stale_enabled_account", snapshot) is None
    assert bounded_sample_gap("security.risky_signin", None) is None


def test_a_streamed_sign_in_sample_is_bounded_and_normalised_from_its_chunks(tmp_path: Path) -> None:
    class _PagedLogs(_LogClient):
        def iter_pages(self, path: str, params: Any = None):  # noqa: ANN001
            rows = self._rows(path)
            for start in range(0, len(rows), 200):
                page: dict[str, Any] = {"value": rows[start : start + 200]}
                if start + 200 < len(rows):
                    page["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/next"
                yield page

    writer = AuditWriter(tmp_path, tenant_name="acme", run_name="logs")
    adapter = AuditWriterCollectorAdapter(writer)
    output = CollectorRunner(adapter).run(
        SecurityCollector(), CollectorRunContext(client=_PagedLogs(5000, 900, risky_at=900), top=None, hooks=adapter.hooks())
    )

    row = next(item for item in output.coverage_rows if item["name"] == "signIns")
    assert row["bounded_sample"] is True and row["item_count"] == LOG_SAMPLE_LIMIT
    assert output.result.payload["signIns"]["bounded_sample"] is True and output.result.payload["signIns"]["chunk_files"]
    snapshot, _findings, rules = _pipeline("security", output.result, run_dir=writer.run_dir)
    record = snapshot[BOUNDED_SAMPLE_SECTION]["records"][0]
    assert record["rows_collected"] == LOG_SAMPLE_LIMIT and record["oldest"] < record["newest"]
    assert rules["security.risky_signin"]["reason"] == "bounded_sample:security.signIns"


def test_an_operator_limit_below_the_sample_is_still_a_coverage_gap_not_a_sample() -> None:
    result = _security(5000, 400, top=50)

    row = next(item for item in result.coverage if item["name"] == "signIns")
    assert row["collection_truncated"] is True and "bounded_sample" not in row and result.status == "partial"


# ---- #23 mailbox forwarding: server-side filter, and a cap that is a gap -----------------------------------------


def test_the_mailbox_forwarding_command_filters_on_the_server_and_passes_the_read_guard() -> None:
    assert check_command("powershell_graph", MAILBOX_FORWARDING_COMMAND) == ("Get-EXOMailbox", "Select-Object")
    assert "ForwardingAddress" in MAILBOX_FORWARDING_COMMAND and "-Filter '" in MAILBOX_FORWARDING_COMMAND
    assert f"-ResultSize {FORWARDING_MAILBOX_LIMIT + 1}" in MAILBOX_FORWARDING_COMMAND
    assert "-Properties" in MAILBOX_FORWARDING_COMMAND
    definitions = json.loads((REPO / "configs" / "collector-definitions.json").read_text(encoding="utf-8"))["collectors"]
    shipped = [
        command
        for entry in definitions["exchange_policy"]["command_collectors"]
        if entry["name"] == "mailboxForwarding"
        for command in entry["commands"]
    ]
    assert shipped == [MAILBOX_FORWARDING_COMMAND]


class _ExchangeAdapter:
    def __init__(self, forwarding_rows: int) -> None:
        self.forwarding_rows = forwarding_rows

    def run(self, command: str, log_event: Any = None, session: Any = None) -> dict[str, Any]:  # noqa: ANN401
        if command == MAILBOX_FORWARDING_COMMAND:
            rows = [
                {"DisplayName": f"Mailbox {index}", "PrimarySmtpAddress": f"m{index}@example.com", "ForwardingSmtpAddress": f"smtp:x{index}@example.net"}
                for index in range(self.forwarding_rows)
            ]
            return {"value": rows}
        return {"value": []}


def _exchange_policy(monkeypatch: pytest.MonkeyPatch, forwarding_rows: int) -> Any:
    monkeypatch.setattr("azure_tenant_audit.collectors.exchange_policy.get_adapter", lambda _name: _ExchangeAdapter(forwarding_rows))
    return ExchangePolicyCollector().run({"client": None, "audit_logger": None})


def test_more_forwarding_mailboxes_than_the_bound_is_a_gap_and_the_rule_is_not_assessed(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _exchange_policy(monkeypatch, FORWARDING_MAILBOX_LIMIT + 1)

    row = next(item for item in result.coverage if item["name"] == "mailboxForwarding")
    assert row["status"] == "partial" and row["collection_truncated"] is True and row["truncation_reason"] == "fanout_limit"
    assert row["item_count"] == FORWARDING_MAILBOX_LIMIT and row["result_limit"] == FORWARDING_MAILBOX_LIMIT
    assert len(result.payload["mailboxForwarding"]["value"]) == FORWARDING_MAILBOX_LIMIT
    assert result.status == "partial"

    snapshot, findings, rules = _pipeline("exchange_policy", result, findings_from_snapshot=False)
    assert [(item["collector"], item["list"], item["reason"]) for item in snapshot["collection_gaps"]["records"]] == [
        ("exchange_policy", "mailboxForwarding", "fanout_limit")
    ]
    assert rules["exchange.mailbox_forwarding_configured"]["status"] == "not_assessed"
    assert rules["exchange.mailbox_forwarding_configured"]["reason"].startswith("collector_not_complete")


def test_forwarding_mailboxes_within_the_bound_are_a_clean_read(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _exchange_policy(monkeypatch, 3)

    row = next(item for item in result.coverage if item["name"] == "mailboxForwarding")
    assert row["status"] == "ok" and "collection_truncated" not in row and row["item_count"] == 3
    snapshot, _findings, _rules = _pipeline("exchange_policy", result, findings_from_snapshot=False)
    assert "collection_gaps" not in snapshot


def test_a_forwarding_contact_address_is_normalised() -> None:
    payload = {"exchange_policy": {"mailboxForwarding": {"value": [{"DisplayName": "A", "PrimarySmtpAddress": "a@example.com", "ForwardingAddress": "Contact B"}]}}}
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="r", collector_payloads=payload, coverage_rows=[], result_rows=[])

    (record,) = [row for row in snapshot["exchange_policy_objects"]["records"] if row["source_name"] == "mailboxForwarding"]
    assert record["forwarding_address"] == "Contact B" and "forwarding_smtp_address" not in record


# ---- #24 every list read is paged; a dropped next link is a gap ----------------------------------------------------


class _OnePageClient:
    def __init__(self, response: Any) -> None:
        self.response = response

    def get_json(self, path: str, params: Any = None, full_url: bool = False) -> Any:  # noqa: ANN401
        return self.response


def test_an_unpaged_read_that_drops_a_next_link_is_a_truncated_list() -> None:
    client = _OnePageClient({"value": [{"id": str(index)} for index in range(200)], "@odata.nextLink": "https://graph.microsoft.com/v1.0/x?$skiptoken=1"})
    payload, coverage = run_graph_endpoints("defender", client, {"profiles": {"endpoint": "/x", "page": False}}, top=None)

    (row,) = coverage
    assert row["status"] == "partial" and row["collection_truncated"] is True
    assert row["truncation_reason"] == REASON_PAGINATION_NOT_FOLLOWED == "pagination_not_followed"
    assert row["error_class"] == "collection_limit" and "next-page link" in row["error"]
    assert payload["profiles"]["collection_truncated"] is True and payload["profiles"]["truncation_reason"] == "pagination_not_followed"
    assert len(payload["profiles"]["value"]) == 200
    assert REASON_PAGINATION_NOT_FOLLOWED in TRUNCATION_REASONS


def test_an_unpaged_singleton_without_a_next_link_is_a_clean_read() -> None:
    payload, coverage = run_graph_endpoints("x", _OnePageClient({"id": "policy", "state": "on"}), {"policy": {"endpoint": "/p", "page": False}}, top=None)

    assert coverage[0]["status"] == "ok" and coverage[0]["collection_truncated"] is None and "collection_truncated" not in payload["policy"]


class _PagedDefenderClient:
    """Graph double: secureScoreControlProfiles answers 200 rows per page with a next link, like the live tenant."""

    def __init__(self, profiles: int) -> None:
        self.profiles = profiles
        self.paths: list[str] = []

    def iter_pages(self, path: str, params: Any = None):  # noqa: ANN001
        self.paths.append(path)
        rows: list[dict[str, Any]]
        if path == "/security/secureScoreControlProfiles":
            rows = [{"id": f"Profile_{index:04d}", "maxScore": 1} for index in range(self.profiles)]
        elif path == "/security/secureScores":
            rows = [{"id": f"score-{index}", "currentScore": 1, "maxScore": 10} for index in range(90)]
        else:
            rows = []
        for start in range(0, max(len(rows), 1), 200):
            page: dict[str, Any] = {"value": rows[start : start + 200]}
            if start + 200 < len(rows):
                page["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/next"
            yield page

    def iter_items(self, path: str, params: Any = None, *, result_limit: int | None = None):  # noqa: ANN001
        count = 0
        for page in self.iter_pages(path, params):
            for row in page["value"]:
                if result_limit is not None and count >= result_limit:
                    return
                yield row
                count += 1

    def get_json(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:  # pragma: no cover - a paged list must never use it
        raise AssertionError("a list was read with an unpaged GET")


def test_secure_score_control_profiles_are_paged_to_the_last_row(tmp_path: Path) -> None:
    client = _PagedDefenderClient(profiles=420)
    writer = AuditWriter(tmp_path, tenant_name="acme", run_name="defender")
    adapter = AuditWriterCollectorAdapter(writer)
    output = CollectorRunner(adapter).run(DefenderCollector(), CollectorRunContext(client=client, top=None, hooks=adapter.hooks()))

    profiles = output.result.payload["secureScoreControlProfiles"]
    # Kept whole inline: the reference list is not streamed to a 20-row sample.
    assert len(profiles["value"]) == 420 and "chunk_files" not in profiles
    assert "/security/secureScoreControlProfiles" in client.paths
    row = next(item for item in output.coverage_rows if item["name"] == "secureScoreControlProfiles")
    assert row["status"] == "ok" and row["item_count"] == 420 and not row.get("collection_truncated")
    assert len(output.result.payload["secureScores"]["value"]) == 90


# Direct ``get_json`` reads that are genuinely one object, or that page themselves. Any other collector module that
# calls ``get_json`` is a candidate unpaged list read, which drops ``@odata.nextLink`` silently.
_DIRECT_GET_JSON_ALLOWED = {
    "_capability_gated.py": "follows @odata.nextLink through iter_items, or records pagination_not_followed",
    "_endpoint_reads.py": "ObjectRead: one object per call",
    "app_credentials.py": "per-object owners ($select=id) and federated credentials of one application",
    "cross_tenant_access.py": "tenant-level policy objects; the partners list uses get_all",
    "dns_posture.py": "the /domains read falls back to get_json only when the client cannot page",
    "identity_protection.py": "a bounded riskyUsers sample (page size), summarised as counts",
    "mailbox_forwarding.py": "per-user messageRules and mailboxSettings",
    "reports_usage.py": "one report settings object per call",
}
# Endpoints a collector spec may read unpaged (``"page": False``): each answers one object, never a list.
_UNPAGED_OBJECT_ENDPOINTS = {
    "/organization",
    "/admin/sharepoint/settings",
    "/policies/adminConsentRequestPolicy",
    "/policies/authorizationPolicy",
    "/policies/authenticationFlowsPolicy",
    "/policies/authenticationMethodsPolicy",
    "/policies/crossTenantAccessPolicy",
    "/policies/identitySecurityDefaultsEnforcementPolicy",
}


def _unpaged_specs(tree: ast.AST) -> list[str]:
    endpoints: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        entries = {key.value: value for key, value in zip(node.keys, node.values) if isinstance(key, ast.Constant)}
        page = entries.get("page")
        if isinstance(page, ast.Constant) and page.value is False:
            endpoint = entries.get("endpoint")
            endpoints.append(endpoint.value if isinstance(endpoint, ast.Constant) else "<dynamic>")
    return endpoints


def test_collectors_read_lists_through_the_shared_paging_path() -> None:
    """A direct list read must be paged; a new unpaged one fails here until it is paged or shown to be a single object."""
    collectors = REPO / "src" / "azure_tenant_audit" / "collectors"
    offenders: list[str] = []
    for path in sorted(collectors.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        direct = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get_json"
        ]
        if direct and path.name not in _DIRECT_GET_JSON_ALLOWED and path.name != "base.py":
            offenders.append(f"{path.name}: {len(direct)} direct get_json read(s)")
        for endpoint in _unpaged_specs(tree):
            if endpoint not in _UNPAGED_OBJECT_ENDPOINTS:
                offenders.append(f"{path.name}: unpaged spec for {endpoint}")
    assert offenders == []


def test_the_lists_that_were_unpaged_are_paged_specs() -> None:
    """secureScoreControlProfiles, secureScores, subscribedSkus and domains are lists: each is paged and kept whole inline."""
    seen: dict[str, dict[str, Any]] = {}
    for module in ("defender", "licensing", "identity"):
        tree = ast.parse((REPO / "src" / "azure_tenant_audit" / "collectors" / f"{module}.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                entries = {key.value: value for key, value in zip(node.keys, node.values) if isinstance(key, ast.Constant)}
                endpoint = entries.get("endpoint")
                if isinstance(endpoint, ast.Constant) and endpoint.value in {
                    "/security/secureScoreControlProfiles",
                    "/security/secureScores",
                    "/subscribedSkus",
                    "/domains",
                }:
                    seen[endpoint.value] = {key: ast.literal_eval(value) for key, value in entries.items() if key in {"page", "inline", "apply_top"}}
    assert set(seen) == {"/security/secureScoreControlProfiles", "/security/secureScores", "/subscribedSkus", "/domains"}
    assert all(spec.get("page", True) is True and spec.get("inline") is True and spec.get("apply_top") is False for spec in seen.values())


def test_a_capability_gated_list_follows_its_next_link(tmp_path: Path) -> None:
    from azure_tenant_audit.collectors._capability_gated import run_capability_gated_endpoints

    class _Client:
        def get_json(self, path: str, params: Any = None, full_url: bool = False) -> dict[str, Any]:
            return {"value": [{"id": "1"}, {"id": "2"}], "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/incidents?$skiptoken=2"}

        def iter_items(self, path: str, params: Any = None):  # noqa: ANN001
            assert path.startswith("https://graph.microsoft.com/")
            yield {"id": "3"}

    payload, coverage = run_capability_gated_endpoints("sentinel_xdr", _Client(), [("xdrIncidents", "/security/incidents")])

    assert [row["id"] for row in payload["xdrIncidents"]["value"]] == ["1", "2", "3"]
    assert coverage[0]["status"] == "ok" and coverage[0]["item_count"] == 3


def test_a_capability_gated_list_that_cannot_page_is_a_gap_not_a_clean_read() -> None:
    from azure_tenant_audit.collectors._capability_gated import run_capability_gated_endpoints

    class _Client:
        def get_json(self, path: str, params: Any = None, full_url: bool = False) -> dict[str, Any]:
            return {"value": [{"id": "1"}], "@odata.nextLink": "https://graph.microsoft.com/v1.0/next"}

    payload, coverage = run_capability_gated_endpoints("sentinel_xdr", _Client(), [("xdrIncidents", "/security/incidents")])

    assert coverage[0]["status"] == "partial" and coverage[0]["truncation_reason"] == "pagination_not_followed"
    assert payload["xdrIncidents"]["collection_truncated"] is True


# ---- #25 update profiles: expose a blocked beta list so the rule cannot read "no profile" ------------------------


def _update_summary(depth: dict[str, Any]) -> dict[str, Any]:
    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads={"intune_depth": depth, "intune": {"managedDevices": {"value": [{"id": "d1", "deviceName": "PC", "operatingSystem": "Windows"}]}}},
        coverage_rows=[],
        result_rows=[],
    )
    return next(row for row in snapshot[UPDATE_SECTION]["records"] if row["kind"] == UPDATE_SUMMARY_KIND)


def _ring_inputs(**profiles: Any) -> dict[str, Any]:
    return {"windowsUpdateRings": {"value": []}, "windowsUpdateRingAssignments": {"value": []}, **profiles}


def test_a_blocked_beta_profile_list_is_a_stated_gap_not_no_profile() -> None:
    summary = _update_summary(
        _ring_inputs(
            windowsQualityUpdateProfiles={"error": "forbidden", "error_class": "insufficient_permissions"},
            windowsFeatureUpdateProfiles={"error": "forbidden", "error_class": "insufficient_permissions"},
        )
    )

    assert summary["quality_profiles_read_state"] == "blocked" and summary["profiles_assigned"] == 0
    assert summary["update_profiles_gap"] == "update_profiles_blocked"


def test_profiles_whose_assignments_were_not_read_are_a_stated_gap() -> None:
    summary = _update_summary(
        _ring_inputs(
            windowsQualityUpdateProfiles={"value": [{"id": "q1", "displayName": "Quality"}]},
            windowsQualityUpdateProfileAssignments={"error": "forbidden", "error_class": "insufficient_permissions"},
            windowsFeatureUpdateProfiles={"value": []},
            windowsFeatureUpdateProfileAssignments={"value": []},
        )
    )

    assert summary["profile_count"] == 1 and summary["profiles_with_unknown_assignments"] == 1
    assert summary["update_profiles_gap"] == "profile_assignments_blocked"


def test_profiles_read_in_full_with_their_assignments_have_no_gap() -> None:
    summary = _update_summary(
        _ring_inputs(
            windowsQualityUpdateProfiles={"value": [{"id": "q1", "displayName": "Quality"}]},
            windowsQualityUpdateProfileAssignments={"value": [{"policyId": "q1", "assignments": [{"id": "a", "target": {"groupId": "g"}}]}]},
            windowsFeatureUpdateProfiles={"value": []},
            windowsFeatureUpdateProfileAssignments={"value": []},
        )
    )

    assert "update_profiles_gap" not in summary and summary["profiles_with_unknown_assignments"] == 0 and summary["profiles_assigned"] == 1


def test_a_bundle_from_before_the_profile_lists_were_collected_has_no_stated_gap() -> None:
    summary = _update_summary(_ring_inputs())

    assert summary["quality_profiles_read_state"] == "absent" and "update_profiles_gap" not in summary


# ---- #28/#44 eDiscovery: every spelling the collector may run is declared ------------------------------------------


def test_every_ediscovery_command_row_names_the_variants_it_may_run() -> None:
    class _Adapter:
        def run(self, command: str, log_event: Any = None) -> dict[str, Any]:  # noqa: ANN401
            return {"error": f"command_not_found:{command}", "error_class": "command_not_found", "command": command}

    class _Client:
        def iter_pages(self, *_a: Any, **_k: Any):
            return iter(())

        def get_all(self, *_a: Any, **_k: Any) -> list[Any]:
            return []

    collector = EDiscoveryCollector()
    import azure_tenant_audit.collectors.ediscovery as module

    original = module.get_adapter
    module.get_adapter = lambda _name: _Adapter()  # type: ignore[assignment]
    try:
        result = collector.run({"client": _Client(), "top": None, "plane": "full", "audit_logger": None})
    finally:
        module.get_adapter = original  # type: ignore[assignment]

    rows = {row["name"]: row for row in result.coverage if row.get("type") == "command"}
    assert set(rows) == {entry["name"] for entry in collector.command_collectors}
    for entry in collector.command_collectors:
        assert rows[entry["name"]]["command_variants"] == entry["commands"]
        # Both spellings were tried, so the first is as declared as the last.
        assert rows[entry["name"]]["command"] in entry["commands"]


def test_checkpoint_resume_rows_keep_their_command_variants() -> None:
    class _Client:
        def get_all(self, *_a: Any, **_k: Any) -> list[Any]:
            return []

    collector = EDiscoveryCollector()
    state = {entry["name"]: {"status": "ok", "item_count": 2, "command": entry["commands"][0]} for entry in collector.command_collectors if entry.get("plane") == "export"}
    result = collector.run({"client": _Client(), "top": None, "plane": "full", "audit_logger": None, "operation_checkpoint_state": state})

    resumed = [row for row in result.coverage if row.get("checkpoint_resume")]
    assert resumed and all(row["command_variants"] for row in resumed)


def test_the_shipped_ediscovery_catalogue_matches_the_commands_the_collector_runs() -> None:
    definitions = json.loads((REPO / "configs" / "collector-definitions.json").read_text(encoding="utf-8"))["collectors"]
    shipped = {entry["name"]: entry["commands"] for entry in definitions["ediscovery"]["command_collectors"]}

    assert shipped == {entry["name"]: entry["commands"] for entry in EDiscoveryCollector.command_collectors}


def test_a_cli_help_dump_that_exits_zero_is_logged_as_an_error_not_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    help_text = "CLI for Microsoft 365 v11.11.0\n\nCommands:\n  purview  ...\n"
    monkeypatch.setattr("shutil.which", lambda name, *a, **k: f"/usr/bin/{name}")
    monkeypatch.setattr("subprocess.run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout=help_text, stderr=""))
    events: list[dict[str, Any]] = []
    response = M365CLIAdapter().run(
        "m365 purview hold list --output json", log_event=lambda event, message, details=None: events.append({"event": event, **(details or {})})
    )

    assert response["error_class"] == "command_parse_error"
    (completed,) = [item for item in events if item["event"] == "command.completed"]
    assert completed["status"] == "error" and completed["return_code"] == 0


def test_a_json_answer_is_still_logged_as_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda name, *a, **k: f"/usr/bin/{name}")
    monkeypatch.setattr("subprocess.run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout='[{"id": "1"}]', stderr=""))
    events: list[dict[str, Any]] = []
    response = M365CLIAdapter().run(
        "m365 purview hold list --output json", log_event=lambda event, message, details=None: events.append({"event": event, **(details or {})})
    )

    assert response["value"] == [{"id": "1"}]
    assert [item["status"] for item in events if item["event"] == "command.completed"] == ["ok"]


# ---- #29 fan-out totals and OneDrive sites come from the whole list, not the 20-row sample -------------------------


def _chunk_writer(run_dir: Path):
    def writer(collector: str, name: str, page: int, rows: list[dict[str, Any]], _meta: Any = None) -> str:
        relative = f"chunks/{collector}/{name}-{page:05d}.jsonl"
        target = run_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        return relative

    return writer


def test_section_total_prefers_the_item_count_over_the_inline_sample() -> None:
    assert section_total({"item_count": 300, "value": [{}] * 20}, [{}] * 20) == 300
    assert section_total({"value": [{}] * 7}, [{}] * 7) == 7
    assert section_total(None, [{}] * 3) == 3
    assert section_total({"item_count": 2}, [{}] * 5) == 5


def test_the_device_configuration_fanout_gap_states_the_real_total(tmp_path: Path) -> None:
    configurations = [{"id": f"cfg-{index}", "displayName": f"Config {index}"} for index in range(300)]

    class _Client:
        def iter_pages(self, path: str, params: Any = None):  # noqa: ANN001
            rows = configurations if path == "/deviceManagement/deviceConfigurations" else []
            for start in range(0, len(rows), 100):
                yield {"value": rows[start : start + 100]}

        def get_batch(self, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return [{"request": item, "status": 200, "body": {"value": []}} for item in requests]

    result = IntuneDepthCollector().run({"client": _Client(), "top": None, "audit_logger": None, "chunk_writer": _chunk_writer(tmp_path), "run_dir": tmp_path})

    gap = next(row for row in result.coverage if row["name"] == "deviceConfigurationAssignmentsFanout")
    assert gap["fanout_total"] == 300 and "only the first 10 of 300" in gap["error"]


def test_onedrive_site_counts_cover_every_site_read(tmp_path: Path) -> None:
    sites = [
        {"id": f"site-{index}", "displayName": f"Site {index}", "webUrl": f"https://contoso-my.sharepoint.com/personal/u{index}" if index % 2 == 0 else f"https://contoso.sharepoint.com/sites/t{index}"}
        for index in range(120)
    ]

    class _Client:
        def get_json(self, path: str, params: Any = None, full_url: bool = False) -> dict[str, Any]:
            return {"sharingCapability": "externalUserAndGuestSharing"}

        def iter_pages(self, path: str, params: Any = None):  # noqa: ANN001
            for start in range(0, len(sites), 50):
                yield {"value": sites[start : start + 50]}

    result = OneDrivePostureCollector().run(
        {"client": _Client(), "top": None, "audit_logger": None, "chunk_writer": _chunk_writer(tmp_path), "run_dir": tmp_path}
    )

    assert result.payload["oneDriveSites"]["item_count"] == 60 and result.payload["teamSites"]["item_count"] == 60
    assert len(result.payload["oneDriveSites"]["value"]) == 20 and result.payload["oneDriveSites"]["chunk_files"]

    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads={"onedrive_posture": result.payload},
        coverage_rows=result.coverage,
        result_rows=[{"name": "onedrive_posture", "status": result.status}],
        run_dir=tmp_path,
    )
    records = snapshot["onedrive_posture_objects"]["records"]
    assert len(records) == 120 and sum(1 for row in records if row["site_kind"] == "personal") == 60
    findings = build_findings([], normalized_snapshot=snapshot)
    onedrive = next(item for item in findings if item["rule_id"] == "onedrive.external_sharing_enabled")
    assert onedrive["evidence"]["personal_site_count"] == 60


def test_onedrive_sites_kept_whole_are_unchanged(tmp_path: Path) -> None:
    class _Client:
        def get_json(self, path: str, params: Any = None, full_url: bool = False) -> dict[str, Any]:
            return {"sharingCapability": "disabled"}

        def get_all(self, path: str, params: Any = None) -> list[dict[str, Any]]:
            return [{"id": "od-1", "webUrl": "https://contoso-my.sharepoint.com/personal/a"}, {"id": "t-1", "webUrl": "https://contoso.sharepoint.com/sites/t"}]

    result = OneDrivePostureCollector().run({"client": _Client(), "top": None, "audit_logger": None})

    assert [row["id"] for row in result.payload["oneDriveSites"]["value"]] == ["od-1"]
    assert [row["id"] for row in result.payload["teamSites"]["value"]] == ["t-1"]
    assert "chunk_files" not in result.payload["oneDriveSites"]


# ---- #48 the words an owner chose for an inbox rule or Gmail filter are not kept ------------------------------------


def test_inbox_rule_and_gmail_filter_keywords_become_counts_and_booleans() -> None:
    from azure_tenant_audit.data_minimisation import minimise_user_text

    rule = {
        "id": "r1",
        "displayName": "Forward",
        "conditions": {"subjectContains": ["invoice 4471", "wire"], "bodyContains": ["Acme merger"], "fromAddresses": [{"emailAddress": {"address": "cfo@example.com"}}]},
        "actions": {"forwardTo": [{"emailAddress": {"address": "x@example.net"}}]},
    }
    gmail_filter = {"id": "f1", "criteria": {"query": "payroll Acme", "negatedQuery": "newsletter", "subject": "salary", "from": "boss@example.com"}, "action": {"forward": "x@example.net"}}

    minimised = minimise_user_text({"messageRules": [rule], "filters": [gmail_filter]})
    text = json.dumps(minimised)

    for secret in ("invoice 4471", "Acme merger", "payroll", "newsletter", "salary"):
        assert secret not in text
    conditions = minimised["messageRules"][0]["conditions"]
    assert conditions["subjectContainsCount"] == 2 and conditions["hasSubjectContains"] is True and conditions["bodyContainsCount"] == 1
    # Addresses stay: forwarding classification and the actions are what the rules judge.
    assert conditions["fromAddresses"][0]["emailAddress"]["address"] == "cfo@example.com"
    assert minimised["messageRules"][0]["actions"]["forwardTo"][0]["emailAddress"]["address"] == "x@example.net"
    criteria = minimised["filters"][0]["criteria"]
    assert criteria["queryLength"] == len("payroll Acme") and criteria["hasQuery"] is True and criteria["from"] == "boss@example.com"
    assert minimised["filters"][0]["action"] == {"forward": "x@example.net"}
    # Idempotent, and the input is untouched.
    assert minimise_user_text(minimised) == minimised
    assert rule["conditions"]["subjectContains"] == ["invoice 4471", "wire"]


def test_the_writer_keeps_no_inbox_rule_keywords_in_the_raw_bundle(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="acme", run_name="rules")
    rule = {"id": "r1", "conditions": {"bodyContains": ["Acme merger"]}, "actions": {"delete": True}}
    path = writer.write_raw("mailbox_forwarding", {"messageRules": {"value": [rule]}})

    assert "Acme merger" not in path.read_text(encoding="utf-8")
