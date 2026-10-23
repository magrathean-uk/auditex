"""The low-severity findings of review v3: DNS edge cases, the Drive crawl, paging leftovers and the API ledger."""
from __future__ import annotations

import ast
import json
import logging
import subprocess
from pathlib import Path
from typing import Any

import pytest

from auditex.gate import gate_findings
from auditex.google_workspace.run import run_google_offline
from azure_tenant_audit import baselines
from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
from azure_tenant_audit.api_inventory import observe_audit_events
from azure_tenant_audit.collection_gaps import SAMPLE_JUDGED_RULES
from azure_tenant_audit.collectors import power_platform as power_platform_module
from azure_tenant_audit.collectors.dns_posture import DnsPostureCollector
from azure_tenant_audit.collectors.identity_protection import IdentityProtectionCollector
from azure_tenant_audit.collectors.power_platform import PowerPlatformCollector
from azure_tenant_audit.contracts import build_validation_report
from azure_tenant_audit.dns_lookup import DohClient, DohError, collect_domain_posture
from azure_tenant_audit.power_platform import PowerPlatformError

from gate_support import offline_run, read_json, rehash
from scripted_collectors import REPO_ROOT, load, rule_statuses

# ---- 13. DNS edge cases ------------------------------------------------------------------------------------------


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


def _query(payload: Any) -> list[str]:
    return DohClient(session=_Session(payload)).query("example.test", "TXT")


@pytest.mark.parametrize(
    "payload",
    [{}, {"Answer": []}, {"Status": None}, {"Status": "n/a"}, {"Status": 0, "TC": True}, {"Status": 0, "TC": True, "Answer": []}],
    ids=["no status", "answer without status", "null status", "text status", "truncated", "truncated empty"],
)
def test_a_doh_answer_that_does_not_say_noerror_or_nxdomain_is_not_evidence_of_absence(payload: Any) -> None:
    with pytest.raises(DohError):
        _query(payload)


def test_an_explicit_noerror_or_nxdomain_without_records_is_still_absent_and_a_complete_answer_is_read() -> None:
    assert _query({"Status": 0}) == []
    assert _query({"Status": 3}) == []
    assert _query({"Status": 0, "TC": False, "Answer": [{"data": '"v=spf1 -all"'}]}) == ["v=spf1 -all"]


class _Resolver:
    def __init__(self, answers: dict[tuple[str, str], list[str]]) -> None:
        self.answers = answers

    def query(self, name: str, record_type: str) -> list[str]:
        return list(self.answers.get((name, record_type), []))


def test_a_revoked_dkim_key_counts_as_an_absent_selector() -> None:
    resolver = _Resolver(
        {
            ("selector1._domainkey.example.test", "TXT"): ["v=DKIM1; k=rsa; p="],
            ("selector2._domainkey.example.test", "TXT"): ["v=DKIM1; k=rsa; p=MIGfMA0GCSq"],
        }
    )

    posture = collect_domain_posture("example.test", resolver)

    assert posture["dkim"]["selectors_present"] == ["selector2"]
    assert posture["dkim"]["selectors_missing"] == ["selector1"]


class _Domains:
    def get_all(self, path: str, params: Any = None) -> list[dict[str, Any]]:
        return [{"id": "example.test", "isVerified": True, "isDefault": True, "authenticationType": "Managed"}]


class _Fetcher:
    def __init__(self, status: int | None, body: str = "", error: str | None = None) -> None:
        self.result = (status, body, error)

    def get_text(self, url: str) -> tuple[int | None, str, str | None]:
        return self.result


def _dns_collector_run(fetcher: Any) -> Any:
    resolver = _Resolver({("_mta-sts.example.test", "TXT"): ["v=STSv1; id=1"]})
    return DnsPostureCollector().run({"client": _Domains(), "dns_resolver": resolver, "https_fetcher": fetcher})


@pytest.mark.parametrize(
    "fetcher",
    [_Fetcher(None, error="Timeout: no answer"), _Fetcher(503), _Fetcher(429)],
    ids=["unreachable", "server error", "throttled"],
)
def test_an_mta_sts_policy_fetch_that_failed_fails_its_row(fetcher: _Fetcher) -> None:
    result = _dns_collector_run(fetcher)

    row = next(item for item in result.coverage if item["name"] == "posture:example.test")
    assert row["status"] == "failed" and row["error_class"] == "public_lookup_error" and row["error"]
    assert result.status == "partial"


@pytest.mark.parametrize(
    "fetcher",
    [_Fetcher(404), _Fetcher(200, "version: STSv1\nmode: enforce\nmx: mail.example.test\nmax_age: 86400\n")],
    ids=["not served", "served"],
)
def test_an_mta_sts_policy_that_answered_keeps_its_row_ok(fetcher: _Fetcher) -> None:
    result = _dns_collector_run(fetcher)

    row = next(item for item in result.coverage if item["name"] == "posture:example.test")
    assert row["status"] == "ok"


# ---- 14. the Drive crawl is a sample ----------------------------------------------------------------------------


def _drive_replay(tmp_path: Path, *, marker: bool, name: str) -> Path:
    payload = json.loads((REPO_ROOT / "examples" / "google_workspace_sample.json").read_text(encoding="utf-8"))
    files = [{"id": f"f{index}", "name": f"Doc {index}", "mimeType": "application/vnd.google-apps.document", "shared": False, "permissions": []} for index in range(500)]
    payload["google_drive_posture"] = {
        "driveFiles": {"value": files, **({"bounded_sample": True, "collection_truncated": False} if marker else {})},
        "sharedDrives": {"value": []},
    }
    sample_path = tmp_path / f"{name}.json"
    sample_path.write_text(json.dumps(payload), encoding="utf-8")
    logging.disable(logging.CRITICAL)
    try:
        run_google_offline(sample_path=sample_path, out=tmp_path / "out", tenant_name="g", run_name=name, domain="example.com", customer_id=None)
    finally:
        logging.disable(logging.NOTSET)
    return tmp_path / "out" / f"g-{name}"


def test_a_drive_crawl_cut_at_its_sample_bound_does_not_read_pass(tmp_path: Path) -> None:
    sampled = _drive_replay(tmp_path, marker=True, name="sampled")
    whole = _drive_replay(tmp_path, marker=False, name="whole")

    for rule in ("google.drive_anyone_with_link", "google.drive_public_discoverable"):
        assert rule in SAMPLE_JUDGED_RULES
        assert rule_statuses(sampled)[rule] == {("not_assessed", "bounded_sample:google_drive_posture.driveFiles")}
        assert {status for status, _reason in rule_statuses(whole)[rule]} == {"pass"}
    records = load(sampled / "normalized" / "bounded_samples.json")["records"]
    assert [(item["collector"], item["list"]) for item in records] == [("google_drive_posture", "driveFiles")]
    assert baselines.rule_inputs_gap("google.drive_anyone_with_link", {"bounded_samples": {"records": records}}) == (
        "bounded_sample:google_drive_posture.driveFiles"
    )


# ---- 16. paging leftovers ----------------------------------------------------------------------------------------


class _RiskyUsers:
    """``get_json`` answers the first page; ``iter_items`` follows the next link, as ``GraphClient`` does."""

    def __init__(self, first: list[dict[str, Any]], rest: list[dict[str, Any]] | Exception, link: str | None = "https://graph.microsoft.com/v1.0/next") -> None:
        self.first, self.rest, self.link = first, rest, link
        self.followed: list[str] = []

    def get_json(self, path: str, params: Any = None) -> dict[str, Any]:
        page: dict[str, Any] = {"value": self.first}
        if self.link:
            page["@odata.nextLink"] = self.link
        return page

    def iter_items(self, link: str, params: Any = None, result_limit: int | None = None):
        self.followed.append(link)
        if isinstance(self.rest, Exception):
            raise self.rest
        return iter(self.rest)


def _risky(level: str, state: str, count: int) -> list[dict[str, Any]]:
    return [{"id": f"r{level}{index}", "riskLevel": level, "riskState": state} for index in range(count)]


def test_risky_users_are_paged_to_the_last_row() -> None:
    client = _RiskyUsers(_risky("low", "atRisk", 2), _risky("high", "confirmedCompromised", 3))

    result = IdentityProtectionCollector().run({"client": client, "audit_logger": None})

    assert client.followed == ["https://graph.microsoft.com/v1.0/next"]
    (summary,) = result.payload["riskyUserSummary"]["value"]
    assert summary["sampled_count"] == 5 and summary["at_risk_count"] == 5
    assert result.status == "ok" and result.coverage[0].get("collection_truncated") is not True
    assert "collection_truncated" not in result.payload["riskyUserSummary"]


def test_a_risky_users_page_that_cannot_be_read_leaves_a_marked_cut_summary() -> None:
    from azure_tenant_audit.graph import GraphError

    client = _RiskyUsers(_risky("low", "atRisk", 2), GraphError("Service unavailable", status=503, request="/next"))

    result = IdentityProtectionCollector().run({"client": client, "audit_logger": None})

    row = result.coverage[0]
    assert (row["status"], row["collection_truncated"], row["truncation_reason"]) == ("failed", True, "pagination_failed")
    assert row["error"] and result.status == "partial"
    assert result.payload["riskyUserSummary"]["collection_truncated"] is True


def test_a_risky_users_link_that_cannot_be_followed_is_recorded_as_not_followed() -> None:
    class _NoPaging:
        def get_json(self, path: str, params: Any = None) -> dict[str, Any]:
            return {"value": _risky("low", "none", 1), "@odata.nextLink": "https://graph.microsoft.com/v1.0/next"}

    result = IdentityProtectionCollector().run({"client": _NoPaging(), "audit_logger": None})

    row = result.coverage[0]
    assert (row["status"], row["collection_truncated"], row["truncation_reason"]) == ("partial", True, "pagination_not_followed")
    assert result.status == "partial"


class _PowerPlatform:
    token = "t"

    def __init__(self, pages: dict[str, dict[str, Any] | Exception]) -> None:
        self.pages = pages
        self.paths: list[str] = []

    def get(self, path: str) -> Any:
        self.paths.append(path)
        page = self.pages.get(path, {})
        if isinstance(page, Exception):
            raise page
        return page


ENVIRONMENTS = "/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments"
POLICIES = "/providers/PowerPlatform.Governance/v2/policies"
NEXT_ENVIRONMENTS = "https://api.bap.microsoft.com/environments?page=2"


def _environment(index: int) -> dict[str, Any]:
    return {"id": f"e{index}", "name": f"e{index}", "properties": {"displayName": f"Env {index}"}}


def _power_platform_run(client: _PowerPlatform) -> Any:
    return PowerPlatformCollector().run({"power_platform_client": client, "audit_logger": None})


def test_power_platform_lists_follow_their_next_link() -> None:
    client = _PowerPlatform(
        {
            ENVIRONMENTS: {"value": [_environment(0), _environment(1)], "nextLink": NEXT_ENVIRONMENTS},
            NEXT_ENVIRONMENTS: {"value": [_environment(2)]},
            POLICIES: {"value": []},
        }
    )

    result = _power_platform_run(client)

    assert [row["id"] for row in result.payload["environments"]["value"]] == ["e0", "e1", "e2"]
    rows = {row["name"]: row for row in result.coverage}
    assert rows["environments"]["status"] == "ok" and rows["environments"]["item_count"] == 3
    assert not rows["environments"].get("collection_truncated") and "collection_truncated" not in result.payload["environments"]
    assert client.paths[:2] == [ENVIRONMENTS, NEXT_ENVIRONMENTS]


def test_a_power_platform_page_that_fails_leaves_a_marked_cut_list() -> None:
    client = _PowerPlatform(
        {
            ENVIRONMENTS: {"value": [_environment(0)], "nextLink": NEXT_ENVIRONMENTS},
            NEXT_ENVIRONMENTS: PowerPlatformError("power platform request denied: 403", status=403, request=NEXT_ENVIRONMENTS),
            POLICIES: {"value": []},
        }
    )

    result = _power_platform_run(client)

    row = next(item for item in result.coverage if item["name"] == "environments")
    assert (row["status"], row["collection_truncated"], row["truncation_reason"]) == ("failed", True, "pagination_failed")
    assert result.payload["environments"]["collection_truncated"] is True
    assert [item["id"] for item in result.payload["environments"]["value"]] == ["e0"]
    assert result.status == "partial"


def test_a_power_platform_list_longer_than_the_page_bound_is_a_marked_cut(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(power_platform_module, "MAX_LIST_PAGES", 2)
    pages: dict[str, dict[str, Any] | Exception] = {
        POLICIES: {"value": [], "nextLink": "https://api.bap.microsoft.com/p?page=2"},
        "https://api.bap.microsoft.com/p?page=2": {"value": [], "nextLink": "https://api.bap.microsoft.com/p?page=3"},
        "https://api.bap.microsoft.com/p?page=3": {"value": []},
    }

    result = _power_platform_run(_PowerPlatform(pages))

    row = next(item for item in result.coverage if item["name"] == "dlpPolicies")
    assert (row["status"], row["collection_truncated"], row["truncation_reason"]) == ("partial", True, "pagination_not_followed")


def test_the_paging_guard_no_longer_allows_a_whole_module_to_drop_a_next_link() -> None:
    """identity_protection.py reads ``get_json`` directly; it must follow ``@odata.nextLink`` or record that it did not."""
    source = (REPO_ROOT / "src" / "azure_tenant_audit" / "collectors" / "identity_protection.py").read_text(encoding="utf-8")
    assert "@odata.nextLink" in source and "iter_items" in source and "REASON_PAGINATION_NOT_FOLLOWED" in source
    power_platform = ast.parse((REPO_ROOT / "src" / "azure_tenant_audit" / "collectors" / "power_platform.py").read_text(encoding="utf-8"))
    assert "nextLink" in ast.unparse(power_platform) and "MAX_LIST_PAGES" in ast.unparse(power_platform)


# ---- 17. the API ledger ------------------------------------------------------------------------------------------


class _Completed:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _run_command(monkeypatch: pytest.MonkeyPatch, completed: Any, command: str = "Get-AcceptedDomain | Select-Object Name") -> list[tuple[str, dict[str, Any]]]:
    events: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr("azure_tenant_audit.adapters.powershell_graph.shutil.which", lambda _name: "/usr/bin/pwsh")

    def fake_run(*_args: Any, **_kwargs: Any) -> Any:
        if isinstance(completed, BaseException):
            raise completed
        return completed

    monkeypatch.setattr("azure_tenant_audit.adapters.powershell_graph.subprocess.run", fake_run)
    PowerShellGraphAdapter().run(command, log_event=lambda event, _message, details=None: events.append((event, dict(details or {}))))
    return events


@pytest.mark.parametrize(
    ("completed", "status", "error_class"),
    [
        (_Completed(0, '{"Name": "contoso.test"}'), "ok", None),
        (_Completed(1, "", "boom"), "failed", "command_error"),
        (_Completed(0, ""), "failed", "command_output_empty"),
        (_Completed(0, "not json"), "failed", "command_parse_error"),
    ],
    ids=["ok", "non-zero exit", "empty output", "unparseable output"],
)
def test_the_powershell_adapter_logs_the_outcome_and_the_command_words_not_only_the_return_code(
    monkeypatch: pytest.MonkeyPatch, completed: Any, status: str, error_class: str | None
) -> None:
    events = _run_command(monkeypatch, completed)

    (details,) = [details for event, details in events if event == "command.completed"]
    assert details["command_words"] == ["Get-AcceptedDomain", "Select-Object"]
    assert details["return_code"] == completed.returncode
    assert (details["status"], details["error_class"]) == (status, error_class)
    # The observed ledger reads that status instead of "rc=0".
    ledger = observe_audit_events(({"event": event, "details": details} for event, details in events), platform="m365")
    (entry,) = ledger["commands"]["executed"]
    assert entry["statuses"] == {status: 1}


@pytest.mark.parametrize(
    "failure",
    [subprocess.TimeoutExpired(cmd="pwsh", timeout=120), OSError("exec failed")],
    ids=["timeout", "exception"],
)
def test_a_powershell_command_that_never_completed_logs_its_words_and_ends_as_failed(monkeypatch: pytest.MonkeyPatch, failure: BaseException) -> None:
    events = _run_command(monkeypatch, failure)

    (details,) = [details for event, details in events if event == "command.failed"]
    assert details["command_words"] == ["Get-AcceptedDomain", "Select-Object"] and details["adapter"] == "powershell_graph"
    ledger = observe_audit_events(({"event": event, "details": details} for event, details in events), platform="m365")
    (entry,) = ledger["commands"]["executed"]
    assert entry["count"] == 1 and entry["statuses"] == {"failed": 1}


def test_a_call_outside_the_declared_set_is_a_gate_and_a_validation_warning(tmp_path: Path) -> None:
    run_dir = offline_run(tmp_path)
    clean = gate_findings(run_dir=str(run_dir), fail_on="critical")
    assert clean["status"] == "pass" and not any("outside the declared set" in warning for warning in clean["warnings"])

    inventory_path = run_dir / "api-inventory.json"
    inventory = read_json(inventory_path)
    inventory["observed_ledger"]["outside_declared"] = {
        "graph": [{"method": "GET", "endpoint": "/users/{id}/calendarView", "api_version": "v1.0"}],
        "commands": [{"adapter": "powershell_graph", "command": "Get-Mailbox Select-Object"}],
        "count": 2,
    }
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    rehash(run_dir)

    result = gate_findings(run_dir=str(run_dir), fail_on="critical")

    assert result["status"] == "pass", "a warning, never a block"
    warning = next(item for item in result["warnings"] if "outside the declared set" in item)
    assert "2 call(s)" in warning and "GET /users/{id}/calendarView" in warning and "Get-Mailbox" in warning
    report = build_validation_report(run_dir=run_dir, read_only=True)
    issue = next(item for item in report["issues"] if item["code"] == "observed_call_outside_declared")
    assert issue["severity"] == "warning" and issue["details"]["count"] == 2
    assert report["valid"] is True
