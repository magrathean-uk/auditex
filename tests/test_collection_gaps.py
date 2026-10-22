"""Stop silent passes: a list is collected to its last row unless the operator limits it, and a list
that was cut short is a coverage gap that stops baselines from reporting ``pass``."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit import cli
from azure_tenant_audit.baselines import build_baseline_alignment
from azure_tenant_audit.collection_gaps import (
    REASON_NEXT_LINK_REFUSED,
    REASON_OPERATOR_LIMIT,
    REASON_PAGINATION_FAILED,
    list_truncations,
    sample_only,
)
from azure_tenant_audit.collector_runner import CollectorRunContext, CollectorRunner
from azure_tenant_audit.collectors.auth_methods import AuthMethodsCollector
from azure_tenant_audit.collectors.base import context_limit, run_graph_endpoints
from azure_tenant_audit.collectors.conditional_access import ConditionalAccessCollector
from azure_tenant_audit.collectors.domains_hybrid import SYNC_SAMPLE_LIMIT, DomainsHybridCollector
from azure_tenant_audit.collectors.identity import IdentityCollector
from azure_tenant_audit.collectors.security import LOG_SAMPLE_LIMIT, SecurityCollector
from azure_tenant_audit.config import AuthConfig
from azure_tenant_audit.contracts import build_validation_report
from azure_tenant_audit.diagnostics import build_diagnostics
from azure_tenant_audit.graph import GRAPH_ROOT, NEXT_LINK_REFUSED, GraphClient, GraphError
from azure_tenant_audit.normalize import build_normalized_snapshot
from azure_tenant_audit.run import build_coverage_ledger

ROWS = 1250
USERS = "/users"
REGISTRATION = "/reports/authenticationMethods/userRegistrationDetails"
POLICIES = "/identity/conditionalAccess/policies"
ASSIGNMENTS = "/roleManagement/directory/roleAssignments"
GROUPS = "/groups"
APPLICATIONS = "/applications"


def _rows(prefix: str, count: int) -> list[dict[str, Any]]:
    return [{"id": f"{prefix}-{index}"} for index in range(count)]


class _Streaming:
    """Graph client that pages in-memory lists through ``iter_items``, like ``GraphClient``."""

    def __init__(self, lists: dict[str, list[dict[str, Any]]]) -> None:
        self.lists = lists
        self.calls: list[tuple[str, dict[str, Any], int | None]] = []

    def iter_items(self, endpoint: str, params: dict[str, Any] | None = None, result_limit: int | None = None):
        self.calls.append((endpoint, dict(params or {}), result_limit))
        rows = self.lists.get(endpoint, [])
        return iter(rows if result_limit is None else rows[:result_limit])

    def get_json(self, path: str, params: Any = None, full_url: bool = False) -> dict[str, Any]:
        return {"value": []}

    def get_all(self, path: str, params: Any = None) -> list[dict[str, Any]]:
        return []


class _Paged(_Streaming):
    """Adds ``iter_pages`` so collectors take the chunk-writing path."""

    def __init__(self, lists: dict[str, list[dict[str, Any]]], page_size: int = 100) -> None:
        super().__init__(lists)
        self.page_size = page_size
        self.pages_served: list[str] = []

    def iter_pages(self, endpoint: str, params: dict[str, Any] | None = None):
        rows = self.lists.get(endpoint, [])
        if not rows:
            yield {"value": []}
            return
        for start in range(0, len(rows), self.page_size):
            self.pages_served.append(endpoint)
            page: dict[str, Any] = {"value": rows[start:start + self.page_size]}
            if start + self.page_size < len(rows):
                page["@odata.nextLink"] = f"{GRAPH_ROOT}{endpoint}?$skiptoken={start}"
            yield page


def _chunk_writer(root: Path):
    def write(collector: str, name: str, page: int, rows: list[dict[str, Any]], metadata: Any = None) -> str:
        relative = f"chunks/{collector}/{name}-{page:05d}.jsonl"
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        return relative

    return write


def _identity_lists(count: int) -> dict[str, list[dict[str, Any]]]:
    return {
        USERS: _rows("u", count),
        GROUPS: _rows("g", count),
        APPLICATIONS: _rows("a", count),
        ASSIGNMENTS: [{"id": f"ra-{i}", "principalId": f"u-{i}", "roleDefinitionId": "rd"} for i in range(count)],
        "/roleManagement/directory/roleDefinitions": _rows("rd", 3),
        "/servicePrincipals": _rows("sp", count),
        REGISTRATION: _rows("reg", count),
        POLICIES: _rows("ca", count),
    }


# ---- default: every list is paged to its last row ---------------------------------------------------


@pytest.mark.parametrize("top", [None, 0, -1])
def test_no_row_limit_pages_every_list_to_the_end(top: int | None) -> None:
    client = _Streaming({USERS: _rows("u", ROWS)})

    payload, coverage = run_graph_endpoints("identity", client, {"users": {"endpoint": USERS}}, top, page_size=100)

    assert len(payload["users"]["value"]) == ROWS
    row = coverage[0]
    assert row["status"] == "ok"
    assert row["item_count"] == ROWS
    assert row["collection_truncated"] is False
    assert row["result_limit"] is None
    assert payload["users"]["collection_truncated"] is False
    assert client.calls == [(USERS, {"$top": "100"}, None)]
    assert list_truncations(coverage) == []


def test_chunked_collection_without_a_limit_reads_every_page(tmp_path: Path) -> None:
    client = _Paged({USERS: _rows("u", ROWS)})

    payload, coverage = run_graph_endpoints(
        "identity", client, {"users": {"endpoint": USERS}}, None, page_size=100, chunk_writer=_chunk_writer(tmp_path)
    )

    assert payload["users"]["item_count"] == ROWS
    assert payload["users"]["chunk_count"] == 13
    assert coverage[0]["collection_truncated"] is False
    assert coverage[0]["status"] == "ok"


@pytest.mark.parametrize("context", [{}, {"top": None}, {"top": 0}])
def test_the_named_identity_lists_have_no_default_cap(context: dict[str, Any], tmp_path: Path) -> None:
    lists = _identity_lists(ROWS)
    client = _Paged(lists)
    for collector, names in (
        (IdentityCollector(), ("users", "groups", "applications", "roleAssignments")),
        (AuthMethodsCollector(), ("userRegistrationDetails",)),
        (ConditionalAccessCollector(), ("conditionalAccessPolicies",)),
    ):
        result = collector.run(
            {"client": client, "page_size": 100, "chunk_writer": _chunk_writer(tmp_path), "run_dir": tmp_path, **context}
        )

        for name in names:
            assert result.payload[name]["item_count"] == ROWS, (collector.name, name)
            assert result.payload[name]["collection_truncated"] is False
        assert result.status == "ok", (collector.name, result.message)
        assert not [row for row in result.coverage if row.get("collection_truncated")]


def test_every_collector_context_defaults_to_no_limit() -> None:
    assert context_limit({}) is None
    assert context_limit({"top": None}) is None
    assert context_limit({"top": 0}) is None
    assert context_limit({"top": 25}) == 25
    assert context_limit({}, default=500) == 500


def test_the_cli_row_limit_is_opt_in() -> None:
    parser = cli.build_parser()
    base = ["--tenant-name", "acme"]

    assert parser.parse_args(base).top is None
    assert parser.parse_args([*base, "--top", "250"]).top == 250


# ---- an explicit limit is recorded as a coverage gap ------------------------------------------------


@pytest.mark.parametrize("chunked", [False, True])
def test_an_explicit_limit_is_recorded_as_a_gap(chunked: bool, tmp_path: Path) -> None:
    client = _Paged({USERS: _rows("u", 250)})
    kwargs: dict[str, Any] = {"chunk_writer": _chunk_writer(tmp_path)} if chunked else {}
    if not chunked:
        client = _Streaming({USERS: _rows("u", 250)})  # type: ignore[assignment]

    payload, coverage = run_graph_endpoints("identity", client, {"users": {"endpoint": USERS}}, 100, page_size=50, **kwargs)

    row = coverage[0]
    assert row["item_count"] == 100
    assert row["status"] == "partial"
    assert row["error_class"] == "collection_limit"
    assert "operator row limit" in row["error"]
    assert row["collection_truncated"] is True
    assert row["truncation_reason"] == REASON_OPERATOR_LIMIT
    assert row["result_limit"] == 100
    assert payload["users"]["collection_truncated"] is True
    assert payload["users"]["truncation_reason"] == REASON_OPERATOR_LIMIT
    assert "error" not in payload["users"], "a cut list is evidence, not a failed read"
    assert list_truncations(coverage) == [
        {
            "collector": "identity",
            "list": "users",
            "rows_collected": 100,
            "reason": REASON_OPERATOR_LIMIT,
            "endpoint": USERS,
            "result_limit": 100,
        }
    ]


@pytest.mark.parametrize("chunked", [False, True])
def test_a_limit_equal_to_the_list_length_is_not_a_gap(chunked: bool, tmp_path: Path) -> None:
    client = (_Paged if chunked else _Streaming)({USERS: _rows("u", 100)})
    kwargs: dict[str, Any] = {"chunk_writer": _chunk_writer(tmp_path)} if chunked else {}

    payload, coverage = run_graph_endpoints("identity", client, {"users": {"endpoint": USERS}}, 100, page_size=50, **kwargs)

    assert coverage[0]["status"] == "ok"
    assert coverage[0]["collection_truncated"] is False
    assert payload["users"]["collection_truncated"] is False


def test_a_fake_client_that_ignores_the_limit_is_still_cut_and_recorded() -> None:
    class GetAllOnly:
        def get_all(self, path: str, params: Any = None) -> list[dict[str, Any]]:
            return _rows("u", 40)

    payload, coverage = run_graph_endpoints("identity", GetAllOnly(), {"users": {"endpoint": USERS}}, 10)

    assert len(payload["users"]["value"]) == 10
    assert coverage[0]["collection_truncated"] is True
    assert coverage[0]["status"] == "partial"


def test_a_truncated_collector_is_partial() -> None:
    client = _Paged(_identity_lists(30))

    result = IdentityCollector().run({"client": client, "top": 10})

    assert result.status == "partial"
    truncated = {row["name"] for row in result.coverage if row.get("collection_truncated")}
    assert {"users", "groups", "applications", "roleAssignments"} <= truncated
    sign_in = next(row for row in result.coverage if row["name"] == "userSignInActivity")
    assert not sign_in.get("capability_gated"), "a cut sign-in list was readable"


# ---- pagination that stops early --------------------------------------------------------------------


def test_a_later_page_failure_is_a_gap_with_its_rows_kept(tmp_path: Path) -> None:
    class Client:
        def iter_pages(self, _endpoint: str, params: Any = None):
            yield {"value": _rows("u", 31), "@odata.nextLink": f"{GRAPH_ROOT}/users?$skiptoken=1"}
            raise GraphError("later page failed", status=503)

    payload, coverage = run_graph_endpoints(
        "identity", Client(), {"users": {"endpoint": USERS}}, None, chunk_writer=_chunk_writer(tmp_path)
    )

    row = coverage[0]
    assert row["status"] == "failed"
    assert row["item_count"] == 31
    assert row["collection_truncated"] is True
    assert row["truncation_reason"] == REASON_PAGINATION_FAILED
    assert payload["users"]["item_count"] == 31
    assert list_truncations(coverage)[0]["reason"] == REASON_PAGINATION_FAILED


def test_a_failed_first_page_is_a_blocked_read_not_a_truncation(tmp_path: Path) -> None:
    class Client:
        def iter_pages(self, _endpoint: str, params: Any = None):
            raise GraphError("forbidden", status=403)
            yield {}  # pragma: no cover

    _payload, coverage = run_graph_endpoints(
        "identity", Client(), {"users": {"endpoint": USERS}}, None, chunk_writer=_chunk_writer(tmp_path)
    )

    assert coverage[0]["status"] == "failed"
    assert coverage[0]["collection_truncated"] is False
    assert list_truncations(coverage) == []


def _graph_client(pages: dict[str, dict[str, Any]]) -> tuple[GraphClient, list[str]]:
    client = GraphClient(AuthConfig(tenant_id="t", client_id="c", auth_mode="access_token", access_token="token"))
    requested: list[str] = []

    def fake_get_json(path, params=None, full_url=False):  # noqa: ANN001, ARG001
        url = path if full_url else f"{GRAPH_ROOT}{path}"
        requested.append(url)
        return pages[url]

    client.get_json = fake_get_json  # type: ignore[method-assign]
    return client, requested


def test_a_next_link_outside_microsoft_graph_is_refused() -> None:
    client, requested = _graph_client(
        {f"{GRAPH_ROOT}/users": {"value": [{"id": "u-1"}], "@odata.nextLink": "https://attacker.example/users?x=1"}}
    )

    pages = client.iter_pages("/users")
    assert next(pages)["value"] == [{"id": "u-1"}]
    with pytest.raises(GraphError) as refused:
        next(pages)

    assert refused.value.error_code == NEXT_LINK_REFUSED
    assert requested == [f"{GRAPH_ROOT}/users"], "the bearer token must not be sent to the foreign host"


@pytest.mark.parametrize("link", ["http://graph.microsoft.com/v1.0/users?x=1", "https://graph.microsoft.com.evil.example/users", "/users?x=1"])
def test_only_https_microsoft_graph_next_links_are_followed(link: str) -> None:
    client, _requested = _graph_client({f"{GRAPH_ROOT}/users": {"value": [], "@odata.nextLink": link}})

    pages = client.iter_pages("/users")
    next(pages)
    with pytest.raises(GraphError):
        next(pages)


def test_a_refused_next_link_is_recorded_as_a_gap(tmp_path: Path) -> None:
    client, _requested = _graph_client(
        {f"{GRAPH_ROOT}/users": {"value": _rows("u", 5), "@odata.nextLink": "https://attacker.example/users"}}
    )

    payload, coverage = run_graph_endpoints(
        "identity", client, {"users": {"endpoint": "/users"}}, None, chunk_writer=_chunk_writer(tmp_path)
    )

    row = coverage[0]
    assert row["error_class"] == "next_link_refused"
    assert row["item_count"] == 5
    assert row["collection_truncated"] is True
    assert row["truncation_reason"] == REASON_NEXT_LINK_REFUSED
    assert payload["users"]["truncation_reason"] == REASON_NEXT_LINK_REFUSED


# ---- bounds the collector chooses are samples, not gaps ----------------------------------------------


def test_the_hybrid_sync_sample_is_bounded_without_being_a_gap() -> None:
    client = _Streaming({USERS: _rows("u", 400), "/domains": _rows("d", 3)})

    result = DomainsHybridCollector().run({"client": client, "top": None})

    sample = next(row for row in result.coverage if row["name"] == "syncSampleUsers")
    assert sample["item_count"] == SYNC_SAMPLE_LIMIT
    assert sample["bounded_sample"] is True
    assert sample["collection_truncated"] is False
    assert sample["status"] == "ok"
    assert result.status == "ok"


def test_an_operator_limit_below_a_sample_bound_is_still_a_gap() -> None:
    client = _Streaming({USERS: _rows("u", 400), "/domains": _rows("d", 3)})

    result = DomainsHybridCollector().run({"client": client, "top": 10})

    sample = next(row for row in result.coverage if row["name"] == "syncSampleUsers")
    assert sample["item_count"] == 10
    assert sample["collection_truncated"] is True
    assert result.status == "partial"


def test_entra_logs_are_a_bounded_sample_unless_the_operator_limits_them() -> None:
    client = _Streaming({"/auditLogs/signIns": _rows("s", 900), "/auditLogs/directoryAudits": _rows("d", 900)})

    default = SecurityCollector().run({"client": client, "top": None})

    assert [row["item_count"] for row in default.coverage] == [LOG_SAMPLE_LIMIT, LOG_SAMPLE_LIMIT]
    assert all(row["bounded_sample"] and not row["collection_truncated"] for row in default.coverage)
    assert default.status == "ok"

    limited = SecurityCollector().run({"client": client, "top": 100})

    assert all(row["collection_truncated"] for row in limited.coverage)
    assert limited.status == "partial"


def test_a_probe_samples_rows_without_recording_a_gap() -> None:
    client = _Streaming({USERS: _rows("u", 50)})

    with sample_only():
        payload, coverage = run_graph_endpoints("identity", client, {"users": {"endpoint": USERS}}, 5)

    assert len(payload["users"]["value"]) == 5
    assert coverage[0]["status"] == "ok"
    assert coverage[0]["collection_truncated"] is False
    assert coverage[0]["bounded_sample"] is True
    assert list_truncations(coverage) == []


# ---- baselines never pass a rule that read a cut list -----------------------------------------------


def _ledger_and_status(collector: Any, collector_name: str, context: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    runner = CollectorRunner()
    output = runner.run(collector, CollectorRunContext(client=_Paged(_identity_lists(30)), page_size=10, **context))
    diagnostics = build_diagnostics([output.result_row], output.coverage_rows, {}, "global-reader")
    ledger = build_coverage_ledger(
        capability_rows=[{"collector": collector_name, "status": "supported_exact_scope"}],
        result_rows=[output.result_row],
        diagnostics=diagnostics,
    )
    return ledger, output.result_row


@pytest.mark.parametrize(
    ("collector", "name", "rule_id"),
    [
        (IdentityCollector(), "identity", "identity.stale_enabled_account"),
        (AuthMethodsCollector(), "auth_methods", "identity.user_mfa_not_registered"),
        (ConditionalAccessCollector(), "conditional_access", "ca.policy_report_only"),
    ],
)
def test_baselines_pass_a_complete_collection_and_not_assess_a_cut_one(collector: Any, name: str, rule_id: str) -> None:
    mappings = {rule_id: {"cis_m365_v7": ["T.1"]}}

    def status(top: int | None) -> dict[str, Any]:
        ledger, _row = _ledger_and_status(collector, name, {"top": top})
        alignment = build_baseline_alignment([], coverage_ledger=ledger, mappings=mappings)
        (control,) = alignment["frameworks"]["cis_m365_v7"]["controls"]
        (rule,) = control["rule_statuses"]
        return rule

    assert status(None) == {"rule_id": rule_id, "status": "pass", "evaluated": True}
    cut = status(10)
    assert cut["status"] == "not_assessed"
    assert cut["evaluated"] is False
    assert cut["reason"] == f"collector_not_complete:{name}"


# ---- the gap reaches the normalized output, the manifest and the contract ---------------------------


def test_the_normalized_snapshot_records_each_cut_list() -> None:
    result = IdentityCollector().run({"client": _Paged(_identity_lists(30)), "top": 10})

    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads={"identity": result.payload},
        coverage_rows=result.coverage,
        result_rows=[{"name": "identity", "status": result.status, "item_count": result.item_count}],
    )

    gaps = {row["source"]: row for row in snapshot["collection_gaps"]["records"]}
    users = gaps["identity.users"]
    assert (users["collector"], users["list"], users["rows_collected"], users["reason"]) == ("identity", "users", 10, "operator_limit")
    assert users["result_limit"] == 10
    assert snapshot["snapshot"]["collection_gap_count"] == len(gaps)
    assert "identity.users" in snapshot["snapshot"]["collection_limited_sections"]
    assert not any(source.endswith(("GroupMembers", "GroupOwners")) for source in gaps), "fan-out wrappers restate a coverage row"


def test_a_complete_collection_records_no_gap() -> None:
    result = IdentityCollector().run({"client": _Paged(_identity_lists(30)), "top": None})

    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads={"identity": result.payload},
        coverage_rows=result.coverage,
        result_rows=[{"name": "identity", "status": result.status, "item_count": result.item_count}],
    )

    assert "collection_gaps" not in snapshot
    assert snapshot["snapshot"]["collection_gap_count"] == 0
    assert snapshot["snapshot"]["collection_limited_sections"] == []


def _live_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *extra: str, rows: int = 7) -> tuple[int, Path]:
    lists = _identity_lists(rows)

    class Graph(_Paged):
        def __init__(self, auth: Any, audit_event: Any = None) -> None:
            super().__init__(lists, page_size=3)

        def token_claims(self) -> dict[str, Any]:
            return {}

    args = cli.build_parser().parse_args(
        [
            "--tenant-name", "acme", "--tenant-id", "t-1", "--access-token", "x.y.z",
            "--collectors", "identity,auth_methods,conditional_access",
            "--out", str(tmp_path), "--run-name", "r", *extra,
        ]
    )
    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: Graph(auth, **kwargs))
    return cli.run_live(args), tmp_path / "acme-r"


def test_a_live_run_without_a_limit_collects_everything_and_is_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rc, run_dir = _live_run(tmp_path, monkeypatch)

    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert rc == 0
    assert manifest["overall_status"] == "ok"
    assert "top_limit" not in manifest
    assert manifest["coverage_gaps"] == []
    assert manifest["contract_status"] == "valid"
    assert not (run_dir / "normalized" / "collection_gaps.json").exists()


def test_a_live_run_with_a_limit_is_partial_and_names_every_cut_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rc, run_dir = _live_run(tmp_path, monkeypatch, "--top", "3")

    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    gaps_file = json.loads((run_dir / "normalized" / "collection_gaps.json").read_text(encoding="utf-8"))
    report_pack = json.loads((run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))

    assert rc == 1
    assert manifest["overall_status"] == "partial"
    assert manifest["top_limit"] == 3
    assert validation["valid"] is True, validation["issues"]
    truncated = {
        (item["collector"], item["list"]): item
        for gap in manifest["coverage_gaps"]
        for item in gap.get("truncated_lists", [])
    }
    for key in (
        ("identity", "users"),
        ("identity", "groups"),
        ("identity", "applications"),
        ("identity", "roleAssignments"),
        ("auth_methods", "userRegistrationDetails"),
        ("conditional_access", "conditionalAccessPolicies"),
    ):
        assert truncated[key]["rows_collected"] == 3
        assert truncated[key]["reason"] == REASON_OPERATOR_LIMIT
    assert {row["source"] for row in gaps_file["records"]} >= {f"{collector}.{name}" for collector, name in truncated}
    assert any("truncated lists" in gap["message"] for gap in manifest["coverage_gaps"])

    alignment = report_pack["baseline_alignment"] if "baseline_alignment" in report_pack else report_pack["summary"]["baseline_alignment"]
    statuses = {
        rule["rule_id"]: rule
        for framework in alignment["frameworks"].values()
        for control in framework["controls"]
        for rule in control["rule_statuses"]
    }
    for rule_id in ("identity.stale_enabled_account", "identity.user_mfa_not_registered", "ca.policy_report_only"):
        assert statuses[rule_id]["status"] == "not_assessed", rule_id
        assert statuses[rule_id]["reason"].startswith("collector_not_complete:"), rule_id
    assert not [rule for rule in statuses.values() if rule["status"] == "pass" and rule["rule_id"].startswith(("identity.", "ca."))]


def test_the_contract_flags_a_cut_list_that_the_manifest_does_not_record(tmp_path: Path) -> None:
    coverage = [{"collector": "identity", "name": "users", "endpoint": USERS, "item_count": 10,
                 "result_limit": 10, "collection_truncated": True, "truncation_reason": "operator_limit"}]
    (tmp_path / "coverage.json").write_text(json.dumps(coverage), encoding="utf-8")
    manifest = {"coverage_path": "coverage.json", "overall_status": "ok", "coverage_gaps": []}
    (tmp_path / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = build_validation_report(run_dir=tmp_path, required_artifacts=(), read_only=True)

    codes = {issue["code"] for issue in report["issues"]}
    assert {"truncated_list_reported_ok", "collection_gap_not_recorded"} <= codes
    assert report["valid"] is False

    manifest.update(
        overall_status="partial",
        coverage_gaps=[{"truncated_lists": [{"collector": "identity", "list": "users"}]}],
    )
    (tmp_path / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    codes = {issue["code"] for issue in build_validation_report(run_dir=tmp_path, required_artifacts=(), read_only=True)["issues"]}
    assert not ({"truncated_list_reported_ok", "collection_gap_not_recorded"} & codes)


def test_a_cut_list_raises_a_collector_issue_finding_that_names_the_limit() -> None:
    from azure_tenant_audit.findings import build_findings

    runner = CollectorRunner()
    output = runner.run(IdentityCollector(), CollectorRunContext(client=_Paged(_identity_lists(30)), top=10, page_size=10))
    diagnostics = build_diagnostics([output.result_row], output.coverage_rows, {}, "global-reader")

    findings = build_findings(diagnostics)

    users = next(item for item in findings if item["id"] == "identity:users")
    assert users["rule_id"] == "collector.issue.collector"
    assert users["error_class"] == "collection_limit"
    assert "operator row limit" in users["returned_value"]
    assert users["status"] == "open"


def test_a_bundle_written_before_gaps_were_recorded_stays_valid(tmp_path: Path) -> None:
    # The shape the previous version wrote at the default 500-row limit: the cut is flagged on an ``ok``
    # row with no reason, the run is ``ok`` and the manifest has no truncated lists.
    coverage = [{"collector": "identity", "name": "users", "endpoint": USERS, "status": "ok", "item_count": 500,
                 "result_limit": 500, "collection_limit_reached": True, "collection_truncated": True}]
    (tmp_path / "coverage.json").write_text(json.dumps(coverage), encoding="utf-8")
    manifest = {"coverage_path": "coverage.json", "overall_status": "ok", "coverage_gaps": [],
                "schema_contract_version": "2026-04-21"}
    (tmp_path / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = build_validation_report(run_dir=tmp_path, required_artifacts=(), read_only=True)

    codes = {issue["code"] for issue in report["issues"]}
    assert not ({"truncated_list_reported_ok", "collection_gap_not_recorded"} & codes)
    assert list_truncations(coverage)[0]["reason"] == REASON_OPERATOR_LIMIT
    assert list_truncations(coverage, require_reason=True) == []


# ---- findings read their own evidence, and only when it was read in full ----------------------------


def _read(*sources: str, **overrides: dict[str, Any]) -> dict[str, Any]:
    return {"normalization_coverage": {"records": [
        {"source": source, "collection_status": "collected", "complete": True, "record_count": 3, **overrides.get(source, {})}
        for source in sources
    ]}}


INTUNE_READS = ("intune_depth.deviceConfigurations", "intune_depth.deviceConfigurationAssignments")
GOVERNANCE_READS = ("identity_governance.roleAssignmentSchedules", "identity_governance.roleEligibilitySchedules")


def _rule_ids(snapshot: dict[str, Any]) -> set[str]:
    from azure_tenant_audit.findings import build_findings

    return {finding["rule_id"] for finding in build_findings([], normalized_snapshot=snapshot)}


def test_unassigned_policies_are_counted_from_intune_depth_only() -> None:
    rule = "intune_depth.policies_without_assignments"
    other_collectors = {"intune_assignment_objects": {"records": []}, "snapshot": {"object_counts": {"policies": 9}}}

    assert rule not in _rule_ids(other_collectors), "policies from conditional_access or intune say nothing about intune_depth"
    no_policies = _read(*INTUNE_READS, **{INTUNE_READS[0]: {"record_count": 0}})
    assert rule not in _rule_ids({"intune_assignment_objects": {"records": []}, **no_policies})
    assert rule in _rule_ids({"intune_assignment_objects": {"records": []}, **_read(*INTUNE_READS)})
    assert rule not in _rule_ids(
        {"intune_assignment_objects": {"records": [{"id": "a1"}]}, **_read(*INTUNE_READS)}
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"intune_depth.deviceConfigurations": {"collection_status": "failed"}},
        {"intune_depth.deviceConfigurations": {"collection_status": "limited"}},
        {"intune_depth.deviceConfigurationAssignments": {"collection_status": "failed"}},
        {"intune_depth.deviceConfigurationAssignments": {"complete": False}},
    ],
)
def test_unassigned_policies_need_both_reads_to_have_succeeded(overrides: dict[str, dict[str, Any]]) -> None:
    snapshot = {"intune_assignment_objects": {"records": []}, **_read(*INTUNE_READS, **overrides)}

    assert "intune_depth.policies_without_assignments" not in _rule_ids(snapshot)


def test_a_failed_assignment_read_does_not_open_the_unassigned_policy_finding_end_to_end() -> None:
    payload = {
        "deviceConfigurations": {"value": [{"id": "p-1", "displayName": "One"}]},
        "deviceConfigurationAssignments": {"value": []},
    }
    failed = [{"collector": "intune_depth", "name": "deviceConfigurationAssignments", "endpoint": "/p-1/assignments",
               "status": "failed", "item_count": 0, "error_class": "insufficient_permissions"}]
    ok = [{"collector": "intune_depth", "name": "deviceConfigurationAssignments", "endpoint": "/p-1/assignments",
           "status": "ok", "item_count": 0}]

    def rule_ids(coverage: list[dict[str, Any]]) -> set[str]:
        snapshot = build_normalized_snapshot(
            tenant_name="acme", run_id="r", collector_payloads={"intune_depth": payload}, coverage_rows=coverage,
            result_rows=[{"name": "intune_depth", "status": "ok", "item_count": 1}],
        )
        return _rule_ids(snapshot)

    assert "intune_depth.policies_without_assignments" not in rule_ids(failed)
    assert "intune_depth.policies_without_assignments" in rule_ids(ok)


def _intune_snapshot(policy_count: int, expanded: int, *, gap: bool) -> dict[str, Any]:
    """An intune_depth read of ``policy_count`` profiles, none assigned, of which ``expanded`` were expanded."""
    from azure_tenant_audit.collection_gaps import fanout_gap_row

    policies = [{"id": f"p-{index}", "displayName": f"Profile {index}"} for index in range(policy_count)]
    payload = {
        "deviceConfigurations": {"value": policies},
        "deviceConfigurationAssignments": {
            "value": [{"policyId": row["id"], "displayName": row["displayName"], "assignments": []} for row in policies[:expanded]]
        },
    }
    coverage = [
        {"collector": "intune_depth", "name": "deviceConfigurations", "endpoint": "/deviceManagement/deviceConfigurations",
         "status": "ok", "item_count": policy_count},
        *[
            {"collector": "intune_depth", "name": "deviceConfigurationAssignments", "endpoint": f"/{row['id']}/assignments",
             "status": "ok", "item_count": 0}
            for row in policies[:expanded]
        ],
    ]
    if gap:
        coverage.append(
            fanout_gap_row("intune_depth", "deviceConfigurationAssignmentsFanout", total=policy_count, expanded=expanded,
                           scope="Device configuration assignments")
        )
    return build_normalized_snapshot(
        tenant_name="acme", run_id="r", collector_payloads={"intune_depth": payload}, coverage_rows=coverage,
        result_rows=[{"name": "intune_depth", "status": "partial" if gap else "ok", "item_count": policy_count}],
    )


def test_unassigned_profiles_are_not_reported_from_a_fan_out_that_stopped_early() -> None:
    from azure_tenant_audit.baselines import intune_assignments_are_a_sample, rule_inputs_gap

    rule = "intune_depth.policies_without_assignments"
    complete = _intune_snapshot(3, 3, gap=False)
    cut = _intune_snapshot(12, 10, gap=True)
    cut_without_gap_row = _intune_snapshot(12, 10, gap=False)

    assert rule in _rule_ids(complete) and not intune_assignments_are_a_sample(complete)
    assert rule_inputs_gap(rule, complete) is None
    for snapshot in (cut, cut_without_gap_row):
        assert intune_assignments_are_a_sample(snapshot)
        assert rule not in _rule_ids(snapshot), "the 2 profiles never expanded may well be assigned"
        assert rule_inputs_gap(rule, snapshot) == "policy_assignments_not_read_for_every_policy"


def test_a_conditional_access_only_tenant_gets_no_device_management_finding() -> None:
    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads={
            "conditional_access": {
                "conditionalAccessPolicies": {"value": [{"id": "ca-1", "displayName": "MFA", "state": "enabled", "conditions": {}, "grantControls": {"builtInControls": ["mfa"]}}]}
            },
            "auth_methods": {"authenticationMethodsPolicy": {"value": [{"id": "a-1"}]}},
        },
        result_rows=[{"name": "conditional_access", "status": "ok", "item_count": 1}],
    )

    assert snapshot["snapshot"]["object_counts"]["policies"] > 0
    assert "intune_depth.policies_without_assignments" not in _rule_ids(snapshot)


def test_the_identity_controls_sample_no_longer_fails_the_endpoints_pillar(tmp_path: Path) -> None:
    from azure_tenant_audit.cli import run_offline

    sample = Path(__file__).resolve().parents[1] / "examples" / "sample_audit_bundle" / "identity_controls_result.json"
    assert run_offline(sample, tmp_path, "t", "ic", auditor_profile="global-reader", plane="inventory") in {0, 1}

    run_dir = tmp_path / "t-ic"
    findings = json.loads((run_dir / "findings" / "findings.json").read_text(encoding="utf-8"))
    assert "intune_depth.policies_without_assignments" not in {item["rule_id"] for item in findings}
    report_pack = json.loads((run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))
    alignment = report_pack.get("baseline_alignment") or report_pack["summary"]["baseline_alignment"]
    endpoints = next(c for c in alignment["frameworks"]["ms_zero_trust"]["controls"] if c["control_id"] == "endpoints")
    assert endpoints["status"] != "fail"


def _intune_alignment(snapshot: dict[str, Any] | None, *, findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    rule = "intune_depth.policies_without_assignments"
    alignment = build_baseline_alignment(
        findings or [],
        normalized_snapshot=snapshot,
        coverage_ledger=[{"collector": "intune_depth", "coverage_status": "complete_exact_scope"}],
        mappings={rule: {"cis_m365_v7": ["T.1"]}},
    )
    (control,) = alignment["frameworks"]["cis_m365_v7"]["controls"]
    (status,) = control["rule_statuses"]
    return status


def test_the_unassigned_policy_rule_is_fail_closed_in_baselines() -> None:
    assert _intune_alignment(_read(*INTUNE_READS))["status"] == "pass"
    cases = [
        (None, "inputs_not_available"),
        (_read(), "device_configurations_not_collected"),
        (_read(INTUNE_READS[0], **{INTUNE_READS[0]: {"record_count": 0}}), "no_device_configurations"),
        (_read(INTUNE_READS[0], **{INTUNE_READS[0]: {"collection_status": "failed"}}), "device_configurations_not_read_in_full"),
        (_read(INTUNE_READS[0]), "policy_assignments_not_read_in_full"),
        (_read(*INTUNE_READS, **{INTUNE_READS[1]: {"collection_status": "failed"}}), "policy_assignments_not_read_in_full"),
    ]
    for snapshot, reason in cases:
        status = _intune_alignment(snapshot)
        assert (status["status"], status["evaluated"], status["reason"]) == ("not_assessed", False, reason)
    failing = _intune_alignment(None, findings=[{"id": "x", "rule_id": "intune_depth.policies_without_assignments", "status": "open"}])
    assert failing["status"] == "fail"


def test_standing_privilege_needs_a_successful_empty_eligibility_read() -> None:
    rule = "identity_governance.standing_privilege_only"
    base = {"governance_objects": {"records": [{"kind": "role_assignment_schedule"}]}}

    assert rule in _rule_ids({**base, **_read(*GOVERNANCE_READS)})
    failed = _read(*GOVERNANCE_READS, **{GOVERNANCE_READS[1]: {"collection_status": "failed"}})
    assert rule not in _rule_ids({**base, **failed})
    assert rule not in _rule_ids(base), "no normalization coverage means the read cannot be vouched for"
    eligible = {"governance_objects": {"records": [{"kind": "role_assignment_schedule"}, {"kind": "role_eligibility_schedule"}]}}
    assert rule not in _rule_ids({**eligible, **_read(*GOVERNANCE_READS)})


def test_a_failed_eligibility_read_does_not_open_standing_privilege_end_to_end() -> None:
    assignments = {"value": [{"id": "a1", "principalId": "u1"}]}

    def rule_ids(eligibility: dict[str, Any], coverage: list[dict[str, Any]]) -> set[str]:
        snapshot = build_normalized_snapshot(
            tenant_name="acme", run_id="r",
            collector_payloads={"identity_governance": {"roleAssignmentSchedules": assignments, "roleEligibilitySchedules": eligibility}},
            coverage_rows=coverage, result_rows=[{"name": "identity_governance", "status": "partial", "item_count": 1}],
        )
        return _rule_ids(snapshot)

    gated = {"error": "needs P2", "error_class": "license_required", "value": []}
    rule = "identity_governance.standing_privilege_only"

    assert rule not in rule_ids(gated, [{"collector": "identity_governance", "name": "roleEligibilitySchedules", "status": "failed"}])
    assert rule in rule_ids({"value": []}, [])


# ---- per-object fan-outs are gaps when they expand only the first ten --------------------------------


class _Fanout:
    """Graph client for the collectors that read a list and then one call per object."""

    def __init__(self, lists: dict[str, list[dict[str, Any]]]) -> None:
        self.lists = lists

    def iter_items(self, endpoint: str, params: Any = None, result_limit: int | None = None):
        rows = self.lists.get(endpoint, [])
        return iter(rows if result_limit is None else rows[:result_limit])

    def get_json(self, path: str, params: Any = None, full_url: bool = False) -> dict[str, Any]:
        return {"sharingCapability": "disabled"}

    def get_all(self, path: str, params: Any = None) -> list[dict[str, Any]]:
        return []


@pytest.mark.parametrize(
    ("collector", "endpoint", "fanout"),
    [
        ("sharepoint_access", "/sites", "sitePermissionsFanout"),
        ("intune_depth", "/deviceManagement/deviceConfigurations", "deviceConfigurationAssignmentsFanout"),
        ("teams", "/groups", "teamChannelsFanout"),
    ],
)
def test_a_fanout_that_expands_only_ten_objects_is_a_gap(collector: str, endpoint: str, fanout: str) -> None:
    from azure_tenant_audit.collectors import REGISTRY

    def run(count: int) -> Any:
        rows = [{"id": f"o-{i}", "displayName": f"O{i}"} for i in range(count)]
        return REGISTRY[collector].run({"client": _Fanout({endpoint: rows}), "top": None})

    complete = run(10)
    sampled = run(11)

    assert complete.status == "ok"
    assert not [row for row in complete.coverage if row["name"] == fanout]
    assert sampled.status == "partial"
    row = next(row for row in sampled.coverage if row["name"] == fanout)
    assert (row["status"], row["collection_truncated"], row["truncation_reason"]) == ("partial", True, "fanout_limit")
    assert (row["fanout_total"], row["fanout_limit"]) == (11, 10)
    assert list_truncations(sampled.coverage) == [
        {"collector": collector, "list": fanout, "rows_collected": 10, "reason": "fanout_limit"}
    ]
    snapshot = build_normalized_snapshot(
        tenant_name="acme", run_id="r", collector_payloads={collector: sampled.payload}, coverage_rows=sampled.coverage,
        result_rows=[{"name": collector, "status": "partial", "item_count": sampled.item_count}],
    )
    assert f"{collector}.{fanout}" in {item["source"] for item in snapshot["collection_gaps"]["records"]}


def test_a_site_ownership_rule_is_not_assessed_when_only_ten_sites_were_read() -> None:
    from azure_tenant_audit.collectors.sharepoint_access import SharePointAccessCollector

    rows = [{"id": f"s-{i}", "displayName": f"S{i}"} for i in range(11)]
    output = CollectorRunner().run(
        SharePointAccessCollector(), CollectorRunContext(client=_Fanout({"/sites": rows}), top=None, page_size=100)
    )
    diagnostics = build_diagnostics([output.result_row], output.coverage_rows, {}, "global-reader")
    ledger = build_coverage_ledger(
        capability_rows=[{"collector": "sharepoint_access", "status": "supported_exact_scope"}],
        result_rows=[output.result_row],
        diagnostics=diagnostics,
    )

    alignment = build_baseline_alignment(
        [], coverage_ledger=ledger, mappings={"sharepoint.site_orphaned": {"cis_m365_v7": ["T.1"]}}
    )

    (control,) = alignment["frameworks"]["cis_m365_v7"]["controls"]
    assert control["rule_statuses"][0]["status"] == "not_assessed"
    assert control["rule_statuses"][0]["reason"] == "collector_not_complete:sharepoint_access"


# ---- an absolute first URL is checked like every next link -------------------------------------------


@pytest.mark.parametrize(
    "url",
    ["https://attacker.example/v1.0/users", "http://graph.microsoft.com/v1.0/users", "https://graph.microsoft.com.evil.example/users"],
)
def test_an_absolute_first_url_outside_graph_is_refused_before_any_request(url: str) -> None:
    client, requested = _graph_client({})

    with pytest.raises(GraphError) as refused:
        list(client.iter_items(url))

    assert refused.value.error_code == NEXT_LINK_REFUSED
    assert requested == []


def test_an_absolute_graph_first_url_is_still_followed() -> None:
    beta = "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPCs"
    client, requested = _graph_client({beta: {"value": [{"id": "pc-1"}]}})

    assert list(client.iter_items(beta)) == [{"id": "pc-1"}]
    assert requested == [beta]


# ---- probes sample in every collector that cuts lists ------------------------------------------------


def test_a_probe_does_not_record_a_reports_usage_cut_as_a_gap() -> None:
    from azure_tenant_audit.collectors.reports_usage import ReportsUsageCollector

    csv_text = "User Principal Name\n" + "\n".join(f"u{i}@example.com" for i in range(30)) + "\n"

    class Client:
        def get_json(self, path: str, params: Any = None) -> dict[str, Any]:
            return {"displayConcealedNames": False}

        def get_content(self, path: str, params: Any = None) -> str:
            return csv_text

    with sample_only():
        sampled = ReportsUsageCollector().run({"client": Client(), "top": 5})
    limited = ReportsUsageCollector().run({"client": Client(), "top": 5})

    usage = [row for row in sampled.coverage if row["name"] == "mailboxUsageDetail"][0]
    assert (usage["item_count"], usage["bounded_sample"], usage["status"]) == (5, True, "ok")
    assert sampled.status == "ok"
    assert list_truncations(sampled.coverage) == []
    assert limited.status == "partial"
    assert list_truncations(limited.coverage)[0]["reason"] == REASON_OPERATOR_LIMIT


def test_a_probe_does_not_record_a_directory_relationship_cut_as_a_gap() -> None:
    import uuid

    from azure_tenant_audit.collectors.directory_relationships import DirectoryRelationshipsCollector

    groups = [{"id": str(uuid.UUID(int=i + 1)), "displayName": f"G{i}"} for i in range(20)]
    apps = [{"id": str(uuid.UUID(int=100 + i)), "displayName": f"A{i}"} for i in range(20)]
    client = _Streaming({"/groups": groups, "/applications": apps})

    with sample_only():
        sampled = DirectoryRelationshipsCollector().run({"client": client, "top": 5})
    limited = DirectoryRelationshipsCollector().run({"client": client, "top": 5})

    assert sampled.status == "ok"
    assert [row for row in sampled.coverage if row.get("bounded_sample")]
    assert list_truncations(sampled.coverage) == []
    assert limited.status == "partial"
    assert {item["reason"] for item in list_truncations(limited.coverage)} == {REASON_OPERATOR_LIMIT}


# ---- an unchunked read keeps the rows it had when a later page fails ---------------------------------


def test_an_unchunked_read_keeps_its_prefix_and_marks_the_failed_page() -> None:
    class Client:
        def iter_items(self, endpoint: str, params: Any = None, result_limit: int | None = None):
            yield from _rows("u", 4)
            raise GraphError("later page failed", status=503)

    payload, coverage = run_graph_endpoints("identity", Client(), {"users": {"endpoint": USERS}}, None)

    row = coverage[0]
    assert payload["users"]["value"] == _rows("u", 4)
    assert row["status"] == "failed"
    assert row["item_count"] == 4
    assert row["collection_truncated"] is True
    assert row["truncation_reason"] == REASON_PAGINATION_FAILED
    assert payload["users"]["truncation_reason"] == REASON_PAGINATION_FAILED
