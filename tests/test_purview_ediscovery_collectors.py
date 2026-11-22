from __future__ import annotations

from azure_tenant_audit.collectors.ediscovery import EDiscoveryCollector
from azure_tenant_audit.collectors.purview import PurviewCollector


class _FakeM365Adapter:
    def __init__(self, responses: dict[str, dict[str, object]]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def run(self, command: str, log_event=None) -> dict[str, object]:
        self.calls.append(command)
        for key in self.responses:
            if key in command:
                return self.responses[key].copy()
        return {"error": "command_not_simulated", "error_class": "command_not_simulated", "command": command}


class _FakeGraphClient:
    def __init__(self, responses: dict[str, list[dict[str, object]]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, tuple[tuple[str, object], ...]]] = []

    def get_all(self, path: str, params: dict[str, object] | None = None) -> list[dict[str, object]]:
        self.calls.append((path, tuple(sorted((params or {}).items()))))
        return list(self.responses.get(path, []))


def test_purview_collector_inventory_plane_runs_inventory_commands_only(monkeypatch) -> None:
    adapter = _FakeM365Adapter(
        responses={
            "m365 purview auditlog list": {"value": [{"status": "ready"}]},
            "m365 purview retentionlabel list": {"value": [{"name": "Confidential"}]},
            "m365 purview retention policy list": {"value": [{"name": "General Retention"}]},
            "m365 purview dlp policy list": {"value": [{"name": "PII"}]},
        }
    )
    monkeypatch.setattr("azure_tenant_audit.collectors.purview.get_adapter", lambda _name: adapter)

    collector = PurviewCollector()
    result = collector.run(
        {
            "client": object(),
            "top": 10,
            "page_size": None,
            "plane": "inventory",
            "audit_logger": None,
        }
    )

    assert result.status == "ok"
    assert "purviewReadiness" in result.payload
    assert "retentionLabels" in result.payload
    assert "retentionPolicies" in result.payload
    assert "dlpPolicies" in result.payload
    assert "auditLogJobs" not in result.payload
    assert "auditLogExports" not in result.payload
    assert any("purview auditlog list" in command for command in adapter.calls)
    assert not any("auditlog export" in command for command in adapter.calls)


def test_purview_collector_export_plane_adds_export_family(monkeypatch) -> None:
    adapter = _FakeM365Adapter(
        responses={
            "m365 purview auditlog list": {"value": [{"status": "ready"}]},
            "m365 purview retentionlabel list": {"value": [{"name": "Confidential"}]},
            "m365 purview retention policy list": {"value": [{"name": "General Retention"}]},
            "m365 purview dlp policy list": {"value": [{"name": "PII"}]},
        }
    )
    monkeypatch.setattr("azure_tenant_audit.collectors.purview.get_adapter", lambda _name: adapter)

    collector = PurviewCollector()
    result = collector.run(
        {
            "client": object(),
            "top": 10,
            "page_size": None,
            "plane": "full",
            "audit_logger": None,
        }
    )

    assert result.status == "ok"
    assert "auditLogJobs" in result.payload
    assert "auditLogExports" in result.payload
    assert len(result.payload["auditLogJobs"]["value"]) == 1
    assert len(result.payload["auditLogExports"]["value"]) == 1
    # Only the documented read-only listing runs. The speculative "audit-log search" / "auditlog search"
    # variants (a search submits a query job) and "auditlog export create" (creates an export) were removed.
    assert any("purview auditlog list --output json --top 100" in command for command in adapter.calls)
    assert not any("search" in command for command in adapter.calls if "ediscovery" not in command)
    assert not any("export create" in command for command in adapter.calls)
    assert all(command.rstrip().split(" --")[0].split()[-1] in {"list", "get", "status"} for command in adapter.calls)


def test_purview_commands_are_all_read_only_and_drop_speculative_variants() -> None:
    from azure_tenant_audit.adapters.read_guard import check_command

    commands = [command for entry in PurviewCollector.command_collectors for command in entry["commands"]]

    for command in commands:
        check_command("m365_cli", command)  # raises CommandRefused for anything that is not a read
    for removed in (
        "m365 purview audit-log search --output json",
        "m365 purview auditlog search --output json",
        "m365 purview auditlog export create --output json --help",
        "m365 purview",
    ):
        assert removed not in commands


def test_purview_optional_readiness_command_failure_isolated(monkeypatch) -> None:
    adapter = _FakeM365Adapter(
        responses={
            "m365 purview retentionlabel list": {"value": [{"name": "Confidential"}]},
            "m365 purview retention policy list": {"value": [{"name": "General Retention"}]},
            "m365 purview dlp policy list": {"value": [{"name": "PII"}]},
        }
    )
    monkeypatch.setattr("azure_tenant_audit.collectors.purview.get_adapter", lambda _name: adapter)

    collector = PurviewCollector()
    result = collector.run(
        {
            "client": object(),
            "top": 10,
            "page_size": None,
            "plane": "inventory",
            "audit_logger": None,
        }
    )

    # readiness command is optional; failure should not make inventory collection partial.
    assert result.status == "ok"
    assert result.payload["purviewReadiness"]["error_class"] == "command_optional_failure"
    assert result.payload["purviewReadiness"]["error"] == "command_output_parse_error"


def test_purview_export_operations_respect_checkpoint_state(monkeypatch) -> None:
    adapter = _FakeM365Adapter(
        responses={
            "m365 purview auditlog list --output json --help": {"value": [{"status": "ready"}]},
            "m365 purview retentionlabel list": {"value": [{"name": "Confidential"}]},
            "m365 purview retention policy list": {"value": [{"name": "General Retention"}]},
            "m365 purview dlp policy list": {"value": [{"name": "PII"}]},
        }
    )
    monkeypatch.setattr("azure_tenant_audit.collectors.purview.get_adapter", lambda _name: adapter)

    callback_calls = []

    def write_export_checkpoint(collector_name: str, operation: str, status: str, item_count: int, message: str, **extra) -> None:
        callback_calls.append(("checkpoint", collector_name, operation, status, item_count, message, extra))

    callback_records = []

    def write_export_records(
        collector_name: str, operation_name: str, page_number: int, records: list[dict], metadata: dict | None = None
    ) -> str:
        callback_records.append((collector_name, operation_name, page_number, len(records), metadata))
        return "raw-record-path"

    def write_export_summary(collector_name: str, operation_name: str, payload: dict) -> str:
        callback_records.append(("summary", collector_name, operation_name, payload))
        return "raw-summary-path"

    collector = PurviewCollector()
    result = collector.run(
        {
            "client": object(),
            "top": 10,
            "page_size": 2,
            "plane": "full",
            "audit_logger": None,
            "operation_checkpoint_state": {
                "auditLogJobs": {"status": "ok", "item_count": 1},
                "auditLogExports": {"status": "ok", "item_count": 1},
            },
            "write_export_checkpoint": write_export_checkpoint,
            "write_export_records": write_export_records,
            "write_export_summary": write_export_summary,
        }
    )

    assert result.status == "ok"
    assert len(callback_calls) == 0
    assert len(callback_records) == 0
    assert result.payload["auditLogJobs"]["status"] == "ok"
    assert result.payload["auditLogExports"]["status"] == "ok"


def test_purview_export_operations_invoke_export_callbacks(monkeypatch) -> None:
    adapter = _FakeM365Adapter(
        responses={
            "m365 purview auditlog list": {"value": [{"status": "ready"}]},
            "m365 purview retentionlabel list": {"value": [{"name": "Confidential"}]},
            "m365 purview retention policy list": {"value": [{"name": "General Retention"}]},
            "m365 purview dlp policy list": {"value": [{"name": "PII"}]},
        }
    )
    monkeypatch.setattr("azure_tenant_audit.collectors.purview.get_adapter", lambda _name: adapter)

    callback_calls = []

    def write_export_checkpoint(collector_name: str, operation: str, status: str, item_count: int, message: str, **extra) -> None:
        callback_calls.append(("checkpoint", collector_name, operation, status, item_count, message, extra))

    exported_paths = []

    def write_export_records(
        collector_name: str, operation_name: str, page_number: int, records: list[dict], metadata: dict | None = None
    ) -> str:
        exported_paths.append((collector_name, operation_name, page_number, metadata))
        return f"{collector_name}/{operation_name}/{page_number}"

    def write_export_summary(collector_name: str, operation_name: str, payload: dict) -> str:
        exported_paths.append(("summary", collector_name, operation_name, payload))
        return f"{collector_name}/{operation_name}/summary.json"

    collector = PurviewCollector()
    result = collector.run(
        {
            "client": object(),
            "top": 10,
            "page_size": 2,
            "plane": "full",
            "audit_logger": None,
            "operation_checkpoint_state": {},
            "write_export_checkpoint": write_export_checkpoint,
            "write_export_records": write_export_records,
            "write_export_summary": write_export_summary,
        }
    )

    assert result.status == "ok"
    assert len(exported_paths) >= 2
    assert any(item[0] == "summary" for item in exported_paths)
    assert any(item[1] == "auditLogJobs" for item in exported_paths if item[0] != "summary")
    assert any(item[1] == "auditLogExports" for item in exported_paths if item[0] != "summary")
    assert any(item[2] == "auditLogJobs" for item in callback_calls)
    assert any(item[2] == "auditLogExports" for item in callback_calls)


def test_ediscovery_export_operations_respect_checkpoint_state(monkeypatch) -> None:
    adapter = _FakeM365Adapter(
        responses={
            "m365 purview ediscovery case list": {"value": [{"id": "case-1"}]},
            "m365 purview ediscovery search list": {"value": [{"id": "search-1"}]},
            "m365 purview hold list": {"value": [{"id": "hold-1"}]},
            "m365 purview ediscoveryexport list": {"value": [{"id": "export-job-1"}]},
            "m365 purview ediscovery review list": {"value": [{"id": "reviewset-1"}]},
            "m365 purview ediscovery reviewset list": {"value": [{"id": "reviewset-1"}]},
        }
    )
    monkeypatch.setattr("azure_tenant_audit.collectors.ediscovery.get_adapter", lambda _name: adapter)

    callback_count = []

    def write_export_checkpoint(collector_name: str, operation: str, status: str, item_count: int, message: str, **extra) -> None:
        callback_count.append((collector_name, operation, status, item_count, message, extra))

    callback_records = []

    def write_export_records(
        collector_name: str, operation_name: str, page_number: int, records: list[dict], metadata: dict | None = None
    ) -> str:
        callback_records.append((collector_name, operation_name, page_number, len(records)))
        return f"{collector_name}/{operation_name}/{page_number}"

    def write_export_summary(collector_name: str, operation_name: str, payload: dict) -> str:
        callback_records.append(("summary", collector_name, operation_name, payload))
        return f"{collector_name}/{operation_name}/summary.json"

    collector = EDiscoveryCollector()
    result = collector.run(
        {
            "client": _FakeGraphClient(
                responses={
                    "/security/cases/ediscoveryCases": [{"id": "case-1"}],
                    "/security/cases/ediscoveryCases/case-1/searches": [],
                    "/security/cases/ediscoveryCases/case-1/operations": [],
                }
            ),
            "top": 10,
            "page_size": 2,
            "plane": "full",
            "audit_logger": None,
                "operation_checkpoint_state": {
                    "exportJobs": {"status": "ok", "item_count": 1},
                    "reviewSets": {"status": "ok", "item_count": 1},
                },
            "write_export_checkpoint": write_export_checkpoint,
            "write_export_records": write_export_records,
            "write_export_summary": write_export_summary,
        }
    )

    assert result.status == "ok"
    assert len(callback_count) == 0
    assert len(callback_records) == 0
    assert result.payload["exportJobs"]["source"] == "checkpoint"


def test_ediscovery_export_operations_invoke_export_callbacks(monkeypatch) -> None:
    adapter = _FakeM365Adapter(
        responses={
            "m365 purview ediscoveryexport list": {"value": [{"id": "export-job-1"}]},
            "m365 purview ediscovery reviewset list": {"value": [{"id": "reviewset-1"}]},
            "m365 purview ediscovery case list": {"value": [{"id": "case-1"}]},
            "m365 purview ediscovery search list": {"value": [{"id": "search-1"}]},
            "m365 purview hold list": {"value": []},
        }
    )
    monkeypatch.setattr("azure_tenant_audit.collectors.ediscovery.get_adapter", lambda _name: adapter)

    callback_count = []

    def write_export_checkpoint(collector_name: str, operation: str, status: str, item_count: int, message: str, **extra) -> None:
        callback_count.append((collector_name, operation, status, item_count, message))

    callback_records = []

    def write_export_records(
        collector_name: str, operation_name: str, page_number: int, records: list[dict], metadata: dict | None = None
    ) -> str:
        callback_records.append((collector_name, operation_name, page_number, len(records)))
        return f"{collector_name}/{operation_name}/{page_number}"

    def write_export_summary(collector_name: str, operation_name: str, payload: dict) -> str:
        callback_records.append(("summary", collector_name, operation_name, payload))
        return f"{collector_name}/{operation_name}/summary.json"

    collector = EDiscoveryCollector()
    result = collector.run(
        {
            "client": _FakeGraphClient(
                responses={
                    "/security/cases/ediscoveryCases": [{"id": "case-1"}],
                    "/security/cases/ediscoveryCases/case-1/searches": [{"id": "search-case-1"}],
                    "/security/cases/ediscoveryCases/case-1/operations": [{"id": "operation-case-1"}],
                }
            ),
            "top": 10,
            "page_size": 2,
            "plane": "full",
            "audit_logger": None,
            "operation_checkpoint_state": {},
            "write_export_checkpoint": write_export_checkpoint,
            "write_export_records": write_export_records,
            "write_export_summary": write_export_summary,
        }
    )

    assert result.status == "ok"
    assert any(item[1] == "exportJobs" for item in callback_count)
    assert any(item[1] == "reviewSets" for item in callback_count)
    assert any(item[0] == "summary" for item in callback_records)


def test_ediscovery_collector_inventory_plane_skips_export_collectors(monkeypatch) -> None:
    adapter = _FakeM365Adapter(
        responses={
            "m365 purview ediscovery case list": {"value": [{"id": "case-1"}]},
            "m365 purview ediscovery search list": {"value": [{"id": "search-1"}]},
            "m365 purview hold list": {"value": [{"id": "hold-1"}]},
        }
    )
    monkeypatch.setattr("azure_tenant_audit.collectors.ediscovery.get_adapter", lambda _name: adapter)

    client = _FakeGraphClient(
        responses={
            "/security/cases/ediscoveryCases": [{"id": "case-1"}],
            "/security/cases/ediscoveryCases/case-1/searches": [{"id": "search-case-1"}],
            "/security/cases/ediscoveryCases/case-1/operations": [{"id": "op-case-1"}],
        }
    )
    collector = EDiscoveryCollector()
    result = collector.run(
        {
            "client": client,
            "top": 250,
            "page_size": None,
            "plane": "inventory",
            "audit_logger": None,
        }
    )

    assert result.status == "ok"
    assert "caseOverview" in result.payload
    assert "searchList" in result.payload
    assert "holdList" in result.payload
    assert "cases" in result.payload
    assert "exportJobs" not in result.payload
    assert "reviewSets" not in result.payload
    assert len(client.calls) >= 3
    assert any("case list" in command for command in adapter.calls)


def test_ediscovery_collector_full_plane_includes_export_commands(monkeypatch) -> None:
    adapter = _FakeM365Adapter(
        responses={
            "m365 purview ediscovery case list": {"value": [{"id": "case-1"}]},
            "m365 purview ediscovery search list": {"value": [{"id": "search-1"}]},
            "m365 purview hold list": {"value": [{"id": "hold-1"}]},
            "m365 purview ediscoveryexport list": {"value": [{"id": "export-job-1"}]},
            "m365 purview ediscovery reviewset list": {"value": [{"id": "reviewset-1"}]},
        }
    )
    monkeypatch.setattr("azure_tenant_audit.collectors.ediscovery.get_adapter", lambda _name: adapter)

    client = _FakeGraphClient(
        responses={
            "/security/cases/ediscoveryCases": [{"id": "case-1"}],
            "/security/cases/ediscoveryCases/case-1/searches": [{"id": "search-case-1"}],
            "/security/cases/ediscoveryCases/case-1/operations": [{"id": "op-case-1"}],
        }
    )
    collector = EDiscoveryCollector()
    result = collector.run(
        {
            "client": client,
            "top": 250,
            "page_size": None,
            "plane": "full",
            "audit_logger": None,
        }
    )

    assert result.status == "ok"
    assert "exportJobs" in result.payload
    assert "reviewSets" in result.payload
    assert any("ediscoveryexport list" in command for command in adapter.calls)
    assert any("reviewset list" in command for command in adapter.calls)


def test_ediscovery_collector_marks_partial_when_export_job_fails(monkeypatch) -> None:
    adapter = _FakeM365Adapter(
        responses={
            "m365 purview ediscovery case list": {"value": [{"id": "case-1"}]},
            "m365 purview ediscovery search list": {"value": [{"id": "search-1"}]},
            "m365 purview hold list": {"value": [{"id": "hold-1"}]},
            "m365 purview ediscoveryexport list": {"error": "forbidden", "error_class": "insufficient_permissions"},
        }
    )
    monkeypatch.setattr("azure_tenant_audit.collectors.ediscovery.get_adapter", lambda _name: adapter)

    client = _FakeGraphClient(
        responses={
            "/security/cases/ediscoveryCases": [{"id": "case-1"}],
            "/security/cases/ediscoveryCases/case-1/searches": [{"id": "search-case-1"}],
            "/security/cases/ediscoveryCases/case-1/operations": [{"id": "op-case-1"}],
        }
    )
    collector = EDiscoveryCollector()
    result = collector.run(
        {
            "client": client,
            "top": 250,
            "page_size": None,
            "plane": "full",
            "audit_logger": None,
        }
    )

    assert result.status == "partial"
    failed_rows = [row for row in (result.coverage or []) if row["name"] == "exportJobs"]
    assert failed_rows and failed_rows[0]["status"] == "failed"
    assert failed_rows[0]["error_class"] == "insufficient_permissions"


# ----- R107: the retired CLI operations are named skips, not command_not_found failures -----


def _skips(result) -> dict[str, dict[str, object]]:
    return {row["name"]: row for row in result.coverage if row.get("type") == "command"}


def test_r107_purview_records_retired_cli_operations_as_named_skips() -> None:
    result = PurviewCollector().run({"plane": "inventory", "audit_logger": None})

    rows = _skips(result)
    for name in ("retentionLabels", "retentionPolicies", "dlpPolicies"):
        assert rows[name]["status"] == "skipped", name
        assert rows[name]["reason"] == "m365_cli_not_used"
        assert rows[name]["error_class"] is None
    assert result.status == "ok"


def test_r107_ediscovery_records_retired_cli_operations_as_named_skips() -> None:
    result = EDiscoveryCollector().run(
        {"client": _FakeGraphClient(responses={}), "top": None, "page_size": None, "plane": "inventory", "audit_logger": None}
    )

    rows = _skips(result)
    for name in ("caseOverview", "searchList", "holdList"):
        assert rows[name]["status"] == "skipped", name
        assert rows[name]["reason"] == "m365_cli_not_used"
        assert rows[name]["error_class"] is None
    assert result.status == "ok"


# ----- R108: the case fan-out reads every case of a chunked list and the Graph cases are normalised -----


class _PagedGraphClient(_FakeGraphClient):
    """Pages lists through ``iter_pages`` so the collector streams them to chunk files, as a live run does."""

    def iter_pages(self, endpoint: str, params: dict[str, object] | None = None):
        self.calls.append((endpoint, tuple(sorted((params or {}).items()))))
        rows = list(self.responses.get(endpoint, []))
        for start in range(0, max(len(rows), 1), 100):
            yield {"value": rows[start:start + 100]}

    def iter_items(self, endpoint: str, params: dict[str, object] | None = None, result_limit: int | None = None):
        rows = list(self.responses.get(endpoint, []))
        return iter(rows if result_limit is None else rows[:result_limit])

    def get_json(self, path: str, params: object = None, full_url: bool = False) -> dict[str, object]:
        return {"value": []}


def _chunk_writer(root):
    import json

    def write(collector: str, name: str, page: int, rows: list[dict[str, object]], metadata: object = None) -> str:
        relative = f"chunks/{collector}/{name}-{page:05d}.jsonl"
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        return relative

    return write


def _run_cases(tmp_path, count: int):
    cases = [{"id": f"case-{index}", "displayName": f"Case {index}", "status": "active"} for index in range(count)]
    client = _PagedGraphClient(responses={"/security/cases/ediscoveryCases": cases})
    result = EDiscoveryCollector().run(
        {
            "client": client,
            "top": None,
            "page_size": 100,
            "plane": "inventory",
            "audit_logger": None,
            "chunk_writer": _chunk_writer(tmp_path),
            "run_dir": tmp_path,
        }
    )
    return result


def test_r108_case_fanout_reads_every_case_of_a_chunked_list(tmp_path) -> None:
    result = _run_cases(tmp_path, 25)

    assert result.payload["cases"]["item_count"] == 25
    assert len(result.payload["cases"]["value"]) < 25  # only the inline sample is kept in the payload
    assert len([name for name in result.payload if name.startswith("case_")]) == 25
    assert not [row for row in result.coverage if row.get("collection_truncated")]


def test_r108_case_fanout_past_its_limit_records_a_gap(tmp_path) -> None:
    from azure_tenant_audit.collectors.ediscovery import CASE_FANOUT_LIMIT

    result = _run_cases(tmp_path, CASE_FANOUT_LIMIT + 3)

    assert len([name for name in result.payload if name.startswith("case_")]) == CASE_FANOUT_LIMIT
    (gap,) = [row for row in result.coverage if row.get("collection_truncated")]
    assert gap["type"] == "derived" and gap["fanout_total"] == CASE_FANOUT_LIMIT + 3


def test_r108_graph_cases_and_searches_are_normalised() -> None:
    from azure_tenant_audit.normalize import build_normalized_snapshot

    payload = {
        "cases": {"value": [{"id": "case-1", "displayName": "Board matter", "status": "active", "createdDateTime": "2026-11-01T00:00:00Z"}]},
        "case_case-1": {
            "searches": {"value": [{"id": "search-1", "displayName": "Mailboxes"}]},
            "operations": {"value": []},
        },
    }
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="run-1", collector_payloads={"ediscovery": payload})

    (case,) = snapshot["ediscovery_cases"]["records"]
    assert case["id"] == "case-1" and case["display_name"] == "Board matter" and case["status"] == "active"
    (search,) = snapshot["ediscovery_searches"]["records"]
    assert search["id"] == "search-1" and search["case_id"] == "case-1"


def test_each_case_streams_its_searches_to_its_own_chunk_files(tmp_path) -> None:
    """Bot review of PR #148: two cases must not share, and overwrite, one searches chunk file."""
    from azure_tenant_audit.normalize import build_normalized_snapshot

    client = _PagedGraphClient(
        responses={
            "/security/cases/ediscoveryCases": [{"id": "c1", "displayName": "One"}, {"id": "c2", "displayName": "Two"}],
            "/security/cases/ediscoveryCases/c1/searches": [{"id": "s1", "displayName": "First"}],
            "/security/cases/ediscoveryCases/c2/searches": [{"id": "s2", "displayName": "Second"}],
        }
    )
    result = EDiscoveryCollector().run(
        {
            "client": client,
            "top": None,
            "page_size": 100,
            "plane": "inventory",
            "audit_logger": None,
            "chunk_writer": _chunk_writer(tmp_path),
            "run_dir": tmp_path,
        }
    )
    files = [result.payload[f"case_{case}"]["searches"].get("chunk_files") for case in ("c1", "c2")]
    assert files[0] and files[1] and set(files[0]).isdisjoint(files[1])

    snapshot = build_normalized_snapshot(
        tenant_name="acme", run_id="run-1", collector_payloads={"ediscovery": result.payload}, run_dir=tmp_path
    )
    searches = sorted((row["case_id"], row["id"]) for row in snapshot["ediscovery_searches"]["records"])
    assert searches == [("c1", "s1"), ("c2", "s2")]
