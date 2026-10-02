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
            "m365 purview audit-log search": {"value": [{"id": "log-job-1"}]},
            "m365 purview auditlog export create": {"value": [{"id": "export-1"}]},
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
    assert any("audit-log search" in command for command in adapter.calls)
    assert any("auditlog export create" in command for command in adapter.calls)


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
            "m365 purview audit-log search": {"value": [{"id": "log-job-1"}]},
            "m365 purview auditlog export create": {"value": [{"id": "export-1"}]},
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
            "m365 purview auditlog list --output json --help": {"value": [{"status": "ready"}]},
            "m365 purview retentionlabel list": {"value": [{"name": "Confidential"}]},
            "m365 purview retention policy list": {"value": [{"name": "General Retention"}]},
            "m365 purview dlp policy list": {"value": [{"name": "PII"}]},
            "m365 purview audit-log search": {"value": [{"id": "log-job-1"}]},
            "m365 purview auditlog export create": {"value": [{"id": "export-1"}]},
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
