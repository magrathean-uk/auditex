from __future__ import annotations

from typing import Any

import pytest

from azure_tenant_audit.collector_runner import CollectorRunContext, CollectorRunHooks, CollectorRunner
from azure_tenant_audit.collectors.base import CollectorResult
from azure_tenant_audit.run import collector_execution_order


class _FakeWriter:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any] | None]] = []
        self.raw: list[tuple[str, dict[str, Any]]] = []
        self.coverage: list[list[dict[str, Any]]] = []
        self.checkpoints: list[tuple[str, dict[str, Any]]] = []

    def log_event(self, event: str, message: str, details: dict[str, Any] | None = None) -> None:
        self.events.append((event, message, details))

    def write_raw(self, name: str, payload: dict[str, Any]) -> str:
        self.raw.append((name, payload))
        return f"raw/{name}.json"

    def write_index_records(self, records: list[dict[str, Any]]) -> None:
        self.coverage.append(records)

    def write_checkpoint(self, collector_name: str, payload: dict[str, Any]) -> str:
        self.checkpoints.append((collector_name, payload))
        return "checkpoints/checkpoint-state.json"


class _SuccessfulCollector:
    name = "identity"

    def run(self, context: dict[str, Any]) -> CollectorResult:
        assert context["client"] == "graph"
        assert context["top"] == 5
        assert context["page_size"] == 2
        assert context["plane"] == "inventory"
        assert context["since"] == "2026-04-01T00:00:00Z"
        assert context["collector_checkpoint_state"] == {"status": "partial"}
        assert context["operation_checkpoint_state"] == {"export": {"status": "ok"}}
        context["audit_logger"]("collector.custom", "custom event", {"collector": "identity"})
        return CollectorResult(
            name="identity",
            status="ok",
            item_count=1,
            message="ok",
            payload={"users": [{"id": "1"}]},
            coverage=[
                {
                    "collector": "identity",
                    "type": "graph",
                    "name": "users",
                    "status": "ok",
                    "item_count": 1,
                }
            ],
        )


class _CrashingCollector:
    name = "security"

    def run(self, _context: dict[str, Any]) -> CollectorResult:
        raise RuntimeError("boom")


def test_runner_calls_legacy_collector_and_writes_result_surfaces() -> None:
    writer = _FakeWriter()
    runner = CollectorRunner(writer)

    run = runner.run(
        _SuccessfulCollector(),
        CollectorRunContext(
            client="graph",
            top=5,
            page_size=2,
            plane="inventory",
            since="2026-04-01T00:00:00Z",
            collector_checkpoint_state={"status": "partial"},
            operation_checkpoint_state={"export": {"status": "ok"}},
            hooks=CollectorRunHooks(audit_logger=writer.log_event),
        ),
    )

    assert run.crashed is False
    assert run.result.status == "ok"
    assert run.coverage_rows[0]["name"] == "users"
    assert writer.raw == [("identity", {"users": [{"id": "1"}]})]
    assert writer.coverage == [[run.coverage_rows[0]]]
    assert writer.checkpoints == [
        (
            "identity",
            {
                "name": "identity",
                "status": "ok",
                "item_count": 1,
                "message": "ok",
                "error": None,
                "coverage_rows": 1,
            },
        )
    ]
    assert [event[0] for event in writer.events] == [
        "collector.started",
        "collector.custom",
        "collector.finished",
    ]


def test_runner_turns_collector_crash_into_checkpoint_row() -> None:
    writer = _FakeWriter()
    runner = CollectorRunner(writer)

    run = runner.run(_CrashingCollector(), CollectorRunContext(client="graph", top=1))

    assert run.crashed is True
    assert run.result.status == "failed"
    assert run.result.error == "boom"
    assert run.result_row == {
        "name": "security",
        "status": "failed",
        "item_count": 0,
        "message": "collector crashed",
        "error": "boom",
        "coverage_rows": 0,
    }
    assert writer.raw == []
    assert writer.coverage == []
    assert writer.checkpoints == [("security", run.result_row)]
    assert [event[0] for event in writer.events] == ["collector.started", "collector.failed"]


def test_context_exposes_checkpoint_and_adapter_hooks_to_existing_collectors() -> None:
    calls: list[tuple[str, Any]] = []

    def write_export_checkpoint(
        collector_name: str,
        operation: str,
        status: str,
        item_count: int,
        message: str,
        **extra: Any,
    ) -> str:
        calls.append(("checkpoint", collector_name, operation, status, item_count, message, extra))
        return "checkpoints/checkpoint-state.json"

    def chunk_writer(
        collector_name: str,
        endpoint_name: str,
        page_number: int,
        records: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> str:
        calls.append(("chunk", collector_name, endpoint_name, page_number, records, metadata))
        return f"chunks/{collector_name}/{endpoint_name}-{page_number:05d}.jsonl"

    context = CollectorRunContext(
        client="graph",
        top=10,
        hooks=CollectorRunHooks(
            write_export_checkpoint=write_export_checkpoint,
            chunk_writer=chunk_writer,
        ),
    ).to_legacy_dict()

    assert context["write_export_checkpoint"]("purview", "auditLogJobs", "ok", 3, "done", command="Get-Job")
    assert context["chunk_writer"]("identity", "users", 1, [{"id": "1"}], {"endpoint": "/users"})
    assert calls == [
        ("checkpoint", "purview", "auditLogJobs", "ok", 3, "done", {"command": "Get-Job"}),
        ("chunk", "identity", "users", 1, [{"id": "1"}], {"endpoint": "/users"}),
    ]


@pytest.mark.parametrize('selected,expected', [
    (['dns_posture', 'identity', 'exchange_policy', 'security'],
     ['identity', 'exchange_policy', 'dns_posture', 'security']),
    (['exchange_policy', 'identity', 'dns_posture'], ['exchange_policy', 'identity', 'dns_posture']),
    (['dns_posture', 'identity'], ['dns_posture', 'identity']),
    (['exchange_policy'], ['exchange_policy']),
    ([], []),
])
def test_dns_execution_dependency_never_adds_collectors_or_mutates_selection(selected, expected):
    original = list(selected)
    assert collector_execution_order(selected) == expected
    assert selected == original


def test_selected_exchange_result_is_reused_by_dns_in_the_same_run():
    from azure_tenant_audit.collectors.dns_posture import DnsPostureCollector

    class Exchange:
        name = 'exchange_policy'

        def run(self, context):
            # Another operation may fail while acceptedDomains remains usable.
            return CollectorResult(name=self.name, status='partial', payload={
                'acceptedDomains': {'value': [{'DomainName': 'accepted.invalid', 'IsCoexistenceDomain': False}]},
                'transportConfig': {'error': 'constructed refusal'},
            }, item_count=1)

    class Graph:
        def get_all(self, path, params):
            assert path == '/domains'
            return [{'id': 'graph-only.invalid', 'isVerified': True}]

    class Resolver:
        def query(self, name, record_type):
            return []

    collectors = {'exchange_policy': Exchange(), 'dns_posture': DnsPostureCollector()}
    runner = CollectorRunner(_FakeWriter())
    payloads = {}
    for name in collector_execution_order(['dns_posture', 'exchange_policy']):
        output = runner.run(collectors[name], CollectorRunContext(
            client=Graph(), top=None, extra={
                'exchange_accepted_domains': payloads.get('exchange_policy', {}).get('acceptedDomains'),
                'dns_resolver': Resolver(), 'public_lookups': False,
            }))
        payloads[name] = output.result.payload
    assert [r['domain'] for r in payloads['dns_posture']['spf_records']['value']] == ['accepted.invalid']
    assert [r['domain'] for r in payloads['dns_posture']['domainPosture']['value']] == ['graph-only.invalid']
