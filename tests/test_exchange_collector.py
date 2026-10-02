from __future__ import annotations

from typing import Any

from azure_tenant_audit.collectors.exchange import ExchangeCollector


class _GraphClient:
    def __init__(self, rows: Any) -> None:
        self._rows = rows

    def get_all(self, path, params=None):  # noqa: ARG002
        if isinstance(self._rows, dict):
            return list(self._rows.get(path, []))
        return list(self._rows)


class _ExchangeTestCollector(ExchangeCollector):
    def __init__(self, responses: dict[str, dict[str, Any]]) -> None:
        self._responses = responses

    def _run_command(self, command, log_event=None):  # noqa: ARG002
        response = self._responses.get(command)
        if response is None:
            return {
                "command": command,
                "error": "unexpected",
                "error_class": "command_error",
            }
        payload = dict(response)
        payload.setdefault("command", command)
        return payload


def test_exchange_collector_collects_readiness_and_posture_sections() -> None:
    collector = _ExchangeTestCollector(
        {
            "m365 status --output json": {"value": [{"connectedAs": "app"}]},
            "m365 tenant info get --output json": {
                "value": [{"tenantId": "tenant-1", "defaultDomainName": "contoso.com"}]
            },
            "m365 outlook report mailboxusagemailboxcount --period D30 --output json": {
                "value": [
                    {"reportDate": "2026-04-16", "mailboxCount": 24},
                    {"reportDate": "2026-04-17", "mailboxCount": 25},
                ]
            },
            "m365 outlook report mailboxusagequotastatusmailboxcounts --period D30 --output json": {
                "value": [{"reportDate": "2026-04-17", "issueType": "warning", "mailboxCount": 2}]
            },
            "m365 outlook report mailboxusagestorage --period D30 --output json": {
                "value": [{"reportDate": "2026-04-17", "storageUsedByte": 1024}]
            },
            "m365 outlook report mailactivitycounts --period D30 --output json": {
                "value": [{"reportDate": "2026-04-17", "sendCount": 30, "receiveCount": 40}]
            },
            "m365 outlook roomlist list --output json": {
                "value": [
                    {"displayName": "HQ Rooms"},
                    {"displayName": "Field Rooms"},
                ]
            },
        }
    )

    result = collector.run({"audit_logger": None, "client": _GraphClient([])})

    assert result.status == "ok"
    assert result.item_count == 9
    assert list(result.payload) == [
        "exchangeConnectivityCheck",
        "exchangeTenantInfo",
        "mailboxCount",
        "mailboxQuotaStatus",
        "mailboxStorage",
        "mailActivityCounts",
        "roomLists",
    ]
    assert result.payload["exchangeConnectivityCheck"]["command"] == "m365 status --output json"
    assert result.payload["exchangeConnectivityCheck"]["source"] == "command"
    assert result.payload["exchangeTenantInfo"]["command"] == "m365 tenant info get --output json"
    assert result.payload["roomLists"]["value"][0]["displayName"] == "HQ Rooms"
    assert result.coverage is not None
    assert len(result.coverage) == 7

    coverage_by_name = {entry["name"]: entry for entry in result.coverage}
    assert coverage_by_name["exchangeConnectivityCheck"]["category"] == "readiness"
    assert coverage_by_name["exchangeTenantInfo"]["category"] == "posture"
    assert coverage_by_name["mailboxCount"]["item_count"] == 2
    assert coverage_by_name["roomLists"]["optional"] is True
    assert coverage_by_name["roomLists"]["command_variants"] == [
        "m365 outlook roomlist list --output json",
    ]


def test_exchange_collector_uses_fallbacks_and_marks_partial_for_failed_posture_sections() -> None:
    collector = _ExchangeTestCollector(
        {
            "m365 status --output json": {
                "error": "command_failed:1",
                "error_class": "command_not_authenticated",
            },
            "m365 tenant info get --output json": {
                "error": "command_not_found:m365",
                "error_class": "command_not_found",
            },
            "m365 status --output json": {"value": [{"connectedAs": "user"}]},
            "m365 outlook report mailboxusagemailboxcount --period D30 --output json": {
                "error": "command_output_empty",
                "error_class": "command_output_empty",
            },
            "m365 outlook report mailboxusagedetail --period D30 --output json": {
                "error": "command_output_empty",
                "error_class": "command_output_empty",
            },
            "m365 outlook roomlist list --output json": {
                "error": "command_not_found:m365",
                "error_class": "command_not_found",
            },
            "m365 outlook report mailboxusagequotastatusmailboxcounts --period D30 --output json": {
                "value": [{"reportDate": "2026-04-17", "underQuotaCount": 24}]
            },
            "m365 outlook report mailboxusagestorage --period D30 --output json": {
                "error": "command_failed:1",
                "error_class": "command_error",
            },
            "m365 outlook report mailactivitycounts --period D30 --output json": {
                "value": [{"reportDate": "2026-04-17", "sendCount": 10}]
            },
        }
    )
    result = collector.run(
        {
            "audit_logger": None,
            "client": _GraphClient(
                {
                    "/organization": [{"id": "tenant-1", "displayName": "Contoso"}],
                    "/users": [
                        {"id": "mailbox-graph-1", "mail": "x@example.com"},
                        {"id": "mailbox-graph-2", "mail": "y@example.com"},
                    ],
                }
            ),
        }
    )

    assert result.status == "partial"
    assert result.item_count == 6
    assert result.payload["exchangeConnectivityCheck"]["command"] == "m365 status --output json"
    assert result.payload["exchangeTenantInfo"]["command"] == "graph /organization"
    assert result.payload["exchangeTenantInfo"]["source"] == "graph"
    assert result.payload["mailboxCount"]["command"] == "graph /users?$select=mail (mail-enabled users)"
    assert result.payload["mailboxCount"]["source"] == "graph"
    assert result.payload["roomLists"]["error_class"] == "command_not_found"

    assert result.coverage is not None
    coverage_by_name = {entry["name"]: entry for entry in result.coverage}
    assert coverage_by_name["exchangeConnectivityCheck"]["command_variants"] == [
        "m365 status --output json",
        "m365 tenant info get --output json",
    ]
    assert coverage_by_name["exchangeTenantInfo"]["status"] == "ok"
    assert coverage_by_name["exchangeTenantInfo"]["source"] == "graph"
    assert coverage_by_name["mailboxCount"]["command_variants"] == [
        "m365 outlook report mailboxusagemailboxcount --period D30 --output json",
        "m365 outlook report mailboxusagedetail --period D30 --output json",
        "m365 outlook roomlist list --output json",
    ]
    assert coverage_by_name["mailboxCount"]["status"] == "ok"
    assert coverage_by_name["mailboxCount"]["source"] == "graph"
    assert coverage_by_name["mailboxStorage"]["status"] == "failed"
    assert coverage_by_name["mailboxStorage"]["category"] == "posture"
    assert coverage_by_name["roomLists"]["status"] == "failed"
    assert coverage_by_name["roomLists"]["optional"] is True
