from __future__ import annotations

import json
import time
from typing import Any, Callable, Optional

from ..adapters import get_adapter
from .base import Collector, CollectorResult, normalize_collection_limit
from ..graph import GraphError


class ExchangeCollector(Collector):
    name = "exchange"
    description = "Exchange posture and readiness checks via optional command execution."
    required_permissions: list[str] = []
    command_collectors = [
        {
            "name": "exchangeConnectivityCheck",
            "category": "readiness",
            "commands": [
                "m365 status --output json",
                "m365 tenant info get --output json",
            ],
            "graph_fallback": "tenant_info",
        },
        {
            "name": "exchangeTenantInfo",
            "category": "posture",
            "commands": [
                "m365 tenant info get --output json",
            ],
            "graph_fallback": "tenant_info",
        },
        {
            "name": "mailboxCount",
            "category": "posture",
            "commands": [
                "m365 outlook report mailboxusagemailboxcount --period D30 --output json",
                "m365 outlook report mailboxusagedetail --period D30 --output json",
                "m365 outlook roomlist list --output json",
            ],
            "graph_fallback": "mailbox_count",
        },
        {
            "name": "mailboxQuotaStatus",
            "category": "posture",
            "commands": [
                "m365 outlook report mailboxusagequotastatusmailboxcounts --period D30 --output json",
            ],
        },
        {
            "name": "mailboxStorage",
            "category": "posture",
            "commands": [
                "m365 outlook report mailboxusagestorage --period D30 --output json",
            ],
        },
        {
            "name": "mailActivityCounts",
            "category": "posture",
            "commands": [
                "m365 outlook report mailactivitycounts --period D30 --output json",
            ],
        },
        {
            "name": "roomLists",
            "category": "posture",
            "optional": True,
            "commands": [
                "m365 outlook roomlist list --output json",
            ],
        },
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = context.get(
            "audit_logger"
        )
        payload: dict[str, Any] = {}
        total = 0
        coverage: list[dict[str, Any]] = []
        graph_client = context.get("client")
        top = context.get("top", 500)

        for command in self.command_collectors:
            start = time.perf_counter()
            category = str(command.get("category", "posture"))
            command_variants = command.get("commands")
            if not isinstance(command_variants, list):
                command_variants = [str(command.get("command", ""))]

            response = self._run_command_variants(command_variants, command["name"], log_event)
            if response.get("error"):
                graph_response = self._graph_fallback_response(
                    command.get("graph_fallback"),
                    graph_client,
                    top=top,
                )
                if graph_response is not None:
                    graph_response["command_variants"] = command_variants
                    graph_response["operation"] = command["name"]
                    graph_response["category"] = category
                    response = graph_response
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            payload[command["name"]] = response

            item_count = self._item_count(response)
            total += item_count

            status = "failed" if response.get("error") else "ok"
            error_class = response.get("error_class") or ("command_error" if response.get("error") else None)
            message = response.get("error")
            coverage.append(
                {
                    "collector": self.name,
                    "type": "command",
                    "category": category,
                    "optional": bool(command.get("optional")),
                    "name": command["name"],
                    "source": response.get("source", "command"),
                    "command": response.get("command", ""),
                    "command_variants": response.get("command_variants"),
                    "status": status,
                    "item_count": item_count,
                    "duration_ms": duration_ms,
                    "error_class": error_class,
                    "error": message,
                }
            )

        partial = any(entry.get("status") != "ok" and not entry.get("optional") for entry in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Exchange posture collection partially completed" if partial else "",
            coverage=coverage,
        )

    def _run_command_variants(
        self,
        commands: list[str],
        operation: str,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
    ) -> dict[str, Any]:
        last_response: dict[str, Any] = {}

        for command in commands:
            response = self._run_command(command, log_event)
            response["command_variants"] = commands
            response["operation"] = operation
            response.setdefault("source", "command")

            if response.get("error") is None:
                return response

            last_response = response

        if not last_response:
            return {
                "error": "command_all_variants_failed",
                "error_class": "command_error",
                "operation": operation,
                "command_variants": commands,
                "source": "command",
            }

        return last_response

    def _run_command(
        self,
        command: str,
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
    ) -> dict[str, Any]:
        adapter = get_adapter("m365_cli")
        return adapter.run(command, log_event=log_event)

    def _run_mailbox_count_graph_fallback(
        self,
        graph_client: Any,
        top: int | str,
    ) -> dict[str, Any] | None:
        if graph_client is None or not hasattr(graph_client, "get_all"):
            return None

        try:
            params: dict[str, str] = {
                "$select": "id,displayName,userPrincipalName,mail,mailboxSettings",
                "$filter": "mail ne null",
            }
            limit = normalize_collection_limit(top, default=500)
            if limit is not None:
                params["$top"] = str(limit)
            users = graph_client.get_all(
                "/users",
                params=params,
            )
            return {
                "command": "graph /users?filter=mail ne null",
                "value": users,
                "source": "graph",
                "error_class": None,
            }
        except GraphError as exc:
            return {
                "command": "graph /users?filter=mail ne null",
                "error": str(exc),
                "source": "graph",
                "error_class": "insufficient_permissions",
            }

    def _run_tenant_info_graph_fallback(self, graph_client: Any) -> dict[str, Any] | None:
        if graph_client is None or not hasattr(graph_client, "get_all"):
            return None

        try:
            organization = graph_client.get_all(
                "/organization",
                params={"$select": "id,displayName,tenantType,city,country"},
            )
            return {
                "command": "graph /organization",
                "value": organization,
                "source": "graph",
                "error_class": None,
            }
        except GraphError as exc:
            return {
                "command": "graph /organization",
                "error": str(exc),
                "source": "graph",
                "error_class": "insufficient_permissions",
            }

    def _graph_fallback_response(
        self,
        fallback_name: Any,
        graph_client: Any,
        *,
        top: int | str,
    ) -> dict[str, Any] | None:
        if fallback_name == "mailbox_count":
            return self._run_mailbox_count_graph_fallback(graph_client, top=top)
        if fallback_name == "tenant_info":
            return self._run_tenant_info_graph_fallback(graph_client)
        return None

    @staticmethod
    def _item_count(response: dict[str, Any]) -> int:
        value = response.get("value")
        return len(value) if isinstance(value, list) else 0
