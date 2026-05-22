from __future__ import annotations

from typing import Any, Callable, Optional

from ..adapters import get_adapter
from .base import Collector, CollectorResult


class ExchangePolicyCollector(Collector):
    name = "exchange_policy"
    description = "Exchange transport, domain, connector, and forwarding policy posture."
    required_permissions: list[str] = []
    command_collectors = [
        (
            "transportRules",
            "Get-TransportRule | Select-Object Name,State,Priority,Mode,RedirectMessageTo,BlindCopyTo,CopyTo,ApplyHtmlDisclaimerText",
        ),
        ("inboundConnectors", "Get-InboundConnector | Select-Object Name,Enabled,ConnectorType"),
        ("outboundConnectors", "Get-OutboundConnector | Select-Object Name,Enabled,ConnectorType"),
        ("acceptedDomains", "Get-AcceptedDomain | Select-Object Name,DomainName,DomainType,Default"),
        (
            "remoteDomains",
            "Get-RemoteDomain | Select-Object Name,DomainName,TrustedMailOutboundEnabled,AutoReplyEnabled,AutoForwardEnabled",
        ),
        (
            "mailboxForwarding",
            "Get-EXOMailbox -ResultSize 50 | Select-Object DisplayName,PrimarySmtpAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward",
        ),
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = context.get("audit_logger")
        adapter = get_adapter("powershell_graph")
        payload: dict[str, Any] = {}
        coverage: list[dict[str, Any]] = []
        total = 0

        for name, command in self.command_collectors:
            response = adapter.run(command, log_event=log_event)
            response.setdefault("command", command)
            payload[name] = response
            values = response.get("value")
            item_count = len(values) if isinstance(values, list) else 0
            total += item_count
            coverage.append(
                {
                    "collector": self.name,
                    "type": "command",
                    "name": name,
                    "command": command,
                    "status": "failed" if response.get("error") else "ok",
                    "item_count": item_count,
                    "duration_ms": response.get("duration_ms", 0.0),
                    "error_class": response.get("error_class"),
                    "error": response.get("error"),
                }
            )

        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Exchange policy collector partially completed" if partial else "",
            coverage=coverage,
        )
