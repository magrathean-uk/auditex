"""Exchange Online policy posture via read-only Exchange PowerShell Get-* cmdlets.

Detection-coverage commands (all read-only ``Get-*`` cmdlets):

* ``Get-AdminAuditLogConfig`` -> ``UnifiedAuditLogIngestionEnabled`` (must run in Exchange
  Online PowerShell; the Security & Compliance value is always False).
  https://learn.microsoft.com/en-us/purview/audit-log-enable-disable
  https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-adminauditlogconfig
* ``Get-OrganizationConfig`` -> ``AuditDisabled`` (False = mailbox auditing on by default).
  https://learn.microsoft.com/en-us/purview/audit-mailboxes
* ``Get-MailboxAuditBypassAssociation`` -> count of accounts with ``AuditBypassEnabled`` only;
  no account names are kept.
  https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-mailboxauditbypassassociation
* ``Get-ProtectionAlert`` -> alert policy names, state, severity, category. Security & Compliance
  PowerShell only (``Connect-IPPSSession``); without that session the row is a coverage gap.
  https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-protectionalert
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from ..adapters import get_adapter
from .base import Collector, CollectorResult


EXCHANGE_ONLINE_SCOPE = "https://outlook.office365.com/.default"


def _exchange_session(client: Any, log_event: Any) -> dict[str, Any]:
    """App-only Exchange Online session (token + initial domain), or a marker that no session is available.

    Needs the Exchange.ManageAsApp application permission and an Exchange-capable read role
    (for example Global Reader) assigned to the service principal:
    https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2
    """
    token = client.app_token_for(EXCHANGE_ONLINE_SCOPE) if hasattr(client, "app_token_for") else None
    organization = None
    if token and hasattr(client, "get_all"):
        try:
            domains = client.get_all("/domains", params={"$select": "id,isInitial"})
            organization = next((str(item["id"]) for item in domains if item.get("isInitial") and item.get("id")), None)
        except Exception as exc:  # noqa: BLE001
            if log_event:
                log_event("collector.exchange_session.failed", "Could not read the tenant's initial domain", {"error": str(exc)})
    if token and organization:
        return {"kind": "exchange_online", "access_token": token, "organization": organization}
    return {"kind": "none"}


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
        ("adminAuditLogConfig", "Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled"),
        ("organizationAuditConfig", "Get-OrganizationConfig | Select-Object AuditDisabled"),
        (
            "mailboxAuditBypass",
            "Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Where-Object { $_.AuditBypassEnabled -eq $true } | Measure-Object | Select-Object Count",
        ),
        ("protectionAlerts", "Get-ProtectionAlert | Select-Object Name,Disabled,Severity,Category,IsSystemRule"),
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = context.get("audit_logger")
        adapter = get_adapter("powershell_graph")
        payload: dict[str, Any] = {}
        coverage: list[dict[str, Any]] = []
        total = 0

        exchange_session = _exchange_session(context.get("client"), log_event)
        for name, command in self.command_collectors:
            # Get-ProtectionAlert lives in Security & Compliance PowerShell, which needs its own session.
            session = {"kind": "security_compliance"} if name == "protectionAlerts" else exchange_session
            response = adapter.run(command, log_event=log_event, session=session)
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
