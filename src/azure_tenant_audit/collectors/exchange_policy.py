"""Exchange Online policy posture via read-only Exchange PowerShell Get-* cmdlets.

Policy configuration commands use explicit ``Select-Object`` lists:

* ``Get-TransportRule`` -> name, state, priority, mode, redirect/copy targets, disclaimer
  configuration, ``FromScope`` and ``PrependSubject``. ``FromScope`` and ``PrependSubject``
  are rule configuration (the latter a subject-prefix setting), not mail. Never select full
  transport-rule objects: conditions and exceptions can hold addresses and keywords.
* ``Get-SharingPolicy`` -> ``Name`` and ``Domains`` (partner domain names and sharing actions),
  without message content.
* ``Get-RemoteDomain`` -> name, domain name, outbound trust, auto-reply and auto-forward settings.
* ``Get-AcceptedDomain`` -> name, domain name, domain type and default-domain flag.
* ``Get-InboundConnector`` and ``Get-OutboundConnector`` -> name, enabled state and connector type.

Detection-coverage commands (all read-only ``Get-*`` cmdlets):

* ``Get-AdminAuditLogConfig`` -> ``UnifiedAuditLogIngestionEnabled`` (must run in Exchange
  Online PowerShell; the Security & Compliance value is always False).
  https://learn.microsoft.com/en-us/purview/audit-log-enable-disable
  https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-adminauditlogconfig
* ``Get-OrganizationConfig`` -> ``Identity``, ``Name`` and ``AuditDisabled``
  (False = mailbox auditing on by default).
  https://learn.microsoft.com/en-us/purview/audit-mailboxes
* ``Get-MailboxAuditBypassAssociation`` -> count of accounts with ``AuditBypassEnabled`` only;
  no account names are kept.
  https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-mailboxauditbypassassociation
* ``Get-ProtectionAlert`` -> alert policy names, state, severity, category. Security & Compliance
  PowerShell only (``Connect-IPPSSession``); without that session the row is a coverage gap.
  https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-protectionalert

Mail protection commands (Cyber Essentials malware protection and secure configuration; all read-only
``Get-*`` cmdlets that pass the shared read guard, Exchange Online PowerShell):

* ``Get-MalwareFilterPolicy`` -> ``IsDefault``, ``EnableFileFilter`` (the common attachment types filter) and
  ``ZapEnabled`` (zero-hour auto purge of malware). The default policy applies to every recipient that no
  other policy covers; the policy settings are read, not the recipients.
  https://learn.microsoft.com/en-us/powershell/module/exchange/get-malwarefilterpolicy
* ``Get-TransportConfig`` -> ``Name`` and ``SmtpClientAuthenticationDisabled``: whether authenticated SMTP submission
  (a basic-authentication protocol) is switched off for the whole tenant.
  https://learn.microsoft.com/en-us/powershell/module/exchange/get-transportconfig
* ``Get-CASMailbox`` -> a count of the mailboxes whose own ``SmtpClientAuthenticationDisabled`` is false. The tenant
  default above can be switched off and still be overridden mailbox by mailbox, so the count says whether the
  default is the whole picture. Only the count is kept, never an address.
  https://learn.microsoft.com/en-us/powershell/module/exchange/get-casmailbox
* ``Get-DkimSigningConfig`` -> ``Domain``, ``Enabled`` and ``Status`` per domain: whether Exchange Online
  signs outbound mail with DKIM, which the DNS lookup in ``dns_posture`` cannot show.
  https://learn.microsoft.com/en-us/powershell/module/exchange/get-dkimsigningconfig

Defender for Office 365 / EOP reads use the same Exchange Online session. Policy settings
are kept; recipient and recipient-group scope lists become same-length placeholders.
No mailbox enumeration or message/file content reads are added:

* ``Get-EOPProtectionPolicyRule`` -> preset policy state and scope.
* ``Get-ATPProtectionPolicyRule`` -> Defender preset policy state and scope.
* ``Get-ATPBuiltInProtectionRule`` -> built-in protection exclusions.
* ``Get-AtpPolicyForO365`` -> SharePoint, Teams and OneDrive ATP policy setting.
* ``Get-MalwareFilterRule`` -> anti-malware policy assignment, priority, state and scope.
* ``Get-SafeAttachmentPolicy`` -> attachment protection action.
* ``Get-SafeAttachmentRule`` -> attachment policy assignment, priority, state and scope.
* ``Get-AntiPhishPolicy`` -> protection flags, actions and domains; targeted users are not selected.
* ``Get-AntiPhishRule`` -> anti-phish policy assignment, state and scope.
* ``Get-HostedContentFilterPolicy`` -> spam/phish actions and allowed sender domains.
* ``Get-HostedContentFilterRule`` -> content filter policy assignment, state and scope.
* ``Get-SafeLinksPolicy`` -> URL scanning, delivery and click tracking settings.
* ``Get-SafeLinksRule`` -> Safe Links policy assignment, priority, state and scope.
* ``Get-HostedConnectionFilterPolicy`` -> IP allow list and safe list setting.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from ..adapters import get_adapter
from ..collection_gaps import REASON_FANOUT_LIMIT, TRUNCATION_ERROR_CLASS
from .base import Collector, CollectorResult
from .exchange_defender_commands import DEFENDER_COMMANDS, minimise_recipients, reclassify_licence_refusals
from .exchange_ipps_commands import IPPS_COMMANDS, IPPS_OPERATIONS, ipps_enabled, ipps_session, minimise_ipps


EXCHANGE_ONLINE_SCOPE = "https://outlook.office365.com/.default"

# Forwarding mailboxes kept per run. The command asks for LIMIT + 1 rows so that a longer list is detected, not guessed.
FORWARDING_MAILBOX_LIMIT = 500
MAILBOX_FORWARDING_COMMAND = (
    f"Get-EXOMailbox -ResultSize {FORWARDING_MAILBOX_LIMIT + 1} "
    "-Properties ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward "
    "-Filter 'ForwardingSmtpAddress -ne $null -or ForwardingAddress -ne $null' "
    "| Select-Object DisplayName,PrimarySmtpAddress,ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward"
)


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
    description = "Exchange transport, domain, connector, forwarding, malware filter, SMTP AUTH and DKIM signing policy posture."
    required_permissions: list[str] = []
    command_collectors = [
        (
            "transportRules",
            "Get-TransportRule | Select-Object Name,State,Priority,Mode,RedirectMessageTo,BlindCopyTo,CopyTo,ApplyHtmlDisclaimerText,FromScope,PrependSubject",
        ),
        ("inboundConnectors", "Get-InboundConnector | Select-Object Name,Enabled,ConnectorType"),
        ("outboundConnectors", "Get-OutboundConnector | Select-Object Name,Enabled,ConnectorType"),
        ("acceptedDomains", "Get-AcceptedDomain | Select-Object Name,DomainName,DomainType,Default"),
        (
            "remoteDomains",
            "Get-RemoteDomain | Select-Object Name,DomainName,TrustedMailOutboundEnabled,AutoReplyEnabled,AutoForwardEnabled",
        ),
        ("sharingPolicy", "Get-SharingPolicy | Select-Object Name,Domains"),
        # The server filters to mailboxes that forward, so the answer does not depend on how many mailboxes the tenant has.
        # One row past FORWARDING_MAILBOX_LIMIT is asked for: seeing it proves the list continued (a gap, never a clean read).
        (
            "mailboxForwarding",
            MAILBOX_FORWARDING_COMMAND,
        ),
        ("adminAuditLogConfig", "Get-AdminAuditLogConfig | Select-Object Identity,UnifiedAuditLogIngestionEnabled"),
        ("organizationAuditConfig", "Get-OrganizationConfig | Select-Object Identity,Name,AuditDisabled"),
        (
            "mailboxAuditBypass",
            "Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Where-Object { $_.AuditBypassEnabled -eq $true } | Measure-Object | Select-Object Count",
        ),
        IPPS_COMMANDS[0],
        ("malwareFilterPolicy", "Get-MalwareFilterPolicy | Select-Object Identity,Name,IsDefault,EnableFileFilter,ZapEnabled,FileTypes"),
        ("transportConfig", "Get-TransportConfig | Select-Object Name,SmtpClientAuthenticationDisabled"),
        # An aggregate, so the answer is never empty (an empty output is read as a failed command) and no mailbox is named.
        (
            "casMailboxSmtpAuth",
            "Get-CASMailbox -ResultSize Unlimited | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false } | Measure-Object | Select-Object Count",
        ),
        ("dkimSigningConfig", "Get-DkimSigningConfig | Select-Object Domain,Enabled,Status"),
        *DEFENDER_COMMANDS,
        *IPPS_COMMANDS[1:],
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = context.get("audit_logger")
        adapter = get_adapter("powershell_graph")
        payload: dict[str, Any] = {}
        coverage: list[dict[str, Any]] = []
        total = 0

        # Consume the PFX password before even the unrelated Exchange children start.
        compliance_session = context.get("ipps_session")
        if compliance_session is None:
            compliance_session = ipps_session()
        exchange_session = _exchange_session(context.get("client"), log_event)
        enabled = ipps_enabled()
        commands = [(name, command) for name, command in self.command_collectors
                    if enabled or name not in IPPS_OPERATIONS - {"protectionAlerts"}]
        for name, command in commands:
            # Get-ProtectionAlert lives in Security & Compliance PowerShell, which needs its own session.
            session = compliance_session if name in IPPS_OPERATIONS else exchange_session
            response = adapter.run(command, log_event=log_event, session=session)
            if name in IPPS_OPERATIONS and enabled:
                response["ipps_enabled"] = True
                minimise_ipps(name, response)
            response.setdefault("command", command)
            minimise_recipients(name, response)
            payload[name] = response

        reclassify_licence_refusals(payload)
        for name, command in commands:
            response = payload[name]
            values = response.get("value")
            cut = (
                name == "mailboxForwarding"
                and not response.get("error")
                and isinstance(values, list)
                and len(values) > FORWARDING_MAILBOX_LIMIT
            )
            if cut:
                values = values[:FORWARDING_MAILBOX_LIMIT]
                response["value"] = values
            item_count = len(values) if isinstance(values, list) else 0
            total += item_count
            row: dict[str, Any] = {
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
            if cut:
                # More forwarding mailboxes exist than were kept: a coverage gap, so the rule never reads this list as clean.
                row.update(
                    status="partial",
                    error_class=TRUNCATION_ERROR_CLASS,
                    error=f"{name}: collection stopped at {item_count} rows because of the collector's row bound; the list is incomplete.",
                    collection_truncated=True,
                    truncation_reason=REASON_FANOUT_LIMIT,
                    result_limit=FORWARDING_MAILBOX_LIMIT,
                    rows_collected=item_count,
                )
                response.update(
                    collection_truncated=True,
                    truncation_reason=REASON_FANOUT_LIMIT,
                    result_limit=FORWARDING_MAILBOX_LIMIT,
                    item_count=item_count,
                )
            coverage.append(row)

        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Exchange policy collector partially completed" if partial else "",
            coverage=coverage,
        )
