"""Exchange Online policy posture via read-only Exchange PowerShell Get-* cmdlets.

Policy configuration commands use explicit ``Select-Object`` lists:

* ``Get-TransportRule`` -> name, state, priority, mode, redirect/copy targets, disclaimer
  configuration, ``FromScope`` and ``PrependSubject``. ``FromScope`` and ``PrependSubject``
  are rule configuration (the latter a subject-prefix setting), not mail. Never select full
  transport-rule objects: conditions and exceptions can hold addresses and keywords.
* ``Get-SharingPolicy`` -> ``Name`` and ``Domains`` (partner domain names and sharing actions),
  without message content.
* ``Get-RemoteDomain`` -> name, domain name, outbound trust, auto-reply and auto-forward settings.
* ``Get-AcceptedDomain`` -> name, domain name, domain type, default-domain flag and ``IsCoexistenceDomain``.
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
  PowerShell only; see the compliance session below.
  https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-protectionalert

Security & Compliance reads (SCuBA MS.SECURITYSUITE 3.1-3.4 and 4.1) run in their own session, opened only in app-only
certificate mode: a certificate token for the Microsoft Exchange Online Protection resource (``COMPLIANCE_SCOPE``, its
``Exchange.ManageAsApp`` permission plus a read role such as Global Reader) is passed to ``Connect-IPPSSession`` as an
access token with the initial domain. A secret, delegated or access-token run, or a connect that fails, records the
``ipps_session_not_opened`` section gap on every read below and never invokes them after the failure; the gaps are
section-scoped, so the Exchange reads above keep the collector's status.
https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2

* ``Get-ProtectionAlert`` (above) -> alert policy name and ``Disabled`` for SS 4.1.
* ``Get-Command Get-DlpCompliancePolicy`` -> a count only: whether the session offers the DLP cmdlets, the DLP licence
  fact ScubaGear reads the same way. A count of 0 skips the two DLP reads as ``dlp_licence_not_detected``.
* ``Get-DlpCompliancePolicy`` -> name, state, mode, workloads and the five location lists; each location entry is
  written as text, and every entry other than ``All`` becomes the placeholder ``location`` (no user, group or site name).
  https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-dlpcompliancepolicy
* ``Get-DlpComplianceRule`` -> name, parent policy, state, information types, block and notify settings; ``NotifyUser``
  entries become the same-length placeholder ``recipient``.
  https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-dlpcompliancerule

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
* ``Get-AntiPhishPolicy`` -> protection flags, actions and domains, plus ``TargetedUsersToProtect`` for SS 2.1. The
  list stays in memory: the adapter rebuilds each policy row from the other selected fields and a per-policy
  ``TargetedUsersCoverage`` summary (counts bound to the run's private SensitiveUsers copy by its manifest HMAC),
  and keeps no stdout, stderr or sample text for this read. See ``targeted_users_coverage``.
* ``Get-AntiPhishRule`` -> anti-phish policy assignment, state and scope.
* ``Get-HostedContentFilterPolicy`` -> spam/phish actions and allowed sender domains.
* ``Get-HostedContentFilterRule`` -> content filter policy assignment, state and scope.
* ``Get-SafeLinksPolicy`` -> URL scanning, delivery and click tracking settings.
* ``Get-SafeLinksRule`` -> Safe Links policy assignment, priority, state and scope.
* ``Get-HostedConnectionFilterPolicy`` -> IP allow list and safe list setting.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..adapters import get_adapter
from ..adapters.powershell_graph import (
    PowerShellGraphAdapter,
    compliance_certificate_token,
)
from ..collection_gaps import (
    DLP_LICENCE_SKIP_TEXT,
    IPPS_SKIP_TEXT,
    REASON_DLP_LICENCE_NOT_DETECTED,
    REASON_FANOUT_LIMIT,
    REASON_IPPS_SESSION_NOT_OPENED,
    SECTION_SCOPED,
    TRUNCATION_ERROR_CLASS,
)
from .base import Collector, CollectorResult
from .exchange_defender_commands import (
    DEFENDER_COMMANDS,
    minimise_recipients,
    reclassify_licence_refusals,
)

EXCHANGE_ONLINE_SCOPE = "https://outlook.office365.com/.default"
# Security & Compliance PowerShell: the Microsoft Exchange Online Protection resource (Exchange.ManageAsApp on it).
COMPLIANCE_SCOPE = "https://ps.compliance.protection.outlook.com/.default"

# DLP reads ScubaGear's rules use. Location entries are cast to text, as ScubaGear's JSON export writes them.
DLP_LOCATIONS = ("ExchangeLocation", "SharePointLocation", "OneDriveLocation", "TeamsLocation", "EndpointDlpLocation")
DLP_POLICY_COMMAND = (
    ",@(Get-DlpCompliancePolicy | Select-Object Name,Enabled,Mode,Workload,"
    + ",".join(f"@{{Name='{name}';Expression={{[string[]]$_.{name}}}}}" for name in DLP_LOCATIONS)
    + ")"
)
DLP_RULE_COMMAND = (
    ",@(Get-DlpComplianceRule | Select-Object Name,ParentPolicyName,Disabled,IsAdvancedRule,AdvancedRule,"
    "ContentContainsSensitiveInformation,BlockAccess,BlockAccessScope,NotifyUser,NotifyUserType)"
)
# A count, never empty: 1 when the session offers the DLP cmdlets (the DLP licence fact), else 0.
DLP_LICENSE_COMMAND = "Get-Command Get-DlpCompliancePolicy -ErrorAction SilentlyContinue | Measure-Object | Select-Object Count"
DLP_READS = ("dlpCompliancePolicies", "dlpComplianceRules")
# Every read that runs in the Security & Compliance session; each is section-scoped.
IPPS_OPERATIONS = frozenset({"protectionAlerts", "dlpLicense", *DLP_READS})

# Forwarding mailboxes kept per run. The command asks for LIMIT + 1 rows so that a longer list is detected, not guessed.
FORWARDING_MAILBOX_LIMIT = 500
MAILBOX_FORWARDING_COMMAND = (
    f",@(Get-EXOMailbox -ResultSize {FORWARDING_MAILBOX_LIMIT + 1} "
    "-Properties ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward "
    "-Filter 'ForwardingSmtpAddress -ne $null -or ForwardingAddress -ne $null' "
    "| Select-Object DisplayName,PrimarySmtpAddress,ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward)"
)


def _exchange_session(client: Any, log_event: Any) -> dict[str, Any]:
    """Exchange Online session (token plus initial domain or signed-in user), or a marker that none is available.

    App-only: needs the Exchange.ManageAsApp application permission and an Exchange-capable read role
    (for example Global Reader) assigned to the service principal:
    https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2
    Delegated (DEC-068): the token is minted silently from the run's one sign-in (GraphClient.delegated_token_for)
    and needs the delegated Office 365 Exchange Online permission Exchange.Manage with admin consent on the
    sign-in app; it is passed with -UserPrincipalName, as the Connect-ExchangeOnline reference requires for a
    delegated access token. No token means no session; Auditex never opens a second sign-in for Exchange.
    """
    token = client.app_token_for(EXCHANGE_ONLINE_SCOPE) if hasattr(client, "app_token_for") else None
    if not token and hasattr(client, "delegated_token_for"):
        delegated = client.delegated_token_for(EXCHANGE_ONLINE_SCOPE)
        user = client.signed_in_username() if delegated and hasattr(client, "signed_in_username") else None
        if delegated and user:
            return {"kind": "exchange_online", "access_token": delegated, "user_principal_name": user}
        return {"kind": "none"}
    organization = _initial_domain(client, log_event) if token else None
    if token and organization:
        return {"kind": "exchange_online", "access_token": token, "organization": organization}
    return {"kind": "none"}


def _initial_domain(client: Any, log_event: Any) -> str | None:
    """The tenant's initial ``.onmicrosoft.com`` domain from Graph, or None."""
    if not hasattr(client, "get_all"):
        return None
    try:
        domains = client.get_all("/domains", params={"$select": "id,isInitial"})
        return next((str(item["id"]) for item in domains if item.get("isInitial") and item.get("id")), None)
    except Exception as exc:  # noqa: BLE001
        if log_event:
            log_event("collector.exchange_session.failed", "Could not read the tenant's initial domain", {"error": str(exc)})
        return None


def _compliance_session(client: Any, organization: str | None, log_event: Any) -> dict[str, Any]:
    """Security & Compliance session (certificate token plus initial domain), or a marker that none is available.

    App-only certificate mode only: the token is minted silently from the run's certificate credential and must pass
    ``compliance_certificate_token``. A secret, delegated or access-token run asks for no token at all (no Microsoft
    source shows a secret-minted token is accepted), so it never prompts and the reads record ``ipps_session_not_opened``.
    """
    auth = getattr(client, "auth", None)
    if getattr(auth, "certificate", None) is None or not hasattr(client, "app_token_for"):
        return {"kind": "none"}
    token = client.app_token_for(COMPLIANCE_SCOPE)
    if not token or not compliance_certificate_token(token):
        if log_event:
            log_event("collector.compliance_session.unavailable", "No certificate token for the compliance session",
                      {"error_class": REASON_IPPS_SESSION_NOT_OPENED})
        return {"kind": "none"}
    organization = organization or _initial_domain(client, log_event)
    if not organization:
        return {"kind": "none"}
    return {"kind": "security_compliance", "access_token": token, "organization": organization}


def _ipps_skip(command: str) -> dict[str, Any]:
    return {
        "command": command, "value": [], "status": "skipped", "reason": REASON_IPPS_SESSION_NOT_OPENED,
        "error_class": REASON_IPPS_SESSION_NOT_OPENED, "error": IPPS_SKIP_TEXT,
    }


def _dlp_not_licensed(response: Any) -> bool:
    """The licence probe ran and found no DLP cmdlet in the session (a count of exactly 0)."""
    if not isinstance(response, dict) or response.get("error") or response.get("error_class"):
        return False
    rows = response.get("value")
    return (isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict)
            and type(rows[0].get("Count")) is int and rows[0]["Count"] == 0)


def minimise_dlp(name: str, response: dict[str, Any]) -> None:
    """Replace DLP location and notify-user entries in place; the rules read only ``All`` and list emptiness.

    A lone information-type object becomes a one-item list, as ScubaGear's export always writes a list. A failed read
    keeps only the length of its output, as the Defender rule reads do, since partial output can name people.
    """
    if name not in DLP_READS:
        return
    if response.get("error") and "stdout" in response:
        response["stdout_bytes"] = len(response.pop("stdout"))
    rows = response.get("value")
    if not isinstance(rows, list):
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        if name == "dlpCompliancePolicies":
            for key in DLP_LOCATIONS:
                value = row.get(key)
                if isinstance(value, list):
                    row[key] = [item if item == "All" else "location" for item in value]
                elif isinstance(value, str) and value and value != "All":
                    row[key] = "location"
            continue
        notify = row.get("NotifyUser")
        if isinstance(notify, list):
            row["NotifyUser"] = ["recipient"] * len(notify)
        elif isinstance(notify, str) and notify:
            row["NotifyUser"] = "recipient"
        if isinstance(row.get("ContentContainsSensitiveInformation"), dict):
            row["ContentContainsSensitiveInformation"] = [row["ContentContainsSensitiveInformation"]]


class ExchangePolicyCollector(Collector):
    name = "exchange_policy"
    description = (
        "Exchange transport, domain, connector, forwarding, malware filter, SMTP AUTH and DKIM signing policy posture, "
        "and Security & Compliance alert and DLP policies."
    )
    required_permissions: list[str] = []
    command_collectors = [
        (
            "transportRules",
            ",@(Get-TransportRule | Select-Object Name,State,Priority,Mode,RedirectMessageTo,BlindCopyTo,CopyTo,FromScope,PrependSubject)",
        ),
        ("inboundConnectors", ",@(Get-InboundConnector | Select-Object Name,Enabled,ConnectorType)"),
        ("outboundConnectors", ",@(Get-OutboundConnector | Select-Object Name,Enabled,ConnectorType)"),
        # These domain/default-policy reads always have an answer. Do not mask missing output as an empty list.
        ("acceptedDomains", "Get-AcceptedDomain | Select-Object Name,DomainName,DomainType,Default,IsCoexistenceDomain"),
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
        ("protectionAlerts", ",@(Get-ProtectionAlert | Select-Object Name,Disabled,Severity,Category,IsSystemRule)"),
        ("dlpLicense", DLP_LICENSE_COMMAND),
        ("dlpCompliancePolicies", DLP_POLICY_COMMAND),
        ("dlpComplianceRules", DLP_RULE_COMMAND),
        ("malwareFilterPolicy", "Get-MalwareFilterPolicy | Select-Object Identity,Name,IsDefault,EnableFileFilter,ZapEnabled,FileTypes"),
        ("transportConfig", "Get-TransportConfig | Select-Object Name,SmtpClientAuthenticationDisabled"),
        # An aggregate, so the answer is never empty (an empty output is read as a failed command) and no mailbox is named.
        (
            "casMailboxSmtpAuth",
            "Get-CASMailbox -ResultSize Unlimited | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false } | Measure-Object | Select-Object Count",
        ),
        # Wrapped so a tenant with no signing configuration answers an empty list, not an empty output read as a failed command.
        ("dkimSigningConfig", ",@(Get-DkimSigningConfig | Select-Object Domain,Enabled,Status)"),
        *DEFENDER_COMMANDS,
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        log_event: Callable[[str, str, dict[str, Any] | None], None] | None = context.get("audit_logger")
        adapter = get_adapter("powershell_graph")
        payload: dict[str, Any] = {}
        coverage: list[dict[str, Any]] = []
        total = 0

        exchange_session = _exchange_session(context.get("client"), log_event)
        compliance_session = _compliance_session(context.get("client"), exchange_session.get("organization"), log_event)
        anti_phish = _anti_phish_boundary(context)
        for name, command in self.command_collectors:
            if name in IPPS_OPERATIONS:
                if compliance_session["kind"] != "security_compliance":
                    # No session (or a connect that already failed): the read is never invoked.
                    payload[name] = _ipps_skip(command)
                    continue
                if name in DLP_READS and _dlp_not_licensed(payload.get("dlpLicense")):
                    payload[name] = {
                        "command": command, "value": [], "item_count": 0, "status": "skipped",
                        "reason": REASON_DLP_LICENCE_NOT_DETECTED, "error_class": "license_required",
                        "error": DLP_LICENCE_SKIP_TEXT,
                    }
                    continue
                response = adapter.run(command, log_event=log_event, session=compliance_session)
                response.setdefault("command", command)
                minimise_dlp(name, response)
                payload[name] = response
                if response.get("error_class") == REASON_IPPS_SESSION_NOT_OPENED:
                    compliance_session = {"kind": "none"}
                continue
            if name == anti_phish.OPERATION:
                response = _run_anti_phish(adapter, command, log_event, exchange_session, anti_phish, context)
                payload[name] = response
                continue
            response = adapter.run(command, log_event=log_event, session=exchange_session)
            response.setdefault("command", command)
            minimise_recipients(name, response)
            payload[name] = response

        reclassify_licence_refusals(payload)
        for name, command in self.command_collectors:
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
            if name in IPPS_OPERATIONS:
                # Security & Compliance reads are section-scoped: their gap is named, the rules that read them say so,
                # and the Exchange reads alone decide the collector's status.
                row[SECTION_SCOPED] = True
                if response.get("status") == "skipped":
                    row.update(status="skipped", reason=response.get("reason"))
                elif response.get("error_class") == REASON_IPPS_SESSION_NOT_OPENED:
                    row["reason"] = REASON_IPPS_SESSION_NOT_OPENED
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

        partial = any(item.get("status") != "ok" and not item.get(SECTION_SCOPED) for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Exchange policy collector partially completed" if partial else "",
            coverage=coverage,
        )


def _anti_phish_boundary(context: dict[str, Any]) -> Any:
    from . import targeted_users_coverage
    return targeted_users_coverage


def _run_anti_phish(
    adapter: Any, command: str, log_event: Any, session: dict[str, Any], boundary: Any, context: dict[str, Any],
) -> dict[str, Any]:
    """The anti-phish read through the targeted-users boundary.

    The run's SensitiveUsers tuple and opaque writer binding come from this collector's context only and travel in
    the transform, never in the session, an event or the payload. The real adapter applies the transform inside its
    boundary; any other adapter's response is put through the same boundary here, so no caller returns the list.
    """
    sensitive_users = context.get(boundary.CONTEXT_USERS)
    binding = context.get(boundary.CONTEXT_BINDING)

    def transform(response: dict[str, Any]) -> dict[str, Any]:
        return boundary.sanitise_response(response, sensitive_users, binding, observed=True)

    if isinstance(adapter, PowerShellGraphAdapter):
        response = adapter.run(command, log_event=log_event, session=session, response_transform=transform)
    else:
        raw = adapter.run(command, log_event=log_event, session=session)
        try:
            response = boundary.sanitise_response(raw, sensitive_users, binding, observed=True)
        except Exception:  # noqa: BLE001 - a value-bearing failure never leaves as text
            response = {"error": "command_exception", "error_class": "command_exception"}
        del raw
        if not isinstance(response, dict):
            response = {"error": boundary.PARSE_ERROR, "error_class": boundary.PARSE_ERROR_CLASS}
    response.setdefault("command", command)
    return response
