"""Bounded field selections for read-only Exchange Online Defender policy evidence."""
from __future__ import annotations

from typing import Any


RULE_SCOPE = (
    "SentTo", "SentToMemberOf", "RecipientDomainIs",
    "ExceptIfSentTo", "ExceptIfSentToMemberOf", "ExceptIfRecipientDomainIs",
)


def _listing(cmdlet: str, props: tuple[str, ...], *, allow_empty: bool = True) -> str:
    command = f"{cmdlet} | Select-Object {','.join(props)}"
    # Default-bearing policies and singleton settings must return an answer.
    return f",@({command})" if allow_empty else command


DEFENDER_COMMANDS: list[tuple[str, str]] = [
    ("eopProtectionPolicyRules", _listing("Get-EOPProtectionPolicyRule", ("Identity", "State", *RULE_SCOPE))),
    ("atpProtectionPolicyRules", _listing("Get-ATPProtectionPolicyRule", ("Identity", "State", *RULE_SCOPE))),
    ("atpBuiltInProtectionRules", _listing("Get-ATPBuiltInProtectionRule", (
        "Identity", "ExceptIfSentTo", "ExceptIfSentToMemberOf", "ExceptIfRecipientDomainIs",
    ))),
    ("atpPolicyForO365", _listing("Get-AtpPolicyForO365", ("Identity", "EnableATPForSPOTeamsODB"), allow_empty=False)),
    ("malwareFilterRules", _listing("Get-MalwareFilterRule", (
        "Identity", "State", "Priority", "MalwareFilterPolicy", *RULE_SCOPE,
    ))),
    ("safeAttachmentPolicies", _listing("Get-SafeAttachmentPolicy", ("Identity", "Action"))),
    ("safeAttachmentRules", _listing("Get-SafeAttachmentRule", (
        "Identity", "State", "Priority", "SafeAttachmentPolicy", *RULE_SCOPE,
    ))),
    ("antiPhishPolicies", _listing("Get-AntiPhishPolicy", (
        "Identity", "Name", "IsDefault", "Enabled", "EnableTargetedUserProtection", "TargetedUserProtectionAction",
        "EnableOrganizationDomainsProtection", "TargetedDomainProtectionAction", "EnableTargetedDomainsProtection",
        "TargetedDomainsToProtect", "EnableFirstContactSafetyTips", "EnableSimilarUsersSafetyTips",
        "EnableSimilarDomainsSafetyTips", "EnableUnusualCharactersSafetyTips", "EnableViaTag", "EnableUnauthenticatedSender",
    ), allow_empty=False)),
    ("antiPhishRules", _listing("Get-AntiPhishRule", ("Identity", "State", "AntiPhishPolicy", *RULE_SCOPE))),
    ("hostedContentFilterPolicies", _listing("Get-HostedContentFilterPolicy", (
        "Identity", "IsDefault", "RecommendedPolicyType", "SpamAction", "HighConfidenceSpamAction",
        "PhishSpamAction", "HighConfidencePhishAction", "AllowedSenderDomains",
    ), allow_empty=False)),
    ("hostedContentFilterRules", _listing("Get-HostedContentFilterRule", (
        "Identity", "State", "HostedContentFilterPolicy", *RULE_SCOPE,
    ))),
    ("safeLinksPolicies", _listing("Get-SafeLinksPolicy", (
        "Identity", "EnableSafeLinksForEmail", "EnableSafeLinksForTeams", "EnableSafeLinksForOffice",
        "EnableForInternalSenders", "ScanUrls", "DeliverMessageAfterScan", "TrackClicks",
    ))),
    ("safeLinksRules", _listing("Get-SafeLinksRule", ("Identity", "State", "Priority", "SafeLinksPolicy", *RULE_SCOPE))),
    ("hostedConnectionFilterPolicy", _listing("Get-HostedConnectionFilterPolicy", ("Name", "IPAllowList", "EnableSafeList"), allow_empty=False)),
]

_RULE_OPERATIONS = frozenset({
    "eopProtectionPolicyRules", "atpProtectionPolicyRules", "atpBuiltInProtectionRules", "malwareFilterRules",
    "safeAttachmentRules", "antiPhishRules", "hostedContentFilterRules", "safeLinksRules",
})
_RECIPIENT_KEYS = ("SentTo", "SentToMemberOf", "ExceptIfSentTo", "ExceptIfSentToMemberOf")


def minimise_recipients(name: str, response: dict[str, Any]) -> None:
    """Replace rule recipients in place, dispatching on the collector operation name.

    Rules use only emptiness; domains, nulls and empty values retain their meaning.
    The adapter has already logged its output sample through shared diagnostic masking.
    """
    if name not in _RULE_OPERATIONS:
        return
    if response.get("error") and "stdout" in response:
        response["stdout_bytes"] = len(response.pop("stdout"))
    rows = response.get("value")
    if not isinstance(rows, list):
        return
    for row in rows:
        if isinstance(row, dict):
            for key in _RECIPIENT_KEYS:
                value = row.get(key)
                if isinstance(value, list):
                    row[key] = ["recipient"] * len(value)
                elif isinstance(value, str) and value:
                    row[key] = "recipient"
                elif isinstance(value, dict) and value:
                    row[key] = ["recipient"]


LICENCE_GATED_OPERATIONS = ("atpProtectionPolicyRules", "atpPolicyForO365")
INFER_LICENCE_FROM_FAILURE = True


def reclassify_licence_refusals(payload: dict[str, Any]) -> None:
    """Infer a licence refusal only when both ATP reads fail after a healthy EOP rule read.

    The real error text of an unlicensed tenant is unknown; even paired generic command
    errors can have other causes, so each reclassified envelope marks the inference.
    Session, authentication, guard, timeout, output and parsing errors remain untouched.
    Keep the original error text so the inference can be reviewed or disabled.
    """
    anchor = payload.get("eopProtectionPolicyRules")
    if not INFER_LICENCE_FROM_FAILURE or anchor is None or anchor.get("error"):
        return
    responses = [payload.get(name, {}) for name in LICENCE_GATED_OPERATIONS]
    if not all(response.get("error") and response.get("error_class") == "command_error" for response in responses):
        return
    # An unlicensed tenant may instead yield command_not_found; confirm on the playground tenant and leave it untouched.
    for response in responses:
        response.update(error_class="license_required", value=[], item_count=0, licence_inferred=True)
