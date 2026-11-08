"""Defender policy evidence for the in-memory SCuBA rule view.

Keep only the collector contract's fields without interpreting their values.
The rule engine owns type and scope checks; the model shape gate stays closed.
Anti-phish policies never carry ``TargetedUsersToProtect``; SS 2.1 membership arrives only as a private,
binding-checked ``TargetedUsersCoverage`` summary that ``project_run`` keeps out of the model value.
"""
from __future__ import annotations

from copy import deepcopy

from auditex.scuba_projection import (
    Bundle,
    Unavailable,
    _collector_error,
    _fields,
    _licence_refused,
    _require,
)
from azure_tenant_audit.value_rules.defender_targeted_users import COVERAGE_KEY, bound_coverage


def _listing_adapter(operation: str, keys: tuple[str, ...]):
    def adapter(bundle: Bundle) -> list[dict]:
        rows = bundle.operation("exchange_policy", operation)
        result = []
        for row in rows:
            _fields(row, {})
            bundle.known_fields(row, set(keys) | {"source_name", "key", "kind"})
            result.append({key: deepcopy(row[key]) for key in keys if key in row})
        return result

    return adapter


_SCOPE_KEYS = (
    "SentTo", "SentToMemberOf", "RecipientDomainIs",
    "ExceptIfSentTo", "ExceptIfSentToMemberOf", "ExceptIfRecipientDomainIs",
)

SECTION_KEYS: dict[str, tuple[str, tuple[str, ...]]] = {
    "admin_audit_log_config": ("adminAuditLogConfig", ("Identity", "UnifiedAuditLogIngestionEnabled")),
    "conn_filter": ("hostedConnectionFilterPolicy", ("Name", "IPAllowList", "EnableSafeList")),
    "atp_policy_for_o365": ("atpPolicyForO365", ("Identity", "EnableATPForSPOTeamsODB")),
    "protection_policy_rules": ("eopProtectionPolicyRules", ("Identity", "State", *_SCOPE_KEYS)),
    "atp_policy_rules": ("atpProtectionPolicyRules", ("Identity", "State", *_SCOPE_KEYS)),
    "built_in_protection_rules": ("atpBuiltInProtectionRules", (
        "Identity", "ExceptIfSentTo", "ExceptIfSentToMemberOf", "ExceptIfRecipientDomainIs")),
    "anti_malware_policies": ("malwareFilterPolicy", ("Identity", "EnableFileFilter", "FileTypes", "ZapEnabled")),
    "anti_malware_rules": ("malwareFilterRules", ("Identity", "State", "Priority", "MalwareFilterPolicy", *_SCOPE_KEYS)),
    "safe_attachment_policies": ("safeAttachmentPolicies", ("Identity", "Action")),
    "safe_attachment_rules": ("safeAttachmentRules", ("Identity", "State", "Priority", "SafeAttachmentPolicy", *_SCOPE_KEYS)),
    "anti_phish_policies": ("antiPhishPolicies", (
        "Identity", "Name", "IsDefault", "Enabled", "EnableTargetedUserProtection", "TargetedUserProtectionAction",
        "EnableOrganizationDomainsProtection", "TargetedDomainProtectionAction", "EnableTargetedDomainsProtection",
        "TargetedDomainsToProtect", "EnableFirstContactSafetyTips", "EnableSimilarUsersSafetyTips",
        "EnableSimilarDomainsSafetyTips", "EnableUnusualCharactersSafetyTips", "EnableViaTag", "EnableUnauthenticatedSender")),
    "anti_phish_rules": ("antiPhishRules", ("Identity", "State", "AntiPhishPolicy", *_SCOPE_KEYS)),
    "hosted_content_filter_policies": ("hostedContentFilterPolicies", (
        "Identity", "IsDefault", "RecommendedPolicyType", "SpamAction", "HighConfidenceSpamAction",
        "PhishSpamAction", "HighConfidencePhishAction", "AllowedSenderDomains")),
    "hosted_content_filter_rules": ("hostedContentFilterRules", ("Identity", "State", "HostedContentFilterPolicy", *_SCOPE_KEYS)),
    "safe_links_policies": ("safeLinksPolicies", (
        "Identity", "EnableSafeLinksForEmail", "EnableSafeLinksForTeams", "EnableSafeLinksForOffice",
        "EnableForInternalSenders", "ScanUrls", "DeliverMessageAfterScan", "TrackClicks")),
    "safe_links_rules": ("safeLinksRules", ("Identity", "State", "Priority", "SafeLinksPolicy", *_SCOPE_KEYS)),
}


def _anti_phish_policies(bundle: Bundle) -> list[dict]:
    """The listing contract plus a private TargetedUsersCoverage on every row, never the literal target list.

    Operation, container and row-shape failures withhold the section as for every listing. A summary is only a
    field: absent gives ``not_collected``; a malformed one, or a known one that does not match this run's verified
    SensitiveUsers binding, gives ``unusable`` (never echoed, source not rewritten). Either makes SS 2.1 membership
    unknown while SS 2.2-2.4 keep the policy's other settings.
    """
    operation, keys = SECTION_KEYS["anti_phish_policies"]
    rows = bundle.operation("exchange_policy", operation)
    binding = bundle.sensitive_users.binding
    result = []
    for row in rows:
        _fields(row, {})
        bundle.known_fields(row, set(keys) | {COVERAGE_KEY, "source_name", "key", "kind"})
        projected = {key: deepcopy(row[key]) for key in keys if key in row}
        projected[COVERAGE_KEY] = bound_coverage(row, binding)
        result.append(projected)
    return result


def _defender_license(bundle: Bundle) -> bool:
    payload, _ = bundle._collector_payload("exchange_policy")
    reads = frozenset({"atpPolicyForO365", "atpProtectionPolicyRules"})
    if payload is None or not reads <= payload.keys():
        raise Unavailable("missing_artifact")
    for name in reads:
        envelope = payload[name]
        if isinstance(envelope, dict) and envelope.get("licence_inferred") is True:
            raise _collector_error(envelope)
    bundle.collector_health("exchange_policy", reads, licence_optional=reads)
    return False if any(_licence_refused(payload[name]) for name in reads) else True


ADAPTERS = {section: _listing_adapter(*SECTION_KEYS[section]) for section in SECTION_KEYS} | {
    "anti_phish_policies": _anti_phish_policies,
    "defender_license": _defender_license,
}
DEFENDER_ADAPTERS = ADAPTERS
