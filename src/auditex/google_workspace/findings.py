from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


_GOOGLE_FRAMEWORK_MAPPINGS: dict[str, dict[str, list[str]]] = {
    "google.collector_issue": {"nist_800_53": ["AU-2", "CA-7"], "iso_27001": ["A.8.16"], "soc2": ["CC7.2"]},
    "google.admin_2sv_not_enforced": {"nist_800_53": ["IA-2"], "iso_27001": ["A.5.17"], "soc2": ["CC6.1"]},
    "google.admin_2sv_not_enrolled": {"nist_800_53": ["IA-2"], "iso_27001": ["A.5.17"], "soc2": ["CC6.1"]},
    "google.user_2sv_not_enrolled": {"nist_800_53": ["IA-2"], "iso_27001": ["A.5.17"], "soc2": ["CC6.1"]},
    "google.login_suspicious_event": {"nist_800_53": ["AU-6", "IR-4"], "iso_27001": ["A.8.15", "A.8.16"], "soc2": ["CC7.2"]},
    "google.admin_privilege_event": {"nist_800_53": ["AC-2", "AC-6", "AU-6"], "iso_27001": ["A.5.15", "A.5.18"], "soc2": ["CC6.1", "CC7.2"]},
    "google.oauth_high_risk_scope": {"nist_800_53": ["AC-3", "AC-6"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.gmail_external_forwarding": {"nist_800_53": ["SC-7"], "iso_27001": ["A.8.12"], "soc2": ["CC6.7"]},
    "google.gmail_external_forwarding_address_ready": {"nist_800_53": ["SC-7"], "iso_27001": ["A.8.12"], "soc2": ["CC6.7"]},
    "google.gmail_filter_external_forwarding": {"nist_800_53": ["SC-7"], "mitre_attack": ["T1114"], "soc2": ["CC7.2"]},
    "google.gmail_hidden_forwarding_filter": {"nist_800_53": ["SI-4"], "mitre_attack": ["T1114"], "soc2": ["CC7.2"]},
    "google.gmail_imap_enabled": {"nist_800_53": ["AC-17"], "iso_27001": ["A.8.20"], "soc2": ["CC6.6"]},
    "google.gmail_pop_enabled": {"nist_800_53": ["AC-17"], "iso_27001": ["A.8.20"], "soc2": ["CC6.6"]},
    "google.gmail_vacation_external_reply": {"nist_800_53": ["SC-7"], "iso_27001": ["A.8.12"], "soc2": ["CC6.7"]},
    "google.gmail_external_send_as": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.gmail_external_delegate": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.drive_anyone_with_link": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.drive_public_discoverable": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.drive_domain_permission": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.drive_external_permission": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.shared_drive_external_members_allowed": {"nist_800_53": ["AC-2", "AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.calendar_public_acl": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.calendar_external_acl": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.calendar_domain_acl": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.group_anyone_can_join": {"nist_800_53": ["AC-2", "AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.group_domain_can_join": {"nist_800_53": ["AC-2", "AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.group_external_members_allowed": {"nist_800_53": ["AC-2"], "iso_27001": ["A.5.18"], "soc2": ["CC6.2"]},
    "google.group_external_member": {"nist_800_53": ["AC-2", "AC-3"], "iso_27001": ["A.5.18"], "soc2": ["CC6.2"]},
    "google.group_anyone_can_post": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.group_anyone_can_post_unmoderated": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.group_domain_can_post": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.group_domain_can_post_unmoderated": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.group_public_view": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.group_public_membership": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.group_domain_view": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.group_domain_membership": {"nist_800_53": ["AC-3"], "iso_27001": ["A.5.15"], "soc2": ["CC6.6"]},
    "google.alert_active": {"nist_800_53": ["IR-5"], "iso_27001": ["A.5.25"], "soc2": ["CC7.3"]},
    "google.super_admin_singleton": {"nist_800_53": ["CP-2", "AC-2"], "iso_27001": ["A.5.18"], "soc2": ["CC6.2"]},
    "google.super_admin_sprawl": {"nist_800_53": ["AC-2", "AC-6"], "iso_27001": ["A.5.18"], "soc2": ["CC6.2"]},
    "google.suspended_admin": {"nist_800_53": ["AC-2"], "iso_27001": ["A.5.18"], "soc2": ["CC6.2"]},
    "google.admin_stale_login": {"nist_800_53": ["AC-2"], "iso_27001": ["A.5.18"], "soc2": ["CC6.2"]},
    "google.mobile_device_compromised": {"nist_800_53": ["SI-4"], "iso_27001": ["A.8.16"], "soc2": ["CC7.2"]},
    "google.mobile_device_stale_sync": {"nist_800_53": ["CM-8", "SI-4"], "iso_27001": ["A.5.9", "A.8.1"], "soc2": ["CC7.1"]},
    "google.chromeos_device_stale_sync": {"nist_800_53": ["CM-8", "SI-4"], "iso_27001": ["A.5.9", "A.8.1"], "soc2": ["CC7.1"]},
    "google.chromeos_device_inactive_assignment": {"nist_800_53": ["CM-8"], "iso_27001": ["A.5.9"], "soc2": ["CC7.1"]},
    "google.dns_spf_missing": {"nist_800_53": ["SC-7", "SC-8"], "iso_27001": ["A.5.14", "A.8.20"], "soc2": ["CC6.6"], "mitre_attack": ["T1566"]},
    "google.dns_dmarc_monitor_only": {"nist_800_53": ["SC-7", "SC-8"], "iso_27001": ["A.5.14", "A.8.20"], "soc2": ["CC6.6"], "mitre_attack": ["T1566"]},
    "google.dns_dkim_missing": {"nist_800_53": ["SC-7", "SC-8"], "iso_27001": ["A.5.14", "A.8.20"], "soc2": ["CC6.6"], "mitre_attack": ["T1566"]},
}

_GOOGLE_BASELINE_CONTROLS: dict[str, str] = {
    "google.admin_2sv_not_enforced": "identity.2sv",
    "google.admin_2sv_not_enrolled": "identity.2sv",
    "google.user_2sv_not_enrolled": "identity.2sv",
    "google.super_admin_singleton": "identity.admin_resilience",
    "google.super_admin_sprawl": "identity.admin_resilience",
    "google.suspended_admin": "identity.admin_hygiene",
    "google.admin_stale_login": "identity.admin_hygiene",
    "google.oauth_high_risk_scope": "apps.oauth_grants",
    "google.gmail_external_forwarding": "gmail.forwarding",
    "google.gmail_external_forwarding_address_ready": "gmail.forwarding",
    "google.gmail_filter_external_forwarding": "gmail.forwarding",
    "google.gmail_hidden_forwarding_filter": "gmail.forwarding",
    "google.gmail_imap_enabled": "gmail.protocols",
    "google.gmail_pop_enabled": "gmail.protocols",
    "google.gmail_vacation_external_reply": "gmail.auto_reply",
    "google.gmail_external_send_as": "gmail.delegation",
    "google.gmail_external_delegate": "gmail.delegation",
    "google.drive_anyone_with_link": "drive.sharing",
    "google.drive_public_discoverable": "drive.sharing",
    "google.drive_domain_permission": "drive.sharing",
    "google.drive_external_permission": "drive.sharing",
    "google.shared_drive_external_members_allowed": "drive.sharing",
    "google.calendar_public_acl": "calendar.sharing",
    "google.calendar_external_acl": "calendar.sharing",
    "google.calendar_domain_acl": "calendar.sharing",
    "google.group_anyone_can_join": "groups.exposure",
    "google.group_domain_can_join": "groups.exposure",
    "google.group_external_members_allowed": "groups.exposure",
    "google.group_external_member": "groups.exposure",
    "google.group_anyone_can_post": "groups.posting",
    "google.group_anyone_can_post_unmoderated": "groups.posting",
    "google.group_domain_can_post": "groups.posting",
    "google.group_domain_can_post_unmoderated": "groups.posting",
    "google.group_public_view": "groups.exposure",
    "google.group_public_membership": "groups.exposure",
    "google.group_domain_view": "groups.exposure",
    "google.group_domain_membership": "groups.exposure",
    "google.alert_active": "security.alerts",
    "google.login_suspicious_event": "security.audit_events",
    "google.admin_privilege_event": "security.audit_events",
    "google.mobile_device_compromised": "devices.mobile",
    "google.mobile_device_stale_sync": "devices.mobile",
    "google.chromeos_device_stale_sync": "devices.chromeos",
    "google.chromeos_device_inactive_assignment": "devices.chromeos",
    "google.dns_spf_missing": "domains.email_auth",
    "google.dns_dmarc_monitor_only": "domains.email_auth",
    "google.dns_dkim_missing": "domains.email_auth",
    "google.collector_issue": "audit.coverage",
}

for _rule_id, _mapping in _GOOGLE_FRAMEWORK_MAPPINGS.items():
    _mapping.setdefault("google_workspace_baseline", [_GOOGLE_BASELINE_CONTROLS.get(_rule_id, "workspace.posture")])


_GOOGLE_RULE_METADATA: dict[str, dict[str, Any]] = {
    "google.collector_issue": {
        "title": "Google Workspace collector issue",
        "risk_rating": "high",
        "description": "Google Workspace evidence is incomplete for this surface.",
        "impact": "The report has a confirmed Google Workspace evidence gap, so affected controls cannot be asserted from this run.",
        "remediation": "Fix the Google Workspace auth scope or service availability, then rerun the collector.",
        "expected_value": "All in-scope Google Workspace collectors complete or have an accepted scope decision.",
    },
    "google.admin_2sv_not_enforced": {
        "title": "Admin account does not enforce 2-step verification",
        "risk_rating": "high",
        "description": "A Google Workspace admin account is not forced through 2-step verification.",
        "impact": "Privileged Google Workspace access can be exposed to password-only compromise.",
        "remediation": "Enforce 2-step verification for all admin accounts.",
        "expected_value": "Every active admin account has 2-step verification enforced.",
    },
    "google.admin_2sv_not_enrolled": {
        "title": "Admin account is not enrolled in 2-step verification",
        "risk_rating": "high",
        "description": "A Google Workspace admin account is not enrolled in 2-step verification.",
        "impact": "An admin without 2-step verification can become a tenant-wide compromise path.",
        "remediation": "Enroll all admin accounts in 2-step verification and prefer phishing-resistant methods.",
        "expected_value": "Every active admin account is enrolled in 2-step verification.",
    },
    "google.user_2sv_not_enrolled": {
        "title": "User account is not enrolled in 2-step verification",
        "risk_rating": "medium",
        "description": "An active Google Workspace user account is not enrolled in 2-step verification.",
        "impact": "Password-only users are easier to compromise and can expose mail, Drive, and group data.",
        "remediation": "Enroll active users in 2-step verification and enforce the Workspace 2SV baseline.",
        "expected_value": "Active user accounts are enrolled in 2-step verification.",
    },
    "google.suspended_admin": {
        "title": "Suspended user still has admin status",
        "risk_rating": "medium",
        "description": "A suspended user still appears as a Google Workspace admin.",
        "impact": "Dormant privileged assignments create confusing recovery paths and can become active again with broad access.",
        "remediation": "Remove admin privileges from suspended or inactive accounts.",
        "expected_value": "Suspended accounts have no Google Workspace admin privileges.",
    },
    "google.admin_stale_login": {
        "title": "Admin account has stale Google Workspace login",
        "risk_rating": "medium",
        "description": "A Google Workspace admin account has not logged in for over 365 days or has never logged in.",
        "impact": "Stale admin accounts can retain powerful privileges without regular monitoring or ownership.",
        "remediation": "Remove stale admin privileges or confirm the account is a documented emergency account with monitored use.",
        "expected_value": "Admin accounts are active, owned, and monitored, or explicitly documented as emergency access.",
    },
    "google.super_admin_singleton": {
        "title": "Only one Google Workspace super admin observed",
        "risk_rating": "high",
        "description": "Google Workspace has a single observed super admin, creating emergency access fragility.",
        "impact": "Loss or compromise of the only super admin can block recovery or concentrate tenant-wide privilege.",
        "remediation": "Maintain at least two protected emergency-capable admins with separate ownership and strong controls.",
        "expected_value": "Two to five protected super admins are present.",
    },
    "google.super_admin_sprawl": {
        "title": "Too many Google Workspace super admins observed",
        "risk_rating": "medium",
        "description": "Google Workspace has a broad super admin set, increasing blast radius if one account is compromised.",
        "impact": "Excess super admins increase tenant-wide compromise risk and weaken least-privilege administration.",
        "remediation": "Reduce super admin membership and move routine administration to delegated roles.",
        "expected_value": "Super admin membership is limited to approved emergency-capable administrators.",
    },
    "google.group_anyone_can_join": {
        "title": "Group allows anyone to join",
        "risk_rating": "medium",
        "description": "A Google group permits open joining.",
        "impact": "Open group membership can expose mail, Drive sharing, calendar access, or app permissions tied to the group.",
        "remediation": "Restrict group joining to owners, managers, or invited users.",
        "expected_value": "Group joining is restricted to approved users.",
    },
    "google.group_domain_can_join": {
        "title": "Group allows domain-wide joining",
        "risk_rating": "medium",
        "description": "A Google group allows any Workspace domain user to join.",
        "impact": "Domain-wide group joining can expose mail, Drive sharing, calendars, or app permissions broadly across the tenant beyond least-privilege need.",
        "remediation": "Restrict group joining to invited users, owners, managers, or approved request workflows unless domain-wide joining is explicitly required.",
        "expected_value": "Group joining is restricted to approved users unless there is a documented domain-wide need.",
    },
    "google.group_external_member": {
        "title": "Google group has external member",
        "risk_rating": "medium",
        "description": "A Google group includes a member outside the Workspace domain.",
        "impact": "External group members can inherit access to mail, shared drives, calendars, or apps beyond the intended boundary.",
        "remediation": "Remove unapproved external members or document the group as an approved external collaboration boundary.",
        "expected_value": "Groups contain only approved internal or explicitly approved external members.",
    },
    "google.oauth_high_risk_scope": {
        "title": "OAuth grant includes high-risk scopes",
        "risk_rating": "high",
        "description": "A Google OAuth grant includes sensitive mail, Drive, admin, or cloud scopes.",
        "impact": "Over-privileged OAuth grants can provide durable access to Workspace data even after password rotation.",
        "remediation": "Review the OAuth client, remove stale grants, and approve only required scopes.",
        "expected_value": "OAuth grants are current, owned, and limited to required scopes.",
    },
    "google.gmail_imap_enabled": {
        "title": "Gmail IMAP access is enabled",
        "risk_rating": "medium",
        "description": "A mailbox permits IMAP access, which can widen mail exfiltration paths.",
        "impact": "Legacy mail protocols can weaken centralized access control and monitoring.",
        "remediation": "Disable IMAP unless there is an approved client requirement.",
        "expected_value": "IMAP is disabled unless explicitly approved.",
    },
    "google.gmail_pop_enabled": {
        "title": "Gmail POP access is enabled",
        "risk_rating": "medium",
        "description": "A mailbox permits POP access, which can bypass modern mail access controls.",
        "impact": "POP access can copy mail out of Google Workspace and reduce investigation visibility.",
        "remediation": "Disable POP unless there is an approved client requirement.",
        "expected_value": "POP is disabled unless explicitly approved.",
    },
    "google.gmail_vacation_external_reply": {
        "title": "Gmail vacation responder can reply outside the domain",
        "risk_rating": "medium",
        "description": "A mailbox vacation responder is enabled without restricting replies to the Workspace domain.",
        "impact": "Automatic vacation replies can leak mailbox presence and business context to external senders outside the approved boundary.",
        "remediation": "Restrict vacation replies to the Workspace domain or disable the responder unless there is an approved business need.",
        "expected_value": "Vacation responders are disabled or restricted to approved internal recipients.",
    },
    "google.gmail_external_forwarding": {
        "title": "Gmail auto-forwarding sends mail outside the domain",
        "risk_rating": "high",
        "description": "A mailbox forwards incoming mail to an external address.",
        "impact": "External forwarding can continuously exfiltrate business mail outside the managed Workspace boundary.",
        "remediation": "Disable unapproved forwarding or document the business exception.",
        "expected_value": "Mailbox auto-forwarding is internal or explicitly approved.",
    },
    "google.gmail_external_forwarding_address_ready": {
        "title": "Gmail has a verified external forwarding address",
        "risk_rating": "medium",
        "description": "A mailbox has a verified external forwarding address that can be used for future auto-forwarding.",
        "impact": "Dormant verified forwarding addresses can be activated later with little friction.",
        "remediation": "Remove unapproved external forwarding addresses even when they are not currently active.",
        "expected_value": "Verified forwarding addresses are internal or explicitly approved.",
    },
    "google.gmail_filter_external_forwarding": {
        "title": "Gmail filter forwards mail outside the domain",
        "risk_rating": "high",
        "description": "A Gmail filter forwards matching mail to an external address.",
        "impact": "Filter-based forwarding can selectively exfiltrate mail while hiding broad forwarding posture.",
        "remediation": "Remove unapproved forwarding filters and review mailbox compromise indicators.",
        "expected_value": "Gmail filters do not forward mail outside approved destinations.",
    },
    "google.gmail_hidden_forwarding_filter": {
        "title": "Gmail hidden filter forwards mail outside the domain",
        "risk_rating": "high",
        "description": "A Gmail filter forwards matching mail externally and removes it from the inbox.",
        "impact": "Hidden forwarding filters are a common mailbox-compromise persistence and exfiltration pattern.",
        "remediation": "Remove hidden forwarding filters and review mailbox compromise indicators.",
        "expected_value": "Gmail filters do not hide or externally forward mail.",
    },
    "google.gmail_external_send_as": {
        "title": "Gmail send-as identity is outside the domain",
        "risk_rating": "medium",
        "description": "A mailbox has a verified send-as identity outside the Workspace domain.",
        "impact": "External send-as identities can confuse accountability and enable impersonation paths.",
        "remediation": "Remove unapproved external send-as identities or document the exception.",
        "expected_value": "Send-as identities are internal or explicitly approved.",
    },
    "google.gmail_external_delegate": {
        "title": "Gmail mailbox delegates access outside the domain",
        "risk_rating": "high",
        "description": "A Gmail mailbox grants delegate access to an address outside the Workspace domain.",
        "impact": "External delegates can read and act on mailbox data outside the managed account boundary.",
        "remediation": "Remove unapproved external Gmail delegates and review mailbox access history.",
        "expected_value": "Mailbox delegates are internal or explicitly approved.",
    },
    "google.drive_anyone_with_link": {
        "title": "Drive file is available to anyone with the link",
        "risk_rating": "high",
        "description": "A Google Drive item grants access to anyone with the link.",
        "impact": "Public link access can expose Workspace documents beyond approved collaborators.",
        "remediation": "Remove public link permissions or document a time-bound exception.",
        "expected_value": "Drive items are not available to anyone with the link unless approved.",
    },
    "google.drive_public_discoverable": {
        "title": "Drive file is publicly discoverable",
        "risk_rating": "high",
        "description": "A Google Drive item is exposed to anyone and can be discovered without a pre-shared link.",
        "impact": "Publicly discoverable Drive content can leak outside the Workspace boundary with broader internet exposure than link-only sharing.",
        "remediation": "Disable public discoverability and restrict access to approved users or groups.",
        "expected_value": "Drive items are not publicly discoverable unless explicitly approved.",
    },
    "google.drive_domain_permission": {
        "title": "Drive item grants domain-wide access",
        "risk_rating": "medium",
        "description": "A Google Drive item grants access to the entire Workspace domain.",
        "impact": "Domain-wide Drive sharing can expose files broadly across the tenant beyond least-privilege need.",
        "remediation": "Restrict Drive sharing to approved users or groups unless domain-wide access is explicitly required.",
        "expected_value": "Drive permissions are scoped to approved users or groups unless there is a documented domain-wide need.",
    },
    "google.drive_external_permission": {
        "title": "Drive item grants access to an external principal",
        "risk_rating": "high",
        "description": "A Google Drive item directly grants access to an external user, group, or domain.",
        "impact": "Direct external Drive permissions can expose files outside the Workspace trust boundary.",
        "remediation": "Remove unapproved external Drive permissions or document a time-bound exception.",
        "expected_value": "Drive permissions are internal or explicitly approved.",
    },
    "google.shared_drive_external_members_allowed": {
        "title": "Shared drive allows external members",
        "risk_rating": "medium",
        "description": "A Google shared drive is configured so members do not have to belong to the Workspace domain.",
        "impact": "Shared drives that permit external members can expose broad folders and inherited collaboration access outside the managed boundary.",
        "remediation": "Restrict shared drives to domain users unless the drive is an approved external collaboration boundary.",
        "expected_value": "Shared drives are limited to domain users unless explicitly approved.",
    },
    "google.calendar_public_acl": {
        "title": "Calendar ACL grants public access",
        "risk_rating": "high",
        "description": "A Google Calendar access rule grants access to the public scope.",
        "impact": "Public calendar sharing can disclose sensitive meetings, guests, or operational patterns.",
        "remediation": "Remove public calendar sharing unless there is an approved exception.",
        "expected_value": "Calendar sharing is private or explicitly approved.",
    },
    "google.calendar_external_acl": {
        "title": "Calendar ACL grants external access",
        "risk_rating": "high",
        "description": "A Google Calendar access rule grants access outside the Workspace domain.",
        "impact": "External calendar sharing can disclose sensitive meeting metadata outside the managed boundary.",
        "remediation": "Remove unapproved external calendar sharing or document a time-bound exception.",
        "expected_value": "Calendar ACLs are internal or explicitly approved.",
    },
    "google.calendar_domain_acl": {
        "title": "Calendar ACL grants domain-wide access",
        "risk_rating": "medium",
        "description": "A Google Calendar access rule grants access to the entire Workspace domain.",
        "impact": "Domain-wide calendar sharing can expose meeting metadata broadly across the tenant beyond least-privilege need.",
        "remediation": "Restrict calendar sharing to approved groups or individuals unless domain-wide access is explicitly required.",
        "expected_value": "Calendar ACLs are scoped to approved users or groups unless there is a documented domain-wide need.",
    },
    "google.group_external_members_allowed": {
        "title": "Google group allows external members",
        "risk_rating": "medium",
        "description": "A Google group permits external members.",
        "impact": "Groups that allow external members can become uncontrolled access paths for mail, Drive, and app permissions.",
        "remediation": "Disable external members unless the group has an approved business exception.",
        "expected_value": "Groups do not allow external members unless approved.",
    },
    "google.group_anyone_can_post": {
        "title": "Google group allows anyone to post",
        "risk_rating": "medium",
        "description": "A Google group permits public posting.",
        "impact": "Public posting can enable spoofing, spam, and data leakage through collaborative inboxes or group archives.",
        "remediation": "Restrict posting to members, managers, or owners.",
        "expected_value": "Group posting is restricted to approved senders.",
    },
    "google.group_anyone_can_post_unmoderated": {
        "title": "Google group allows public posting without moderation",
        "risk_rating": "medium",
        "description": "A Google group permits public posting and does not moderate posts from non-members.",
        "impact": "Unmoderated public posting increases spam, abuse, and impersonation risk for the group.",
        "remediation": "Set message moderation to at least non-member moderation or disable public posting.",
        "expected_value": "Public-post groups moderate non-member or all messages.",
    },
    "google.group_domain_can_post": {
        "title": "Google group allows domain-wide posting",
        "risk_rating": "medium",
        "description": "A Google group permits all Workspace domain users to post.",
        "impact": "Domain-wide posting can expose collaborative inboxes or group archives to broad internal spoofing, spam, and misdelivery paths.",
        "remediation": "Restrict posting to members, managers, owners, or approved senders unless domain-wide posting is explicitly required.",
        "expected_value": "Group posting is limited to approved senders unless there is a documented domain-wide need.",
    },
    "google.group_domain_can_post_unmoderated": {
        "title": "Google group allows unmoderated domain-wide posting",
        "risk_rating": "medium",
        "description": "A Google group permits all Workspace domain users to post and does not moderate those posts.",
        "impact": "Unmoderated domain-wide posting broadens spoofing, spam, and internal misuse risk across the tenant.",
        "remediation": "Enable moderation for domain-wide posting or restrict posting to a narrower approved sender set.",
        "expected_value": "Domain-wide posting is disabled or moderated unless explicitly approved.",
    },
    "google.group_public_view": {
        "title": "Google group is publicly viewable",
        "risk_rating": "medium",
        "description": "A Google group allows anyone on the internet to view group metadata or content.",
        "impact": "Publicly viewable groups can disclose membership purpose, routing, and discussion structure outside the Workspace boundary.",
        "remediation": "Restrict group visibility to domain users, members, managers, or owners.",
        "expected_value": "Group visibility is limited to approved internal viewers.",
    },
    "google.group_public_membership": {
        "title": "Google group membership is publicly viewable",
        "risk_rating": "medium",
        "description": "A Google group allows anyone on the internet to view group membership.",
        "impact": "Public membership visibility can expose internal people, aliases, and organizational structure to outsiders.",
        "remediation": "Restrict membership visibility to approved internal viewers.",
        "expected_value": "Group membership visibility is limited to approved internal viewers.",
    },
    "google.group_domain_view": {
        "title": "Google group is visible across the Workspace domain",
        "risk_rating": "medium",
        "description": "A Google group allows all domain users to view group metadata or content.",
        "impact": "Domain-wide group visibility can expose collaboration structure and content broadly across the tenant beyond least-privilege need.",
        "remediation": "Restrict group visibility to members, managers, owners, or approved internal groups unless domain-wide visibility is explicitly required.",
        "expected_value": "Group visibility is limited to approved internal viewers unless there is a documented domain-wide need.",
    },
    "google.group_domain_membership": {
        "title": "Google group membership is visible across the Workspace domain",
        "risk_rating": "medium",
        "description": "A Google group allows all domain users to view group membership.",
        "impact": "Domain-wide group membership visibility can expose internal people, aliases, and organizational structure broadly across the tenant.",
        "remediation": "Restrict membership visibility to approved internal viewers unless domain-wide visibility is explicitly required.",
        "expected_value": "Group membership visibility is limited to approved internal viewers unless there is a documented domain-wide need.",
    },
    "google.mobile_device_compromised": {
        "title": "Mobile device is marked compromised",
        "risk_rating": "high",
        "description": "Google Workspace reports a managed mobile device as compromised.",
        "impact": "Compromised mobile devices can expose Workspace sessions, mail, and synchronized data.",
        "remediation": "Block or wipe the device, investigate the owning account, and require device re-enrollment before restoring access.",
        "expected_value": "Managed mobile devices are not marked compromised.",
    },
    "google.mobile_device_stale_sync": {
        "title": "Mobile device has stale sync",
        "risk_rating": "medium",
        "description": "Google Workspace reports a managed mobile device that has not synced recently.",
        "impact": "Stale devices can retain access posture assumptions after they are lost, retired, or unmanaged.",
        "remediation": "Investigate stale mobile devices, block or remove devices no longer in use, and require re-enrollment before restoring access.",
        "expected_value": "Managed mobile devices sync recently or are removed from inventory.",
    },
    "google.chromeos_device_stale_sync": {
        "title": "ChromeOS device has stale sync",
        "risk_rating": "medium",
        "description": "Google Workspace reports a managed ChromeOS device that has not synced recently.",
        "impact": "Stale ChromeOS inventory can leave old device trust assumptions in place after devices are retired, lost, or no longer managed.",
        "remediation": "Investigate stale ChromeOS devices, remove inactive inventory, and re-enroll devices before restoring managed access.",
        "expected_value": "Managed ChromeOS devices sync recently or are removed from inventory.",
    },
    "google.chromeos_device_inactive_assignment": {
        "title": "Inactive ChromeOS device still has assigned user",
        "risk_rating": "medium",
        "description": "Google Workspace reports a disabled or deprovisioned ChromeOS device that still has an annotated user assignment.",
        "impact": "Inactive assigned devices can confuse asset ownership, weaken inventory trust, and hide stale access assumptions.",
        "remediation": "Review inactive ChromeOS inventory, clear stale user assignments, and confirm the device lifecycle state is accurate.",
        "expected_value": "Inactive ChromeOS devices do not retain stale user assignments.",
    },
    "google.alert_active": {
        "title": "Google Workspace Alert Center alert is active",
        "risk_rating": "high",
        "description": "Alert Center returned an active security or admin alert.",
        "impact": "Active alerts can indicate unresolved account, data, or admin security incidents.",
        "remediation": "Triage and close the alert in Google Workspace Alert Center.",
        "expected_value": "Alert Center has no active unresolved security alerts.",
    },
    "google.login_suspicious_event": {
        "title": "Suspicious Google login event observed",
        "risk_rating": "high",
        "description": "Google Reports login activity includes a suspicious login event.",
        "impact": "Suspicious login events can indicate credential theft, impossible travel, or adversary session activity.",
        "remediation": "Investigate the login event, revoke sessions if needed, and confirm 2SV and access controls responded.",
        "expected_value": "Login audit activity has no unresolved suspicious events.",
    },
    "google.admin_privilege_event": {
        "title": "Google admin privilege change observed",
        "risk_rating": "high",
        "description": "Google Reports admin activity includes a role or admin privilege change.",
        "impact": "Unreviewed admin privilege changes can indicate privilege escalation or unauthorized administration.",
        "remediation": "Review the actor, target account, approval trail, and recent login activity; revert unauthorized admin changes.",
        "expected_value": "Admin privilege changes are approved, reviewed, and attributable.",
    },
    "google.dns_spf_missing": {
        "title": "SPF record missing",
        "risk_rating": "medium",
        "description": "The domain does not publish an SPF record.",
        "impact": "Missing SPF weakens email authentication and allows easier spoofing of the Workspace domain.",
        "remediation": "Publish an SPF record that includes Google Workspace mail sources.",
        "expected_value": "The domain publishes a valid SPF record for approved senders.",
    },
    "google.dns_dmarc_monitor_only": {
        "title": "DMARC policy is missing or monitor-only",
        "risk_rating": "medium",
        "description": "The domain's DMARC policy does not enforce quarantine or reject.",
        "impact": "Monitor-only DMARC limits protection against spoofed mail using the Workspace domain.",
        "remediation": "Move DMARC toward quarantine or reject after validating mail flows.",
        "expected_value": "The domain publishes an enforcing DMARC policy.",
    },
    "google.dns_dkim_missing": {
        "title": "Google DKIM selector not found",
        "risk_rating": "medium",
        "description": "No Google Workspace DKIM selector was observed for the domain.",
        "impact": "Missing DKIM reduces message authentication quality and can weaken domain reputation.",
        "remediation": "Enable and publish Google Workspace DKIM signing records.",
        "expected_value": "Google Workspace DKIM selectors are published and active.",
    },
}


def google_rule_metadata() -> dict[str, dict[str, Any]]:
    metadata: dict[str, dict[str, Any]] = {}
    for rule_id, row in _GOOGLE_RULE_METADATA.items():
        item = dict(row)
        item.setdefault("references", ["Google Workspace Admin audit evidence", "Auditex Google Workspace rules"])
        item.setdefault("control_ids", [rule_id.upper().replace(".", "-")])
        mappings = _GOOGLE_FRAMEWORK_MAPPINGS.get(rule_id)
        if mappings:
            item["framework_mappings"] = {key: list(value) for key, value in mappings.items()}
        metadata[rule_id] = item
    return metadata


def _evidence_ref(section: str, collector: str, record: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifact_path": f"normalized/{section}.json",
        "artifact_kind": "normalized_json",
        "collector": collector,
        "record_key": str(record.get("key") or record.get("id") or section),
        "source_name": section,
    }


def _affected_object(record: dict[str, Any]) -> str:
    for key in ("primary_email", "user_email", "actor_email", "email", "domain", "id"):
        value = record.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, (list, dict)):
            continue
        return str(value)
    return str(record.get("id") or record.get("key") or "unknown")


def _finding(
    *,
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    collector: str,
    section: str,
    record: dict[str, Any],
    description: str,
    remediation: str,
    returned_value: Any,
) -> dict[str, Any]:
    metadata = google_rule_metadata().get(rule_id, {})
    finding_id = f"{rule_id}:{record.get('id') or record.get('key')}"
    payload = {
        "id": finding_id,
        "rule_id": rule_id,
        "severity": severity,
        "risk_rating": severity,
        "category": category,
        "title": title or metadata.get("title") or rule_id,
        "status": "open",
        "collector": collector,
        "description": description or metadata.get("description"),
        "impact": metadata.get("impact") or description,
        "remediation": remediation or metadata.get("remediation"),
        "expected_value": metadata.get("expected_value") or "Google Workspace posture follows the approved baseline.",
        "returned_value": returned_value,
        "references": metadata.get("references") or ["Google Workspace Admin audit evidence", "Auditex Google Workspace rules"],
        "control_ids": metadata.get("control_ids") or [rule_id.upper().replace(".", "-")],
        "affected_objects": [_affected_object(record)],
        "evidence_refs": [_evidence_ref(section, collector, record)],
    }
    mappings = _GOOGLE_FRAMEWORK_MAPPINGS.get(rule_id)
    if mappings:
        payload["framework_mappings"] = mappings
    return payload


def _records(snapshot: dict[str, Any], section: str) -> list[dict[str, Any]]:
    payload = snapshot.get(section) or {}
    records = payload.get("records") if isinstance(payload, dict) else []
    return [item for item in records if isinstance(item, dict)] if isinstance(records, list) else []


def _external_email(value: Any, workspace_domain: str | None) -> bool:
    text = str(value or "").strip().lower()
    if "@" not in text or not workspace_domain:
        return False
    return not text.endswith(f"@{workspace_domain.lower()}")


def _external_domain(value: Any, workspace_domain: str | None) -> bool:
    text = str(value or "").strip().lower()
    if not text or not workspace_domain:
        return False
    return text != workspace_domain.lower()


def _drive_permission_record(drive_file: dict[str, Any], permission: dict[str, Any]) -> dict[str, Any]:
    permission_id = str(
        permission.get("id")
        or permission.get("emailAddress")
        or permission.get("domain")
        or permission.get("type")
        or "permission"
    )
    return {**drive_file, "id": f"{drive_file.get('id') or drive_file.get('key')}:{permission_id}"}


def _mailbox_delegate_record(mailbox: dict[str, Any], delegate: dict[str, Any]) -> dict[str, Any]:
    delegate_id = str(delegate.get("delegateEmail") or delegate.get("email") or "delegate")
    return {**mailbox, "id": f"{mailbox.get('id') or mailbox.get('key')}:{delegate_id}"}


def _mailbox_forwarding_address_record(mailbox: dict[str, Any], forwarding_address: dict[str, Any]) -> dict[str, Any]:
    address_id = str(forwarding_address.get("forwardingEmail") or forwarding_address.get("email") or "forwarding_address")
    return {**mailbox, "id": f"{mailbox.get('id') or mailbox.get('key')}:{address_id}"}


def _mailbox_auto_forwarding_record(mailbox: dict[str, Any], auto_forwarding: dict[str, Any]) -> dict[str, Any]:
    address_id = str(auto_forwarding.get("emailAddress") or auto_forwarding.get("forwardTo") or "auto_forwarding")
    return {**mailbox, "id": f"{mailbox.get('id') or mailbox.get('key')}:{address_id}"}


def _mailbox_send_as_record(mailbox: dict[str, Any], send_as: dict[str, Any]) -> dict[str, Any]:
    send_as_id = str(send_as.get("sendAsEmail") or send_as.get("email") or "send_as")
    return {**mailbox, "id": f"{mailbox.get('id') or mailbox.get('key')}:{send_as_id}"}


def _mailbox_filter_record(mailbox: dict[str, Any], gmail_filter: dict[str, Any]) -> dict[str, Any]:
    filter_id = str(gmail_filter.get("id") or gmail_filter.get("forward") or "filter")
    return {**mailbox, "id": f"{mailbox.get('id') or mailbox.get('key')}:{filter_id}"}


def _mailbox_vacation_returned_value(vacation: dict[str, Any]) -> dict[str, Any]:
    return {
        "enableAutoReply": vacation.get("enableAutoReply"),
        "restrictToContacts": vacation.get("restrictToContacts"),
        "restrictToDomain": vacation.get("restrictToDomain"),
    }


def _mailbox_surface_error(
    mailbox: dict[str, Any],
    *,
    surface: str,
    error_key: str,
) -> dict[str, Any] | None:
    payload = mailbox.get(error_key)
    if not isinstance(payload, dict) or not payload:
        return None
    error_class = str(payload.get("error_class") or "client_error")
    return _finding(
        rule_id="google.collector_issue",
        title="Google Workspace collector issue",
        severity="high" if error_class in {"insufficient_permissions", "unauthenticated"} else "medium",
        category="permission" if error_class in {"insufficient_permissions", "unauthenticated"} else "collector",
        collector="google_gmail_settings",
        section="google_mailbox_settings",
        record=mailbox,
        description=f"Google Workspace evidence is incomplete for this Gmail {surface} surface.",
        remediation=f"Fix the Gmail {surface}-read permission or service availability, then rerun the collector.",
        returned_value={"surface": surface, **payload},
    )


def _truthy_google_setting(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "yes", "enabled", "allow"}


def _stale_google_login(value: Any, *, days: int = 365) -> bool:
    text = str(value or "").strip()
    if not text or text.startswith("1970-01-01"):
        return bool(text)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed < datetime.now(tz=timezone.utc) - timedelta(days=days)


def _stale_google_timestamp(value: Any, *, days: int = 90) -> bool:
    return _stale_google_login(value, days=days)


def build_google_findings(normalized_snapshot: dict[str, Any], diagnostics: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    diagnostics = diagnostics or []
    snapshot = normalized_snapshot.get("snapshot") or {}
    workspace_domain = snapshot.get("workspace_domain")
    findings: list[dict[str, Any]] = []

    for row in diagnostics:
        collector = str(row.get("collector") or "google_workspace")
        error_class = str(row.get("error_class") or "client_error")
        target = str(row.get("name") or row.get("endpoint") or collector)
        record = {"id": f"{collector}:{target}", "key": f"diagnostic:{collector}:{target}"}
        findings.append(
            _finding(
                rule_id="google.collector_issue",
                title="Google Workspace collector issue",
                severity="high" if error_class in {"insufficient_permissions", "unauthenticated"} else "medium",
                category="permission" if error_class in {"insufficient_permissions", "unauthenticated"} else "collector",
                collector=collector,
                section="coverage_ledger",
                record=record,
                description="Google Workspace evidence is incomplete for this surface.",
                remediation="Fix the Google Workspace auth scope or service availability, then rerun the collector.",
                returned_value=row.get("error") or error_class,
            )
        )

    for user in _records(normalized_snapshot, "google_users"):
        if user.get("is_admin") and user.get("is_enforced_in_2sv") is False:
            findings.append(
                _finding(
                    rule_id="google.admin_2sv_not_enforced",
                    title="Admin account does not enforce 2-step verification",
                    severity="high",
                    category="identity",
                    collector="google_directory",
                    section="google_users",
                    record=user,
                    description="A Google Workspace admin account is not forced through 2-step verification.",
                    remediation="Enforce 2-step verification for all admin accounts.",
                    returned_value=user.get("primary_email"),
                )
            )
        if user.get("is_admin") and user.get("is_enrolled_in_2sv") is False:
            findings.append(
                _finding(
                    rule_id="google.admin_2sv_not_enrolled",
                    title="Admin account is not enrolled in 2-step verification",
                    severity="high",
                    category="identity",
                    collector="google_directory",
                    section="google_users",
                    record=user,
                    description="A Google Workspace admin account is not enrolled in 2-step verification.",
                    remediation="Enroll all admin accounts in 2-step verification and prefer phishing-resistant methods.",
                    returned_value=user.get("primary_email"),
                )
            )
        if not user.get("is_admin") and not user.get("suspended") and user.get("is_enrolled_in_2sv") is False:
            findings.append(
                _finding(
                    rule_id="google.user_2sv_not_enrolled",
                    title="User account is not enrolled in 2-step verification",
                    severity="medium",
                    category="identity",
                    collector="google_directory",
                    section="google_users",
                    record=user,
                    description="An active Google Workspace user account is not enrolled in 2-step verification.",
                    remediation="Enroll active users in 2-step verification and enforce the Workspace 2SV baseline.",
                    returned_value=user.get("primary_email"),
                )
            )
        if user.get("is_admin") and user.get("suspended"):
            findings.append(
                _finding(
                    rule_id="google.suspended_admin",
                    title="Suspended user still has admin status",
                    severity="medium",
                    category="identity",
                    collector="google_directory",
                    section="google_users",
                    record=user,
                    description="A suspended user still appears as a Google Workspace admin.",
                    remediation="Remove admin privileges from suspended or inactive accounts.",
                    returned_value=user.get("primary_email"),
                )
            )
        if user.get("is_admin") and _stale_google_login(user.get("last_login_time")):
            findings.append(
                _finding(
                    rule_id="google.admin_stale_login",
                    title="Admin account has stale Google Workspace login",
                    severity="medium",
                    category="identity",
                    collector="google_directory",
                    section="google_users",
                    record=user,
                    description="A Google Workspace admin account has not logged in for over 365 days or has never logged in.",
                    remediation="Remove stale admin privileges or confirm the account is a documented emergency account with monitored use.",
                    returned_value=user.get("last_login_time"),
                )
            )

    super_admins = [user for user in _records(normalized_snapshot, "google_users") if user.get("is_admin")]
    if len(super_admins) == 1:
        admin = super_admins[0]
        findings.append(
            _finding(
                rule_id="google.super_admin_singleton",
                title="Only one Google Workspace super admin observed",
                severity="high",
                category="identity",
                collector="google_directory",
                section="google_users",
                record=admin,
                description="Google Workspace has a single observed super admin, creating emergency access fragility.",
                remediation="Maintain at least two protected emergency-capable admins with separate ownership and strong controls.",
                returned_value=admin.get("primary_email"),
            )
        )
    elif len(super_admins) > 5:
        record = {
            "id": "super_admin_sprawl",
            "key": "google_admin_resilience:super_admin_sprawl",
            "primary_email": f"{len(super_admins)} super admins",
        }
        findings.append(
            _finding(
                rule_id="google.super_admin_sprawl",
                title="Too many Google Workspace super admins observed",
                severity="medium",
                category="identity",
                collector="google_directory",
                section="google_users",
                record=record,
                description="Google Workspace has a broad super admin set, increasing blast radius if one account is compromised.",
                remediation="Reduce super admin membership and move routine administration to delegated roles.",
                returned_value={"super_admin_count": len(super_admins)},
            )
        )

    open_join_groups: set[str] = set()

    for group_setting in _records(normalized_snapshot, "google_group_settings"):
        if str(group_setting.get("who_can_join") or "").upper() == "ANYONE_CAN_JOIN":
            group_email = str(group_setting.get("email") or "").strip().lower()
            if group_email:
                open_join_groups.add(group_email)
            findings.append(
                _finding(
                    rule_id="google.group_anyone_can_join",
                    title="Group allows anyone to join",
                    severity="medium",
                    category="collaboration",
                    collector="google_groups_settings",
                    section="google_group_settings",
                    record=group_setting,
                    description="A Google group permits open joining.",
                    remediation="Restrict group joining to owners, managers, or invited users.",
                    returned_value=group_setting.get("email"),
                )
            )
        if str(group_setting.get("who_can_join") or "").upper() == "ALL_IN_DOMAIN_CAN_JOIN":
            findings.append(
                _finding(
                    rule_id="google.group_domain_can_join",
                    title="Group allows domain-wide joining",
                    severity="medium",
                    category="collaboration",
                    collector="google_groups_settings",
                    section="google_group_settings",
                    record=group_setting,
                    description="A Google group allows any Workspace domain user to join.",
                    remediation="Restrict group joining to invited users, owners, managers, or approved request workflows unless domain-wide joining is explicitly required.",
                    returned_value=group_setting.get("email"),
                )
            )

    for group in _records(normalized_snapshot, "google_groups"):
        group_email = str(group.get("email") or "").strip().lower()
        if group_email and group_email in open_join_groups:
            continue
        if str(group.get("who_can_join") or "").upper() == "ANYONE_CAN_JOIN":
            findings.append(
                _finding(
                    rule_id="google.group_anyone_can_join",
                    title="Group allows anyone to join",
                    severity="medium",
                    category="collaboration",
                    collector="google_directory",
                    section="google_groups",
                    record=group,
                    description="A Google group permits open joining.",
                    remediation="Restrict group joining to owners, managers, or invited users.",
                    returned_value=group.get("email"),
                )
            )

    for member in _records(normalized_snapshot, "google_group_members"):
        if _external_email(member.get("email"), workspace_domain):
            findings.append(
                _finding(
                    rule_id="google.group_external_member",
                    title="Google group has external member",
                    severity="medium",
                    category="collaboration",
                    collector="google_directory",
                    section="google_group_members",
                    record=member,
                    description="A Google group includes a member outside the Workspace domain.",
                    remediation="Remove unapproved external members or document the group as an approved external collaboration boundary.",
                    returned_value={"group": member.get("group_email"), "member": member.get("email")},
                )
            )

    for member_error in _records(normalized_snapshot, "google_group_member_errors"):
        error_class = str(member_error.get("error_class") or "client_error")
        findings.append(
            _finding(
                rule_id="google.collector_issue",
                title="Google Workspace collector issue",
                severity="high" if error_class in {"insufficient_permissions", "unauthenticated"} else "medium",
                category="permission" if error_class in {"insufficient_permissions", "unauthenticated"} else "collector",
                collector="google_directory",
                section="google_group_member_errors",
                record=member_error,
                description="Google Workspace evidence is incomplete for this group membership surface.",
                remediation="Fix the Google group member-read permission or service availability, then rerun the collector.",
                returned_value={
                    "surface": "group-members",
                    "group": member_error.get("group_email"),
                    "error_class": member_error.get("error_class"),
                    "error": member_error.get("error"),
                },
            )
        )

    for alias_error in _records(normalized_snapshot, "google_alias_errors"):
        error_class = str(alias_error.get("error_class") or "client_error")
        findings.append(
            _finding(
                rule_id="google.collector_issue",
                title="Google Workspace collector issue",
                severity="high" if error_class in {"insufficient_permissions", "unauthenticated"} else "medium",
                category="permission" if error_class in {"insufficient_permissions", "unauthenticated"} else "collector",
                collector="google_directory",
                section="google_alias_errors",
                record=alias_error,
                description="Google Workspace evidence is incomplete for this user alias surface.",
                remediation="Fix the Google user alias-read permission or service availability, then rerun the collector.",
                returned_value={
                    "surface": "aliases",
                    "user_email": alias_error.get("user_email"),
                    "error_class": alias_error.get("error_class"),
                    "error": alias_error.get("error"),
                },
            )
        )

    high_risk_scope_terms = ("gmail.modify", "gmail.settings.sharing", "/auth/drive", "admin.directory", "cloud-platform")
    for grant in _records(normalized_snapshot, "google_oauth_grants"):
        scopes = [str(item) for item in grant.get("scopes") or []]
        if any(any(term in scope for term in high_risk_scope_terms) for scope in scopes):
            findings.append(
                _finding(
                    rule_id="google.oauth_high_risk_scope",
                    title="OAuth grant includes high-risk scopes",
                    severity="high",
                    category="application",
                    collector="google_directory",
                    section="google_oauth_grants",
                    record=grant,
                    description="A Google OAuth grant includes sensitive mail, Drive, admin, or cloud scopes.",
                    remediation="Review the OAuth client, remove stale grants, and approve only required scopes.",
                    returned_value=scopes,
                )
            )

    for grant_error in _records(normalized_snapshot, "google_oauth_grant_errors"):
        error_class = str(grant_error.get("error_class") or "client_error")
        findings.append(
            _finding(
                rule_id="google.collector_issue",
                title="Google Workspace collector issue",
                severity="high" if error_class in {"insufficient_permissions", "unauthenticated"} else "medium",
                category="permission" if error_class in {"insufficient_permissions", "unauthenticated"} else "collector",
                collector="google_directory",
                section="google_oauth_grant_errors",
                record=grant_error,
                description="Google Workspace evidence is incomplete for this OAuth grant surface.",
                remediation="Fix the Google token-read permission or service availability, then rerun the collector.",
                returned_value={
                    "surface": "oauth-grants",
                    "user_email": grant_error.get("user_email"),
                    "error_class": grant_error.get("error_class"),
                    "error": grant_error.get("error"),
                },
            )
        )

    for mailbox in _records(normalized_snapshot, "google_mailbox_settings"):
        for surface, error_key in (
            ("auto-forwarding", "auto_forwarding_error"),
            ("filters", "filters_error"),
            ("forwarding-addresses", "forwarding_addresses_error"),
            ("send-as", "send_as_error"),
            ("delegates", "delegates_error"),
            ("imap", "imap_error"),
            ("pop", "pop_error"),
            ("vacation", "vacation_error"),
        ):
            issue = _mailbox_surface_error(mailbox, surface=surface, error_key=error_key)
            if issue is not None:
                findings.append(issue)
        auto_forwarding = mailbox.get("auto_forwarding") if isinstance(mailbox.get("auto_forwarding"), dict) else {}
        imap = mailbox.get("imap") if isinstance(mailbox.get("imap"), dict) else {}
        pop = mailbox.get("pop") if isinstance(mailbox.get("pop"), dict) else {}
        vacation = mailbox.get("vacation") if isinstance(mailbox.get("vacation"), dict) else {}
        if imap.get("enabled") is True:
            findings.append(
                _finding(
                    rule_id="google.gmail_imap_enabled",
                    title="Gmail IMAP access is enabled",
                    severity="medium",
                    category="mail",
                    collector="google_gmail_settings",
                    section="google_mailbox_settings",
                    record=mailbox,
                    description="A mailbox permits IMAP access, which can widen mail exfiltration paths.",
                    remediation="Disable IMAP unless there is an approved client requirement.",
                    returned_value=imap,
                )
            )
        if str(pop.get("accessWindow") or "").lower() not in {"", "disabled", "access_window_unspecified"}:
            findings.append(
                _finding(
                    rule_id="google.gmail_pop_enabled",
                    title="Gmail POP access is enabled",
                    severity="medium",
                    category="mail",
                    collector="google_gmail_settings",
                    section="google_mailbox_settings",
                    record=mailbox,
                    description="A mailbox permits POP access, which can bypass modern mail access controls.",
                    remediation="Disable POP unless there is an approved client requirement.",
                    returned_value=pop,
                )
            )
        if vacation.get("enableAutoReply") is True and vacation.get("restrictToDomain") is not True:
            findings.append(
                _finding(
                    rule_id="google.gmail_vacation_external_reply",
                    title="Gmail vacation responder can reply outside the domain",
                    severity="medium",
                    category="mail",
                    collector="google_gmail_settings",
                    section="google_mailbox_settings",
                    record=mailbox,
                    description="A mailbox vacation responder is enabled without restricting replies to the Workspace domain.",
                    remediation="Restrict vacation replies to the Workspace domain or disable the responder unless there is an approved business need.",
                    returned_value=_mailbox_vacation_returned_value(vacation),
                )
            )
        if auto_forwarding.get("enabled") and _external_email(auto_forwarding.get("emailAddress"), workspace_domain):
            findings.append(
                _finding(
                    rule_id="google.gmail_external_forwarding",
                    title="Gmail auto-forwarding sends mail outside the domain",
                    severity="high",
                    category="mail",
                    collector="google_gmail_settings",
                    section="google_mailbox_settings",
                    record=_mailbox_auto_forwarding_record(mailbox, auto_forwarding),
                    description="A mailbox forwards incoming mail to an external address.",
                    remediation="Disable unapproved forwarding or document the business exception.",
                    returned_value=auto_forwarding.get("emailAddress"),
                )
            )
        active_forward_to = str(auto_forwarding.get("emailAddress") or "").strip().lower() if auto_forwarding.get("enabled") else ""
        for forwarding_address in mailbox.get("forwarding_addresses") or []:
            if not isinstance(forwarding_address, dict):
                continue
            forwarding_email = forwarding_address.get("forwardingEmail") or forwarding_address.get("email")
            status = str(forwarding_address.get("verificationStatus") or "").strip().lower()
            if status not in {"accepted", "verified"}:
                continue
            if not _external_email(forwarding_email, workspace_domain):
                continue
            if str(forwarding_email or "").strip().lower() == active_forward_to:
                continue
            findings.append(
                _finding(
                    rule_id="google.gmail_external_forwarding_address_ready",
                    title="Gmail has a verified external forwarding address",
                    severity="medium",
                    category="mail",
                    collector="google_gmail_settings",
                    section="google_mailbox_settings",
                    record=_mailbox_forwarding_address_record(mailbox, forwarding_address),
                    description="A mailbox has a verified external forwarding address that can be used for future auto-forwarding.",
                    remediation="Remove unapproved external forwarding addresses even when they are not currently active.",
                    returned_value=forwarding_email,
                )
            )
        for gmail_filter in mailbox.get("filters") or []:
            action = gmail_filter.get("action") if isinstance(gmail_filter, dict) else {}
            forward_to = action.get("forward") if isinstance(action, dict) else None
            remove_labels = action.get("removeLabelIds") if isinstance(action, dict) else []
            if not isinstance(remove_labels, list):
                remove_labels = []
            if _external_email(forward_to, workspace_domain):
                rule_id = "google.gmail_hidden_forwarding_filter" if "INBOX" in remove_labels else "google.gmail_filter_external_forwarding"
                rule_metadata = google_rule_metadata().get(rule_id, {})
                findings.append(
                    _finding(
                        rule_id=rule_id,
                        title=str(rule_metadata.get("title") or rule_id),
                        severity="high",
                        category="mail",
                        collector="google_gmail_settings",
                        section="google_mailbox_settings",
                        record=_mailbox_filter_record(mailbox, gmail_filter),
                        description=str(rule_metadata.get("description") or "A Gmail filter forwards matching mail to an external address."),
                        remediation=str(rule_metadata.get("remediation") or "Remove unapproved forwarding filters and review mailbox compromise indicators."),
                        returned_value=forward_to,
                    )
                )
        for send_as in mailbox.get("send_as") or []:
            if not isinstance(send_as, dict):
                continue
            send_as_email = send_as.get("sendAsEmail")
            if _external_email(send_as_email, workspace_domain) and str(send_as.get("verificationStatus") or "").lower() in {"accepted", "verified"}:
                findings.append(
                    _finding(
                        rule_id="google.gmail_external_send_as",
                        title="Gmail send-as identity is outside the domain",
                        severity="medium",
                        category="mail",
                        collector="google_gmail_settings",
                        section="google_mailbox_settings",
                        record=_mailbox_send_as_record(mailbox, send_as),
                        description="A mailbox has a verified send-as identity outside the Workspace domain.",
                        remediation="Remove unapproved external send-as identities or document the exception.",
                        returned_value=send_as_email,
                    )
                )
        for delegate in mailbox.get("delegates") or []:
            if not isinstance(delegate, dict):
                continue
            delegate_email = delegate.get("delegateEmail") or delegate.get("email")
            verification_status = str(delegate.get("verificationStatus") or "").lower()
            if _external_email(delegate_email, workspace_domain) and verification_status in {"accepted", "verified"}:
                findings.append(
                    _finding(
                        rule_id="google.gmail_external_delegate",
                        title="Gmail mailbox delegates access outside the domain",
                        severity="high",
                        category="mail",
                        collector="google_gmail_settings",
                        section="google_mailbox_settings",
                        record=_mailbox_delegate_record(mailbox, delegate),
                        description="A Gmail mailbox grants delegate access to an address outside the Workspace domain.",
                        remediation="Remove unapproved external Gmail delegates and review mailbox access history.",
                        returned_value=delegate_email,
                    )
                )
    for drive_file in _records(normalized_snapshot, "google_drive_files"):
        for permission in drive_file.get("permissions") or []:
            if not isinstance(permission, dict):
                continue
            permission_type = str(permission.get("type") or "").lower()
            role = str(permission.get("role") or "").lower()
            write_like = role in {"writer", "fileorganizer", "organizer", "owner"}
            if permission_type == "anyone" and role in {"reader", "commenter", "writer", "fileorganizer", "organizer"}:
                allow_file_discovery = permission.get("allowFileDiscovery") is True
                findings.append(
                    _finding(
                        rule_id="google.drive_public_discoverable" if allow_file_discovery else "google.drive_anyone_with_link",
                        title="Drive file is publicly discoverable" if allow_file_discovery else "Drive file is available to anyone with the link",
                        severity="high" if write_like else "medium",
                        category="collaboration",
                        collector="google_drive_posture",
                        section="google_drive_files",
                        record=drive_file,
                        description=(
                            "A Google Drive item is exposed to anyone and can be discovered without a pre-shared link."
                            if allow_file_discovery
                            else "A Google Drive item grants access to anyone with the link."
                        ),
                        remediation=(
                            "Disable public discoverability and restrict access to approved users or groups."
                            if allow_file_discovery
                            else "Remove public link permissions or document a time-bound exception."
                        ),
                        returned_value={"name": drive_file.get("name"), "permission": permission},
                    )
                )
            if permission_type in {"user", "group"} and _external_email(permission.get("emailAddress"), workspace_domain):
                findings.append(
                    _finding(
                        rule_id="google.drive_external_permission",
                        title="Drive item grants access to an external principal",
                        severity="high" if write_like else "medium",
                        category="collaboration",
                        collector="google_drive_posture",
                        section="google_drive_files",
                        record=_drive_permission_record(drive_file, permission),
                        description="A Google Drive item directly grants access to a user or group outside the Workspace domain.",
                        remediation="Remove unapproved external Drive permissions or document a time-bound exception.",
                        returned_value={"name": drive_file.get("name"), "permission": permission},
                    )
                )
            elif permission_type == "domain" and _external_domain(permission.get("domain"), workspace_domain):
                findings.append(
                    _finding(
                        rule_id="google.drive_external_permission",
                        title="Drive item grants access to an external domain",
                        severity="high" if write_like else "medium",
                        category="collaboration",
                        collector="google_drive_posture",
                        section="google_drive_files",
                        record=_drive_permission_record(drive_file, permission),
                        description="A Google Drive item directly grants access to another domain.",
                        remediation="Remove unapproved external Drive domain permissions or document a time-bound exception.",
                        returned_value={"name": drive_file.get("name"), "permission": permission},
                    )
                )
            elif permission_type == "domain" and workspace_domain and str(permission.get("domain") or "").lower() == str(workspace_domain).lower():
                findings.append(
                    _finding(
                        rule_id="google.drive_domain_permission",
                        title="Drive item grants domain-wide access",
                        severity="high" if write_like else "medium",
                        category="collaboration",
                        collector="google_drive_posture",
                        section="google_drive_files",
                        record=_drive_permission_record(drive_file, permission),
                        description="A Google Drive item grants access to the entire Workspace domain.",
                        remediation="Restrict Drive sharing to approved users or groups unless domain-wide access is explicitly required.",
                        returned_value={"name": drive_file.get("name"), "permission": permission},
                    )
                )

    for shared_drive in _records(normalized_snapshot, "google_shared_drives"):
        restrictions = shared_drive.get("restrictions") if isinstance(shared_drive.get("restrictions"), dict) else {}
        if restrictions.get("domainUsersOnly") is False:
            findings.append(
                _finding(
                    rule_id="google.shared_drive_external_members_allowed",
                    title="Shared drive allows external members",
                    severity="medium",
                    category="collaboration",
                    collector="google_drive_posture",
                    section="google_shared_drives",
                    record=shared_drive,
                    description="A Google shared drive is configured so members do not have to belong to the Workspace domain.",
                    remediation="Restrict shared drives to domain users unless the drive is an approved external collaboration boundary.",
                    returned_value={"name": shared_drive.get("name"), "restrictions": restrictions},
                )
            )

    for calendar_acl in _records(normalized_snapshot, "google_calendar_acls"):
        scope = calendar_acl.get("scope") if isinstance(calendar_acl.get("scope"), dict) else {}
        role = str(calendar_acl.get("role") or "").lower()
        scope_type = str(scope.get("type") or "").lower()
        scope_value = scope.get("value")
        if role in {"", "none"}:
            continue
        if scope_type == "default":
            findings.append(
                _finding(
                    rule_id="google.calendar_public_acl",
                    title="Calendar ACL grants public access",
                    severity="high" if role in {"writer", "owner"} else "medium",
                    category="calendar",
                    collector="google_calendar_posture",
                    section="google_calendar_acls",
                    record=calendar_acl,
                    description="A Google Calendar access rule grants access to the public scope.",
                    remediation="Remove public calendar sharing unless there is an approved exception.",
                    returned_value={"calendar": calendar_acl.get("calendar_id"), "role": role, "scope": scope},
                )
            )
        elif scope_type in {"user", "group"} and _external_email(scope_value, workspace_domain):
            findings.append(
                _finding(
                    rule_id="google.calendar_external_acl",
                    title="Calendar ACL grants external access",
                    severity="high" if role in {"writer", "owner"} else "medium",
                    category="calendar",
                    collector="google_calendar_posture",
                    section="google_calendar_acls",
                    record=calendar_acl,
                    description="A Google Calendar access rule grants access to a user or group outside the Workspace domain.",
                    remediation="Remove unapproved external calendar sharing or document a time-bound exception.",
                    returned_value={"calendar": calendar_acl.get("calendar_id"), "role": role, "scope": scope},
                )
            )
        elif scope_type == "domain" and workspace_domain and str(scope_value or "").lower() != str(workspace_domain).lower():
            findings.append(
                _finding(
                    rule_id="google.calendar_external_acl",
                    title="Calendar ACL grants external domain access",
                    severity="high" if role in {"writer", "owner"} else "medium",
                    category="calendar",
                    collector="google_calendar_posture",
                    section="google_calendar_acls",
                    record=calendar_acl,
                    description="A Google Calendar access rule grants access to another domain.",
                    remediation="Remove unapproved external domain calendar sharing or document a time-bound exception.",
                    returned_value={"calendar": calendar_acl.get("calendar_id"), "role": role, "scope": scope},
                )
            )
        elif scope_type == "domain" and workspace_domain and str(scope_value or "").lower() == str(workspace_domain).lower():
            findings.append(
                _finding(
                    rule_id="google.calendar_domain_acl",
                    title="Calendar ACL grants domain-wide access",
                    severity="medium",
                    category="calendar",
                    collector="google_calendar_posture",
                    section="google_calendar_acls",
                    record=calendar_acl,
                    description="A Google Calendar access rule grants access to the entire Workspace domain.",
                    remediation="Restrict domain-wide calendar sharing to approved calendars or document the business exception.",
                    returned_value={"calendar": calendar_acl.get("calendar_id"), "role": role, "scope": scope},
                )
            )

    for calendar_acl_error in _records(normalized_snapshot, "google_calendar_acl_errors"):
        error_class = str(calendar_acl_error.get("error_class") or "client_error")
        findings.append(
            _finding(
                rule_id="google.collector_issue",
                title="Google Workspace collector issue",
                severity="high" if error_class in {"insufficient_permissions", "unauthenticated"} else "medium",
                category="permission" if error_class in {"insufficient_permissions", "unauthenticated"} else "collector",
                collector="google_calendar_posture",
                section="google_calendar_acl_errors",
                record=calendar_acl_error,
                description="Google Workspace evidence is incomplete for this calendar ACL surface.",
                remediation="Fix the Google Calendar ACL-read permission or service availability, then rerun the collector.",
                returned_value={
                    "surface": "calendar-acls",
                    "calendar": calendar_acl_error.get("calendar_id"),
                    "error_class": calendar_acl_error.get("error_class"),
                    "error": calendar_acl_error.get("error"),
                },
            )
        )

    for group_setting in _records(normalized_snapshot, "google_group_settings"):
        if _truthy_google_setting(group_setting.get("allow_external_members")):
            findings.append(
                _finding(
                    rule_id="google.group_external_members_allowed",
                    title="Google group allows external members",
                    severity="medium",
                    category="collaboration",
                    collector="google_groups_settings",
                    section="google_group_settings",
                    record=group_setting,
                    description="A Google group permits external members.",
                    remediation="Disable external members unless the group has an approved business exception.",
                    returned_value=group_setting.get("email"),
                )
            )
        if str(group_setting.get("who_can_view_group") or "").upper() == "ANYONE_CAN_VIEW":
            findings.append(
                _finding(
                    rule_id="google.group_public_view",
                    title="Google group is publicly viewable",
                    severity="medium",
                    category="collaboration",
                    collector="google_groups_settings",
                    section="google_group_settings",
                    record=group_setting,
                    description="A Google group allows anyone on the internet to view group metadata or content.",
                    remediation="Restrict group visibility to domain users, members, managers, or owners.",
                    returned_value=group_setting.get("email"),
                )
            )
        if str(group_setting.get("who_can_view_group") or "").upper() == "ALL_IN_DOMAIN_CAN_VIEW":
            findings.append(
                _finding(
                    rule_id="google.group_domain_view",
                    title="Google group is visible across the Workspace domain",
                    severity="medium",
                    category="collaboration",
                    collector="google_groups_settings",
                    section="google_group_settings",
                    record=group_setting,
                    description="A Google group allows all domain users to view group metadata or content.",
                    remediation="Restrict group visibility to members, managers, owners, or approved internal groups unless domain-wide visibility is explicitly required.",
                    returned_value=group_setting.get("email"),
                )
            )
        if str(group_setting.get("who_can_view_membership") or "").upper() == "ANYONE_CAN_VIEW":
            findings.append(
                _finding(
                    rule_id="google.group_public_membership",
                    title="Google group membership is publicly viewable",
                    severity="medium",
                    category="collaboration",
                    collector="google_groups_settings",
                    section="google_group_settings",
                    record=group_setting,
                    description="A Google group allows anyone on the internet to view group membership.",
                    remediation="Restrict membership visibility to approved internal viewers.",
                    returned_value=group_setting.get("email"),
                )
            )
        if str(group_setting.get("who_can_view_membership") or "").upper() == "ALL_IN_DOMAIN_CAN_VIEW":
            findings.append(
                _finding(
                    rule_id="google.group_domain_membership",
                    title="Google group membership is visible across the Workspace domain",
                    severity="medium",
                    category="collaboration",
                    collector="google_groups_settings",
                    section="google_group_settings",
                    record=group_setting,
                    description="A Google group allows all domain users to view group membership.",
                    remediation="Restrict membership visibility to approved internal viewers unless domain-wide visibility is explicitly required.",
                    returned_value=group_setting.get("email"),
                )
            )
        if str(group_setting.get("who_can_post_message") or "").upper() == "ANYONE_CAN_POST":
            findings.append(
                _finding(
                    rule_id="google.group_anyone_can_post",
                    title="Google group allows anyone to post",
                    severity="medium",
                    category="collaboration",
                    collector="google_groups_settings",
                    section="google_group_settings",
                    record=group_setting,
                    description="A Google group permits public posting.",
                    remediation="Restrict posting to members, managers, or owners.",
                    returned_value=group_setting.get("email"),
                )
            )
            moderation = str(group_setting.get("message_moderation_level") or "").upper()
            if moderation not in {"MODERATE_NON_MEMBERS", "MODERATE_ALL_MESSAGES"}:
                findings.append(
                    _finding(
                        rule_id="google.group_anyone_can_post_unmoderated",
                        title="Google group allows public posting without moderation",
                        severity="medium",
                        category="collaboration",
                        collector="google_groups_settings",
                        section="google_group_settings",
                        record=group_setting,
                        description="A Google group permits public posting and does not moderate posts from non-members.",
                        remediation="Set message moderation to at least non-member moderation or disable public posting.",
                        returned_value={
                            "email": group_setting.get("email"),
                            "whoCanPostMessage": group_setting.get("who_can_post_message"),
                            "messageModerationLevel": group_setting.get("message_moderation_level"),
                        },
                    )
                )
        if str(group_setting.get("who_can_post_message") or "").upper() == "ALL_IN_DOMAIN_CAN_POST":
            findings.append(
                _finding(
                    rule_id="google.group_domain_can_post",
                    title="Google group allows domain-wide posting",
                    severity="medium",
                    category="collaboration",
                    collector="google_groups_settings",
                    section="google_group_settings",
                    record=group_setting,
                    description="A Google group permits all Workspace domain users to post.",
                    remediation="Restrict posting to members, managers, owners, or approved senders unless domain-wide posting is explicitly required.",
                    returned_value=group_setting.get("email"),
                )
            )
            moderation = str(group_setting.get("message_moderation_level") or "").upper()
            if moderation not in {"MODERATE_NON_MEMBERS", "MODERATE_ALL_MESSAGES"}:
                findings.append(
                    _finding(
                        rule_id="google.group_domain_can_post_unmoderated",
                        title="Google group allows unmoderated domain-wide posting",
                        severity="medium",
                        category="collaboration",
                        collector="google_groups_settings",
                        section="google_group_settings",
                        record=group_setting,
                        description="A Google group permits all Workspace domain users to post and does not moderate those posts.",
                        remediation="Enable moderation for domain-wide posting or restrict posting to a narrower approved sender set.",
                        returned_value={
                            "email": group_setting.get("email"),
                            "whoCanPostMessage": group_setting.get("who_can_post_message"),
                            "messageModerationLevel": group_setting.get("message_moderation_level"),
                        },
                    )
                )

    for group_setting_error in _records(normalized_snapshot, "google_group_setting_errors"):
        error_class = str(group_setting_error.get("error_class") or "client_error")
        findings.append(
            _finding(
                rule_id="google.collector_issue",
                title="Google Workspace collector issue",
                severity="high" if error_class in {"insufficient_permissions", "unauthenticated"} else "medium",
                category="permission" if error_class in {"insufficient_permissions", "unauthenticated"} else "collector",
                collector="google_groups_settings",
                section="google_group_setting_errors",
                record=group_setting_error,
                description="Google Workspace evidence is incomplete for this group settings surface.",
                remediation="Fix the Google Groups settings-read permission or service availability, then rerun the collector.",
                returned_value={
                    "surface": "group-settings",
                    "email": group_setting_error.get("email"),
                    "error_class": group_setting_error.get("error_class"),
                    "error": group_setting_error.get("error"),
                },
            )
        )

    for mobile_device in _records(normalized_snapshot, "google_mobile_devices"):
        if str(mobile_device.get("compromised_status") or "").strip().lower() in {"compromised", "compromised_status_compromised"}:
            findings.append(
                _finding(
                    rule_id="google.mobile_device_compromised",
                    title="Mobile device is marked compromised",
                    severity="high",
                    category="device",
                    collector="google_devices",
                    section="google_mobile_devices",
                    record=mobile_device,
                    description="Google Workspace reports a managed mobile device as compromised.",
                    remediation="Block or wipe the device, investigate the owning account, and require device re-enrollment before restoring access.",
                    returned_value=mobile_device.get("compromised_status"),
                )
            )
        if _stale_google_timestamp(mobile_device.get("last_sync")):
            findings.append(
                _finding(
                    rule_id="google.mobile_device_stale_sync",
                    title="Mobile device has stale sync",
                    severity="medium",
                    category="device",
                    collector="google_devices",
                    section="google_mobile_devices",
                    record=mobile_device,
                    description="Google Workspace reports a managed mobile device that has not synced recently.",
                    remediation="Investigate stale mobile devices, block or remove devices no longer in use, and require re-enrollment before restoring access.",
                    returned_value=mobile_device.get("last_sync"),
                )
            )

    for chrome_device in _records(normalized_snapshot, "google_chromeos_devices"):
        if _stale_google_timestamp(chrome_device.get("last_sync")):
            findings.append(
                _finding(
                    rule_id="google.chromeos_device_stale_sync",
                    title="ChromeOS device has stale sync",
                    severity="medium",
                    category="device",
                    collector="google_devices",
                    section="google_chromeos_devices",
                    record=chrome_device,
                    description="Google Workspace reports a managed ChromeOS device that has not synced recently.",
                    remediation="Investigate stale ChromeOS devices, remove inactive inventory, and re-enroll devices before restoring managed access.",
                    returned_value=chrome_device.get("last_sync"),
                )
            )
        if str(chrome_device.get("status") or "").strip().lower() in {"deprovisioned", "disabled", "inactive"} and str(chrome_device.get("annotated_user") or "").strip():
            findings.append(
                _finding(
                    rule_id="google.chromeos_device_inactive_assignment",
                    title="Inactive ChromeOS device still has assigned user",
                    severity="medium",
                    category="device",
                    collector="google_devices",
                    section="google_chromeos_devices",
                    record=chrome_device,
                    description="Google Workspace reports a disabled or deprovisioned ChromeOS device that still has an annotated user assignment.",
                    remediation="Review inactive ChromeOS inventory, clear stale user assignments, and confirm the device lifecycle state is accurate.",
                    returned_value={"status": chrome_device.get("status"), "annotated_user": chrome_device.get("annotated_user")},
                )
            )

    for alert in _records(normalized_snapshot, "google_alerts"):
        findings.append(
            _finding(
                rule_id="google.alert_active",
                title="Google Workspace Alert Center alert is active",
                severity="high" if str(alert.get("severity") or "").upper() in {"HIGH", "CRITICAL"} else "medium",
                category="security",
                collector="google_alert_center",
                section="google_alerts",
                record=alert,
                description="Alert Center returned an active security or admin alert.",
                remediation="Triage and close the alert in Google Workspace Alert Center.",
                returned_value=alert.get("alert_type"),
            )
        )

    suspicious_login_events = {"suspicious_login", "suspicious_login_activity", "login_challenge"}
    admin_privilege_events = {
        "assign_role",
        "change_user_admin_privilege",
        "change_user_privilege",
        "create_role",
        "grant_admin_privilege",
    }
    for activity in _records(normalized_snapshot, "google_activity_events"):
        event_names = {str(name or "").strip().lower() for name in activity.get("event_names") or []}
        application = str(activity.get("application") or "").lower()
        if application == "login" and event_names.intersection(suspicious_login_events):
            findings.append(
                _finding(
                    rule_id="google.login_suspicious_event",
                    title="Suspicious Google login event observed",
                    severity="high",
                    category="identity",
                    collector="google_reports",
                    section="google_activity_events",
                    record=activity,
                    description="Google Reports login activity includes a suspicious login event.",
                    remediation="Investigate the login event, revoke sessions if needed, and confirm 2SV and access controls responded.",
                    returned_value=sorted(event_names),
                )
            )
        if application == "admin" and event_names.intersection(admin_privilege_events):
            findings.append(
                _finding(
                    rule_id="google.admin_privilege_event",
                    title="Google admin privilege change observed",
                    severity="high",
                    category="identity",
                    collector="google_reports",
                    section="google_activity_events",
                    record=activity,
                    description="Google Reports admin activity includes a role or admin privilege change.",
                    remediation="Review the actor, target account, approval trail, and recent login activity; revert unauthorized admin changes.",
                    returned_value=sorted(event_names),
                )
            )

    for posture in _records(normalized_snapshot, "google_dns_posture"):
        spf = posture.get("spf") if isinstance(posture.get("spf"), dict) else {}
        dmarc = posture.get("dmarc") if isinstance(posture.get("dmarc"), dict) else {}
        dkim = posture.get("dkim") if isinstance(posture.get("dkim"), dict) else {}
        if not spf.get("present"):
            findings.append(
                _finding(
                    rule_id="google.dns_spf_missing",
                    title="SPF record missing",
                    severity="medium",
                    category="dns",
                    collector="google_dns_posture",
                    section="google_dns_posture",
                    record=posture,
                    description="The domain does not publish an SPF record.",
                    remediation="Publish an SPF record that includes Google Workspace mail sources.",
                    returned_value=posture.get("domain"),
                )
            )
        if dmarc.get("policy") in {None, "", "none"}:
            findings.append(
                _finding(
                    rule_id="google.dns_dmarc_monitor_only",
                    title="DMARC policy is missing or monitor-only",
                    severity="medium",
                    category="dns",
                    collector="google_dns_posture",
                    section="google_dns_posture",
                    record=posture,
                    description="The domain's DMARC policy does not enforce quarantine or reject.",
                    remediation="Move DMARC toward quarantine or reject after validating mail flows.",
                    returned_value=dmarc.get("policy"),
                )
            )
        if not dkim.get("selectors_present"):
            findings.append(
                _finding(
                    rule_id="google.dns_dkim_missing",
                    title="Google DKIM selector not found",
                    severity="medium",
                    category="dns",
                    collector="google_dns_posture",
                    section="google_dns_posture",
                    record=posture,
                    description="No Google Workspace DKIM selector was observed for the domain.",
                    remediation="Enable and publish Google Workspace DKIM signing records.",
                    returned_value=posture.get("domain"),
                )
            )
    return findings
