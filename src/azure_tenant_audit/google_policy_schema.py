"""Field allow-list for Google Cloud Identity Policy API evidence.

Field names and enum members come from Google's supported Policy API settings
and ScubaGoggles v1.1.0 (08a08ce1). Objects and repeated objects are projected
recursively. A null under a known field represents an unreadable value.

https://docs.cloud.google.com/identity/docs/concepts/supported-policy-api-settings
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

CUSTOMER_ID = re.compile(r"C0[0-9A-Za-z]{5,}")
_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}(?::[A-Za-z0-9][A-Za-z0-9_-]{0,127})?")
_DURATION = re.compile(r"[0-9]{1,12}(?:\.[0-9]{1,9})?s")
_TIMESTAMP = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2})[Tt]([0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.([0-9]{1,9}))?([Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


def policy_reference(value: Any) -> bool:
    """Only opaque references in Google ID fields, including Gmail's colon-separated IDs."""
    return (
        isinstance(value, str)
        and bool(_REFERENCE.fullmatch(value))
        and not value.lower().startswith("redacted:")
        and CUSTOMER_ID.search(value) is None
    )


def _timestamp_parts(value: Any) -> tuple[datetime, str] | None:
    match = _TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return None
    date, time, fraction, zone = match.groups()
    offset = "+00:00" if zone.upper() == "Z" else zone
    try:
        second = datetime.fromisoformat(f"{date}T{time}{offset}").astimezone(UTC)
    except (ValueError, OverflowError):
        return None
    return second, fraction or ""


def policy_timestamp_utc(value: Any) -> str | None:
    """An RFC 3339 timestamp in UTC, preserving all fractional digits."""
    parsed = _timestamp_parts(value)
    if parsed is None:
        return None
    second, fraction = parsed
    return second.isoformat()[:-6] + (f".{fraction}" if fraction else "") + "Z"


def policy_enforced_at(value: Any, as_of: datetime) -> bool:
    """Whether the timestamp is in force at as_of, including sub-microsecond fractions."""
    parsed = _timestamp_parts(value)
    if parsed is None:
        return False
    second, fraction = parsed
    return (second, int(fraction.ljust(9, "0"))) <= (as_of.replace(microsecond=0), as_of.microsecond * 1_000)


def _ip_address(value: Any) -> str | None:
    # Zone identifiers and netmasks are unnecessary. A zone can contain arbitrary text.
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F.:]{1,45}(?:/[0-9]{1,3})?", value):
        return None
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    return value


@dataclass(frozen=True)
class RequiredPolicyField:
    """A missing field leaves the containing evidence unreadable."""

    schema: Any
    when: str | None = None


def _value_schemas() -> dict[str, dict[str, Any]]:
    schemas: dict[str, dict[str, Any]] = {
        "access_approval.axa_user_scoping": {
            "requiresCustomerApproval": "bool",
        },
        "access_management.user_scoping": {
            "accessManagementRegime": ("PREFERENCE_UNSPECIFIED", "CJIS_IRS_1075_GOOGLE_STAFF", "US_GOOGLE_STAFF", "EU_GOOGLE_STAFF"),
        },
        "api_controls.app_approval_requests": {
            "allowedForAll": ("OPTION_UNSPECIFIED", "ENABLED", "DISABLED"),
        },
        "api_controls.custom_user_message": {},
        "api_controls.google_services": {},
        "api_controls.internal_apps": {
            "trustInternalApps": "bool",
        },
        "api_controls.unconfigured_third_party_apps": {
            "accessLevel": ("ACCESS_LEVEL_UNSPECIFIED", "BLOCK_ALL", "ALLOW_SIGN_IN_ONLY"),
            "accessLevelUnder18": ("ACCESS_LEVEL_UNDER18_UNSPECIFIED", "ALLOW_SIGN_IN_ONLY_UNDER18"),
        },
        "calendar.appointment_schedules": {
            "enablePayments": "bool",
        },
        "calendar.external_invitations": {
            "warnOnInvite": "bool",
        },
        "calendar.interoperability": {
            "enableInteroperability": "bool",
            "enableFullEventDetails": "bool",
            "enableExchangeRoomBooking": "bool",
        },
        "calendar.primary_calendar_max_allowed_external_sharing": {
            "maxAllowedExternalSharing": (
                "EXTERNAL_FREE_BUSY_ONLY",
                "EXTERNAL_ALL_INFO_READ_ONLY",
                "EXTERNAL_ALL_INFO_READ_WRITE",
                "EXTERNAL_ALL_INFO_READ_WRITE_MANAGE",
            ),
        },
        "calendar.secondary_calendar_max_allowed_external_sharing": {
            "maxAllowedExternalSharing": (
                "EXTERNAL_FREE_BUSY_ONLY",
                "EXTERNAL_ALL_INFO_READ_ONLY",
                "EXTERNAL_ALL_INFO_READ_WRITE",
                "EXTERNAL_ALL_INFO_READ_WRITE_MANAGE",
            ),
        },
        "calendar.service_status": {
            "serviceState": ("ENABLED", "DISABLED"),
        },
        "chat.chat_and_space_restrictions": {
            "restrictionLevel": ("RESTRICTION_LEVEL_UNSPECIFIED", "UNRESTRICTED", "RESTRICTED"),
        },
        "chat.chat_apps_access": {
            "enableApps": "bool",
            "enableWebhooks": "bool",
        },
        "chat.chat_external_spaces": {
            "enabled": "bool",
            "domainAllowlistMode": ("DOMAIN_ALLOWLIST_MODE_UNSPECIFIED", "TRUSTED_DOMAINS", "ALL_DOMAINS"),
        },
        "chat.chat_file_sharing": {
            "externalFileSharing": ("ALL_FILES", "IMAGES_ONLY", "NO_FILES", "FILE_SHARING_OPTION_UNSPECIFIED"),
            "internalFileSharing": ("ALL_FILES", "IMAGES_ONLY", "NO_FILES", "FILE_SHARING_OPTION_UNSPECIFIED"),
        },
        "chat.chat_history": {
            "historyOnByDefault": "bool",
            "allowUserModification": "bool",
        },
        "chat.chat_space_access_default": {
            "accessType": ("ACCESS_TYPE_UNSPECIFIED", "RESTRICTED", "PRIMARY_TARGET_AUDIENCE"),
        },
        "chat.chat_third_party_archiving": {
            "enabled": "bool",
        },
        "chat.content_reporting": {
            "oneOnOneDirectMessagesReporting": ("CONTENT_REPORTING_STATE_UNSPECIFIED", "ENABLED", "DISABLED"),
            "groupDirectMessagesReporting": ("CONTENT_REPORTING_STATE_UNSPECIFIED", "ENABLED", "DISABLED"),
            "spacesReporting": ("CONTENT_REPORTING_STATE_UNSPECIFIED", "ENABLED", "DISABLED"),
            "spacesReportingType": ("SPACES_REPORTING_TYPE_UNSPECIFIED", "ALL_SPACES", "DISCOVERABLE_SPACES_ONLY"),
            "reportingFormCustomizationEnabled": "bool",
        },
        "chat.external_chat_restriction": {
            "allowExternalChat": "bool",
            "externalChatRestriction": ("NO_RESTRICTION", "TRUSTED_DOMAINS", "RESTRICTION_UNSPECIFIED"),
        },
        "chat.service_status": {
            "serviceState": ("ENABLED", "DISABLED"),
        },
        "chat.space_history": {
            "historyState": (
                "DEFAULT_HISTORY_ON",
                "DEFAULT_HISTORY_OFF",
                "HISTORY_ALWAYS_ON",
                "HISTORY_ALWAYS_OFF",
                "HISTORY_STATE_UNSPECIFIED",
            ),
        },
        "classroom.api_data_access": {
            "enableApiAccess": "bool",
        },
        "classroom.class_membership": {
            "whoCanJoinClasses": ("ANYONE_IN_DOMAIN", "ANYONE_IN_ALLOWLISTED_DOMAINS", "ANY_GOOGLE_WORKSPACE_USER", "ANYONE"),
            "whichClassesCanUsersJoin": ("CLASSES_IN_DOMAIN", "CLASSES_IN_ALLOWLISTED_DOMAINS", "ANY_GOOGLE_WORKSPACE_CLASS"),
        },
        "classroom.gemini_access": {
            "enabled": "bool",
        },
        "classroom.guardian_access": {
            "allowAccess": "bool",
            "whoCanManageGuardianAccess": ("VERIFIED_TEACHERS_AND_DOMAIN_ADMINS", "DOMAIN_ADMINS_ONLY"),
        },
        "classroom.originality_reports": {
            "enableOriginalityReportsSchoolMatches": "bool",
        },
        "classroom.roster_import": {
            "rosterImportOption": ("OFF", "ON_CLEVER"),
        },
        "classroom.service_status": {
            "serviceState": ("ENABLED", "DISABLED"),
        },
        "classroom.student_unenrollment": {
            "whoCanUnenrollStudents": ("STUDENTS_AND_TEACHERS", "TEACHERS_ONLY"),
        },
        "classroom.teacher_permissions": {
            "whoCanCreateClasses": ("ANYONE_IN_DOMAIN", "ALL_PENDING_AND_VERIFIED_TEACHERS", "VERIFIED_TEACHERS_ONLY"),
        },
        "data_regions.data_at_rest_region": {
            "region": ("REGION_UNSPECIFIED", "ANY_REGION", "US", "EUROPE"),
        },
        "data_regions.data_processing_region": {
            "limitToStorageRegion": "bool",
        },
        "drive_and_docs.drive_for_desktop": {
            "allowDriveForDesktop": "bool",
            "restrictToAuthorizedDevices": "bool",
            "showDownloadLink": "bool",
            "allowRealTimePresence": "bool",
        },
        "drive_and_docs.drive_sdk": {
            "enableDriveSdkApiAccess": "bool",
        },
        "drive_and_docs.external_file_warning": {
            "highlightingEnabled": "bool",
        },
        "drive_and_docs.external_sharing": {
            "externalSharingMode": ("DISALLOWED", "ALLOWLISTED_DOMAINS", "ALLOWED"),
            "allowReceivingExternalFiles": "bool",
            "warnForSharingOutsideAllowlistedDomains": "bool",
            "allowReceivingFilesOutsideAllowlistedDomains": "bool",
            "allowNonGoogleInvitesInAllowlistedDomains": "bool",
            "warnForExternalSharing": "bool",
            "allowNonGoogleInvites": "bool",
            "allowPublishingFiles": "bool",
            "accessCheckerSuggestions": ("RECIPIENTS_OR_AUDIENCE_OR_PUBLIC", "RECIPIENTS_OR_AUDIENCE", "RECIPIENTS_ONLY"),
            "allowedPartiesForDistributingContent": ("ALL_ELIGIBLE_USERS", "ELIGIBLE_INTERNAL_USERS", "NONE"),
        },
        "drive_and_docs.file_security_update": {
            "securityUpdate": ("APPLY_TO_IMPACTED_FILES", "REMOVE_FROM_IMPACTED_FILES"),
            "allowUsersToManageUpdate": "bool",
        },
        "drive_and_docs.general_access_default": {
            "defaultFileAccess": (
                "PRIVATE_TO_OWNER",
                "PRIMARY_AUDIENCE_WITH_LINK",
                "PRIMARY_AUDIENCE_WITH_LINK_OR_SEARCH",
                "LINK_SHARING_PRIVATE",
            ),
        },
        "drive_and_docs.service_status": {
            "serviceState": ("ENABLED", "DISABLED"),
        },
        "drive_and_docs.shared_drive_creation": {
            "allowSharedDriveCreation": "bool",
            "orgUnitForNewSharedDrives": ("CREATOR_ORG_UNIT", "CUSTOM_ORG_UNIT"),
            "allowManagersToOverrideSettings": "bool",
            "allowExternalUserAccess": "bool",
            "allowNonMemberAccess": "bool",
            "allowedPartiesForDownloadPrintCopy": ("ALL", "EDITORS_ONLY", "MANAGERS_ONLY"),
            "allowContentManagersToShareFolders": "bool",
        },
        "early_access_apps.service_status": {
            "serviceState": ("ENABLED", "DISABLED"),
        },
        "enterprise_service_restrictions.service_status": {
            "serviceState": ("ENABLED", "DISABLED"),
        },
        "gemini_app.conversation_history": {
            "conversationHistoryState": ("CONVERSATION_HISTORY_STATE_UNSPECIFIED", "ENABLED", "DISABLED"),
            "conversationRetention": ("CONVERSATION_RETENTION_UNSPECIFIED", "THREE_MONTHS", "EIGHTEEN_MONTHS", "THIRTY_SIX_MONTHS"),
        },
        "gemini_app.conversation_sharing": {
            "conversationSharingOption": (
                "CONVERSATION_SHARING_OPTION_UNSPECIFIED",
                "ALLOW_SHARING_VIA_LINK",
                "ALLOW_SHARING_VIA_DRIVE",
                "DISABLED",
            ),
        },
        "gemini_app.gem_sharing": {
            "gemSharingAllowed": "bool",
        },
        "gemini_app.service_status": {
            "serviceState": ("ENABLED", "DISABLED"),
        },
        "gemini_app.unlicensed_user_access": {
            "enabled": "bool",
        },
        "gmail.attachment_compliance": {},
        "gmail.auto_forwarding": {
            "enableAutoForwarding": "bool",
            "allowedForwardingDestination": ("ANY_ADDRESS", "INTERNAL_ADDRESSES"),
        },
        "gmail.blocked_sender_lists": {},
        "gmail.comprehensive_mail_storage": {
            "ruleId": RequiredPolicyField("reference"),
        },
        "gmail.confidential_mode": {
            "enableConfidentialMode": "bool",
        },
        "gmail.content_compliance": {},
        "gmail.email_address_lists": {},
        "gmail.email_attachment_safety": {
            "enableEncryptedAttachmentProtection": "bool",
            "encryptedAttachmentProtectionConsequence": ("WARNING", "SPAM_FOLDER", "QUARANTINE"),
            "encryptedAttachmentProtectionQuarantineId": "int",
            "enableAttachmentWithScriptsProtection": "bool",
            "attachmentWithScriptsProtectionConsequence": ("WARNING", "SPAM_FOLDER", "QUARANTINE"),
            "attachmentWithScriptsProtectionQuarantineId": "int",
            "enableAnomalousAttachmentProtection": "bool",
            "anomalousAttachmentProtectionConsequence": ("WARNING", "SPAM_FOLDER", "QUARANTINE"),
            "anomalousAttachmentProtectionQuarantineId": "int",
            "applyFutureRecommendedSettingsAutomatically": "bool",
        },
        "gmail.email_image_proxy_bypass": {
            "enableImageProxy": "bool",
        },
        "gmail.email_quarantines": {},
        "gmail.email_spam_filter_ip_allowlist": {
            "allowedIpAddresses": ["ip"],
        },
        "gmail.enhanced_pre_delivery_message_scanning": {
            "enableImprovedSuspiciousContentDetection": "bool",
        },
        "gmail.enhanced_smime_encryption": {
            "allowUserToUploadCertificates": "bool",
        },
        "gmail.external_recipient_warning": {
            "enabled": "bool",
        },
        "gmail.gmail_name_format": {
            "allowCustomDisplayNames": "bool",
            "defaultDisplayNameFormat": ("FIRSTNAME_LASTNAME", "LASTNAME_COMMA_FIRSTNAME"),
        },
        "gmail.imap_access": {
            "enableImapAccess": "bool",
        },
        "gmail.links_and_external_images": {
            "enableShortenerScanning": "bool",
            "enableExternalImageScanning": "bool",
            "enableAggressiveWarningsOnUntrustedLinks": "bool",
            "applyFutureSettingsAutomatically": "bool",
        },
        "gmail.mail_delegation": {
            "enableMailDelegation": "bool",
            "allowCustomDelegateAttribution": "bool",
            "enableDelegateAttribution": "bool",
            "enableMailboxGroupDelegation": "bool",
        },
        "gmail.objectionable_content": {},
        "gmail.per_user_outbound_gateway": {
            "allowUsersToUseExternalSmtpServers": "bool",
        },
        "gmail.pop_access": {
            "enablePopAccess": "bool",
        },
        "gmail.restrict_delivery": {},
        "gmail.rule_states": {},
        "gmail.service_status": {
            "serviceState": ("ENABLED", "DISABLED"),
        },
        "gmail.smime_encryption": {
            "enableSmimeEncryption": ("STATUS_UNSPECIFIED", "STATUS_DISABLED", "STATUS_ENABLED"),
            "allowSha1GloballyInSmimeSignature": "bool",
        },
        "gmail.spam_override_lists": {},
        "gmail.spoofing_and_authentication": {
            "detectDomainNameSpoofing": "bool",
            "domainNameSpoofingConsequence": ("WARNING", "SPAM_FOLDER", "QUARANTINE", "NO_ACTION"),
            "domainNameSpoofingQuarantineId": "int",
            "detectEmployeeNameSpoofing": "bool",
            "employeeNameSpoofingConsequence": ("WARNING", "SPAM_FOLDER", "QUARANTINE", "NO_ACTION"),
            "employeeNameSpoofingQuarantineId": "int",
            "detectDomainSpoofingFromUnauthenticatedSenders": "bool",
            "domainSpoofingConsequence": ("WARNING", "SPAM_FOLDER", "QUARANTINE", "NO_ACTION"),
            "domainSpoofingQuarantineId": "int",
            "detectUnauthenticatedEmails": "bool",
            "unauthenticatedEmailConsequence": ("WARNING", "SPAM_FOLDER", "QUARANTINE", "NO_ACTION"),
            "unauthenticatedEmailQuarantineId": "int",
            "detectGroupsSpoofing": "bool",
            "groupsSpoofingVisibilityType": ("PRIVATE_GROUPS_ONLY", "ALL_GROUPS"),
            "groupsSpoofingConsequence": ("WARNING", "SPAM_FOLDER", "QUARANTINE", "NO_ACTION"),
            "groupsSpoofingQuarantineId": "int",
            "applyFutureSettingsAutomatically": "bool",
        },
        "gmail.user_email_uploads": {
            "enableMailAndContactsImport": "bool",
        },
        "gmail.web_offline": {
            "enabled": "bool",
            "signoutDataDeletionEnforced": "bool",
        },
        "gmail.workspace_sync_for_outlook": {
            "enableGoogleWorkspaceSyncForMicrosoftOutlook": "bool",
        },
        "groups_for_business.groups_sharing": {
            "collaborationCapability": ("ANYONE_CAN_ACCESS", "DOMAIN_USERS_ONLY"),
            "createGroupsAccessLevel": ("ADMIN_ONLY", "USERS_IN_DOMAIN", "ANYONE_CAN_CREATE"),
            "ownersCanAllowExternalMembers": "bool",
            "ownersCanAllowIncomingMailFromPublic": "bool",
            "viewTopicsDefaultAccessLevel": ("OWNERS", "MANAGERS", "GROUP_MEMBERS", "DOMAIN_USERS", "ANYONE_CAN_VIEW_TOPICS"),
            "ownersCanHideGroups": "bool",
            "newGroupsAreHidden": "bool",
        },
        "groups_for_business.service_status": {
            "serviceState": ("ENABLED", "DISABLED"),
        },
        "meet.automatic_recording": {
            "enabled": "bool",
        },
        "meet.automatic_transcription": {
            "enabled": "bool",
        },
        "meet.meet_incoming_call_restrictions": {
            "allowedCallers": ("ALLOWED_CALLERS_UNSPECIFIED", "ALL", "CONTACTS_AND_ORGANIZATION_ONLY", "NONE"),
        },
        "meet.meet_joining": {
            "allowedAudience": ("ALLOWED_AUDIENCE_UNSPECIFIED", "OPEN", "TRUSTED", "RESTRICTED"),
        },
        "meet.meet_messaging": {
            "enabled": "bool",
        },
        "meet.meet_polls": {
            "enabled": "bool",
        },
        "meet.meet_presenting": {
            "enabled": "bool",
        },
        "meet.meet_questions": {
            "enabled": "bool",
        },
        "meet.safety_access": {
            "meetingsAllowedToJoin": ("SAME_ORGANIZATION_ONLY", "ANY_WORKSPACE_ORGANIZATION", "ALL"),
        },
        "meet.safety_domain": {
            "usersAllowedToJoin": ("SAME_ORGANIZATION_ONLY", "LOGGED_IN", "ALL"),
        },
        "meet.safety_external_participants": {
            "enableExternalLabel": "bool",
        },
        "meet.safety_host_management": {
            "enableHostManagement": "bool",
        },
        "meet.service_status": {
            "serviceState": ("ENABLED", "DISABLED"),
        },
        "meet.video_recording": {
            "enableRecording": "bool",
        },
        "multi_party_approval.calendar_actions": {},
        "multi_party_approval.domains_actions": {},
        "multi_party_approval.groups_actions": {},
        "multi_party_approval.require_approvals": {
            "multiPartyApprovalState": ("MULTI_PARTY_APPROVAL_STATE_UNSPECIFIED", "ENABLED", "DISABLED"),
        },
        "multi_party_approval.security_actions": {},
        "multi_party_approval.security_actions_api_access": {},
        "provisioning.conflicting_accounts_management": {
            "option": (
                "OPTION_UNSPECIFIED",
                "AUTOMATICALLY_SEND_INVITATIONS",
                "REPLACE_CONFLICTING_ACCOUNT",
                "PRESERVE_CONFLICTING_ACCOUNT",
            ),
        },
        "rule.system_defined_alerts": {
            "state": ("ACTIVE", "INACTIVE"),
            "createTime": "timestamp",
            "updateTime": "timestamp",
            "displayName": "system-alert-name",
        },
        "security.advanced_protection_program": {
            "enableAdvancedProtectionSelfEnrollment": "bool",
            "securityCodeOption": ("ALLOWED_WITH_REMOTE_ACCESS", "ALLOWED_WITHOUT_REMOTE_ACCESS", "CODES_NOT_ALLOWED"),
        },
        "security.less_secure_apps": {
            "allowLessSecureApps": "bool",
        },
        "security.login_challenges": {
            "enableEmployeeIdChallenge": "bool",
        },
        "security.passkeys_restriction": {
            "allowedPasskeysType": ("ALLOWED_PASSKEYS_TYPE_UNSPECIFIED", "HARDWARE_SECURITY_KEYS_ONLY", "ANY_DEVICE_OR_PLATFORM"),
        },
        "security.password": {
            "expirationDuration": "duration",
            "allowReuse": "bool",
            "enforceRequirementsAtLogin": "bool",
            "maximumLength": "int",
            "minimumLength": "int",
            "allowedStrength": ("STRONG", "WEAK"),
        },
        "security.session_controls": {
            "webSessionDuration": "duration",
        },
        "security.super_admin_account_recovery": {
            "enableAccountRecovery": "bool",
        },
        "security.two_step_verification_device_trust": {
            "allowTrustingDevice": "bool",
        },
        "security.two_step_verification_enforcement": {
            "enforcedFrom": "timestamp",
        },
        "security.two_step_verification_enforcement_factor": {
            "allowedSignInFactorSet": (
                "ALL",
                "PASSKEY_ONLY",
                "PASSKEY_PLUS_SECURITY_CODE",
                "PASSKEY_PLUS_IP_BOUND_SECURITY_CODE",
                "NO_TELEPHONY",
            ),
        },
        "security.two_step_verification_enrollment": {
            "allowEnrollment": "bool",
        },
        "security.two_step_verification_grace_period": {
            "enrollmentGracePeriod": "duration",
        },
        "security.two_step_verification_sign_in_code": {
            "backupCodeExceptionPeriod": "duration",
        },
        "security.user_account_recovery": {
            "enableAccountRecovery": "bool",
        },
        "sites.service_status": {
            "serviceState": ("ENABLED", "DISABLED"),
        },
        "sites.sites_creation_and_modification": {
            "allowSitesCreation": "bool",
            "allowSitesModification": "bool",
        },
        "takeout.service_status": {
            "serviceState": ("ENABLED", "DISABLED"),
        },
        "workspace_marketplace.apps_access_options": {
            "accessLevel": ("ALLOW_ALL", "ALLOW_LISTED_APPS", "ALLOW_NONE"),
            "allowAllInternalApps": "bool",
        },
        "workspace_marketplace.apps_allowlist": {},
    }

    # ProtoJSON wrappers are represented by their scalar values. These references join the
    # corresponding Gmail rule or address-list ID, so a discarded element invalidates the row.
    spam_override = {
        "ruleId": RequiredPolicyField("reference"),
        "enableAggressiveFiltering": "bool",
        "addToQuarantine": "bool",
        "quarantineId": "int",
        "bypassInternalSenders": "bool",
        "bypassSelectedSenders": "bool",
        "bypassSenderAllowlist": RequiredPolicyField(["reference"], when="bypassSelectedSenders"),
        "hideWarningBannerFromSelectedSenders": "bool",
        "hideWarningBannerSenderAllowlist": RequiredPolicyField(["reference"], when="hideWarningBannerFromSelectedSenders"),
        "hideWarningBannerForAll": "bool",
    }
    blocked_sender = {
        "ruleId": RequiredPolicyField("reference"),
        "senderBlocklist": ["reference"],
        "bypassApprovedSender": "bool",
        "bypassApprovedSenderAllowlist": RequiredPolicyField(["reference"], when="bypassApprovedSender"),
    }
    api_service = {
        "scopesGroup": RequiredPolicyField((
            "UNSPECIFIED", "DRIVE_ALL", "DRIVE_HIGH_RISK", "GMAIL_ALL", "GMAIL_HIGH_RISK", "CALENDAR_ALL",
            "CONTACTS_ALL", "GSUITE_ADMIN_ALL", "VAULT_ALL", "CLOUD_PLATFORM", "CLOUD_BILLING", "CLOUD_ML",
            "APPS_SCRIPT_RUNTIME", "APPS_SCRIPT_API", "CLASSROOM_ALL", "CLASSROOM_HIGH_RISK", "COMMUNICATIONS",
            "TASKS", "GROUPS", "KEEP", "CLOUD_SEARCH", "CHAT", "SIGN_IN", "CHAT_HIGH_RISK", "MEET",
            "WORKSPACE_STUDIO", "VOICE", "GEMINI_NOTEBOOK",
        )),
        "isEnabled": RequiredPolicyField("bool"),
    }
    alert = {
        "displayName": RequiredPolicyField("system-alert-name"),
        "state": RequiredPolicyField(("ACTIVE", "INACTIVE")),
        "createTime": "timestamp",
        "updateTime": "timestamp",
    }
    schemas.update({
        "api_controls.google_services": {"services": [api_service]},
        "gmail.blocked_sender_lists": {"blockedSenders": [blocked_sender]},
        "gmail.email_address_lists": {"emailAddressList": "address-lists"},
        "gmail.email_spam_filter_ip_allowlist": {"allowedIpAddresses": ["ip"]},
        "gmail.spam_override_lists": {"spamOverride": [spam_override]},
        "gmail.rule_states": {"ruleStates": [{"ruleId": RequiredPolicyField("reference"), "enabled": RequiredPolicyField("bool")}]},
        "rule.system_defined_alerts": {**alert, "rules": [alert]},
    })
    return schemas


POLICY_VALUE_SCHEMAS = _value_schemas()

# Older 2SV samples and API responses use both spellings, sometimes with more than
# one of these fields on a 2SV row. Keep the spelling so older bundle shapes survive.
TWO_STEP_VALUE_FIELDS = {
    "enforcedFrom": "enforced_from",
    "allowEnrollment": "allow_enrollment",
    "allowedSignInFactorSet": "allowed_sign_in_factor_set",
    "enrollmentGracePeriod": "enrollment_grace_period",
}
_TWO_STEP_FIELDS = {
    "enforcedFrom": "timestamp",
    "allowEnrollment": "bool",
    "allowedSignInFactorSet": POLICY_VALUE_SCHEMAS["security.two_step_verification_enforcement_factor"]["allowedSignInFactorSet"],
    "enrollmentGracePeriod": "duration",
}
for _section, _fields in POLICY_VALUE_SCHEMAS.items():
    if _section.startswith("security.two_step_verification_"):
        _fields.update(_TWO_STEP_FIELDS)
        _fields.update({alias: _TWO_STEP_FIELDS[field] for field, alias in TWO_STEP_VALUE_FIELDS.items()})


def policy_scalar(value: Any, schema: Any) -> Any:
    """Project a scalar at an allow-listed path, with null for a type or vocabulary mismatch."""
    if isinstance(schema, tuple):
        return value if isinstance(value, str) and value in schema else None
    if schema == "bool":
        return value if isinstance(value, bool) else None
    if schema == "int":
        return value if type(value) is int and 0 <= value < 2**63 else None
    if schema == "duration":
        return value if isinstance(value, str) and _DURATION.fullmatch(value) else None
    if schema == "timestamp":
        return policy_timestamp_utc(value)
    if schema == "reference":
        return value if policy_reference(value) else None
    if schema == "ip":
        return _ip_address(value)
    raise ValueError("Unknown policy field schema")
