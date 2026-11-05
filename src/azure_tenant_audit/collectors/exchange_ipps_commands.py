"""Opt-in IPPS policy reads. Output shapes are inferred, never tenant-observed.

Calculated Select-Object fields minimise scopes before JSON or diagnostic logging.
AdvancedRule is omitted: its free-form JSON can hold recipients and content matches.
"""
from __future__ import annotations

import os
from typing import Any

from ..secret_hygiene import ipps_password_env_allowed
from .exchange_defender_commands import _listing


IPPS_ENABLE_ENV = "AUDITEX_ENABLE_IPPS"
DLP_LOCATION_FIELDS = (
    "ExchangeLocation", "SharePointLocation",
    "OneDriveLocation", "TeamsLocation", "EndpointDlpLocation",
)
DLP_EXCEPTION_FIELDS = tuple(name + "Exception" for name in DLP_LOCATION_FIELDS)
EXCEPTIONS_AVAILABLE = "AuditexExceptionPropertiesAvailable"
DLP_POLICY_FIELDS = ("Name", "Enabled", "Mode", "Workload", *DLP_LOCATION_FIELDS, *DLP_EXCEPTION_FIELDS)
DLP_RULE_FIELDS = (
    "Name", "ParentPolicyName", "Disabled", "IsAdvancedRule", "ContentContainsSensitiveInformation",
    "BlockAccess", "BlockAccessScope", "NotifyUser", "NotifyUserType",
)
ALERT_FIELDS = ("Name", "Disabled", "Severity", "Category", "IsSystemRule")


def ipps_enabled() -> bool:
    return os.environ.get(IPPS_ENABLE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def ipps_session() -> dict[str, Any]:
    # Consume once before any collector children, as in the certificate-auth branch.
    # A closure keeps the password out of session reprs and all other child environments.
    password_env = os.environ.get("AUDITEX_IPPS_CERTIFICATE_PASSWORD_ENV", "")
    password = os.environ.pop(password_env, None) if ipps_password_env_allowed(password_env) else None

    def password_provider() -> str | None:
        return password

    # No Graph/domain lookup and no secret fallback. The adapter validates each value.
    if not ipps_enabled():
        return {"kind": "security_compliance"}
    return {
        "kind": "security_compliance", "enabled": True,
        "app_id": os.environ.get("AZURE_CLIENT_ID", ""),
        "organization": os.environ.get("AUDITEX_IPPS_ORGANIZATION", ""),
        "certificate_thumbprint": os.environ.get("AUDITEX_IPPS_CERTIFICATE_THUMBPRINT", ""),
        "certificate_file": os.environ.get("AUDITEX_IPPS_CERTIFICATE_FILE", ""),
        "certificate_password_env": password_env,
        "certificate_password_provider": password_provider,
    }


def _scope_field(name: str, *, all_literal: bool = False) -> str:
    # foreach is a read-only language construct accepted by the shared guard.
    return (
        "@{Name='" + name + "';Expression={ if ($null -eq $_." + name + ") { $null } "
        "else { ,@(foreach ($entry in @($_." + name + ")) { "
        + ("if ($entry -ceq 'All') { 'All' } else { 'scope' }" if all_literal else "'scope'")
        + " }) } }}"
    )


IPPS_COMMANDS = [
    ("protectionAlerts", _listing("Get-ProtectionAlert", ALERT_FIELDS)),
    ("dlpCompliancePolicies", _listing("Get-DlpCompliancePolicy", (
        *DLP_POLICY_FIELDS[:4], *(_scope_field(name, all_literal=True) for name in DLP_LOCATION_FIELDS),
        *(_scope_field(name) for name in DLP_EXCEPTION_FIELDS),
        "@{Name='" + EXCEPTIONS_AVAILABLE + "';Expression={ "
        + " -and ".join("($null -ne $_.PSObject.Properties['" + name + "'])" for name in DLP_EXCEPTION_FIELDS)
        + " }}",
    ))),
    ("dlpComplianceRules", _listing("Get-DlpComplianceRule", (
        *DLP_RULE_FIELDS[:4],
        "@{Name='ContentContainsSensitiveInformation';Expression={ if ($null -eq $_.ContentContainsSensitiveInformation) "
        "{ $null } else { ,@($_.ContentContainsSensitiveInformation | Select-Object name) } }}",
        "BlockAccess", "BlockAccessScope", _scope_field("NotifyUser"), "NotifyUserType",
    ))),
]
IPPS_OPERATIONS = frozenset(name for name, _ in IPPS_COMMANDS)


def project_ipps_row(name: str, source: dict[str, Any]) -> dict[str, Any]:
    """Pure projection of child JSON, before persistence; scalar collections stay unusable.

    PowerShell only minimises private scope/recipient content and preserves arrays.
    Field filtering, information-type shaping and availability validation live here.
    An absent availability marker must never be reconstructed from selected nulls.
    """
    fields = {"protectionAlerts": ALERT_FIELDS, "dlpCompliancePolicies": (*DLP_POLICY_FIELDS, EXCEPTIONS_AVAILABLE),
              "dlpComplianceRules": DLP_RULE_FIELDS}[name]
    row = {key: source[key] for key in fields if key in source}
    for key in (*DLP_LOCATION_FIELDS, *DLP_EXCEPTION_FIELDS) if name == "dlpCompliancePolicies" else ("NotifyUser",):
        value = row.get(key)
        if isinstance(value, list):
            row[key] = ["All" if key in DLP_LOCATION_FIELDS and item == "All" else "scope" for item in value]
        elif value is not None:
            row[key] = "scope"
    if name == "dlpCompliancePolicies":
        row[EXCEPTIONS_AVAILABLE] = (
            row.get(EXCEPTIONS_AVAILABLE) is True and all(key in row for key in DLP_EXCEPTION_FIELDS)
        )
    info = row.get("ContentContainsSensitiveInformation")
    if isinstance(info, list):
        row["ContentContainsSensitiveInformation"] = [
            {"name": item["name"]} if isinstance(item, dict) and isinstance(item.get("name"), str) else {}
            for item in info
        ]
    elif info is not None:
        row["ContentContainsSensitiveInformation"] = {}
    return row


def minimise_ipps(name: str, response: dict[str, Any]) -> None:
    """Apply the pure projection to each row before any collector persistence."""
    rows = response.get("value")
    if not isinstance(rows, list):
        return
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue  # The rule shape check rejects it.
        rows[index] = project_ipps_row(name, row)
