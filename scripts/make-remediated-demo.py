#!/usr/bin/env python3
"""Build the "30 days later" twin of the synthetic demo tenant.

The twin applies the fixes a team would make first after reading the demo
report, so `auditex compare` can show a believable before/after story.
Re-run after editing examples/demo_tenant/demo_tenant.json:

    python3 scripts/make-remediated-demo.py
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples" / "demo_tenant" / "demo_tenant.json"
TARGET = ROOT / "examples" / "demo_tenant" / "demo_tenant_remediated.json"
GLOBAL_ADMIN_ROLE = "62e90394-69f5-4237-9190-012177145e10"


def dumps_fixture(data: dict) -> str:
    """Fixture layout: one record per line inside each collector section, so diffs stay reviewable."""
    lines = ["{"]
    collectors = list(data.items())
    for index, (collector, payload) in enumerate(collectors):
        tail = "," if index < len(collectors) - 1 else ""
        sections = list(payload.items()) if isinstance(payload, dict) else []
        if collector.startswith("_") or not all(isinstance(section, dict) and "value" in section for _, section in sections):
            body = json.dumps(payload, indent=2, ensure_ascii=False).replace("\n", "\n  ")
            lines.append(f"  {json.dumps(collector)}: {body}{tail}")
            continue
        lines.append(f"  {json.dumps(collector)}: {{")
        for section_index, (name, section) in enumerate(sections):
            section_tail = "," if section_index < len(sections) - 1 else ""
            records = section.get("value") or []
            extras = {key: value for key, value in section.items() if key != "value"}
            prefix = "".join(f"{json.dumps(key)}: {json.dumps(value, ensure_ascii=False)}, " for key, value in extras.items())
            if not records:
                lines.append(f"    {json.dumps(name)}: {{{prefix}\"value\": []}}{section_tail}")
                continue
            lines.append(f"    {json.dumps(name)}: {{")
            for key, value in extras.items():
                lines.append(f"      {json.dumps(key)}: {json.dumps(value, ensure_ascii=False)},")
            lines.append('      "value": [')
            for record_index, record in enumerate(records):
                record_tail = "," if record_index < len(records) - 1 else ""
                lines.append(f"        {json.dumps(record, ensure_ascii=False)}{record_tail}")
            lines.append("      ]")
            lines.append(f"    }}{section_tail}")
        lines.append(f"  }}{tail}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _values(payload: dict, collector: str, section: str) -> list[dict]:
    return payload.setdefault(collector, {}).setdefault(section, {}).setdefault("value", [])


def remediate(source: dict) -> tuple[dict, list[str]]:
    data = copy.deepcopy(source)
    changes: list[str] = []

    rules = _values(data, "mailbox_forwarding", "messageRules")
    kept = [rule for rule in rules if not rule.get("forwards_externally") and not rule.get("hide_from_user")]
    if len(kept) != len(rules):
        rules[:] = kept
        changes.append("Removed inbox rules that forwarded mail externally or hid messages from the user.")

    transport = _values(data, "exchange_policy", "transportRules")
    kept = [rule for rule in transport if not rule.get("RedirectMessageTo")]
    if len(kept) != len(transport):
        transport[:] = kept
        changes.append("Deleted the 'Redirect invoices' transport rule.")
    for domain in _values(data, "exchange_policy", "remoteDomains"):
        if domain.get("AutoForwardEnabled"):
            domain["AutoForwardEnabled"] = False
            changes.append(f"Turned off automatic forwarding for remote domain {domain.get('Name')}.")

    for bypass in _values(data, "exchange_policy", "mailboxAuditBypass"):
        if int(bypass.get("Count") or 0) > 0:
            bypass["Count"] = 0
            changes.append("Removed the mailbox audit bypass from the scan-to-email service account.")
    for alert in _values(data, "exchange_policy", "protectionAlerts"):
        if alert.get("Disabled") and alert.get("IsSystemRule"):
            alert["Disabled"] = False
            changes.append(f"Re-enabled the '{alert.get('Name')}' alert policy.")

    for posture in _values(data, "dns_posture", "domainPosture"):
        dmarc = posture.get("dmarc") or {}
        if dmarc.get("present") and dmarc.get("policy") == "none":
            dmarc["policy"] = "quarantine"
            dmarc["record"] = str(dmarc.get("record", "")).replace("p=none", "p=quarantine")
            changes.append(f"Moved DMARC for {posture.get('domain')} from p=none to p=quarantine.")
        dkim = posture.get("dkim")
        if isinstance(dkim, dict) and dkim.get("selectors_missing") and not posture.get("managed_by_microsoft"):
            dkim["selectors_present"] = sorted(set(dkim.get("selectors_present", [])) | set(dkim["selectors_missing"]))
            dkim["selectors_missing"] = []
            changes.append(f"Enabled DKIM signing for {posture.get('domain')}.")

    for app in _values(data, "app_credentials", "applicationCredentials"):
        if app.get("display_name") != "ShipTrack Sync":
            continue
        app["password_credentials"] = [
            credential for credential in app.get("password_credentials", []) if credential.get("end_date_time", "") > "2026-10-02"
        ]
        app["redirect_uris"] = [uri for uri in app.get("redirect_uris", []) if uri.get("scheme") != "http"]
        app["owner_count"] = max(1, int(app.get("owner_count") or 0))
        changes.append("ShipTrack Sync: removed the expired secret and the http:// redirect URI, and assigned an owner.")

    for resource in _values(data, "app_consent", "servicePrincipalAppRoleAssignments"):
        assignments = resource.get("assignments") or []
        kept = [item for item in assignments if item.get("appRoleValue") != "RoleManagement.ReadWrite.Directory"]
        if len(kept) != len(assignments):
            resource["assignments"] = kept
            changes.append("Payroll Export: revoked the RoleManagement.ReadWrite.Directory application permission it never needed.")

    users = {user.get("id"): user for user in _values(data, "identity", "users")}
    assignments = _values(data, "identity", "roleAssignments")
    disabled_admins = [
        assignment
        for assignment in assignments
        if assignment.get("roleDefinitionId") == GLOBAL_ADMIN_ROLE
        and users.get(assignment.get("principalId"), {}).get("accountEnabled") is False
    ]
    if disabled_admins:
        assignments[:] = [assignment for assignment in assignments if assignment not in disabled_admins]
        changes.append("Removed Global Administrator from the disabled account.")
    registrations = _values(data, "auth_methods", "userRegistrationDetails")
    for registration in registrations:
        if registration.get("isAdmin") and not registration.get("isMfaRegistered"):
            registration.update(
                {
                    "isMfaRegistered": True,
                    "isMfaCapable": True,
                    "methodsRegistered": ["microsoftAuthenticatorPush"],
                    "defaultMfaMethod": "microsoftAuthenticatorPush",
                }
            )
            changes.append(f"Registered MFA for admin {registration.get('userPrincipalName')}.")

    provenance = data.setdefault("_fixture_provenance", {})
    provenance.update(
        {
            "fixture_id": "m365-demo-tenant-remediated",
            "source_path": "examples/demo_tenant/demo_tenant_remediated.json",
            "description": "Synthetic demo tenant for Halcyon Freight Ltd 30 days after the first remediation sprint. "
            "Generated by scripts/make-remediated-demo.py from demo_tenant.json; every person, domain and id is fictional.",
            "remediations": changes,
        }
    )
    return data, changes


def main() -> int:
    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    remediated, changes = remediate(source)
    TARGET.write_text(dumps_fixture(remediated), encoding="utf-8")
    print(f"Wrote {TARGET.relative_to(ROOT)} with {len(changes)} remediations")
    for change in changes:
        print(f"  - {change}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
