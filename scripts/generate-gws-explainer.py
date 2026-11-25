#!/usr/bin/env python3
"""Generate the offline Google Workspace explainer catalogue."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from azure_tenant_audit.resources import open_text_resource  # noqa: E402
from azure_tenant_audit.value_rules.gws.catalogue import catalogue  # noqa: E402

# One fixed "what to check" line per kind cell. Gmail DNS policies (SPF, DKIM, DMARC) are published in DNS at the
# domain's DNS host; only DKIM key generation happens in the Admin console. Everything else is read from Google
# Workspace, so those lines point at the Admin console or at running the collection again.
_RERUN = "Run the collection again so the {} read completes"
_SCOPE = "Grant the scope the missing evidence section needs, then run the collection again."
_SHAPE = "Run the collection again; if the evidence section is still malformed, report it as an Auditex problem."
_DNS = "SPF TXT, DKIM selector or DMARC TXT (at _dmarc) record"
_SETTING = {
    "no_unit_violates": "Check the setting again after any change in the Admin console.",
    "policy_read_incomplete": "Run the collection again so the policy and organisational unit read completes.",
    "section_not_collected": _SCOPE,
    "section_shape_unusable": _SHAPE,
    "service_off_everywhere": "Check the service is meant to stay off in every organisational unit.",
    "service_status_absent": "Run the collection again so the service on or off status is read for every unit this policy covers.",
    "setting_absent": "Check in the Admin console that the setting is configured at the top-level organisational unit, then collect again.",
    "setting_value_unusable": "Check the setting in the Admin console for an unknown or malformed value, then collect again.",
    "unit_violates": "In the Admin console, change the setting on each organisational unit or group that holds a value the baseline forbids.",
}
CHECKS = {
    ("admin_sso", "admin_uses_external_sso"): "In the Admin console, move each privileged account that uses an external identity provider to sign in with Google.",
    ("admin_sso", "admins_use_google_sign_in"): "Check the SSO profile assignments again after any change.",
    ("admin_sso", "assignment_unusable"): "Check the inbound SSO profile assignments in the Admin console for an unknown mode or two that disagree for one target, then collect again.",
    ("admin_sso", "lineage_unresolved"): _RERUN.format("organisational unit") + ", then check the SSO assignments of privileged accounts.",
    ("admin_sso", "membership_incomplete"): _RERUN.format("group membership") + ", then check the groups that hold an SSO assignment.",
    ("admin_sso", "section_not_collected"): _SCOPE,
    ("admin_sso", "section_shape_unusable"): _SHAPE,
    ("admin_sso", "sso_read_incomplete"): _RERUN.format("inbound SSO assignment") + ", then check how privileged accounts sign in.",
    ("admin_sso", "user_read_incomplete"): _RERUN.format("user and admin role") + ".",
    ("gws_dns", "dns_read_incomplete"): "Run the collection again so every domain's DNS lookup completes; the records live at the domain's DNS host, not in the Admin console.",
    ("gws_dns", "domain_record_unusable"): f"Check the domain's {_DNS} at its DNS host for a malformed entry, then collect again.",
    ("gws_dns", "domain_violates"): "Correct the failing domain's SPF TXT, DKIM selector or DMARC TXT (at _dmarc) record at its DNS host; generate DKIM keys in the Admin console, then publish them in DNS.",
    ("gws_dns", "no_domain_violates"): "Check the domain DNS records again after any change at the DNS host.",
    ("gws_dns", "no_domains"): "Check the tenant's domains are collected, then run the collection again; the records are read from each domain's DNS host.",
    ("gws_dns", "resolver_error"): f"Run the collection again; if a lookup keeps failing, check the {_DNS} answers at the domain's DNS host.",
    ("gws_dns", "section_not_collected"): "Run the collection again so the DNS lookups run; the records are read from each domain's DNS host, not the Admin console.",
    ("gws_dns", "section_shape_unusable"): "Run the collection again; if the DNS evidence is still malformed, report it as an Auditex problem.",
    **{("gws_list_settings", cell): line for cell, line in {
        **_SETTING,
        "no_unit_violates": "Check the setting again after any change in the Admin console.",
        "setting_value_unusable": "Check the setting, list or rule state in the Admin console for an unknown or malformed value, then collect again.",
        "unit_violates": "In the Admin console, remove the forbidden value from each organisational unit or group that holds it.",
    }.items()},
    ("manual_only", "manual_check"): "Check the setting by hand in the Admin console against the baseline; no read-only API exposes it.",
    **{("setting", cell): line for cell, line in _SETTING.items()},
    ("setting_event", "event_read_incomplete"): _RERUN.format("admin log") + ", then check the last change logged for each unit.",
    ("setting_event", "event_value_unusable"): "Check the admin log for a setting-change event with a missing or unknown value, time or unit, or two that conflict, then collect again.",
    ("setting_event", "no_setting_event"): "Set the setting at the top-level organisational unit in the Admin console so the admin log records a change, then collect again.",
    ("setting_event", "no_unit_violates"): "Check the setting again after any further change.",
    ("setting_event", "policy_read_incomplete"): _RERUN.format("policy") + " and the service status is known.",
    ("setting_event", "section_not_collected"): _SCOPE,
    ("setting_event", "section_shape_unusable"): "Run the collection again; if the topology, setting-change events or policy evidence is still malformed, report it as an Auditex problem.",
    ("setting_event", "service_off_everywhere"): "Check the service is meant to stay off in every unit.",
    ("setting_event", "service_status_absent"): "Run the collection again so the top-level unit's service status is read, or set the service on or off explicitly in the Admin console.",
    ("setting_event", "unit_violates"): "In the Admin console, change the setting on each unit whose last logged change set a value the baseline forbids.",
    **{("settings_multi", cell): line for cell, line in {
        **_SETTING,
        "no_unit_violates": "Check the settings again after any change in the Admin console.",
        "setting_absent": "Check in the Admin console that every setting this policy reads is configured at the top-level organisational unit, then collect again.",
        "setting_value_unusable": "Check each setting this policy reads in the Admin console for a wrong type or unknown value, then collect again.",
        "unit_violates": "In the Admin console, change the settings on each organisational unit or group whose combination the baseline does not allow.",
    }.items()},
    ("super_admin_count", "count_in_range"): "Check the super admin count again after adding or removing an account.",
    ("super_admin_count", "count_out_of_range"): "In the Admin console, bring the number of super admin accounts to between two and eight.",
    ("super_admin_count", "count_unusable"): "Run the collection again; a tenant always has a super admin, so report it as an Auditex problem if the read keeps showing none.",
    ("super_admin_count", "section_not_collected"): _SCOPE,
    ("super_admin_count", "section_shape_unusable"): _SHAPE,
    ("super_admin_count", "user_read_incomplete"): _RERUN.format("user and admin role") + ".",
    ("twosv", "no_unit_violates"): "Check the 2-Step Verification settings again after any change in the Admin console.",
    ("twosv", "policy_read_incomplete"): _RERUN.format("policy and organisational unit") + ".",
    ("twosv", "section_not_collected"): _SCOPE,
    ("twosv", "section_shape_unusable"): _SHAPE,
    ("twosv", "setting_value_unusable"): "Check the 2-Step Verification settings of each organisational unit and group in the Admin console for an unreadable value, then collect again.",
    ("twosv", "unit_violates"): "In the Admin console, change the 2-Step Verification setting on each organisational unit or group that breaks the policy.",
}


def _check_line(kind, name, verdict):
    line = CHECKS[(kind, name)]
    # Met and not applicable lines join the 3-sentence explanation, so they stay short; steps are capped at 30 words.
    limit = 14 if verdict in ("met", "not_applicable") else 30
    if len(line.split()) > limit or "\u2014" in line or line.count(". ") or not line.endswith("."):
        raise ValueError("GWS check line out of bounds")
    return line


def generate():
    rules = catalogue()
    baselines = json.loads(open_text_resource("configs/scuba-gws-policy-sections.json"))["policies"]
    if set(baselines) != set(rules["policies"]):
        raise ValueError("GWS policy catalogues disagree")
    if any(baselines[pid]["sections"] != row["sections"] for pid, row in rules["policies"].items()):
        raise ValueError("GWS policy sections disagree")
    cells = {(kind, name) for kind, value in rules["kinds"].items() for name in value["cells"]}
    if cells != set(CHECKS):
        raise ValueError("GWS check lines do not match the kind cells")
    kinds = {}
    for kind, value in sorted(rules["kinds"].items()):
        kinds[kind] = {}
        for name, cell in sorted(value["cells"].items()):
            check = _check_line(kind, name, cell["verdict"])
            kinds[kind][name] = {"remediation_steps": check, "reason_texts": cell.get("reason_texts", [])}
    return {"schema_version": 1, "policies": {
        pid: {"baseline_text": baselines[pid]["baseline_text"], "kind": row["kind"]}
        for pid, row in sorted(rules["policies"].items())}, "kinds": kinds,
        "shared_reasons": "Check the policy and report the assessment problem."}


def main():
    if sys.argv[1:] not in ([], ["--check"]):
        print("usage: generate-gws-explainer.py [--check]", file=sys.stderr)
        return 2
    check = bool(sys.argv[1:])
    output = Path("configs/explainer-gws-template.json")
    try:
        result = (json.dumps(generate(), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
        if check:
            if output.read_bytes() != result:
                print("GWS explainer template drift", file=sys.stderr)
                return 1
        else:
            output.write_bytes(result)
    except (OSError, ValueError, KeyError):
        print("GWS explainer template generation failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
