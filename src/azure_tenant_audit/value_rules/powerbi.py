"""Power BI and AAD 3.4 value rules, adapted from the pinned v3.6 kit reference."""
from __future__ import annotations

import re

from .catalogue import row_for
from .record import _not_collected, _rec

GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
AAD_34 = "MS.AAD.3.4v1"
KNOWN_STATES = ("preMigration", "migrationInProgress", "unknownFutureValue")   # Graph enum; any other string is reported as unrecognised

def _groups_state(entry):
    """none (key absent or []), listed (non-empty, every element an object with a GUID graphId), unusable (anything else, a literal null
    included: v2 settles spec C4 on the safer verdict, an enabled setting whose group list is null is not claimed to be unrestricted)."""
    if "enabledSecurityGroups" not in entry:
        return "none"
    groups = entry["enabledSecurityGroups"]
    if not isinstance(groups, list):
        return "unusable"
    if not groups:
        return "none"
    ok = all(isinstance(g, dict) and isinstance(g.get("graphId"), str) and GUID.match(g["graphId"]) for g in groups)
    return "listed" if ok else "unusable"


def powerbi(policy_id, sections):
    row = row_for(policy_id)
    name, kind = row["params"]["setting_name"], row["kind"].removeprefix("powerbi.")
    out = _not_collected(policy_id, sections, row["sections"])
    if out:
        return out
    licence = sections["powerbi_license_found"]
    if licence is False:
        return _rec(policy_id, "not_assessed", "data_unavailable_no_licence",
                    "Data unavailable: licence not detected: no Power BI licence was found (a false read can also mean missing permissions or a failed command), "
                    "so the tenant settings could not be read; the policy was not assessed.", "licence_false", ["powerbi_license_found"])
    if licence is not True:                           # null/other: the Rego reads these as "found"; the rule does not
        return _rec(policy_id, "not_assessed", "data_unavailable_licence_flag_unusable",
                    "Data unavailable: licence not detected: powerbi_license_found is not a boolean, so it is unknown whether a Power BI licence was found "
                    "and the tenant settings could be read; the policy was not assessed.", "licence_flag_unusable", ["powerbi_license_found"])
    denial = sections["powerbi_access_denied_reason"]
    if denial is not None and denial != "":           # decision 2 and answer (c): "" and a literal JSON null both mean "no denial" (the Rego reads null as a denial: spec divergence D12)
        return _rec(policy_id, "not_assessed", "data_unavailable_access_denied",
                    "Data unavailable: the Power BI Admin API denied access to the tenant settings; "
                    "the policy was not assessed.", "access_denied", ["powerbi_access_denied_reason"])
    settings = sections["powerbi_tenant_settings"]
    cite = ["powerbi_tenant_settings"]
    if not isinstance(settings, list):
        return _rec(policy_id, "not_assessed", "data_unusable_settings_not_a_list",
                    "Data unusable: powerbi_tenant_settings is not a list of tenant-setting objects; the policy was not assessed.",
                    "settings_not_a_list", cite)
    entries = [e for e in settings if isinstance(e, dict) and e.get("settingName") == name]
    if not entries:
        cell = "settings_empty" if not settings else "setting_entry_missing"
        return _rec(policy_id, "not_assessed", "data_unavailable_setting_not_found",
                    f"Data unavailable: tenant setting {name} is not in the exported settings"
                    + (" (the list is empty)" if not settings else "") + "; the policy was not assessed.", cell, cite)
    if len(entries) > 1:
        duplicated_text = (f"Data unusable: tenant setting {name} appears 2 times in the export; the policy was not assessed."
                           if len(entries) == 2 else
                           f"Data unusable: tenant setting {name} appears more than once in the export; the policy was not assessed.")
        return _rec(policy_id, "not_assessed", "data_unusable_setting_duplicated",
                    duplicated_text,
                    "setting_entry_duplicated", cite)
    entry = entries[0]
    if "enabled" not in entry:
        return _rec(policy_id, "not_assessed", "data_unusable_enabled_missing",
                    f"Data unusable: tenant setting {name} has no enabled flag; the policy was not assessed.", "enabled_missing", cite)
    enabled = entry["enabled"]
    if type(enabled) is not bool:
        return _rec(policy_id, "not_assessed", "data_unusable_enabled_not_boolean",
                    f"Data unusable: the enabled flag of {name} is not true or false; the policy was not assessed.",
                    "enabled_not_boolean", cite)
    groups = _groups_state(entry)
    if kind == "on":
        if enabled:
            return _rec(policy_id, "met", "setting_enabled", f"Requirement met: {name} is enabled.", "on.enabled")
        return _rec(policy_id, "not_met", "setting_not_enabled", f"Requirement not met: {name} is not enabled.", "on.disabled")
    if kind == "off":
        if not enabled:
            return _rec(policy_id, "met", "setting_disabled", f"Requirement met: {name} is disabled.", "off.disabled", groups=groups)
        # decision 3: the pinned Rego ignores security groups here, so enabled is not met whatever the group list says
        return _rec(policy_id, "not_met", "setting_enabled", f"Requirement not met: {name} is enabled.", "off.enabled", groups=groups)
    if not enabled:
        return _rec(policy_id, "met", "setting_disabled", f"Requirement met: {name} is disabled.", "og.disabled", groups=groups)
    if groups == "listed":
        return _rec(policy_id, "met", "enabled_for_specific_groups",
                    f"Requirement met: {name} is enabled only for specific security groups.", "og.enabled_groups_listed")
    if groups == "none":
        return _rec(policy_id, "not_met", "enabled_for_everyone",
                    f"Requirement not met: {name} is enabled and no security group restricts it.", "og.enabled_no_groups")
    return _rec(policy_id, "not_assessed", "data_unusable_security_groups",
                f"Data unusable: the security groups of {name} are not a list of group objects with a graphId; "
                "the policy was not assessed.", "og.enabled_groups_unusable", cite)


def aad_3_4(policy_id, sections):
    out = _not_collected(policy_id, sections, row_for(policy_id)["sections"])
    if out:
        return out
    cite = ["authentication_method"]
    section = sections["authentication_method"]
    if not isinstance(section, list):
        return _rec(policy_id, "not_assessed", "data_unusable_section_shape",
                    "Data unusable: authentication_method is not a list holding one policy object; the policy was not assessed.",
                    "section_shape_unusable", cite)
    if len(section) != 1:
        count_text = (f"Data unusable: authentication_method holds {len(section)} objects, not one; the policy was not assessed."
                      if len(section) in (0, 2) else
                      "Data unusable: authentication_method does not hold exactly one object; the policy was not assessed.")
        return _rec(policy_id, "not_assessed", "data_unusable_section_not_singleton",
                    count_text,
                    "section_not_singleton", cite)
    item = section[0]
    policy = item.get("authentication_method_policy") if isinstance(item, dict) else None
    if not isinstance(policy, dict):
        return _rec(policy_id, "not_assessed", "data_unusable_policy_object_absent",
                    "Data unusable: authentication_method has no authentication_method_policy object; the policy was not assessed.",
                    "policy_object_absent", cite)
    if "PolicyMigrationState" not in policy:
        return _rec(policy_id, "not_assessed", "data_unavailable_state_absent",
                    "Data unavailable: PolicyMigrationState is not in the exported authentication methods policy; "
                    "the policy was not assessed.", "state_field_absent", cite)
    state = policy["PolicyMigrationState"]
    if state is None:                                  # answer (b): never met without evidence; deliberate divergence from the Rego's is_null branch (D13)
        return _rec(policy_id, "not_assessed", "data_unavailable_migration_state_absent",
                    "Data unavailable: migration state absent; the policy was not assessed.", "state_null", cite)
    if type(state) is not str:
        return _rec(policy_id, "not_assessed", "data_unusable_state_not_a_string",
                    "Data unusable: PolicyMigrationState is not a string; the policy was not assessed.", "state_not_a_string", cite)
    if state == "migrationComplete":
        return _rec(policy_id, "met", "migration_complete", "Requirement met: authentication methods migration is complete.",
                    "state_complete")
    shown = state if state in KNOWN_STATES else "an unrecognised value"
    return _rec(policy_id, "not_met", "migration_not_complete",
                f"Requirement not met: authentication methods migration state is {shown}, not migrationComplete.",
                "state_not_complete", state_class="known" if state in KNOWN_STATES else "other")
