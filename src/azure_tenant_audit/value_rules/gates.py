"""Render the shared config gate after enforcing the value rule's section shape.

Thresholds stay in ``scuba_precheck.check_gate``; the reference requires stricter
section shapes for environment and Authenticator gates than the legacy reader.
Divergence tags stay out of product output.
"""
from __future__ import annotations

from typing import Any

from azure_tenant_audit.scuba_precheck import check_gate, policy_rule

from .record import _rec

ENVIRONMENT_NAMES = {"gcc": "GCC", "gcchigh": "GCC High", "dod": "DOD"}


def _names(values: list[str]) -> str:
    names = [ENVIRONMENT_NAMES[value] for value in values]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " or " + names[-1]


def closed_gate(policy_id: str, sections: dict[str, Any]) -> dict | None:
    rule = policy_rule(policy_id)
    if rule is None:
        return None
    if rule["section"] == "scuba_config" and rule["path"] == ["M365Environment"]:
        if not isinstance(sections.get("scuba_config"), dict):
            return None
    if rule["section"] == "authentication_method":
        methods = sections.get("authentication_method")
        if not isinstance(methods, list) or len(methods) != 1 or not isinstance(methods[0], dict):
            return None
    gate = check_gate(policy_id, sections)
    if gate is None or gate["class"] != "closed_gate":
        return None
    if rule["section"] == "scuba_config" and rule["path"] == ["M365Environment"]:
        return _rec(policy_id, "not_applicable", "policy_not_applicable_environment",
                    f"Not applicable: the policy does not apply to {_names(rule['closed_values'])} environments.",
                    "closed_gate")
    # stage 6: render the config-decided SharePoint slider gate using closed names only.
    if rule["section"] == "SPO_tenant" and rule["path"] == ["SharingCapability"]:
        from .sharepoint import SLIDER_NAMES, SP_GATE_APPLIES
        return _rec(policy_id, "not_applicable", "policy_not_applicable_sharing_slider",
                    f"Not applicable: the policy applies only when {SP_GATE_APPLIES[policy_id]}; "
                    f"the slider is set to {SLIDER_NAMES[gate['value']]}.", "closed_gate")
    # stage 9: render the existing Authenticator-disabled gate without adding a CA exemption.
    if rule["section"] == "authentication_method":
        return _rec(policy_id, "not_applicable", "policy_not_applicable_authenticator_disabled",
                    "Not applicable: the policy applies only when Microsoft Authenticator is enabled; it is disabled.",
                    "closed_gate")
    raise ValueError("Closed gate has no value-rule rendering")
