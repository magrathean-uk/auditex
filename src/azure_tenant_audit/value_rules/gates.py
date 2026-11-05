"""The value-rule closed gate: the decision is the shared ``scuba_precheck.check_gate`` (one source, also the oracle
generator's); this module only renders it as the rule's ``closed_gate`` cell. Divergence tags stay out of product output."""
from __future__ import annotations

from typing import Any

from azure_tenant_audit.scuba_precheck import check_gate, policy_rule

from .record import _rec

ENVIRONMENT_NAMES = {"gcc": "GCC", "gcchigh": "GCC High", "dod": "DOD"}


def _names(values: list[str]) -> str:
    names = [ENVIRONMENT_NAMES[value] for value in values]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " or " + names[-1]


def closed_gate(policy_id: str, sections: dict[str, Any]) -> dict | None:
    gate = check_gate(policy_id, sections)
    if gate is None or gate["class"] != "closed_gate":
        return None
    rule = policy_rule(policy_id)
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
    # The Authenticator gate is rendered when its kind ships (stage 9).
    raise ValueError("Closed gate has no value-rule rendering")
