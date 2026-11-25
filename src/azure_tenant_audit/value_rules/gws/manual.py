"""``manual_only``: the 17 ScubaGoggles v1.1.0 policies no read-only API can answer (design section 1).

ScubaGoggles reports them as "Currently not able to be tested automatically" (SG:scubagoggles/rego/Utils.rego:562).
The kind is evidence-free: it always answers not_assessed with the fixed reason, on any evidence.
"""
from __future__ import annotations

from ..record import _A

MANUAL_CHECK = "data_unavailable_manual_check"
_TEXT = ("Data unavailable: no read-only Google Workspace API exposes this setting; check it by hand in the Admin "
         "console against the baseline text.")


def manual_only(policy_id: str, row: dict, sections: dict) -> dict:
    return _A(policy_id, MANUAL_CHECK, _TEXT, "manual_check", ["gws_tenant"])


KINDS = {"manual_only": manual_only}
