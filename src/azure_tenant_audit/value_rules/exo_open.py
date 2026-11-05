"""EXO 1.1 forwarding allow-list: v3.9.1 exact, case-sensitive strings."""
from __future__ import annotations

from .helpers import _label, _scan_bad_wins
from .lookups import _ev_any_flag
from .record import _A


def _allow_list(params, sections):
    """Absent/null path means no allowance; an explicitly non-list is unusable."""
    current = sections["scuba_config"]
    if current is None:
        return []
    if not isinstance(current, dict):
        return None
    for key in params["allow_list"]:
        if not isinstance(current, dict) or key not in current:
            return []
        current = current[key]
    return [] if current is None else current if isinstance(current, list) else None


def exo_forwarding(policy_id, row, sections):
    params = row["params"]
    entries = _allow_list(params, sections)
    if entries is None:
        return _A(policy_id, "data_unusable_allow_list",
                  "Data unusable: the configured forwarding allow-list is not a list; the policy was not assessed.",
                  "allow_list_unusable", ["scuba_config"])
    # A wildcard never authorises every domain. Other entries are exact strings
    # without case folding, substring matching or implicit whitespace trim.
    listed = any(entry != "*" for entry in entries)
    allowed = {entry for entry in entries if type(entry) is str and entry != "*"}
    base = _ev_any_flag(params)

    def evaluate(item):
        state = base(item)
        name = item.get(params["label"])
        if listed and state == "bad" and type(name) is str and name in allowed:
            return "clear"
        return state

    record = _scan_bad_wins(policy_id, params, sections, evaluate, _label(params["label"]))
    if listed and record["cell"] == "flag_bad":
        record["cell"] = "forwarder_not_allowed"
    elif listed and record["cell"] == "all_clear":
        if any(isinstance(item, dict) and base(item) == "bad" for item in sections[params["section"]]):
            record["cell"] = "forwarders_all_allowed"
            record["reason_code"] = "forwarders_all_allow_listed"
            record["reason_text"] = (
                "Requirement met: every object in remote_domains that forwards automatically is on the configured allow-list."
            )
    return record


KINDS = {"exo_forwarding": exo_forwarding}
