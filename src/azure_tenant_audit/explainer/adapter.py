"""Explicit product RuleRecord adaptation; never evaluates or repairs a verdict."""
from copy import deepcopy

from .textkit import shared_exceptions


def adapt_record(record, *, templates):
    """Copy only public fields; resolve null citations using the fixed policy read set.

    rule_not_implemented routing is a product decision. This adapter accepts only
    known template policies with their complete fixed read set, never invents a
    policy/cell or turns an ordinary result into an unimplemented-rule result.
    """
    if not isinstance(record, dict):
        raise ValueError("invalid rule record")
    fields = ("policy_id", "verdict", "cell", "reason_code", "reason_text")
    try:
        result = {key: record[key] for key in fields}
        policy = templates["policies"][result["policy_id"]]
    except (KeyError, TypeError) as exc:
        raise ValueError("unknown policy or incomplete rule record") from exc
    required = policy["sections"]
    cited = record.get("cited_sections")
    result["cited_sections"] = deepcopy(required if cited is None else cited)
    entry = shared_exceptions().get(result["reason_code"])
    if entry:
        if result["cell"] is not None:
            # The pre-A1 product catalogue represented a failed rule as a cell named after its reason code. That
            # sentinel is gone: both shared reasons carry a null cell and are never looked up as cells.
            raise ValueError("legacy rule-failure sentinel rejected: a shared reason has a null cell (A1)")
        if any(result[key] != entry[key] for key in ("verdict", "cell", "reason_text")):
            raise ValueError("invalid A1 shared reason")
        if result["cited_sections"] != required:
            raise ValueError("shared reason requires the fixed policy read set")
    return result
