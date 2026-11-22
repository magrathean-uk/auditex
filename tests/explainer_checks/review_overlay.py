"""Documented product deviations from the spec's byte-exact v3.9.1 cell catalogue pin.

Review lane rules-followup (R003, R099): SS 7.1 to 7.3 read built_in_protection_rules, retire no_rules_configured and
add the three Built-In cells SS 1.3 already has. The pin predates this; tests that compare the product with the pin
compare it with ``review_catalogue(pin, product)``, and ``test_review_overlay_is_exactly_the_documented_deviation``
proves the overlay changes nothing else.
"""
from __future__ import annotations

from copy import deepcopy

R003_POLICIES = tuple(f"MS.SECURITYSUITE.7.{n}v1" for n in (1, 2, 3))
R003_RETIRED = ("no_rules_configured",)
R003_ADDED = ("builtin_rule_unusable", "no_policy_covers_all", "partial_tier_may_cover")
R003_SECTION = "built_in_protection_rules"


def review_catalogue(pin: dict, product: dict) -> dict:
    """The pin with the documented deviation applied: sections, full-list citations, the not-a-list variant and the
    added and retired cells of SS 7.1 to 7.3 come from the product catalogue; every other value stays the pin's."""
    policies = product.get("policies", product)
    out = deepcopy(pin)
    for pid in R003_POLICIES:
        row, shipped = out[pid], policies[pid]
        old = list(row["sections"])
        row["sections"] = list(shipped["sections"])
        for cell in R003_RETIRED:
            del row["cells"][cell]
        for cell in R003_ADDED:
            row["cells"][cell] = deepcopy(shipped["cells"][cell])
        for cell in row["cells"].values():
            if cell.get("cited") == old:
                cell["cited"] = list(row["sections"])
        not_a_list = row["cells"]["section_not_a_list"]
        not_a_list["cited_variants"] = sorted([*not_a_list["cited_variants"], [R003_SECTION]])
        if "reason_texts" in not_a_list:
            not_a_list["reason_texts"] = sorted([*not_a_list["reason_texts"],
                                                 f"Data unusable: {R003_SECTION} is not a list of objects; the policy was not assessed."])
    return out
