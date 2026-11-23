"""Documented product deviations from the spec's byte-exact v3.9.1 cell catalogue pin.

Review lane rules-followup (R003, R099): SS 7.1 to 7.3 read built_in_protection_rules, retire no_rules_configured and
add the three Built-In cells SS 1.3 already has. The pin predates this; tests that compare the product with the pin
compare it with ``review_catalogue(pin)``.

Every value the overlay adds is written out here, never read from the shipped catalogue, so a changed shipped cell
disagrees with the reviewed pin instead of being copied into it (bot review wave 2, item 62).

Bot review wave 2 also adds the preset and combined partial_tier_may_cover answers (item 50) and the unknown-order
rule_unusable text (item 59) to SS 7.1 to 7.3.
"""
from __future__ import annotations

from copy import deepcopy

R003_POLICIES = tuple(f"MS.SECURITYSUITE.7.{n}v1" for n in (1, 2, 3))
R003_RETIRED = ("no_rules_configured",)
R003_ADDED = ("builtin_rule_unusable", "no_policy_covers_all", "partial_tier_may_cover")
R003_SECTION = "built_in_protection_rules"
R003_SECTIONS = ["atp_policy_rules", "built_in_protection_rules", "defender_license", "protection_policy_rules",
                 "safe_links_policies", "safe_links_rules"]
R003_WHAT = {"MS.SECURITYSUITE.7.1v1": "URL comparison with a block-list",
             "MS.SECURITYSUITE.7.2v1": "direct download link scanning",
             "MS.SECURITYSUITE.7.3v1": "user click tracking"}


def _unusable(kind: str, recommendation: str) -> dict:
    return {"evidence_kind": kind, "limitations": ["evidence_unusable", f"evidence_unusable:<section>:{kind}"],
            "recommendations": [recommendation], "verdict": "not_assessed"}


def r003_added_cells(policy_id: str) -> dict:
    """The three Built-In cells SS 7.1 to 7.3 add, as reviewed."""
    what = R003_WHAT[policy_id]
    return {
        "builtin_rule_unusable": {
            "cited": [R003_SECTION], "reason_code": "data_unusable_builtin_rule",
            "reason_texts": ["Data unusable: built_in_protection_rules holds more than one rule; the policy was not "
                             "assessed.",
                             "Data unusable: built_in_protection_rules holds no rule with readable exclusions; the policy "
                             "was not assessed."],
            **_unusable("unusable", "recollect_unusable_evidence")},
        "no_policy_covers_all": {
            "cited": list(R003_SECTIONS), "reason_code": "no_policy_covers_all_recipients",
            "reason_texts": ["Requirement not met: the Built-In Protection rule excludes some recipients and no Safe Links "
                             f"rule or preset covers them, so they get no Safe Links policy ({what})."],
            "verdict": "not_met"},
        "partial_tier_may_cover": {
            "cited": [R003_SECTION, "safe_links_rules"],
            "cited_variants": [["atp_policy_rules", R003_SECTION, "protection_policy_rules"],
                               ["atp_policy_rules", R003_SECTION, "protection_policy_rules", "safe_links_rules"],
                               [R003_SECTION, "safe_links_rules"]],
            "reason_code": "data_unusable_partial_tier_may_cover",
            "reason_texts": ["Data unusable: the built-in protection rule has exclusions and a partly scoped Safe Links "
                             "rule exists that may cover the excluded recipients; the policy was not assessed.",
                             "Data unusable: the built-in protection rule has exclusions and a partly scoped Standard or "
                             "Strict preset security policy exists that may cover the excluded recipients; the policy was "
                             "not assessed.",
                             "Data unusable: the built-in protection rule has exclusions and a partly scoped preset "
                             "security policy and Safe Links rule exist that may cover the excluded recipients; the policy "
                             "was not assessed."],
            **_unusable("undecidable", "review_policy_against_baseline_text")},
    }


# Bot review wave 2 (item 59): a non-compliant partial rule of unknown Priority leaves the rule order undecided.
UNKNOWN_ORDER_TEXT = ("Data unusable: a partly scoped Safe Links rule whose policy turns off a flag the policy reads has "
                      "no numeric Priority, so it may apply before the covering rule; the policy was not assessed.")


def review_catalogue(pin: dict) -> dict:
    """The pin with the documented deviation applied: sections, full-list citations, the not-a-list variant and the
    added and retired cells of SS 7.1 to 7.3, all written out above; every other value stays the pin's."""
    out = deepcopy(pin)
    for pid in R003_POLICIES:
        row = out[pid]
        old = list(row["sections"])
        row["sections"] = list(R003_SECTIONS)
        for cell in R003_RETIRED:
            del row["cells"][cell]
        row["cells"].update(r003_added_cells(pid))
        rule_unusable = row["cells"]["rule_unusable"]
        rule_unusable["reason_texts"] = sorted([*rule_unusable["reason_texts"], UNKNOWN_ORDER_TEXT])
        for cell in row["cells"].values():
            if cell.get("cited") == old:
                cell["cited"] = list(row["sections"])
        not_a_list = row["cells"]["section_not_a_list"]
        not_a_list["cited_variants"] = sorted([*not_a_list["cited_variants"], [R003_SECTION]])
        if "reason_texts" in not_a_list:
            not_a_list["reason_texts"] = sorted([*not_a_list["reason_texts"],
                                                 f"Data unusable: {R003_SECTION} is not a list of objects; the policy was not assessed."])
    return out
