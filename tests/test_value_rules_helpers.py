"""Unit tests of the cross-kind value-rule helpers, one case per cell condition of the v3.9 cell tables.

The Defender helpers H1 to H5 (``_accepted``, ``PRESET_RE``, ``_cover``, ``_state``, ``_preset_pair``) and the
shape, licence, P2 and slider helpers get vector coverage when their kinds ship (stages 4 to 7); here they are pinned
on the conditions the cell tables state.
"""
from __future__ import annotations

import json

import pytest

from azure_tenant_audit.collection_markers import NOT_COLLECTED
from azure_tenant_audit.value_rules import assess, rule_failure
from azure_tenant_audit.value_rules.catalogue import catalogue, shared_reason
from azure_tenant_audit.value_rules.helpers import (
    PRESET_RE, _accepted, _cover, _env_cell, _flag, _gate_slider, _int, _licence_cell, _list_state, _lst, _p2_gate,
    _preset_pair, _scan_bad_wins, _scan_good_wins, _shape, _state,
)
from azure_tenant_audit.value_rules.record import checked

P = "MS.TEST.0.0v1"   # helpers build records for any policy; the inventory is enforced by assess


@pytest.mark.parametrize("value,expected", [(3, 3), (0, 0), (3.0, 3), (-1.0, -1), (2.5, None), (True, None),
                                            (False, None), ("3", None), (None, None), (float("nan"), None)])
def test_int(value, expected):
    assert _int(value) == expected


def test_lst_null_leaf_is_empty_and_anything_else_unusable():
    assert _lst({"a": {"b": None}}, "a", "b") == []
    assert _lst({"a": {"b": ["x", "y"]}}, "a", "b") == ["x", "y"]
    assert _lst({"a": {}}, "a", "b") is None
    assert _lst({"a": {"b": ["x", 1]}}, "a", "b") is None
    assert _lst({"a": {"b": "x"}}, "a", "b") is None
    assert _lst({"a": None}, "a", "b") is None
    assert _lst({"a": None}, "a", "b", null_parent_empty=True) == []


@pytest.mark.parametrize("value", [None, {}, {"Identity": "x"}, "text", 3, True])
def test_list_state_not_a_list(value):
    out, items = _list_state(P, {"s": value}, "s")
    assert (out["cell"], out["reason_code"], out["cited_sections"]) == ("section_not_a_list",
                                                                      "data_unusable_section_not_a_list", ["s"])
    assert out["reason_text"] == "Data unusable: s is not a list of objects; the policy was not assessed."
    assert items == []


@pytest.mark.parametrize("value", [[], [1, "x", None, []]])
def test_list_state_no_usable_items(value):
    out, _ = _list_state(P, {"s": value}, "s")
    assert (out["cell"], out["reason_code"]) == ("no_usable_items", "data_unavailable_section_empty")


def test_list_state_ignores_junk_beside_an_object():
    out, items = _list_state(P, {"s": [1, {"a": 1}, "x"]}, "s")
    assert out is None and items == [{"a": 1}]


@pytest.mark.parametrize("item,state", [({"f": True}, "bad"), ({"f": False}, "clear"), ({}, "unusable"),
                                        ({"f": None}, "unusable"), ({"f": "true"}, "unusable"), ({"f": 1}, "unusable")])
def test_flag(item, state):
    assert _flag(item, "f", True) == state


SCAN = {"section": "s", "what": "x is on", "fields": ["f"], "bad": True}


def _bad_wins(items, label_ok=lambda item: type(item.get("Identity")) is str):
    def evaluate(item):
        return _flag(item, "f", True)

    return _scan_bad_wins(P, SCAN, {"s": items}, evaluate, label_ok)


@pytest.mark.parametrize("items,cell", [
    ([{"Identity": "a", "f": True}, {"Identity": "b"}, {"f": True}], "flag_bad"),        # monotone: one labelled bad wins
    ([{"f": True}, {"Identity": "b"}], "flag_bad_unlabelled"),                            # D17 before D16
    ([{"Identity": "a", "f": False}, {"Identity": "b", "f": None}], "flag_unusable"),     # D16
    ([{"Identity": "a", "f": False}, {"Identity": "b", "f": False}], "all_clear"),
])
def test_scan_bad_wins_aggregation(items, cell):
    assert _bad_wins(items)["cell"] == cell


def test_scan_bad_wins_texts_name_only_parameters():
    out = _bad_wins([{"Identity": "secret@example.invalid", "f": True}])
    assert out["reason_text"] == "Requirement not met: x is on (found in s)." and out["verdict"] == "not_met"
    assert _bad_wins([{"f": True}])["reason_text"] == (
        "Data unusable: an object in s shows that x is on but carries no name or identity; the policy was not assessed.")
    seen = _scan_bad_wins(P, {**SCAN, "seen": "a flagged result"}, {"s": [{"f": True}]},
                          lambda item: _flag(item, "f", True), lambda item: False)
    assert "shows a flagged result but" in seen["reason_text"]


GOOD = {"section": "s", "field": "f", "label": "Identity", "what": "y is enabled"}


@pytest.mark.parametrize("items,cell,verdict", [
    ([{"Identity": "a", "f": True}, {"Identity": "b", "f": None}], "flag_true", "met"),
    ([{"f": True}, {"Identity": "b", "f": False}], "flag_true_unlabelled", "not_assessed"),
    ([{"Identity": "a", "f": False}, {"Identity": "b"}], "flag_unusable", "not_assessed"),
    ([{"Identity": "a", "f": False}, {"f": False}], "none_enabled", "not_met"),
])
def test_scan_good_wins(items, cell, verdict):
    out = _scan_good_wins(P, GOOD, {"s": items})
    assert (out["cell"], out["verdict"]) == (cell, verdict)


def test_shape_lists_then_elements_in_rule_order():
    order = ("accepted_domains", "rules", "policies")
    out = _shape(P, {"rules": {}, "policies": []}, ["rules", "policies"], ["rules"], order)
    assert (out["cell"], out["cited_sections"]) == ("section_not_a_list", ["rules"])
    out = _shape(P, {"rules": [{}, 3], "policies": []}, ["rules", "policies"], ["policies", "rules"], order)
    assert (out["cell"], out["reason_code"], out["cited_sections"]) == (
        "list_element_unusable", "data_unusable_list_element", ["rules"])
    assert _shape(P, {"rules": [{}], "policies": []}, ["rules", "policies"], ["rules"], order) is None


@pytest.mark.parametrize("value,cell", [(True, None), (False, "licence_false"), (None, "licence_flag_unusable"),
                                        ("true", "licence_flag_unusable"), (1, "licence_flag_unusable")])
def test_licence_cell(value, cell):
    out = _licence_cell(P, {"defender_license": value}, "defender_license")
    assert (out and out["cell"]) == cell
    if cell == "licence_false":
        assert out["reason_code"] == "data_unavailable_no_licence"
        assert out["reason_text"].startswith("Data unavailable: licence not detected: no Defender for Office 365 licence")
        assert out["cited_sections"] == ["defender_license"]
    if cell == "licence_flag_unusable":
        assert out["reason_code"] == "data_unavailable_licence_flag_unusable"


def test_licence_cell_dlp_words():
    out = _licence_cell(P, {"defender_dlp_license": False}, "defender_dlp_license", "Microsoft Purview DLP")
    assert "no Microsoft Purview DLP licence was found" in out["reason_text"]
    assert "so the DLP policies and rules could not be read" in out["reason_text"]


@pytest.mark.parametrize("plans,cell", [
    ({}, "section_not_a_list"), (None, "section_not_a_list"),
    ([], "licence_not_detected"),
    ([{"ServicePlanName": "AAD_PREMIUM_P2"}], "licence_not_detected"),     # v3.7 AAD-B6: no ServicePlanId counts for nothing
    ([{"ServicePlanName": "AAD_PREMIUM", "ServicePlanId": "x"}], "licence_not_detected"),
    ([3, {"ServicePlanName": "AAD_PREMIUM_P2", "ServicePlanId": None}], None),
])
def test_p2_gate(plans, cell):
    out = _p2_gate(P, {"service_plans": plans})
    assert (out and out["cell"]) == cell
    if cell == "licence_not_detected":
        assert out["reason_code"] == "data_unavailable_no_licence"
        assert "licence not detected" in out["reason_text"]


@pytest.mark.parametrize("value,expected", [
    ([{"SharingCapability": 2}], 2), ({"SharingCapability": 0}, 0), ([{"SharingCapability": 3.0}], 3),
    ([{"SharingCapability": True}], None), ([{"SharingCapability": 4}], None), ([{"SharingCapability": "2"}], None),
    ([{"SharingCapability": 1}, {"SharingCapability": 1}], None), ([], None), ([{}], None), (NOT_COLLECTED, None),
])
def test_gate_slider_reads_like_the_shared_gate(value, expected):
    assert _gate_slider({"SPO_tenant": value}) == expected


@pytest.mark.parametrize("config,proceeds", [
    ({"M365Environment": "commercial"}, True), ({"M365Environment": "Commercial"}, False),
    ({"M365Environment": "gcc"}, False), ({"M365Environment": None}, False), ({}, False),
    (None, False), ([{"M365Environment": "commercial"}], False), ("commercial", False),
])
def test_environment_cell_needs_exactly_commercial(config, proceeds):
    """C9, D19: TEAMS 2.2, 2.3 and 4.1 proceed only on exactly commercial (the gate answers gcc, gcchigh and dod first)."""
    out = _env_cell(P, {"scuba_config": config})
    assert (out is None) is proceeds
    if out:
        assert (out["cell"], out["reason_code"], out["cited_sections"]) == (
            "environment_unknown", "data_unusable_environment_field", ["scuba_config"])


# ---- H1 to H5 ----
@pytest.mark.parametrize("value,expected", [
    ([{"DomainName": " Contoso.COM "}, {"DomainName": "fabrikam.com"}], {"contoso.com", "fabrikam.com"}),
    ([], None), (None, None), (NOT_COLLECTED, None), ({"DomainName": "a.com"}, None),
    ([{"DomainName": "a.com"}, {"DomainName": " "}], None), ([{"DomainName": "a.com"}, {}], None),
    ([{"DomainName": "a.com"}, "b.com"], None),
])
def test_h1_accepted(value, expected):
    assert _accepted({"accepted_domains": value}) == expected


def test_h1_accepted_absent_section():
    assert _accepted({}) is None


def test_h2_preset_regexes():
    strict, standard = PRESET_RE
    assert strict.search("Strict Preset Security Policy1234") and strict.search("strict preset security policy")
    assert not strict.search("Standard Preset Security Policy")
    assert standard.search("Standard Preset Security Policy") and not standard.search("Custom policy")


EVERYONE = {"SentTo": None, "SentToMemberOf": [], "RecipientDomainIs": None}


@pytest.mark.parametrize("item,accepted,expected,trace", [
    (EVERYONE, None, "q", {}),
    ({**EVERYONE, "SentTo": ["a@x.com"]}, None, "x", {}),
    ({**EVERYONE, "SentToMemberOf": ["group"]}, None, "x", {}),
    ({"SentTo": None, "SentToMemberOf": None}, None, "u", {}),                  # RecipientDomainIs absent
    ({**EVERYONE, "SentTo": "a@x.com"}, None, "u", {}),                         # not a list
    ({**EVERYONE, "RecipientDomainIs": ["a.com", "b.com"]}, {"a.com", "b.com"}, "q", {"via": True}),
    ({**EVERYONE, "RecipientDomainIs": ["A.com ", "b.com"]}, {"a.com", "b.com"}, "q", {"via": True, "case": True}),
    ({**EVERYONE, "RecipientDomainIs": ["a.com"]}, {"a.com", "b.com"}, "x", {"via": True}),
    ({**EVERYONE, "RecipientDomainIs": ["a.com"]}, None, "u", {"via": True}),
    ({**EVERYONE, "RecipientDomainIs": ["a.com", 3]}, {"a.com"}, "u", {"via": True}),
    ({**EVERYONE, "ExceptIfSentTo": ["vip@x.com"]}, None, "u", {}),
    ({**EVERYONE, "ExceptIfRecipientDomainIs": []}, None, "q", {}),
])
def test_h3_cover(item, accepted, expected, trace):
    seen = {}
    assert _cover(item, accepted, seen) == expected
    assert seen == trace


def test_h3_cover_exclusions_narrow_for_spam():
    trace = {}
    assert _cover({**EVERYONE, "ExceptIfSentToMemberOf": ["g"]}, None, trace, excl="narrows") == "x"
    assert trace == {"excl": True}
    assert _cover({**EVERYONE, "ExceptIfSentToMemberOf": "g"}, None, {}, excl="narrows") == "u"


@pytest.mark.parametrize("rule,expected", [({"State": "Enabled"}, "Enabled"), ({"State": "Disabled"}, "Disabled"),
                                           ({"State": "enabled"}, None), ({"State": None}, None), ({}, None),
                                           ({"State": True}, None)])
def test_h4_state(rule, expected):
    assert _state(rule) == expected


def test_h5_preset_pair_topology():
    strict, standard = PRESET_RE
    rules = [{"Identity": "Strict Preset Security Policy"}, {"Identity": "Custom"}]
    policies = [{"Identity": "Strict Preset Security Policy1"}]
    mine, matched, usable = _preset_pair(rules, policies, strict, standard)
    assert (len(mine), len(matched), usable) == (1, 1, True)
    _, _, usable = _preset_pair(rules * 2, policies, strict, standard)
    assert usable is False
    _, _, usable = _preset_pair([{"Identity": "Strict Preset Security Policy / Standard Preset Security Policy"}],
                                policies, strict, standard)
    assert usable is False
    assert _preset_pair([], [], strict, standard) == ([], [], True)


# ---- the inventory boundary and the product-fault answer ----
def test_checked_refuses_answers_outside_the_inventory():
    good = assess("MS.TEAMS.1.1v1", {"meeting_policies": []})
    assert good["cell"] == "no_usable_items"
    for key, bad in (("reason_text", "Data unusable: something else."), ("reason_code", "other"),
                     ("verdict", "met"), ("cited_sections", ["scuba_config"]), ("cell", "flag_bad")):
        with pytest.raises(ValueError):
            checked({**good, key: bad})


def test_rule_failure_entry_is_catalogued_once():
    entry = shared_reason("rule_evaluation_failed")
    assert entry == {"verdict": "not_assessed", "reason_code": "rule_evaluation_failed",
                     "reason_text": ("Not assessed: Auditex could not evaluate this policy on the collected evidence. "
                                     "This is a product fault, not a tenant setting."),
                     "recommendation": "report_product_fault"}
    assert all(entry["reason_code"] not in row["cells"] for row in catalogue()["policies"].values())
    record = rule_failure("MS.TEAMS.2.2v2")
    assert record["cited_sections"] == ["federation_configuration", "scuba_config"]
    # A1: the failure is not a cell; its record has a null cell.
    assert (record["cell"], record["reason_code"], record["reason_text"]) == (
        None, entry["reason_code"], entry["reason_text"])
    assert json.dumps(record["detail"]) == "{}"
