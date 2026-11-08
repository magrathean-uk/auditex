"""TargetedUsersCoverage v1: helper, schema and SS 2.1 rule parity (SS 2.1 interface sections 4 and 7-9).

The oracle below is a frozen copy of the b591772 literal comparison and ``_phish_content``. It never calls the new
helper, so parity is against the old code, not the new code against itself.
"""
from __future__ import annotations

from copy import deepcopy
import json
import lzma
from pathlib import Path
import random
import zlib

import jsonschema
import pytest

from azure_tenant_audit.value_rules import assess, defender_phish
from azure_tenant_audit.value_rules.defender_targeted_users import (
    BINDING_KEY,
    COVERAGE_KEY,
    MembershipResult,
    SensitiveUsersBinding,
    binding_from_config,
    bound_coverage,
    membership,
    membership_from_coverage,
    minimal_coverage,
    shaped_coverage,
    validate_coverage_shape,
)

SS21 = "MS.SECURITYSUITE.2.1v1"
FIXTURES = json.loads(Path("tests/fixtures/targeted-users-coverage-v1.json").read_text())
DIGEST = FIXTURES["fixture_hmac_sha256"]
OTHER_DIGEST = "1" * 64
C = frozenset(FIXTURES["addresses"])
BINDING = SensitiveUsersBinding(2, DIGEST)
KNOWN = {"version": 1, "state": "known", "input_hmac_sha256": DIGEST, "input_count": 2,
         "protected_nonempty": True, "missing_count": 0}
RECORD_KEYS = ("cell", "verdict", "reason_code", "reason_text", "citations", "cited", "flags")


# -- frozen b591772 oracle -------------------------------------------------------------------------------
def _frozen_email_of(entry):
    parts = entry.split(";")
    if len(parts) > 1:
        e = parts[1].strip().lower()
        return e or None
    return entry.strip().lower() or None


def _frozen_have(lst):
    return {n for n in (_frozen_email_of(x.strip().lower()) for x in lst if x is not None) if n}


def frozen_membership(lst, cfg):
    if not isinstance(lst, list) or any(type(x) is not str for x in lst if x is not None):
        return "u"
    have = _frozen_have(lst)
    return "t" if have and cfg <= have else "f"


def frozen_phish_content(need, pol, cfg, binding=None):
    """b591772 ``_phish_content`` verbatim: literal lists only, no summary."""
    tf, action, all_c = defender_phish._tf, defender_phish._action_class, defender_phish._all_c
    if need == "org_domains":
        return all_c([tf(pol.get("EnableOrganizationDomainsProtection")), action(pol.get("TargetedDomainProtectionAction"))])
    if need == "safety_tips":
        return all_c([tf(pol.get(k)) for k in defender_phish.SAFETY_TIPS])
    if need == "users":
        flag, act, lst = tf(pol.get("EnableTargetedUserProtection")), action(pol.get("TargetedUserProtectionAction")), pol.get("TargetedUsersToProtect")

        def norm(x):
            return _frozen_email_of(x.strip().lower())
    else:
        flag, act, lst = tf(pol.get("EnableTargetedDomainsProtection")), action(pol.get("TargetedDomainProtectionAction")), pol.get("TargetedDomainsToProtect")

        def norm(x):
            return x.strip().lower() or None
    if not isinstance(lst, list) or any(type(x) is not str for x in lst if x is not None):
        inc = "u"
    else:
        have = {n for n in (norm(x) for x in lst if x is not None) if n}
        inc = "t" if have and cfg <= have else "f"
    return all_c([flag, act, inc])


def _record(record):
    return {key: record.get(key) for key in RECORD_KEYS}


def _frozen_assess(monkeypatch, sections):
    with monkeypatch.context() as patch:
        patch.setattr(defender_phish, "_phish_content", frozen_phish_content)
        return assess(SS21, deepcopy(sections))


def _summary(lst, configured, digest=DIGEST):
    """What the collector builds below the caps: known from the pure helper, unknown as ``unusable``."""
    result = membership(lst, configured)
    if result.value == "u":
        return minimal_coverage("unusable")
    return {"version": 1, "state": "known", "input_hmac_sha256": digest, "input_count": len(configured),
            "protected_nonempty": result.protected_nonempty, "missing_count": result.missing_count}


ATOMS = [
    "alice@example.invalid", " BOB@Example.Invalid ", "Name;alice@example.invalid", "Name;", ";bob@example.invalid",
    "x;bob@example.invalid;ignored", "a;b;c;d", "carol@example.invalid", "group-dl@example.invalid", "Display Name",
    "not-an-email", " ", "", None, "ALİCE@example.invalid", "alice@example.invalid ", "Alice@Example.Invalid;x",
    "ß@example.invalid", "SS@example.invalid",
]
BAD = [1, 0, True, False, 1.5, {"a": 1}, ["alice@example.invalid"], ("bob@example.invalid",)]
NON_LISTS = [None, "alice@example.invalid", {"x": 1}, 3, True, ("alice@example.invalid", "bob@example.invalid"),
             frozenset(C)]
CONFIGS = [C, frozenset({"alice@example.invalid"}), frozenset({"group-dl@example.invalid"}),
           frozenset({"display name"}), frozenset({"ss@example.invalid"}), frozenset()]


def generated_lists(count=600, seed=20261107):
    rng = random.Random(seed)
    lists = [[], [None], [None, " ", "Name;"], list(C), sorted(C, reverse=True) * 3,
             ["alice@example.invalid", "bob@example.invalid", 7], [7, "alice@example.invalid", "bob@example.invalid"],
             ["group-dl@example.invalid"], ["Display Name"]]
    for _ in range(count):
        size = rng.randint(0, 7)
        pool = ATOMS + (BAD if rng.random() < 0.2 else [])
        lists.append([deepcopy(rng.choice(pool)) for _ in range(size)])
    return lists + NON_LISTS


# -- pure helper -----------------------------------------------------------------------------------------
@pytest.mark.parametrize("configured", CONFIGS, ids=lambda c: f"C{len(c)}-{sorted(c)[:1]}")
def test_membership_matches_frozen_comparison_and_records_the_exact_pair(configured):
    for lst in generated_lists():
        result = membership(deepcopy(lst), configured)
        assert isinstance(result, MembershipResult)
        assert result.value == frozen_membership(lst, configured), lst
        if result.value == "u":
            assert (result.protected_nonempty, result.missing_count) == (None, None)
            continue
        have = _frozen_have(lst)
        assert result.protected_nonempty is bool(have)
        assert result.missing_count == len(configured - have)
        assert (result.value == "t") is (result.protected_nonempty and result.missing_count == 0)


def test_membership_is_pure_unbounded_and_order_insensitive():
    big = ["x@example.invalid"] * 10_001 + list(C)
    before = list(big)
    assert membership(big, C).value == "t"            # the pure helper never caps; the producer's wrapper does
    assert big == before
    assert membership(list(reversed(big)), C) == membership(big, C)
    assert membership(["Name;ALICE@example.invalid;ignored", "bob@example.invalid"], C).value == "t"
    assert membership(["alice@example.invalid", "bob@example.invalid", True], C).value == "u"
    assert membership(["alice@example.invalid", "bob@example.invalid", 0], C).value == "u"
    assert membership(["group-dl@example.invalid"], frozenset({"group-dl@example.invalid"})).value == "t"
    assert membership(["group-dl@example.invalid"], C) == MembershipResult("f", True, 2)
    assert membership([], C) == MembershipResult("f", False, 2)
    assert membership([None, " ", "Name;"], C) == MembershipResult("f", False, 2)
    assert membership(["anything"], frozenset()).value == "t"      # defined empty-set behaviour, called directly
    assert membership(["ALİCE@example.invalid"], frozenset({"alİce@example.invalid".lower()})).value == "t"


# -- shape, invariants and binding -----------------------------------------------------------------------
def _without(field):
    return {k: v for k, v in KNOWN.items() if k != field}


INVALID = [
    *[_without(field) for field in KNOWN],
    {**KNOWN, "protected_nonempty": None}, {**KNOWN, "protected_nonempty": "true"}, {**KNOWN, "protected_nonempty": 1},
    {**KNOWN, "protected_nonempty": False, "missing_count": 0}, {**KNOWN, "protected_nonempty": False, "missing_count": 1},
    {**KNOWN, "missing_count": -1}, {**KNOWN, "missing_count": 3}, {**KNOWN, "missing_count": False},
    {**KNOWN, "missing_count": 0.0},
    {**KNOWN, "input_count": 0}, {**KNOWN, "input_count": 10_001}, {**KNOWN, "input_count": True},
    {**KNOWN, "input_count": 2.0},
    {**KNOWN, "version": True}, {**KNOWN, "version": 1.0}, {**KNOWN, "version": 2}, {**KNOWN, "version": "1"},
    {**KNOWN, "state": "Known"}, {**KNOWN, "state": "KNOWN"}, {**KNOWN, "state": "other"}, {**KNOWN, "state": None},
    {**KNOWN, "extra": 1}, {**KNOWN, "TargetedUsersToProtect": ["alice@example.invalid"]},
    {**KNOWN, "input_hmac_sha256": DIGEST.upper()}, {**KNOWN, "input_hmac_sha256": DIGEST[:63]},
    {**KNOWN, "input_hmac_sha256": "g" * 64}, {**KNOWN, "input_hmac_sha256": None},
    {**KNOWN, "input_hmac_sha256": DIGEST + "\n"},
    {"version": 1, "state": "unusable", "input_count": 2}, {"version": 1, "state": "over_limit", "missing_count": 0},
    {"version": 1, "state": "not_collected", "input_hmac_sha256": DIGEST}, {"version": 1, "state": "unusable", "x": None},
    {"version": 1}, {"state": "unusable"}, {}, [], None, "known", json.dumps(KNOWN), 1, True,
]


@pytest.mark.parametrize("value", INVALID, ids=range(len(INVALID)))
def test_invalid_proofs_are_rejected_and_never_membership(value):
    assert validate_coverage_shape(value) is False
    assert membership_from_coverage(value, C, BINDING) == "u"
    shaped = shaped_coverage({COVERAGE_KEY: value})
    assert shaped == {"version": 1, "state": "unusable"}
    assert bound_coverage({COVERAGE_KEY: value}, BINDING) == shaped


@pytest.mark.parametrize("state", ["unusable", "not_collected", "over_limit"])
def test_minimal_states_are_unknown_and_reproduced_without_echo(state):
    value = {"version": 1, "state": state}
    assert validate_coverage_shape(value)
    assert membership_from_coverage(value, C, BINDING) == "u"
    assert bound_coverage({COVERAGE_KEY: value}, BINDING) == value
    assert bound_coverage({COVERAGE_KEY: value}, BINDING) is not value


def test_known_pairs_and_binding_disagreements():
    assert membership_from_coverage(KNOWN, C, BINDING) == "t"
    assert membership_from_coverage({**KNOWN, "missing_count": 1}, C, BINDING) == "f"
    assert membership_from_coverage({**KNOWN, "protected_nonempty": False, "missing_count": 2}, C, BINDING) == "f"
    # Only the bound (nonempty, missing 0) pair is success; missing 0 alone without binding is unknown.
    assert membership_from_coverage(KNOWN, C, None) == "u"
    assert membership_from_coverage(KNOWN, C, SensitiveUsersBinding(2, OTHER_DIGEST)) == "u"
    assert membership_from_coverage(KNOWN, C, SensitiveUsersBinding(3, DIGEST)) == "u"
    assert membership_from_coverage(KNOWN, C | {"carol@example.invalid"}, BINDING) == "u"
    assert membership_from_coverage(KNOWN, frozenset({"alice@example.invalid"}), BINDING) == "u"
    assert membership_from_coverage(KNOWN, list(C), BINDING) == "u"
    assert membership_from_coverage(KNOWN, C, {"input_count": 2, "input_hmac_sha256": DIGEST}) == "u"
    assert bound_coverage({COVERAGE_KEY: KNOWN}, BINDING) == KNOWN
    assert bound_coverage({COVERAGE_KEY: KNOWN}, BINDING) is not KNOWN
    assert bound_coverage({COVERAGE_KEY: KNOWN}, None) == {"version": 1, "state": "unusable"}
    assert bound_coverage({COVERAGE_KEY: KNOWN}, SensitiveUsersBinding(2, OTHER_DIGEST)) == {"version": 1, "state": "unusable"}
    assert bound_coverage({}, BINDING) == {"version": 1, "state": "not_collected"}
    assert bound_coverage({"TargetedUsersToProtect": list(C)}, BINDING) == {"version": 1, "state": "not_collected"}
    assert shaped_coverage({COVERAGE_KEY: KNOWN}) == KNOWN
    with pytest.raises(ValueError):
        minimal_coverage("known")


@pytest.mark.parametrize("args", [(True, DIGEST), (0, DIGEST), (-1, DIGEST), (2.0, DIGEST), ("2", DIGEST),
                                  (2, DIGEST.upper()), (2, DIGEST[:-1]), (2, 5), (2, None)])
def test_binding_is_validated_and_never_displayed(args):
    with pytest.raises(ValueError) as caught:
        SensitiveUsersBinding(*args)
    assert DIGEST not in str(caught.value) and DIGEST.upper() not in str(caught.value)
    assert DIGEST not in repr(BINDING) and DIGEST not in str(BINDING) and "input_count" not in repr(BINDING)
    with pytest.raises(AttributeError):
        BINDING.input_count = 3  # frozen


def test_binding_from_config_is_closed():
    assert binding_from_config({"input_count": 2, "input_hmac_sha256": DIGEST}) == BINDING
    assert binding_from_config(BINDING) is BINDING
    for value in ({"input_count": True, "input_hmac_sha256": DIGEST}, {"input_count": 2},
                  {"input_count": 2, "input_hmac_sha256": DIGEST, "extra": 1}, {"input_count": 2, "input_hmac_sha256": DIGEST.upper()},
                  [2, DIGEST], None, "x", json.dumps({"input_count": 2, "input_hmac_sha256": DIGEST})):
        assert binding_from_config(value) is None


def test_schema_matches_python_validation_except_cross_field_invariants():
    schema = json.loads(Path("schemas/targeted_users_coverage.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    assert validator.is_valid(KNOWN)
    for state in ("unusable", "not_collected", "over_limit"):
        assert validator.is_valid({"version": 1, "state": state})
    # JSON Schema cannot express exact non-boolean integers or the cross-field invariants; Python must refuse them.
    schema_only = [{**KNOWN, "protected_nonempty": False, "missing_count": 0}, {**KNOWN, "missing_count": 3},
                   {**KNOWN, "protected_nonempty": False, "missing_count": 1}, {**KNOWN, "missing_count": 0.0},
                   {**KNOWN, "input_count": 2.0}, {**KNOWN, "version": 1.0},
                   {**KNOWN, "input_hmac_sha256": DIGEST + "\n"}]   # Python ``re`` lets ``$`` precede a final newline
    for value in INVALID:
        if isinstance(value, dict) and value not in schema_only:
            assert not validator.is_valid(value), value
        assert not validate_coverage_shape(value)
    for case in FIXTURES["cases"]:
        coverage = case["policy_row"].get(COVERAGE_KEY)
        if coverage is not None and case["case"] != "unknown_shape_bad_invariant":
            assert validator.is_valid(coverage) is validate_coverage_shape(coverage), case["case"]


# -- SS 2.1 rule: fixtures, edge cases and parity ---------------------------------------------------------
def _harness(*rows, config=None):
    sections = deepcopy(FIXTURES["harness"])
    sections["anti_phish_policies"] = deepcopy(list(rows))
    if config is not None:
        sections["scuba_config"]["SecuritySuite"][SS21] = config
    return sections


@pytest.mark.parametrize("case", FIXTURES["cases"], ids=lambda c: c["case"])
def test_fixture_summaries_reach_the_documented_cells(case):
    row = case["policy_row"]
    expected = case["expected"]
    if COVERAGE_KEY in row:
        assert membership_from_coverage(row[COVERAGE_KEY], C, BINDING) == expected["membership"]
    record = assess(SS21, _harness(row))
    assert (record["verdict"], record["cell"]) == (expected["verdict"], expected["cell"])


def _met():
    return deepcopy(FIXTURES["cases"][0]["policy_row"])


def test_configuration_outcomes_never_use_a_passing_summary():
    binding = {"input_count": 2, "input_hmac_sha256": DIGEST}
    assert assess(SS21, _harness(_met(), config={"SensitiveUsers": [], BINDING_KEY: binding}))["cell"] == "config_list_empty"
    assert assess(SS21, _harness(_met(), config={"SensitiveUsers": [" ", None, 5], BINDING_KEY: binding}))["cell"] == "config_list_empty"
    assert assess(SS21, _harness(_met(), config={"SensitiveUsers": ["a;b;c"], BINDING_KEY: binding}))["cell"] == "config_entry_unusable"
    bad_entry = {"SensitiveUsers": [*FIXTURES["addresses"], 5], BINDING_KEY: binding}
    assert assess(SS21, _harness(_met(), config=bad_entry))["cell"] == "config_entry_unusable"   # Q plus cfg_bad
    assert assess(SS21, _harness(_met(), config={"SensitiveUsers": FIXTURES["addresses"]}))["cell"] == "policy_field_unusable"
    for broken in ({"input_count": 2}, {"input_count": True, "input_hmac_sha256": DIGEST},
                   {"input_count": 2, "input_hmac_sha256": OTHER_DIGEST}, {"input_count": 3, "input_hmac_sha256": DIGEST}):
        config = {"SensitiveUsers": FIXTURES["addresses"], BINDING_KEY: broken}
        assert assess(SS21, _harness(_met(), config=config))["cell"] == "policy_field_unusable"
    sections = _harness(_met())
    sections["scuba_config"] = {"Defender": {"MS.DEFENDER.2.1v1": {"SensitiveUsers": FIXTURES["addresses"], BINDING_KEY: binding}}}
    assert assess(SS21, sections)["cell"] == "default_qualifies"


def test_summary_takes_precedence_and_literal_path_stays_for_direct_input():
    literal = {k: v for k, v in _met().items() if k != COVERAGE_KEY}
    literal["TargetedUsersToProtect"] = list(C)
    assert assess(SS21, _harness(literal))["cell"] == "default_qualifies"          # reference/export input
    both = {**literal, COVERAGE_KEY: {"version": 1, "state": "unusable"}}
    assert assess(SS21, _harness(both))["cell"] == "policy_field_unusable"         # invalid summary: no fallback
    both = {**literal, COVERAGE_KEY: {**KNOWN, "missing_count": 1}}
    assert assess(SS21, _harness(both))["cell"] == "no_qualifying_policy"


def test_unknown_custom_summary_without_rules_keeps_custom_policy_without_rule():
    default = {**_met(), "EnableTargetedUserProtection": False}
    custom = {**_met(), "Identity": "Custom anti-phish", "Name": "Custom anti-phish", "IsDefault": False,
              COVERAGE_KEY: {"version": 1, "state": "unusable"}}
    assert assess(SS21, _harness(default, custom))["cell"] == "custom_policy_without_rule"


@pytest.mark.parametrize("flag,action", [(True, "Quarantine"), (True, "MoveToJmf"), (True, "NoAction"),
                                         (False, "Quarantine"), (None, "Quarantine"), (True, "Other"), (True, 3)])
def test_full_rule_record_parity_with_frozen_rule(monkeypatch, flag, action):
    for lst in generated_lists(count=120, seed=zlib.crc32(f"{flag}|{action}".encode())):
        literal = {**{k: v for k, v in _met().items() if k != COVERAGE_KEY},
                   "EnableTargetedUserProtection": flag, "TargetedUserProtectionAction": action,
                   "TargetedUsersToProtect": deepcopy(lst)}
        old = _frozen_assess(monkeypatch, _harness(literal))
        summarised = {**{k: v for k, v in literal.items() if k != "TargetedUsersToProtect"}, COVERAGE_KEY: _summary(lst, C)}
        assert _record(assess(SS21, _harness(summarised))) == _record(old), lst


# -- allowed repository vectors -------------------------------------------------------------------------
def _vectors():
    with lzma.open(Path("tests/fixtures/value-rules/vectors-s5.jsonl.xz"), "rt") as handle:
        return [json.loads(line) for line in handle]


VECTORS = _vectors()
SP = {"list_key": "SensitiveUsers", "alias": "MS.DEFENDER.2.1v1", "need": "users"}


def _config_block(config):
    for top, key in (("SecuritySuite", SS21), ("Defender", "MS.DEFENDER.2.1v1")):
        block = config.get(top) if isinstance(config, dict) else None
        if isinstance(block, dict) and key in block:
            return block[key]
    return None


def test_every_ss21_vector_keeps_its_record_after_summary_substitution(monkeypatch):
    from collections import Counter

    rows = [row for row in VECTORS if row["policy"] == SS21]
    assert len(rows) == 264
    cells = Counter()
    substituted = 0
    for vector in rows:
        sections = deepcopy(vector["sections"])
        expected = (vector["rule_cell"], vector["rule_verdict"], vector["rule_reason_code"], vector["rule_reason_text"])
        old = _frozen_assess(monkeypatch, sections)
        assert (old["cell"], old["verdict"], old["reason_code"], old["reason_text"]) == expected
        try:
            configured, _ = defender_phish._phish_cfg(SS21, SP, sections)
        except (AttributeError, TypeError, KeyError):
            configured = None
        block = _config_block(sections.get("scuba_config"))
        policies = sections.get("anti_phish_policies")
        if isinstance(policies, list) and all(isinstance(p, dict) for p in policies):
            for policy in policies:
                lst = policy.pop("TargetedUsersToProtect", None)
                if configured and isinstance(block, dict):
                    policy[COVERAGE_KEY] = _summary(lst, frozenset(configured), OTHER_DIGEST)
                else:
                    policy[COVERAGE_KEY] = minimal_coverage("unusable")
            if configured and isinstance(block, dict):
                block[BINDING_KEY] = {"input_count": len(configured), "input_hmac_sha256": OTHER_DIGEST}
            substituted += 1
        new = assess(SS21, sections)
        assert _record(new) == _record(old), vector.get("id", expected)
        cells[new["cell"]] += 1
    assert substituted > 150
    assert {"default_qualifies", "custom_qualifies", "preset_qualifies", "no_qualifying_policy",
            "qualifier_shadowed", "policy_field_unusable"} <= cells.keys()


def test_adjacent_ss22_to_ss24_records_ignore_the_summary():
    rows = [row for row in VECTORS if row["policy"].startswith("MS.SECURITYSUITE.2.") and row["policy"] != SS21]
    assert {row["policy"] for row in rows} >= {"MS.SECURITYSUITE.2.2v1", "MS.SECURITYSUITE.2.3v1", "MS.SECURITYSUITE.2.4v1"}
    for vector in rows:
        sections = deepcopy(vector["sections"])
        policies = sections.get("anti_phish_policies")
        if isinstance(policies, list):
            for index, policy in enumerate(policies):
                if isinstance(policy, dict):
                    policy[COVERAGE_KEY] = [KNOWN, {"version": 1, "state": "unusable"}, "junk"][index % 3]
        record = assess(vector["policy"], sections)
        assert (record["cell"], record["verdict"], record["reason_code"], record["reason_text"]) == (
            vector["rule_cell"], vector["rule_verdict"], vector["rule_reason_code"], vector["rule_reason_text"])
