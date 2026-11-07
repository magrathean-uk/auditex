"""SS 2.1 TargetedUsersCoverage v1 producer and anti-phish row boundary (collect lane). Constructed data only.

The producer module is imported inside a fixture, so on a base without it these tests error at run time rather than
breaking collection of the file; the fail-first proofs for the boundary live in the adapter, replay and resume files.
"""
from __future__ import annotations

from copy import deepcopy
import importlib
import json

import pytest

from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
from azure_tenant_audit.sensitive_users import SensitiveUsers, sensitive_users_digest

ADDRESSES = ("alice@example.invalid", "bob@example.invalid")
KEY = bytes(range(32))
DIGEST = "440e979a9184114e5d0376ee777b8c0ff444ca0db3a2242e01937331f494538a"
CANARIES = ("Zebulon Quarkwright", "zq-canary@unlisted-canary.invalid", "canary-domain-x.invalid", "Name;;bad@@canary-malformed")
SETTINGS = {
    "Identity": "Default", "Name": "Default", "IsDefault": True, "Enabled": True,
    "EnableTargetedUserProtection": True, "TargetedUserProtectionAction": "Quarantine",
    "EnableOrganizationDomainsProtection": True, "TargetedDomainProtectionAction": "Quarantine",
    "EnableTargetedDomainsProtection": True, "TargetedDomainsToProtect": ["partner.example.invalid"],
    "EnableFirstContactSafetyTips": True, "EnableSimilarUsersSafetyTips": True, "EnableSimilarDomainsSafetyTips": True,
    "EnableUnusualCharactersSafetyTips": True, "EnableViaTag": True, "EnableUnauthenticatedSender": True,
}


@pytest.fixture
def tuc():
    return importlib.import_module("azure_tenant_audit.collectors.targeted_users_coverage")


@pytest.fixture
def binding():
    from azure_tenant_audit.value_rules.defender_targeted_users import SensitiveUsersBinding
    return SensitiveUsersBinding(2, DIGEST)


USERS = SensitiveUsers(ADDRESSES)


def _row(targets=None, **extra):
    row = dict(SETTINGS)
    if targets is not None:
        row["TargetedUsersToProtect"] = targets
    row.update(extra)
    return row


def _known(nonempty, missing):
    return {"version": 1, "state": "known", "input_hmac_sha256": DIGEST, "input_count": 2,
            "protected_nonempty": nonempty, "missing_count": missing}


def test_fixture_digest_is_the_writer_hmac_of_the_public_test_tuple():
    assert sensitive_users_digest(ADDRESSES, KEY) == DIGEST


@pytest.mark.parametrize("targets,expected", [
    ([*ADDRESSES], (True, 0)),
    (["alice@example.invalid"], (True, 1)),
    ([], (False, 2)),
    ([None, " ", "Name;"], (False, 2)),
    (["Name;ALICE@example.invalid;ignored", " Bob@Example.Invalid "], (True, 0)),
    (["Alice Display Name", "Bob Display Name"], (True, 2)),
    (["group@example.invalid"], (True, 2)),
    (["not-an-address", *ADDRESSES, *ADDRESSES], (True, 0)),
    ([";alice@example.invalid", "x;bob@example.invalid;y;z"], (True, 0)),
])
def test_known_summary_matches_the_product_membership_helper(tuc, binding, targets, expected):
    from azure_tenant_audit.value_rules.defender_targeted_users import membership, validate_coverage_shape
    row = _row(targets)
    before = deepcopy(row)
    summary = tuc.summarise(row, USERS, binding)
    assert summary == _known(*expected)
    assert validate_coverage_shape(summary) and list(summary) == [
        "version", "state", "input_hmac_sha256", "input_count", "protected_nonempty", "missing_count"]
    result = membership(targets, frozenset(ADDRESSES))
    assert (result.protected_nonempty, result.missing_count) == expected
    assert row == before, "the producer never mutates the policy row"


@pytest.mark.parametrize("targets", [
    "alice@example.invalid", {"Address": "alice@example.invalid"}, 5, True, None,
    [*ADDRESSES, {"x": 1}], [*ADDRESSES, ["nested"]], [*ADDRESSES, 1], [*ADDRESSES, False],
    [float("nan")], ["\ud800"],
])
def test_unusable_targets_are_never_false_membership(tuc, binding, targets):
    assert tuc.summarise(_row(targets), USERS, binding) == {"version": 1, "state": "unusable"}


def test_absent_target_field_is_unusable_not_an_empty_list(tuc, binding):
    assert tuc.summarise(_row(), USERS, binding) == {"version": 1, "state": "unusable"}


@pytest.mark.parametrize("users,bound", [
    (SensitiveUsers(), True), (None, True), (USERS, False), (SensitiveUsers(ADDRESSES[:1]), True),
])
def test_no_loaded_tuple_or_no_matching_binding_is_not_collected(tuc, binding, users, bound):
    assert tuc.summarise(_row([*ADDRESSES]), users, binding if bound else None) == {
        "version": 1, "state": "not_collected"}


@pytest.mark.parametrize("fake", [
    {"input_count": 2, "input_hmac_sha256": DIGEST}, KEY, DIGEST, (2, DIGEST),
])
def test_only_the_writer_binding_type_binds_never_a_key_or_mapping(tuc, fake):
    assert tuc.summarise(_row([*ADDRESSES]), USERS, fake) == {"version": 1, "state": "not_collected"}


# Entry cap: raw elements before filtering, normalisation or deduplication; inclusive.
@pytest.mark.parametrize("targets,state", [
    ([*ADDRESSES] + [None] * 9_998, "known"),
    ([*ADDRESSES] + [None] * 9_999, "over_limit"),
    (["alice@example.invalid"] * 10_000, "known"),
    (["alice@example.invalid"] * 10_001, "over_limit"),
    ([None] * 10_001, "over_limit"),
    ([" "] * 10_001, "over_limit"),
    ([*ADDRESSES] * 5_000 + [{"x": 1}], "over_limit"),
])
def test_entry_cap_counts_raw_entries(tuc, binding, targets, state):
    assert tuc.summarise(_row(targets), USERS, binding)["state"] == state


def _sized(builder, size):
    """A list whose compact strict-UTF-8 JSON is exactly ``size`` bytes (asserted independently)."""
    value = builder(size)
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    assert len(encoded) == size
    return value


BYTE_SHAPES = {
    "ascii": lambda n: ["a" * (n - 4)],
    "two_entries_and_comma": lambda n: ["a" * ((n - 7) // 2), "b" * (n - 7 - (n - 7) // 2)],
    "non_ascii": lambda n: ["é" * 1000 + "a" * (n - 4 - 2000)],
    "four_byte": lambda n: ["\U0001F600" * 100 + "a" * (n - 4 - 400)],
    "escaped_quotes": lambda n: ['"' * 1000 + "a" * (n - 4 - 2000)],
    "control_escape": lambda n: ["\x01" * 100 + "a" * (n - 4 - 600)],
    "null_counted": lambda n: [None, "a" * (n - 9)],
    "duplicates": lambda n: ["alice@example.invalid"] * 9_000 + ["a" * (n - 2 - 9_000 * 24 - 2)],
    "covering_then_padding": lambda n: [*ADDRESSES, "p" * (n - 50)],
}


@pytest.mark.parametrize("shape", list(BYTE_SHAPES))
def test_byte_cap_is_inclusive_compact_utf8_json(tuc, binding, shape):
    at_limit = _sized(BYTE_SHAPES[shape], 262_144)
    over = _sized(BYTE_SHAPES[shape], 262_145)
    assert tuc.summarise(_row(at_limit), USERS, binding)["state"] == "known"
    assert tuc.summarise(_row(over), USERS, binding) == {"version": 1, "state": "over_limit"}


def test_byte_cap_never_evaluates_a_passing_prefix(tuc, binding):
    huge_first = ["x" * 300_000, *ADDRESSES]
    assert tuc.summarise(_row(huge_first), USERS, binding) == {"version": 1, "state": "over_limit"}
    covering_prefix = [*ADDRESSES] * 5_000 + ["tail"]
    assert tuc.summarise(_row(covering_prefix), USERS, binding) == {"version": 1, "state": "over_limit"}


def test_byte_cap_stops_at_the_first_chunk_past_the_limit(tuc, monkeypatch):
    seen = []
    real = json.JSONEncoder.iterencode

    def spy(self, value, _one_shot=False):
        for chunk in real(self, value, _one_shot):
            seen.append(len(chunk))
            yield chunk
    monkeypatch.setattr(json.JSONEncoder, "iterencode", spy)
    assert tuc._over_byte_limit(["a" * 300_000] + ["b"] * 9_000) is True
    assert len(seen) <= 3, "the encoder is abandoned once the bound is passed"


def test_helper_failure_is_unusable_and_never_escapes(tuc, binding, monkeypatch):
    def boom(*_):
        raise ValueError(f"leak {CANARIES[1]}")
    monkeypatch.setattr(tuc, "membership", boom)
    assert tuc.summarise(_row([*ADDRESSES]), USERS, binding) == {"version": 1, "state": "unusable"}


def test_row_rebuild_keeps_every_selected_setting_and_drops_targets_and_unknown_fields(tuc, binding):
    supplied = {**_known(True, 0), "input_hmac_sha256": "ab" * 32}
    row = _row(["alice@example.invalid", *CANARIES], Extra=CANARIES[0], TargetedUsersCoverage=supplied)
    clean = tuc.sanitise_policy_row(row, USERS, binding, observed=True)
    assert {k: clean[k] for k in SETTINGS} == SETTINGS
    assert clean["TargetedUsersCoverage"] == _known(True, 1), "fresh literals overwrite a supplied summary"
    assert set(clean) == {*SETTINGS, "TargetedUsersCoverage"}
    assert all(c not in json.dumps(clean) for c in CANARIES) and "ab" * 32 not in json.dumps(clean)


def test_row_with_bad_targets_keeps_its_other_rule_fields(tuc, binding):
    clean = tuc.sanitise_policy_row(_row([*ADDRESSES, {"Name": CANARIES[0]}]), USERS, binding, observed=True)
    assert {k: clean[k] for k in SETTINGS} == SETTINGS
    assert clean["TargetedUsersCoverage"] == {"version": 1, "state": "unusable"}


def test_replayed_summary_without_literals_is_never_rebound(tuc, binding):
    row = _row(None, TargetedUsersCoverage=_known(True, 0))
    assert tuc.sanitise_policy_row(row, USERS, binding, observed=False)["TargetedUsersCoverage"] == {
        "version": 1, "state": "not_collected"}


@pytest.mark.parametrize("value", [
    [_row([*ADDRESSES]), "Default"], [CANARIES[1]], [None], [[_row([*ADDRESSES])]], "Default", 7,
])
def test_scalar_or_unrepresentable_rows_are_a_controlled_parse_error(tuc, binding, value):
    out = tuc.sanitise_response({"value": value}, USERS, binding, observed=True, command="cmd")
    assert out == {"command": "cmd", "error": "command_output_parse_error", "error_class": "command_parse_error"}


def test_live_success_without_a_row_container_is_a_parse_error_not_a_fake_policy(tuc, binding):
    out = tuc.sanitise_response({}, USERS, binding, observed=True, command="cmd")
    assert "value" not in out and out["error_class"] == "command_parse_error"


def test_error_envelope_keeps_only_fixed_classes_and_numbers(tuc):
    envelope = {"error": f"command_failed:1 {CANARIES[1]}", "error_class": "command_error", "return_code": 1,
                "stdout": json.dumps([{"TargetedUsersToProtect": list(CANARIES)}]), "stderr": CANARIES[0],
                "stdout_sample": CANARIES[2], "message": CANARIES[3]}
    out = tuc.sanitise_response(envelope, None, None, observed=True)
    assert out == {"error": "command_error", "error_class": "command_error", "return_code": 1}


def test_transform_output_is_checked_against_the_closed_shape(tuc, binding):
    good = tuc.sanitise_response({"value": [_row([*ADDRESSES])]}, USERS, binding, observed=True)
    assert tuc.enforce_response(good, command="cmd")["command"] == "cmd"
    for bad in ({"value": [{**good["value"][0], "TargetedUsersToProtect": [CANARIES[1]]}]},
                {"value": [{k: v for k, v in good["value"][0].items() if k != "TargetedUsersCoverage"}]},
                {"value": good["value"], "stdout": CANARIES[0]},
                {"value": good["value"], "error": CANARIES[1]}):
        with pytest.raises(tuc.BoundaryError) as caught:
            tuc.enforce_response(bad, command="cmd")
        assert all(c not in str(caught.value) for c in CANARIES)


class _FakeAdapter:
    """Not a PowerShellGraphAdapter: the collector must apply the boundary itself."""

    def __init__(self, anti_phish):
        self.anti_phish = anti_phish
        self.kwargs = []

    def run(self, command, log_event=None, session=None):
        self.kwargs.append(command)
        if command.startswith("Get-AntiPhishPolicy"):
            return deepcopy(self.anti_phish)
        return {"value": []}


@pytest.mark.parametrize("bound", [True, False])
def test_collector_applies_the_boundary_for_another_adapter(monkeypatch, binding, bound):
    rows = [_row([*ADDRESSES, *CANARIES]), _row([{"bad": CANARIES[0]}]), _row(None)]
    adapter = _FakeAdapter({"value": rows, "stdout": CANARIES[1]})
    monkeypatch.setattr("azure_tenant_audit.collectors.exchange_policy.get_adapter", lambda _name: adapter)
    context = {"sensitive_users": USERS, "sensitive_users_binding": binding} if bound else {}
    result = ExchangePolicyCollector().run(context)
    envelope = result.payload["antiPhishPolicies"]
    text = json.dumps(result.payload) + json.dumps(result.coverage)
    assert all(c not in text for c in CANARIES) and "TargetedUsersToProtect\":" not in text
    states = [row["TargetedUsersCoverage"] for row in envelope["value"]]
    if bound:
        assert states == [_known(True, 0), {"version": 1, "state": "unusable"}, {"version": 1, "state": "unusable"}]
    else:
        assert states == [{"version": 1, "state": "not_collected"}] * 3
    assert all({k: row[k] for k in SETTINGS} == SETTINGS for row in envelope["value"])
    assert DIGEST not in json.dumps(result.coverage)


def test_collector_hands_the_transform_to_the_real_adapter(monkeypatch, binding):
    from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
    seen = {}

    class _Spy(PowerShellGraphAdapter):
        def run(self, command, log_event=None, session=None, response_transform=None):
            if command.startswith("Get-AntiPhishPolicy"):
                seen["transform"] = response_transform
                return response_transform({"value": [_row([*ADDRESSES])]})
            seen.setdefault("others", []).append(response_transform)
            return {"value": []}
    monkeypatch.setattr("azure_tenant_audit.collectors.exchange_policy.get_adapter", lambda _name: _Spy())
    result = ExchangePolicyCollector().run({"sensitive_users": USERS, "sensitive_users_binding": binding})
    assert callable(seen["transform"]) and set(seen["others"]) == {None}
    assert result.payload["antiPhishPolicies"]["value"][0]["TargetedUsersCoverage"] == _known(True, 0)
    assert "sensitive_users" not in json.dumps(result.payload, default=str)
