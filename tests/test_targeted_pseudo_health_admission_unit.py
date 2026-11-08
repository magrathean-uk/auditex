"""Generic pseudo-operation health has no policy-target exception and never calls hostile values."""
from copy import deepcopy

import pytest

from azure_tenant_audit.collectors import anti_phish_admission as admission


@pytest.mark.parametrize("key,value", [
    ("error", "untrusted detail"), ("error_class", {"nested": "untrusted detail"}),
    ("resolver_error", True), ("collection_truncated", True), ("bounded_sample", True),
    ("@odata.nextLink", "https://invalid.example/next"), ("truncation_reason", "unknown"),
    ("incomplete", True), ("partial", True), ("complete", False),
    ("read_state", "failed"), ("collection_status", "not_collected"),
])
def test_generic_health_walks_refusal_inside_even_the_target_value(key, value):
    original = [{"TargetedUsersToProtect": [{"details": {key: value}}]}]
    before = deepcopy(original)
    assert admission.subtree_healthy(original) is False
    assert original == before


def test_status_is_only_health_on_the_root_mapping():
    assert admission.subtree_healthy({"status": "Provisioned"}) is False
    assert admission.subtree_healthy({"status": "ok", "value": [{"status": "Provisioned"}]}) is True
    assert admission.subtree_healthy([{"status": "failed"}]) is True
    assert admission.subtree_healthy({"value": [{"error": None, "complete": True}]}) is True


def test_generic_health_refuses_bounds_and_cycles(monkeypatch):
    monkeypatch.setattr(admission, "MAX_DEPTH", 4)
    monkeypatch.setattr(admission, "MAX_NODES", 8)
    assert admission.subtree_healthy([None] * 8) is False
    assert admission.subtree_healthy([[[[[]]]]]) is False
    cycle = []
    cycle.append(cycle)
    assert admission.subtree_healthy(cycle) is False
    assert admission.subtree_healthy({"value": [None, 1, True, 2.5, "data"]}) is True


def test_generic_health_validates_keys_before_equality_and_never_calls_objects():
    class Hostile:
        def __hash__(self):
            return hash("error")
        def __eq__(self, other):
            pytest.fail("input equality called")
        def __bool__(self):
            pytest.fail("input truthiness called")
    key = Hostile()
    assert admission.subtree_healthy({key: "data"}) is False
    assert admission.subtree_healthy({"error": Hostile()}) is False
    assert admission.subtree_healthy([Hostile()]) is False
