"""Malformed local-only metadata cannot carry proof values into shared output."""
import json
from copy import deepcopy

import pytest

from azure_tenant_audit.output_redaction import redact_output

DIGEST = "ac1d" + "7" * 60
PROOF = {"supplied": True, "count": 7, "hmac_sha256": DIGEST}
CASES = [
    ("sensitive_users", [PROOF], {}),
    ("sensitive_users", ((PROOF,),), {}),
    ("sensitive_users", json.dumps([PROOF]), {}),
    ("sensitive_users", json.dumps([[PROOF]]), {}),
    ("sensitive_users", DIGEST, {}),
    ("sensitive_users", 7, {}),
    ("sensitive_users", {"supplied": DIGEST, "count": 7}, {}),
    ("sensitive_users", {"supplied": {"count": 7, "hmac_sha256": DIGEST}}, {}),
    ("sensitive_users", {"supplied": [PROOF]}, {}),
    ("sensitive_users", {"supplied": 1, "hmac_sha256": DIGEST}, {}),
    ("sensitive_users", json.dumps({"supplied": [PROOF]}), "{}"),
    ("operator_inputs", [{"sensitive_users": PROOF}], {}),
    ("operator_inputs", json.dumps([{"sensitive_users": PROOF}]), {}),
    ("operator_inputs", DIGEST, {}),
]


@pytest.mark.parametrize("profile", ["shareable", "customer_pack", "explainer"])
@pytest.mark.parametrize("field,value,expected", CASES)
def test_malformed_private_metadata_is_withheld(profile, field, value, expected):
    if field == "sensitive_users":
        payload = {"operator_inputs": {field: value, "partner_domains": {"count": 9}}}
        expected_payload = {"operator_inputs": {field: expected, "partner_domains": {"count": 9}}}
    else:
        payload = {field: value}
        expected_payload = {field: expected}
    payload["ordinary"] = {"count": 7, "input_count": 7}
    expected_payload["ordinary"] = {"count": 7, "input_count": 7}
    before = deepcopy(payload)
    out = redact_output(payload, profile=profile)
    assert out == expected_payload
    assert DIGEST not in json.dumps(out)
    assert payload == before
    assert redact_output(out, profile=profile) == out
    assert redact_output(payload, profile="local") is payload


@pytest.mark.parametrize("supplied", [False, True])
def test_boolean_supplied_remains_shareable(supplied):
    payload = {"operator_inputs": {"sensitive_users": {"supplied": supplied, "count": 7,
                                                       "hmac_sha256": DIGEST}}}
    assert redact_output(payload) == {"operator_inputs": {"sensitive_users": {"supplied": supplied}}}
