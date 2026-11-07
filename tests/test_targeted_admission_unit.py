"""Unit truth for the SS 2.1 typed inline admission validator (``collectors.anti_phish_admission``).

Pure-module tests: envelope key/type/count/chunk matrix, explicit failure envelopes, recursive row health in exact
parity with the projection's ``_healthy`` (the projection is the test oracle only; the module never imports it), the
target-value exemption and its near neighbours, typed row status as data, bounds and data-free behaviour. The main
flow stays unwired until root hooks ``sanitise_response`` and the adapter's callback acceptance.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import logging
from pathlib import Path

import pytest

from azure_tenant_audit.collectors import anti_phish_admission as adm
from azure_tenant_audit.collectors import targeted_users_coverage as tuc

ADMITTED, FAILED, REFUSED = adm.ADMITTED, adm.FAILED, adm.REFUSED
TARGET = adm.TARGET_KEY
ROW = {"Identity": "Default", "Name": "Default", "IsDefault": True, "Enabled": True,
       "EnableTargetedUserProtection": True, "TargetedUserProtectionAction": "Quarantine",
       TARGET: ["alice@example.invalid", "Bob;bob@example.invalid"],
       "TargetedDomainsToProtect": ["partner.example.invalid"], "EnableViaTag": True}
CHUNK = "raw/exchange_policy/antiPhishPolicies/part-0001.jsonl"
FLAGS = ("collection_truncated", "bounded_sample", "incomplete", "partial", "collection_limit_reached")


def _env(extra=None, rows=None):
    # No deepcopy: the validator never mutates (asserted below) and deep chains would exhaust deepcopy's stack.
    return {"status": "ok", "value": list([ROW] if rows is None else rows), **(extra or {})}


def _code(response, **kwargs):
    result = adm.admit_response(response, **kwargs)
    assert result in adm.CODES and result in (ADMITTED, FAILED, REFUSED)
    return result


def _chain(levels, leaf):
    value = leaf
    for _ in range(levels):
        value = {"x": value}
    return value


def _list_chain(levels, leaf):
    value = leaf
    for _ in range(levels):
        value = [value]
    return value


class Hostile:
    """Raises from every protocol method; the validator must never call into it."""

    def _boom(self, *args, **kwargs):
        raise RuntimeError("hostile canary zq-adm-hostile@unlisted.invalid")

    __bool__ = __eq__ = __ne__ = __hash__ = __len__ = __iter__ = __repr__ = __str__ = __float__ = __int__ = _boom
    __lt__ = __gt__ = __le__ = __ge__ = __getitem__ = __contains__ = _boom


class Mapping(dict):
    pass


# ---------------------------------------------------------------------------------------------------------------
# Envelope keys, exact types, counts and chunks.

ACCEPT = [
    ("command", "Get-AntiPhishPolicy | Select-Object Identity"), ("command", ""),
    ("status", "ok"), ("status", "success"), ("status", "collected"), ("status", "complete"),
    ("collection_status", "collected"), ("read_state", "collected"), ("complete", True),
    ("error", None), ("error_class", None), ("reason", None), ("reason", "offline_bundle"), ("state", None),
    ("truncation_reason", None), ("resolver_error", None), ("@odata.nextLink", None),
    *[(key, value) for key in FLAGS for value in (False, None)],
    ("sample_truncated", False), ("licence_inferred", True), ("licence_inferred", False),
    ("return_code", 0), ("duration_ms", 0), ("duration_ms", 12), ("duration_ms", 12.5),
    ("stdout_bytes", 0), ("stdout_bytes", 10), ("stderr_bytes", 0), ("stderr_bytes", 3), ("result_limit", 2),
    ("item_count", 1), ("stdout", "WARNING: ordinary"), ("stderr", ""), ("message", None), ("message", "ok"),
    ("stdout_sample", "x"), ("stderr_sample", None),
]
REFUSE = [
    ("command", 7), ("command", None), ("command", ["x"]),
    ("status", "error"), ("status", "partial"), ("status", "failed"), ("status", "OK"), ("status", ""),
    ("status", 1), ("status", None), ("status", True),
    ("collection_status", "partial"), ("collection_status", None), ("read_state", "failed"), ("read_state", True),
    ("complete", False), ("complete", 1), ("complete", "true"), ("complete", None),
    ("error", ""), ("error", False), ("error", 0), ("error", []), ("error_class", ""), ("error_class", {}),
    ("reason", "rate_limit"), ("reason", ""), ("reason", 1), ("state", "over_limit"), ("state", ""),
    ("truncation_reason", ""), ("truncation_reason", False), ("truncation_reason", "operator_limit"),
    ("resolver_error", ""), ("resolver_error", False), ("resolver_error", "x"),
    ("@odata.nextLink", ""), ("@odata.nextLink", "https://graph.invalid/next"),
    *[(key, value) for key in FLAGS for value in (True, 0, 1, "", "false", [], {})],
    ("sample_truncated", True), ("sample_truncated", None), ("sample_truncated", 0), ("sample_truncated", 1),
    ("sample_truncated", "false"), ("sample_truncated", ""),
    ("licence_inferred", None), ("licence_inferred", 0), ("licence_inferred", "no"),
    ("return_code", 1), ("return_code", -1), ("return_code", False), ("return_code", "0"), ("return_code", 0.0),
    ("duration_ms", -1), ("duration_ms", float("nan")), ("duration_ms", float("inf")), ("duration_ms", True),
    ("duration_ms", "1"), ("stdout_bytes", -1), ("stdout_bytes", True), ("stdout_bytes", 1.0),
    ("stderr_bytes", None), ("result_limit", 0), ("result_limit", 1), ("result_limit", True), ("result_limit", "5"),
    ("item_count", True), ("item_count", False), ("item_count", "1"), ("item_count", None), ("item_count", 1.0),
    ("item_count", 0), ("item_count", 2), ("item_count", -1),
    ("chunk_files", []), ("chunk_files", [CHUNK]), ("chunk_files", None), ("chunk_count", 0), ("chunk_count", 1),
    ("chunk_count", None),
    ("nextPageToken", "x"), ("has_more", False), ("warning", ""), ("warnings", []), ("exception", "x"),
    ("traceback", None), ("details", {}), ("details", "x"), ("stdout", ["x"]), ("stderr", 1),
    ("message", {"complete": False}), ("stdout_sample", False), ("@odata.context", "x"), ("@odata.count", 1), ("Value", []),
    ("value ", []), (TARGET, []), ("targeted_users_to_protect", None), ("TargetedUsersCoverage", {}),
]


@pytest.mark.parametrize(("key", "value"), ACCEPT, ids=[f"{k}-{i}" for i, (k, _v) in enumerate(ACCEPT)])
def test_supported_envelope_key_types_are_admitted(key, value):
    assert _code(_env({key: value})) is ADMITTED
    assert adm.is_admitted(_env({key: value})) is True


@pytest.mark.parametrize(("key", "value"), REFUSE, ids=[f"{k}-{i}" for i, (k, _v) in enumerate(REFUSE)])
def test_unsupported_envelope_key_or_type_is_refused(key, value):
    assert _code(_env({key: value})) is REFUSED
    assert adm.is_admitted(_env({key: value})) is False


def test_success_keys_cover_the_boundary_vocabulary_plus_the_scan_flag():
    assert tuc._ENVELOPE_KEYS <= adm.SUCCESS_KEYS
    assert adm.SUCCESS_KEYS - tuc._ENVELOPE_KEYS == {"sample_truncated", *adm.DIAGNOSTIC_TEXT}
    assert set(adm.DIAGNOSTIC_TEXT) <= tuc._COMPONENT_KEYS
    assert not {"chunk_files", "chunk_count"} & adm.SUCCESS_KEYS


def test_full_supported_envelope_and_exact_counts_are_admitted():
    full = {"command": "c", "status": "ok", "sample_truncated": False, "complete": True,
            "collection_status": "collected", "read_state": "collected", "return_code": 0, "duration_ms": 1.5,
            "stdout_bytes": 9, "stderr_bytes": 0, "result_limit": 1000, "licence_inferred": False,
            **{flag: False for flag in FLAGS}, "truncation_reason": None, "resolver_error": None,
            "@odata.nextLink": None, "error": None, "error_class": None, "reason": None, "state": None}
    assert _code(_env({**full, "item_count": 1})) is ADMITTED
    assert _code(_env({"item_count": 3}, rows=[ROW, ROW, ROW])) is ADMITTED
    assert _code(_env({"item_count": 0}, rows=[])) is ADMITTED
    assert _code(_env({"item_count": 2}, rows=[ROW, ROW, ROW])) is REFUSED
    assert _code(_env({"result_limit": 3}, rows=[ROW, ROW, ROW])) is REFUSED


@pytest.mark.parametrize("response", [
    {"value": []}, {"command": "c", "value": []}, {"read_state": "collected", "value": []}, {"status": "ok"},
    {"status": "ok", "value": None}, {"status": "ok", "value": {}}, {"status": "ok", "value": "x"},
    {"status": "ok", "value": (ROW,)}, {"status": "ok", "value": [ROW, "row"]}, {"status": "ok", "value": [None]},
    {"status": "ok", "value": [[ROW]]}, {"status": "ok", "value": [Mapping(ROW)]}, {}, [], [ROW], None, "x", 1,
    (ROW,), Mapping(_env()), Hostile(),
], ids=lambda value: type(value).__name__)
def test_non_inline_or_non_row_shapes_are_refused(response):
    assert _code(response) is REFUSED


def test_empty_reads_need_a_health_statement():
    assert _code({"status": "ok", "value": []}) is ADMITTED
    assert _code({"complete": True, "value": []}) is ADMITTED
    assert _code({"collection_status": "collected", "value": []}) is ADMITTED
    assert _code({"value": []}) is REFUSED


@pytest.mark.parametrize("marker", ["error", "error_class"])
@pytest.mark.parametrize("value", ["command_timeout", "x", 1, True, ["x"], {"m": 1}, float("nan"), Hostile()],
                         ids=lambda value: type(value).__name__)
def test_explicit_failure_envelopes_stay_failed_whatever_else_they_carry(marker, value):
    assert _code({marker: value}) is FAILED
    assert _code(_env({marker: value})) is FAILED
    assert _code(_env({marker: value, "chunk_files": [CHUNK], "sample_truncated": True, "unknown": 1},
                      rows=[{**ROW, "incomplete": True}])) is FAILED
    assert adm.is_admitted(_env({marker: value})) is False


# ---------------------------------------------------------------------------------------------------------------
# Row health: exact parity with the projection's recursive refusal, outside the target value.

MARKERS = ("error", "error_class", "resolver_error", "collection_truncated", "bounded_sample", "@odata.nextLink",
           "truncation_reason", "incomplete", "partial", "complete", "read_state", "collection_status", "status")
VALUES = (True, False, None, 0, 1, 0.0, 2.5, "", "x", "collected", "failed", "ok", "Provisioned", [], [0], {},
          {"a": None})
PLACES = {
    "row": lambda m: {**ROW, **m},
    "nested": lambda m: {**ROW, "Extra": m},
    "list": lambda m: {**ROW, "Extra": [1, "a", m]},
    "deep": lambda m: {**ROW, "Extra": _chain(10, [m])},
    "retained-field": lambda m: {**ROW, "TargetedDomainsToProtect": ["partner.example.invalid", m]},
    "neighbour-case": lambda m: {**ROW, "targetedUsersToProtect": [m]},
    "neighbour-upper": lambda m: {**ROW, "TARGETEDUSERSTOPROTECT": [m]},
    "neighbour-separated": lambda m: {**ROW, "Targeted_Users_To_Protect": [m]},
    "neighbour-trailing-space": lambda m: {**ROW, TARGET + " ": [m]},
    "neighbour-nested": lambda m: {**ROW, "Extra": {TARGET: [m]}},
    "neighbour-in-list": lambda m: {**ROW, "Extra": [{TARGET: [m]}]},
    "supplied-summary": lambda m: {**ROW, "TargetedUsersCoverage": m},
}


def _projection_refuses(row):
    from auditex.scuba_projection import _healthy

    try:
        _healthy(row, metadata=False)
    except Exception:  # noqa: BLE001 - any refusal of the oracle
        return True
    return False


@pytest.mark.parametrize("place", sorted(PLACES))
@pytest.mark.parametrize("marker", MARKERS)
def test_row_health_matches_the_projection_outside_the_target_value(place, marker):
    for value in VALUES:
        row = PLACES[place]({marker: deepcopy(value)})
        expected = REFUSED if _projection_refuses(row) else ADMITTED
        assert _code(_env(rows=[ROW, row])) is expected, (place, marker, value)
        assert _code(_env(rows=[row]), target_key=None) is expected, (place, marker, value)


def test_typed_row_status_is_data_and_harmless_extra_fields_are_admitted():
    for status in ("Provisioned", "Failed", "error", "partial", 5, None, True, [], {"x": "failed"}):
        row = {**ROW, "status": status, "Nested": {"status": status, "items": [{"status": status}]}}
        assert _code(_env(rows=[row])) is ADMITTED, status
    extra = {**ROW, "UnselectedExtra": "ordinary", "WhenChanged": "2026-11-01T00:00:00Z", "Count": 3, "Ratio": 0.5,
             "Flags": [True, False, None], "Nested": {"complete": True, "read_state": "collected",
                                                      "collection_status": "collected", "deeper": [{"a": [1, {}]}]}}
    assert _code(_env(rows=[extra])) is ADMITTED


MALFORMED_TARGETS = {
    "member-complete-false": [{"complete": False}],
    "member-markers": ["alice@example.invalid", {"error": "x", "read_state": "failed", "incomplete": True}],
    "nested-list": [[{"partial": True}]],
    "object": {"incomplete": True},
    "deep": _chain(500, {"error": "x"}),
    "deep-list": _list_chain(500, {"collection_status": "partial"}),
    "non-finite": [float("nan"), float("inf")],
    "non-json": [object(), b"bytes", {1, 2}],
    "tuple": ("alice@example.invalid",),
    "hostile": [Hostile()],
    "scalar": "alice@example.invalid",
    "null": None,
}


@pytest.mark.parametrize("case", sorted(MALFORMED_TARGETS))
def test_actual_target_value_is_never_walked(case):
    row = {**ROW, TARGET: MALFORMED_TARGETS[case]}
    assert _code(_env(rows=[row])) is ADMITTED, "a malformed target entry only makes coverage unusable"
    if case not in ("scalar", "null"):
        assert _code(_env(rows=[row]), target_key=None) is REFUSED, "walked when no key is exempt"


def test_exemption_is_the_exact_top_level_row_key_only():
    marker = [{"complete": False}]
    for row in ({**ROW, "Extra": {TARGET: marker}}, {**ROW, "Extra": [{TARGET: marker}]},
                {**ROW, "targetedUsersToProtect": marker}, {**ROW, TARGET.upper(): marker},
                {**ROW, "Targeted Users To Protect": marker}, {**ROW, TARGET + " ": marker}):
        assert _code(_env(rows=[row])) is REFUSED, sorted(row)
    assert _code(_env({TARGET: marker})) is REFUSED, "an envelope-level target key is unknown metadata"
    assert _code(_env(rows=[{**ROW, "Custom": marker}]), target_key="Custom") is ADMITTED


# ---------------------------------------------------------------------------------------------------------------
# Bounds and data-free behaviour.


def test_depth_bound_counts_container_levels_from_the_envelope():
    assert _code(_env(rows=[{**ROW, "Extra": _chain(61, 1)}])) is ADMITTED  # innermost mapping at level 64
    assert _code(_env(rows=[{**ROW, "Extra": _chain(62, 1)}])) is REFUSED
    assert _code(_env(rows=[{**ROW, "Extra": _list_chain(61, 1)}])) is ADMITTED
    assert _code(_env(rows=[{**ROW, "Extra": _list_chain(62, 1)}])) is REFUSED
    assert _code(_env(rows=[{**ROW, "Extra": _chain(5000, 1)}])) is REFUSED, "no recursion limit is reached"


def test_node_bound_refuses_and_wide_reads_stay_linear(monkeypatch):
    assert _code(_env(rows=[{**ROW, "Extra": list(range(200_000))}])) is ADMITTED
    monkeypatch.setattr(adm, "MAX_NODES", 50)
    assert _code(_env()) is ADMITTED
    assert _code(_env(rows=[{**ROW, "Extra": list(range(100))}])) is REFUSED
    assert _code(_env(rows=[ROW] * 51)) is REFUSED
    assert _code(_env(rows=[{**ROW, TARGET: list(range(10_000))}])) is ADMITTED, "the target value is not counted"


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), (1,), {1}, b"x", object(), 1j,
                                   Hostile(), Mapping(a=1)], ids=lambda value: type(value).__name__)
def test_non_json_row_values_are_refused_without_calling_them(value):
    assert _code(_env(rows=[{**ROW, "Extra": value}])) is REFUSED
    assert _code(_env(rows=[{**ROW, "Extra": [value]}])) is REFUSED
    assert _code(_env({"status": value})) is REFUSED


def test_non_text_keys_are_refused():
    assert _code(_env(rows=[{**ROW, 1: "x"}])) is REFUSED
    assert _code(_env(rows=[{**ROW, "Extra": {None: 1}}])) is REFUSED
    assert _code({**_env(), 1: "x"}) is REFUSED


def test_input_is_never_mutated_and_nothing_is_logged(caplog):
    cases = [_env(), _env({"sample_truncated": True}), _env(rows=[{**ROW, "Extra": [{"complete": False}]}]),
             _env({"error": "failed for zq-adm@unlisted.invalid"}), _env(rows=[{**ROW, TARGET: [{"error": "x"}]}])]
    with caplog.at_level(logging.DEBUG):
        for response in cases:
            before = deepcopy(response)
            adm.admit_response(response)
            adm.scan_admitted(response)
            assert response == before
    assert caplog.records == []


def test_module_is_pure_engine_code():
    tree = ast.parse(Path(adm.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add("." * node.level + (node.module or ""))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"print", "repr", "str", "format", "open", "eval", "exec"}, node.func.id
    assert imported == {"__future__", "math"}


# ---------------------------------------------------------------------------------------------------------------
# Scan/count/chunk part alone, for every reduced operation envelope.

SCAN_TRUE = [{"value": []}, {"status": "ok"}, {"value": [1], "item_count": 1}, {"value": [], "sample_truncated": False},
             {"value": [1, 2], "item_count": 2, "sample_truncated": False}, {"error": "x", "value": [], "item_count": 0}]
SCAN_FALSE = [[], None, "x", Hostile(), Mapping(value=[]), {"chunk_files": []}, {"chunk_files": [CHUNK], "value": []},
              {"chunk_count": 0}, {"chunk_count": 1, "value": []}, {"value": [], "sample_truncated": True},
              {"value": [], "sample_truncated": None}, {"value": [], "sample_truncated": 0},
              {"value": [], "sample_truncated": "false"}, {"value": [1], "item_count": True},
              {"value": [1], "item_count": "1"}, {"value": [1], "item_count": None}, {"value": [1], "item_count": 1.0},
              {"value": [1], "item_count": 2}, {"item_count": 0}, {"sample_truncated": False},
              {"value": {"a": 1}, "item_count": 1}]


@pytest.mark.parametrize("envelope", SCAN_TRUE, ids=[str(i) for i in range(len(SCAN_TRUE))])
def test_scan_admitted_accepts_supported_inline_metadata(envelope):
    assert adm.scan_admitted(envelope) is True


@pytest.mark.parametrize("envelope", SCAN_FALSE, ids=[str(i) for i in range(len(SCAN_FALSE))])
def test_scan_admitted_refuses_scan_count_and_chunk_metadata(envelope):
    assert adm.scan_admitted(envelope) is False
