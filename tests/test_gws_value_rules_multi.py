"""``settings_multi`` (M13-L09): the 14 multi-field and mode-dependent GWS policies, synthetic data only.

The vectors in ``tests/fixtures/gws-value-rules/multi.jsonl`` replay through ``test_gws_value_rules_replay.py``; this
file pins the rows, the params contract, the per-row vector coverage and the unknown-is-not-safe rule (design 8.4).
Every expected value is a literal.
"""
from __future__ import annotations

import copy
import json
from collections import defaultdict
from pathlib import Path

import pytest

from azure_tenant_audit.value_rules import gws
from azure_tenant_audit.value_rules.gws import multi
from azure_tenant_audit.value_rules.gws.catalogue import catalogue

VECTORS = [json.loads(line) for line in
           (Path(__file__).parent / "fixtures" / "gws-value-rules" / "multi.jsonl").read_text().splitlines() if line]

ROWS = {
    "GWS.GMAIL.5.5v1": ("own_any_bad", "gmail"),
    "GWS.GMAIL.7.6v1": ("own_any_bad", "gmail"),
    "GWS.GMAIL.9.1v1": ("own_any_bad", "gmail"),
    "GWS.DRIVEDOCS.1.2v1": ("sharing_mode", "drive_and_docs"),
    "GWS.DRIVEDOCS.1.3v1": ("sharing_mode", "drive_and_docs"),
    "GWS.DRIVEDOCS.1.4v1": ("sharing_mode", "drive_and_docs"),
    "GWS.DRIVEDOCS.1.5v1": ("sharing_mode", "drive_and_docs"),
    "GWS.DRIVEDOCS.1.7v1": ("sharing_mode", "drive_and_docs"),
    "GWS.DRIVEDOCS.3.1v1": ("effective_any_bad", "drive_and_docs"),
    "GWS.DRIVEDOCS.5.1v1": ("effective_all_bad", "drive_and_docs"),
    "GWS.GROUPS.4.1v1": ("own_any_bad", "groups_for_business"),
    "GWS.CHAT.4.1v1": ("effective_all_bad", "chat"),
    "GWS.COMMONCONTROLS.11.1v1": ("effective_any_bad", None),
    "GWS.COMMONCONTROLS.12.1v1": ("own_any_bad", None),
}
# Rows whose fields all have a pinned default, so the top unit can never lack a value.
DEFAULTED = {"GWS.DRIVEDOCS.1.2v1", "GWS.DRIVEDOCS.1.3v1", "GWS.DRIVEDOCS.1.4v1", "GWS.DRIVEDOCS.1.5v1",
             "GWS.DRIVEDOCS.1.7v1", "GWS.GROUPS.4.1v1", "GWS.CHAT.4.1v1", "GWS.COMMONCONTROLS.11.1v1"}
TENANT = {"as_of": "2026-11-25T12:00:00Z", "top_unit": "ou:root", "org_units": {"ou:root": None, "ou:a": "ou:root"},
          "complete": True}


def _rows() -> dict[str, dict]:
    return {pid: row for pid, row in catalogue()["policies"].items() if row["kind"] == "settings_multi"}


def test_the_fourteen_rows_and_their_sub_kinds():
    rows = _rows()
    assert sorted(rows) == sorted(ROWS)
    for policy_id, row in rows.items():
        assert row["sections"] == ["gws_tenant", "gws_policies"]
        assert (row["params"]["kind"], row["params"]["service"]) == ROWS[policy_id]
    assert multi.KINDS == {"settings_multi": multi.settings_multi}
    assert gws._registry()["settings_multi"] is multi.settings_multi


def test_every_shipped_row_has_valid_params():
    for row in _rows().values():
        multi._params(row["params"])


def test_drive_rows_branch_on_the_documented_modes():
    for policy_id in ("GWS.DRIVEDOCS.1.2v1", "GWS.DRIVEDOCS.1.3v1", "GWS.DRIVEDOCS.1.4v1", "GWS.DRIVEDOCS.1.5v1",
                      "GWS.DRIVEDOCS.1.7v1"):
        params = _rows()[policy_id]["params"]
        assert params["mode"] == {"section": "drive_and_docs_external_sharing", "field": "externalSharingMode",
                                  "values": ["ALLOWED", "ALLOWLISTED_DOMAINS", "DISALLOWED"]}
    branches = {policy_id: sorted((check["mode"], check["field"], check["scope"])
                                  for check in _rows()[policy_id]["params"]["checks"])
                for policy_id in ("GWS.DRIVEDOCS.1.2v1", "GWS.DRIVEDOCS.1.5v1")}
    assert branches == {
        "GWS.DRIVEDOCS.1.2v1": [("ALLOWLISTED_DOMAINS", "allowReceivingFilesOutsideAllowlistedDomains", "effective"),
                                ("DISALLOWED", "allowReceivingExternalFiles", "own")],
        "GWS.DRIVEDOCS.1.5v1": [("ALLOWED", "allowPublishingFiles", "effective"),
                                ("ALLOWLISTED_DOMAINS", "allowPublishingFiles", "effective")]}


def test_takeout_reads_the_status_and_the_nine_app_sections():
    sections = [check["section"] for check in _rows()["GWS.COMMONCONTROLS.12.1v1"]["params"]["checks"]]
    assert sections == ["takeout_service_status", "blogger_user_takeout", "books_user_takeout",
                        "location_history_user_takeout", "maps_user_takeout", "pay_user_takeout",
                        "photos_user_takeout", "play_user_takeout", "play_console_user_takeout",
                        "youtube_user_takeout"]


GOOD = {"kind": "effective_any_bad", "service": None, "checks": [
    {"section": "drive_and_docs_file_security_update", "field": "allowUsersToManageUpdate", "good": [False]}]}


@pytest.mark.parametrize("change", [
    lambda p: p.update(kind="setting"),
    lambda p: p.pop("service"),
    lambda p: p.update(service=""),
    lambda p: p.update(service="nosuchservice"),
    lambda p: p.update(checks=[]),
    lambda p: p.update(extra=1),
    lambda p: p.update(required="any"),  # only own_any_bad takes it
    lambda p: p["checks"][0].update(field="noSuchField"),
    lambda p: p["checks"][0].update(section="no_such_section"),
    lambda p: p["checks"][0].update(good=[]),
    lambda p: p["checks"][0].update(good=["false"]),
    lambda p: p["checks"][0].update(values=["A"]),  # a bool field has no value list
    lambda p: p["checks"][0].update(mode="ALLOWED"),  # only sharing_mode checks carry a mode
    lambda p: p["checks"].append(copy.deepcopy(p["checks"][0])),
    lambda p: p["checks"].append({"section": "drive_and_docs_file_security_update", "field": "securityUpdate",
                                  "good": ["APPLY_TO_IMPACTED_FILES"]}),  # an enum needs its value list
    lambda p: p["checks"].append({"section": "drive_and_docs_file_security_update", "field": "securityUpdate",
                                  "good": ["OTHER"], "values": ["APPLY_TO_IMPACTED_FILES"]}),
    lambda p: p.update(kind="own_any_bad"),  # without ``required``
    lambda p: p.update(kind="sharing_mode"),  # without ``mode``
])
def test_malformed_params_are_refused(change):
    params = copy.deepcopy(GOOD)
    multi._params(params)
    change(params)
    with pytest.raises(ValueError):
        multi._params(params)


def test_every_row_has_the_lane_vector_set():
    cells = defaultdict(set)
    for vector in VECTORS:
        cells[vector["policy"]].add(vector["cell"])
    for policy_id, (_, service) in ROWS.items():
        need = {"no_unit_violates", "unit_violates", "section_not_collected", "policy_read_incomplete",
                "section_shape_unusable", "setting_value_unusable"}
        if service:
            need |= {"service_off_everywhere", "service_status_absent"}
        if policy_id not in DEFAULTED:
            need.add("setting_absent")
        assert need <= cells[policy_id], (policy_id, sorted(need - cells[policy_id]))


def test_the_kind_specific_cases_are_present():
    notes = {vector["vector_id"] for vector in VECTORS}
    assert {"multi-gmail55-group", "multi-gmail55-sub-ou", "multi-gmail55-bad-wins", "multi-gmail91-merge",
            "multi-drive12-sub-mode-from-top", "multi-drive12-sub-field-from-top", "multi-drive13-other-branch",
            "multi-drive13-sub-wrong-branch", "multi-drive51-sub-effective", "multi-chat41-sub-effective",
            "multi-groups41-other-field", "multi-cc121-status-absent", "multi-gmail91-tie"} <= notes
    assert {vector["divergence"] for vector in VECTORS if "divergence" in vector} == {"D3", "D11", "D12"}


@pytest.mark.parametrize("vector", VECTORS, ids=[vector["vector_id"] for vector in VECTORS])
def test_read_order_never_changes_the_answer(vector):
    sections = copy.deepcopy(vector["sections"])
    policies = sections.get("gws_policies", {}).get("policies")
    if not isinstance(policies, list):
        pytest.skip("no policy list to reorder")
    policies.reverse()
    record = gws.assess(vector["policy"], sections)
    assert (record["verdict"], record["cell"]) == (vector["verdict"], vector["cell"])


def _assess(policy_id: str, policies: list) -> dict:
    return gws.assess(policy_id, {"gws_tenant": TENANT, "gws_policies": {"complete": True, "policies": policies}})


@pytest.mark.parametrize("policy_id", sorted(ROWS))
@pytest.mark.parametrize("junk", [None, "", 0, "true", [], {}, 1.5])
def test_junk_values_never_answer_met(policy_id, junk):
    """Unknown is not safe: every participating field at junk, at the top unit and in a sub-unit."""
    row = _rows()[policy_id]
    params = row["params"]
    checks = params["checks"] + ([params["mode"]] if "mode" in params else [])
    values: dict[str, dict] = defaultdict(dict)
    for check in checks:
        values[check["section"]][check["field"]] = junk
    status = [{"unit": "ou:root", "unit_kind": "org_unit", "section": f"{params['service']}_service_status",
               "sort_order": 1, "value": {"serviceState": "ENABLED"}}] if params["service"] else []
    for unit in ("ou:root", "ou:a"):
        policies = status + [{"unit": unit, "unit_kind": "org_unit", "section": section, "sort_order": 1,
                              "value": dict(fields)} for section, fields in values.items()]
        record = _assess(policy_id, policies)
        # In a sub-unit a defaulted top unit may still violate on its own (DRIVEDOCS 1.4); it never answers met.
        assert record["verdict"] != "met", (unit, record["cell"])
        if unit == "ou:root":
            assert record["cell"] == "setting_value_unusable"


@pytest.mark.parametrize("policy_id", sorted(ROWS))
def test_answers_carry_only_constant_texts(policy_id):
    texts = {(vector["cell"], gws.assess(vector["policy"], copy.deepcopy(vector["sections"]))["reason_text"])
             for vector in VECTORS if vector["policy"] == policy_id}
    for _, text in texts:
        assert "ou:" not in text and "group:" not in text and "example." not in text
    assert len({cell for cell, _ in texts}) == len(texts)


def test_a_non_mapping_unit_section_is_unusable_not_absent():
    status = {"unit": "ou:root", "unit_kind": "org_unit", "section": "drive_and_docs_service_status",
              "sort_order": 1, "value": {"serviceState": "ENABLED"}}
    good = {"unit": "ou:root", "unit_kind": "org_unit", "section": "drive_and_docs_file_security_update",
            "sort_order": 1, "value": {"allowUsersToManageUpdate": False, "securityUpdate": "APPLY_TO_IMPACTED_FILES"}}
    tied = [{"unit": "ou:a", "unit_kind": "org_unit", "section": "drive_and_docs_file_security_update",
             "sort_order": 1, "value": {"allowUsersToManageUpdate": flag}} for flag in (True, False)]
    record = _assess("GWS.DRIVEDOCS.3.1v1", [status, good, *tied])
    assert record["cell"] == "setting_value_unusable"
