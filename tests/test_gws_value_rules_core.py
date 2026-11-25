"""GWS value-rule engine core (design M13 sections 5.1, 5.3, 8.1, 8.2): loader, registry, gate, reducers, manual kind.

Synthetic data only; every expected value is a literal. Loader and dispatch cases run on a controlled catalogue (the
shipped main file with empty fragments), so a later lane adding valid kinds and rows to a fragment never breaks them.
"""
from __future__ import annotations

import json
import traceback
from pathlib import Path

import pytest

from azure_tenant_audit import value_rules
from azure_tenant_audit.value_rules import gws
from azure_tenant_audit.value_rules.gws import catalogue as gws_catalogue
from azure_tenant_audit.value_rules.gws import reduce as R
from azure_tenant_audit.value_rules.gws.record import checked_gws, rule_failure_gws
from azure_tenant_audit.value_rules.record import UNDECIDABLE_CODES, evidence_kind

ROOT = Path(__file__).resolve().parents[1]
MAIN = "configs/scuba-gws-value-rules.json"
FRAGMENT = "configs/scuba-gws-rules-setting-core.json"
MANUAL_IDS = {
    "GWS.CALENDAR.3.2v1", "GWS.COMMONCONTROLS.8.3v1", "GWS.COMMONCONTROLS.9.1v1", "GWS.COMMONCONTROLS.9.2v1",
    "GWS.COMMONCONTROLS.14.1v1", "GWS.COMMONCONTROLS.14.2v1", "GWS.COMMONCONTROLS.16.3v1",
    "GWS.COMMONCONTROLS.16.4v1", "GWS.COMMONCONTROLS.18.1v1", "GWS.COMMONCONTROLS.18.2v1", "GWS.DRIVEDOCS.1.10v1",
    "GWS.DRIVEDOCS.1.11v1", "GWS.DRIVEDOCS.5.2v1", "GWS.GEMINI.3.1v1", "GWS.GEMINI.3.2v1", "GWS.GEMINI.4.1v1",
    "GWS.MEET.6.3v1"}
MANUAL_TEXT = ("Data unavailable: no read-only Google Workspace API exposes this setting; check it by hand in the "
               "Admin console against the baseline text.")


FRAGMENTS = [f"configs/scuba-gws-rules-{name}.json" for name in (
    "setting-core", "setting-collab", "multi", "identity", "lists", "events", "dns")]
UNIMPLEMENTED = "GWS.GMAIL.1.1v1"  # no row in the controlled catalogue


def _files() -> dict[str, dict]:
    """The controlled catalogue: the shipped main file and an empty stub for every fragment."""
    files = {path: {"kinds": {}, "policies": {}} for path in FRAGMENTS}
    files[MAIN] = json.loads((ROOT / MAIN).read_text(encoding="utf-8"))
    return files


def _sem(files: dict, section: str) -> dict:
    return next(entry for entry in files[MAIN]["section_semantics"] if entry["section"] == section)


def _field(files: dict, section: str, name: str) -> dict:
    return next(field for field in _sem(files, section)["fields"] if field["name"] == name)


@pytest.fixture
def controlled(monkeypatch):
    data = _load(_files())
    monkeypatch.setattr(gws_catalogue, "catalogue", lambda: data)
    return data


def _load(files: dict[str, dict]) -> dict:
    return gws_catalogue._load(lambda path: json.dumps(files[path]))


def _gated_kind() -> dict:
    return {"cells": {
        "section_not_collected": {
            "evidence_kind": None, "verdict": "not_assessed", "reason_code": "required_evidence_section_not_collected",
            "limitations": ["required_evidence_section_not_collected",
                            "required_evidence_section_not_collected:<section>"],
            "recommendations": ["collect_missing_evidence_section"]},
        "no_unit_violates": {"verdict": "met", "reason_code": "no_unit_violates",
                             "reason_texts": ["Requirement met: no unit violates the setting."]}}}


def _with_gated(files: dict) -> dict:
    files[FRAGMENT] = {"kinds": {"test_gate": _gated_kind()}, "policies": {"GWS.GMAIL.1.1v1": {
        "kind": "test_gate", "rule_id": "GWS.GMAIL.1.1v1.test_gate", "sections": ["gws_tenant", "gws_policies"],
        "params": {}}}}
    return files


# --- loader ---------------------------------------------------------------------------------------------------------

def test_shipped_catalogue_loads_with_pins():
    data = gws_catalogue.catalogue()
    assert data["scubagoggles_version"] == "v1.1.0"
    assert data["scubagoggles_commit"] == "08a08ce145178582284d81ab1f3625987f3ad66b"
    assert len(data["policy_ids"]) == 138
    assert "manual_only" in data["kinds"]
    assert {pid for pid, row in data["policies"].items() if row["kind"] == "manual_only"} == MANUAL_IDS
    assert set(data["policies"]) <= set(data["policy_ids"])


def test_controlled_catalogue_is_the_manual_subset():
    data = _load(_files())
    assert set(data["kinds"]) == {"manual_only"}
    assert set(data["policies"]) == MANUAL_IDS


def test_shipped_fragments_have_the_fragment_shape():
    for path in FRAGMENTS:
        assert set(json.loads((ROOT / path).read_text(encoding="utf-8"))) == {"kinds", "policies"}


def test_gws_configs_keep_section_and_setting_names_out_of_mapping_keys():
    # Review B1: a Google section or setting name (``securityUpdate``, ``region``) as a config key would become a
    # product field name the shareable redaction keeps when a person or group has that name.
    names = {entry["section"] for entry in _files()[MAIN]["section_semantics"]}
    names |= {field["name"] for entry in _files()[MAIN]["section_semantics"] for field in entry["fields"]}
    assert {"drive_and_docs_file_security_update", "securityUpdate", "region", "serviceState"} <= names
    keys: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            keys.update(node)
            for item in node.values():
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)
    for path in [MAIN, *FRAGMENTS]:
        walk(json.loads((ROOT / path).read_text(encoding="utf-8")))
    assert sorted(keys & names) == []


def _mutate(target, fn):
    files = _files()
    fn(files)
    with pytest.raises(ValueError, match=target):
        _load(files)


@pytest.mark.parametrize("change, message", [
    (lambda f: f[MAIN].update(scubagoggles_version="v1.0.0"), "Invalid GWS value-rule catalogue"),
    (lambda f: f[MAIN].update(scubagoggles_commit="08a08ce1"), "Invalid GWS value-rule catalogue"),
    (lambda f: f[MAIN].update(schema_version=2), "Invalid GWS value-rule catalogue"),
    (lambda f: f[MAIN].update(extra=1), "Invalid GWS value-rule catalogue"),
    (lambda f: f[MAIN]["shared_reasons"]["rule_not_implemented"].update(reason_text="x"),
     "Invalid GWS value-rule shared reasons"),
    (lambda f: f[MAIN]["policy_ids"].pop(), "Invalid GWS value-rule policy ids"),
    (lambda f: f[MAIN]["policy_ids"].append("GWS.GMAIL.99.1v1"), "Invalid GWS value-rule policy ids"),
    (lambda f: f[MAIN]["fragment_files"].pop(), "Invalid GWS value-rule fragments"),
    (lambda f: f[FRAGMENT].update(extra={}), "Invalid GWS value-rule fragment"),
    (lambda f: f[MAIN]["policies"].update({"MS.AAD.1.1v1": dict(f[MAIN]["policies"]["GWS.MEET.6.3v1"],
                                                                rule_id="MS.AAD.1.1v1.manual_only")}),
     "Invalid GWS value-rule policy"),
    (lambda f: f[MAIN]["policies"].update({"GWS.GMAIL.99.1v1": dict(f[MAIN]["policies"]["GWS.MEET.6.3v1"],
                                                                    rule_id="GWS.GMAIL.99.1v1.manual_only")}),
     "Invalid GWS value-rule policy"),
    (lambda f: f[FRAGMENT]["policies"].update({"GWS.MEET.6.3v1": f[MAIN]["policies"]["GWS.MEET.6.3v1"]}),
     "GWS value-rule policy is defined twice"),
    (lambda f: f[FRAGMENT]["kinds"].update({"manual_only": f[MAIN]["kinds"]["manual_only"]}),
     "GWS value-rule kind is defined twice"),
    (lambda f: f[MAIN]["policies"]["GWS.MEET.6.3v1"].update(kind="setting", rule_id="GWS.MEET.6.3v1.setting"),
     "Invalid GWS value-rule policy"),
    (lambda f: f[MAIN]["policies"]["GWS.MEET.6.3v1"].update(rule_id="GWS.MEET.6.3v1.manual"),
     "Invalid GWS value-rule policy"),
    (lambda f: f[MAIN]["policies"]["GWS.MEET.6.3v1"].update(cells={}), "Invalid GWS value-rule policy"),
    (lambda f: f[MAIN]["policies"]["GWS.MEET.6.3v1"].update(params=None), "Invalid GWS value-rule policy"),
    (lambda f: f[MAIN]["policies"]["GWS.MEET.6.3v1"].update(sections=["conditional_access_policies"]),
     "Invalid GWS value-rule sections"),
    (lambda f: f[MAIN]["policies"]["GWS.MEET.6.3v1"].update(sections=[]), "Invalid GWS value-rule sections"),
    (lambda f: f[MAIN]["policies"]["GWS.MEET.6.3v1"].update(sections=["gws_tenant", "gws_tenant"]),
     "Invalid GWS value-rule sections"),
    (lambda f: f[MAIN]["kinds"]["manual_only"]["cells"]["manual_check"].update(reason_texts=["x" * 401]),
     "Incomplete GWS value-rule cell"),
    (lambda f: f[MAIN]["kinds"]["manual_only"]["cells"]["manual_check"].update(reason_texts=["b", "a"]),
     "Incomplete GWS value-rule cell"),
    (lambda f: f[MAIN]["kinds"]["manual_only"]["cells"]["manual_check"].update(reason_texts=[]),
     "Incomplete GWS value-rule cell"),
    (lambda f: f[MAIN]["kinds"]["manual_only"]["cells"]["manual_check"].update(verdict="met"),
     "Invalid GWS value-rule kind gate"),
    (lambda f: f[MAIN]["kinds"]["manual_only"]["cells"]["manual_check"].update(reason_codes=["a"]),
     "Invalid GWS value-rule cell"),
    (lambda f: f[MAIN]["kinds"]["manual_only"]["cells"]["manual_check"].update(cited=["gws_dns"]),
     "Invalid GWS value-rule cell citation"),
    (lambda f: f[MAIN]["kinds"]["manual_only"]["cells"]["manual_check"].update(recommendations=["x"]),
     "Invalid value-rule evidence limitations"),
    (lambda f: f[MAIN]["kinds"]["manual_only"].update(evidence_free=False), "Invalid GWS value-rule kind gate"),
    (lambda f: f[MAIN]["kinds"]["manual_only"].update(extra=1), "Invalid GWS value-rule kind"),
    (lambda f: _sem(f, "gmail_pop_access").update(reducer="min"), "Invalid GWS section semantics"),
    (lambda f: _sem(f, "gmail_pop_access").pop("src"), "Invalid GWS section semantics"),
    (lambda f: _sem(f, "gmail_rule_states").pop("key"), "Invalid GWS section semantics"),
    (lambda f: _field(f, "gmail_rule_states", "ruleStates").update(type="list_strings"),
     "Invalid GWS section semantics"),
    (lambda f: _sem(f, "gmail_pop_access")["fields"].append({"name": "enablePopAccess", "type": "bool"}),
     "Invalid GWS section semantics"),
    (lambda f: f[MAIN]["section_semantics"].append(dict(_sem(f, "gmail_pop_access"))),
     "Invalid GWS section semantics"),
    (lambda f: _field(f, "gmail_pop_access", "enablePopAccess").update(other=1), "Invalid GWS section semantics"),
    (lambda f: f[MAIN].update(section_semantics={}), "Invalid GWS section semantics"),
    (lambda f: _sem(f, "gmail_mail_delegation").pop("default_src"), "Invalid GWS section default"),
    (lambda f: _field(f, "gmail_pop_access", "enablePopAccess").update(default=False), "Invalid GWS section default"),
    (lambda f: _sem(f, "gmail_rule_states").update(default_src="SG:scubagoggles/policy_api.py:1"),
     "Invalid GWS section default"),
])
def test_loader_refuses(change, message):
    _mutate(message, change)


@pytest.mark.parametrize("change", [
    lambda f: _sem(f, "gmail_pop_access").update(reducer=["max"]),
    lambda f: _sem(f, "gmail_pop_access").update(fields={"enablePopAccess": "bool"}),
    lambda f: _field(f, "gmail_pop_access", "enablePopAccess").update(type=["bool"]),
    lambda f: f[MAIN]["kinds"]["manual_only"]["cells"]["manual_check"].update(verdict=["not_assessed"]),
    lambda f: f[MAIN]["kinds"]["manual_only"]["cells"]["manual_check"].update(cited=[["gws_tenant"]]),
    lambda f: f[MAIN]["policies"]["GWS.MEET.6.3v1"].update(kind=["manual_only"]),
    lambda f: f[MAIN]["policies"]["GWS.MEET.6.3v1"].update(sections=[["gws_tenant"]]),
    lambda f: f[MAIN]["kinds"]["manual_only"].update(evidence_free=1),
    lambda f: f[MAIN].update(schema_version=True),
    lambda f: _sem(f, "gmail_pop_access").update(outside_expected_table=1),
    lambda f: f.update({FRAGMENT: ["kinds", "policies"]}),
    lambda f: f[FRAGMENT].update(policies={"GWS.GMAIL.1.1v1": "row"}),
])
def test_loader_refuses_malformed_shapes_with_value_error(change):
    files = _files()
    change(files)
    with pytest.raises(ValueError):
        _load(files)


def test_loader_refuses_a_gated_kind_without_the_gate_cell():
    files = _with_gated(_files())
    del files[FRAGMENT]["kinds"]["test_gate"]["cells"]["section_not_collected"]
    with pytest.raises(ValueError, match="Invalid GWS value-rule kind gate"):
        _load(files)


def test_loader_refuses_a_citation_outside_a_row_using_the_kind():
    files = _with_gated(_files())
    files[FRAGMENT]["kinds"]["test_gate"]["cells"]["no_unit_violates"]["cited"] = ["gws_policies", "gws_tenant"]
    with pytest.raises(ValueError, match="Invalid GWS value-rule cell citation"):
        _load(files)


def test_loader_resolves_cells_through_the_kind():
    data = _load(_with_gated(_files()))
    cells = data["policies"]["GWS.GMAIL.1.1v1"]["cells"]
    assert cells["no_unit_violates"]["cited"] == ["gws_tenant", "gws_policies"]
    assert cells["section_not_collected"]["cited"] == ["gws_tenant", "gws_policies"]
    assert cells["section_not_collected"]["reason_texts"] == [
        "Data unavailable: required evidence section(s) not collected: gws_policies.",
        "Data unavailable: required evidence section(s) not collected: gws_tenant, gws_policies.",
        "Data unavailable: required evidence section(s) not collected: gws_tenant."]


_DUPLICATED_ROW = '"GWS.MEET.6.3v1": {"kind": "manual_only", "rule_id": "GWS.MEET.6.3v1.manual_only", ' \
    '"sections": ["gws_tenant"], "params": {}}, '


@pytest.mark.parametrize("path, old, new", [
    # Review M1: the same policy twice in one file, identical but for params; the last one must not silently win.
    (MAIN, '"GWS.MEET.6.3v1": {', _DUPLICATED_ROW.replace('"params": {}', '"params": {"changed": true}')
     + '"GWS.MEET.6.3v1": {'),
    (MAIN, '"manual_only": {"cells"', '"manual_only": {"cells": {}}, "manual_only": {"cells"'),
    (MAIN, '"reducer": "max"', '"reducer": "merge", "reducer": "max"'),
    (FRAGMENTS[0], '"kinds": {}', '"kinds": {}, "kinds": {}'),
])
def test_loader_refuses_a_member_repeated_in_one_file(path, old, new):
    files = _files()
    texts = {name: json.dumps(data) for name, data in files.items()}
    assert old in texts[path]
    texts[path] = texts[path].replace(old, new, 1)
    with pytest.raises(ValueError, match="GWS value-rule catalogue repeats a member: scuba-gws-"):
        gws_catalogue._load(texts.__getitem__)


def _resource_root(tmp_path: Path, omit: str) -> Path:
    for path, data in _files().items():
        if not path.endswith(omit):
            (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / path).write_text(json.dumps(data), encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("omit", ["scuba-gws-rules-dns.json", "scuba-gws-value-rules.json"])
def test_an_unreadable_resource_is_named_without_its_path(tmp_path, monkeypatch, omit):
    # Review B5: the error and its displayed chain name the shipped file only, never the resolved resource root.
    root = _resource_root(tmp_path / "synthetic-resource-root", omit)
    monkeypatch.setattr(gws_catalogue, "open_text_resource", lambda path: (root / path).read_text(encoding="utf-8"))
    gws_catalogue.catalogue.cache_clear()
    try:
        with pytest.raises(ValueError) as caught:
            gws.assess("GWS.MEET.6.3v1", {})
    finally:
        gws_catalogue.catalogue.cache_clear()
    assert str(caught.value) == f"GWS value-rule catalogue resource is unreadable: {omit}"
    shown = "".join(traceback.format_exception(caught.value))
    assert "synthetic-resource-root" not in shown and str(tmp_path) not in shown


def test_undecodable_resource_is_named_without_its_path():
    files = _files()
    texts = {name: json.dumps(data) for name, data in files.items()}
    texts[FRAGMENTS[-1]] = "{"
    with pytest.raises(ValueError) as caught:
        gws_catalogue._load(texts.__getitem__)
    assert str(caught.value) == "GWS value-rule catalogue resource is not valid JSON: scuba-gws-rules-dns.json"
    assert caught.value.__cause__ is None and caught.value.__suppress_context__ is True


def test_section_semantics_cover_the_pinned_tables():
    semantics = gws_catalogue.catalogue()["section_semantics"]
    assert len(semantics) == 104
    outside = {key for key, entry in semantics.items() if entry.get("outside_expected_table")}
    assert outside == {"api_controls_google_services", "api_controls_internal_apps",
                       "api_controls_unconfigured_third_party_apps", "early_access_apps_service_status",
                       "gemini_app_service_status", "gmail_per_user_outbound_gateway"}
    assert sum("default" in entry for entry in semantics.values()) == 27
    assert all(entry["src"].startswith("SG:scubagoggles/") for entry in semantics.values())
    assert {key: entry["reducer"] for key, entry in semantics.items() if entry["reducer"] != "max"} == {
        "calendar_interoperability": "merge", "calendar_primary_calendar_max_allowed_external_sharing": "merge",
        "calendar_secondary_calendar_max_allowed_external_sharing": "merge", "chat_chat_history": "merge",
        "chat_external_chat_restriction": "merge", "drive_and_docs_drive_sdk": "merge",
        "gmail_blocked_sender_lists": "max_map", "gmail_email_address_lists": "max_map", "gmail_imap_access": "merge",
        "gmail_mail_delegation": "merge", "gmail_rule_states": "max_map", "gmail_spam_override_lists": "max_map",
        "groups_for_business_groups_sharing": "merge", "rule_dlp": "list", "rule_system_defined_alerts": "list",
        "security_less_secure_apps": "merge", "security_super_admin_account_recovery": "merge",
        "security_user_account_recovery": "merge", "workspace_marketplace_apps_access_options": "merge"}
    assert semantics["gmail_email_address_lists"]["key"] == "id"
    assert semantics["gmail_rule_states"]["key"] == "ruleId"
    assert semantics["gmail_mail_delegation"] == {
        "default": {"enableMailDelegation": False}, "default_src": "SG:scubagoggles/policy_api.py:411",
        "fields": {"enableMailDelegation": "bool"}, "reducer": "merge", "src": "SG:scubagoggles/policy_api.py:240"}
    assert semantics["drive_and_docs_general_access_default"]["default"] == {
        "defaultFileAccess": "LINK_SHARING_PRIVATE"}


# --- registry and dispatch ------------------------------------------------------------------------------------------

def test_registries_are_disjoint():
    assert "manual_only" in gws._registry()
    assert set(gws._registry()).isdisjoint(value_rules._registry())
    assert not hasattr(gws, "KINDS")
    assert set(gws_catalogue.catalogue()["kinds"]) <= set(gws._registry())


def test_cross_platform_ids_answer_none():
    assert value_rules.assess("GWS.MEET.6.3v1", {}) is None
    assert value_rules.assess("GWS.GMAIL.1.1v1", {}) is None
    assert gws.assess("MS.AAD.1.1v1", {}) is None


def test_a_policy_without_a_row_answers_none(controlled):
    assert UNIMPLEMENTED in controlled["policy_ids"]
    assert gws.assess(UNIMPLEMENTED, {}) is None


def test_m365_catalogue_never_uses_the_manual_code():
    text = (ROOT / "configs/scuba-value-rules.json").read_text(encoding="utf-8")
    assert "data_unavailable_manual_check" not in text
    for path in (ROOT / "src/azure_tenant_audit/value_rules").glob("*.py"):
        assert "data_unavailable_manual_check" not in path.read_text(encoding="utf-8") or path.name == "record.py"


def test_manual_code_is_undecidable():
    assert "data_unavailable_manual_check" in UNDECIDABLE_CODES
    assert evidence_kind("data_unavailable_manual_check") == "undecidable"


@pytest.mark.parametrize("policy_id", sorted(MANUAL_IDS))
def test_manual_policies_answer_the_fixed_reason(policy_id):
    record = gws.assess(policy_id, {"gws_tenant": {"collection_status": "not_collected"}})
    assert record == {"policy_id": policy_id, "verdict": "not_assessed",
                      "reason_code": "data_unavailable_manual_check", "reason_text": MANUAL_TEXT,
                      "cell": "manual_check", "cited_sections": ["gws_tenant"], "detail": {}}
    assert gws.as_pack_response(record, "SHALL", ["gws_tenant"])["recommendations"] == [
        "review_policy_against_baseline_text"]


def test_checked_gws_refuses_off_inventory_answers(controlled):
    good = gws.assess("GWS.MEET.6.3v1", {})
    for change in ({"reason_text": "Data unavailable: other."}, {"verdict": "not_met"}, {"cell": "met"},
                   {"cited_sections": ["gws_policies"]}, {"reason_code": "data_unavailable_other"},
                   {"cell": "rule_evaluation_failed"}, {"policy_id": "GWS.GMAIL.1.1v1"}):
        with pytest.raises(ValueError):
            checked_gws({**good, **change})


def test_rule_failure_is_a_shared_reason(controlled):
    record = rule_failure_gws("GWS.MEET.6.3v1")
    assert checked_gws(record) is record
    assert (record["cell"], record["reason_code"], record["cited_sections"]) == (
        None, "rule_evaluation_failed", ["gws_tenant"])
    with pytest.raises(ValueError):
        checked_gws({**record, "cited_sections": []})
    with pytest.raises(ValueError):
        rule_failure_gws(UNIMPLEMENTED)


def test_gate_runs_before_a_gated_kind(monkeypatch):
    data = _load(_with_gated(_files()))
    monkeypatch.setattr(gws_catalogue, "catalogue", lambda: data)
    calls = []

    def kind(policy_id, row, sections):
        calls.append(policy_id)
        return {"policy_id": policy_id, "verdict": "met", "reason_code": "no_unit_violates",
                "reason_text": "Requirement met: no unit violates the setting.", "cell": "no_unit_violates",
                "cited_sections": None, "detail": {}}

    monkeypatch.setattr(gws, "_registry", lambda: {"test_gate": kind, "manual_only": lambda *a: None})
    record = gws.assess("GWS.GMAIL.1.1v1", {"gws_tenant": {}, "gws_policies": {"collection_status": "not_collected"}})
    assert (record["cell"], record["reason_text"], record["cited_sections"]) == (
        "section_not_collected", "Data unavailable: required evidence section(s) not collected: gws_policies.",
        ["gws_policies"])
    assert calls == []
    record = gws.assess("GWS.GMAIL.1.1v1", {"gws_tenant": {}, "gws_policies": {}})
    assert (record["verdict"], record["cell"], calls) == ("met", "no_unit_violates", ["GWS.GMAIL.1.1v1"])


# --- reducers -------------------------------------------------------------------------------------------------------

TENANT = {"as_of": "2026-11-25T12:00:00Z", "top_unit": "ou:root", "org_units": {"ou:root": None, "ou:a": "ou:root"},
          "complete": True}


def _p(unit, section, sort_order, value, unit_kind=None):
    return {"unit": unit, "unit_kind": unit_kind or ("group" if "/group:" in unit else "org_unit"),
            "section": section, "sort_order": sort_order, "value": value}


def _units(policies, keys, complete=True):
    return R.effective_units({"gws_tenant": TENANT, "gws_policies": {"complete": complete, "policies": policies}},
                             keys)


def test_merge_fills_fields_the_winner_lacks():
    units = _units([_p("ou:a", "chat_chat_history", 5, {"allowUserModification": False, "historyOnByDefault": False}),
                    _p("ou:a", "chat_chat_history", 10, {"historyOnByDefault": True})], ["chat_chat_history"])
    assert units.values["ou:a"] == {"chat_chat_history": {"historyOnByDefault": True, "allowUserModification": False}}
    assert units.explicit["ou:a"] == frozenset({("chat_chat_history", "historyOnByDefault"),
                                                ("chat_chat_history", "allowUserModification")})


def test_max_keeps_the_highest_sort_order_only():
    units = _units([_p("ou:a", "gmail_pop_access", 7, {"enablePopAccess": True}),
                    _p("ou:a", "gmail_pop_access", 3, {"enablePopAccess": False}),
                    _p("ou:a", "security_password", 2, {"allowReuse": False}),
                    _p("ou:a", "security_password", 9, {"minimumLength": 12})],
                   ["gmail_pop_access", "security_password"])
    assert units.values["ou:a"] == {"gmail_pop_access": {"enablePopAccess": True},
                                    "security_password": {"minimumLength": 12}}
    units = _units([_p("ou:a", "gmail_pop_access", 3, {"enablePopAccess": False}),
                    _p("ou:a", "gmail_pop_access", 7, {"enablePopAccess": True})], ["gmail_pop_access"])
    assert units.values["ou:a"] == {"gmail_pop_access": {"enablePopAccess": True}}


def test_group_unit_is_never_ranked_against_its_ou():
    units = _units([_p("ou:root/group:g1", "gmail_pop_access", 100, {"enablePopAccess": True}),
                    _p("ou:root", "gmail_pop_access", 1, {"enablePopAccess": False})], ["gmail_pop_access"])
    assert units.values == {"ou:root": {"gmail_pop_access": {"enablePopAccess": False}},
                            "ou:root/group:g1": {"gmail_pop_access": {"enablePopAccess": True}}}


def test_defaults_fill_the_top_unit_only():
    units = _units([_p("ou:a", "gmail_mail_delegation", 1, {"enableMailDelegation": True}),
                    _p("ou:root", "groups_for_business_groups_sharing", 1,
                       {"collaborationCapability": "ANYONE_CAN_ACCESS"})],
                   ["gmail_auto_forwarding", "gmail_mail_delegation", "groups_for_business_groups_sharing",
                    "gmail_pop_access"])
    assert units.values["ou:root"] == {
        "gmail_auto_forwarding": {"enableAutoForwarding": True},
        "gmail_mail_delegation": {"enableMailDelegation": False},
        "groups_for_business_groups_sharing": {
            "collaborationCapability": "ANYONE_CAN_ACCESS", "createGroupsAccessLevel": "USERS_IN_DOMAIN",
            "newGroupsAreHidden": False, "ownersCanAllowExternalMembers": False,
            "ownersCanAllowIncomingMailFromPublic": True, "ownersCanHideGroups": False,
            "viewTopicsDefaultAccessLevel": "DOMAIN_USERS"}}
    assert units.values["ou:a"] == {"gmail_mail_delegation": {"enableMailDelegation": True}}
    assert units.explicit["ou:root"] == frozenset({("groups_for_business_groups_sharing", "collaborationCapability")})


@pytest.mark.parametrize("complete", [False, None, "true", 1])
def test_defaults_withheld_unless_the_read_is_complete(complete):
    sections = {"gws_tenant": TENANT, "gws_policies": {"policies": []}}
    if complete is not None:
        sections["gws_policies"]["complete"] = complete
    units = R.effective_units(sections, ["gmail_auto_forwarding"])
    assert units.values == {"ou:root": {}}
    assert units.complete is False
    assert R.effective(units, "ou:root", "gmail_auto_forwarding", "enableAutoForwarding") is R.MISSING


def test_list_reducer_keeps_every_value_highest_first():
    units = _units([_p("ou:root", "rule_system_defined_alerts", 1, {"displayName": "a", "state": "ACTIVE"}),
                    _p("ou:root", "rule_system_defined_alerts", 2, {"displayName": "b", "state": "INACTIVE"}),
                    _p("ou:root", "rule_system_defined_alerts", 1, {"displayName": "c", "state": "ACTIVE"})],
                   ["rule_system_defined_alerts"])
    assert units.values["ou:root"]["rule_system_defined_alerts"] == [
        {"displayName": "b", "state": "INACTIVE"}, {"displayName": "a", "state": "ACTIVE"},
        {"displayName": "c", "state": "ACTIVE"}]


def test_max_map_merges_entries_by_primary_key():
    units = _units([
        _p("ou:root", "gmail_email_address_lists", 1,
           {"emailAddressList": [{"id": "l1", "count": 9, "domains": 1}, {"id": "l2", "count": 3}]}),
        _p("ou:root", "gmail_email_address_lists", 5, {"emailAddressList": [{"id": "l1", "count": 2}]})],
        ["gmail_email_address_lists"])
    assert units.values["ou:root"]["gmail_email_address_lists"] == {
        "emailAddressList": [{"id": "l1", "count": 2, "domains": 1}, {"id": "l2", "count": 3}]}


@pytest.mark.parametrize("policies", [
    [_p("ou:a", "gmail_pop_access", 4, {"enablePopAccess": True}),
     _p("ou:a", "gmail_pop_access", 4, {"enablePopAccess": False})],
    [_p("ou:a", "gmail_pop_access", 4, None)],
    [_p("ou:a", "gmail_pop_access", 4, ["x"])],
    [_p("ou:a", "chat_chat_history", 4, {"historyOnByDefault": True}), _p("ou:a", "chat_chat_history", 1, "x")],
    [_p("ou:a", "gmail_rule_states", 4, {"ruleStates": [{"state": "ON"}]})],
    [_p("ou:a", "gmail_rule_states", 4, {"ruleStates": "x"})],
    [_p("ou:a", "gmail_rule_states", 4, {"ruleStates": [{"ruleId": "r1"}, {"ruleId": "r1"}]})],
    [_p("ou:a", "gmail_rule_states", 4, {"ruleStates": [{"ruleId": "r1"}]}),
     _p("ou:a", "gmail_rule_states", 1, {"ruleStates": [{"ruleId": "r2", "y": 1}, {"ruleId": "r2", "y": 2}]})],
    [_p("ou:a", "gmail_pop_access", 4, {"enablePopAccess": True}),
     _p("ou:a", "gmail_pop_access", 4, {"enablePopAccess": 1})],
    [_p("ou:a", "gmail_pop_access", True, {"enablePopAccess": True})],
    [_p("ou:a", "gmail_pop_access", float("nan"), {"enablePopAccess": True})],
    [_p("ou:a", "gmail_pop_access", "1", {"enablePopAccess": True})],
    [{"unit": "ou:a", "unit_kind": "org_unit", "section": "gmail_pop_access", "sort_order": 1}],
    [_p("ou:a", "gmail_pop_access", None, {"enablePopAccess": False}),
     _p("ou:a", "gmail_pop_access", 9, {"enablePopAccess": False})],
])
def test_unreducible_value_is_unusable_for_that_unit_only(policies):
    section = policies[0]["section"]
    units = _units([*policies, _p("ou:root", "gmail_pop_access", 1, {"enablePopAccess": False})],
                   [section, "gmail_pop_access"])
    assert units.values["ou:a"][section] is R.UNUSABLE
    assert units.values["ou:root"]["gmail_pop_access"] == {"enablePopAccess": False}


def test_equal_sort_order_with_equal_values_is_not_a_tie():
    units = _units([_p("ou:a", "gmail_pop_access", 4, {"enablePopAccess": True}),
                    _p("ou:a", "gmail_pop_access", 4, {"enablePopAccess": True})], ["gmail_pop_access"])
    assert units.values["ou:a"] == {"gmail_pop_access": {"enablePopAccess": True}}


@pytest.mark.parametrize("sections", [
    {"gws_tenant": TENANT, "gws_policies": {"complete": True, "policies": "x"}},
    {"gws_tenant": TENANT, "gws_policies": {"complete": True}},
    {"gws_tenant": TENANT, "gws_policies": None},
    {"gws_tenant": {"top_unit": None}, "gws_policies": {"complete": True, "policies": []}},
    {"gws_tenant": {"collection_status": "not_collected"}, "gws_policies": {"complete": True, "policies": []}},
    {"gws_tenant": TENANT, "gws_policies": {"complete": True, "policies": ["x"]}},
    {"gws_tenant": TENANT, "gws_policies": {"complete": True, "policies": [{"section": 3}]}},
    {"gws_tenant": TENANT, "gws_policies": {"complete": True, "policies": [
        _p("ou:a/group:g1", "gmail_pop_access", 1, {"enablePopAccess": True}, unit_kind="org_unit")]}},
    {"gws_tenant": TENANT, "gws_policies": {"complete": True, "policies": [
        _p("ou:a", "gmail_pop_access", 1, {"enablePopAccess": True}, unit_kind=["org_unit"])]}},
    {"gws_tenant": TENANT, "gws_policies": {"complete": True, "policies": [
        _p("ou:root/group:g1", "gmail_pop_access", 1, {"enablePopAccess": True}, unit_kind="group")]},
     "_top_group": True},
    None,
    {"gws_tenant": TENANT, "gws_policies": {"complete": True, "policies": [
        _p("", "gmail_pop_access", 1, {"enablePopAccess": True})]}},
])
def test_envelope_that_cannot_be_placed_is_unusable(sections):
    if isinstance(sections, dict) and sections.pop("_top_group", False):
        sections["gws_tenant"] = {**TENANT, "top_unit": "ou:root/group:g1"}
    with pytest.raises(R.Unusable):
        R.effective_units(sections, ["gmail_pop_access"])


def test_malformed_entries_of_other_sections_are_not_read():
    units = _units([{"unit": None, "section": "meet_video_recording", "sort_order": "x"},
                    _p("ou:a", "gmail_pop_access", 1, {"enablePopAccess": False})], ["gmail_pop_access"])
    assert units.values == {"ou:root": {}, "ou:a": {"gmail_pop_access": {"enablePopAccess": False}}}


def test_unknown_section_key_is_a_programming_error():
    with pytest.raises(ValueError, match="Unknown GWS policy section"):
        _units([], ["gmail_not_a_section"])


def test_effective_reads_the_unit_then_the_top_unit():
    units = _units([_p("ou:root", "security_password", 1, {"minimumLength": 14, "allowReuse": False}),
                    _p("ou:a", "security_password", 1, {"minimumLength": 8}),
                    _p("ou:b", "gmail_pop_access", 1, None)], ["security_password", "gmail_pop_access"])
    assert R.effective(units, "ou:a", "security_password", "minimumLength") == 8
    assert R.effective(units, "ou:a", "security_password", "allowReuse") is False
    assert R.effective(units, "ou:c", "security_password", "minimumLength") == 14
    assert R.effective(units, "ou:a", "security_password", "expirationDuration") is R.MISSING
    assert R.effective(units, "ou:b", "gmail_pop_access", "enablePopAccess") is R.UNUSABLE


# --- service_on -----------------------------------------------------------------------------------------------------

def _status(state):
    return {"serviceState": state}


@pytest.mark.parametrize("unit_state, top_state, expected", [
    ("ENABLED", "DISABLED", "on"),
    ("enabled", None, "on"),
    ("DISABLED", "ENABLED", "off"),
    ("DISABLED", None, "off"),
    (None, "ENABLED", "on"),
    (None, "DISABLED", "off"),
    (None, None, "unknown"),
    ("PAUSED", "ENABLED", "unknown"),
    (7, "ENABLED", "unknown"),
    (None, "PAUSED", "unknown"),
    (None, 1, "unknown"),
])
def test_service_on_truth_table(unit_state, top_state, expected):
    policies = []
    if unit_state is not None:
        policies.append(_p("ou:a", "gmail_service_status", 1, _status(unit_state)))
    if top_state is not None:
        policies.append(_p("ou:root", "gmail_service_status", 1, _status(top_state)))
    units = _units(policies, ["gmail_service_status"])
    assert R.service_on(units, "ou:a", "gmail") == expected


def test_service_on_top_unit_and_unreadable_values():
    units = _units([_p("ou:root", "gmail_service_status", 1, _status("ENABLED")),
                    _p("ou:root/group:g1", "gmail_service_status", 1, _status("DISABLED")),
                    _p("ou:b", "gmail_service_status", 1, {"other": 1}),
                    _p("ou:c", "gmail_service_status", 1, None)], ["gmail_service_status"])
    assert R.service_on(units, "ou:root", "gmail") == "on"
    assert R.service_on(units, "ou:root/group:g1", "gmail") == "off"
    assert R.service_on(units, "ou:b", "gmail") == "unknown"  # a supplied record without a status never inherits
    assert R.service_on(units, "ou:c", "gmail") == "unknown"
    assert R.service_on(units, "ou:a", "chat") == "unknown"


@pytest.mark.parametrize("unit_value", [{}, {"other": 1}, {"serviceState": None}, {"serviceState": ""}])
def test_service_status_record_without_a_status_is_unknown_not_inherited(unit_value):
    # Review B3: an explicit unreadable override at ou:a never takes the top unit's off (the all-off service gate).
    units = _units([_p("ou:root", "gmail_service_status", 1, _status("DISABLED")),
                    _p("ou:a", "gmail_service_status", 1, unit_value)], ["gmail_service_status"])
    assert R.service_on(units, "ou:root", "gmail") == "off"
    assert R.service_on(units, "ou:a", "gmail") == "unknown"
    assert R.service_on(units, "ou:b", "gmail") == "off"  # no record at all still inherits


def test_top_unit_status_record_without_a_status_is_unknown():
    units = _units([_p("ou:root", "gmail_service_status", 1, {})], ["gmail_service_status"])
    assert R.service_on(units, "ou:root", "gmail") == "unknown"
    assert R.service_on(units, "ou:a", "gmail") == "unknown"


# --- equal ranks (D11 at the deciding rank of each field or map item; review B2) -----------------------------------

_INTEROP = [_p("ou:root", "calendar_interoperability", 8, {"enableFullEventDetails": True}),
            _p("ou:root", "calendar_interoperability", 7, {"enableInteroperability": False}),
            _p("ou:root", "calendar_interoperability", 7, {"enableInteroperability": True})]


@pytest.mark.parametrize("policies", [_INTEROP, [_INTEROP[0], _INTEROP[2], _INTEROP[1]],
                                      [_INTEROP[2], _INTEROP[1], _INTEROP[0]]])
def test_merge_field_tied_at_its_own_rank_is_unusable_in_any_order(policies):
    units = _units([*policies, _p("ou:a", "calendar_interoperability", 1, {"enableInteroperability": False})],
                   ["calendar_interoperability"])
    assert units.complete is True
    assert units.values["ou:root"]["calendar_interoperability"] is R.UNUSABLE
    assert R.effective(units, "ou:root", "calendar_interoperability", "enableInteroperability") is R.UNUSABLE
    assert units.values["ou:a"] == {"calendar_interoperability": {"enableInteroperability": False}}


@pytest.mark.parametrize("order", [(0, 1, 2), (2, 1, 0), (1, 0, 2)])
def test_merge_equal_ranked_fields_that_agree_or_do_not_overlap_merge(order):
    policies = [_p("ou:a", "calendar_interoperability", 7, {"enableInteroperability": False}),
                _p("ou:a", "calendar_interoperability", 7, {"enableInteroperability": False,
                                                              "enableFullEventDetails": True}),
                _p("ou:a", "calendar_interoperability", 7, {"enableExchangeRoomBooking": True})]
    units = _units([policies[index] for index in order], ["calendar_interoperability"])
    assert units.values["ou:a"]["calendar_interoperability"] == {
        "enableInteroperability": False, "enableFullEventDetails": True, "enableExchangeRoomBooking": True}


def test_merge_higher_rank_decides_a_field_tied_lower_down():
    units = _units([_p("ou:a", "calendar_interoperability", 9, {"enableInteroperability": True}),
                    _p("ou:a", "calendar_interoperability", 7, {"enableInteroperability": False}),
                    _p("ou:a", "calendar_interoperability", 7, {"enableInteroperability": True,
                                                              "enableFullEventDetails": False})],
                   ["calendar_interoperability"])
    assert units.values["ou:a"]["calendar_interoperability"] == {
        "enableInteroperability": True, "enableFullEventDetails": False}


_RULES = [_p("ou:root", "gmail_rule_states", 8, {"ruleStates": [{"ruleId": "other", "state": "ACTIVE"}]}),
          _p("ou:root", "gmail_rule_states", 7, {"ruleStates": [{"ruleId": "r1", "state": "ACTIVE"}]}),
          _p("ou:root", "gmail_rule_states", 7, {"ruleStates": [{"ruleId": "r1", "state": "INACTIVE"}]})]


@pytest.mark.parametrize("policies", [_RULES, [_RULES[0], _RULES[2], _RULES[1]], [_RULES[2], _RULES[1], _RULES[0]]])
def test_max_map_item_tied_at_its_own_rank_is_unusable_in_any_order(policies):
    units = _units([*policies, _p("ou:a", "gmail_rule_states", 1, {"ruleStates": [{"ruleId": "r1", "state": "ACTIVE"}]})],
                   ["gmail_rule_states"])
    assert units.values["ou:root"]["gmail_rule_states"] is R.UNUSABLE
    assert units.values["ou:a"] == {"gmail_rule_states": {"ruleStates": [{"ruleId": "r1", "state": "ACTIVE"}]}}


@pytest.mark.parametrize("order", [(0, 1, 2), (2, 1, 0)])
def test_max_map_equal_ranked_items_that_agree_or_differ_in_key_merge(order):
    policies = [_p("ou:a", "gmail_rule_states", 7, {"ruleStates": [{"ruleId": "r2", "state": "ACTIVE"}]}),
                _p("ou:a", "gmail_rule_states", 7, {"ruleStates": [{"ruleId": "r1", "state": "INACTIVE"}]}),
                _p("ou:a", "gmail_rule_states", 7, {"ruleStates": [{"ruleId": "r1", "state": "INACTIVE",
                                                                      "note": "n"}]})]
    units = _units([policies[index] for index in order], ["gmail_rule_states"])
    assert units.values["ou:a"]["gmail_rule_states"] == {"ruleStates": [
        {"ruleId": "r1", "state": "INACTIVE", "note": "n"}, {"ruleId": "r2", "state": "ACTIVE"}]}


def test_list_reducer_is_independent_of_read_order_at_equal_rank():
    first = _p("ou:root", "rule_system_defined_alerts", 1, {"displayName": "c", "state": "ACTIVE"})
    second = _p("ou:root", "rule_system_defined_alerts", 1, {"displayName": "a", "state": "ACTIVE"})
    for policies in ([first, second], [second, first]):
        units = _units(policies, ["rule_system_defined_alerts"])
        assert units.values["ou:root"]["rule_system_defined_alerts"] == [
            {"displayName": "a", "state": "ACTIVE"}, {"displayName": "c", "state": "ACTIVE"}]


# --- tenant topology (review B4) -----------------------------------------------------------------------------------

def _with_tenant(tenant, keys=("gmail_mail_delegation",)):
    return R.effective_units({"gws_tenant": tenant, "gws_policies": {"complete": True, "policies": []}}, list(keys))


@pytest.mark.parametrize("tenant", [
    {"top_unit": "ou:root", "org_units": {}, "complete": False},
    {"top_unit": "ou:root", "org_units": {"ou:root": None}, "complete": False},
    {"top_unit": "ou:root", "org_units": {"ou:root": None}},
    {"top_unit": "ou:root", "org_units": {"ou:root": None}, "complete": "true"},
])
def test_partial_tenant_topology_is_incomplete_and_gets_no_default(tenant):
    units = _with_tenant(tenant)
    assert units.complete is False
    assert units.values == {"ou:root": {}}
    assert R.effective(units, "ou:root", "gmail_mail_delegation", "enableMailDelegation") is R.MISSING


@pytest.mark.parametrize("tenant", [
    {"top_unit": "not-an-ou", "org_units": {}, "complete": True},
    {"top_unit": "not-an-ou", "org_units": {"not-an-ou": None}, "complete": True},
    {"top_unit": "ou:", "org_units": {"ou:": None}, "complete": True},
    {"top_unit": "ou:root", "org_units": {}, "complete": True},
    {"top_unit": "ou:root", "org_units": {"ou:a": None}, "complete": True},
    {"top_unit": "ou:root", "org_units": {"ou:root": "ou:a", "ou:a": None}, "complete": True},
    {"top_unit": "ou:root", "org_units": {"ou:root": None, "ou:a": None}, "complete": True},
    {"top_unit": "ou:root", "org_units": None, "complete": True},
    {"top_unit": "ou:root", "complete": False},
    {"top_unit": "ou:root", "org_units": {"ou:root": None, "x": "ou:root"}, "complete": False},
    {"top_unit": "ou:root", "org_units": {"ou:root": None, "ou:a": 7}, "complete": False},
])
def test_invalid_root_binding_is_unusable_never_a_compliant_default(tenant):
    with pytest.raises(R.Unusable):
        _with_tenant(tenant)


def test_complete_tenant_and_read_apply_the_default():
    units = _with_tenant({"top_unit": "ou:root", "org_units": {"ou:root": None, "ou:a": "ou:root"}, "complete": True})
    assert units.complete is True
    assert units.values == {"ou:root": {"gmail_mail_delegation": {"enableMailDelegation": False}}}
