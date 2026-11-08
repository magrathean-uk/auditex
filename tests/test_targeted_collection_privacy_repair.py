"""SS 2.1 collector privacy repair, round 1: the three E1 counterexamples and their neighbours.

1. A retained selected field carrying an explicit nested ``TargetedUsersToProtect`` subtree (or an encoded one).
2. Unsupported, flat, legacy, nested, error and encoded sample layouts, including value-bearing diagnostics that sit
   beside a target-bearing component.
3. One-token names accepted as error, status, reason or class text, from envelopes and from a malicious callback.

Imports only APIs that already exist at E1, so on E1 this module collects and fails on its assertions, never on an
import. Constructed data only: no tenant, network or PowerShell; the child process is replaced at the adapter's
bounded-run seam, which sits before every privacy step the adapter takes.
"""
from __future__ import annotations

from copy import deepcopy
from functools import partial
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from azure_tenant_audit import cli
from azure_tenant_audit.adapters import powershell_graph as pg
from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
from azure_tenant_audit.collectors import targeted_users_coverage as tuc
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
from azure_tenant_audit.sensitive_users import SensitiveUsers
from azure_tenant_audit.value_rules.defender_targeted_users import SensitiveUsersBinding

COVERAGE = "TargetedUsersCoverage"
COMMANDS = dict(ExchangePolicyCollector.command_collectors)
ANTI_PHISH = COMMANDS["antiPhishPolicies"]
OTHER = COMMANDS["transportConfig"]

# Independent canaries: configured (in the operator list) and unconfigured; email, name, domain and malformed.
CONFIGURED = ("r1-conf-a@configured-r1canary.invalid", "r1-conf-b@configured-r1canary.invalid")
CONFIGURED_NAME = "Ophelia Brindlecastle"
UNCONF_EMAIL = "zq-canary@unlisted-canary.invalid"
UNCONF_NAME = "Zebulon Quarkwright"
UNCONF_DOMAIN = "r1canary-domain.invalid"
MALFORMED = "Name;;bad@@r1canary-malformed"
ONE_TOKEN = "zebulonquarkwright"
FRAGMENTS = ("zebulon", "quarkwright", "zq-canary", "unlisted-canary", "ophelia", "brindlecastle",
             "configured-r1canary", "r1canary-domain", "r1canary-malformed")
TARGETS = [f"{CONFIGURED_NAME};{CONFIGURED[0]}", CONFIGURED[1].upper(), f"{UNCONF_NAME};{UNCONF_EMAIL}",
           UNCONF_DOMAIN, MALFORMED]
USERS = SensitiveUsers(tuple(sorted(CONFIGURED)))
BINDING = SensitiveUsersBinding(2, "cd" * 32)
MODES = {"configured": (USERS, BINDING), "unconfigured": (None, None)}
# A target list as a quoted key (plain, escaped, repr or \u-escaped); a select list naming the field is not one.
TARGET_KEY = re.compile(r"(?:t|\\+u0054)argeted_?users_?to_?protect\\*[\"']\s*:", re.IGNORECASE)

SETTINGS = {
    "Identity": "Default", "Name": "Default", "IsDefault": True, "Enabled": True,
    "EnableTargetedUserProtection": True, "TargetedUserProtectionAction": "Quarantine",
    "EnableOrganizationDomainsProtection": True, "TargetedDomainProtectionAction": "Quarantine",
    "EnableTargetedDomainsProtection": True, "TargetedDomainsToProtect": ["partner.example.invalid"],
    "EnableFirstContactSafetyTips": True, "EnableSimilarUsersSafetyTips": True,
    "EnableSimilarDomainsSafetyTips": True, "EnableUnusualCharactersSafetyTips": True, "EnableViaTag": True,
    "EnableUnauthenticatedSender": True,
}
HEALTHY = {name: {"status": "ok", "value": []} for name in (
    "acceptedDomains", "antiPhishRules", "eopProtectionPolicyRules", "atpProtectionPolicyRules", "atpPolicyForO365")}
TRANSPORT = {"command": OTHER, "status": "ok", "value": [{"Identity": "T", "SmtpClientAuthenticationDisabled": True}]}
UNRELATED = {"users": {"status": "ok", "value": [{"id": "u-1", "displayName": "Ordinary Person", "enabled": True}]}}
KNOWN_CLASSES = {None, "command_error", "command_parse_error", "command_timeout", "command_exception",
                 "command_not_found", "command_not_authenticated", "session_not_connected", "module_not_found",
                 "command_output_empty"}
TEXT_SLOTS = ("error", "error_class", "status", "reason", "state", "truncation_reason", "collection_status")

# Counterexample 1 verbatim (finding 1), then neighbours: list/dict nesting, key aliases, encoded and escaped JSON.
COUNTEREXAMPLE_1 = {"Identity": "Default", "TargetedDomainsToProtect": [{"TargetedUsersToProtect": [UNCONF_EMAIL]}]}
NESTED_CARRIERS = {
    "domains-list-of-dict": ("TargetedDomainsToProtect", [{"TargetedUsersToProtect": [UNCONF_EMAIL]}]),
    "domains-mixed-lower": ("TargetedDomainsToProtect",
                            ["partner.example.invalid", {"targeteduserstoprotect": [UNCONF_NAME, CONFIGURED[0]]}]),
    "domains-nested-list": ("TargetedDomainsToProtect", [["partner.example.invalid", UNCONF_DOMAIN]]),
    "name-dict-upper": ("Name", {"TARGETEDUSERSTOPROTECT": [UNCONF_DOMAIN, CONFIGURED_NAME]}),
    "identity-deep-underscore": ("Identity", {"inner": [{"Targeted_Users_To_Protect": [MALFORMED]}]}),
    "action-encoded-json": ("TargetedUserProtectionAction", json.dumps({"TargetedUsersToProtect": [UNCONF_EMAIL]})),
    "name-double-encoded": ("Name", json.dumps(json.dumps({"TargetedUsersToProtect": [UNCONF_NAME, CONFIGURED[1]]}))),
    "name-escaped-key": ("Name", '{"\\u0054argetedUsersToProtect":["%s"]}' % UNCONF_EMAIL),
    "domains-encoded-item": ("TargetedDomainsToProtect",
                             ["partner.example.invalid", json.dumps({"TargetedUsersToProtect": [UNCONF_DOMAIN]})]),
}

# Counterexample 2 verbatim (finding 2).
COUNTEREXAMPLE_2 = {"exchange_policy": {"legacyAntiPhish": {
    "stdout": "{\"TargetedUsersToProtect\":[\"zq-canary@unlisted-canary.invalid\"]}",
    "error": "failed for Zebulon Quarkwright"}}}
DEEP_LEVELS = 2500


def _deep_carrier():
    """A section nested past any recursion limit, with a target list at the bottom; built without recursion."""
    bottom = {"TargetedUsersToProtect": [UNCONF_EMAIL], "detail": f"for {UNCONF_NAME}"}
    node = bottom
    for _ in range(DEEP_LEVELS):
        node = {"down": node}
    return node, bottom


SAMPLE_LAYOUTS = {
    "counterexample-2": lambda: deepcopy(COUNTEREXAMPLE_2),
    "legacy-keyless-encoded-array": lambda: {"exchange_policy": {"legacyAntiPhishExport": {
        "stdout": json.dumps([UNCONF_EMAIL, UNCONF_DOMAIN, CONFIGURED[0]]), "stderr": f"WARNING: {UNCONF_NAME}",
        "message": MALFORMED, "error_class": "command_error"}}},
    "bare-row-list-with-scalar-row": lambda: {"exchange_policy": {"antiPhishPolicies": [
        {"Identity": "Flat", "TargetedUsersToProtect": [UNCONF_EMAIL]}, UNCONF_NAME]}},
    "flat-top-upper-key-and-note": lambda: {"antiPhishPolicies": {"value": [
        {"Identity": "Flat", "TARGETEDUSERSTOPROTECT": [UNCONF_DOMAIN], "note": f"set for {UNCONF_NAME}"}]}},
    "top-level-key-aliases": lambda: {"TargetedUsersToProtect": [UNCONF_EMAIL],
                                      "targeted_users_to_protect": [CONFIGURED_NAME]},
    "nested-double-encoded-with-detail": lambda: {"exchange_policy": {"unexpected": {"nested": {"deeper": [{
        "blob": json.dumps(json.dumps({"TargetedUsersToProtect": [UNCONF_EMAIL]})),
        "detail": f"failed for {UNCONF_NAME}"}]}}}},
    "escaped-key-in-other-envelope": lambda: {"exchange_policy": {"transportConfig": {
        **deepcopy(TRANSPORT), "stderr": '{"\\u0054argetedUsersToProtect":["%s"]}' % UNCONF_EMAIL,
        "error": f"failed for {UNCONF_NAME}"}}},
    "malformed-truncated-json": lambda: {"exchange_policy": {"atpPolicyForO365": {
        "status": "ok", "value": [], "stdout": '{"TargetedUsersToProtect": ["%s", "Zebul' % UNCONF_EMAIL}}},
    "error-envelope-recognised": lambda: {"exchange_policy": {"antiPhishPolicies": {
        "error": f"command_failed:1 {UNCONF_NAME}", "error_class": "command_error", "return_code": 1,
        "stdout": json.dumps([{"TargetedUsersToProtect": [UNCONF_EMAIL]}]), "stderr": UNCONF_DOMAIN,
        "message": f"for {CONFIGURED_NAME}"}}},
    "one-token-error-recognised": lambda: {"exchange_policy": {"antiPhishPolicies": {
        "error": ONE_TOKEN, "error_class": "command_error"}}},
    "over-cap-text": lambda: {"exchange_policy": {"legacyExport": {
        "stdout": "x" * (2 * 1024 * 1024) + json.dumps({"TargetedUsersToProtect": [UNCONF_EMAIL]})}}},
}


def _strings(value):
    """Every key and scalar in ``value`` as text, walked without recursion."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                yield ("key", str(key))
                stack.append(child)
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
        elif item is not None:
            yield ("value", item if isinstance(item, str) else str(item))


def _leaks(*values):
    found = []
    for value in values:
        for kind, text in _strings(value):
            folded = text.casefold()
            found.extend(fragment for fragment in FRAGMENTS if fragment in folded)
            if kind == "key" and re.sub(r"[^a-z0-9]", "", folded) == "targeteduserstoprotect":
                found.append("target key")
            if TARGET_KEY.search(text):
                found.append("encoded target key")
    return found


def _depth(value):
    deepest, stack = 0, [(value, 1)]
    while stack:
        item, level = stack.pop()
        deepest = max(deepest, level)
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        stack.extend((child, level + 1) for child in children)
    return deepest


def _settings_without(row, field):
    return {key: value for key, value in row.items() if key not in (field, COVERAGE)}


def _expected_settings(field):
    return {key: value for key, value in SETTINGS.items() if key != field}


# ---------------------------------------------------------------------------------------------------------------
# Finding 1: nested target subtrees beneath retained selected fields.


@pytest.mark.parametrize("mode", sorted(MODES))
@pytest.mark.parametrize("carrier", sorted(NESTED_CARRIERS))
def test_retained_field_carrying_a_target_subtree_never_survives_the_row_rebuild(carrier, mode):
    field, value = NESTED_CARRIERS[carrier]
    users, binding = MODES[mode]
    row = {**SETTINGS, field: deepcopy(value), "TargetedUsersToProtect": list(TARGETS)}
    source = deepcopy(row)
    for out in (tuc.sanitise_policy_row(row, users, binding, observed=True),
                tuc.sanitise_response({"status": "ok", "value": [row]}, users, binding, observed=True)["value"][0]):
        assert _leaks(out) == [], carrier
        assert _settings_without(out, field) == _expected_settings(field), "ordinary settings are kept"
        expected = "known" if users else "not_collected"
        assert out[COVERAGE]["state"] == expected, "the real target field keeps its summary semantics"
        assert not isinstance(out.get(field), dict)
    assert row == source, "the input row is never modified"
    shaped = tuc.sanitise_response({"value": [row]}, users, binding, observed=True)
    assert tuc.enforce_response(shaped, command="cmd")["value"] == shaped["value"], "own output passes the check"


@pytest.mark.parametrize("mode", sorted(MODES))
def test_counterexample_1_verbatim_keeps_identity_and_no_target(mode):
    users, binding = MODES[mode]
    for observed in (True, False):
        out = tuc.sanitise_response({"value": [deepcopy(COUNTEREXAMPLE_1)]}, users, binding, observed=observed)
        assert _leaks(out) == []
        (row,) = out["value"]
        assert row["Identity"] == "Default" and row[COVERAGE]["state"] != "known"


@pytest.mark.parametrize("carrier", sorted(NESTED_CARRIERS))
def test_callback_row_with_a_nested_target_subtree_is_refused(carrier):
    field, value = NESTED_CARRIERS[carrier]
    good = tuc.sanitise_response({"value": [{**SETTINGS, "TargetedUsersToProtect": list(TARGETS)}]}, USERS, BINDING,
                                 observed=True)
    assert tuc.enforce_response(deepcopy(good), command="cmd")["value"] == good["value"]
    bad = deepcopy(good)
    bad["value"][0][field] = deepcopy(value)
    with pytest.raises(tuc.BoundaryError) as caught:
        tuc.enforce_response(bad, command="cmd")
    assert _leaks(str(caught.value), repr(caught.value)) == []


@pytest.fixture
def live(monkeypatch):
    """Replace the child process at the adapter's bounded-run seam; returns a function that plants its output."""
    monkeypatch.setattr(pg.shutil, "which", lambda name: "pwsh-stub" if name == "pwsh" else None)

    def plant(stdout: str, stderr: str = "", *, code: int = 0):
        data = stdout.encode("utf-8")

        def fake(argv, **_kwargs):
            return SimpleNamespace(returncode=code, stdout=bytearray(data), stderr=stderr, stdout_total=len(data),
                                   stderr_total=len(stderr.encode("utf-8")), overflow=False, timed_out=False,
                                   duration_ms=1.0, pid=0)
        monkeypatch.setattr(pg, "_run_bounded", fake)
    return plant


def _run(**kwargs):
    events = []
    response = PowerShellGraphAdapter().run(
        ANTI_PHISH, log_event=lambda kind, message, details: events.append((kind, message, details)), **kwargs)
    return response, events


def _completed_classes(events):
    return [details.get("error_class") for kind, _m, details in events if kind == "command.completed"]


@pytest.mark.parametrize("callback", [False, True])
@pytest.mark.parametrize("carrier", ["domains-list-of-dict", "action-encoded-json", "name-escaped-key",
                                     "domains-mixed-lower"])
def test_live_adapter_drops_nested_targets_with_and_without_the_collector_callback(live, carrier, callback):
    field, value = NESTED_CARRIERS[carrier]
    live(json.dumps([{**SETTINGS, field: value, "TargetedUsersToProtect": TARGETS}, deepcopy(COUNTEREXAMPLE_1)]),
         f"WARNING: {UNCONF_NAME}\n")
    transform = partial(tuc.sanitise_response, sensitive_users=USERS, binding=BINDING, observed=True)
    response, events = _run(**({"response_transform": transform} if callback else {}))
    assert _leaks(response, events) == []
    first, second = response["value"]
    assert _settings_without(first, field) == _expected_settings(field)
    assert first[COVERAGE]["state"] == ("known" if callback else "not_collected")
    assert second["Identity"] == "Default" and second[COVERAGE]["state"] != "known"
    assert _completed_classes(events) == [None]


# ---------------------------------------------------------------------------------------------------------------
# Finding 2: unsupported sample layouts, encoded carriers and value-bearing diagnostics.


@pytest.mark.parametrize("mode", sorted(MODES))
@pytest.mark.parametrize("layout", sorted(SAMPLE_LAYOUTS))
def test_unsupported_sample_layouts_copy_no_protected_material(layout, mode):
    users, binding = MODES[mode]
    sample = {**SAMPLE_LAYOUTS[layout](), "identity": deepcopy(UNRELATED)}
    source = deepcopy(sample)
    out = tuc.sanitise_sample(sample, users, binding)
    assert _leaks(out) == [], layout
    assert sample == source, "the source sample is never modified"
    assert out["identity"] == UNRELATED, "a section outside the affected component is kept"


def test_counterexample_2_keeps_unrelated_operations_and_commands():
    sample = deepcopy(COUNTEREXAMPLE_2)
    sample["exchange_policy"].update(deepcopy(HEALTHY), transportConfig=deepcopy(TRANSPORT))
    for users, binding in MODES.values():
        out = tuc.sanitise_sample(sample, users, binding)
        assert _leaks(out) == []
        section = out["exchange_policy"]
        assert {name: section[name] for name in HEALTHY} == HEALTHY
        assert section["transportConfig"] == TRANSPORT, "a non-sensitive command and its rows are unchanged"
        legacy = section.get("legacyAntiPhish", {})
        assert not {"stdout", "stderr", "message"} & set(legacy)
        assert legacy.get("error") in KNOWN_CLASSES, "a removed component keeps no value-bearing diagnostic"


def test_deep_sample_section_fails_closed_without_escaping():
    deep, bottom = _deep_carrier()
    sample = {"exchange_policy": {"deep": deep, **deepcopy(HEALTHY)}, "identity": deepcopy(UNRELATED)}
    out = tuc.sanitise_sample(sample, USERS, BINDING)
    assert _leaks(out) == [] and out["identity"] == UNRELATED
    assert _depth(out) < 200, "an over-deep subtree is discarded, not copied"
    assert bottom["TargetedUsersToProtect"] == [UNCONF_EMAIL], "the source is never modified"


def test_recognised_rows_and_fixed_metadata_survive_beside_carriers():
    envelope = {"status": "ok", "command": ANTI_PHISH, "return_code": 0, "duration_ms": 12.5,
                "value": [{**SETTINGS, "TargetedUsersToProtect": list(TARGETS)},
                          {**SETTINGS, "Identity": "Old", "Name": "Old", "IsDefault": False, COVERAGE: {
                              "version": 1, "state": "known", "input_hmac_sha256": "ab" * 32, "input_count": 2,
                              "protected_nonempty": True, "missing_count": 0}}]}
    sample = {**deepcopy(COUNTEREXAMPLE_2), "identity": deepcopy(UNRELATED)}
    sample["exchange_policy"].update(deepcopy(HEALTHY), antiPhishPolicies=envelope, transportConfig=deepcopy(TRANSPORT))
    out = tuc.sanitise_sample(sample, USERS, BINDING)
    assert _leaks(out) == []
    anti = out["exchange_policy"]["antiPhishPolicies"]
    assert (anti["status"], anti["return_code"], anti["duration_ms"]) == ("ok", 0, 12.5)
    assert anti.get("command") in (None, ANTI_PHISH)
    fresh, old = anti["value"]
    assert _settings_without(fresh, None) == SETTINGS
    assert fresh[COVERAGE] == {"version": 1, "state": "known", "input_hmac_sha256": BINDING.input_hmac_sha256,
                               "input_count": 2, "protected_nonempty": True, "missing_count": 0}
    assert old[COVERAGE] == {"version": 1, "state": "not_collected"}, "an old summary alone is never rebound"


@pytest.mark.parametrize("mode", sorted(MODES))
def test_resume_never_carries_encoded_or_diagnostic_target_text(mode):
    users, binding = MODES[mode]
    payload = {
        "antiPhishPolicies": {"status": "ok", "value": [{**SETTINGS, COVERAGE: {"version": 1,
                                                                                 "state": "not_collected"}}]},
        **deepcopy(COUNTEREXAMPLE_2["exchange_policy"]),
        "transportConfig": deepcopy(TRANSPORT),
    }
    source = deepcopy(payload)
    minimised, reusable = tuc.resume_payload(payload, users, binding)
    assert _leaks(minimised) == []
    assert payload == source
    assert reusable is False, "a payload that carried target text is never reused as it was"
    assert minimised.get("transportConfig") == TRANSPORT


# The composed Opus review's F2 shape verbatim: a dict under Name, through the sample and resume copies.
REVIEW_F2 = {"antiPhishPolicies": {"value": [{"Identity": "Default",
                                              "Name": {"TargetedUsersToProtect": ["Zebulon Quarkwright"]}}]}}


@pytest.mark.parametrize("mode", sorted(MODES))
def test_review_f2_shape_leaves_the_sample_and_resume_copies_clean(mode):
    users, binding = MODES[mode]
    out = tuc.sanitise_sample({"exchange_policy": deepcopy(REVIEW_F2)}, users, binding)
    assert _leaks(out) == []
    assert out["exchange_policy"]["antiPhishPolicies"]["value"][0]["Identity"] == "Default"
    payload = deepcopy(REVIEW_F2)
    minimised, reusable = tuc.resume_payload(payload, users, binding)
    assert _leaks(minimised) == [] and reusable is False
    assert payload == REVIEW_F2


# ---------------------------------------------------------------------------------------------------------------
# Finding 3: closed diagnostic vocabulary, from envelopes and from a callback.


def _clean_response():
    return tuc.sanitise_response({"value": [{**SETTINGS, "TargetedUsersToProtect": list(TARGETS)}]}, USERS, BINDING,
                                 observed=True)


MALICIOUS_SLOTS = [*((slot, ONE_TOKEN) for slot in TEXT_SLOTS),
                   ("error", f"command_failed:{ONE_TOKEN}"), ("error_class", f"command_error:{ONE_TOKEN}"),
                   ("error", f"command_failed:1:{ONE_TOKEN}"), ("status", f"ok:{ONE_TOKEN}"),
                   ("return_code", ONE_TOKEN), ("duration_ms", [ONE_TOKEN]), ("stdout_bytes", {"n": ONE_TOKEN}),
                   ("complete", ONE_TOKEN), ("collection_truncated", [ONE_TOKEN])]


@pytest.mark.parametrize(("slot", "value"), MALICIOUS_SLOTS)
def test_enforce_refuses_one_token_names_in_every_envelope_slot(slot, value):
    bad = {**_clean_response(), slot: value}
    with pytest.raises(tuc.BoundaryError) as caught:
        tuc.enforce_response(bad, command="cmd")
    assert _leaks(str(caught.value), repr(caught.value)) == []


CANONICAL = [("error_class", value) for value in sorted(KNOWN_CLASSES - {None})] + [
    ("error", "command_failed:1"), ("error", "command_failed:-9"), ("error", "command_output_parse_error"),
    ("error", "command_output_over_limit"), ("error", "command_timeout"), ("error", "command_exception"),
    ("error", "command_output_empty"), ("state", "over_limit"), ("status", "ok"), ("status", "failed"),
    ("error_class", None),
]


# The closed admission accepts a canonical token only in the envelope the adapter itself writes around it: a success
# (``status: ok``, ``error_class: None``) exits 0 and, on replay of an empty list, states its health; a failure-only
# token (``status: failed``, ``state: over_limit``) travels with the fixed class beside it, as in the adapter's
# failure and over-limit returns. Every other canonical token is already an explicit failure class.
CANONICAL_ENVELOPE = {
    ("status", "ok"): {"return_code": 0},
    ("error_class", None): {"return_code": 0, "status": "ok"},
    ("status", "failed"): {"error_class": "command_error"},
    ("state", "over_limit"): {"error": "command_output_over_limit", "error_class": "command_error"},
}


@pytest.mark.parametrize(("slot", "value"), CANONICAL)
def test_canonical_classes_keep_their_behaviour(slot, value):
    envelope = {"return_code": 1, **CANONICAL_ENVELOPE.get((slot, value), {})}
    good = {**_clean_response(), slot: value, "duration_ms": 3.5, "complete": True, **envelope}
    enforced = tuc.enforce_response(deepcopy(good), command="cmd")
    assert enforced[slot] == value and enforced["return_code"] == envelope["return_code"]
    assert enforced["complete"] is True
    assert {key: enforced[key] for key in envelope} == envelope, "the companion class is kept, never upgraded"
    replayed = tuc.sanitise_response({"value": [], slot: value, **envelope}, None, None, observed=False)
    assert replayed[slot] == value, "a canonical source value is kept as it was"
    assert {key: replayed[key] for key in envelope} == envelope


@pytest.mark.parametrize("slot", TEXT_SLOTS)
@pytest.mark.parametrize("observed", [True, False])
def test_sanitiser_never_keeps_a_one_token_name(slot, observed):
    response = {"value": [{**SETTINGS, "TargetedUsersToProtect": list(TARGETS)}], slot: ONE_TOKEN}
    if slot == "error":
        response["error_class"] = "command_error"  # counterexample 3 verbatim, with rows beside it
    out = tuc.sanitise_response(response, USERS, BINDING, observed=observed)
    assert _leaks(out) == []
    tuc.enforce_response(deepcopy(out), command="cmd")
    if slot == "error":
        assert "error" in out and out.get("error_class") in KNOWN_CLASSES - {None}, "the failure is kept"
    if slot == "error_class":
        assert out.get("error_class") in KNOWN_CLASSES - {None}, "the failure is kept"


def _malicious(slot, value):
    def transform(response):
        return {**tuc.sanitise_response(response, USERS, BINDING, observed=True), slot: value}
    return transform


def _nested_row_callback(response):
    shaped = tuc.sanitise_response(response, USERS, BINDING, observed=True)
    shaped["value"][0]["TargetedDomainsToProtect"] = [{"TargetedUsersToProtect": [UNCONF_EMAIL]}]
    return shaped


@pytest.mark.parametrize("transform", [
    *(_malicious(slot, value) for slot, value in MALICIOUS_SLOTS),
    _nested_row_callback,
    lambda response: ONE_TOKEN,
    lambda response: {"value": ONE_TOKEN},
    lambda response: {"value": [{"Identity": UNCONF_NAME}]},
], ids=[*(f"{slot}-{i}" for i, (slot, _v) in enumerate(MALICIOUS_SLOTS)), "nested-row", "scalar", "scalar-rows",
        "row-without-summary"])
def test_malicious_callback_output_never_reaches_an_event_or_the_return(live, transform):
    live(json.dumps([{**SETTINGS, "TargetedUsersToProtect": TARGETS}]))
    response, events = _run(response_transform=transform)
    assert _leaks(response, events) == []
    assert response.get("error_class") in KNOWN_CLASSES, "a refused callback becomes a fixed class"
    assert all(value in KNOWN_CLASSES for value in _completed_classes(events))
    assert all(type(response[key]) in (int, float) for key in ("return_code", "duration_ms") if key in response)


@pytest.mark.parametrize("code", [0, 1])
def test_live_one_token_stdout_and_stderr_never_become_a_class(live, code):
    live(json.dumps({"error": ONE_TOKEN, "error_class": ONE_TOKEN, "status": ONE_TOKEN, "value": [
        {**SETTINGS, "TargetedUsersToProtect": TARGETS}]}), ONE_TOKEN, code=code)
    for kwargs in ({}, {"response_transform": partial(tuc.sanitise_response, sensitive_users=USERS, binding=BINDING,
                                                      observed=True)}):
        response, events = _run(**kwargs)
        assert _leaks(response, events) == []
        assert response.get("error_class") in KNOWN_CLASSES
        assert all(value in KNOWN_CLASSES for value in _completed_classes(events))


# ---------------------------------------------------------------------------------------------------------------
# Whole offline flow: the real sample-copy path, every generated file, and SS 2.1-2.4 parity.


def _replay(tmp_path: Path, sample: dict, *, users=CONFIGURED, name="r1"):
    path = tmp_path / f"{name}-sample.json"
    path.write_text(json.dumps(sample))
    before = path.read_bytes()
    out = tmp_path / f"out-{name}"
    cli.run_offline(path, out, "acme", name, sensitive_users=SensitiveUsers(tuple(sorted(users))) if users else None)
    assert path.read_bytes() == before, "the source sample is never modified"
    return out / f"acme-{name}"


def _scan(root: Path, *, private=("operator-inputs/sensitive-users.txt",)):
    leaks = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes().decode("utf-8", "replace")
        folded = data.casefold()
        for fragment in FRAGMENTS:
            allowed = fragment == "configured-r1canary" and relative in private
            if fragment in folded and not allowed:
                leaks.append((relative, fragment))
        if TARGET_KEY.search(data):
            leaks.append((relative, "target key"))
    return leaks


def _flow_sample(*, carriers: bool, extra_row: bool = False):
    rows = [{**SETTINGS, "TargetedUsersToProtect": list(TARGETS)}]
    sample = {"exchange_policy": {**deepcopy(HEALTHY), "transportConfig": deepcopy(TRANSPORT),
                                  "antiPhishPolicies": {"status": "ok", "value": rows}},
              "identity": deepcopy(UNRELATED)}
    if carriers:
        rows[0]["Extra"] = json.dumps({"TargetedUsersToProtect": [UNCONF_EMAIL]})
        if extra_row:  # a second Default row would change the SS 2.x records, so parity runs without it
            rows.append(deepcopy(COUNTEREXAMPLE_1))
        for layout in ("counterexample-2", "nested-double-encoded-with-detail", "legacy-keyless-encoded-array"):
            for name, value in SAMPLE_LAYOUTS[layout]()["exchange_policy"].items():
                sample["exchange_policy"][name] = value
        sample.update(SAMPLE_LAYOUTS["flat-top-upper-key-and-note"]())
    return sample


@pytest.mark.parametrize("users", [CONFIGURED, None], ids=["configured", "unconfigured"])
def test_offline_flow_writes_no_canary_to_any_generated_file(tmp_path, capsys, caplog, users):
    run_dir = _replay(tmp_path, _flow_sample(carriers=True, extra_row=True), users=users)
    assert _scan(run_dir, private=("operator-inputs/sensitive-users.txt",) if users else ()) == []
    captured = capsys.readouterr()
    assert _leaks(captured.out, captured.err, caplog.text) == []
    if users:
        private = (run_dir / "operator-inputs/sensitive-users.txt").read_text()
        assert private == "\n".join(sorted(CONFIGURED)) + "\n", "the private operator copy is unchanged"
    sample_copy = json.loads((run_dir / "raw/sample_input.json").read_text())
    assert "identity" in sample_copy and "transportConfig" in sample_copy["exchange_policy"]


def test_offline_flow_counterexample_3_envelope(tmp_path):
    sample = {"exchange_policy": {**deepcopy(HEALTHY), **SAMPLE_LAYOUTS["one-token-error-recognised"]()[
        "exchange_policy"]}, "identity": deepcopy(UNRELATED)}
    run_dir = _replay(tmp_path, sample, name="r1ce3")
    assert _scan(run_dir) == []


def test_ss21_to_ss24_records_match_a_carrier_free_control(tmp_path):
    from auditex.scuba_projection import project_run, rule_policy_section
    from azure_tenant_audit.value_rules import assess

    def records(run_dir):
        projection = project_run(run_dir)
        result = {}
        for policy in ("MS.SECURITYSUITE.2.1v1", "MS.SECURITYSUITE.2.2v1", "MS.SECURITYSUITE.2.3v1",
                       "MS.SECURITYSUITE.2.4v1"):
            sections = deepcopy(projection.rule_sections)
            sections["scuba_config"] = rule_policy_section(projection, policy, "scuba_config")
            record = assess(policy, sections)
            result[policy] = (record["verdict"], record["cell"], record.get("reason_code"))
        return result

    def rows(run_dir):
        copied = json.loads((run_dir / "raw/sample_input.json").read_text())["exchange_policy"]["antiPhishPolicies"]
        return [({k: v for k, v in row.items() if k != COVERAGE},
                 {k: v for k, v in row[COVERAGE].items() if k != "input_hmac_sha256"}) for row in copied["value"]]

    control = _replay(tmp_path, _flow_sample(carriers=False), name="control")
    repaired = _replay(tmp_path, _flow_sample(carriers=True), name="carriers")
    assert _scan(repaired) == []
    assert records(repaired) == records(control)
    assert records(control)["MS.SECURITYSUITE.2.1v1"][0] == "met"
    assert rows(repaired) == rows(control)


@pytest.mark.parametrize("transform", [lambda response: {}, lambda response: {"status": "ok"},
                                       lambda response: {"complete": True, "return_code": 0}])
def test_callback_success_without_rows_is_refused(live, transform):
    live(json.dumps([{**SETTINGS, "TargetedUsersToProtect": TARGETS}]))
    response, events = _run(response_transform=transform)
    assert _leaks(response, events) == []
    assert response.get("error_class") in KNOWN_CLASSES - {None}, "an empty success never stands for a read"
