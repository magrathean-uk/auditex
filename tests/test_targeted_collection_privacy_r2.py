"""SS 2.1 collector privacy repair, round 2: the two findings of the frozen-commit review of R1 and their neighbours.

1. A component that carries the target only through a mapping below it (a ``value`` row, a nested object, an encoded
   string inside one) kept its own diagnostic text: the verbatim ``transportConfig`` envelope and the flat top-level
   ``antiPhishPolicies`` envelope, then every ancestor shape between the sample root and the row.
2. Safe reduction dropped health and truncation markers (``truncation_reason`` had an empty vocabulary; unknown
   ``status``, ``bounded_sample``, ``incomplete``, ``partial``, ``@odata.nextLink``, non-boolean ``complete`` and the rest
   were not carried), so a cut or failed anti-phish read could replay as a healthy one and meet SS 2.1.

Imports only APIs that already exist at R1 (40af343), so there this module collects and fails on its assertions, never
on an import. Constructed data only: no tenant, network, PowerShell or model.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re

import pytest

from azure_tenant_audit import cli
from azure_tenant_audit.collection_gaps import TRUNCATION_REASONS
from azure_tenant_audit.collectors import targeted_users_coverage as tuc
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
from azure_tenant_audit.sensitive_users import SensitiveUsers
from azure_tenant_audit.value_rules.defender_targeted_users import SensitiveUsersBinding

COVERAGE = "TargetedUsersCoverage"
COMMANDS = dict(ExchangePolicyCollector.command_collectors)
OTHER = COMMANDS["transportConfig"]

# Configured (in the operator list) and unconfigured canaries: address, name, domain and a malformed entry.
CONFIGURED = ("r2-conf-a@configured-r2canary.invalid", "r2-conf-b@configured-r2canary.invalid")
CONFIGURED_NAME = "Peregrine Thistlewood"
UNCONF_EMAIL = "zq-canary@unlisted-canary.invalid"
UNCONF_NAME = "Zebulon Quarkwright"
UNCONF_DOMAIN = "r2canary-domain.invalid"
MALFORMED = "Name;;bad@@r2canary-malformed"
FRAGMENTS = ("zebulon", "quarkwright", "zq-canary", "unlisted-canary", "peregrine", "thistlewood",
             "configured-r2canary", "r2canary-domain", "r2canary-malformed")
TARGETS = [f"{CONFIGURED_NAME};{CONFIGURED[0]}", CONFIGURED[1].upper(), f"{UNCONF_NAME};{UNCONF_EMAIL}",
           UNCONF_DOMAIN, MALFORMED]
USERS = SensitiveUsers(tuple(sorted(CONFIGURED)))
BINDING = SensitiveUsersBinding(2, "ef" * 32)
MODES = {"configured": (USERS, BINDING), "unconfigured": (None, None)}
TARGET_KEY = re.compile(r"(?:t|\\+u0054)argeted_?users_?to_?protect\\*[\"']\s*:", re.IGNORECASE)
KNOWN_ERRORS = {"command_error", "command_parse_error", "command_timeout", "command_exception", "command_not_found",
                "command_not_authenticated", "session_not_connected", "module_not_found", "command_output_empty",
                "command_output_parse_error", "command_output_over_limit", "command_empty", "command_not_found:pwsh"}

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
    "acceptedDomains", "eopProtectionPolicyRules", "atpProtectionPolicyRules", "atpPolicyForO365")}
RULES = {"status": "ok", "value": [{"Name": "Ordinary rule", "Comments": "Ordinary unrelated text", "Priority": 0}]}
TRANSPORT = {"command": OTHER, "status": "ok", "value": [{"Identity": "T", "SmtpClientAuthenticationDisabled": True}]}
UNRELATED = {"users": {"status": "ok", "value": [{"id": "u-1", "displayName": "Ordinary Person", "enabled": True}]}}

# Finding 1, verbatim.
FINDING_1 = {"exchange_policy": {"transportConfig": {
    "error": "failed for Zebulon Quarkwright",
    "value": [{"TargetedUsersToProtect": ["zq-canary@unlisted-canary.invalid"]}]}}}
FLAT_ENVELOPE = {"antiPhishPolicies": {
    "error": f"failed for {UNCONF_NAME}", "value": [{"TargetedUsersToProtect": [UNCONF_EMAIL, CONFIGURED[0]]}]}}


def _target(*extra):
    return {"TargetedUsersToProtect": [UNCONF_EMAIL, CONFIGURED_NAME, *extra]}


# Ancestors whose only target-bearing material sits in a mapping, list or encoded string below them, each with its
# own value-bearing diagnostic text. Every layout keeps ``identity`` and the healthy exchange operations beside it.
ANCESTORS = {
    "known-op-nested-details": lambda: {"exchange_policy": {"transportConfig": {
        **deepcopy(TRANSPORT), "details": {"inner": _target()}, "message": f"failed for {UNCONF_NAME}"}}},
    "known-op-row-nested-object": lambda: {"exchange_policy": {"transportConfig": {
        "status": "ok", "error": f"denied for {CONFIGURED_NAME}",
        "value": [{"Identity": "T", "Nested": _target(UNCONF_DOMAIN), "Comment": f"for {UNCONF_NAME}"}]}}},
    "known-op-list-of-lists": lambda: {"exchange_policy": {"transportConfig": {
        "error_class": "command_error", "error": f"{UNCONF_DOMAIN} failed", "value": [[_target(MALFORMED)]]}}},
    "known-op-encoded-below-mapping": lambda: {"exchange_policy": {"transportConfig": {
        "status": "ok", "stderr": f"WARNING: {UNCONF_NAME}",
        "value": [{"Identity": "T", "Blob": {"b": json.dumps(json.dumps(_target()))}}]}}},
    "known-op-escaped-key-below-mapping": lambda: {"exchange_policy": {"transportConfig": {
        "status": "ok", "reason": f"{UNCONF_NAME}",
        "value": [{"Identity": "T", "Blob": {"b": '{"\\u0054argetedUsersToProtect":["%s"]}' % UNCONF_EMAIL}}]}}},
    "other-collector-op": lambda: {"legacy_export": {
        "someOp": {"error": f"failed for {UNCONF_NAME}", "value": [_target()]},
        "otherOp": {"status": "ok", "value": [{"id": "x-1", "note": "Ordinary unrelated text"}]}}},
    "flat-envelope-nested-details": lambda: {"antiPhishPolicies": {
        "status": "ok", "value": [], "details": {"x": _target()}, "message": UNCONF_NAME}},
    "root-row-list": lambda: {"legacyAntiPhish": [{"Identity": "X", "Nested": _target(), "note": UNCONF_NAME}]},
    "root-note-beside-bearing-section": lambda: {"note": f"failed for {UNCONF_NAME}", **deepcopy(FINDING_1)},
    "unknown-op-nested-details": lambda: {"exchange_policy": {"legacyAntiPhish": {
        "details": {"deeper": [_target()]}, "error": f"failed for {UNCONF_NAME}", "stdout": UNCONF_DOMAIN}}},
}


def _strings(value):
    """Every key and scalar in ``value`` as text, walked without recursion."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                yield "key", str(key)
                stack.append(child)
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
        elif item is not None:
            yield "value", item if isinstance(item, str) else str(item)


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


def _with_neighbours(sample):
    out = deepcopy(sample)
    section = out.setdefault("exchange_policy", {})
    for name, value in {**HEALTHY, "antiPhishRules": RULES, "transportConfig": TRANSPORT}.items():
        section.setdefault(name, deepcopy(value))
    out.setdefault("identity", deepcopy(UNRELATED))
    return out


# ---------------------------------------------------------------------------------------------------------------
# Finding 1: target-bearing ancestors keep no diagnostic text.


@pytest.mark.parametrize("mode", sorted(MODES))
@pytest.mark.parametrize("sample", [FINDING_1, FLAT_ENVELOPE], ids=["finding-1-verbatim", "flat-top-level"])
def test_finding_1_envelopes_keep_the_failure_but_no_text(sample, mode):
    users, binding = MODES[mode]
    source = deepcopy(sample)
    out = tuc.sanitise_sample(sample, users, binding)
    assert _leaks(out) == []
    assert sample == source, "the source sample is never modified"
    envelope = out["exchange_policy"]["transportConfig"] if "exchange_policy" in sample else out["antiPhishPolicies"]
    assert envelope.get("error") in KNOWN_ERRORS, "the failure stays a failure, as fixed text"
    assert isinstance(envelope.get("value"), list) and _leaks(envelope["value"]) == []


@pytest.mark.parametrize("mode", sorted(MODES))
@pytest.mark.parametrize("layout", sorted(ANCESTORS))
def test_ancestor_layouts_keep_no_diagnostic_and_keep_unrelated_evidence(layout, mode):
    users, binding = MODES[mode]
    sample = _with_neighbours(ANCESTORS[layout]())
    source = deepcopy(sample)
    out = tuc.sanitise_sample(sample, users, binding)
    assert _leaks(out) == [], layout
    assert sample == source, "the source sample is never modified"
    assert out["identity"] == UNRELATED, "another collector is never reduced"
    section = out["exchange_policy"]
    assert {name: section[name] for name in HEALTHY} == HEALTHY, "sibling operations are kept as they were"
    assert section["antiPhishRules"] == RULES, "unrelated text in a component that carries no target is kept"
    if "transportConfig" not in ANCESTORS[layout]().get("exchange_policy", {}):
        assert section["transportConfig"] == TRANSPORT
    if layout == "other-collector-op":
        assert out["legacy_export"]["otherOp"] == ANCESTORS[layout]()["legacy_export"]["otherOp"]


def test_failed_ancestor_stays_failed_and_its_safe_rows_stay():
    sample = _with_neighbours(ANCESTORS["known-op-row-nested-object"]())
    sample["exchange_policy"]["transportConfig"]["value"].append({"Identity": "U", "SmtpClientAuthenticationDisabled": True})
    out = tuc.sanitise_sample(sample, USERS, BINDING)["exchange_policy"]["transportConfig"]
    assert out.get("error") in KNOWN_ERRORS and out.get("status") == "ok"
    assert {"Identity": "U", "SmtpClientAuthenticationDisabled": True} in out["value"], "a row with no target is kept"


def test_deep_ancestor_fails_closed_without_escaping():
    node = _target()
    for _ in range(120):
        node = {"down": node, "note": UNCONF_NAME}
    sample = _with_neighbours({"exchange_policy": {"transportConfig": {"status": "ok", "value": [node]}}})
    out = tuc.sanitise_sample(sample, USERS, BINDING)
    assert _leaks(out) == [] and out["identity"] == UNRELATED


def test_resume_never_reuses_a_known_operation_with_a_nested_target():
    payload = {**deepcopy(HEALTHY), "antiPhishRules": deepcopy(RULES),
               **deepcopy(ANCESTORS["known-op-row-nested-object"]()["exchange_policy"])}
    for users, binding in MODES.values():
        minimised, reusable = tuc.resume_payload(payload, users, binding)
        assert reusable is False and _leaks(minimised) == []
        assert minimised["antiPhishRules"] == RULES


# ---------------------------------------------------------------------------------------------------------------
# Finding 2: health and truncation markers survive safe reduction as fixed tokens.

UNSAFE = [
    ("truncation_reason", "operator_limit"), ("truncation_reason", "pagination_failed"),
    ("truncation_reason", UNCONF_NAME), ("truncation_reason", ["x"]),
    ("status", "error"), ("status", "unknown"), ("status", "partial"), ("status", UNCONF_NAME), ("status", 1),
    ("collection_status", "partial"), ("collection_status", UNCONF_EMAIL), ("read_state", "denied"),
    ("bounded_sample", True), ("bounded_sample", "yes"), ("incomplete", True), ("partial", True), ("partial", 1),
    ("@odata.nextLink", f"https://graph.invalid/next?skip={UNCONF_EMAIL}"),
    ("resolver_error", f"failed for {UNCONF_NAME}"), ("complete", False), ("complete", "false"), ("complete", 0),
    ("complete", None), ("collection_truncated", True), ("collection_truncated", "yes"), ("collection_truncated", 1),
]
SAFE = [("status", "ok"), ("status", "success"), ("status", "collected"), ("status", "complete"),
        ("complete", True), ("collection_truncated", False), ("truncation_reason", None), ("bounded_sample", False),
        ("partial", False), ("incomplete", None)]


def _unhealthy(envelope):
    from auditex.scuba_projection import Unavailable, _healthy

    try:
        _healthy(envelope)
    except Unavailable:
        return True
    return False


def _marked(key, value):
    return {"status": "ok", key: value, "value": [{**SETTINGS, "TargetedUsersToProtect": list(CONFIGURED)}]}


@pytest.mark.parametrize("observed", [True, False])
@pytest.mark.parametrize(("key", "value"), UNSAFE, ids=[f"{k}-{i}" for i, (k, _v) in enumerate(UNSAFE)])
def test_recognised_read_keeps_every_refusal_marker(key, value, observed):
    out = tuc.sanitise_response(_marked(key, value), USERS, BINDING, observed=observed)
    assert _leaks(out) == []
    assert _unhealthy(out), "a cut or failed read never reads as healthy to the projection"
    if key in cli._UNHEALTHY_SECTION_KEYS or key == "status":
        assert cli._healthy_section(out) is False, "nor to the resume publisher"
    if key == "truncation_reason" and isinstance(value, str):
        assert out[key] in TRUNCATION_REASONS and (value not in TRUNCATION_REASONS or out[key] == value)
    if key == "status" and value == "partial":
        assert out[key] == "partial"
    tuc.enforce_response(deepcopy(out), command="cmd")  # the closed result is also a valid callback result


@pytest.mark.parametrize(("key", "value"), SAFE, ids=[f"{k}-{i}" for i, (k, _v) in enumerate(SAFE)])
def test_healthy_markers_stay_healthy(key, value):
    out = tuc.sanitise_response(_marked(key, value), USERS, BINDING, observed=False)
    assert not _unhealthy(out) and out["value"][0][COVERAGE]["state"] == "known"
    tuc.enforce_response(deepcopy(out), command="cmd")


def test_legacy_limit_marker_still_replays_as_cut():
    from azure_tenant_audit.collection_gaps import section_was_cut

    out = tuc.sanitise_response(_marked("collection_limit_reached", True), USERS, BINDING, observed=False)
    assert section_was_cut(out), "an older section that only says its limit was reached still replays as cut"
    reduced = tuc.sanitise_sample({"exchange_policy": {"transportConfig": {
        "collection_limit_reached": "yes", "value": [{"Nested": _target()}]}}}, USERS, BINDING)
    assert section_was_cut(reduced["exchange_policy"]["transportConfig"]) and _leaks(reduced) == []


@pytest.mark.parametrize(("key", "value"), UNSAFE, ids=[f"{k}-{i}" for i, (k, _v) in enumerate(UNSAFE)])
def test_reduced_component_keeps_every_refusal_marker(key, value):
    sample = _with_neighbours({"exchange_policy": {"transportConfig": {
        "status": "ok", key: value, "value": [{"Identity": "T", "Nested": _target()}]}}})
    out = tuc.sanitise_sample(sample, USERS, BINDING)
    assert _leaks(out) == []
    assert _unhealthy(out["exchange_policy"]["transportConfig"])


# ---------------------------------------------------------------------------------------------------------------
# Whole offline flow: producer -> offline replay -> project_run -> assess, every generated file and the console.


def _replay(tmp_path: Path, sample: dict, *, users=CONFIGURED, name="r2"):
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
            if fragment in folded and not (fragment == "configured-r2canary" and relative in private):
                leaks.append((relative, fragment))
        if TARGET_KEY.search(data):
            leaks.append((relative, "target key"))
    return leaks


def _records(run_dir):
    from auditex.scuba_projection import project_run, rule_policy_section
    from azure_tenant_audit.value_rules import assess

    projection = project_run(run_dir)
    result = {}
    for policy in ("MS.SECURITYSUITE.2.1v1", "MS.SECURITYSUITE.2.2v1", "MS.SECURITYSUITE.2.3v1",
                   "MS.SECURITYSUITE.2.4v1"):
        sections = deepcopy(projection.rule_sections)
        sections["scuba_config"] = rule_policy_section(projection, policy, "scuba_config")
        record = assess(policy, sections)
        result[policy] = (record["verdict"], record["cell"], record.get("reason_code"))
    return result


def _flow(anti_phish_extra=None, *, carriers=False):
    envelope = {"status": "ok",
                "value": [{**SETTINGS, "TargetedUsersToProtect": list(TARGETS)}], **(anti_phish_extra or {})}
    sample = _with_neighbours({"exchange_policy": {"antiPhishPolicies": envelope}})
    if carriers:  # target carriers outside every operation SS 2.1-2.4 read
        for layout in ("other-collector-op", "flat-envelope-nested-details", "root-row-list",
                       "unknown-op-nested-details"):
            for name, value in ANCESTORS[layout]().items():
                if name == "exchange_policy":
                    sample[name].update(value)
                else:
                    sample[name] = value
        sample["note"] = f"failed for {UNCONF_NAME}"
    return sample


@pytest.mark.parametrize("users", [CONFIGURED, None], ids=["configured", "unconfigured"])
def test_offline_flow_with_finding_1_writes_no_canary_anywhere(tmp_path, capsys, caplog, users):
    sample = _flow(carriers=True)
    sample["exchange_policy"]["transportConfig"] = deepcopy(FINDING_1["exchange_policy"]["transportConfig"])
    sample.update(deepcopy(FLAT_ENVELOPE))
    run_dir = _replay(tmp_path, sample, users=users)
    assert _scan(run_dir, private=("operator-inputs/sensitive-users.txt",) if users else ()) == []
    captured = capsys.readouterr()
    assert _leaks(captured.out, captured.err, caplog.text) == []
    copied = json.loads((run_dir / "raw/sample_input.json").read_text())
    assert "identity" in copied and "antiPhishRules" in copied["exchange_policy"]
    assert copied["exchange_policy"]["transportConfig"].get("error") in KNOWN_ERRORS


UNSAFE_FLOW = [("truncation_reason", "operator_limit"), ("status", "error"), ("bounded_sample", True),
               ("incomplete", True), ("partial", True), ("complete", False), ("collection_status", "partial"),
               ("@odata.nextLink", f"https://graph.invalid/next?skip={UNCONF_EMAIL}")]


@pytest.mark.parametrize(("key", "value"), UNSAFE_FLOW, ids=[key for key, _value in UNSAFE_FLOW])
def test_unsafe_recognised_read_cannot_meet_through_the_whole_flow(tmp_path, key, value):
    run_dir = _replay(tmp_path, _flow({key: value}), name="unsafe")
    assert _scan(run_dir) == []
    verdict = _records(run_dir)["MS.SECURITYSUITE.2.1v1"][0]
    assert verdict != "met", f"{key} must withhold the anti-phish section"


def test_complete_control_meets_and_carriers_keep_ss21_to_ss24_parity(tmp_path):
    control = _replay(tmp_path, _flow(), name="control")
    carried = _replay(tmp_path, _flow(carriers=True), name="carriers")
    assert _scan(carried) == []
    assert _records(control)["MS.SECURITYSUITE.2.1v1"][0] == "met"
    assert _records(carried) == _records(control)
