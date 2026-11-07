"""SS 2.1 sample minimisation: a sample-root collector section is routed by its position, not by its value types.

The frozen-commit review of 166a522 (F1) found that a collector section counted as a container of independent
operations only when every value was a mapping or a list. One scalar beside a legacy target carrier
(``schema_version: 1``) made the whole section one component, and reducing it to ``{}`` lost the healthy ``users``
operation with the carrier. Here a collector section stays a collector section: its own envelope, diagnostic and
policy slots are reduced together, and every other operation keeps its own walk and is kept unless it bears the target.

Imports only APIs that exist at 166a522, so there this module collects and fails on its assertions, never on an
import. Constructed data only: no tenant, network, PowerShell or model.
"""
from __future__ import annotations

from copy import deepcopy
import itertools
import json
from pathlib import Path
import re

import pytest

from azure_tenant_audit import cli
from azure_tenant_audit.collectors import targeted_users_coverage as tuc
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
from azure_tenant_audit.sensitive_users import SensitiveUsers
from azure_tenant_audit.value_rules.defender_targeted_users import SensitiveUsersBinding

COVERAGE = "TargetedUsersCoverage"
NOT_COLLECTED = {"version": 1, "state": "not_collected"}
COMMANDS = dict(ExchangePolicyCollector.command_collectors)

# Configured (in the operator list) and unconfigured canaries: address, name, domain and a malformed entry.
CONFIGURED = ("sm-conf-a@configured-smcanary.invalid", "sm-conf-b@configured-smcanary.invalid")
CONFIGURED_NAME = "Ottoline Brackenridge"
UNCONF_EMAIL = "zq-canary@unlisted-canary.invalid"
UNCONF_NAME = "Wystan Fennimore"
UNCONF_DOMAIN = "smcanary-domain.invalid"
MALFORMED = "Name;;bad@@smcanary-malformed"
FRAGMENTS = ("zq-canary", "unlisted-canary", "ottoline", "brackenridge", "wystan", "fennimore",
             "configured-smcanary", "smcanary-domain", "smcanary-malformed")
TARGETS = [f"{CONFIGURED_NAME};{CONFIGURED[0]}", CONFIGURED[1].upper(), f"{UNCONF_NAME};{UNCONF_EMAIL}",
           UNCONF_DOMAIN, MALFORMED]
USERS = SensitiveUsers(tuple(sorted(CONFIGURED)))
BINDING = SensitiveUsersBinding(2, "ab" * 32)
MODES = {"configured": (USERS, BINDING), "unconfigured": (None, None)}
TARGET_KEY = re.compile(r"(?:t|\\+u0054)argeted_?users_?to_?protect\\*[\"']\s*:", re.IGNORECASE)
KNOWN_ERRORS = {"command_error", "command_parse_error", "command_timeout", "command_exception", "command_not_found",
                "command_not_authenticated", "session_not_connected", "module_not_found", "command_output_empty",
                "command_output_parse_error", "command_output_over_limit", "command_empty", "command_not_found:pwsh"}

# F1, verbatim from the review.
F1 = {'identity': {'users': {'status': 'ok', 'value': [{'id': 'u-1', 'displayName': 'Ordinary'}]},
                   'schema_version': 1,
                   'legacy': {'value': [{'TargetedUsersToProtect': ['zq-canary@unlisted-canary.invalid']}]}}}
USERS_OP = {'status': 'ok', 'value': [{'id': 'u-1', 'displayName': 'Ordinary'}]}

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
# A real Get-AntiPhishRule row always carries State (exactly Enabled or Disabled, D47); without it every SS 2.x
# rule is rule_state_unusable before the policy is read. Disabled: it scopes nothing, so Default stays the policy.
RULES = {"status": "ok", "value": [{"Name": "Ordinary rule", "State": "Disabled", "Comments": "Ordinary unrelated text",
                                    "Priority": 0}]}
TRANSPORT = {"command": COMMANDS["transportConfig"], "status": "ok",
             "value": [{"Identity": "T", "SmtpClientAuthenticationDisabled": True}]}


def _carrier(*extra):
    return {"TargetedUsersToProtect": [UNCONF_EMAIL, CONFIGURED_NAME, CONFIGURED[0], UNCONF_DOMAIN, MALFORMED, *extra]}


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


def _identity(out):
    identity = out.get("identity")
    return identity if isinstance(identity, dict) else {}


# ---------------------------------------------------------------------------------------------------------------
# F1 and its permutations: scalar metadata never turns a collector section into one reducible component.


@pytest.mark.parametrize("mode", sorted(MODES))
def test_f1_counterexample_keeps_the_healthy_operation_and_its_metadata(mode):
    sample = deepcopy(F1)
    source = deepcopy(sample)
    out = tuc.sanitise_sample(sample, *MODES[mode])
    assert sample == source, "the source sample is never modified"
    assert _leaks(out) == []
    identity = _identity(out)
    assert identity.get("users") == USERS_OP, "an independent healthy operation is never reduced with the carrier"
    assert identity.get("schema_version") == 1 and type(identity["schema_version"]) is int
    legacy = identity.get("legacy", {})
    assert all(row.get(COVERAGE, NOT_COLLECTED) == NOT_COLLECTED for row in legacy.get("value", []))


METADATA = [1, 0, -7, 2.5, True, False, None, "1", "v1", ""]
ORDERS = list(itertools.permutations(("users", "schema_version", "legacy")))


@pytest.mark.parametrize("mode", sorted(MODES))
@pytest.mark.parametrize("order", ORDERS, ids=["-".join(order) for order in ORDERS])
@pytest.mark.parametrize("meta", METADATA, ids=[f"{type(v).__name__}-{i}" for i, v in enumerate(METADATA)])
def test_scalar_metadata_in_any_order_never_costs_a_healthy_operation(meta, order, mode):
    parts = {"users": deepcopy(USERS_OP), "schema_version": meta, "legacy": {"value": [_carrier()]}}
    out = tuc.sanitise_sample({"identity": {name: parts[name] for name in order}}, *MODES[mode])
    assert _leaks(out) == []
    identity = _identity(out)
    assert identity.get("users") == USERS_OP
    if type(meta) is str:
        assert "schema_version" not in identity, "free text in a bearing section goes, as at the sample root"
    else:
        assert "schema_version" in identity and identity["schema_version"] == meta
        assert type(identity["schema_version"]) is type(meta), "numbers, booleans and null are kept exactly"


PLACEMENTS = {
    "carrier-in-sibling-collector-before": lambda: {
        "legacy_export": {"schema_version": 1, "legacy": {"value": [_carrier()]}},
        "identity": {"users": deepcopy(USERS_OP), "schema_version": 1}},
    "carrier-in-sibling-collector-after": lambda: {
        "identity": {"users": deepcopy(USERS_OP), "schema_version": 1},
        "legacy_export": {"legacy": {"value": [_carrier()]}, "schema_version": 1}},
    "both-collectors-bear": lambda: {
        "identity": {"schema_version": 1, "legacy": {"value": [_carrier()]}, "users": deepcopy(USERS_OP)},
        "legacy_export": {"users": deepcopy(USERS_OP), "count": 2, "legacy": {"value": [_carrier()]}}},
    "exchange-policy-and-identity": lambda: {
        "exchange_policy": {"schema_version": 1, "legacyAntiPhish": {"value": [_carrier()]}, **deepcopy(HEALTHY)},
        **deepcopy(F1)},
    "identity-before-exchange-policy": lambda: {
        **deepcopy(F1),
        "exchange_policy": {**deepcopy(HEALTHY), "legacyAntiPhish": {"value": [_carrier()]}, "schema_version": 1}},
}


@pytest.mark.parametrize("mode", sorted(MODES))
@pytest.mark.parametrize("placement", sorted(PLACEMENTS))
def test_collector_placements_keep_every_independent_operation(placement, mode):
    sample = PLACEMENTS[placement]()
    source = deepcopy(sample)
    out = tuc.sanitise_sample(sample, *MODES[mode])
    assert sample == source and _leaks(out) == []
    assert _identity(out).get("users") == USERS_OP and _identity(out).get("schema_version") == 1
    if "legacy_export" in sample and "users" in sample["legacy_export"]:
        assert out["legacy_export"].get("users") == USERS_OP and out["legacy_export"].get("count") == 2
    if "exchange_policy" in sample:
        section = out["exchange_policy"]
        assert {name: section.get(name) for name in HEALTHY} == HEALTHY


# ---------------------------------------------------------------------------------------------------------------
# Unknown, flat, legacy and recognised shapes.


@pytest.mark.parametrize("mode", sorted(MODES))
def test_flat_collector_envelope_is_reduced_but_its_independent_operation_stays(mode):
    sample = {"identity": {
        "status": "ok", "error": f"failed for {UNCONF_NAME}", "message": f"denied {CONFIGURED_NAME}",
        "stdout": json.dumps(_carrier()), "stderr": UNCONF_DOMAIN,
        "value": [{"id": "u-2", "TargetedUsersToProtect": [UNCONF_EMAIL]}, UNCONF_NAME, {"id": "u-3"}],
        "users": deepcopy(USERS_OP), "schema_version": 1}}
    out = _identity(tuc.sanitise_sample(sample, *MODES[mode]))
    assert _leaks(out) == []
    assert out.get("users") == USERS_OP and out.get("schema_version") == 1
    assert out.get("status") == "ok" and out.get("error") in KNOWN_ERRORS, "the failure stays a failure, as a token"
    assert not {"message", "stdout", "stderr"} & set(out)
    assert {"id": "u-3"} in out.get("value", []), "a row with no target is kept"


@pytest.mark.parametrize("mode", sorted(MODES))
def test_legacy_policy_row_section_keeps_safe_fields_and_scalar_metadata(mode):
    sample = {"legacyPolicy": {"Identity": "Legacy", "Enabled": True, "TargetedUsersToProtect": list(TARGETS),
                               "note": f"set for {UNCONF_NAME}", "schema_version": 3}}
    out = tuc.sanitise_sample(sample, *MODES[mode])["legacyPolicy"]
    assert _leaks(out) == []
    assert (out.get("Identity"), out.get("Enabled"), out.get(COVERAGE)) == ("Legacy", True, NOT_COLLECTED)
    assert out.get("schema_version") == 3 and "note" not in out


@pytest.mark.parametrize("mode", sorted(MODES))
def test_unknown_root_list_and_unknown_operation_keep_their_plain_rows(mode):
    sample = {"legacyRows": [{"id": "r-1", "note": "Ordinary"}, {"Identity": "X", "Nested": _carrier()}],
              "identity": {"users": deepcopy(USERS_OP), "schema_version": 1,
                           "unknownOp": {"status": "ok", "value": [{"id": "k-1"}, {"Nested": _carrier()}]}}}
    out = tuc.sanitise_sample(sample, *MODES[mode])
    assert _leaks(out) == []
    assert {"id": "r-1", "note": "Ordinary"} in out["legacyRows"]
    identity = _identity(out)
    assert identity.get("users") == USERS_OP
    assert identity.get("unknownOp", {}).get("status") == "ok" and {"id": "k-1"} in identity["unknownOp"]["value"]


@pytest.mark.parametrize("mode", sorted(MODES))
def test_recognised_read_is_summarised_beside_the_f1_section(mode):
    users, binding = MODES[mode]
    sample = {"exchange_policy": {"antiPhishPolicies": {
        "status": "ok", "value": [{**SETTINGS, "TargetedUsersToProtect": list(TARGETS)}]}}, **deepcopy(F1)}
    out = tuc.sanitise_sample(sample, users, binding)
    assert _leaks(out) == []
    row = out["exchange_policy"]["antiPhishPolicies"]["value"][0]
    assert {key: row[key] for key in SETTINGS} == SETTINGS
    expected = ({"version": 1, "state": "known", "input_hmac_sha256": BINDING.input_hmac_sha256, "input_count": 2,
                 "protected_nonempty": True, "missing_count": 0} if users else NOT_COLLECTED)
    assert row[COVERAGE] == expected
    assert _identity(out).get("users") == USERS_OP


# ---------------------------------------------------------------------------------------------------------------
# Ancestors still lose their diagnostic text; the R2 nested and encoded closure stays.


def _deep(levels=120):
    node = _carrier()
    for _ in range(levels):
        node = {"down": node, "note": UNCONF_NAME}
    return node


BEARING_OPERATIONS = {
    "error-and-nested-details": lambda: {"status": "ok", "error": f"failed for {UNCONF_NAME}",
                                         "details": {"deeper": [{"inner": _carrier()}]}, "value": []},
    "double-encoded-row": lambda: {"status": "ok", "stderr": f"WARNING: {UNCONF_NAME}",
                                   "value": [{"id": "x", "Blob": {"b": json.dumps(json.dumps(_carrier()))}}]},
    "escaped-key": lambda: {"status": "ok", "reason": UNCONF_NAME,
                            "value": [{"Blob": '{"\\u0054argetedUsersToProtect":["%s"]}' % UNCONF_EMAIL}]},
    "keyless-encoded-stdout": lambda: {"error_class": "command_error", "message": CONFIGURED_NAME,
                                       "stdout": json.dumps(json.dumps(_carrier()))},
    "past-the-bounds": lambda: {"status": "ok", "value": [_deep()]},
    "bare-deep-mapping": _deep,
}


@pytest.mark.parametrize("mode", sorted(MODES))
@pytest.mark.parametrize("meta", [1, "v1", True, None], ids=["int", "str", "bool", "null"])
@pytest.mark.parametrize("operation", sorted(BEARING_OPERATIONS))
def test_bearing_operation_loses_its_text_and_its_siblings_stay(operation, meta, mode):
    sample = {"identity": {"users": deepcopy(USERS_OP), "schema_version": meta,
                           "legacy": BEARING_OPERATIONS[operation]()}}
    source = deepcopy(sample)
    out = tuc.sanitise_sample(sample, *MODES[mode])
    assert sample == source and _leaks(out) == [], operation
    identity = _identity(out)
    assert identity.get("users") == USERS_OP
    legacy = identity.get("legacy")
    if isinstance(legacy, dict) and "error" in legacy:
        assert legacy["error"] in KNOWN_ERRORS


@pytest.mark.parametrize("mode", sorted(MODES))
def test_section_level_diagnostics_go_and_the_failure_stays(mode):
    sample = {"identity": {"error": f"failed for {UNCONF_NAME}", "error_class": CONFIGURED_NAME,
                           "message": UNCONF_EMAIL, "traceback": UNCONF_DOMAIN, "truncation_reason": UNCONF_NAME,
                           "users": deepcopy(USERS_OP), "schema_version": 1, "legacy": {"value": [_carrier()]}}}
    out = _identity(tuc.sanitise_sample(sample, *MODES[mode]))
    assert _leaks(out) == []
    assert out.get("error") in KNOWN_ERRORS and out.get("error_class") in KNOWN_ERRORS
    assert out.get("truncation_reason"), "a refusal marker is never dropped"
    assert not {"message", "traceback"} & set(out)
    assert out.get("users") == USERS_OP and out.get("schema_version") == 1


@pytest.mark.parametrize("mode", sorted(MODES))
def test_supplied_summary_beside_a_carrier_is_never_trusted(mode):
    known = {"version": 1, "state": "known", "input_hmac_sha256": BINDING.input_hmac_sha256, "input_count": 2,
             "protected_nonempty": True, "missing_count": 0}
    sample = {"identity": {COVERAGE: known, "schema_version": 1, "users": deepcopy(USERS_OP),
                           "legacy": {"value": [{**_carrier(), COVERAGE: known}]}}}
    out = _identity(tuc.sanitise_sample(sample, *MODES[mode]))
    assert _leaks(out) == [] and out.get(COVERAGE) == NOT_COLLECTED
    assert out.get("users") == USERS_OP


# ---------------------------------------------------------------------------------------------------------------
# Independent operations: health and rows unchanged, never aliased, never mutated.

HEALTH_VARIANTS = [
    {"status": "failed", "error": "command_error", "value": []},
    {"status": "ok", "truncation_reason": "operator_limit", "collection_truncated": True, "value": [{"id": "t"}]},
    {"status": "ok", "@odata.nextLink": "https://graph.invalid/next", "value": [{"id": "n"}]},
    {"status": "partial", "partial": True, "incomplete": True, "value": [{"id": "p", "enabled": False}]},
    {"status": "ok", "complete": False, "bounded_sample": True, "value": [{"id": "b", "count": 0}]},
    {"error": "Unrelated failure text", "value": [{"id": "e", "displayName": "Ordinary Person"}]},
]


@pytest.mark.parametrize("mode", sorted(MODES))
@pytest.mark.parametrize("variant", range(len(HEALTH_VARIANTS)))
def test_independent_operation_health_and_rows_are_unchanged(variant, mode):
    operation = HEALTH_VARIANTS[variant]
    sample = {"identity": {"users": deepcopy(operation), "schema_version": 1, "legacy": {"value": [_carrier()]}}}
    out = _identity(tuc.sanitise_sample(sample, *MODES[mode]))
    assert out.get("users") == operation, "an operation with no target keeps its health markers and text as they were"
    assert _leaks(out) == []


def test_section_without_a_carrier_is_copied_exactly():
    sample = {"identity": {"users": deepcopy(USERS_OP), "schema_version": "v1", "note": "Ordinary unrelated text",
                           "ratio": 0.5, "enabled": True, "missing": None}}
    for users, binding in MODES.values():
        assert tuc.sanitise_sample(deepcopy(sample), users, binding) == sample


@pytest.mark.parametrize("mode", sorted(MODES))
def test_aliased_source_containers_are_copied_not_shared(mode):
    users_op = deepcopy(USERS_OP)
    carrier = {"value": [_carrier()]}
    sample = {"identity": {"users": users_op, "schema_version": 1, "legacy": carrier, "legacyAgain": carrier},
              "directory": {"users": users_op}}
    source = deepcopy(sample)
    out = tuc.sanitise_sample(sample, *MODES[mode])
    assert sample == source and _leaks(out) == []
    assert _identity(out).get("users") == USERS_OP and out["directory"].get("users") == USERS_OP
    _identity(out)["users"]["value"].append({"id": "mutated"})
    out["directory"]["users"]["status"] = "mutated"
    assert users_op == USERS_OP and sample == source, "the output never aliases the source"


@pytest.mark.parametrize("mode", sorted(MODES))
def test_fixture_provenance_keeps_its_own_boundary(mode):
    bearing = {"synthetic": True, "source": "sm-fixture", "detail": {"TargetedUsersToProtect": [UNCONF_EMAIL]},
               "note": UNCONF_NAME}
    plain = {"synthetic": True, "source": "sm-fixture", "schema_version": 1}
    for provenance in (bearing, plain):
        sample = {"_fixture_provenance": deepcopy(provenance), **deepcopy(F1)}
        out = tuc.sanitise_sample(sample, *MODES[mode])
        assert out["_fixture_provenance"] == tuc.strip_targets(provenance), "provenance routing is unchanged"
        assert _leaks(out) == []
        assert _identity(out).get("users") == USERS_OP


# ---------------------------------------------------------------------------------------------------------------
# Whole offline flow: sample copy, bundle, logs and console; SS 2.1-2.4 parity with a carrier-free control.


def _replay(tmp_path: Path, sample: dict, *, users=CONFIGURED, name="sm"):
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
            if fragment in folded and not (fragment == "configured-smcanary" and relative in private):
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


def _control():
    return {"exchange_policy": {
        "antiPhishPolicies": {"status": "ok", "value": [{**SETTINGS, "TargetedUsersToProtect": list(TARGETS)}]},
        **deepcopy(HEALTHY), "antiPhishRules": deepcopy(RULES), "transportConfig": deepcopy(TRANSPORT)},
        "identity": {"users": deepcopy(USERS_OP)}}


def _with_f1_carriers():
    sample = _control()
    sample["identity"] = deepcopy(F1["identity"])
    sample["identity"]["legacyExport"] = {"error": f"failed for {UNCONF_NAME}", "stdout": json.dumps(_carrier()),
                                          "value": [_carrier()]}
    sample["legacy_export"] = {"schema_version": 2, "rows": {"value": [{"Nested": _carrier()}]},
                               "otherOp": {"status": "ok", "value": [{"id": "x-1", "note": "Ordinary text"}]}}
    sample["_fixture_provenance"] = {"synthetic": True, "detail": {"TargetedUsersToProtect": [UNCONF_EMAIL]}}
    return sample


@pytest.mark.parametrize("users", [CONFIGURED, None], ids=["configured", "unconfigured"])
def test_offline_flow_keeps_independent_operations_and_writes_no_canary(tmp_path, capsys, caplog, users):
    run_dir = _replay(tmp_path, _with_f1_carriers(), users=users)
    assert _scan(run_dir, private=("operator-inputs/sensitive-users.txt",) if users else ()) == []
    captured = capsys.readouterr()
    assert _leaks(captured.out, captured.err, caplog.text) == []
    copied = json.loads((run_dir / "raw/sample_input.json").read_text())
    assert copied["identity"].get("users") == USERS_OP and copied["identity"].get("schema_version") == 1
    assert copied.get("legacy_export", {}).get("otherOp") == {"status": "ok", "value": [{"id": "x-1", "note": "Ordinary text"}]}
    assert copied.get("legacy_export", {}).get("schema_version") == 2
    assert copied["exchange_policy"]["antiPhishRules"] == RULES


def test_carrier_free_control_is_unchanged_and_ss21_to_ss24_keep_parity(tmp_path):
    control_sample = _control()
    sanitised = tuc.sanitise_sample(deepcopy(control_sample), USERS, BINDING)
    rest = {name: value for name, value in control_sample["exchange_policy"].items() if name != "antiPhishPolicies"}
    assert {name: sanitised["exchange_policy"][name] for name in rest} == rest
    assert sanitised["identity"] == control_sample["identity"]
    control = _replay(tmp_path, control_sample, name="control")
    carried = _replay(tmp_path, _with_f1_carriers(), name="carriers")
    assert _scan(carried) == []
    assert _records(control)["MS.SECURITYSUITE.2.1v1"][0] == "met"
    assert _records(carried) == _records(control)
