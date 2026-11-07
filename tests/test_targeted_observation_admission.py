"""SS 2.1 typed inline observation admission: false-met counterexamples and complete controls (E8 lane B).

The original anti-phish operation response must be admitted as a supported inline success before any envelope
metadata or row field is removed and before a fresh known ``TargetedUsersCoverage`` can be generated. The projection
refuses the original evidence for an unsupported scan/count/chunk envelope, unknown envelope metadata or a row health
marker anywhere outside the actual ``TargetedUsersToProtect`` value, so a minimised copy must never meet instead.

Only base APIs are used here (offline replay, ``project_run``, ``assess``, the boundary helper, the collector and the
adapter), never the admission module itself: on the frozen base every counterexample fails an assertion, not an
import. The counterexamples stay red until root wires the admission validator into ``sanitise_response`` and the
adapter's callback acceptance; the controls are green before and after.
"""
from __future__ import annotations

from copy import deepcopy
from functools import partial
import json
from pathlib import Path
import re
import stat
import sys

import pytest

from azure_tenant_audit import cli
from azure_tenant_audit.adapters import powershell_graph as pg
from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
from azure_tenant_audit.collectors import targeted_users_coverage as tuc
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector, _run_anti_phish
from azure_tenant_audit.sensitive_users import SensitiveUsers
from azure_tenant_audit.value_rules.defender_targeted_users import SensitiveUsersBinding

COVERAGE = "TargetedUsersCoverage"
COMMANDS = dict(ExchangePolicyCollector.command_collectors)
ANTI_PHISH = COMMANDS["antiPhishPolicies"]
OTHER = COMMANDS["transportConfig"]
CONFIGURED = ("adm-a@configured-admcanary.invalid", "adm-b@configured-admcanary.invalid")
UNCONF_EMAIL = "zx-admcanary@unlisted-admcanary.invalid"
UNCONF_NAME = "Ottoline Brackenridge"
FRAGMENTS = ("ottoline", "brackenridge", "zx-admcanary", "unlisted-admcanary", "configured-admcanary")
TARGETS = [f"Configured Person;{CONFIGURED[0]}", CONFIGURED[1].upper(), f"{UNCONF_NAME};{UNCONF_EMAIL}"]
USERS = SensitiveUsers(tuple(sorted(CONFIGURED)))
BINDING = SensitiveUsersBinding(2, "ab" * 32)
TARGET_KEY = re.compile(r"(?:t|\\+u0054)argeted_?users_?to_?protect\\*[\"']\s*:", re.IGNORECASE)
SS2 = ("MS.SECURITYSUITE.2.1v1", "MS.SECURITYSUITE.2.2v1", "MS.SECURITYSUITE.2.3v1", "MS.SECURITYSUITE.2.4v1")

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
CHUNK = "raw/exchange_policy/antiPhishPolicies/part-0001.jsonl"

# Original envelopes the projection would refuse (scan/count/chunk keys, unknown metadata, unsupported known-key
# types) or that carry no exact supported meaning. Each must refuse after the boundary, never meet.
ENVELOPE_REFUSED = [
    ("sample_truncated-true", {"sample_truncated": True}),
    ("sample_truncated-string", {"sample_truncated": "yes"}),
    ("sample_truncated-one", {"sample_truncated": 1}),
    ("sample_truncated-null", {"sample_truncated": None}),
    ("sample_truncated-with-count", {"sample_truncated": True, "item_count": 1}),
    ("item_count-true", {"item_count": True}),
    ("item_count-string", {"item_count": "1"}),
    ("item_count-null", {"item_count": None}),
    ("item_count-float", {"item_count": 1.0}),
    ("item_count-nonmatching", {"item_count": 2}),
    ("item_count-zero", {"item_count": 0}),
    ("item_count-negative", {"item_count": -1}),
    ("chunk_files-one", {"chunk_files": [CHUNK]}),
    ("chunk_files-empty", {"chunk_files": []}),
    ("chunk_count-one", {"chunk_count": 1}),
    ("chunk_count-zero", {"chunk_count": 0}),
    ("chunk-both", {"chunk_files": [CHUNK], "chunk_count": 1}),
    ("unknown-scalar", {"nextPageToken": "opaque"}),
    ("unknown-flag", {"has_more": True}),
    ("unknown-object", {"paging": {"next": None}}),
    ("unknown-diagnostic", {"warning": "ordinary"}),
    ("unknown-odata-context", {"@odata.context": "https://graph.invalid/$metadata"}),
    ("status-complete", {"status": "complete"}),
    ("return_code-string", {"return_code": "0"}),
    ("return_code-bool", {"return_code": False}),
    ("return_code-nonzero", {"return_code": 1}),
    ("duration-string", {"duration_ms": "12"}),
    ("stdout_bytes-bool", {"stdout_bytes": True}),
    ("licence_inferred-string", {"licence_inferred": "no"}),
    ("truncation_reason-false", {"truncation_reason": False}),
    ("truncation_reason-empty", {"truncation_reason": ""}),
    ("partial-zero", {"partial": 0}),
    ("command-number", {"command": 7}),
    ("reason-rate-limit", {"reason": "rate_limit"}),
    ("state-over-limit", {"state": "over_limit"}),
]
# Row health markers the projection refuses recursively (``_healthy`` and ``_fields``) wherever they sit outside the
# actual top-level ``TargetedUsersToProtect`` value, including near-neighbour keys and nested Extra fields.
ROW_REFUSED = [
    ("incomplete", {"incomplete": True}),
    ("complete-false", {"complete": False}),
    ("complete-string", {"complete": "true"}),
    ("complete-null", {"complete": None}),
    ("read_state-failed", {"read_state": "failed"}),
    ("collection_status-partial", {"collection_status": "partial"}),
    ("error", {"error": "denied"}),
    ("error_class", {"error_class": "command_error"}),
    ("truncation_reason", {"truncation_reason": "operator_limit"}),
    ("bounded_sample", {"bounded_sample": True}),
    ("partial-one", {"partial": 1}),
    ("resolver_error", {"resolver_error": "unresolved"}),
    ("next-link", {"@odata.nextLink": "https://graph.invalid/next"}),
    ("collection_truncated", {"collection_truncated": True}),
    ("nested-extra-complete", {"Extra": {"inner": [{"complete": False}]}}),
    ("nested-extra-read_state", {"Extra": [{"deeper": {"read_state": "failed"}}]}),
    ("retained-field-member", {"TargetedDomainsToProtect": [{"incomplete": True}]}),
    ("neighbour-case", {"targetedUsersToProtect": [{"complete": False}]}),
    ("neighbour-spaced", {"Targeted Users To Protect": [{"error": "x"}]}),
    ("neighbour-nested", {"Extra": {"TargetedUsersToProtect": [{"incomplete": True}]}}),
    ("neighbour-supplied-summary", {COVERAGE: {"complete": False}}),
]
# The exact E8 counterexamples, run through the whole offline flow as well as the boundary.
FLOW_REFUSED = {
    "envelope": ["sample_truncated-true", "sample_truncated-null", "item_count-true", "item_count-string",
                 "item_count-null", "item_count-nonmatching", "chunk_files-one", "chunk_count-one",
                 "unknown-scalar", "return_code-string"],
    "row": ["incomplete", "complete-false", "read_state-failed", "error", "nested-extra-complete",
            "retained-field-member", "neighbour-case", "neighbour-nested"],
}
# Exact supported envelope and harmless row data: still a fresh bound met.
FULL_CONTROL_ENVELOPE = {
    "command": ANTI_PHISH, "status": "ok", "item_count": 1, "sample_truncated": False, "complete": True,
    "collection_status": "collected", "read_state": "collected", "return_code": 0, "duration_ms": 12.5,
    "stdout_bytes": 100, "stderr_bytes": 0, "result_limit": 1000, "licence_inferred": False,
    "collection_truncated": False, "bounded_sample": False, "collection_limit_reached": False, "partial": None,
    "incomplete": None, "truncation_reason": None, "resolver_error": None, "@odata.nextLink": None,
    "error": None, "error_class": None, "reason": None, "state": None,
}
FULL_CONTROL_ROW = {
    "status": "Provisioned", "UnselectedExtra": "ordinary", "WhenChanged": "2026-11-01T00:00:00Z",
    "Nested": {"status": "Disabled", "note": "fine", "complete": True, "read_state": "collected",
               "collection_status": "collected", "items": [{"status": "Failed"}, 1, 2.5, None, False]},
}
# Malformed target members only make coverage unusable; SS 2.2-2.4 keep their settings.
MALFORMED_TARGETS = {
    "member-complete-false": [*TARGETS, {"complete": False}],
    "member-markers": [{"incomplete": True, "error": "x", "read_state": "failed"}, *TARGETS],
    "member-nested-list": [*TARGETS, [{"collection_status": "partial"}]],
    "value-object": {"complete": False},
}


def _by_id(matrix, ids):
    table = dict(matrix)
    return [(name, table[name]) for name in ids]


def _envelope(extra=None, row=None, targets=None):
    policy = {**SETTINGS, "TargetedUsersToProtect": deepcopy(TARGETS if targets is None else targets), **(row or {})}
    return {"status": "ok", "value": [policy], **deepcopy(extra or {})}


def _sample(envelope):
    sample = {"exchange_policy": {"antiPhishPolicies": envelope}}
    for name, value in {**HEALTHY, "antiPhishRules": RULES, "transportConfig": TRANSPORT}.items():
        sample["exchange_policy"][name] = deepcopy(value)
    sample["identity"] = deepcopy(UNRELATED)
    return sample


def _replay(tmp_path: Path, sample: dict, *, name: str):
    path = tmp_path / f"{name}-sample.json"
    path.write_text(json.dumps(sample))
    before = path.read_bytes()
    out = tmp_path / f"out-{name}"
    cli.run_offline(path, out, "acme", name, sensitive_users=USERS)
    assert path.read_bytes() == before, "the source sample is never modified"
    return out / f"acme-{name}"


def _scan(root: Path):
    leaks = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes().decode("utf-8", "replace")
        folded = data.casefold()
        for fragment in FRAGMENTS:
            if fragment in folded and not (fragment == "configured-admcanary"
                                           and relative == "operator-inputs/sensitive-users.txt"):
                leaks.append((relative, fragment))
        if TARGET_KEY.search(data):
            leaks.append((relative, "target key"))
    return leaks


def _records(run_dir):
    from auditex.scuba_projection import project_run, rule_policy_section
    from azure_tenant_audit.value_rules import assess

    projection = project_run(run_dir)
    result = {}
    for policy in SS2:
        sections = deepcopy(projection.rule_sections)
        sections["scuba_config"] = rule_policy_section(projection, policy, "scuba_config")
        record = assess(policy, sections)
        result[policy] = (record["verdict"], record["cell"], record.get("reason_code"))
    return result


def _known(out):
    rows = out.get("value") if isinstance(out, dict) else None
    return any(isinstance(row, dict) and isinstance(row.get(COVERAGE), dict) and row[COVERAGE].get("state") == "known"
               for row in rows or [])


def _refused(out):
    """A fixed failure the projection refuses, with no known coverage generated from the unadmitted rows."""
    return isinstance(out, dict) and bool(out.get("error_class")) and bool(out.get("error")) and not _known(out)


def _texts(value):
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                yield str(key)
                stack.append(child)
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
        elif item is not None:
            yield str(item)


def _leaks(*values):
    found = []
    for value in values:
        for text in _texts(value):
            folded = text.casefold()
            found.extend(fragment for fragment in FRAGMENTS if fragment in folded)
            if re.sub(r"[^a-z0-9]", "", folded) == "targeteduserstoprotect" or TARGET_KEY.search(text):
                found.append("target key")
    return found


# ---------------------------------------------------------------------------------------------------------------
# Boundary helper, both replayed and observed reads.


@pytest.mark.parametrize("observed", [True, False], ids=["observed", "replayed"])
@pytest.mark.parametrize(("name", "extra"), ENVELOPE_REFUSED, ids=[name for name, _ in ENVELOPE_REFUSED])
def test_unadmitted_envelope_never_becomes_known_success(name, extra, observed):
    original = _envelope(extra)
    kept = deepcopy(original)
    out = tuc.sanitise_response(original, USERS, BINDING, observed=observed)
    assert original == kept, "the original response is never mutated"
    assert _leaks(out) == []
    assert _refused(out), f"{name}: an unsupported envelope must stay a fixed failure, never known coverage"
    tuc.enforce_response(deepcopy(out), command="cmd")


@pytest.mark.parametrize("observed", [True, False], ids=["observed", "replayed"])
@pytest.mark.parametrize(("name", "row"), ROW_REFUSED, ids=[name for name, _ in ROW_REFUSED])
def test_row_health_marker_is_refused_before_its_fields_are_dropped(name, row, observed):
    out = tuc.sanitise_response(_envelope(row=row), USERS, BINDING, observed=observed)
    assert _leaks(out) == []
    assert _refused(out), f"{name}: a refused original row must not become a fresh known summary"
    tuc.enforce_response(deepcopy(out), command="cmd")


def test_explicit_failure_envelope_keeps_its_fixed_failure():
    for error, error_class in (("command_timeout", "command_timeout"), (f"failed for {UNCONF_NAME}", "x")):
        out = tuc.sanitise_response({"error": error, "error_class": error_class, **_envelope()}, USERS, BINDING,
                                    observed=False)
        assert _leaks(out) == [] and out.get("error") and out.get("error_class")
        if error_class == "command_timeout":
            assert (out["error"], out["error_class"]) == ("command_timeout", "command_timeout")


@pytest.mark.parametrize("observed", [True, False], ids=["observed", "replayed"])
def test_complete_controls_stay_known(observed):
    for out in (tuc.sanitise_response(_envelope(), USERS, BINDING, observed=observed),
                tuc.sanitise_response(_envelope(FULL_CONTROL_ENVELOPE, FULL_CONTROL_ROW), USERS, BINDING,
                                      observed=observed)):
        assert _leaks(out) == [] and not out.get("error") and not out.get("error_class")
        (row,) = out["value"]
        assert row[COVERAGE] == {"version": 1, "state": "known", "input_hmac_sha256": BINDING.input_hmac_sha256,
                                 "input_count": 2, "protected_nonempty": True, "missing_count": 0}
        assert "status" not in row and "Nested" not in row, "harmless unknown row data is still discarded"
        tuc.enforce_response(deepcopy(out), command="cmd")


@pytest.mark.parametrize("case", sorted(MALFORMED_TARGETS))
def test_malformed_target_members_only_make_coverage_unusable(case):
    out = tuc.sanitise_response(_envelope(targets=MALFORMED_TARGETS[case]), USERS, BINDING, observed=False)
    assert _leaks(out) == [] and not out.get("error") and not out.get("error_class")
    (row,) = out["value"]
    assert row[COVERAGE] == {"version": 1, "state": "unusable"}
    assert row["TargetedDomainsToProtect"] == ["partner.example.invalid"] and row["EnableViaTag"] is True


# ---------------------------------------------------------------------------------------------------------------
# Collector with another adapter (no callback): the response still crosses the same admission.


class _Adapter:
    def __init__(self, response):
        self._response = response

    def run(self, command, log_event=None, session=None):
        return deepcopy(self._response)


def _collect(response):
    context = {tuc.CONTEXT_USERS: USERS, tuc.CONTEXT_BINDING: BINDING}
    return _run_anti_phish(_Adapter(response), ANTI_PHISH, lambda *args: None, {}, tuc, context)


@pytest.mark.parametrize(("name", "extra", "row"), [
    ("sample_truncated", {"sample_truncated": True}, None),
    ("item_count-null", {"item_count": None}, None),
    ("chunk_files", {"chunk_files": [CHUNK]}, None),
    ("row-incomplete", None, {"incomplete": True}),
    ("row-nested-complete", None, {"Extra": {"x": [{"complete": False}]}}),
])
def test_collector_with_another_adapter_refuses_unadmitted_success(name, extra, row):
    out = _collect(_envelope(extra, row))
    assert _leaks(out) == []
    assert _refused(out), name


def test_collector_with_another_adapter_keeps_the_complete_control():
    out = _collect(_envelope(FULL_CONTROL_ENVELOPE, FULL_CONTROL_ROW))
    assert not out.get("error_class") and _known(out)


# ---------------------------------------------------------------------------------------------------------------
# Real adapter with a synthetic child process: with and without the collector callback, and a callback that
# returns a valid closed success the original response never supported.

CHILD = """\
import os, sys
path = os.environ.get("ADM_STDOUT_FILE")
if path:
    with open(path, "rb") as handle:
        sys.stdout.buffer.write(handle.read())
    sys.stdout.buffer.flush()
sys.exit(0)
"""


@pytest.fixture
def child(tmp_path, monkeypatch):
    script = tmp_path / "pwsh"
    script.write_text(f"#!{sys.executable} -I\n{CHILD}")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(pg.shutil, "which", lambda name: str(script) if name == "pwsh" else None)

    def plant(stdout: str):
        path = tmp_path / "ADM_STDOUT_FILE"
        path.write_bytes(stdout.encode("utf-8"))
        monkeypatch.setenv("ADM_STDOUT_FILE", str(path))
    return plant


def _adapter_run(**kwargs):
    events = []
    response = PowerShellGraphAdapter().run(
        ANTI_PHISH, log_event=lambda kind, message, details: events.append((kind, message, details)), session=None,
        **kwargs)
    return response, events


TRANSFORM = partial(tuc.sanitise_response, sensitive_users=USERS, binding=BINDING, observed=True)


def _lying_transform(_response):
    """A callback that ignores the original read and returns a valid closed success with a fresh bound summary."""
    return tuc.sanitise_response(_envelope(), USERS, BINDING, observed=True)


ADAPTER_REFUSED = {
    "envelope-sample_truncated": json.dumps(_envelope({"sample_truncated": True})),
    "envelope-item_count-string": json.dumps(_envelope({"item_count": "1"})),
    "envelope-chunk_count": json.dumps(_envelope({"chunk_count": 1})),
    "row-list-read_state": json.dumps([{**SETTINGS, "TargetedUsersToProtect": TARGETS, "read_state": "failed"}]),
    "row-list-nested-incomplete": json.dumps([{**SETTINGS, "TargetedUsersToProtect": TARGETS,
                                               "Extra": {"deep": [{"incomplete": True}]}}]),
}


@pytest.mark.parametrize("transform", ["none", "collector", "lying"])
@pytest.mark.parametrize("case", sorted(ADAPTER_REFUSED))
def test_adapter_refuses_unadmitted_success_with_or_without_a_callback(child, case, transform):
    child(ADAPTER_REFUSED[case])
    kwargs = {} if transform == "none" else {
        "response_transform": TRANSFORM if transform == "collector" else _lying_transform}
    response, events = _adapter_run(**kwargs)
    assert _leaks(response, events) == []
    assert _refused(response), f"{case}/{transform}: an unadmitted original read is never accepted as success"


@pytest.mark.parametrize("transform", ["collector", "lying"])
def test_adapter_accepts_the_supported_control(child, transform):
    child(json.dumps([{**SETTINGS, "TargetedUsersToProtect": TARGETS, **FULL_CONTROL_ROW}]))
    response, events = _adapter_run(response_transform=TRANSFORM if transform == "collector" else _lying_transform)
    assert _leaks(response, events) == []
    assert not response.get("error_class") and _known(response)


# ---------------------------------------------------------------------------------------------------------------
# Whole offline flow: run_offline -> project_run -> assess.


@pytest.mark.parametrize(("name", "extra"), _by_id(ENVELOPE_REFUSED, FLOW_REFUSED["envelope"]),
                         ids=FLOW_REFUSED["envelope"])
def test_unadmitted_envelope_cannot_meet_through_the_whole_flow(tmp_path, name, extra):
    run_dir = _replay(tmp_path, _sample(_envelope(extra)), name="env")
    assert _scan(run_dir) == []
    assert _records(run_dir)["MS.SECURITYSUITE.2.1v1"][0] == "not_assessed", name


@pytest.mark.parametrize(("name", "row"), _by_id(ROW_REFUSED, FLOW_REFUSED["row"]), ids=FLOW_REFUSED["row"])
def test_refused_original_row_cannot_meet_through_the_whole_flow(tmp_path, name, row):
    run_dir = _replay(tmp_path, _sample(_envelope(row=row)), name="row")
    assert _scan(run_dir) == []
    assert _records(run_dir)["MS.SECURITYSUITE.2.1v1"][0] == "not_assessed", name


def test_complete_controls_meet_through_the_whole_flow(tmp_path):
    plain = _records(_replay(tmp_path, _sample(_envelope()), name="plain"))
    full_dir = _replay(tmp_path, _sample(_envelope(FULL_CONTROL_ENVELOPE, FULL_CONTROL_ROW)), name="full")
    assert _scan(full_dir) == []
    assert plain["MS.SECURITYSUITE.2.1v1"][0] == "met"
    assert _records(full_dir) == plain


@pytest.mark.parametrize("case", sorted(MALFORMED_TARGETS))
def test_malformed_target_members_keep_ss22_to_ss24(tmp_path, case):
    plain = _records(_replay(tmp_path, _sample(_envelope()), name="plain"))
    run_dir = _replay(tmp_path, _sample(_envelope(targets=MALFORMED_TARGETS[case])), name="malformed")
    assert _scan(run_dir) == []
    records = _records(run_dir)
    assert records["MS.SECURITYSUITE.2.1v1"][:2] == ("not_assessed", "policy_field_unusable")
    assert {k: v for k, v in records.items() if k != "MS.SECURITYSUITE.2.1v1"} == {
        k: v for k, v in plain.items() if k != "MS.SECURITYSUITE.2.1v1"}
