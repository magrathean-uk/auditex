"""Offline Defender / EOP collector contract; no PowerShell or tenant connection."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from azure_tenant_audit import baselines
from azure_tenant_audit.adapters.read_guard import check_command
from azure_tenant_audit.collectors import exchange_defender_commands as defender
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
from azure_tenant_audit.secret_hygiene import redact_command_string

ROOT = Path(__file__).resolve().parents[1]
NEW_OPERATIONS = (
    "eopProtectionPolicyRules", "atpProtectionPolicyRules", "atpBuiltInProtectionRules", "atpPolicyForO365",
    "malwareFilterRules", "safeAttachmentPolicies", "safeAttachmentRules", "antiPhishPolicies", "antiPhishRules",
    "hostedContentFilterPolicies", "hostedContentFilterRules", "safeLinksPolicies", "safeLinksRules",
    "hostedConnectionFilterPolicy",
)
RULE_OPERATIONS = (
    "eopProtectionPolicyRules", "atpProtectionPolicyRules", "atpBuiltInProtectionRules", "malwareFilterRules",
    "safeAttachmentRules", "antiPhishRules", "hostedContentFilterRules", "safeLinksRules",
)
RECIPIENT_KEYS = ("SentTo", "SentToMemberOf", "ExceptIfSentTo", "ExceptIfSentToMemberOf")
UNCHANGED_ERRORS = (
    "session_not_connected", "command_not_authenticated", "command_refused", "command_timeout",
    "command_output_empty", "command_parse_error", "command_not_found", "command_exception",
)


class _FakeAdapter:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def run(self, command, log_event=None, session=None):
        self.calls.append((command, session))
        # Match the real adapter: its command envelope is redacted/requoted, not the raw command.
        return {**deepcopy(self.responses[command]), "command": redact_command_string(command)}


def _run(monkeypatch, **overrides):
    commands = dict(ExchangePolicyCollector.command_collectors)
    responses = {command: {"value": []} for command in commands.values()}
    responses.update({commands[name]: value for name, value in overrides.items()})
    adapter = _FakeAdapter(responses)
    monkeypatch.setattr("azure_tenant_audit.collectors.exchange_policy.get_adapter", lambda _name: adapter)
    return ExchangePolicyCollector().run({}), adapter


def _licence_ledger():
    return [{
        "collector": "exchange_policy", "coverage_status": "partial_success",
        "diagnostics": [
            {"item": name, "error_class": "license_required"} for name in defender.LICENCE_GATED_OPERATIONS
        ],
    }]


def test_defender_commands_are_read_only_and_have_explicit_field_selections():
    assert tuple(name for name, _ in defender.DEFENDER_COMMANDS) == NEW_OPERATIONS
    commands = dict(ExchangePolicyCollector.command_collectors)
    for name in (*NEW_OPERATIONS, "malwareFilterPolicy", "adminAuditLogConfig"):
        command = commands[name]
        assert check_command("powershell_graph", command) == (
            command.removeprefix(",@(").split()[0], "Select-Object",
        )
        for forbidden in ("*", "-ResultSize Unlimited", "Set-", "New-", "Remove-"):
            assert forbidden not in command
        # SS 2.1 reads the targeted-user list on the anti-phish policy read only; it is summarised and dropped in memory.
        assert ("TargetedUsersToProtect" in command) == (name == "antiPhishPolicies")
        if name not in {"malwareFilterPolicy", "adminAuditLogConfig", "atpPolicyForO365",
                        "antiPhishPolicies", "hostedContentFilterPolicies", "hostedConnectionFilterPolicy"}:
            assert command.startswith(",@(") and command.endswith(")")
        else:
            assert not command.startswith(",@(")
    assert commands["adminAuditLogConfig"] == "Get-AdminAuditLogConfig | Select-Object Identity,UnifiedAuditLogIngestionEnabled"
    assert commands["malwareFilterPolicy"] == "Get-MalwareFilterPolicy | Select-Object Identity,Name,IsDefault,EnableFileFilter,ZapEnabled,FileTypes"
    for name in ("antiPhishRules", "hostedContentFilterRules"):
        assert "Priority" not in commands[name]
    fields = commands["antiPhishPolicies"].split("Select-Object ", 1)[1].split(",")
    assert fields.index("TargetedUsersToProtect") == fields.index("TargetedUserProtectionAction") + 1
    assert fields.count("TargetedUsersToProtect") == 1 and len(fields) == 17
    assert all("TargetedUsersToProtect" not in command for other, command in ExchangePolicyCollector.command_collectors
               if other != "antiPhishPolicies")


def test_defender_collector_collects_every_new_operation_without_changing_session_routing(monkeypatch):
    result, adapter = _run(monkeypatch)
    assert result.status == "ok"
    assert set(NEW_OPERATIONS) <= result.payload.keys()
    assert all(result.payload[name]["value"] == [] for name in NEW_OPERATIONS)
    assert all(row["status"] == "ok" for row in result.coverage if row["name"] != "protectionAlerts")
    alert = next(row for row in result.coverage if row["name"] == "protectionAlerts")
    assert alert["status"] == "skipped" and alert["reason"] == "ipps_session_not_opened"
    names = list(result.payload)
    assert names.index("acceptedDomains") < min(names.index(name) for name in NEW_OPERATIONS)
    assert names.index("eopProtectionPolicyRules") + 1 == names.index("atpProtectionPolicyRules")
    calls = dict(adapter.calls)
    sessions = {name: calls[command] for name, command in ExchangePolicyCollector.command_collectors
                if name != "protectionAlerts"}
    assert dict(ExchangePolicyCollector.command_collectors)["protectionAlerts"] not in calls
    assert all(sessions[name] == {"kind": "none"} for name in NEW_OPERATIONS)


@pytest.mark.parametrize("operation", RULE_OPERATIONS)
def test_defender_rule_recipient_lists_are_minimised_before_entering_payload(monkeypatch, operation):
    planted = "planted@example.invalid"
    row = {key: [planted, "group@example.invalid"] for key in RECIPIENT_KEYS}
    row.update(RecipientDomainIs=["example.invalid"], ExceptIfRecipientDomainIs=["sub.example.invalid"])
    nulls = {key: None for key in RECIPIENT_KEYS}
    scalars = {key: planted for key in RECIPIENT_KEYS}
    objects = {key: {"Address": planted} for key in RECIPIENT_KEYS}
    empty = dict(zip(RECIPIENT_KEYS, ([], "", {}, None), strict=False))
    result, _ = _run(monkeypatch, **{operation: {"value": [row, nulls, scalars, objects, empty, "malformed-row"]}})
    assert planted not in json.dumps(result.payload)
    command = dict(ExchangePolicyCollector.command_collectors)[operation]
    assert result.payload[operation]["command"] == redact_command_string(command) != command
    rows = result.payload[operation]["value"]
    for key in RECIPIENT_KEYS:
        assert rows[0][key] == ["recipient", "recipient"]
    assert rows[0]["RecipientDomainIs"] == ["example.invalid"]
    assert rows[0]["ExceptIfRecipientDomainIs"] == ["sub.example.invalid"]
    assert rows[1:] == [
        nulls, {key: "recipient" for key in RECIPIENT_KEYS},
        {key: ["recipient"] for key in RECIPIENT_KEYS}, empty, "malformed-row",
    ]


def test_minimise_recipients_preserves_empty_lists_non_rule_operations_and_unusable_envelopes():
    command = dict(defender.DEFENDER_COMMANDS)["safeLinksRules"]
    response = {"command": command, "value": [{"SentTo": [], "ExceptIfSentTo": None, "SentToMemberOf": 7}]}
    before = deepcopy(response)
    defender.minimise_recipients("safeLinksRules", response)
    assert response == before
    for value in (None, {}, "unusable"):
        response = {"command": command, "value": value}
        before = deepcopy(response)
        defender.minimise_recipients("safeLinksRules", response)
        assert response == before
    response = {
        "command": dict(ExchangePolicyCollector.command_collectors)["malwareFilterPolicy"],
        "value": [{"SentTo": ["retained@example.invalid"]}],
        "error": "original failure", "stdout": "retained@example.invalid", "stderr": "diagnostic",
    }
    before = deepcopy(response)
    defender.minimise_recipients("malwareFilterPolicy", response)
    assert response == before


def test_defender_rule_error_stdout_is_replaced_with_its_length_and_stderr_is_kept(monkeypatch):
    planted = "planted@example.invalid"
    stdout = json.dumps([{"SentTo": [planted]}])
    result, _ = _run(monkeypatch, safeLinksRules={
        "error": "command_failed:1", "error_class": "command_error",
        "stdout": stdout, "stderr": "original diagnostic",
    })
    envelope = result.payload["safeLinksRules"]
    assert "stdout" not in envelope
    assert envelope["stdout_bytes"] == len(stdout)
    assert envelope["stderr"] == "original diagnostic"
    assert envelope["error_class"] == "command_error"
    assert planted not in json.dumps(result.payload)


@pytest.mark.parametrize("operation", defender.LICENCE_GATED_OPERATIONS)
def test_defender_licence_inference_preserves_error_and_updates_payload_and_coverage(monkeypatch, operation):
    error = {"error": "original failure", "error_class": "command_error", "value": [{"Identity": "unusable"}], "item_count": 1}
    result, _ = _run(monkeypatch, **{name: error for name in defender.LICENCE_GATED_OPERATIONS})
    envelope = result.payload[operation]
    assert envelope["error_class"] == "license_required"
    assert envelope["error"] == "original failure"
    assert envelope["value"] == [] and envelope["item_count"] == 0
    assert envelope["licence_inferred"] is True
    assert result.status == "partial" and result.item_count == 0
    coverage = next(row for row in result.coverage if row["name"] == operation)
    assert coverage["error_class"] == "license_required" and coverage["item_count"] == 0
    assert coverage["status"] == "failed" and coverage["error"] == "original failure"


@pytest.mark.parametrize("operation", defender.LICENCE_GATED_OPERATIONS)
def test_defender_licence_inference_requires_a_healthy_eop_rules_anchor(monkeypatch, operation):
    error = {"error": "original failure", "error_class": "command_error"}
    result, _ = _run(monkeypatch, eopProtectionPolicyRules=error, **{
        name: error for name in defender.LICENCE_GATED_OPERATIONS
    })
    assert result.payload[operation]["error_class"] == "command_error"
    assert "value" not in result.payload[operation]
    assert "licence_inferred" not in result.payload[operation]


def test_defender_licence_inference_uses_eop_rules_even_when_accepted_domains_failed(monkeypatch):
    error = {"error": "original failure", "error_class": "command_error"}
    result, _ = _run(monkeypatch, acceptedDomains=error, **{
        name: error for name in defender.LICENCE_GATED_OPERATIONS
    })
    assert result.payload["acceptedDomains"]["error_class"] == "command_error"
    assert all(result.payload[name]["licence_inferred"] for name in defender.LICENCE_GATED_OPERATIONS)


@pytest.mark.parametrize("operation", defender.LICENCE_GATED_OPERATIONS)
def test_defender_licence_inference_leaves_a_single_atp_failure_as_a_coverage_gap(monkeypatch, operation):
    error = {"error": "original failure", "error_class": "command_error", "value": [{"Identity": "unusable"}]}
    result, _ = _run(monkeypatch, **{operation: error})
    assert result.payload[operation] == {
        **error, "command": redact_command_string(dict(ExchangePolicyCollector.command_collectors)[operation]),
    }
    coverage = next(row for row in result.coverage if row["name"] == operation)
    assert coverage["error_class"] == "command_error" and coverage["item_count"] == 1
    assert result.status == "partial" and result.item_count == 1


@pytest.mark.parametrize("missing", ("eopProtectionPolicyRules", *defender.LICENCE_GATED_OPERATIONS))
def test_defender_licence_inference_requires_all_three_envelopes(missing):
    payload = {name: {"error": "failure", "error_class": "command_error"} for name in defender.LICENCE_GATED_OPERATIONS}
    payload["eopProtectionPolicyRules"] = {"value": []}
    del payload[missing]
    before = deepcopy(payload)
    defender.reclassify_licence_refusals(payload)
    assert payload == before


@pytest.mark.parametrize("operation", defender.LICENCE_GATED_OPERATIONS)
@pytest.mark.parametrize("error_class", UNCHANGED_ERRORS)
def test_defender_licence_inference_leaves_other_error_classes_untouched(monkeypatch, operation, error_class):
    error = {"error": "original failure", "error_class": error_class}
    overrides = {name: {"error": "other ATP failure", "error_class": "command_error"} for name in defender.LICENCE_GATED_OPERATIONS}
    overrides[operation] = error
    result, _ = _run(monkeypatch, **overrides)
    envelope = result.payload[operation]
    assert envelope == {**error, "command": redact_command_string(dict(ExchangePolicyCollector.command_collectors)[operation])}
    assert all("licence_inferred" not in result.payload[name] for name in defender.LICENCE_GATED_OPERATIONS)
    assert all(result.payload[name]["error_class"] == overrides[name]["error_class"] for name in defender.LICENCE_GATED_OPERATIONS)


def test_defender_licence_inference_can_be_disabled_and_does_not_change_other_operations(monkeypatch):
    error = {"error": "original failure", "error_class": "command_error"}
    result, _ = _run(monkeypatch, safeLinksPolicies=error)
    assert result.payload["safeLinksPolicies"]["error_class"] == "command_error"
    monkeypatch.setattr(defender, "INFER_LICENCE_FROM_FAILURE", False)
    result, _ = _run(monkeypatch, **{name: error for name in defender.LICENCE_GATED_OPERATIONS})
    for name in defender.LICENCE_GATED_OPERATIONS:
        assert result.payload[name]["error_class"] == "command_error"
        assert "value" not in result.payload[name]


def test_defender_scope_config_matches_the_shipped_commands():
    definition = json.loads((ROOT / "configs/collector-definitions.json").read_text())["collectors"]["exchange_policy"]
    commands = dict(ExchangePolicyCollector.command_collectors)
    for name in (*NEW_OPERATIONS, "malwareFilterPolicy", "adminAuditLogConfig"):
        (entry,) = [row for row in definition["command_collectors"] if row["name"] == name]
        assert entry["commands"] == [commands[name]]
        assert definition["query_plan"].count(name) == 1
        if name in (*NEW_OPERATIONS, "malwareFilterPolicy"):
            assert entry["category"] == "policy"
    index = definition["query_plan"].index("dkimSigningConfig") + 1
    assert tuple(definition["query_plan"][index:]) == NEW_OPERATIONS


def test_defender_permissions_add_only_the_new_optional_commands():
    path = "configs/collector-permissions.json"
    shipped = json.loads((ROOT / path).read_text())["collector_permissions"]["exchange_policy"]
    assert shipped["graph_scopes"] == []
    assert shipped["minimum_role_hints"] == ["Exchange Reader", "Exchange Administrator", "Global Reader"]
    assert shipped["command_tools"] == ["pwsh", "powershell_graph"]
    cmdlets = [command.removeprefix(",@(").split()[0] for _, command in defender.DEFENDER_COMMANDS]
    assert len(cmdlets) == 14
    assert set(cmdlets) <= set(shipped["optional_commands"])
    assert len(shipped["optional_commands"]) == len(set(shipped["optional_commands"]))


def test_defender_licence_ledger_exempts_only_the_two_gated_diagnostics():
    ledger = _licence_ledger()
    assert baselines._licence_limited_collectors(ledger) == {"exchange_policy"}
    ledger[0]["diagnostics"].append({"item": "safeLinksPolicies", "error_class": "command_error"})
    assert baselines._licence_limited_collectors(ledger) == set()
    ledger[0]["diagnostics"][-1]["error_class"] = "license_required"
    assert baselines._licence_limited_collectors(ledger) == set()


def test_defender_licence_ledger_does_not_change_existing_baseline_verdicts(monkeypatch):
    # Exercise all shipped mappings with healthy audit signals and an otherwise partial Exchange collector.
    snapshot = {"detection_signal_objects": {"records": [
        {"name": name, "status": "on"} for name in (
            "unified_audit_log", "mailbox_audit_default", "mailbox_audit_bypass_clear", "alert_policies",
        )
    ]}}
    ledger = _licence_ledger()
    with_entry = baselines.build_baseline_alignment([], normalized_snapshot=snapshot, coverage_ledger=ledger)
    monkeypatch.delitem(baselines._LICENCE_GATED_SECTIONS, "exchange_policy")
    without_entry = baselines.build_baseline_alignment([], normalized_snapshot=snapshot, coverage_ledger=ledger)
    assert with_entry == without_entry
