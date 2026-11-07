"""Exchange SCuBA inputs from synthetic cmdlet responses; no tenant or PowerShell."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from auditex.scuba_projection import project_run
from azure_tenant_audit.adapters.read_guard import check_command
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
from azure_tenant_audit.detection_coverage import build_detection_signals
from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.normalize import build_normalized_snapshot

ROOT = Path(__file__).resolve().parents[1]
COMMANDS = {
    "acceptedDomains": "Get-AcceptedDomain | Select-Object Name,DomainName,DomainType,Default,IsCoexistenceDomain",
    "transportRules": ",@(Get-TransportRule | Select-Object Name,State,Priority,Mode,RedirectMessageTo,BlindCopyTo,CopyTo,ApplyHtmlDisclaimerText,FromScope,PrependSubject)",
    "remoteDomains": "Get-RemoteDomain | Select-Object Name,DomainName,TrustedMailOutboundEnabled,AutoReplyEnabled,AutoForwardEnabled",
    "organizationAuditConfig": "Get-OrganizationConfig | Select-Object Identity,Name,AuditDisabled",
    "transportConfig": "Get-TransportConfig | Select-Object Name,SmtpClientAuthenticationDisabled",
    "sharingPolicy": "Get-SharingPolicy | Select-Object Name,Domains",
}
SECTIONS = {
    "transport_config": ("transportConfig", {"Name": "Transport", "SmtpClientAuthenticationDisabled": True}),
    "org_config": ("organizationAuditConfig", {"Identity": "Tenant", "Name": "Example", "AuditDisabled": False}),
}
VECTORS = json.loads((ROOT / "tests/fixtures/collect-exchange/exchange-cmdlet-vectors.json").read_text())


def write(root, path, payload):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload) + "\n")


def operation(root, name, rows):
    path = root / "raw/exchange_policy.json"
    payload = json.loads(path.read_text()) if path.exists() else {}
    payload[name] = {"value": rows, "status": "ok"}
    write(root, "raw/exchange_policy.json", payload)


def manifest(root):
    write(root, "run-manifest.json", {
        "run_id": "t", "platform": "m365", "tenant_id": "11111111-1111-4111-8111-111111111111",
    })


class FakeAdapter:
    def __init__(self, fail_sharing=False):
        self.responses = {}
        for name, command in ExchangePolicyCollector.command_collectors:
            source = next((row for operation_name, row in SECTIONS.values() if name == operation_name), None)
            if source is not None:
                # Simulate Select-Object, so the integration test exercises the collector's field list.
                selected = command.split(" | Select-Object ")[-1].split(",")
                rows = [{key: value for key, value in source.items() if key in selected}]
            else:
                rows = [{"Name": "Partners", "Domains": ["partner.example.invalid:CalendarSharingFreeBusySimple"]}] if name == "sharingPolicy" else []
            self.responses[command] = {"value": rows}
            if name == "sharingPolicy" and fail_sharing:
                self.responses[command] = {"error": "synthetic refusal", "error_class": "command_not_authenticated"}

    def run(self, command, log_event=None, session=None):
        return deepcopy(self.responses[command])


def collect(monkeypatch, *, fail_sharing=False):
    adapter = FakeAdapter(fail_sharing)
    monkeypatch.setattr("azure_tenant_audit.collectors.exchange_policy.get_adapter", lambda _name: adapter)
    return ExchangePolicyCollector().run({"audit_logger": None})


@pytest.mark.parametrize("name,expected", COMMANDS.items())
def test_explicit_command_fields(name, expected):
    assert dict(ExchangePolicyCollector.command_collectors)[name] == expected


def test_all_commands_pass_read_guard():
    for _, command in ExchangePolicyCollector.command_collectors:
        words = check_command("powershell_graph", command)
        assert words[0].startswith("Get-")
        assert all(word.startswith("Get-") or word in {"Select-Object", "Where-Object", "Measure-Object"} for word in words)


def test_accepted_domain_flag_survives_collection_without_changing_projection(monkeypatch, tmp_path):
    adapter = FakeAdapter()
    command = COMMANDS['acceptedDomains']
    selected = command.removesuffix(')').split(' | Select-Object ')[1].split(',')
    constructed_row = {'Name': 'Mail', 'DomainName': 'mail.example.invalid',
                       'DomainType': 'Authoritative', 'Default': True, 'IsCoexistenceDomain': False}
    adapter.responses[command] = {'value': [{key: constructed_row[key] for key in selected}]}
    monkeypatch.setattr('azure_tenant_audit.collectors.exchange_policy.get_adapter', lambda _name: adapter)
    result = ExchangePolicyCollector().run({})
    assert result.payload['acceptedDomains']['value'] == [constructed_row]
    assert next(c for c in result.coverage if c['name'] == 'acceptedDomains')['status'] == 'ok'
    manifest(tmp_path)
    write(tmp_path, 'raw/exchange_policy.json', result.payload)
    projection = project_run(tmp_path, redact=False)
    expected = [{'Name': 'Mail', 'DomainName': 'mail.example.invalid'}]
    assert projection['accepted_domains'] == projection.rule_sections['accepted_domains'] == expected
    assert projection.report['sections']['accepted_domains']['ignored_fields'] == [
        'Default', 'DomainType', 'IsCoexistenceDomain']


def test_sharing_policy_payload_and_coverage(monkeypatch):
    result = collect(monkeypatch)
    assert result.payload["sharingPolicy"]["value"][0]["Name"] == "Partners"
    coverage = {row["name"]: row for row in result.coverage}
    assert coverage["sharingPolicy"]["status"] == "ok"
    assert coverage["sharingPolicy"]["item_count"] == 1
    assert list(result.payload).index("sharingPolicy") == list(result.payload).index("remoteDomains") + 1
    assert len(result.payload) == len(result.coverage) == len(ExchangePolicyCollector.command_collectors)
    assert result.status == "ok"


def test_sharing_policy_failure_is_isolated(monkeypatch):
    complete = collect(monkeypatch)
    failed = collect(monkeypatch, fail_sharing=True)
    assert failed.status == "partial"
    coverage = {row["name"]: row for row in failed.coverage}
    assert coverage["sharingPolicy"]["status"] == "failed"
    assert failed.payload["sharingPolicy"]["error_class"] == "command_not_authenticated"
    assert failed.item_count == complete.item_count - 1
    for name in complete.payload:
        if name != "sharingPolicy":
            assert failed.payload[name] == complete.payload[name]
            assert coverage[name]["status"] == ("skipped" if name == "protectionAlerts" else "ok")


def test_collector_output_reaches_rule_and_model_views(monkeypatch, tmp_path):
    result = collect(monkeypatch)
    manifest(tmp_path)
    for name, envelope in result.payload.items():
        operation(tmp_path, name, envelope["value"])
    projection = project_run(tmp_path, redact=False)
    for section, (_, row) in SECTIONS.items():
        assert projection.rule_sections[section] == [row]
        assert projection[section] == [row]
        assert projection[section] != NOT_COLLECTED


def test_old_select_lists_withhold_both_views(tmp_path):
    manifest(tmp_path)
    for section, (name, row) in SECTIONS.items():
        operation(tmp_path, name, [{key: value for key, value in row.items() if key not in {"Name", "Identity"}}])
    projection = project_run(tmp_path, redact=False)
    for section in SECTIONS:
        assert projection[section] == projection.rule_sections[section] == NOT_COLLECTED
        assert projection.report["sections"][section]["detail"]["kind"] == "missing_field"


# The same malformed families exist for both policies. Empty lists pass the rule
# view but have no witnessed model shape; pin that distinction separately.
WITHHELD_FAMILIES = {
    "bad_label_null", "bad_unlabelled", "bad_unlabelled_and_clear", "bad_unlabelled_and_labelled",
    "bad_with_unusable_other", "clear_with_junk_elements", "section_null", "section_object",
    "section_only_junk", "section_string", "unusable_and_clear",
}
WITHHELD_FIELDS = {"field_absent", "field_int", "field_null", "field_string"}


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["vector_id"])
def test_vector_round_trip(tmp_path, vector):
    manifest(tmp_path)
    section, rows = next(iter(vector["sections"].items()))
    name, fields = SECTIONS[section]
    operation(tmp_path, name, rows)
    projection = project_run(tmp_path, redact=False)
    withheld = vector["family"] in WITHHELD_FAMILIES or vector["family"].rsplit("_", 1)[0] in WITHHELD_FIELDS
    if withheld:
        assert projection.rule_sections[section] == NOT_COLLECTED
        assert projection[section] == NOT_COLLECTED
    else:
        expected = [{key: row[key] for key in fields} for row in rows]
        assert projection.rule_sections[section] == expected
        assert projection[section] == (NOT_COLLECTED if vector["family"] == "section_empty_list" else expected)


def test_normalisation_keys_and_detection_survive_widening(monkeypatch):
    payload = collect(monkeypatch).payload
    old_payload = deepcopy(payload)
    for name, _ in SECTIONS.values():
        for row in old_payload[name]["value"]:
            row.pop("Identity", None)
            row.pop("Name", None)

    def records(value):
        snapshot = build_normalized_snapshot(tenant_name="acme", run_id="t", collector_payloads={"exchange_policy": value})
        return {row["source_name"]: row for row in snapshot["exchange_policy_objects"]["records"]}

    before, after = records(old_payload), records(payload)
    for name, object_id in (("organizationAuditConfig", "Tenant"), ("transportConfig", "Transport")):
        assert before[name]["id"] == name
        assert before[name]["key"] == f"exchange_policy_object:{name}"
        assert after[name]["id"] == object_id
        assert after[name]["key"] == f"exchange_policy_object:{object_id}"
        assert after[name]["kind"] == "exchange_policy_object"
    assert after["organizationAuditConfig"]["audit_disabled"] is False
    assert after["transportConfig"]["smtp_client_auth_disabled"] is True
    signals = {row["name"]: row for row in build_detection_signals({"exchange_policy": payload})}
    assert signals["mailbox_audit_default"]["status"] == "on"


def test_config_commands_equal_collector():
    definition = json.loads((ROOT / "configs/collector-definitions.json").read_text())["collectors"]["exchange_policy"]
    commands = {row["name"]: row["commands"] for row in definition["command_collectors"]}
    assert commands == {name: [command] for name, command in ExchangePolicyCollector.command_collectors}
    assert definition["query_plan"] == [name for name, _ in ExchangePolicyCollector.command_collectors]
