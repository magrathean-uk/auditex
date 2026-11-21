"""Deep-review fixes for the Defender and DNS value rules and their evidence (lane value-rules-defender-dns).

Each test names the review finding it pins. Synthetic, offline data only.
"""
from __future__ import annotations

import json
from pathlib import Path

from auditex.scuba_projection import project_run
from azure_tenant_audit.collectors.exchange_defender_commands import DEFENDER_COMMANDS
from azure_tenant_audit.value_rules import assess

ACCEPTED = [{"DomainName": "contoso.example"}]
EVERYONE = {key: None for key in (
    "SentTo", "SentToMemberOf", "RecipientDomainIs", "ExceptIfSentTo", "ExceptIfSentToMemberOf",
    "ExceptIfRecipientDomainIs")}


def _write_run(root: Path, operations: dict[str, list[dict]]) -> Path:
    (root / "raw").mkdir(parents=True, exist_ok=True)
    (root / "run-manifest.json").write_text(json.dumps({"run_id": "synthetic-review", "platform": "m365"}) + "\n")
    payload = {name: {"value": rows, "status": "ok"} for name, rows in operations.items()}
    (root / "raw/exchange_policy.json").write_text(json.dumps(payload) + "\n")
    return root


# ---- R002: the EOP preset rule's policy links reach the spam cascade ----

def test_r002_eop_preset_rule_read_selects_policy_links():
    command = dict(DEFENDER_COMMANDS)["eopProtectionPolicyRules"]
    fields = command.split("Select-Object ", 1)[1].rstrip(")").split(",")
    for link in ("HostedContentFilterPolicy", "AntiPhishPolicy", "MalwareFilterPolicy"):
        assert link in fields


def _spam_policy(identity, kind, default=False, action="Quarantine"):
    return {"Identity": identity, "IsDefault": default, "RecommendedPolicyType": kind, "SpamAction": action,
            "HighConfidenceSpamAction": action, "PhishSpamAction": action, "HighConfidencePhishAction": "Quarantine",
            "AllowedSenderDomains": []}


def test_r002_collector_shaped_standard_preset_answers_spam_rows(tmp_path):
    preset = "Standard Preset Security Policy1700000000000"
    run = _write_run(tmp_path, {
        "eopProtectionPolicyRules": [{"Identity": preset, "State": "Enabled", "HostedContentFilterPolicy": preset,
                                      "AntiPhishPolicy": preset, "MalwareFilterPolicy": preset, **EVERYONE}],
        "hostedContentFilterPolicies": [_spam_policy("Default", "Custom", default=True, action="MoveToJmf"),
                                        _spam_policy(preset, "Standard")],
        "hostedContentFilterRules": [],
    })
    sections = dict(project_run(run, redact=False).rule_sections)
    assert sections["protection_policy_rules"][0]["HostedContentFilterPolicy"] == preset
    sections["accepted_domains"] = ACCEPTED
    for policy in ("MS.SECURITYSUITE.6.1v1", "MS.SECURITYSUITE.6.2v1"):
        record = assess(policy, sections)
        assert (record["verdict"], record["cell"]) == ("met", "standard_covers_compliant"), policy
