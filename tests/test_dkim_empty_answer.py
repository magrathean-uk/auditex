"""D4: an empty Get-DkimSigningConfig answer is an empty list, which the DKIM rule reads as no signing configuration."""
from __future__ import annotations

import pytest

from azure_tenant_audit.adapters.read_guard import check_command
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
from azure_tenant_audit.value_rules import assess

POLICY = "MS.EXO.3.1v1"
KEY = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"


def sections(config, domain="example.com"):
    return {
        "dkim_config": config,
        "dkim_records": [{"domain": domain, "rdata": [KEY]}],
        "spf_records": [{"compliant": True, "domain": domain, "message": "SPF record found."}],
    }


def test_command_is_wrapped_so_an_empty_answer_is_a_list_and_stays_read_only():
    command = dict(ExchangePolicyCollector.command_collectors)["dkimSigningConfig"]
    assert command == ",@(Get-DkimSigningConfig | Select-Object Domain,Enabled,Status)"
    assert check_command("powershell_graph", command)[0] == "Get-DkimSigningConfig"


def test_empty_config_list_reads_no_signing_config():
    record = assess(POLICY, sections([]))
    assert (record["verdict"], record["cell"]) == ("not_met", "domain_noncompliant.no_signing_config")
    assert record["reason_text"] == "Requirement not met: at least one domain has no DKIM signing configuration."


def test_empty_config_beside_a_coexistence_domain_only_flags_nothing():
    record = assess(POLICY, sections([], domain="t.mail.onmicrosoft.com"))
    assert record["verdict"] == "met"


def test_a_config_for_the_domain_still_reads_as_before():
    record = assess(POLICY, sections([{"Domain": "example.com", "Enabled": True}]))
    assert record["verdict"] == "met"


@pytest.mark.parametrize("bad", [[None, "x"], "text", None])
def test_a_config_without_any_object_stays_unusable(bad):
    record = assess(POLICY, sections(bad))
    assert record["verdict"] == "not_assessed"
    assert record["cell"] in {"no_usable_items", "section_not_a_list", "section_not_collected"}


def test_empty_records_or_spf_lists_stay_unusable():
    base = sections([{"Domain": "example.com", "Enabled": True}])
    for name in ("dkim_records", "spf_records"):
        record = assess(POLICY, {**base, name: []})
        assert (record["verdict"], record["cell"]) == ("not_assessed", "no_usable_items")
