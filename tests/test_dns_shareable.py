"""DNS-SHAREABLE: DNS record text never reaches a shareable export or a customer pack.

A DMARC record names report mailboxes and an SPF record names the domains and addresses allowed to send. The local
report keeps the public TXT text; the shareable, customer-pack and explainer profiles show fixed-vocabulary predicates
(policy, qualifier, counts, whether the CISA report address is listed) and pseudonymised DNS names instead.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from azure_tenant_audit.dns_shareable import shareable_dns_record
from azure_tenant_audit.output_redaction import (
    PROFILE_CUSTOMER_PACK,
    PROFILE_EXPLAINER,
    PROFILE_LOCAL,
    redact_output,
)

ROOT = Path(__file__).resolve().parents[1]
GOOGLE_SAMPLE = ROOT / "examples" / "google_workspace_sample.json"
M365_SAMPLE = ROOT / "examples" / "demo_tenant" / "demo_tenant.json"

MAILBOX_LOCAL = "zq-dmarc-reports"
MAILBOX_DOMAIN = "acme-synth.test"
MAILBOX = f"{MAILBOX_LOCAL}@{MAILBOX_DOMAIN}"
SPF_INCLUDE = "mail.zqsender-synth.test"
SPF_IP = "203.0.113.97"
DMARC = (f"v=DMARC1; p=reject; sp=quarantine; rua=mailto:{MAILBOX},mailto:reports@dmarc.cyber.dhs.gov; "
         f"ruf=mailto:{MAILBOX}")
SPF = f"v=spf1 include:_spf.google.com include:{SPF_INCLUDE} ip4:{SPF_IP} -all"
DKIM = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADzqsynthkey"
# Text that must not appear in any shareable file: the mailbox in every spelling, the record text and what it names
# (the rule title "DMARC rua= URI list ..." is product text, so the tag is matched with its value).
NEEDLES = (MAILBOX_LOCAL, MAILBOX_DOMAIN, "v=DMARC1", "rua=mailto", "v=spf1", SPF_INCLUDE, SPF_IP, "DKIM1", "zqsynthkey",
           "_dmarc.")
FORMATS = ("json", "md", "csv", "html", "sarif", "oscal")


def _hits(root: Path) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            found = [needle for needle in NEEDLES if needle.encode() in data]
            if found:
                hits[str(path.relative_to(root))] = found
    return hits


def _google_posture() -> dict:
    return {
        "domain": "example.com", "isPrimary": True, "resolver_error": None,
        "spf": {"present": True, "all_qualifier": "-", "mechanisms": SPF.split()[1:], "raw": SPF,
                "multiple_records": False, "records": [SPF]},
        "dmarc": {"present": True, "policy": "reject", "subdomain_policy": "quarantine", "pct": 100,
                  "pct_partial": False, "aggregate_addresses": [f"mailto:{MAILBOX}", "mailto:reports@dmarc.cyber.dhs.gov"],
                  "aggregate_addresses_invalid": [], "forensic_addresses": [f"mailto:{MAILBOX}"],
                  "forensic_addresses_invalid": [], "raw": DMARC, "multiple_records": False,
                  "query_name": "_dmarc.example.com", "inherited": False, "records": [DMARC]},
        "dkim": {"selectors_present": ["google"], "selectors_missing": [], "selectors": {"google": [DKIM]}},
    }


def _exports(run_dir: Path, tmp_path: Path) -> tuple[Path, Path]:
    from auditex.cli import run_exporter, verify_customer_pack, write_customer_pack

    exports = tmp_path / "exports"
    for format_name in FORMATS:
        run_exporter(name=format_name, run_dir=str(run_dir), output_path=str(exports / f"export.{format_name}"))
    pack = tmp_path / "pack"
    write_customer_pack(str(run_dir), str(pack))
    assert verify_customer_pack(str(pack))["valid"] is True
    assert len(list(exports.iterdir())) == 6 and any(pack.rglob("*.json"))
    return exports, pack


def test_google_dmarc_mailbox_and_record_text_stay_out_of_shareable_exports_and_the_pack(tmp_path: Path) -> None:
    from auditex import cli as auditex_cli
    from auditex.reporting import render_report

    sample = json.loads(GOOGLE_SAMPLE.read_text(encoding="utf-8"))
    sample["google_dns_posture"]["domainPosture"]["value"] = [_google_posture()]
    path = tmp_path / "sample.json"
    path.write_text(json.dumps(sample), encoding="utf-8")
    assert auditex_cli.main([
        "google", "run", "--offline", "--sample", str(path), "--domain", "example.com", "--customer-id", "my_customer",
        "--tenant-name", "Example", "--run-name", "dns", "--out", str(tmp_path / "out"),
    ]) == 0
    run_dir = tmp_path / "out" / "Example-dns"

    exports, pack = _exports(run_dir, tmp_path)

    assert _hits(exports) == {}
    assert _hits(pack) == {}
    shared = json.loads((exports / "export.json").read_text(encoding="utf-8"))
    (record,) = shared["sections"]["normalized"]["google_dns_posture"]["records"]
    assert record["dmarc"]["record_text"] == "withheld"
    assert record["dmarc"]["policy"] == "reject"
    assert record["dmarc"]["subdomain_policy_present"] is True
    assert record["dmarc"]["rua_count"] == 2
    assert record["dmarc"]["ruf_count"] == 1
    assert record["dmarc"]["cisa_rua_present"] is True
    assert record["dmarc"]["query_domain"].startswith("Id ")
    assert record["spf"] == {"record_text": "withheld", "present": True, "all_qualifier": "-",
                             "multiple_records": False, "mechanism_count": 4, "record_count": 1}
    assert record["dkim"]["selectors_present"] == ["google"]
    assert record["dkim"]["selector_record_count"] == 1
    # The private local report keeps the public record text the operator queried.
    local = render_report(run_dir=str(run_dir), format_name="json", profile=PROFILE_LOCAL,
                          output_path=str(tmp_path / "local.json"))
    assert DMARC in Path(local["output_path"]).read_text(encoding="utf-8")


def test_m365_dmarc_addresses_and_spf_mechanisms_stay_out_of_shareable_exports_and_the_pack(tmp_path: Path) -> None:
    from azure_tenant_audit.cli import main as audit_main

    sample = json.loads(M365_SAMPLE.read_text(encoding="utf-8"))
    posture = sample["dns_posture"]["domainPosture"]["value"][0]
    posture["spf"]["mechanisms"] = [f"include:{SPF_INCLUDE}", f"ip4:{SPF_IP}", "~all"]
    posture["spf"]["record"] = SPF
    posture["dmarc"]["record"] = DMARC
    posture["dmarc"]["aggregate_addresses"] = [f"mailto:{MAILBOX}", f"{MAILBOX_LOCAL}-bare@{MAILBOX_DOMAIN}"]
    posture["dmarc"]["aggregate_addresses_invalid"] = [f"{MAILBOX_LOCAL}-bare@{MAILBOX_DOMAIN}"]
    posture["tls_rpt"] = {"present": True, "rua": [f"mailto:{MAILBOX}"], "raw": f"v=TLSRPTv1; rua=mailto:{MAILBOX}"}
    path = tmp_path / "sample.json"
    path.write_text(json.dumps(sample), encoding="utf-8")
    assert audit_main(["--offline", "--sample", str(path), "--tenant-name", "t", "--out", str(tmp_path / "out")]) == 0
    (run_dir,) = [entry for entry in (tmp_path / "out").iterdir() if entry.is_dir()]

    exports, pack = _exports(run_dir, tmp_path)

    assert _hits(exports) == {}
    assert _hits(pack) == {}
    shared = json.loads((exports / "export.json").read_text(encoding="utf-8"))
    record = shared["sections"]["normalized"]["dns_posture_objects"]["records"][0]
    assert record["dmarc_rua_count"] == 2
    assert record["dmarc_rua_invalid_count"] == 1
    assert record["dmarc_cisa_rua_present"] is False
    assert record["spf_mechanism_count"] == 3
    assert record["tls_rpt_rua_count"] == 1
    assert "dmarc_aggregate_addresses" not in record and "spf_mechanisms" not in record
    (invalid,) = [row for row in shared["sections"]["findings"] if row["rule_id"] == "dns_posture.dmarc_rua_invalid"]
    assert invalid["returned_value"] == 1


@pytest.mark.parametrize("profile", ["shareable", PROFILE_CUSTOMER_PACK, PROFILE_EXPLAINER])
def test_every_shareable_profile_withholds_record_text(profile: str) -> None:
    out = redact_output({"records": [_google_posture()]}, profile=profile)
    text = json.dumps(out)
    assert not [needle for needle in NEEDLES if needle in text]
    assert redact_output({"records": [_google_posture()]}, profile=PROFILE_LOCAL) == {"records": [_google_posture()]}


def _same_name(name: str) -> str:
    return f"Id <{name}>"


def test_rewrite_is_idempotent() -> None:
    once = shareable_dns_record(_google_posture(), _same_name)
    assert shareable_dns_record(once, _same_name) == once
    flat = {"kind": "dns_posture", "domain": "example.com", "spf_mechanisms": ["-all"], "dmarc_policy": "reject",
            "dmarc_aggregate_addresses": ["mailto:reports@dmarc.cyber.dhs.gov"], "dmarc_aggregate_invalid": [],
            "tls_rpt_rua": None, "mta_sts_id": "20260101"}
    flat_once = shareable_dns_record(flat, _same_name)
    assert flat_once == {"kind": "dns_posture", "domain": "example.com", "spf_mechanism_count": 1,
                         "dmarc_policy": "reject", "dmarc_rua_count": 1, "dmarc_cisa_rua_present": True,
                         "dmarc_rua_invalid_count": 0, "tls_rpt_rua_count": None, "mta_sts_id_present": True}
    assert shareable_dns_record(flat_once, _same_name) == flat_once


@pytest.mark.parametrize(
    ("dmarc", "expected"),
    [
        # A missing semicolon folds the report address into the policy tag: never shown, never read as reject.
        ({"policy": f"reject rua=mailto:{MAILBOX}"}, {"policy": "unrecognised"}),
        ({"policy": ""}, {"policy": "unrecognised"}),
        ({"policy": None}, {"policy": None}),
        ({"policy": 1}, {"policy": "unrecognised"}),
        ({"policy": "REJECT"}, {"policy": "reject"}),
        ({"pct": "100"}, {"pct": "unrecognised"}),
        ({"pct": True}, {"pct": "unrecognised"}),
        ({"pct": 101}, {"pct": "unrecognised"}),
        ({"pct": 50}, {"pct": 50}),
        ({"present": "yes"}, {"present": None}),
        ({"aggregate_addresses": f"mailto:{MAILBOX}"}, {"rua_count": None, "cisa_rua_present": None}),
        ({"aggregate_addresses": [None]}, {"rua_count": 1, "cisa_rua_present": None}),
        ({"aggregate_addresses": []}, {"rua_count": 0, "cisa_rua_present": False}),
        ({"aggregate_addresses": ["MAILTO:Reports@DMARC.cyber.dhs.gov!10m"]}, {"rua_count": 1, "cisa_rua_present": True}),
        ({"query_name": ""}, {"query_domain": None}),
        ({"query_name": 7}, {"query_domain": None}),
        ({"records": "v=DMARC1; p=reject"}, {"record_count": None}),
        ({"subdomain_policy": None}, {"subdomain_policy": None, "subdomain_policy_present": False}),
    ],
)
def test_malformed_dmarc_values_never_become_predicates(dmarc: dict, expected: dict) -> None:
    out = shareable_dns_record({"domain": "example.com", "dmarc": dmarc}, _same_name)
    assert out == {"domain": "example.com", "dmarc": {"record_text": "withheld", **expected}}


@pytest.mark.parametrize("value", ["v=DMARC1; p=reject", ["v=DMARC1"], 5])
def test_a_record_section_that_is_not_a_mapping_is_unrecognised(value: object) -> None:
    out = shareable_dns_record({"domain": "example.com", "dmarc": value, "spf": {"all_qualifier": "^"}}, _same_name)
    assert out == {"domain": "example.com", "dmarc": "unrecognised",
                   "spf": {"record_text": "withheld", "all_qualifier": "unrecognised"}}


def test_older_bundle_posture_without_record_text_still_renders() -> None:
    # The shipped sample's posture predates record text, counts and query names.
    out = redact_output({"domain": "example.com", "spf": {"present": False}, "dmarc": {"present": True, "policy": "none"},
                         "dkim": {"selectors_present": [], "selectors_missing": ["google"]}})
    assert out == {
        "domain": "example.com",
        "spf": {"record_text": "withheld", "present": False},
        "dmarc": {"record_text": "withheld", "present": True, "policy": "none"},
        "dkim": {"record_text": "withheld", "selectors_present": [], "selectors_missing": ["google"]},
    }


def test_mta_sts_tls_rpt_and_bimi_text_is_withheld() -> None:
    out = shareable_dns_record({
        "domain": "example.com",
        "mta_sts": {"dns_present": True, "id": "zq2026", "raw": "v=STSv1; id=zq2026", "policy": {"mode": "enforce"}},
        "tls_rpt": {"present": True, "rua": [f"mailto:{MAILBOX}"], "raw": f"v=TLSRPTv1; rua=mailto:{MAILBOX}"},
        "bimi": {"present": True, "logo_url": f"https://{MAILBOX_DOMAIN}/l.svg", "logo_url_is_https": True,
                 "authority_url": None, "authority_url_is_https": None, "raw": "v=BIMI1; l=x"},
    }, _same_name)
    assert out == {
        "domain": "example.com",
        "mta_sts": {"record_text": "withheld", "dns_present": True, "id_present": True, "policy_mode": "enforce"},
        "tls_rpt": {"record_text": "withheld", "present": True, "rua_count": 1},
        "bimi": {"record_text": "withheld", "present": True, "logo_url_present": True, "logo_url_is_https": True,
                 "authority_url_present": False, "authority_url_is_https": None},
    }


def test_scuba_dns_rows_and_resolver_log_lose_their_answers() -> None:
    row = {"domain": "example.com", "rdata": [DMARC], "log": [
        {"query_name": "_dmarc.example.com", "query_method": "DoH", "query_result": "Query returned 1 txt records",
         "query_answers": [DMARC], "outcome": "answers"}]}
    out = redact_output(row, profile=PROFILE_CUSTOMER_PACK)
    text = json.dumps(out)
    assert not [needle for needle in NEEDLES if needle in text]
    assert out["rdata_count"] == 1
    assert out["log"][0]["query_answer_count"] == 1
    assert out["log"][0]["query_domain"].startswith("Id ")


def test_dmarc_monitor_only_finding_shows_only_a_policy_word() -> None:
    finding = {"rule_id": "dns_posture.dmarc_monitor_only", "returned_value": f"none rua=mailto:{MAILBOX}"}
    assert shareable_dns_record(finding, _same_name)["returned_value"] == "unrecognised"
    assert shareable_dns_record({**finding, "returned_value": "none"}, _same_name)["returned_value"] == "none"
    assert shareable_dns_record({**finding, "returned_value": None}, _same_name)["returned_value"] is None
