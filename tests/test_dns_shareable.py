"""DNS-SHAREABLE: DNS posture reaches a shareable export or a customer pack only as pseudonymised domain ids and
fixed-vocabulary predicates.

A DMARC record names report mailboxes and an SPF record names the domains and addresses allowed to send; the posture's
domain, query names and the ids derived from them name the domain. The local report keeps the public TXT text; the
shareable, customer-pack and explainer profiles show allow-listed predicates computed from parsed values, mark a
wrong-typed or unreadable value ``unusable`` and pseudonymise every DNS name.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from azure_tenant_audit.dns_lookup import parse_dmarc
from azure_tenant_audit.dns_shareable import shareable_dns_record
from azure_tenant_audit.output_redaction import (
    PROFILE_CUSTOMER_PACK,
    PROFILE_EXPLAINER,
    PROFILE_LOCAL,
    RedactionContext,
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
# Posture domains planted only in DNS posture rows, and a DNS name planted only in a DMARC query_domain.
GOOGLE_DOMAIN = "zq-posture-google.test"
GOOGLE_ALIAS = "zq-alias-google.test"
GOOGLE_DERIVED = "zq-derived-google.test"
DERIVED_QUERY = "_dmarc.zq-derived-receiver.test"
M365_DOMAIN = "zq-posture-m365.test"
M365_PCT_DOMAIN = "zq-pct-m365.test"
# Text that must not appear in any shareable file: the mailbox in every spelling, the record text and what it names
# (the rule title "DMARC rua= URI list ..." is product text, so the tag is matched with its value).
NEEDLES = (MAILBOX_LOCAL, MAILBOX_DOMAIN, "v=DMARC1", "rua=mailto", "v=spf1", SPF_INCLUDE, SPF_IP, "DKIM1", "zqsynthkey",
           "_dmarc.", "zq-posture-", "zq-alias-", "zq-derived-", "zq-pct-")
FORMATS = ("json", "md", "csv", "html", "sarif", "oscal")
PSEUDONYM = re.compile(r"Id [0-9a-f]{16}")


def _hits(root: Path) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            data = path.read_bytes().lower()
            found = [needle for needle in NEEDLES if needle.lower().encode() in data]
            if found:
                hits[str(path.relative_to(root))] = found
    return hits


def _google_posture(domain: str = "example.com") -> dict:
    return {
        "domain": domain, "isPrimary": True, "resolver_error": None,
        "spf": {"present": True, "all_qualifier": "-", "mechanisms": SPF.split()[1:], "raw": SPF,
                "multiple_records": False, "records": [SPF]},
        "dmarc": {"present": True, "policy": "reject", "subdomain_policy": "quarantine", "pct": 100,
                  "pct_partial": False, "aggregate_addresses": [f"mailto:{MAILBOX}", "mailto:reports@dmarc.cyber.dhs.gov"],
                  "aggregate_addresses_invalid": [], "forensic_addresses": [f"mailto:{MAILBOX}"],
                  "forensic_addresses_invalid": [], "raw": DMARC, "multiple_records": False,
                  "query_name": f"_dmarc.{domain}", "inherited": False, "records": [DMARC]},
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


def test_google_dns_posture_reaches_shareable_exports_and_the_pack_only_as_pseudonyms_and_predicates(
    tmp_path: Path,
) -> None:
    from auditex import cli as auditex_cli
    from auditex.reporting import render_report

    sample = json.loads(GOOGLE_SAMPLE.read_text(encoding="utf-8"))
    sample["google_dns_posture"]["domainPosture"]["value"] = [
        _google_posture(GOOGLE_DOMAIN),
        # A wrong-typed DMARC section on an alias row (no mapping-valued sibling).
        {"domain": GOOGLE_ALIAS, "alias": True, "resolver_error": False, "dmarc": DMARC},
        # An input-supplied query_domain in place of query_name.
        {"domain": GOOGLE_DERIVED, "alias": True, "resolver_error": False,
         "dmarc": {"present": True, "policy": "reject", "raw": DMARC, "query_domain": DERIVED_QUERY}},
    ]
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
    valid, alias, derived = shared["sections"]["normalized"]["google_dns_posture"]["records"]
    assert PSEUDONYM.fullmatch(valid["domain"]) and valid["id"] == valid["domain"]
    assert valid["key"] == f"google_domain_posture:{valid['domain']}"
    assert valid["dmarc"]["record_text"] == "withheld"
    assert valid["dmarc"]["policy"] == "reject"
    assert valid["dmarc"]["rua_count"] == 2
    assert valid["dmarc"]["cisa_rua_present"] is True
    assert PSEUDONYM.fullmatch(valid["dmarc"]["query_domain"])
    assert valid["spf"] == {"record_text": "withheld", "present": True, "all_qualifier": "-",
                            "multiple_records": False, "mechanism_count": 4, "record_count": 1}
    assert alias["dmarc"] == "unusable" and alias["alias"] is True
    assert PSEUDONYM.fullmatch(derived["dmarc"]["query_domain"])
    monitor = [row for row in shared["sections"]["findings"] if row["rule_id"] == "google.dns_dmarc_monitor_only"]
    assert [row["id"] for row in monitor] == [f"google.dns_dmarc_monitor_only:{alias['domain']}"]
    assert monitor[0]["affected_objects"] == [alias["domain"]]
    # The private local report keeps the public record text the operator queried.
    local = render_report(run_dir=str(run_dir), format_name="json", profile=PROFILE_LOCAL,
                          output_path=str(tmp_path / "local.json"))
    assert DMARC in Path(local["output_path"]).read_text(encoding="utf-8")


def test_m365_dns_posture_reaches_shareable_exports_and_the_pack_only_as_pseudonyms_and_predicates(
    tmp_path: Path,
) -> None:
    from azure_tenant_audit.cli import main as audit_main

    sample = json.loads(M365_SAMPLE.read_text(encoding="utf-8"))
    rows = sample["dns_posture"]["domainPosture"]["value"]
    posture = rows[0]
    posture["domain"] = M365_DOMAIN
    posture["spf"]["mechanisms"] = [f"include:{SPF_INCLUDE}", f"ip4:{SPF_IP}", "~all"]
    posture["spf"]["record"] = SPF
    posture["dmarc"]["record"] = DMARC
    posture["dmarc"]["aggregate_addresses"] = [f"mailto:{MAILBOX}", f"{MAILBOX_LOCAL}-bare@{MAILBOX_DOMAIN}"]
    posture["dmarc"]["aggregate_addresses_invalid"] = [f"{MAILBOX_LOCAL}-bare@{MAILBOX_DOMAIN}"]
    posture["tls_rpt"] = {"present": True, "rua": [f"mailto:{MAILBOX}"], "raw": f"v=TLSRPTv1; rua=mailto:{MAILBOX}"}
    # A wrong-typed percentage that holds the record text.
    rows.append(json.loads(json.dumps(posture)))
    rows[-1]["domain"] = M365_PCT_DOMAIN
    rows[-1]["dmarc"].update(present=True, policy="reject", pct=DMARC, pct_partial=True)
    path = tmp_path / "sample.json"
    path.write_text(json.dumps(sample), encoding="utf-8")
    assert audit_main(["--offline", "--sample", str(path), "--tenant-name", "t", "--out", str(tmp_path / "out")]) == 0
    (run_dir,) = [entry for entry in (tmp_path / "out").iterdir() if entry.is_dir()]
    bundle_findings = json.loads((run_dir / "findings" / "findings.json").read_text(encoding="utf-8"))
    assert not [row for row in bundle_findings if row["rule_id"] == "dns_posture.dmarc_pct_partial"]

    exports, pack = _exports(run_dir, tmp_path)

    assert _hits(exports) == {}
    assert _hits(pack) == {}
    shared = json.loads((exports / "export.json").read_text(encoding="utf-8"))
    records = shared["sections"]["normalized"]["dns_posture_objects"]["records"]
    (record,) = [row for row in records if row.get("dmarc_pct") == 100]
    (pct_record,) = [row for row in records if row.get("dmarc_pct") == "unusable"]
    assert PSEUDONYM.fullmatch(record["domain"]) and record["id"] == record["domain"]
    assert record["key"] == f"dns_posture:{record['domain']}"
    assert record["dmarc_rua_count"] == 2
    assert record["dmarc_rua_invalid_count"] == 1
    assert record["dmarc_cisa_rua_present"] is False
    assert record["spf_mechanism_count"] == 3
    assert record["tls_rpt_rua_count"] == 1
    assert "dmarc_aggregate_addresses" not in record and "spf_mechanisms" not in record
    assert pct_record["dmarc_pct"] == "unusable" and pct_record["dmarc_pct_partial"] == "unusable"
    (invalid,) = [row for row in shared["sections"]["findings"]
                  if row["rule_id"] == "dns_posture.dmarc_rua_invalid" and record["domain"] in row["id"]]
    assert invalid["id"] == f"dns_posture:{record['domain']}:dmarc_rua_invalid"
    assert invalid["affected_objects"] == [record["domain"]]
    assert invalid["returned_value"] == 1
    assert invalid["evidence"]["domain"] == record["domain"]


@pytest.mark.parametrize("profile", ["shareable", PROFILE_CUSTOMER_PACK, PROFILE_EXPLAINER])
def test_every_shareable_profile_withholds_record_text_and_domains(profile: str) -> None:
    out = redact_output({"records": [_google_posture()]}, profile=profile)
    text = json.dumps(out)
    assert not [needle for needle in (*NEEDLES, "example.com") if needle in text]
    assert redact_output({"records": [_google_posture()]}, profile=PROFILE_LOCAL) == {"records": [_google_posture()]}


def _name(name: str) -> str:
    return name if name.startswith("Id ") else f"Id <{name.strip().lower().rstrip('.')}>"


def test_the_posture_is_allow_listed_and_every_dns_name_is_pseudonymised() -> None:
    record = {**_google_posture(), "kind": "google_domain_posture", "source": "google_dns_posture.domainPosture",
              "id": "Example.COM", "key": "google_domain_posture:example.com", "note": f"see {MAILBOX}",
              "verified_by": "zq-operator"}
    assert shareable_dns_record(record, _name) == {
        "domain": "Id <example.com>", "isPrimary": True, "resolver_error": None,
        "spf": {"record_text": "withheld", "present": True, "all_qualifier": "-", "multiple_records": False,
                "mechanism_count": 4, "record_count": 1},
        "dmarc": {"record_text": "withheld", "present": True, "policy": "reject", "subdomain_policy": "quarantine",
                  "subdomain_policy_present": True, "pct": 100, "pct_partial": False, "rua_count": 2,
                  "rua_invalid_count": 0, "cisa_rua_present": True, "ruf_count": 1, "ruf_invalid_count": 0,
                  "inherited": False, "multiple_records": False, "record_count": 1,
                  "query_domain": "Id <_dmarc.example.com>"},
        "dkim": {"record_text": "withheld", "selectors_present": ["google"], "selectors_missing": [],
                 "selector_record_count": 1},
        "kind": "google_domain_posture", "source": "google_dns_posture.domainPosture",
        "id": "Id <example.com>", "key": "google_domain_posture:Id <example.com>",
    }


def test_rewrite_is_idempotent() -> None:
    once = shareable_dns_record(_google_posture(), _name)
    assert shareable_dns_record(once, _name) == once
    flat = {"kind": "dns_posture", "source": "dns_posture.domainPosture", "id": "example.com",
            "key": "dns_posture:example.com", "domain": "example.com", "spf_mechanisms": ["-all"],
            "dmarc_policy": "reject", "dmarc_present": True, "dmarc_pct": 100, "dmarc_pct_partial": False,
            "dmarc_aggregate_addresses": ["mailto:reports@dmarc.cyber.dhs.gov"], "dmarc_aggregate_invalid": [],
            "tls_rpt_rua": None, "mta_sts_id": "20260101", "authentication_type": "Managed", "zq_extra": MAILBOX}
    flat_once = shareable_dns_record(flat, _name)
    assert flat_once == {"kind": "dns_posture", "source": "dns_posture.domainPosture", "id": "Id <example.com>",
                         "key": "dns_posture:Id <example.com>", "domain": "Id <example.com>",
                         "spf_mechanism_count": 1, "dmarc_policy": "reject", "dmarc_present": True, "dmarc_pct": 100,
                         "dmarc_pct_partial": False, "dmarc_rua_count": 1, "dmarc_cisa_rua_present": True,
                         "dmarc_rua_invalid_count": 0, "tls_rpt_rua_count": None, "mta_sts_id_present": True,
                         "authentication_type": "managed"}
    assert shareable_dns_record(flat_once, _name) == flat_once


@pytest.mark.parametrize(
    ("dmarc", "expected"),
    [
        # A missing semicolon folds the report address into the policy tag: never shown, never read as reject.
        ({"policy": f"reject rua=mailto:{MAILBOX}"}, {"policy": "unusable"}),
        ({"policy": ""}, {"policy": "unusable"}),
        ({"policy": None}, {"policy": None}),
        ({"policy": 1}, {"policy": "unusable"}),
        ({"policy": "REJECT"}, {"policy": "reject"}),
        ({"pct": "100"}, {"pct": "unusable"}),
        ({"pct": True}, {"pct": "unusable"}),
        ({"pct": 101}, {"pct": "unusable"}),
        ({"pct": 50}, {"pct": 50, "pct_partial": True}),
        # Partial enforcement comes from a readable percentage, never from the flag beside an unreadable one.
        ({"pct": DMARC, "pct_partial": True}, {"pct": "unusable", "pct_partial": "unusable"}),
        ({"pct": None, "pct_partial": True}, {"pct": None, "pct_partial": "unusable"}),
        ({"pct": 100, "pct_partial": True}, {"pct": 100, "pct_partial": False}),
        ({"pct": 40, "pct_partial": False}, {"pct": 40, "pct_partial": True}),
        ({"present": "yes"}, {"present": "unusable"}),
        ({"aggregate_addresses": f"mailto:{MAILBOX}"}, {"rua_count": "unusable", "cisa_rua_present": "unusable"}),
        ({"aggregate_addresses": [None]}, {"rua_count": "unusable", "cisa_rua_present": "unusable"}),
        ({"aggregate_addresses": [""]}, {"rua_count": "unusable", "cisa_rua_present": "unusable"}),
        ({"aggregate_addresses": None}, {"rua_count": None, "cisa_rua_present": None}),
        ({"aggregate_addresses": []}, {"rua_count": 0, "cisa_rua_present": False}),
        ({"aggregate_addresses": ["MAILTO:Reports@DMARC.cyber.dhs.gov!10m"]}, {"rua_count": 1, "cisa_rua_present": True}),
        # Only a valid mailto: URI is a CISA contact: a bare address or a malformed size suffix is not.
        ({"aggregate_addresses": ["reports@dmarc.cyber.dhs.gov"]}, {"rua_count": 1, "cisa_rua_present": False}),
        ({"aggregate_addresses": ["mailto:reports@dmarc.cyber.dhs.gov!invalid"]},
         {"rua_count": 1, "cisa_rua_present": False}),
        ({"forensic_addresses": [7]}, {"ruf_count": "unusable"}),
        ({"query_name": ""}, {"query_domain": "unusable"}),
        ({"query_name": 7}, {"query_domain": "unusable"}),
        ({"query_domain": DERIVED_QUERY}, {"query_domain": f"Id <{DERIVED_QUERY}>"}),
        ({"query_domain": ["x"]}, {"query_domain": "unusable"}),
        ({"records": "v=DMARC1; p=reject"}, {"record_count": "unusable"}),
        ({"subdomain_policy": None}, {"subdomain_policy": None, "subdomain_policy_present": False}),
    ],
)
def test_malformed_dmarc_values_never_become_predicates(dmarc: dict, expected: dict) -> None:
    out = shareable_dns_record({"domain": "example.com", "dmarc": dmarc}, _name)
    assert out == {"domain": "Id <example.com>", "dmarc": {"record_text": "withheld", **expected}}


@pytest.mark.parametrize(
    ("text", "invalid_count", "cisa"),
    [
        ("v=DMARC1; p=reject; rua=reports@dmarc.cyber.dhs.gov", 1, False),
        ("v=DMARC1; p=reject; rua=mailto:reports@dmarc.cyber.dhs.gov!invalid", 0, False),
        ("v=DMARC1; p=reject; rua=mailto:reports@dmarc.cyber.dhs.gov!10m", 0, True),
        ("v=DMARC1; p=reject; rua=mailto:reports@dmarc.cyber.dhs.gov", 0, True),
    ],
)
def test_the_cisa_predicate_needs_a_valid_parsed_uri(text: str, invalid_count: int, cisa: bool) -> None:
    out = redact_output({"domain": "review.test", "dmarc": parse_dmarc(text)})["dmarc"]
    assert (out["rua_invalid_count"], out["cisa_rua_present"]) == (invalid_count, cisa)


@pytest.mark.parametrize(
    ("selectors", "count"),
    [({"google": 7}, "unusable"), ({"google": [None]}, "unusable"), ({"google": [""]}, "unusable"),
     ({"google": None}, "unusable"), ({"google": []}, 0), ({}, 0), ({"google": [DKIM], "s2": [DKIM]}, 2),
     (None, None), (7, "unusable")],
)
def test_unreadable_dkim_members_leave_the_record_count_unknown(selectors: object, count: object) -> None:
    out = shareable_dns_record({"domain": "example.com", "dkim": {"selectors": selectors}}, _name)
    assert out["dkim"] == {"record_text": "withheld", "selector_record_count": count}


def test_m365_selector_details_count_found_selectors() -> None:
    details = {"selector1": {"present": True, "key_type": "rsa", "raw": DKIM}, "selector2": {"present": True}}
    out = shareable_dns_record({"domain": "example.com", "dkim": {"selector_details": details}}, _name)
    assert out["dkim"] == {"record_text": "withheld", "selector_record_count": 2}
    bad = shareable_dns_record({"domain": "example.com", "dkim": {"selector_details": {"s": {"raw": DKIM}}}}, _name)
    assert bad["dkim"] == {"record_text": "withheld", "selector_record_count": "unusable"}


@pytest.mark.parametrize("value", ["v=DMARC1; p=reject", ["v=DMARC1"], 5])
def test_a_record_section_that_is_not_a_mapping_is_unusable_without_a_mapping_sibling(value: object) -> None:
    assert shareable_dns_record({"domain": "example.com", "alias": True, "dmarc": value}, _name) == {
        "domain": "Id <example.com>", "alias": True, "dmarc": "unusable",
    }
    out = redact_output({"records": [{"domain": "example.com", "alias": True, "dmarc": value}]})
    assert "DMARC1" not in json.dumps(out) and "example.com" not in json.dumps(out)


def test_older_bundle_posture_without_record_text_still_renders() -> None:
    # The shipped sample's posture predates record text, counts and query names.
    out = shareable_dns_record({"domain": "example.com", "spf": {"present": False},
                                "dmarc": {"present": True, "policy": "none"},
                                "dkim": {"selectors_present": [], "selectors_missing": ["google"]}}, _name)
    assert out == {
        "domain": "Id <example.com>",
        "spf": {"record_text": "withheld", "present": False},
        "dmarc": {"record_text": "withheld", "present": True, "policy": "none"},
        "dkim": {"record_text": "withheld", "selectors_present": [], "selectors_missing": ["google"]},
    }


def test_mta_sts_tls_rpt_and_bimi_text_is_withheld() -> None:
    out = shareable_dns_record({
        "domain": "example.com", "managed_by_microsoft": False, "resolver_error": "DNS resolver could not answer at r.test.",
        "mta_sts": {"dns_present": True, "id": "zq2026", "raw": "v=STSv1; id=zq2026",
                    "policy": {"mode": "enforce", "fetch_status": "ok", "url": "https://mta-sts.example.com/x",
                               "mx": ["mx.example.com"]}},
        "tls_rpt": {"present": True, "rua": [f"mailto:{MAILBOX}"], "raw": f"v=TLSRPTv1; rua=mailto:{MAILBOX}"},
        "bimi": {"present": True, "logo_url": f"https://{MAILBOX_DOMAIN}/l.svg", "logo_url_is_https": True,
                 "authority_url": None, "authority_url_is_https": None, "raw": "v=BIMI1; l=x"},
    }, _name)
    assert out == {
        "domain": "Id <example.com>", "managed_by_microsoft": False, "resolver_error": True,
        "mta_sts": {"record_text": "withheld", "dns_present": True, "id_present": True, "policy_fetch_status": "ok",
                    "policy_mode": "enforce"},
        "tls_rpt": {"record_text": "withheld", "present": True, "rua_count": 1},
        "bimi": {"record_text": "withheld", "present": True, "logo_url_present": True, "logo_url_is_https": True,
                 "authority_url_present": False, "authority_url_is_https": None},
    }


def test_scuba_dns_rows_and_resolver_log_lose_their_answers_and_names() -> None:
    row = {"domain": "example.com", "rdata": [DMARC], "log": [
        {"query_name": "_dmarc.example.com", "query_method": "DoH", "query_result": "Query returned 1 txt records",
         "query_answers": [DMARC], "outcome": "answers"}]}
    out = redact_output(row, profile=PROFILE_CUSTOMER_PACK)
    text = json.dumps(out)
    assert not [needle for needle in (*NEEDLES, "example.com") if needle in text]
    assert out["rdata_count"] == 1
    assert out["log"][0]["query_answer_count"] == 1
    assert PSEUDONYM.fullmatch(out["log"][0]["query_domain"])


def test_dns_findings_and_proof_rows_carry_only_pseudonymised_ids_and_predicates() -> None:
    evidence = {"kind": "dns_posture", "domain": "example.com", "dmarc_pct": DMARC, "dmarc_pct_partial": True}
    finding = {"id": "dns_posture:example.com:dmarc_pct_partial", "rule_id": "dns_posture.dmarc_pct_partial",
               "title": "DMARC enforcement is partial (pct < 100)", "affected_objects": ["example.com"],
               "returned_value": DMARC, "evidence": evidence,
               "evidence_refs": [{"record_key": "dns_posture:example.com", "artifact_path": "normalized/x.json"}]}
    proof = {"finding_id": "dns_posture:example.com:dmarc_pct_partial", "id": "dns_posture:example.com:x",
             "rule_id": "dns_posture.dmarc_pct_partial", "record_key": "dns_posture:example.com",
             "affected_objects": ["example.com"],
             "blast_radius": {"scope": "single_object", "affected_count": 1, "affected_objects": ["example.com"]}}
    google = {"id": "google.dns_spf_missing:example.com", "rule_id": "google.dns_spf_missing",
              "affected_objects": ["example.com"], "returned_value": "example.com"}
    out = redact_output({"findings": [finding, google], "proof_table": [proof],
                         "summary": "dns_posture:example.com:spf_missing and google_domain_posture:example.com"})
    text = json.dumps(out)
    assert "example.com" not in text and "DMARC1" not in text
    (domain,) = set(PSEUDONYM.findall(text))
    first, second = out["findings"]
    assert first["id"] == f"dns_posture:{domain}:dmarc_pct_partial"
    assert first["affected_objects"] == [domain]
    assert first["returned_value"] == "unusable"
    assert first["evidence"] == {"kind": "dns_posture", "domain": domain, "dmarc_pct": "unusable",
                                 "dmarc_pct_partial": "unusable"}
    assert first["evidence_refs"][0]["record_key"] == f"dns_posture:{domain}"
    assert second == {"id": f"google.dns_spf_missing:{domain}", "rule_id": "google.dns_spf_missing",
                      "affected_objects": [domain], "returned_value": domain}
    assert out["proof_table"][0]["finding_id"] == first["id"]
    assert out["proof_table"][0]["blast_radius"]["affected_objects"] == [domain]
    assert out["summary"] == f"dns_posture:{domain}:spf_missing and google_domain_posture:{domain}"


def test_dmarc_monitor_only_finding_shows_only_a_policy_word() -> None:
    finding = {"rule_id": "dns_posture.dmarc_monitor_only", "returned_value": f"none rua=mailto:{MAILBOX}"}
    assert shareable_dns_record(finding, _name)["returned_value"] == "unusable"
    assert shareable_dns_record({**finding, "returned_value": "none"}, _name)["returned_value"] == "none"
    assert shareable_dns_record({**finding, "returned_value": None}, _name)["returned_value"] is None


# Every key the rewrite writes, as a person could be called: none is renamed by person redaction.
EMITTED_KEYS = (
    "record_text", "present", "all_qualifier", "multiple_records", "mechanism_count", "record_count",
    "policy", "subdomain_policy", "subdomain_policy_present", "pct", "pct_partial", "rua_count", "rua_invalid_count",
    "cisa_rua_present", "ruf_count", "ruf_invalid_count", "query_domain", "selectors_present", "selectors_missing",
    "selectors_unresolved", "selector_record_count", "dns_present", "id_present", "policy_fetch_status",
    "policy_mode", "logo_url_present", "logo_url_is_https", "authority_url_present", "authority_url_is_https",
    "spf_mechanism_count", "dmarc_rua_count", "dmarc_cisa_rua_present", "dmarc_rua_invalid_count",
    "tls_rpt_rua_count", "mta_sts_id_present", "dmarc_pct", "dmarc_pct_partial", "dmarc_present",
    "dmarc_record_count", "spf_present", "spf_multiple_records", "dmarc_multiple_records", "mta_sts_dns_present",
    "mta_sts_policy_fetch_status", "mta_sts_policy_http_status", "tls_rpt_present", "bimi_present", "bimi_logo_https",
    "dkim_selectors_present", "dkim_selectors_missing", "dkim_selectors_unresolved", "rdata_count", "query_answer_count",
)


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in _keys(item)}
    return set()


def _every_emitted_key() -> dict:
    return {"records": [
        {"domain": "review.test",
         "spf": {"present": True, "kind": "spf", "all_qualifier": "-", "multiple_records": False, "mechanisms": ["-all"],
                 "records": [SPF]},
         "dmarc": {"present": True, "kind": "dmarc", "policy": "reject", "subdomain_policy": "reject", "pct": 100,
                   "pct_partial": False, "aggregate_addresses": ["mailto:agg@receiver.test"],
                   "aggregate_addresses_invalid": [], "forensic_addresses": ["mailto:forensic@receiver.test"],
                   "forensic_addresses_invalid": [], "multiple_records": False, "records": [DMARC],
                   "query_name": "_dmarc.review.test"},
         "dkim": {"selectors_present": ["google"], "selectors_missing": [], "selectors_unresolved": [],
                  "selectors": {"google": [DKIM]}},
         "mta_sts": {"dns_present": True, "id": "x", "policy": {"fetch_status": "ok", "mode": "enforce"}},
         "tls_rpt": {"present": True, "rua": []},
         "bimi": {"present": True, "logo_url": "https://review.test/l.svg", "logo_url_is_https": True,
                  "authority_url": None, "authority_url_is_https": None}},
        {"kind": "dns_posture", "domain": "review.test", "spf_present": True, "spf_mechanisms": ["-all"],
         "spf_multiple_records": False, "dmarc_present": True, "dmarc_multiple_records": False, "dmarc_record_count": 1,
         "dmarc_pct": 100, "dmarc_pct_partial": False, "dmarc_aggregate_addresses": [], "dmarc_aggregate_invalid": [],
         "dkim_selectors_present": [], "dkim_selectors_missing": [], "dkim_selectors_unresolved": [],
         "mta_sts_dns_present": True, "mta_sts_id": "x", "mta_sts_policy_fetch_status": "ok",
         "mta_sts_policy_http_status": 200, "tls_rpt_present": True, "tls_rpt_rua": [], "bimi_present": False,
         "bimi_logo_https": None},
        {"domain": "review.test", "rdata": [], "log": [{"query_name": "x.review.test", "query_answers": []}]},
    ]}


def test_every_emitted_predicate_key_survives_a_matching_person_name() -> None:
    fixed_key = bytes(range(32))
    plain = redact_output(_every_emitted_key(), context=RedactionContext(key=fixed_key))
    assert _keys(plain) - {"domain", "kind", "log", "records", "spf", "dmarc", "dkim", "mta_sts", "tls_rpt", "bimi"} == set(
        EMITTED_KEYS)
    for key in EMITTED_KEYS:
        person = " ".join(word.capitalize() for word in key.split("_"))
        context = RedactionContext(key=fixed_key, protected_names=frozenset({person}))
        assert redact_output(_every_emitted_key(), context=context) == plain, person


def test_an_unreadable_percentage_is_never_partial_enforcement_and_never_a_pass() -> None:
    from azure_tenant_audit.baselines import build_baseline_alignment
    from azure_tenant_audit.findings import build_findings
    from azure_tenant_audit.normalize import build_normalized_snapshot

    def snapshot(pct: object) -> dict:
        row = {"domain": "a.example", "managed_by_microsoft": False, "spf": {"present": True, "all_qualifier": "-"},
               "dmarc": {"present": True, "policy": "reject", "pct": pct, "pct_partial": True},
               "dkim": {"selectors_present": ["selector1"], "selectors_missing": []},
               "mta_sts": {"dns_present": True, "policy": {"fetch_status": "ok", "mode": "enforce"}},
               "tls_rpt": {"present": True}, "bimi": {"present": False}}
        return build_normalized_snapshot(tenant_name="t", run_id="r",
                                         collector_payloads={"dns_posture": {"domainPosture": {"value": [row]}}})

    rule = "dns_posture.dmarc_pct_partial"
    for pct, fires, status in ((DMARC, False, "not_assessed"), (None, False, "not_assessed"), ("50", False, "not_assessed"),
                               (50, True, "fail"), (100, False, "pass")):
        data = snapshot(pct)
        findings = build_findings([], normalized_snapshot=data)
        assert any(row["rule_id"] == rule for row in findings) is fires, pct
        alignment = build_baseline_alignment(
            findings, normalized_snapshot=data, coverage_ledger=[{"collector": "dns_posture",
                                                                  "coverage_status": "complete_exact_scope"}],
            mappings={rule: {"cis_m365_v7": ["T.1"]}},
        )
        statuses = {item["status"] for control in alignment["frameworks"]["cis_m365_v7"]["controls"]
                    for item in control["rule_statuses"] if item["rule_id"] == rule}
        assert statuses == {status}, pct
