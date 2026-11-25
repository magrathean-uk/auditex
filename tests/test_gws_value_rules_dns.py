"""``gws_dns`` kind (design M13 section 8.2; SG:scubagoggles/rego/Gmail.rego:117-430): GMAIL.2.1, 3.1, 4.1 to 4.4.

The vectors in ``tests/fixtures/gws-value-rules/dns.jsonl`` carry the verdict, cell and code as literals and replay in
``test_gws_value_rules_replay.py``. These tests pin the rows, the coverage of the vector file and the properties no
single vector shows: no domain or record text in an answer, input untouched, order independence, bad parameters.
"""
from __future__ import annotations

import copy
import itertools
import json
from collections import defaultdict
from pathlib import Path

import pytest

from azure_tenant_audit.value_rules import gws
from azure_tenant_audit.value_rules.gws import dns as dns_module
from azure_tenant_audit.value_rules.gws.catalogue import catalogue

VECTORS = [json.loads(line) for line in
           (Path(__file__).parent / "fixtures" / "gws-value-rules" / "dns.jsonl").read_text("utf-8").splitlines()
           if line.strip()]
ROWS = {
    "GWS.GMAIL.2.1v1": {"check": "dkim", "domains": "primary_and_secondary"},
    "GWS.GMAIL.3.1v1": {"check": "spf", "domains": "primary_and_secondary"},
    "GWS.GMAIL.4.1v1": {"check": "dmarc_published", "domains": "all"},
    "GWS.GMAIL.4.2v1": {"check": "dmarc_reject", "domains": "all"},
    "GWS.GMAIL.4.3v1": {"check": "dmarc_cisa_contact", "domains": "all"},
    "GWS.GMAIL.4.4v1": {"check": "dmarc_agency_contact", "domains": "all"},
}
CELLS = {"section_not_collected", "no_domain_violates", "domain_violates", "section_shape_unusable",
         "domain_record_unusable", "dns_read_incomplete", "no_domains", "resolver_error"}


def test_rows_and_kind_are_the_shipped_ones():
    data = catalogue()
    assert set(data["kinds"]["gws_dns"]["cells"]) == CELLS
    dns_rows = {pid: row for pid, row in data["policies"].items() if row["kind"] == "gws_dns"}
    assert {pid: row["params"] for pid, row in dns_rows.items()} == ROWS
    assert all(row["sections"] == ["gws_dns"] for row in dns_rows.values())
    assert "gws_dns" in gws._registry()


def test_every_row_has_every_reachable_cell_vector():
    seen = defaultdict(set)
    for vector in VECTORS:
        seen[vector["policy"]].add(vector["cell"])
    assert dict(seen) == {pid: CELLS for pid in ROWS}


def test_vectors_use_only_synthetic_domains():
    sections = [vector["sections"].get("gws_dns") for vector in VECTORS]
    names = {entry["domain"] for section in sections if isinstance(section, dict)
             for entry in section.get("domains", []) if isinstance(entry, dict)}
    assert names <= {"", "  ", "a.example.com", "b.example.org", "b.example.net"}
    assert "@" not in "".join(name for name in names)


def test_no_domain_or_record_text_in_any_answer():
    for vector in VECTORS:
        record = gws.assess(vector["policy"], copy.deepcopy(vector["sections"]))
        text = json.dumps(record)
        for leak in ("example", "mailto", "v=spf1", "DMARC1", "DKIM1", "dhs.gov", "_dmarc"):
            assert leak not in text, vector["vector_id"]
        assert record["detail"] == {}, vector["vector_id"]
        assert record["cited_sections"] == ["gws_dns"], vector["vector_id"]


def test_assess_does_not_change_its_input():
    for vector in VECTORS:
        sections = copy.deepcopy(vector["sections"])
        gws.assess(vector["policy"], sections)
        assert sections == vector["sections"], vector["vector_id"]


def _dom(name, spf, own_dmarc, alias=False):
    return {"domain": name, "alias": alias, "resolver_error": False, "spf": {"records": spf},
            "dkim": {"selectors": {"google": ["v=DKIM1; p=A"], "selector1": [], "selector2": []}},
            "dmarc": {"query_name": "_dmarc." + name, "inherited": False, "records": own_dmarc}}


def test_answer_does_not_depend_on_domain_order():
    good = _dom("a.example.com", ["v=spf1 -all"], ["v=DMARC1; p=reject"])
    bad = _dom("b.example.org", ["v=spf1 ~all"], ["v=DMARC1; p=none"])
    broken = {**_dom("c.example.net", ["v=spf1 -all"], []), "spf": "x"}
    errored = {"domain": "d.example.net", "alias": False, "resolver_error": True}
    for policy in ROWS:
        answers = set()
        for order in itertools.permutations([good, bad, broken, errored]):
            record = gws.assess(policy, {"gws_dns": {"complete": True, "domains": list(order)}})
            answers.add((record["verdict"], record["cell"]))
        assert len(answers) == 1, policy


def test_one_check_never_reads_another_checks_fields():
    # Only SPF is malformed: every DMARC and DKIM row still answers from its own fields.
    entry = {**_dom("a.example.com", [], ["v=DMARC1; p=reject; rua=mailto:a@example.com,mailto:b@example.org; "
                                         "ruf=mailto:f@example.com"]), "spf": None}
    verdicts = {policy: gws.assess(policy, {"gws_dns": {"complete": True, "domains": [entry]}})["cell"]
                for policy in ROWS}
    assert verdicts == {"GWS.GMAIL.2.1v1": "no_domain_violates", "GWS.GMAIL.3.1v1": "domain_record_unusable",
                        "GWS.GMAIL.4.1v1": "no_domain_violates", "GWS.GMAIL.4.2v1": "no_domain_violates",
                        "GWS.GMAIL.4.3v1": "domain_violates", "GWS.GMAIL.4.4v1": "no_domain_violates"}


def test_resolver_error_is_never_met():
    errored = {"domain": "a.example.com", "alias": False, "resolver_error": True}
    for policy in ROWS:
        record = gws.assess(policy, {"gws_dns": {"complete": True, "domains": [errored]}})
        assert (record["verdict"], record["cell"]) == ("not_assessed", "resolver_error"), policy


@pytest.mark.parametrize("params", [{}, {"check": "spf"}, {"check": "spf", "domains": "some"},
                                    {"check": "mx", "domains": "all"}, {"check": ["spf"], "domains": "all"}])
def test_unknown_parameters_raise(params):
    row = {"params": params, "cells": {}, "sections": ["gws_dns"]}
    with pytest.raises(ValueError):
        dns_module.gws_dns("GWS.GMAIL.3.1v1", row, {"gws_dns": {"complete": True, "domains": []}})


def test_a_long_run_of_blanks_is_linear():
    # A quadratic blank-stripping regex took about ten seconds on 80,000 blanks.
    import time
    entry = _dom("a.example.com", ["v=spf1 -all"], ["v=DMARC1;" + " " * 400000])
    started = time.monotonic()
    record = gws.assess("GWS.GMAIL.4.2v1", {"gws_dns": {"complete": True, "domains": [entry]}})
    assert (record["verdict"], record["cell"]) == ("not_met", "domain_violates")
    assert time.monotonic() - started < 3


def test_long_records_parse_in_linear_time():
    # The SPF term and DMARC tag and URI parsers must not backtrack on long input.
    import time
    long_rua = "v=DMARC1; p=reject; rua=mailto:" + "a" * 200000 + "@" + "b." * 100000 + "example.com!"
    long_spf = "v=spf1 " + "include:" + "x" * 200000 + " " + " " * 200000 + "~all"
    entry = _dom("a.example.com", [long_spf], [long_rua])
    started = time.monotonic()
    answers = {policy: gws.assess(policy, {"gws_dns": {"complete": True, "domains": [entry]}})["cell"]
               for policy in ("GWS.GMAIL.3.1v1", "GWS.GMAIL.4.3v1", "GWS.GMAIL.4.4v1")}
    assert answers == {"GWS.GMAIL.3.1v1": "domain_violates", "GWS.GMAIL.4.3v1": "domain_violates",
                       "GWS.GMAIL.4.4v1": "domain_violates"}
    assert time.monotonic() - started < 3


def test_oversized_numbers_and_long_macros_are_malformed_not_errors():
    # Digit runs past Python's int conversion limit (4,300 digits) must answer, not raise, and parse in linear time.
    import time
    cases = {
        ("GWS.GMAIL.3.1v1", "v=spf1 a:%{d" + "1" * 10000 + "}.example.net -all", None): "no_domain_violates",
        ("GWS.GMAIL.3.1v1", "v=spf1 a:%{d" + "0" * 10000 + "}.example.net -all", None): "domain_violates",
        ("GWS.GMAIL.3.1v1", "v=spf1 ip4:192.0.2.1/² -all", None): "domain_violates",
        ("GWS.GMAIL.3.1v1", "v=spf1 include:" + "%{d}" * 100000 + ".example.net -all", None): "no_domain_violates",
        ("GWS.GMAIL.4.3v1", "v=spf1 -all", "v=DMARC1; p=reject; rua=mailto:reports@dmarc.cyber.dhs.gov!" + "9" * 10000):
            "domain_violates",
        ("GWS.GMAIL.4.3v1", "v=spf1 -all", "v=DMARC1; p=reject; rua=mailto:reports@dmarc.cyber.dhs.gov!" + "0" * 10000
         + "1k"): "no_domain_violates",
        ("GWS.GMAIL.4.4v1", "v=spf1 -all", "v=DMARC1; p=reject; rua=mailto:%22" + "a" * 200000 + "%22@example.com?"
         + "a=b&" * 50000 + "c=d,mailto:" + "a." * 100000 + "a@example.org; ruf=mailto:f@example.com"):
            "no_domain_violates",
    }
    started = time.monotonic()
    answers = {key: gws.assess(key[0], {"gws_dns": {"complete": True, "domains": [
        _dom("a.example.com", [key[1]], [key[2]] if key[2] else [])]}})["cell"] for key in cases}
    assert answers == cases
    assert time.monotonic() - started < 3
