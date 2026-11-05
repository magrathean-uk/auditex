"""EXO DKIM and DMARC parsers, ported from the v3.9 value-rule reference.

The grammar deliberately distinguishes absent records, unusable answers and
empty DNS answers. Only constant catalogue texts leave this module.
"""
from __future__ import annotations

import re

from .helpers import _list_state
from .record import ITEM_LABEL, _A, _rec


_DMARC_V = re.compile(r"^[vV]\s*=\s*DMARC1\s*(?:;|$)")


_TAG = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(.*)$", re.S)


# The reference pattern was ^mailto:([^\s,!;]+@[^\s,!;]+?)(?:![0-9]+[kKmMgGtT]?)?$ (re.I). Its first class holds "@", so on
# a long run of "@" followed by a failing tail it tried every split (quadratic in the string length). The body is the maximal
# run of characters that are none of whitespace , ! ; (the optional size suffix can only start at the first other character),
# so one linear pattern finds it and "@" is then looked for at an index with a character on each side: the same language,
# the same group, no backtracking over the body.
_URI = re.compile(r"^mailto:([^\s,!;]+)(?:![0-9]+[kKmMgGtT]?)?$", re.I)


DHS_ADDRESS = "reports@dmarc.cyber.dhs.gov"


DMARC_P = ("none", "quarantine", "reject")


def parse_tags(text):
    """tag=value list split on ';' (empty items allowed, so a trailing ';' is optional). -> (tags {name: [values]}, syntax_ok)."""
    tags, ok = {}, True
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        m = _TAG.match(part)
        if not m:
            ok = False
            continue
        tags.setdefault(m.group(1).lower(), []).append(m.group(2).strip())
    return tags, ok


def parse_dmarc(text):
    """None when the string is not a DMARC record (first tag is not v=DMARC1); else {"tags", "syntax"}."""
    t = text.strip()
    if not _DMARC_V.match(t):
        return None
    tags, ok = parse_tags(t)
    return {"tags": tags, "syntax_ok": ok}


def parse_uris(value):
    addrs, junk = [], 0
    for p in value.split(","):
        m = _URI.match(p.strip())
        if m and m.group(1).find("@", 1, len(m.group(1)) - 1) != -1:
            addrs.append(m.group(1).lower())
        else:
            junk += 1
    return addrs, junk


def _one(tags, k):
    v = tags.get(k)
    if v is None:
        return "absent", None
    return ("dup", None) if len(v) > 1 else ("one", v[0])


def _need_published(tags):
    s, v = _one(tags, "p")
    if s == "dup":
        return "unusable", "tag_duplicated"
    if s == "absent":
        return "bad", "p_absent"
    return ("ok", "") if v.lower() in DMARC_P else ("bad", "p_invalid")


def _need_reject(tags):
    s, v = _one(tags, "p")
    if s == "dup":
        return "unusable", "tag_duplicated"
    if s == "absent":
        return "bad", "p_absent"
    if v.lower() == "reject":
        return "ok", ""
    return ("bad", "p_not_reject") if v.lower() in DMARC_P else ("bad", "p_invalid")


def _need_dhs(tags):
    s, v = _one(tags, "rua")
    if s == "dup":
        return "unusable", "tag_duplicated"
    if s == "absent":
        return "bad", "rua_absent"
    addrs, junk = parse_uris(v)
    if DHS_ADDRESS in addrs:
        return "ok", ""
    return ("unusable", "uri_unusable") if junk else ("bad", "dhs_address_absent")


def _need_contacts(tags):
    sa, va = _one(tags, "rua")
    sf, vf = _one(tags, "ruf")
    if "dup" in (sa, sf):
        return "unusable", "tag_duplicated"
    ra, ja = parse_uris(va) if sa == "one" else ([], 0)
    rf, jf = parse_uris(vf) if sf == "one" else ([], 0)
    rego_ok = len(ra) >= 2 and len(rf) >= 1
    agency = any(x != DHS_ADDRESS for x in ra) and any(x != DHS_ADDRESS for x in rf)      # v3.7 (lens B DLP-F3, D104): the baseline wants an agency contact in both RUA and RUF
    if rego_ok and agency:
        return "ok", ""
    if ja or jf:
        return "unusable", "uri_unusable"
    if sa == "absent":
        return "bad", "rua_absent"
    if sf == "absent":
        return "bad", "ruf_absent"
    return "bad", "agency_contact_missing" if rego_ok else "contacts_missing"


_NEEDS = {"dmarc_published": _need_published, "dmarc_reject": _need_reject, "dmarc_dhs_rua": _need_dhs, "dmarc_agency_contacts": _need_contacts}


def _dmarc_domain(entry, need):
    rd = entry.get("rdata", None) if "rdata" in entry else None
    if not isinstance(rd, list) or any(type(x) is not str for x in rd):
        return "unusable", "rdata_unusable"
    if not rd:
        return "unusable", "rdata_empty"     # v3.1 ruling 3 (D29): an empty answer is not distinguishable from a failed lookup in the evidence
    cands = [p for p in (parse_dmarc(x) for x in rd) if p is not None]
    if not cands:
        return "bad", "no_record"
    if len(cands) > 1:
        return "unusable", "multiple_records"
    if not cands[0]["syntax_ok"]:
        return "unusable", "record_syntax"
    res, sub = _NEEDS[need](cands[0]["tags"])
    if res == "bad" and len(rd) > 1:
        return "unusable", "other_strings_present"       # a continuation chunk could hold the missing tag
    return res, sub


def _dkim_string(text):
    """'valid' (first tag v=DKIM1 and a non-empty p), 'invalid', or 'syntax' (starts v=DKIM1 but has a malformed tag)."""
    t = text.strip()
    first = t.split(";", 1)[0].strip()
    if not re.match(r"^[vV]\s*=\s*DKIM1$", first):
        return "invalid"
    tags, ok = parse_tags(t)
    if not ok:
        return "syntax"
    p = tags.get("p", [""])
    return "valid" if len(p) == 1 and re.sub(r"\s+", "", p[0]) != "" else "invalid"


DOMAIN_NOT_MET = {      # v3.9 (c): one plain sentence per (need, failing sub-reason); no raw code, no `is not the case`. The sub-reason stays in the cell id.
    ("dkim_enabled", "no_signing_config"): "at least one domain has no DKIM signing configuration",
    ("dkim_enabled", "dkim_not_enabled"): "DKIM signing is not enabled for at least one domain",
    ("dkim_enabled", "no_dkim_record_entry"): "at least one domain has no DKIM record entry",
    ("dkim_enabled", "key_not_published"): "the DKIM key is not published for at least one domain",
    ("dmarc_published", "no_record"): "at least one domain has no DMARC record",
    ("dmarc_published", "p_absent"): "the DMARC record of at least one domain has no policy (p) tag",
    ("dmarc_published", "p_invalid"): "the DMARC record of at least one domain has a policy (p) tag that is not none, quarantine or reject",
    ("dmarc_reject", "no_record"): "at least one domain has no DMARC record",
    ("dmarc_reject", "p_absent"): "the DMARC record of at least one domain has no policy (p) tag",
    ("dmarc_reject", "p_invalid"): "the DMARC record of at least one domain has a policy (p) tag that is not none, quarantine or reject",
    ("dmarc_reject", "p_not_reject"): "the DMARC policy of at least one domain is not reject",
    ("dmarc_dhs_rua", "no_record"): "at least one domain has no DMARC record",
    ("dmarc_dhs_rua", "rua_absent"): "the DMARC record of at least one domain has no aggregate report address (rua)",
    ("dmarc_dhs_rua", "dhs_address_absent"): "the DMARC aggregate report address (rua) of at least one domain does not include the CISA address",
    ("dmarc_agency_contacts", "no_record"): "at least one domain has no DMARC record",
    ("dmarc_agency_contacts", "rua_absent"): "the DMARC record of at least one domain has no aggregate report address (rua)",
    ("dmarc_agency_contacts", "ruf_absent"): "the DMARC record of at least one domain has no failure report address (ruf)",
    ("dmarc_agency_contacts", "contacts_missing"): "the DMARC record of at least one domain does not name the required report contacts",
    ("dmarc_agency_contacts", "agency_contact_missing"): "the DMARC record of at least one domain names no agency contact other than the CISA address in its aggregate reports, its failure reports or both",
}


def _scan_domains(policy_id, name, results, what, cited, need=None):
    """results: list of (state, sub, labelled). Bad wins, then unusable, else met."""
    bad = [r for r in results if r[0] == "bad" and r[2]]
    if bad:
        return _rec(policy_id, "not_met", "domain_noncompliant", f"Requirement not met: {DOMAIN_NOT_MET[(need, bad[0][1])]}.",
                    "domain_noncompliant." + bad[0][1], None)
    unl = [r for r in results if r[0] == "bad" and not r[2]]
    if unl:
        return _A(policy_id, ITEM_LABEL, f"Data unusable: a record in {name} shows a failing domain but names no domain; the policy was not assessed.",
                  "domain_unlabelled", cited)
    un = [r for r in results if r[0] == "unusable"]
    empty = [r for r in un if r[1] in ("rdata_empty", "dkim_rdata_empty")]
    if un and empty and un[0] is empty[0]:
        return _A(policy_id, "data_unavailable_dns_answer_empty",
                  "Data unavailable: a DNS answer (rdata) is empty and the export does not say whether the lookup succeeded or failed; the policy was not assessed.",
                  "domain_unusable." + empty[0][1], cited)
    if un:
        return _A(policy_id, "data_unusable_dns_record", f"Data unusable: a DNS record could not be read exactly ({un[0][1]}); the policy was not assessed.",
                  "domain_unusable." + un[0][1], cited)
    return _rec(policy_id, "met", "all_domains_compliant", f"Requirement met: {what if what.endswith('every domain') else what + ' for every domain'}.", "all_compliant", None)


def _parser(policy_id, sp, sections):
    need = sp["need"]
    if need.startswith("dmarc"):
        name = sp["section"]
        out, items = _list_state(policy_id, sections, name)
        if out:
            return out
        res = [(*_dmarc_domain(e, need), type(e.get("domain")) is str) for e in items]
        return _scan_domains(policy_id, name, res, sp["what"], [name], need)
    for name in ("dkim_config", "dkim_records", "spf_records"):
        out, _ = _list_state(policy_id, sections, name)
        if out:
            return out
    cfg = [e for e in sections["dkim_config"] if isinstance(e, dict)]
    recs = [e for e in sections["dkim_records"] if isinstance(e, dict)]
    coexist = {c["Domain"] for c in cfg if type(c.get("Domain")) is str and c["Domain"].endswith(".mail.onmicrosoft.com")}
    # Indexed once, keyed exactly as the loop compared (== on a string domain, input order kept per domain): the per-domain
    # list scans were quadratic in the number of domains.
    cfg_by_domain, rec_by_domain = {}, {}
    for c in cfg:
        if type(c.get("Domain")) is str:
            cfg_by_domain.setdefault(c["Domain"], []).append(c)
    for r in recs:
        if type(r.get("domain")) is str:
            rec_by_domain.setdefault(r["domain"], []).append(r)
    res, seen = [], set()
    for e in (x for x in sections["spf_records"] if isinstance(x, dict)):
        d = e.get("domain")
        if type(d) is not str:
            res.append(("unusable", "spf_domain_absent", True))
            continue
        if d in seen or d in coexist:
            continue
        seen.add(d)
        mine = cfg_by_domain.get(d, [])
        if not mine:
            res.append(("bad", "no_signing_config", True))
            continue
        flags = [c.get("Enabled") for c in mine]
        if not any(f is True for f in flags):
            res.append(("bad", "dkim_not_enabled", True) if all(f is False for f in flags) else ("unusable", "enabled_flag_unusable", True))
            continue
        rr = rec_by_domain.get(d, [])
        if not rr:
            res.append(("bad", "no_dkim_record_entry", True))
            continue
        verdicts, unusable, empty = [], False, False
        for r in rr:
            rd = r.get("rdata", None) if "rdata" in r else None
            if not isinstance(rd, list) or any(type(x) is not str for x in rd):
                unusable = True
            elif not rd:
                empty = True                  # v3.1 ruling 3 (D29)
            else:
                verdicts += [_dkim_string(x) for x in rd]
        if "valid" in verdicts:
            res.append(("ok", "", True))
        elif unusable or "syntax" in verdicts:
            res.append(("unusable", "dkim_rdata_unusable", True))
        elif empty:
            res.append(("unusable", "dkim_rdata_empty", True))
        else:
            res.append(("bad", "key_not_published", True))
    return _scan_domains(policy_id, "spf_records", res, sp["what"], ["dkim_config", "dkim_records", "spf_records"], need)


def parser(policy_id: str, row: dict, sections: dict) -> dict:
    return _parser(policy_id, row["params"], sections)


KINDS = {"parser": parser}
