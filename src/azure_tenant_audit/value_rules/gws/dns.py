"""``gws_dns``: GMAIL.2.1, 3.1 and 4.1 to 4.4 on the ``gws_dns`` section (design M13 sections 7 and 8.2).

Follows SG:scubagoggles/rego/Gmail.rego:117-430, with the unknown-is-not-safe changes of design 8.4:

- DKIM (2.1) and SPF (3.1) look at primary and secondary domains only; the DMARC rows (4.1 to 4.4) also look at alias
  domains (SG:scubagoggles/provider.py, ``get_dnsinfo``).
- DKIM: some selector holds a record starting ``v=DKIM1;``. SPF: exactly one record, ending ``-all`` or containing
  ``redirect`` (``~all`` fails, so does a second record).
- DMARC: exactly one record starting ``v=DMARC1;`` (4.1), and the later rows read that record only. A record found at
  the author domain needs ``p=reject``; one inherited from a parent domain needs ``sp=reject``, or no ``sp`` and
  ``p=reject`` (4.2). 4.3 wants the CISA reporting address in the record. 4.4 wants exactly one ``rua`` and one
  ``ruf`` tag, with at least two ``rua`` and one ``ruf`` ``mailto:`` addresses.
- A domain with ``resolver_error`` is unknown, never compliant. A positively read violation wins over unknown
  domains, and over a cut read: the domains that were read keep their violation whatever the unread ones hold (lead,
  25 Nov 2026). A cut read with no violation, a malformed section or entry, and an empty domain list are unknown.

Only the fields a row reads are checked, so one domain's bad DKIM data never weakens its SPF answer. No domain name,
record or address ever enters an answer: every text is the catalogued constant of the row's cell.
"""
from __future__ import annotations

import re
from typing import Any

from ..record import _rec

_SECTION = "gws_dns"
_CISA_CONTACT = "mailto:reports@dmarc.cyber.dhs.gov"
_DELIMITERS = re.compile(r"([=;])")
_SCOPES = {"primary_and_secondary", "all"}


class _Bad(Exception):
    """One domain entry does not have the shape its check reads."""


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise _Bad
    return value


def _dkim(domain: dict) -> bool:
    dkim = domain.get("dkim")
    selectors = dkim.get("selectors") if isinstance(dkim, dict) else None
    if not isinstance(selectors, dict) or not selectors:
        raise _Bad
    records = [record for answers in selectors.values() for record in _strings(answers)]
    return any(record.startswith("v=DKIM1;") for record in records)


def _spf(domain: dict) -> bool:
    spf = domain.get("spf")
    records = [record for record in _strings(spf.get("records") if isinstance(spf, dict) else None)
               if record.startswith("v=spf1")]
    return len(records) == 1 and (records[0].endswith("-all") or "redirect" in records[0])


def _standard(record: str) -> str:
    """The record with blanks around ``=`` and ``;`` removed and a closing ``;``, as Gmail.rego:259-272 does (the
    closing ``;`` comes after the blanks are removed). Linear: a long run of blanks never backtracks."""
    pieces = _DELIMITERS.split(record)
    last = len(pieces) - 1
    for index in range(0, len(pieces), 2):  # the text between delimiters, never a delimiter itself
        if index > 0:
            pieces[index] = pieces[index].lstrip(" \t")
        if index < last:
            pieces[index] = pieces[index].rstrip(" \t")
    return "".join(pieces) + ";"


def _dmarc_record(domain: dict) -> tuple[str | None, bool]:
    """The one ``v=DMARC1;`` record (None when there are none or several) and whether it came from a parent."""
    dmarc = domain.get("dmarc")
    if not isinstance(dmarc, dict):
        raise _Bad
    valid = [record for record in _strings(dmarc.get("records")) if record.startswith("v=DMARC1;")]
    if len(valid) != 1:
        return None, False
    name, inherited = dmarc.get("query_name"), dmarc.get("inherited")
    if not isinstance(name, str) or not isinstance(inherited, bool):
        raise _Bad
    # The record is the author domain's own when the final query name is exactly ``_dmarc.<domain>`` (Gmail.rego:
    # 274-278); a parent's is ``_dmarc.<ancestor>``. The section's flag must say the same, and a name that is neither
    # means the record is not this domain's, so the entry is unusable.
    host = domain["domain"]
    own = name == "_dmarc." + host
    parent = name.startswith("_dmarc.") and len(name) > 7 and host.endswith("." + name[7:])
    if not (parent if inherited else own):
        raise _Bad
    return valid[0], inherited


def _published(domain: dict) -> bool:
    return _dmarc_record(domain)[0] is not None


def _reject(domain: dict) -> bool:
    record, inherited = _dmarc_record(domain)
    if record is None:
        return False
    text = _standard(record)
    if not inherited:
        return ";p=reject;" in text
    return ";sp=reject;" in text or (";sp=" not in text and ";p=reject;" in text)


def _cisa_contact(domain: dict) -> bool:
    record, _ = _dmarc_record(domain)
    return record is not None and _CISA_CONTACT in record


def _addresses(parts: list[str], tag: str) -> tuple[int, int]:
    """(tags named ``tag``, ``mailto:`` addresses in their first value), Gmail.rego:392-416."""
    tags = [part for part in parts if part.lower().startswith(tag)]
    addresses = [address for part in tags for address in part.split("=")[1].split(",")
                 if address.strip(" ").lower().startswith("mailto:")]
    return len(tags), len(addresses)


def _agency_contact(domain: dict) -> bool:
    record, _ = _dmarc_record(domain)
    if record is None:
        return False
    parts = [part.strip(" ") for part in record.split(";") if part.strip(" ")]
    (rua_tags, rua), (ruf_tags, ruf) = _addresses(parts, "rua="), _addresses(parts, "ruf=")
    return rua_tags == 1 and ruf_tags == 1 and rua >= 2 and ruf >= 1


_CHECKS = {"dkim": _dkim, "spf": _spf, "dmarc_published": _published, "dmarc_reject": _reject,
           "dmarc_cisa_contact": _cisa_contact, "dmarc_agency_contact": _agency_contact}


def _answer(policy_id: str, row: dict, cell: str) -> dict[str, Any]:
    entry = row["cells"][cell]
    return _rec(policy_id, entry["verdict"], entry["reason_code"], entry["reason_texts"][0], cell,
                list(row["sections"]))


def gws_dns(policy_id: str, row: dict, sections: dict) -> dict[str, Any]:
    params = row["params"]
    which, scope = params.get("check"), params.get("domains")
    if not isinstance(which, str) or which not in _CHECKS or not isinstance(scope, str) or scope not in _SCOPES:
        raise ValueError("GWS DNS rule has unknown parameters")
    check = _CHECKS[which]
    section = sections.get(_SECTION)
    domains = section.get("domains") if isinstance(section, dict) else None
    if (not isinstance(domains, list) or not isinstance(section.get("complete"), bool)
            or any(not isinstance(entry, dict) for entry in domains)):
        return _answer(policy_id, row, "section_shape_unusable")
    violates = unusable = unknown = covered = False
    for entry in domains:
        alias, error = entry.get("alias"), entry.get("resolver_error")
        name = entry.get("domain")
        if (not isinstance(name, str) or not name or not isinstance(alias, bool) or not isinstance(error, bool)):
            unusable = True
            continue
        if alias and scope != "all":
            continue
        covered = True
        if error:
            unknown = True
            continue
        try:
            violates = violates or not check(entry)
        except _Bad:
            unusable = True
    if violates:
        return _answer(policy_id, row, "domain_violates")
    if section["complete"] is not True:
        return _answer(policy_id, row, "dns_read_incomplete")
    if unusable:
        return _answer(policy_id, row, "domain_record_unusable")
    if not covered:
        return _answer(policy_id, row, "no_domains")
    if unknown:
        return _answer(policy_id, row, "resolver_error")
    return _answer(policy_id, row, "no_domain_violates")


KINDS = {"gws_dns": gws_dns}
