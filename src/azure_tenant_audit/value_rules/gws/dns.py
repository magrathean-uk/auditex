"""``gws_dns``: GMAIL.2.1, 3.1 and 4.1 to 4.4 on the ``gws_dns`` section (design M13 sections 7 and 8.2).

Follows SG:scubagoggles/rego/Gmail.rego:117-430, with the unknown-is-not-safe changes of design 8.4 and records parsed
as RFC 7208 (SPF) and RFC 7489 (DMARC) do rather than by substring (lead, 25 Nov 2026, L13 review):

- DKIM (2.1) and SPF (3.1) look at primary and secondary domains only; the DMARC rows (4.1 to 4.4) also look at alias
  domains (SG:scubagoggles/provider.py, ``get_dnsinfo``). An alias entry is skipped by 2.1 and 3.1 whatever else it
  holds, so its unreadable data weakens only the DMARC rows.
- DKIM: the three pinned selectors ``google``, ``selector1`` and ``selector2`` must all have been read (design 7);
  some answer among them starts ``v=DKIM1;``. Any other selector the collector holds is not read.
- SPF: exactly one record whose version section is ``v=spf1`` (RFC 7208 4.5, case-insensitive). Its terms must parse
  (RFC 7208 4.6, 5, 6; a malformed record fails), and it passes only when its single ``all`` is the final directive
  with qualifier ``-``, or it has no ``all`` and one ``redirect=`` modifier. ``~all``, ``?all``, ``+all`` and a bare
  ``all`` fail, and so does a second record.
- DMARC: exactly one record whose first tag is ``v=DMARC1`` (4.1). It is an RFC 6376 3.2 tag-list (blanks around
  names and values, tag names case-insensitive by the RFC 7489 6.4 grammar, ``DMARC1`` case-sensitive); a repeated tag
  or a malformed list makes the domain have no DMARC record. A missing or invalid ``p``, or an invalid ``sp``, reads as
  ``p=none`` when ``rua`` holds a valid URI, else as no record (RFC 7489 6.6.3). An author-domain record needs
  ``p=reject``; an inherited one needs ``sp=reject``, or no ``sp`` and ``p=reject`` (4.2). ``rua`` and ``ruf`` are
  RFC 7489 6.4 URI lists: a malformed URI, an empty ``mailto:`` among them, makes that tag count for nothing. 4.3 wants
  ``mailto:reports@dmarc.cyber.dhs.gov`` as a whole ``rua`` URI (the baseline names aggregate reports); 4.4 wants at
  least two ``rua`` and one ``ruf`` ``mailto:`` addresses.
- A non-DMARC TXT answer beside the DMARC record is never read for the later rows (design 8.3 D22).
- A domain with ``resolver_error`` is unknown, never compliant. A positively read violation wins over unknown
  domains, over a cut read and over a malformed list element: the domains that were read keep their violation
  whatever the unread ones hold (lead, 25 Nov 2026). A cut read with no violation, a malformed section or entry, a
  blank domain name and an empty domain list are unknown.

Only the fields a row reads are checked, so one domain's bad DKIM data never weakens its SPF answer. No domain name,
record or address ever enters an answer: every text is the catalogued constant of the row's cell.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from ..record import _rec

_SECTION = "gws_dns"
_SCOPES = {"primary_and_secondary", "all"}
_DKIM_SELECTORS = ("google", "selector1", "selector2")
_WSP = " \t"
_CISA_CONTACT = "reports@dmarc.cyber.dhs.gov"
_POLICIES = {"none", "quarantine", "reject"}
# RFC 6376 3.2: tag-name = ALPHA *ALNUMPUNC; tag-value = [ tval *( 1*WSP tval ) ], tval = 1*VALCHAR (%x21-3A / %x3C-7E).
# The two classes in _TAG_VALUE are disjoint, so the match is linear.
_TAG_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_TAG_VALUE = re.compile(r"[\x21-\x3a\x3c-\x7e]+(?:[ \t]+[\x21-\x3a\x3c-\x7e]+)*")
# RFC 7489 6.4: dmarc-uri = URI [ "!" 1*DIGIT [ "k" / "m" / "g" / "t" ] ]; a comma or "!" inside the URI is encoded.
_SIZE = r"(?:![0-9]+[kmgtKMGT]?)?"
_MAILTO = re.compile(r"[Mm][Aa][Ii][Ll][Tt][Oo]:([^\s@,;!?]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)" + _SIZE)
_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[\x22-\x2b\x2d-\x3a\x3c-\x7e]+" + _SIZE)
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
# RFC 7208 12: mechanism names and modifier names are case-insensitive.
_MECHANISM = re.compile(r"([+?~-]?)(all|include|a|mx|ptr|ip4|ip6|exists)([:/].*)?", re.IGNORECASE | re.DOTALL)
_MODIFIER = re.compile(r"([A-Za-z][A-Za-z0-9_.-]*)=(.*)", re.DOTALL)


class _Bad(Exception):
    """One domain entry does not have the shape its check reads."""


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise _Bad
    return value


def _identity(name: Any) -> bool:
    """A domain name the row can stand for: a non-empty string with no blank or control character."""
    return isinstance(name, str) and bool(name) and all(char.isprintable() and not char.isspace() for char in name)


def _dkim(domain: dict) -> bool:
    dkim = domain.get("dkim")
    selectors = dkim.get("selectors") if isinstance(dkim, dict) else None
    if not isinstance(selectors, dict):
        raise _Bad
    records = [record for selector in _DKIM_SELECTORS for record in _strings(selectors.get(selector))]
    return any(record.startswith("v=DKIM1;") for record in records)


# --- SPF (RFC 7208) ---------------------------------------------------------------------------------------------------

def _is_spf(record: str) -> bool:
    """RFC 7208 4.5: the version section is exactly ``v=spf1``, ended by a space or the end of the record."""
    return record[:6].lower() == "v=spf1" and (len(record) == 6 or record[6] == " ")


def _ip_argument(argument: str, version: int) -> bool:
    """``:address`` with an optional ``/prefix`` (RFC 7208 5.6)."""
    if not argument.startswith(":"):
        return False
    address, slash, prefix = argument[1:].partition("/")
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if parsed.version != version:
        return False
    return not slash or (prefix.isdigit() and len(prefix) <= 3 and int(prefix) <= (32 if version == 4 else 128))


def _directive(term: str) -> tuple[str, str] | None | bool:
    """``(qualifier, mechanism)`` for a well-formed directive, False for a malformed one, None when not a directive."""
    match = _MECHANISM.fullmatch(term)
    if match is None:
        return None
    qualifier, name, argument = match[1], match[2].lower(), match[3]
    if name == "all":
        ok = argument is None
    elif name in ("include", "exists"):
        ok = argument is not None and argument.startswith(":") and len(argument) > 1
    elif name in ("ip4", "ip6"):
        ok = argument is not None and _ip_argument(argument, 4 if name == "ip4" else 6)
    elif name == "ptr":
        ok = argument is None or (argument.startswith(":") and len(argument) > 1)
    else:  # a, mx: [ ":" domain-spec ] [ dual-cidr-length ]
        ok = argument is None or len(argument) > 1
    return (qualifier or "+", name) if ok else False


def _spf_passes(record: str) -> bool:
    """One SPF record, parsed by terms: a final ``-all``, or no ``all`` and a ``redirect=`` modifier."""
    directives: list[tuple[str, str]] = []
    modifiers: dict[str, str] = {}
    for term in record[6:].split(" "):
        if not term:
            continue  # terms are separated by one or more spaces, and trailing spaces are allowed
        if any(not 0x21 <= ord(char) <= 0x7E for char in term):
            return False
        directive = _directive(term)
        if directive is False:
            return False
        if directive is not None:
            directives.append(directive)
            continue
        modifier = _MODIFIER.fullmatch(term)
        if modifier is None:
            return False
        name = modifier[1].lower()
        if name in ("redirect", "exp") and name in modifiers:
            return False  # RFC 7208 6: each at most once, else a permanent error
        modifiers[name] = modifier[2]
    alls = [index for index, (_, mechanism) in enumerate(directives) if mechanism == "all"]
    if alls:  # RFC 7208 6.1: redirect is ignored when the record has an all mechanism
        return alls == [len(directives) - 1] and directives[-1][0] == "-"
    return bool(modifiers.get("redirect"))


def _spf(domain: dict) -> bool:
    spf = domain.get("spf")
    records = [record for record in _strings(spf.get("records") if isinstance(spf, dict) else None)
               if _is_spf(record)]
    return len(records) == 1 and _spf_passes(records[0])


# --- DMARC (RFC 7489) -------------------------------------------------------------------------------------------------

def _tag_list(record: str) -> dict[str, str] | None:
    """RFC 6376 3.2 tag-list with RFC 7489 6.4 tag names (case-insensitive, so kept lower case): None when malformed
    or a tag repeats. Blanks after a closing ``;`` are tolerated."""
    pieces = record.split(";")
    if len(pieces) > 1 and not pieces[-1].strip(_WSP):
        pieces.pop()
    tags: dict[str, str] = {}
    for piece in pieces:
        name, equals, value = piece.partition("=")
        name, value = name.strip(_WSP), value.strip(_WSP)
        if not equals or not _TAG_NAME.fullmatch(name) or (value and not _TAG_VALUE.fullmatch(value)):
            return None
        name = name.lower()
        if name in tags:
            return None
        tags[name] = value
    return tags


def _is_dmarc(record: str) -> bool:
    """RFC 7489 6.6.3: a record whose first tag is ``v=DMARC1`` (``DMARC1`` case-sensitive)."""
    name, equals, value = record.split(";", 1)[0].partition("=")
    return bool(equals) and name.strip(_WSP).lower() == "v" and value.strip(_WSP) == "DMARC1"


def _uris(value: str | None) -> list[str] | None:
    """The ``mailto:`` addresses of an RFC 7489 6.4 URI list; None when the tag is absent or any URI is malformed."""
    if value is None:
        return None
    addresses = []
    for token in value.split(","):
        token = token.strip(_WSP)
        scheme = _SCHEME.match(token)
        if scheme is None:
            return None
        if scheme[0].lower() == "mailto:":
            mailto = _MAILTO.fullmatch(token)
            if mailto is None:
                return None
            addresses.append(mailto[1])
        elif not _URI.fullmatch(token):
            return None
    return addresses


def _policy(tags: dict[str, str]) -> dict[str, str] | None:
    """The record as RFC 7489 6.6.3 applies it: invalid or absent ``p``, or invalid ``sp``, reads as ``p=none`` when
    ``rua`` holds a valid URI, else there is no policy."""
    p, sp = tags.get("p", "").lower(), tags.get("sp")
    if p in _POLICIES and (sp is None or sp.lower() in _POLICIES):
        return {**tags, "p": p, **({"sp": sp.lower()} if sp is not None else {})}
    if _uris(tags.get("rua")):
        return {**{name: value for name, value in tags.items() if name != "sp"}, "p": "none"}
    return None


def _dmarc_record(domain: dict) -> tuple[dict[str, str] | None, bool]:
    """The one DMARC record's tags as applied (None when there are none, several, or it is malformed) and whether it
    came from a parent."""
    dmarc = domain.get("dmarc")
    if not isinstance(dmarc, dict):
        raise _Bad
    valid = [record for record in _strings(dmarc.get("records")) if _is_dmarc(record)]
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
    tags = _tag_list(valid[0])
    return (_policy(tags) if tags is not None else None), inherited


def _published(domain: dict) -> bool:
    return _dmarc_record(domain)[0] is not None


def _reject(domain: dict) -> bool:
    tags, inherited = _dmarc_record(domain)
    if tags is None:
        return False
    return (tags.get("sp", tags["p"]) if inherited else tags["p"]) == "reject"


def _cisa_contact(domain: dict) -> bool:
    tags, _ = _dmarc_record(domain)
    addresses = _uris(tags.get("rua")) if tags is not None else None
    return addresses is not None and _CISA_CONTACT in (address.lower() for address in addresses)


def _agency_contact(domain: dict) -> bool:
    tags, _ = _dmarc_record(domain)
    if tags is None:
        return False
    rua, ruf = _uris(tags.get("rua")), _uris(tags.get("ruf"))
    return rua is not None and ruf is not None and len(rua) >= 2 and len(ruf) >= 1


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
    if not isinstance(domains, list) or not isinstance(section.get("complete"), bool):
        return _answer(policy_id, row, "section_shape_unusable")
    violates = malformed = unusable = unknown = covered = False
    for entry in domains:
        if not isinstance(entry, dict):
            malformed = True  # decided after the scan, so a domain that was read keeps its violation
            continue
        alias = entry.get("alias")
        if not isinstance(alias, bool):
            unusable = True
            continue
        if alias and scope != "all":
            continue  # out of this row's scope, whatever else the entry holds
        error = entry.get("resolver_error")
        if not _identity(entry.get("domain")) or not isinstance(error, bool):
            unusable = True
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
    if malformed:
        return _answer(policy_id, row, "section_shape_unusable")
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
