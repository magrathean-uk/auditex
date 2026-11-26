"""``gws_dns``: GMAIL.2.1, 3.1 and 4.1 to 4.4 on the ``gws_dns`` section (design M13 sections 7 and 8.2).

Follows SG:scubagoggles/rego/Gmail.rego:117-430, with the unknown-is-not-safe changes of design 8.4 and records parsed
as RFC 7208 (SPF) and RFC 7489 (DMARC) do rather than by substring (lead, 25 Nov 2026, L13 review):

- DKIM (2.1) and SPF (3.1) look at primary and secondary domains only; the DMARC rows (4.1 to 4.4) also look at alias
  domains (SG:scubagoggles/provider.py, ``get_dnsinfo``). An alias entry is skipped by 2.1 and 3.1 whatever else it
  holds, so its unreadable data weakens only the DMARC rows.
- DKIM: the three pinned selectors ``google``, ``selector1`` and ``selector2`` must all have been read (design 7);
  some answer among them starts ``v=DKIM1;``. Any other selector the collector holds is not read.
- SPF: exactly one record whose version section is ``v=spf1`` (RFC 7208 4.5, case-insensitive). Its terms must parse
  (RFC 7208 4.6, 5, 6 and 7: every domain-spec and macro, CIDR length, IP address, ``redirect`` and ``exp`` argument
  and unknown-modifier macro-string, with no empty label in a domain-spec; a malformed record establishes no policy and fails), and it passes only when
  its single ``all`` is the final directive with qualifier ``-``, or it has no ``all`` and one ``redirect=`` modifier.
  ``~all``, ``?all``, ``+all`` and a bare ``all`` fail, and so does a second record.
- DMARC: exactly one record whose first tag is ``v=DMARC1`` (4.1). It is an RFC 6376 3.2 tag-list (blanks around
  names and values, tag names case-insensitive by the RFC 7489 6.4 grammar, ``DMARC1`` case-sensitive); a repeated tag
  or a malformed list makes the domain have no DMARC record. A missing or invalid ``p``, or an invalid ``sp``, reads as
  ``p=none`` when ``rua`` holds a valid URI, else as no record (RFC 7489 6.6.3). An author-domain record needs
  ``p=reject``; an inherited one needs ``sp=reject``, or no ``sp`` and ``p=reject`` (4.2). Tag order after ``v`` is
  not enforced (receivers and ScubaGoggles read tags in any order; lead, 25 Nov 2026). ``rua`` and ``ruf`` are RFC 7489
  6.4 URI lists: each URI is RFC 3986 with an optional size limit within 64 bits, and a ``mailto:`` URI is RFC 6068
  (header fields allowed; its ``to`` part and ``to`` fields are percent-decoded RFC 5322 addr-specs). A malformed URI,
  or a ``mailto:`` naming no recipient, makes that tag count for nothing in 4.3 and 4.4; the 6.6.3 fallback needs only
  one syntactically valid URI of any scheme (RFC 3986: a closed IP literal and, for ``http`` and ``https``, a host).
  A ``mailto:`` URI is read by its raw text: the ``@`` between local part and domain must be unencoded, a domain
  literal's brackets and a second recipient's comma must be percent-encoded (RFC 6068 2, RFC 3986 2.2). Known
  limitation: a ``to`` header field whose value carries a display name (``Name <addr>``) is not read, and the
  recipient in it counts for nothing; real DMARC records do not use it. 4.3 wants a ``rua`` address whose local part is exactly ``reports`` (RFC
  5321 2.4) at ``dmarc.cyber.dhs.gov`` in any case; 4.4 wants at least two ``rua`` and one ``ruf`` addresses.
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
from urllib.parse import unquote

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
# RFC 7489 6.4: dmarc-uri = URI [ "!" 1*DIGIT [ "k" / "m" / "g" / "t" ] ], the number within an unsigned 64-bit
# integer; a comma or "!" inside the URI is percent-encoded, so a raw "!" can only start the size limit.
_SIZE = re.compile(r"[0-9]+[kmgtKMGT]?")
_U64 = 2 ** 64 - 1
_DIGITS = re.compile(r"[0-9]+")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
# RFC 3986 characters less "," and "!" (RFC 7489 6.4), and well-formed percent-encodings.
# Square brackets belong to an IP literal in the authority only (RFC 3986 2.2, 3.2.2); see ``_authority``.
_URI_REST = re.compile(r"(?:[A-Za-z0-9\-._~:/?#@$&'()*+;=]|%[0-9A-Fa-f]{2})*")
_REG_NAME = re.compile(r"(?:[A-Za-z0-9\-._~$&'()*+;=]|%[0-9A-Fa-f]{2})*")
_USERINFO = re.compile(r"(?:[A-Za-z0-9\-._~:$&'()*+;=]|%[0-9A-Fa-f]{2})*")
_PORT = re.compile(r"[0-9]*")
_IPVFUTURE = re.compile(r"v[0-9A-Fa-f]+\.[A-Za-z0-9\-._~$&'()*+;=:]+")
# RFC 6068 2: hfields = "?" hfield *( "&" hfield ), hfield = *qchar "=" *qchar; qchar = unreserved / pct-encoded /
# some-delims, less "," and "!" (RFC 7489 6.4).
_QCHARS = r"(?:[A-Za-z0-9\-._~$'()*+;:@]|%[0-9A-Fa-f]{2})*"
_HFIELDS = re.compile(_QCHARS + "=" + _QCHARS + "(?:&" + _QCHARS + "=" + _QCHARS + ")*")
# The raw ``to`` part before percent-decoding: addr-spec characters a URI may carry unencoded (RFC 6068 2).
# Brackets are not among them: a domain literal's brackets must be percent-encoded.
_TO_RAW = re.compile(r"(?:[A-Za-z0-9\-._~$&'()*+;:@=]|%[0-9A-Fa-f]{2})*")
_ATEXT = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~")
# RFC 7208 12: mechanism names and modifier names are case-insensitive.
_MECHANISM = re.compile(r"([+?~-]?)(all|include|a|mx|ptr|ip4|ip6|exists)([:/].*)?", re.IGNORECASE | re.DOTALL)
_MODIFIER = re.compile(r"([A-Za-z][A-Za-z0-9_.-]*)=(.*)", re.DOTALL)
# RFC 7208 7.1: macro-expand = "%{" macro-letter transformers *delimiter "}"; transformers = *DIGIT [ "r" ]. The
# letters c, r and t belong only in explanation text (7.3), never in a record.
_MACRO = re.compile(r"\{([slodiphvSLODIPHV])([0-9]*)([rR]?)[.\-+,/_=]*\}")
_TOPLABEL = re.compile(r"[A-Za-z0-9]*[A-Za-z][A-Za-z0-9]*|[A-Za-z0-9]+-[A-Za-z0-9-]*[A-Za-z0-9]")
_CIDR6 = re.compile(r"//([0-9]+)\Z")
_CIDR4 = re.compile(r"/([0-9]+)\Z")


class _Bad(Exception):
    """One domain entry does not have the shape its check reads."""


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
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


def _cidr(digits: str, top: int) -> bool:
    """RFC 7208 5.6: ``"0" / %x31-39 0*nDIGIT`` within the address family's range."""
    return _DIGITS.fullmatch(digits) is not None and (digits == "0" or digits[0] != "0") and len(digits) <= 3 \
        and int(digits) <= top


def _macro_string(text: str) -> str | None:
    """RFC 7208 7.1 macro-string, with each macro-expand replaced by ``%`` (never a literal there); None if invalid."""
    out, index = [], 0
    while index < len(text):
        char = text[index]
        if char != "%":
            if not 0x21 <= ord(char) <= 0x7E:
                return None
            out.append(char)
            index += 1
            continue
        following = text[index + 1:index + 2]
        if following in ("%", "_", "-"):
            out.append("%")
            index += 2
            continue
        macro = _MACRO.match(text, index + 1)
        if macro is None or (macro[2] and not macro[2].strip("0")):
            return None  # 7.3: a transformer digit, when given, is nonzero
        out.append("%")
        index = macro.end()
    return "".join(out)


def _domain_spec(text: str) -> bool:
    """RFC 7208 7.1: domain-spec = macro-string domain-end; domain-end = ( "." toplabel [ "." ] ) / macro-expand."""
    flat = _macro_string(text)
    if not flat:
        return False
    macro_end = flat.endswith("%")
    if flat.endswith("."):
        flat = flat[:-1]
    labels = flat.split(".")
    # RFC 7208 4.8: a domain-spec that is not a valid domain name is a permerror, so no label may be empty (a leading
    # dot, a double dot) or, when it holds no macro, longer than 63 characters (RFC 1035 2.3.4).
    if any(not label or (len(label) > 63 and "%" not in label) for label in labels):
        return False
    return macro_end or (len(labels) > 1 and "%" not in labels[-1] and _TOPLABEL.fullmatch(labels[-1]) is not None)


def _ip_argument(argument: str, version: int) -> bool:
    """``:address`` with an optional ``/prefix`` (RFC 7208 5.6)."""
    if not argument.startswith(":"):
        return False
    address, slash, prefix = argument[1:].partition("/")
    if "%" in address:
        return False  # no zone index in an ip6-network
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if parsed.version != version:
        return False
    return not slash or _cidr(prefix, 32 if version == 4 else 128)


def _host_argument(argument: str | None) -> bool:
    """``a`` and ``mx``: [ ":" domain-spec ] [ dual-cidr-length ], dual-cidr-length = [ "/" ip4 ] [ "//" ip6 ]."""
    if argument is None:
        return True
    six = _CIDR6.search(argument)
    if six is not None:
        if not _cidr(six[1], 128):
            return False
        argument = argument[:six.start()]
    four = _CIDR4.search(argument)
    if four is not None:
        if not _cidr(four[1], 32):
            return False
        argument = argument[:four.start()]
    return not argument or (argument.startswith(":") and _domain_spec(argument[1:]))


def _directive(term: str) -> tuple[str, str] | None | bool:
    """``(qualifier, mechanism)`` for a well-formed directive, False for a malformed one, None when not a directive."""
    match = _MECHANISM.fullmatch(term)
    if match is None:
        return None
    qualifier, name, argument = match[1], match[2].lower(), match[3]
    if name == "all":
        ok = argument is None
    elif name in ("include", "exists"):
        ok = argument is not None and argument.startswith(":") and _domain_spec(argument[1:])
    elif name in ("ip4", "ip6"):
        ok = argument is not None and _ip_argument(argument, 4 if name == "ip4" else 6)
    elif name == "ptr":
        ok = argument is None or (argument.startswith(":") and _domain_spec(argument[1:]))
    else:
        ok = _host_argument(argument)
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
        if not (_domain_spec(modifier[2]) if name in ("redirect", "exp") else _macro_string(modifier[2]) is not None):
            return False  # RFC 7208 6.1, 6.2: redirect and exp take a domain-spec; 6.3: others a macro-string
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


def _dot_atom(text: str, start: int) -> int:
    """End of the RFC 5322 dot-atom-text at ``start`` (RFC 6532 allows non-ASCII atext), or -1 when there is none."""
    index, last_dot = start, True
    while index < len(text):
        char = text[index]
        if char == ".":
            if last_dot:
                return -1
            last_dot = True
        elif char in _ATEXT or ord(char) > 0x7F:
            last_dot = False
        else:
            break
        index += 1
    return -1 if last_dot else index


def _decode(raw: str) -> tuple[str, list[bool]] | None:
    """Percent-decode ``raw`` (already matched by ``_TO_RAW``) as UTF-8, with a flag per decoded character that is True
    when it came from a percent-encoding; None when the octets are not UTF-8."""
    text: list[str] = []
    encoded: list[bool] = []
    index = 0
    while index < len(raw):
        if raw[index] != "%":
            text.append(raw[index])
            encoded.append(False)
            index += 1
            continue
        start = index
        while raw.startswith("%", index):
            index += 3
        try:
            piece = bytes.fromhex(raw[start:index].replace("%", "")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
        text.extend(piece)
        encoded.extend([True] * len(piece))
    return "".join(text), encoded


def _addresses(to: str) -> list[tuple[str, str]] | None:
    """RFC 6068 2 ``to = addr-spec *( "," addr-spec )``, percent-decoded: (local part, domain) pairs, the local part
    unquoted (RFC 5321 4.1.2: a quoted and an unquoted spelling name the same mailbox); None when malformed. The
    ``@`` between local part and domain must be written unencoded: an encoded ``%40`` is data, not the separator
    (RFC 3986 2.2)."""
    decoded = _TO_RAW.fullmatch(to) and _decode(to)
    if not decoded:
        return None
    text, encoded = decoded
    if not text:
        return []
    found, index = [], 0
    while True:
        if text.startswith('"', index):  # quoted-string: qtext (%d33 %d35-91 %d93-126), WSP, quoted-pair
            local, index = [], index + 1
            while index < len(text) and text[index] != '"':
                char = text[index]
                if char == "\\" and index + 1 < len(text) and (0x20 <= ord(text[index + 1]) <= 0x7E
                                                                 or text[index + 1] == "\t"):
                    local.append(text[index + 1])
                    index += 2
                elif char in _WSP or (0x21 <= ord(char) <= 0x7E and char != "\\") or ord(char) > 0x7F:
                    local.append(char)
                    index += 1
                else:
                    return None
            if index >= len(text):
                return None
            local_part, index = "".join(local), index + 1
        else:
            end = _dot_atom(text, index)
            if end < 0:
                return None
            local_part, index = text[index:end], end
        if not text.startswith("@", index) or encoded[index]:
            return None
        index += 1
        if text.startswith("[", index):  # domain literal: dtext-no-obs (%d33-90 / %d94-126)
            close = text.find("]", index)
            if close < 0 or any(not (33 <= ord(c) <= 90 or 94 <= ord(c) <= 126) for c in text[index + 1:close]):
                return None
            domain, index = text[index:close + 1], close + 1
        else:
            end = _dot_atom(text, index)
            if end < 0:
                return None
            domain, index = text[index:end], end
        found.append((local_part, domain))
        if index == len(text):
            return found
        if text[index] != ",":
            return None
        index += 1


def _authority(authority: str, scheme: str) -> bool:
    """RFC 3986 3.2 ``[ userinfo "@" ] host [ ":" port ]``. An IP literal must be closed and hold an IPv6 address or an
    IPvFuture; an ``http`` or ``https`` host is not empty (RFC 9110 4.2.2)."""
    userinfo, at, hostport = authority.rpartition("@")
    if at and _USERINFO.fullmatch(userinfo) is None:
        return False
    if hostport.startswith("["):
        close = hostport.find("]")
        if close < 0:
            return False
        host, port = hostport[1:close], hostport[close + 1:]
        if port and not (port[0] == ":" and _PORT.fullmatch(port[1:])):
            return False
        if _IPVFUTURE.fullmatch(host) is None:
            try:
                ipaddress.IPv6Address(host)
            except ValueError:
                return False
            if "%" in host:
                return False
        return True
    host, colon, port = hostport.partition(":")
    if colon and not _PORT.fullmatch(port):
        return False
    if _REG_NAME.fullmatch(host) is None:
        return False
    return bool(host) or scheme.lower() not in ("http:", "https:")


def _uri(token: str) -> list[tuple[str, str]] | None:
    """One RFC 7489 6.4 dmarc-uri: the mailbox addresses a ``mailto:`` URI names in its ``to`` part and ``to`` header
    fields (RFC 6068 2), an empty list for any other valid URI, None when malformed. A ``mailto:`` URI that names no
    recipient is a valid URI but no reporting address, so it counts as malformed here."""
    uri, bang, size = token.partition("!")
    if bang:
        number = size.rstrip("kmgtKMGT").lstrip("0") or "0"
        if _SIZE.fullmatch(size) is None or len(number) > 20 or int(number) > _U64:
            return None
    scheme = _SCHEME.match(uri)
    if scheme is None:
        return None
    rest = uri[scheme.end():]
    if scheme[0].lower() != "mailto:" and rest.startswith("//"):
        end = min((rest.find(mark, 2) for mark in "/?#" if mark in rest[2:]), default=len(rest))
        if not _authority(rest[2:end], scheme[0]):
            return None
        rest = rest[end:]
    if _URI_REST.fullmatch(rest) is None:
        return None
    if scheme[0].lower() != "mailto:":
        return []
    to, question, hfields = uri[scheme.end():].partition("?")
    if question and _HFIELDS.fullmatch(hfields) is None:
        return None
    addresses = _addresses(to)
    for field in hfields.split("&") if question else ():
        name, _, value = field.partition("=")
        if addresses is not None and unquote(name).lower() == "to":
            extra = _addresses(value)
            addresses = None if extra is None else addresses + extra
    return addresses or None


def _uris(value: str | None) -> list[tuple[str, str]] | None:
    """The mailbox addresses of an RFC 7489 6.4 URI list; None when the tag is absent or any URI in it is malformed."""
    if value is None:
        return None
    addresses = []
    for token in value.split(","):
        found = _uri(token.strip(_WSP))
        if found is None:
            return None
        addresses.extend(found)
    return addresses


def _policy(tags: dict[str, str]) -> dict[str, str] | None:
    """The record as RFC 7489 6.6.3 applies it: invalid or absent ``p``, or invalid ``sp``, reads as ``p=none`` when
    ``rua`` holds at least one syntactically valid URI of any scheme, else there is no policy."""
    p, sp = tags.get("p", "").lower(), tags.get("sp")
    if p in _POLICIES and (sp is None or sp.lower() in _POLICIES):
        return {**tags, "p": p, **({"sp": sp.lower()} if sp is not None else {})}
    rua = tags.get("rua")
    if rua is not None and any(_uri(token.strip(_WSP)) is not None for token in rua.split(",")):
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
    """The local part is matched exactly (RFC 5321 2.4: it is case-sensitive), the domain case-insensitively."""
    tags, _ = _dmarc_record(domain)
    addresses = _uris(tags.get("rua")) if tags is not None else None
    local, _, host = _CISA_CONTACT.partition("@")
    return addresses is not None and any(found == local and name.lower() == host for found, name in addresses)


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
