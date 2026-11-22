"""DNS-over-HTTPS lookups and email-auth record parsers.

Used by the dns_posture collector to evaluate SPF, DKIM, DMARC, MTA-STS, TLS-RPT
(RFC 8460, https://datatracker.ietf.org/doc/html/rfc8460), and BIMI records for verified tenant domains without depending on system DNS resolvers.
"""
from __future__ import annotations

import contextvars
import ipaddress
import logging
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, NamedTuple, Protocol
from urllib.parse import urlsplit

import requests

DEFAULT_DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
DEFAULT_TIMEOUT_SECONDS = 5.0
# Review R164: a customer that cannot send domain names to Cloudflare names its own DoH (JSON API) resolver.
DOH_ENDPOINT_ENV = "AUDITEX_DOH_ENDPOINT"


# Every character an RFC 3986 URL may carry. Anything else (a backslash, a space, a control or non-ASCII character)
# is read differently by Requests (urllib3) and urllib.parse, so the host shown could differ from the host asked.
_URL_CHARACTERS = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
_HOST_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class ResolverAddress(NamedTuple):
    """The parts of a resolver URL that may be shown: never its user info, path, query or fragment (review R164)."""

    scheme: str
    host: str          # a DNS name in lower case, an IPv4 address or a bracketed IPv6 address
    port: int | None   # None for the scheme's default port

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.host}{f':{self.port}' if self.port is not None else ''}"

    @property
    def host_port(self) -> str:
        return self.host if self.port is None else f"{self.host}:{self.port}"


def _display_host(host: str) -> str | None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return f"[{address.compressed}]" if address.version == 6 else address.compressed
    name = host.lower().rstrip(".")
    if not name or len(name) > 253 or not all(_HOST_LABEL.fullmatch(label) for label in name.split(".")):
        return None
    return name


def doh_resolver_address(endpoint: object) -> ResolverAddress | None:
    """The safe display parts of a resolver URL, or None when the value is not an http(s) URL with a plain host.

    The one parser every place that shows or stores a resolver goes through: the run notices, data-handling.json,
    DohClient errors, both providers' coverage rows and gap reasons built from older diagnostics.
    """
    text = str(endpoint or "").strip()
    if not _URL_CHARACTERS.fullmatch(text):
        return None
    try:
        parts = urlsplit(text)
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not host:
        return None
    netloc_host = parts.netloc.rpartition("@")[2]
    # An IPv6 address only between brackets: "https://2001:db8::53:8443" is not a host and port.
    if ":" in host and not netloc_host.startswith("["):
        return None
    shown = _display_host(host)
    if shown is None:
        return None
    return ResolverAddress(scheme, shown, None if port in (None, _DEFAULT_PORTS[scheme]) else port)


def doh_resolver_display(endpoint: object) -> str | None:
    """``scheme://host[:port]`` of a resolver URL (IPv6 bracketed, the default port left out), or None."""
    address = doh_resolver_address(endpoint)
    return address.origin if address else None


def resolve_doh_endpoint(value: str | None = None, environ: Mapping[str, str] | None = None) -> str:
    """The DoH resolver for this run: an explicit option, else ``AUDITEX_DOH_ENDPOINT``, else Cloudflare.

    Only a plain ``https://host/path`` URL is accepted: no other scheme, no user name or password, no query and no
    fragment, and nothing that Requests would read as a different host from the one Auditex shows.
    The error never repeats the value, which may carry a token.
    """
    chosen = value
    if chosen is None:
        chosen = (os.environ if environ is None else environ).get(DOH_ENDPOINT_ENV)
        if chosen is None or not chosen.strip():
            return DEFAULT_DOH_ENDPOINT                      # an unset or blank variable means the default
    text = chosen.strip()
    address = doh_resolver_address(text)
    netloc = urlsplit(text).netloc if address else ""
    # No query string either: the client adds its own parameters, and a token there would reach error messages.
    if address is None or address.scheme != "https" or "@" in netloc or "?" in text or "#" in text:
        raise ValueError("The DNS-over-HTTPS endpoint must be a plain https:// URL with a host and path "
                         f"(option or {DOH_ENDPOINT_ENV}); no other scheme, credentials, query or fragment.")
    return text


def doh_resolver_origin(endpoint: str) -> str | None:
    """``https://host[:port]`` of a resolver URL: never its path, which can hold an account token, nor user info."""
    return doh_resolver_display(endpoint)


def doh_resolver_disclosure(endpoint: str) -> str:
    """Notice wording for the resolver that receives the tenant's domain names.

    A configured resolver is named by its host (and a port that is not the default) alone: its path can hold an
    account token (review R164).
    """
    if endpoint == DEFAULT_DOH_ENDPOINT:
        return f"the public Cloudflare DNS-over-HTTPS resolver ({DEFAULT_DOH_ENDPOINT})"
    address = doh_resolver_address(endpoint)
    return f"the configured DNS-over-HTTPS resolver at {address.host_port if address else 'a host that is not shown'}"


# A resolver diagnostic read back from a bundle (an offline sample, an older run) is untrusted text: it may name the
# resolver by its full URL (user info, a path token, a query) or carry library text that repeats the request path
# without a scheme. It is never cut apart by hand: each URL in it is parsed by ``doh_resolver_address`` and only its
# display form is ever shown (review R164, follow-up to #179).
_DIAGNOSTIC_URL = re.compile(r"https?://\S*", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".,;:)]}'\">"
_UNNAMED_ORIGIN = "the DNS-over-HTTPS resolver"


def _origin_of_token(token: str) -> str | None:
    """Display origin of one whitespace-delimited URL token, trailing sentence punctuation allowed."""
    while token:
        address = doh_resolver_address(token)
        if address is not None:
            return address.origin
        if token[-1] not in _TRAILING_PUNCTUATION:
            return None
        token = token[:-1]
    return None


def resolver_named_in(text: object) -> str | None:
    """The display origin of the one resolver an untrusted diagnostic names, or None.

    None when the text names no URL, names URLs that are not all the same resolver, or holds an ``@`` outside its
    URLs (user info with a space in it: the host could not be told apart from the user name).
    """
    value = str(text or "")
    tokens = [match.group(0) for match in _DIAGNOSTIC_URL.finditer(value)]
    if not tokens or value.count("@") != sum(token.count("@") for token in tokens):
        return None
    origins = {_origin_of_token(token) for token in tokens}
    if len(origins) != 1:
        return None
    return origins.pop()


_ORIGIN = r"(?P<origin>https?://\S+|the DNS-over-HTTPS resolver)"
_QUESTION = r"[A-Za-z0-9]{1,16} [A-Za-z0-9_*.-]{1,253}"
# DohClient's own wording (and the replay wording below): the only free text a resolver diagnostic keeps.
_AUDITEX_DIAGNOSTICS = tuple(re.compile(pattern) for pattern in (
    rf"DoH query failed for {_QUESTION} at {_ORIGIN} \((?:HTTP \d{{3}}|request failed(?:: [A-Za-z_][A-Za-z0-9_]*)?)\)",
    rf"DoH response from {_ORIGIN} (?:was not an object|carried no usable status|was truncated \(TC\)) for {_QUESTION}",
    rf"DoH resolver at {_ORIGIN} could not answer {_QUESTION}: (?:[A-Z]{{1,16}}|rcode -?\d{{1,5}})",
    rf"DoH resolver at {_ORIGIN} did not answer; the recorded diagnostic is not repeated",
))
# Text with no URL syntax at all (no slash, at sign, query or percent sign) cannot carry user info, a path or a query.
_PLAIN_DIAGNOSTIC = re.compile(r"[A-Za-z0-9 _.,;:()'-]{1,300}")


def safe_resolver_diagnostic(text: object) -> str:
    """A resolver diagnostic from a bundle, safe to copy, summarise or write.

    Auditex's own DohClient wording naming a resolver by its display form, and text with no URL syntax, are kept as
    they are. Anything else is replaced by a fixed sentence naming the resolver's display form (when it can be told)
    and nothing of the original text. The result is stable: passing it through again returns it unchanged.
    """
    value = str(text or "")
    for pattern in _AUDITEX_DIAGNOSTICS:
        match = pattern.fullmatch(value)
        if match is not None:
            origin = match.group("origin")
            if origin == _UNNAMED_ORIGIN or doh_resolver_display(origin) == origin:
                return value
    if _PLAIN_DIAGNOSTIC.fullmatch(value) and "http" not in value.lower():
        return value
    origin = resolver_named_in(value) or _UNNAMED_ORIGIN
    return f"DoH resolver at {origin} did not answer; the recorded diagnostic is not repeated"


def sanitise_resolver_fields(value: Any) -> Any:
    """A copy of replayed collector data whose resolver diagnostics went through ``safe_resolver_diagnostic``.

    Every ``resolver_error``, the ``error`` of any record or section whose ``error_class`` is ``dns_resolver_error``
    and any ``doh_endpoint`` (reduced to its display form) are rewritten, at any depth; nothing else changes.
    """
    if isinstance(value, list):
        return [sanitise_resolver_fields(item) for item in value]
    if not isinstance(value, Mapping):
        return value
    resolver_row = value.get("error_class") == "dns_resolver_error"
    cleaned: dict[Any, Any] = {}
    for key, item in value.items():
        if key == "resolver_error" and item:
            cleaned[key] = safe_resolver_diagnostic(item)
        elif key == "error" and resolver_row and item:
            cleaned[key] = safe_resolver_diagnostic(item)
        elif key == "doh_endpoint" and item:
            cleaned[key] = doh_resolver_display(item)
        else:
            cleaned[key] = sanitise_resolver_fields(item)
    return cleaned


# Requests and urllib3 log each request target (the resolver's path, which can hold a token, and the query) at DEBUG,
# and urllib3 names the URL in its retry and redirect lines. While a DoH request runs, their records are dropped.
_DOH_REQUEST_ACTIVE: contextvars.ContextVar[bool] = contextvars.ContextVar("auditex_doh_request", default=False)
_TRANSPORT_LOGGER_PREFIXES = ("urllib3", "requests")


class _DohTransportLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not _DOH_REQUEST_ACTIVE.get()


_DOH_TRANSPORT_LOG_FILTER = _DohTransportLogFilter()


def _guard_transport_loggers() -> None:
    """Attach the filter to every transport logger, including any created since the last request."""
    names = {"urllib3", "urllib3.connectionpool", "urllib3.connection", "urllib3.poolmanager", "urllib3.response",
             "urllib3.util.retry", "requests"}
    names.update(name for name in list(logging.root.manager.loggerDict)
                 if name.split(".", 1)[0] in _TRANSPORT_LOGGER_PREFIXES)
    for name in names:
        logger = logging.getLogger(name)
        if _DOH_TRANSPORT_LOG_FILTER not in logger.filters:
            logger.addFilter(_DOH_TRANSPORT_LOG_FILTER)


def _transport_detail(exc: BaseException) -> str:
    """A bounded description of a failed DoH request: the HTTP status or the error class, never the library text,
    which can repeat the resolver URL and so a token in its path."""
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if isinstance(status, int) and not isinstance(status, bool):
        return f"HTTP {status}"
    return f"request failed: {type(exc).__name__}"


# DNS response codes. NOERROR with no answer and NXDOMAIN are definite statements that the record is absent; every
# other code (SERVFAIL, REFUSED, FORMERR, NOTIMP and so on) means the resolver did not answer the question.
_RCODE_NOERROR = 0
_RCODE_NXDOMAIN = 3
_ABSENT_RCODES = frozenset({_RCODE_NOERROR, _RCODE_NXDOMAIN})
_RCODE_NAMES = {1: "FORMERR", 2: "SERVFAIL", 4: "NOTIMP", 5: "REFUSED"}


class DohError(RuntimeError):
    """Raised when a DoH query cannot be completed."""


class DnsAnswer(NamedTuple):
    records: list[str]
    outcome: str  # answers, empty or nxdomain
    record_types: tuple[int | None, ...] = ()  # aligned with records, when supplied by the resolver


class DnsResolver(Protocol):
    def query(self, name: str, record_type: str) -> list[str]: ...


@dataclass
class DohClient:
    """Minimal DNS-over-HTTPS client returning record data strings."""

    session: Any = field(default_factory=requests.Session)
    endpoint: str = field(default_factory=resolve_doh_endpoint, repr=False)  # the path can hold a token
    timeout: float = DEFAULT_TIMEOUT_SECONDS

    def query(self, name: str, record_type: str) -> list[str]:
        return self.query_detailed(name, record_type).records

    def _origin(self) -> str:
        return doh_resolver_display(self.endpoint) or "the DNS-over-HTTPS resolver"

    def query_detailed(self, name: str, record_type: str) -> DnsAnswer:
        # The full URL lives only in the request itself: no transport logger records it meanwhile.
        _guard_transport_loggers()
        quiet = _DOH_REQUEST_ACTIVE.set(True)
        try:
            response = self.session.get(
                self.endpoint,
                params={"name": name, "type": record_type},
                headers={"accept": "application/dns-json"},
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:  # noqa: BLE001
            # Bot review wave 2 item 13: the library text can carry the endpoint URL, so only the resolver's origin
            # and a bounded detail are kept.
            raise DohError(f"DoH query failed for {record_type} {name} at {self._origin()} "
                           f"({_transport_detail(exc)})") from None
        finally:
            _DOH_REQUEST_ACTIVE.reset(quiet)
        if not isinstance(payload, dict):
            raise DohError(f"DoH response from {self._origin()} was not an object for {record_type} {name}")
        # A response with no ``Status`` (or one that is not a number) is not a statement about the record: only an
        # explicit NOERROR or NXDOMAIN says "absent".
        status = payload.get("Status")
        try:
            if status is None or isinstance(status, bool):
                raise ValueError("no status")
            rcode = int(status)
        except (TypeError, ValueError) as exc:
            raise DohError(f"DoH response from {self._origin()} carried no usable status for {record_type} {name}") from exc
        if payload.get("TC") is True:
            # The resolver cut the answer short: records may be missing from it, so nothing can be called absent.
            raise DohError(f"DoH response from {self._origin()} was truncated (TC) for {record_type} {name}")
        if rcode not in _ABSENT_RCODES:
            # SERVFAIL (2), REFUSED (5) and the other failure codes say the resolver could not answer; they
            # are not evidence that the record does not exist, so the domain reads unknown, never "missing".
            raise DohError(f"DoH resolver at {self._origin()} could not answer {record_type} {name}: "
                           f"{_RCODE_NAMES.get(rcode, f'rcode {rcode}')}")
        answer = payload.get("Answer") or []
        records: list[str] = []
        record_types: list[int | None] = []
        for entry in answer:
            if not isinstance(entry, dict):
                continue
            data = entry.get("data")
            if not isinstance(data, str):
                continue
            records.append(_decode_txt(data))
            record_types.append(entry.get("type"))
        outcome = "nxdomain" if rcode == _RCODE_NXDOMAIN else "answers" if records else "empty"
        return DnsAnswer(records, outcome,
                         tuple(record_types) if any(t is not None for t in record_types) else ())


def _decode_txt(data: str) -> str:
    """Strip the surrounding quotes used by DoH and concatenate multi-string TXT records."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    if parts:
        return "".join(parts)
    return data.strip().strip('"')


def _ask(resolver: DnsResolver, name: str) -> DnsAnswer:
    return _ask_type(resolver, name, "TXT")


def _ask_type(resolver: DnsResolver, name: str, record_type: str) -> DnsAnswer:
    detailed = getattr(resolver, "query_detailed", None)
    if detailed is not None:
        return detailed(name, record_type)
    records = resolver.query(name, record_type)
    return DnsAnswer(records, "answers" if records else "empty")


def _record_ask(resolver: DnsResolver, name: str) -> DnsAnswer:
    """Retry a record question once; a second resolver failure still propagates."""
    try:
        return _ask(resolver, name)
    except DohError:
        return _ask(resolver, name)


class CachingResolver:
    """Share successful answers between posture and raw records; never cache DohError."""

    def __init__(self, resolver: DnsResolver):
        self.resolver = resolver
        self.cache: dict[tuple[str, str], DnsAnswer] = {}

    def query(self, name: str, record_type: str) -> list[str]:
        return self.query_detailed(name, record_type).records

    def query_detailed(self, name: str, record_type: str) -> DnsAnswer:
        key = (name, record_type)
        if key not in self.cache:
            answer = _ask_type(self.resolver, name, record_type)
            self.cache[key] = answer._replace(records=list(answer.records))
        answer = self.cache[key]
        return answer._replace(records=list(answer.records))


def is_coexistence_domain(domain: str) -> bool:
    """Infer ScubaGear's IsCoexistenceDomain from the .mail.onmicrosoft.com suffix.

    Graph domains do not carry the Exchange coexistence property (SG-P:594-599).
    """
    return domain.lower().endswith(".mail.onmicrosoft.com")


def _dns_log(name: str, answer: DnsAnswer) -> dict[str, Any]:
    # SG-P:429-463: successful DoH log shape, including the NXDOMAIN distinction.
    result = ("Query returned NXDomain" if answer.outcome == "nxdomain"
              else f"Query returned {len(answer.records)} txt records")
    return {"query_name": name, "query_method": "DoH", "query_result": result,
            "query_answers": answer.records}


def _dmarc_log(name: str, answer: DnsAnswer) -> dict[str, Any]:
    """The step's log line plus its outcome (answers, empty or nxdomain), which the DMARC value rule reads.

    A step the resolver failed on or timed out on raises ``DohError`` and never reaches an entry, so an entry's outcomes
    are all answered steps.
    """
    return {**_dns_log(name, answer), "outcome": answer.outcome}


def spf_fails_unapproved_senders(record: str) -> bool:
    """RFC 7208 terms of one ``v=spf1`` record: the first ``all`` mechanism decides (``-all`` or ``~all``), and only a
    record without one is judged by its ``redirect=`` modifier (section 6.1: redirect is ignored beside ``all``).

    Divergence from SG-P:520-545, which tests raw substrings, so ``?all`` or ``+all`` beside a ``redirect`` or an
    ``include:`` name holding "redirect" or "-all" passed (review R102). Names are case-insensitive (section 4.6.1).
    """
    for term in record.split()[1:]:
        qualifier = term[0] if term[0] in "+-~?" else ""
        if term[len(qualifier):].lower() == "all":
            return qualifier in ("-", "~")
    return any(term.lower().startswith("redirect=") for term in record.split()[1:])


def scuba_spf_record(domain: str, resolver: DnsResolver) -> dict[str, Any]:
    answer = _record_ask(resolver, domain)
    # SG-P:520-545: case-sensitive prefix check, all TXT answers retained; compliance is tokenised (R102).
    spf = [r for r in answer.records if r.startswith("v=spf1 ")]
    compliant = any(spf_fails_unapproved_senders(r) for r in spf)
    if compliant:
        message = "SPF record found."
    elif spf:
        message = "SPF record found, but it does not fail unapproved senders or redirect to one that does."
    elif answer.records:
        message = "Domain name exists but no SPF records returned."
    # SG-P:547-560: resolver failures propagate rather than become an SPF result.
    elif answer.outcome == "nxdomain":
        message = "Domain does not exist."
    else:
        message = "Domain name exists but no answers returned."
    return {"domain": domain, "compliant": compliant, "message": message,
            "rdata": answer.records, "log": [_dns_log(domain, answer)]}


def scuba_dkim_record(domain: str, resolver: DnsResolver) -> dict[str, Any] | None:
    if is_coexistence_domain(domain):
        return None
    # SG-P:601-629: try four selectors in order; the first string answer wins.
    dashed = domain.replace(".", "-")
    selectors = ("selector1", "selector2", f"selector1-{dashed}", f"selector2-{dashed}")
    log = []
    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"
        answer = _record_ask(resolver, name)
        # SG-P:297-303: traditional DNS keeps TXT strings, not CNAME targets.
        # With NOERROR and no TXT, DoH fallback retains CNAME data and stops the walk.
        if answer.record_types:
            records = [r for r, kind in zip(answer.records, answer.record_types, strict=False) if kind != 5]
            if records:
                answer = DnsAnswer(records, answer.outcome)
            elif answer.outcome == "nxdomain":
                # RFC 6604 permits NXDOMAIN with a CNAME to a missing target;
                # inferred, not observed live. SG-P:450-459 adds no answers, so walk on.
                answer = DnsAnswer([], "nxdomain")
        log.append(_dns_log(name, answer))
        if answer.records:
            break
    return {"domain": domain, "rdata": answer.records, "log": log}


def _valid_dmarc(records: list[str]) -> list[str]:
    # PowerShell -match is case-insensitive (SG-P:674,730).
    return [r for r in records if re.match(r"^v=DMARC1", r, re.IGNORECASE)]


def _dmarc_walk(domain: str, resolver: DnsResolver, log: list[dict[str, Any]]) -> list[str]:
    """SG-P:698-765: RFC 9989 parent walk after the author query, at most eight total."""
    author = [label for label in domain.split(".") if label]
    labels = author[:]
    queries = 1
    selected: list[str] = []
    policy_domain = None
    while len(labels) > 1 and queries < 8:
        # SG-P:707-716: long names jump to seven labels, otherwise remove one.
        labels = labels[-7:] if len(labels) >= 8 else labels[1:]
        parent = ".".join(labels)
        name = f"_dmarc.{parent}"
        answer = _record_ask(resolver, name)
        queries += 1
        log.append(_dmarc_log(name, answer))
        valid = _valid_dmarc(answer.records)
        # SG-P:724-730: zero or multiple valid answers do not end discovery.
        if len(valid) != 1:
            continue
        if re.search(r"psd=y\b", valid[0], re.IGNORECASE):
            # SG-P:739-755: prefer the policy exactly one label below the PSD.
            start = len(author) - len(labels) - 1
            organisational = ".".join(author[start:]) if start >= 0 else None
            return selected if policy_domain == organisational else valid
        selected, policy_domain = valid, parent
        # SG-P:758-764: psd=n declares the organisational boundary itself.
        if re.search(r"psd=n\b", valid[0], re.IGNORECASE):
            break
    return selected


def scuba_dmarc_record(domain: str, resolver: DnsResolver) -> dict[str, Any] | None:
    # SG-P:661-665: coexistence domains cannot publish custom DMARC records.
    if is_coexistence_domain(domain):
        return None
    name = f"_dmarc.{domain}"
    answer = _record_ask(resolver, name)
    log = [_dmarc_log(name, answer)]
    valid = _valid_dmarc(answer.records)
    # SG-P:674-696: only one author policy wins; other TXT does not block parents.
    records = valid if len(valid) == 1 else _dmarc_walk(domain, resolver, log)
    return {"domain": domain, "rdata": records, "log": log}


def parse_spf(record: str) -> dict[str, Any] | None:
    text = record.strip()
    if not text.lower().startswith("v=spf1"):
        return None
    tokens = text.split()
    mechanisms = [token for token in tokens[1:] if not token.lower().startswith("v=")]
    all_qualifier = None
    for token in mechanisms:
        # The first term that is exactly an all mechanism with at most one qualifier, as spf_fails_unapproved_senders
        # reads it; a name merely ending in "all" (include:spf.examplemall) is not one.
        qualifier = token[0] if token[0] in "+-~?" else ""
        if token[len(qualifier):].lower() == "all":
            all_qualifier = qualifier or "+"
            break
    return {
        "version": "spf1",
        "mechanisms": mechanisms,
        "all_qualifier": all_qualifier,
        "raw": record,
    }


def parse_dmarc(record: str) -> dict[str, Any] | None:
    text = record.strip()
    if "v=dmarc1" not in text.lower():
        return None
    tags = _split_semicolon_tags(text)
    pct_raw = tags.get("pct")
    pct: int | None
    try:
        pct = int(pct_raw) if pct_raw is not None else 100
    except (TypeError, ValueError):
        pct = None
    aggregate = _split_csv(tags.get("rua"))
    forensic = _split_csv(tags.get("ruf"))
    aggregate_invalid = [uri for uri in aggregate if not _is_valid_dmarc_uri(uri)]
    forensic_invalid = [uri for uri in forensic if not _is_valid_dmarc_uri(uri)]
    return {
        "version": "DMARC1",
        "policy": tags.get("p"),
        "subdomain_policy": tags.get("sp"),
        "pct": pct,
        "aggregate_addresses": aggregate,
        "aggregate_addresses_invalid": aggregate_invalid,
        "forensic_addresses": forensic,
        "forensic_addresses_invalid": forensic_invalid,
        "raw": record,
    }


def parse_mta_sts(record: str) -> dict[str, Any] | None:
    text = record.strip()
    if "v=stsv1" not in text.lower():
        return None
    tags = _split_semicolon_tags(text)
    return {
        "version": "STSv1",
        "id": tags.get("id"),
        "raw": record,
    }


def parse_tls_rpt(record: str) -> dict[str, Any] | None:
    """Parse an SMTP TLS Reporting record (RFC 8460 section 3) published at ``_smtp._tls.<domain>``."""
    text = record.strip()
    if not text.lower().startswith("v=tlsrptv1"):
        return None
    tags = _split_semicolon_tags(text)
    return {
        "version": "TLSRPTv1",
        "rua": _split_csv(tags.get("rua")),
        "raw": record,
    }


def parse_bimi(record: str) -> dict[str, Any] | None:
    text = record.strip()
    if "v=bimi1" not in text.lower():
        return None
    tags = _split_semicolon_tags(text)
    logo_url = tags.get("l")
    authority_url = tags.get("a")
    return {
        "version": "BIMI1",
        "logo_url": logo_url,
        "authority_url": authority_url,
        "logo_url_is_https": _is_https_url(logo_url) if logo_url is not None else False,
        "authority_url_is_https": _is_https_url(authority_url) if authority_url is not None else None,
        "raw": record,
    }


def _is_valid_dmarc_uri(uri: str) -> bool:
    """Permissive validator for DMARC ``rua=``/``ruf=`` URIs (RFC 7489 §6.4).

    Accepts ``mailto:`` URIs with an ``@`` in the local-part/host, and ``https://`` URLs.
    Rejects bare addresses (no ``mailto:`` scheme), ``http://`` (mixed-content / clear-text),
    and obviously malformed mailto entries (no ``@``).
    """
    s = uri.strip()
    if not s:
        return False
    if s.lower().startswith("mailto:"):
        return "@" in s[len("mailto:") :]
    if s.lower().startswith("https://"):
        return True
    return False


def _is_https_url(url: str) -> bool:
    return bool(url) and url.lower().startswith("https://")


def _split_semicolon_tags(text: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for chunk in text.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def is_microsoft_managed_domain(domain: str) -> bool:
    return domain.lower().endswith(".onmicrosoft.com")


def collect_domain_posture(
    domain: str,
    resolver: DnsResolver,
    *,
    dkim_selectors: Iterable[str] = ("selector1", "selector2"),
    dkim_fallback_selectors: Iterable[str] = (),
) -> dict[str, Any]:
    """Resolve and assess email-auth records for a single domain.

    The DKIM probe is tiered: primary ``dkim_selectors`` are queried first
    (Microsoft 365 defaults ``selector1``/``selector2`` in the typical case),
    and ``dkim_fallback_selectors`` are only queried when no primary selector
    resolves. This avoids extra DoH traffic on tenants that are correctly
    using the M365 defaults.
    """
    primary = tuple(dkim_selectors)
    fallback = tuple(dkim_fallback_selectors)
    all_probed = list(primary) + [s for s in fallback if s not in primary]

    posture: dict[str, Any] = {
        "domain": domain,
        "managed_by_microsoft": is_microsoft_managed_domain(domain),
        "resolver_error": None,
    }
    try:
        spf_records = resolver.query(domain, "TXT")
        dmarc_records = resolver.query(f"_dmarc.{domain}", "TXT")
        mta_sts_records = resolver.query(f"_mta-sts.{domain}", "TXT")
        tls_rpt_records = resolver.query(f"_smtp._tls.{domain}", "TXT")
        bimi_records = resolver.query(f"default._bimi.{domain}", "TXT")
        dkim_results: dict[str, dict[str, Any] | None] = {}
        for selector in primary:
            records = resolver.query(f"{selector}._domainkey.{domain}", "TXT")
            dkim_results[selector] = _summarize_dkim(records)
        if fallback and not any(dkim_results.values()):
            for selector in fallback:
                if selector in dkim_results:
                    continue
                records = resolver.query(f"{selector}._domainkey.{domain}", "TXT")
                dkim_results[selector] = _summarize_dkim(records)
    except DohError as exc:
        posture["resolver_error"] = str(exc)
        posture.update(unknown_posture(all_probed))
        return posture

    posture["spf"] = _summarize_spf(spf_records)
    posture["dmarc"] = _summarize_dmarc(dmarc_records)
    posture["dkim"] = _summarize_dkim_collection(dkim_results)
    posture["mta_sts"] = _summarize_mta_sts(mta_sts_records)
    posture["tls_rpt"] = _summarize_tls_rpt(tls_rpt_records)
    posture["bimi"] = _summarize_bimi(bimi_records)
    return posture


def unknown_posture(probed_selectors: Iterable[str]) -> dict[str, Any]:
    """The record sections of a domain the resolver could not answer for: ``present`` is ``None``, never ``False``.

    A resolver failure says nothing about what the domain publishes, so no record is called absent.
    The selectors are listed as probed, not as missing.
    """
    return {
        "spf": {"present": None, "kind": "spf"},
        "dmarc": {"present": None, "kind": "dmarc"},
        "dkim": {"selectors_present": [], "selectors_missing": [], "selectors_unresolved": list(probed_selectors)},
        "mta_sts": {"dns_present": None},
        "tls_rpt": {"present": None, "kind": "tls_rpt"},
        "bimi": {"present": None, "kind": "bimi"},
    }


def _summarize_spf(records: list[str]) -> dict[str, Any]:
    parsed_records = [parsed for rec in records if (parsed := parse_spf(rec)) is not None]
    if not parsed_records:
        return _absent("spf")
    parsed = parsed_records[0]
    return {
        "present": True,
        "all_qualifier": parsed.get("all_qualifier"),
        "mechanisms": parsed.get("mechanisms"),
        "raw": parsed.get("raw"),
        # RFC 7208 §4.5: multiple v=spf1 records yield PermError on the receiver side,
        # which makes both records ineffective. Surface the violation so findings can fire.
        "multiple_records": len(parsed_records) > 1,
    }


_DMARC_RECORD_START = re.compile(r"^\s*v\s*=\s*DMARC1\s*(?:;|$)", re.IGNORECASE)


def _summarize_dmarc(records: list[str]) -> dict[str, Any]:
    parsed_records = [parsed for rec in records if (parsed := parse_dmarc(rec)) is not None]
    if not parsed_records:
        return _absent("dmarc")
    # RFC 7489 section 6.6.3: only strings that begin with v=DMARC1 are records; with more than one a receiver applies
    # no DMARC policy at all, so the domain has no effective record (dmarc_missing fires) (review R109).
    records_proper = [rec for rec in records if _DMARC_RECORD_START.match(rec)]
    if len(records_proper) > 1:
        return {**_absent("dmarc"), "multiple_records": True, "record_count": len(records_proper)}
    parsed = (parse_dmarc(records_proper[0]) if records_proper else None) or parsed_records[0]
    pct = parsed.get("pct")
    pct_partial = isinstance(pct, int) and 0 <= pct < 100
    return {
        "present": True,
        "policy": parsed.get("policy"),
        "subdomain_policy": parsed.get("subdomain_policy"),
        "pct": pct,
        "pct_partial": pct_partial,
        "aggregate_addresses": parsed.get("aggregate_addresses"),
        "aggregate_addresses_invalid": parsed.get("aggregate_addresses_invalid") or [],
        "forensic_addresses": parsed.get("forensic_addresses"),
        "forensic_addresses_invalid": parsed.get("forensic_addresses_invalid") or [],
        "raw": parsed.get("raw"),
        "multiple_records": False,
    }


def _summarize_mta_sts(records: list[str]) -> dict[str, Any]:
    parsed = next((parse_mta_sts(rec) for rec in records if parse_mta_sts(rec)), None)
    return {
        "dns_present": parsed is not None,
        "id": parsed.get("id") if parsed else None,
        "raw": parsed.get("raw") if parsed else None,
    }


def _summarize_tls_rpt(records: list[str]) -> dict[str, Any]:
    parsed = next((parse_tls_rpt(rec) for rec in records if parse_tls_rpt(rec)), None)
    if parsed is None:
        return _absent("tls_rpt")
    return {"present": True, "rua": parsed.get("rua") or [], "raw": parsed.get("raw")}


def _summarize_bimi(records: list[str]) -> dict[str, Any]:
    parsed = next((parse_bimi(rec) for rec in records if parse_bimi(rec)), None)
    if parsed is None:
        return _absent("bimi")
    return {
        "present": True,
        "logo_url": parsed.get("logo_url"),
        "logo_url_is_https": parsed.get("logo_url_is_https"),
        "authority_url": parsed.get("authority_url"),
        "authority_url_is_https": parsed.get("authority_url_is_https"),
        "raw": parsed.get("raw"),
    }


def _summarize_dkim(records: list[str]) -> dict[str, Any] | None:
    for record in records:
        text = record.strip()
        if "v=dkim1" in text.lower() or "k=" in text.lower():
            tags = _split_semicolon_tags(text)
            if "p" in tags and not tags["p"].strip():
                # RFC 6376 section 3.6.1: an empty ``p=`` revokes the key. The selector no longer signs anything.
                continue
            return {
                "present": True,
                "key_type": tags.get("k"),
                "raw": record,
            }
    return None


def _summarize_dkim_collection(results: dict[str, dict[str, Any] | None]) -> dict[str, Any]:
    selectors_present = [name for name, value in results.items() if value]
    selectors_missing = [name for name, value in results.items() if not value]
    return {
        "selectors_present": selectors_present,
        "selectors_missing": selectors_missing,
        "selector_details": {name: value for name, value in results.items() if value},
    }


def _absent(kind: str) -> dict[str, Any]:
    return {"present": False, "kind": kind}
