"""DNS posture in the shareable profiles: pseudonymised domain ids and fixed-vocabulary predicates, built by allow-list.

The local report keeps the TXT text the operator queried (public data). The shareable, customer-pack and explainer
profiles replace a DNS posture record with an allow-listed copy, because a DMARC record names report mailboxes
(``rua=mailto:...``), an SPF record names the domains and addresses allowed to send, and the posture's own domain,
query names and the ids derived from them name the domain. What remains says what was published (policy, qualifier,
counts, whether a valid CISA report URI is listed), not where or to whom.

Applied by ``output_redaction._Redactor.mapping`` to every mapping before it is walked. Rules:

- Only the fields listed here are written; any other field of a posture record is dropped.
- A predicate is computed from the parsed value. A wrong-typed, unreadable or out-of-vocabulary value becomes
  ``"unusable"``, never its text; ``None`` (nothing published or nothing read) stays ``None``.
- Every domain, query name and DNS-derived id (record key, finding id, evidence ``record_key``) goes through the
  keyed DNS pseudonym, whichever field it arrives in and whatever the domain's shape: the domain part of an id is all
  of it after the prefix (less a Microsoft 365 rule suffix), never a DNS-name match. ``dns_ref_text`` does the same for
  ids inside free text.

The rewrite is a pure function of the record and the pseudonym key and is idempotent: a record it has already
rewritten comes back unchanged.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

WITHHELD = "withheld"
UNUSABLE = "unusable"
# CISA's DMARC aggregate report address (BOD 18-01; SCuBA MS.EXO.4.3v1 and GWS.GMAIL.4.3v1).
CISA_RUA = "reports@dmarc.cyber.dhs.gov"

_DMARC_POLICIES = frozenset({"none", "quarantine", "reject"})
_SPF_QUALIFIERS = frozenset({"+", "-", "~", "?"})
_MTA_STS_MODES = frozenset({"enforce", "testing", "none"})
# Values, never mapping keys: held as one string each so they stay out of the redaction field-name exemption
# (``output_redaction._D5_FIELD_NAMES``), as ``ce_plus._KNOWN_RULE_REASONS`` does.
_MTA_STS_FETCH = frozenset("ok skipped unreachable http_error invalid_policy".split())
_AUTHENTICATION_TYPES = frozenset("managed federated".split())
_KINDS = frozenset({"spf", "dmarc", "tls_rpt", "bimi"})
_POSTURE_KINDS = frozenset("google_domain_posture dns_posture".split())
_POSTURE_SOURCES = frozenset({"google_dns_posture.domainPosture", "dns_posture.domainPosture"})
_SELECTOR_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?")
# RFC 7489 section 6.2: a ``mailto:`` URI may end in ``!`` and a size (digits and an optional unit).
_CISA_URI_RE = re.compile(r"mailto:" + re.escape(CISA_RUA) + r"(?:![0-9]+[kmgt]?)?")
_RECORD_FIELDS = ("spf", "dmarc", "dkim", "mta_sts", "tls_rpt", "bimi")
# The rule part of a Microsoft 365 DNS finding id (``dns_posture:<domain>:<rule>``), split off before the domain part
# is pseudonymised. A rule missing here still leaks nothing: its id becomes one pseudonym of ``<domain>:<rule>``.
_M365_DNS_RULES = frozenset(
    "spf_missing spf_passthrough spf_multiple_records dmarc_missing dmarc_monitor_only dmarc_multiple_records "
    "dmarc_pct_partial dmarc_rua_invalid dkim_missing bimi_logo_insecure mta_sts_missing mta_sts_policy_invalid "
    "mta_sts_testing_mode tls_rpt_missing".split()
)
_REF_PREFIX = r"dns_posture|google_domain_posture|google\.dns_[a-z_]+"
_REF_RE = re.compile(r"(?P<prefix>" + _REF_PREFIX + r"):(?P<rest>.*)\Z", re.DOTALL)
# The domain part is all of an id but a final ``:<rule>`` (and an optional numeric row index after it): a real id is
# ``dns_posture:<domain>:<rule>``, so a rule name inside the domain text (a URL path such as ``/x:spf_missing:y``) stays
# in the domain part and is pseudonymised with it; any other text after the rule is domain text too.
_M365_RULE_RE = re.compile(
    r"(?P<name>.*):(?P<rule>(?:" + "|".join(sorted(_M365_DNS_RULES)) + r")(?::[0-9]+)?)\Z", re.DOTALL
)
# In free text the domain part of an id runs to the next space, quote or delimiter, whatever its shape (internationalised,
# single-label, URL-shaped, trailing dots). A pseudonym (``Id <hex>``) is matched first so a rewritten id stays as it is.
_DNS_REF_RE = re.compile(
    r"(?<![\w.])(?P<prefix>" + _REF_PREFIX + r"):"
    r"(?P<name>(?:User|Id|Group|Guid) [0-9a-f]{16}(?![0-9a-f])|[^\s\"'`<>|,;&()\[\]{}]+)"
)
# Sentence punctuation after an id in free text stays outside the pseudonym.
_TRAILING = ".:!?"
_DNS_REF_FIELDS = ("id", "finding_id", "record_key", "key")
# Flat Microsoft 365 ``dns_posture`` fields that only a posture record carries.
_FLAT_MARKERS = frozenset(
    {"spf_mechanisms", "dmarc_aggregate_addresses", "dmarc_aggregate_invalid", "tls_rpt_rua", "mta_sts_id",
     "spf_all_qualifier", "dmarc_policy", "dmarc_subdomain_policy", "mta_sts_policy_mode", "spf_mechanism_count",
     "dmarc_rua_count", "dmarc_rua_invalid_count", "tls_rpt_rua_count", "mta_sts_id_present"}
)

Pseudonymise = Callable[[str], str]
_MISSING = object()


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _bool(value: Any) -> Any:
    return value if value is None or isinstance(value, bool) else UNUSABLE


def _vocab(value: Any, allowed: frozenset[str]) -> Any:
    if value is None:
        return None
    if isinstance(value, str) and value.strip().lower() in allowed:
        return value.strip().lower()
    return UNUSABLE


def _count_value(value: Any) -> Any:
    """An already counted value: a non-negative int, ``None``, else ``unusable``."""
    if value is None:
        return None
    return value if _is_int(value) and value >= 0 else UNUSABLE


def _pct(value: Any) -> Any:
    if value is None:
        return None
    return value if _is_int(value) and 0 <= value <= 100 else UNUSABLE


def _entries(value: Any) -> Any:
    """The number of entries of a list of non-empty strings; ``None`` for ``None``; ``unusable`` for anything else
    (a member that is not a non-empty string leaves the count unknown)."""
    if value is None:
        return None
    if isinstance(value, list) and all(isinstance(entry, str) and entry.strip() for entry in value):
        return len(value)
    return UNUSABLE


def _count(record: Mapping[Any, Any], list_key: str, count_key: str) -> Any:
    if list_key in record:
        return _entries(record[list_key])
    if count_key in record:
        return _count_value(record[count_key])
    return _MISSING


def _cisa_listed(value: Any) -> Any:
    """Whether a valid ``mailto:`` URI for the CISA address is in a list of report URIs."""
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(entry, str) and entry.strip() for entry in value):
        return UNUSABLE
    return any(_CISA_URI_RE.fullmatch(entry.strip().lower()) is not None for entry in value)


def _cisa(record: Mapping[Any, Any], list_key: str, flag_key: str) -> Any:
    if list_key in record:
        return _cisa_listed(record[list_key])
    if flag_key in record:
        return _bool(record[flag_key])
    return _MISSING


def _selectors(value: Any) -> Any:
    if value is None:
        return None
    if not isinstance(value, list):
        return UNUSABLE
    return [item if isinstance(item, str) and _SELECTOR_RE.fullmatch(item) else UNUSABLE for item in value]


def _selector_records(value: Any) -> Any:
    """Readable DKIM records across a selector mapping: Google lists the TXT strings per selector, Microsoft 365 keeps
    one ``{"present": true, ...}`` detail per found selector. Any other member leaves the count unknown."""
    if value is None:
        return None
    if not isinstance(value, Mapping):
        return UNUSABLE
    total = 0
    for item in value.values():
        if isinstance(item, list) and all(isinstance(entry, str) and entry.strip() for entry in item):
            total += len(item)
        elif isinstance(item, Mapping) and item.get("present") is True:
            total += 1
        else:
            return UNUSABLE
    return total


def _present_text(value: Any) -> Any:
    """Whether a text field was published: a non-empty string is ``True``, ``None`` or ``""`` is ``False``."""
    if value is None:
        return False
    return bool(value.strip()) if isinstance(value, str) else UNUSABLE


def _resolver_error(value: Any) -> Any:
    """Whether the resolver failed for the domain. Its text can name the resolver host, so only the flag remains."""
    if value is None or isinstance(value, bool):
        return value
    return bool(value.strip()) if isinstance(value, str) else UNUSABLE


_URL_SHAPED_RE = re.compile(r"[/?#@\\]|:[0-9]+\Z|\A[A-Za-z][A-Za-z0-9+.-]*:")
_SCHEME_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9+.-]*:(?://)?")


def _host(text: str) -> str:
    """The host a domain value stands for: for a URL-shaped value the scheme, user information, path, query, fragment
    and port are stripped; trailing dots are removed, the name is lower-cased and IDNA-encoded where it will encode. A
    plain DNS name (``_dmarc.example.com`` included) only loses case and trailing dots. A pseudonym is returned as it
    is. No part of the original text beyond the host survives."""
    host = text.strip()
    if host.startswith(("User ", "Id ", "Group ", "Guid ")):
        return host
    if _URL_SHAPED_RE.search(host):
        host = _SCHEME_RE.sub("", host, count=1)
        host = re.split(r"[/?#\\]", host, maxsplit=1)[0].rpartition("@")[2]
        host = re.sub(r":[0-9]*\Z", "", host)
    host = host.lower().rstrip(".")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _pseudo(pseudonymise: Pseudonymise, text: str) -> str:
    """The pseudonym of the host a domain value names, never of text beyond it."""
    return pseudonymise(_host(text))


def _name(value: Any, pseudonymise: Pseudonymise) -> Any:
    if value is None:
        return None
    return _pseudo(pseudonymise, value) if isinstance(value, str) and value.strip() else UNUSABLE


def _split_rule(prefix: str, rest: str) -> tuple[str, str]:
    """``rest`` of an id as (domain part, ``:<rule>`` suffix or ``""``)."""
    if prefix == "dns_posture":
        match = _M365_RULE_RE.match(rest)
        if match is not None:
            return match["name"], ":" + match["rule"]
    return rest, ""


def dns_ref(value: str, pseudonymise: Pseudonymise) -> str:
    """A whole DNS-derived id or key: ``<prefix>:<domain>[:<rule>]`` with its domain part pseudonymised whatever its
    shape, or a bare DNS name pseudonymised as a whole."""
    match = _REF_RE.match(value)
    if match is None:
        return _pseudo(pseudonymise, value)
    name, rule = _split_rule(match["prefix"], match["rest"])
    return f"{match['prefix']}:{_pseudo(pseudonymise, name)}{rule}"


def dns_ref_text(text: str, pseudonymise: Pseudonymise) -> str:
    """``text`` with the DNS name in every DNS-derived id (``dns_posture:<name>``, ``google_domain_posture:<name>``,
    ``google.dns_<rule>:<name>``) replaced by its pseudonym."""
    if ":" not in text:
        return text
    if not any(char.isspace() for char in text) and _REF_RE.match(text):
        # A whole value that is one id (a record key in an evidence ref, a mapping key): its domain part is all of it.
        return dns_ref(text, pseudonymise)

    def replace(match: re.Match[str]) -> str:
        token = match["name"]
        if token.startswith(("User ", "Id ", "Group ", "Guid ")):
            return match[0]
        body = token.rstrip(_TRAILING)
        tail = token[len(body):]
        name, rule = _split_rule(match["prefix"], body)
        if not name:
            return match[0]
        return f"{match['prefix']}:{_pseudo(pseudonymise, name)}{rule}{tail}"

    return _DNS_REF_RE.sub(replace, text)


def _ref(value: Any, pseudonymise: Pseudonymise) -> Any:
    """A record id or key: a bare DNS name, or ``<kind>:<name>``."""
    if not isinstance(value, str) or not value.strip():
        return _name(value, pseudonymise)
    return dns_ref(value, pseudonymise)


def _put(out: dict[str, Any], key: str, value: Any) -> None:
    if value is not _MISSING:
        out[key] = value


def _spf(record: Mapping[Any, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"record_text": WITHHELD}
    if "present" in record:
        out["present"] = _bool(record["present"])
    if "kind" in record:
        out["kind"] = _vocab(record["kind"], _KINDS)
    if "all_qualifier" in record:
        out["all_qualifier"] = _vocab(record["all_qualifier"], _SPF_QUALIFIERS)
    if "multiple_records" in record:
        out["multiple_records"] = _bool(record["multiple_records"])
    _put(out, "mechanism_count", _count(record, "mechanisms", "mechanism_count"))
    _put(out, "record_count", _count(record, "records", "record_count"))
    return out


def _dmarc_pct_partial(record: Mapping[Any, Any], pct_key: str, partial_key: str, present_key: str) -> Any:
    """Partial enforcement, asserted only beside a readable affirmative publication flag (``True``) and a readable
    parsed percentage: a missing, wrong-typed or contradictory flag and an unreadable percentage prove nothing, and the
    companion flag never does. A record that is positively not published (flag ``False``, no percentage) stays
    ``False`` (nothing published, nothing partial)."""
    present = record.get(present_key)
    pct = _pct(record[pct_key]) if pct_key in record else _MISSING
    if present is True:
        if _is_int(pct):
            return pct < 100
        return UNUSABLE if partial_key in record else _MISSING
    if _is_int(pct):
        return UNUSABLE
    if present is False and record.get(partial_key) is False and (pct is None or pct is _MISSING):
        return False
    return UNUSABLE if partial_key in record else _MISSING


def _dmarc(record: Mapping[Any, Any], pseudonymise: Pseudonymise) -> dict[str, Any]:
    out: dict[str, Any] = {"record_text": WITHHELD}
    if "present" in record:
        out["present"] = _bool(record["present"])
    if "kind" in record:
        out["kind"] = _vocab(record["kind"], _KINDS)
    if "policy" in record:
        out["policy"] = _vocab(record["policy"], _DMARC_POLICIES)
    if "subdomain_policy" in record:
        out["subdomain_policy"] = _vocab(record["subdomain_policy"], _DMARC_POLICIES)
        # An unreadable sp= proves nothing about whether one was published.
        out["subdomain_policy_present"] = (
            UNUSABLE if out["subdomain_policy"] == UNUSABLE else out["subdomain_policy"] is not None
        )
    elif "subdomain_policy_present" in record:
        out["subdomain_policy_present"] = _bool(record["subdomain_policy_present"])
    if "pct" in record:
        out["pct"] = _pct(record["pct"])
    _put(out, "pct_partial", _dmarc_pct_partial(record, "pct", "pct_partial", "present"))
    _put(out, "rua_count", _count(record, "aggregate_addresses", "rua_count"))
    _put(out, "rua_invalid_count", _count(record, "aggregate_addresses_invalid", "rua_invalid_count"))
    _put(out, "cisa_rua_present", _cisa(record, "aggregate_addresses", "cisa_rua_present"))
    _put(out, "ruf_count", _count(record, "forensic_addresses", "ruf_count"))
    _put(out, "ruf_invalid_count", _count(record, "forensic_addresses_invalid", "ruf_invalid_count"))
    if "inherited" in record:
        out["inherited"] = _bool(record["inherited"])
    if "multiple_records" in record:
        out["multiple_records"] = _bool(record["multiple_records"])
    _put(out, "record_count", _count(record, "records", "record_count"))
    if "query_name" in record:
        out["query_domain"] = _name(record["query_name"], pseudonymise)
    elif "query_domain" in record:
        out["query_domain"] = _name(record["query_domain"], pseudonymise)
    return out


def _dkim(record: Mapping[Any, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"record_text": WITHHELD}
    for key in ("selectors_present", "selectors_missing", "selectors_unresolved"):
        if key in record:
            out[key] = _selectors(record[key])
    if "selectors" in record:
        out["selector_record_count"] = _selector_records(record["selectors"])
    elif "selector_details" in record:
        out["selector_record_count"] = _selector_records(record["selector_details"])
    elif "selector_record_count" in record:
        out["selector_record_count"] = _count_value(record["selector_record_count"])
    return out


def _mta_sts(record: Mapping[Any, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"record_text": WITHHELD}
    if "dns_present" in record:
        out["dns_present"] = _bool(record["dns_present"])
    if "id" in record:
        out["id_present"] = _present_text(record["id"])
    elif "id_present" in record:
        out["id_present"] = _bool(record["id_present"])
    if "policy" in record:
        policy = record["policy"]
        if isinstance(policy, Mapping):
            out["policy_fetch_status"] = _vocab(policy.get("fetch_status"), _MTA_STS_FETCH)
            out["policy_mode"] = _vocab(policy.get("mode"), _MTA_STS_MODES)
        else:
            out["policy_mode"] = None if policy is None else UNUSABLE
    else:
        if "policy_fetch_status" in record:
            out["policy_fetch_status"] = _vocab(record["policy_fetch_status"], _MTA_STS_FETCH)
        if "policy_mode" in record:
            out["policy_mode"] = _vocab(record["policy_mode"], _MTA_STS_MODES)
    return out


def _tls_rpt(record: Mapping[Any, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"record_text": WITHHELD}
    if "present" in record:
        out["present"] = _bool(record["present"])
    if "kind" in record:
        out["kind"] = _vocab(record["kind"], _KINDS)
    _put(out, "rua_count", _count(record, "rua", "rua_count"))
    return out


def _bimi(record: Mapping[Any, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"record_text": WITHHELD}
    if "present" in record:
        out["present"] = _bool(record["present"])
    if "kind" in record:
        out["kind"] = _vocab(record["kind"], _KINDS)
    if "logo_url" in record:
        out["logo_url_present"] = _present_text(record["logo_url"])
    elif "logo_url_present" in record:
        out["logo_url_present"] = _bool(record["logo_url_present"])
    if "logo_url_is_https" in record:
        out["logo_url_is_https"] = _bool(record["logo_url_is_https"])
    if "authority_url" in record:
        out["authority_url_present"] = _present_text(record["authority_url"])
    elif "authority_url_present" in record:
        out["authority_url_present"] = _bool(record["authority_url_present"])
    if "authority_url_is_https" in record:
        out["authority_url_is_https"] = _bool(record["authority_url_is_https"])
    return out


def _section(field: str, value: Any, pseudonymise: Pseudonymise) -> Any:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        return UNUSABLE
    if field == "spf":
        return _spf(value)
    if field == "dmarc":
        return _dmarc(value, pseudonymise)
    if field == "dkim":
        return _dkim(value)
    if field == "mta_sts":
        return _mta_sts(value)
    if field == "tls_rpt":
        return _tls_rpt(value)
    return _bimi(value)


def _common(key: Any, value: Any, pseudonymise: Pseudonymise) -> Any:
    """The fields a nested and a flat posture record share, or ``_MISSING`` for a field that is not one of them."""
    if key == "kind":
        return value if isinstance(value, str) and value in _POSTURE_KINDS else UNUSABLE
    if key == "source":
        return value if isinstance(value, str) and value in _POSTURE_SOURCES else UNUSABLE
    if key in ("id", "key"):
        return _ref(value, pseudonymise)
    if key == "domain":
        return _name(value, pseudonymise)
    if key == "resolver_error":
        return _resolver_error(value)
    if key in ("alias", "is_primary", "isPrimary", "is_default", "isDefault", "managed_by_microsoft"):
        return _bool(value)
    if key in ("authentication_type", "authenticationType"):
        return _vocab(value, _AUTHENTICATION_TYPES)
    return _MISSING


def _nested(record: Mapping[Any, Any], pseudonymise: Pseudonymise) -> dict[Any, Any]:
    out: dict[Any, Any] = {}
    for key, value in record.items():
        if key in _RECORD_FIELDS:
            out[key] = _section(key, value, pseudonymise)
        else:
            _put(out, key, _common(key, value, pseudonymise))
    return out


def _flat_field(record: Mapping[Any, Any], key: Any, value: Any, out: dict[Any, Any]) -> None:
    if key in ("spf_present", "spf_multiple_records", "dmarc_present", "dmarc_multiple_records", "mta_sts_dns_present",
               "tls_rpt_present", "bimi_present", "bimi_logo_https", "dmarc_cisa_rua_present", "mta_sts_id_present"):
        out[key] = _bool(value)
    elif key == "spf_all_qualifier":
        out[key] = _vocab(value, _SPF_QUALIFIERS)
    elif key in ("dmarc_policy", "dmarc_subdomain_policy"):
        out[key] = _vocab(value, _DMARC_POLICIES)
    elif key == "mta_sts_policy_mode":
        out[key] = _vocab(value, _MTA_STS_MODES)
    elif key == "mta_sts_policy_fetch_status":
        out[key] = _vocab(value, _MTA_STS_FETCH)
    elif key in ("dmarc_record_count", "mta_sts_policy_http_status", "spf_mechanism_count", "dmarc_rua_count",
                 "dmarc_rua_invalid_count", "tls_rpt_rua_count"):
        out[key] = _count_value(value)
    elif key == "dmarc_pct":
        out[key] = _pct(value)
    elif key == "dmarc_pct_partial":
        # The normalised record drops an unreadable (``None``) percentage, so a published DMARC record without one had
        # a percentage nobody could read.
        _put(out, key, _dmarc_pct_partial(record, "dmarc_pct", "dmarc_pct_partial", "dmarc_present"))
    elif key == "spf_mechanisms":
        out["spf_mechanism_count"] = _entries(value)
    elif key == "dmarc_aggregate_addresses":
        out["dmarc_rua_count"] = _entries(value)
        out["dmarc_cisa_rua_present"] = _cisa_listed(value)
    elif key == "dmarc_aggregate_invalid":
        out["dmarc_rua_invalid_count"] = _entries(value)
    elif key == "tls_rpt_rua":
        out["tls_rpt_rua_count"] = _entries(value)
    elif key == "mta_sts_id":
        out["mta_sts_id_present"] = _present_text(value)
    elif key in ("dkim_selectors_present", "dkim_selectors_missing", "dkim_selectors_unresolved"):
        out[key] = _selectors(value)


def _flat(record: Mapping[Any, Any], pseudonymise: Pseudonymise) -> dict[Any, Any]:
    out: dict[Any, Any] = {}
    for key, value in record.items():
        common = _common(key, value, pseudonymise)
        if common is not _MISSING:
            out[key] = common
        else:
            _flat_field(record, key, value, out)
    return out


def _scuba_row(record: Mapping[Any, Any], pseudonymise: Pseudonymise) -> dict[Any, Any]:
    out: dict[Any, Any] = {}
    for key, value in record.items():
        if key == "rdata":
            out["rdata_count"] = _entries(value)
        elif key == "query_answers":
            out["query_answer_count"] = _entries(value)
        elif key in ("query_name", "query_domain"):
            out["query_domain"] = _name(value, pseudonymise)
        elif key == "domain":
            out[key] = _name(value, pseudonymise)
        else:
            out.setdefault(key, value)
    return out


def _dns_rule(rule: Any) -> bool:
    return isinstance(rule, str) and (rule.startswith("dns_posture.") or rule.startswith("google.dns_"))


def _returned(rule: str, value: Any, pseudonymise: Pseudonymise) -> Any:
    """A DNS finding's ``returned_value`` in the shareable profiles: each rule's own predicate, else ``None`` or
    ``unusable``."""
    if rule in ("dns_posture.dmarc_monitor_only", "google.dns_dmarc_monitor_only"):
        return "" if value == "" else _vocab(value, _DMARC_POLICIES)
    if rule == "dns_posture.spf_passthrough":
        return _vocab(value, _SPF_QUALIFIERS)
    if rule == "dns_posture.mta_sts_testing_mode":
        return _vocab(value, _MTA_STS_MODES)
    if rule == "dns_posture.dmarc_pct_partial":
        return _pct(value)
    if rule == "dns_posture.dmarc_multiple_records":
        return _count_value(value)
    if rule == "dns_posture.dmarc_rua_invalid":
        return _count_value(value) if not isinstance(value, list) else _entries(value)
    if rule == "dns_posture.dkim_missing":
        return _selectors(value)
    if rule == "dns_posture.mta_sts_policy_invalid":
        if value is None:
            return None
        if not isinstance(value, Mapping):
            return UNUSABLE
        return {"fetch_status": _vocab(value.get("fetch_status"), _MTA_STS_FETCH),
                "http_status": _count_value(value.get("http_status"))}
    if rule in ("google.dns_spf_missing", "google.dns_dkim_missing"):
        return _name(value, pseudonymise)
    return None if value is None else UNUSABLE


def _finding(record: Mapping[Any, Any], pseudonymise: Pseudonymise) -> dict[Any, Any]:
    """A DNS finding, or a row built from one (proof table, reviewer index): its DNS-derived ids, affected domains and
    returned value rewritten; its ``evidence`` (a flat posture record) is rewritten when the walk reaches it."""
    rule = record["rule_id"]
    out: dict[Any, Any] = {}
    for key, value in record.items():
        if key in _DNS_REF_FIELDS and isinstance(value, str):
            out[key] = dns_ref(value, pseudonymise) if _REF_RE.match(value) else dns_ref_text(value, pseudonymise)
        elif key == "affected_objects" and isinstance(value, list):
            out[key] = [_name(item, pseudonymise) for item in value]
        elif key == "blast_radius" and isinstance(value, Mapping) and isinstance(value.get("affected_objects"), list):
            out[key] = {**value, "affected_objects": [_name(item, pseudonymise) for item in value["affected_objects"]]}
        elif key == "returned_value":
            out[key] = _returned(rule, value, pseudonymise)
        else:
            out[key] = value
    return out


def _posture_kind(record: Mapping[Any, Any]) -> str | None:
    kind = record.get("kind")
    if kind == "google_domain_posture" or (
        "domain" in record and any(field in record for field in _RECORD_FIELDS)
    ):
        return "nested"
    if kind == "dns_posture" or (
        record.get("source") == "dns_posture.domainPosture" or any(key in record for key in _FLAT_MARKERS)
    ) and "domain" in record:
        return "flat"
    return None


def shareable_dns_record(record: Mapping[Any, Any], pseudonymise: Pseudonymise) -> Mapping[Any, Any]:
    """``record`` rewritten for a shareable profile, or ``record`` itself when it is not DNS posture output.

    Recognised shapes: a domain posture with ``spf``/``dmarc``/``dkim``/``mta_sts``/``tls_rpt``/``bimi`` sections
    (Google normalised and raw, Microsoft 365 raw), a flat Microsoft 365 ``dns_posture`` record (normalised, and the
    ``evidence`` of a DNS finding), a SCuBA DNS row (``rdata``) or its resolver log entry (``query_answers``), and a
    DNS finding or a row built from one. ``pseudonymise`` maps a DNS name to its keyed pseudonym (idempotent).
    """
    shape = _posture_kind(record)
    if shape == "nested":
        return _nested(record, pseudonymise)
    if shape == "flat":
        return _flat(record, pseudonymise)
    if ("rdata" in record and "domain" in record) or "query_answers" in record:
        return _scuba_row(record, pseudonymise)
    if _dns_rule(record.get("rule_id")):
        return _finding(record, pseudonymise)
    return record
