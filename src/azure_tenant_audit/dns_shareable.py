"""DNS record text in the shareable profiles: fixed-vocabulary predicates, never the published text.

The local report keeps the TXT text the operator queried (public data). The shareable, customer-pack and explainer
profiles replace it, because a DMARC record names report mailboxes (``rua=mailto:...``), an SPF record names the
domains and addresses allowed to send, and a DMARC query name repeats the domain. What remains says what was published
(policy, qualifier, counts, whether the CISA report address is listed), not where or to whom.

Applied by ``output_redaction._Redactor.mapping`` to every mapping before it is walked. The rewrite is a pure
function of the record and the pseudonym key, keeps the record's key order, and is idempotent: a record it has
already rewritten comes back unchanged. A wrong-typed or unrecognised value never becomes a predicate value; it
becomes ``None`` (no value) or ``"unrecognised"`` (a value that is not in the vocabulary).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

WITHHELD = "withheld"
UNRECOGNISED = "unrecognised"
# CISA's DMARC aggregate report address (BOD 18-01; SCuBA MS.EXO.4.3v1 and GWS.GMAIL.4.3v1).
CISA_RUA = "reports@dmarc.cyber.dhs.gov"

_DMARC_POLICIES = frozenset({"none", "quarantine", "reject"})
_SPF_QUALIFIERS = frozenset({"+", "-", "~", "?"})
_MTA_STS_MODES = frozenset({"enforce", "testing", "none"})
_KINDS = frozenset({"spf", "dmarc", "tls_rpt", "bimi"})
_SELECTOR_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?")
_RECORD_FIELDS = ("spf", "dmarc", "dkim", "mta_sts", "tls_rpt", "bimi")
# Flat Microsoft 365 ``dns_posture`` record fields that hold record text, and what replaces them.
_FLAT_FIELDS = frozenset(
    {"spf_mechanisms", "dmarc_aggregate_addresses", "dmarc_aggregate_invalid", "tls_rpt_rua", "mta_sts_id",
     "spf_all_qualifier", "dmarc_policy", "dmarc_subdomain_policy", "mta_sts_policy_mode"}
)
_FLAT_TEXT_FIELDS = ("spf_mechanisms", "dmarc_aggregate_addresses", "dmarc_aggregate_invalid", "tls_rpt_rua")
# Findings whose ``returned_value`` is copied from record text.
_RETURNED_COUNT_RULES = frozenset({"dns_posture.dmarc_rua_invalid"})
_RETURNED_POLICY_RULES = frozenset({"dns_posture.dmarc_monitor_only", "google.dns_dmarc_monitor_only"})

_MISSING = object()


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _vocab(value: Any, allowed: frozenset[str]) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and value.strip().lower() in allowed:
        return value.strip().lower()
    return UNRECOGNISED


def _count(record: Mapping[Any, Any], list_key: str, count_key: str) -> Any:
    """The length of ``record[list_key]`` (a list), else an already counted ``record[count_key]``; ``_MISSING``
    when neither key is there and ``None`` when the value there is not a list or a count."""
    if list_key in record:
        value = record[list_key]
        return len(value) if isinstance(value, list) else None
    if count_key in record:
        value = record[count_key]
        return value if _is_int(value) and value >= 0 else None
    return _MISSING


def _address(entry: Any) -> str | None:
    if not isinstance(entry, str):
        return None
    text = entry.strip().lower()
    return text[len("mailto:"):] if text.startswith("mailto:") else text


def _cisa(record: Mapping[Any, Any], list_key: str, flag_key: str) -> Any:
    """Whether the CISA report address is listed. ``None`` for a list that is not a list of strings."""
    if list_key in record:
        value = record[list_key]
        if not isinstance(value, list):
            return None
        addresses = [_address(entry) for entry in value]
        if any(address is None for address in addresses):
            return None
        # A ``!size`` suffix (RFC 7489 section 6.2) does not change the address.
        return any(address.split("!", 1)[0] == CISA_RUA for address in addresses if address is not None)
    if flag_key in record:
        return _bool(record[flag_key])
    return _MISSING


def _pct(value: Any) -> Any:
    if value is None:
        return None
    return value if _is_int(value) and 0 <= value <= 100 else UNRECOGNISED


def _selectors(value: Any) -> Any:
    if not isinstance(value, list):
        return None
    return [item if isinstance(item, str) and _SELECTOR_RE.fullmatch(item) else UNRECOGNISED for item in value]


def _put(out: dict[str, Any], key: str, value: Any) -> None:
    if value is not _MISSING:
        out[key] = value


def _copy(out: dict[str, Any], record: Mapping[Any, Any], key: str, convert: Callable[[Any], Any]) -> None:
    if key in record:
        out[key] = convert(record[key])


def _kind(value: Any) -> str | None:
    return value if isinstance(value, str) and value in _KINDS else None


def _query_domain(record: Mapping[Any, Any], pseudonymise: Callable[[str], str]) -> Any:
    name = record.get("query_name", _MISSING)
    if name is _MISSING:
        return record.get("query_domain") if isinstance(record.get("query_domain"), str) else _MISSING
    if not isinstance(name, str) or not name.strip():
        return None
    return pseudonymise(name.strip().lower().rstrip("."))


def _spf(record: Mapping[Any, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"record_text": WITHHELD}
    _copy(out, record, "present", _bool)
    _copy(out, record, "kind", _kind)
    _copy(out, record, "all_qualifier", lambda value: _vocab(value, _SPF_QUALIFIERS))
    _copy(out, record, "multiple_records", _bool)
    _put(out, "mechanism_count", _count(record, "mechanisms", "mechanism_count"))
    _put(out, "record_count", _count(record, "records", "record_count"))
    return out


def _dmarc(record: Mapping[Any, Any], pseudonymise: Callable[[str], str]) -> dict[str, Any]:
    out: dict[str, Any] = {"record_text": WITHHELD}
    _copy(out, record, "present", _bool)
    _copy(out, record, "kind", _kind)
    _copy(out, record, "policy", lambda value: _vocab(value, _DMARC_POLICIES))
    _copy(out, record, "subdomain_policy", lambda value: _vocab(value, _DMARC_POLICIES))
    if "subdomain_policy" in record:
        out["subdomain_policy_present"] = record["subdomain_policy"] is not None
    elif "subdomain_policy_present" in record:
        out["subdomain_policy_present"] = _bool(record["subdomain_policy_present"])
    _copy(out, record, "pct", _pct)
    _copy(out, record, "pct_partial", _bool)
    _put(out, "rua_count", _count(record, "aggregate_addresses", "rua_count"))
    _put(out, "rua_invalid_count", _count(record, "aggregate_addresses_invalid", "rua_invalid_count"))
    _put(out, "cisa_rua_present", _cisa(record, "aggregate_addresses", "cisa_rua_present"))
    _put(out, "ruf_count", _count(record, "forensic_addresses", "ruf_count"))
    _put(out, "ruf_invalid_count", _count(record, "forensic_addresses_invalid", "ruf_invalid_count"))
    _copy(out, record, "inherited", _bool)
    _copy(out, record, "multiple_records", _bool)
    _put(out, "record_count", _count(record, "records", "record_count"))
    _put(out, "query_domain", _query_domain(record, pseudonymise))
    return out


def _dkim(record: Mapping[Any, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"record_text": WITHHELD}
    for key in ("selectors_present", "selectors_missing", "selectors_unresolved"):
        _copy(out, record, key, _selectors)
    if "selectors" in record or "selector_details" in record:
        records = record.get("selectors", record.get("selector_details"))
        out["selector_record_count"] = (
            sum(len(value) if isinstance(value, list) else 1 for value in records.values() if value)
            if isinstance(records, Mapping) else None
        )
    elif "selector_record_count" in record:
        value = record["selector_record_count"]
        out["selector_record_count"] = value if _is_int(value) and value >= 0 else None
    return out


def _mta_sts(record: Mapping[Any, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"record_text": WITHHELD}
    _copy(out, record, "dns_present", _bool)
    if "id" in record:
        out["id_present"] = isinstance(record["id"], str) and bool(record["id"].strip())
    elif "id_present" in record:
        out["id_present"] = _bool(record["id_present"])
    policy = record.get("policy")
    if isinstance(policy, Mapping):
        out["policy_mode"] = _vocab(policy.get("mode"), _MTA_STS_MODES)
    elif "policy_mode" in record:
        out["policy_mode"] = _vocab(record["policy_mode"], _MTA_STS_MODES)
    return out


def _tls_rpt(record: Mapping[Any, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"record_text": WITHHELD}
    _copy(out, record, "present", _bool)
    _copy(out, record, "kind", _kind)
    _put(out, "rua_count", _count(record, "rua", "rua_count"))
    return out


def _bimi(record: Mapping[Any, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"record_text": WITHHELD}
    _copy(out, record, "present", _bool)
    _copy(out, record, "kind", _kind)
    for name in ("logo_url", "authority_url"):
        if name in record:
            out[f"{name}_present"] = isinstance(record[name], str) and bool(record[name].strip())
        else:
            _copy(out, record, f"{name}_present", _bool)
        _copy(out, record, f"{name}_is_https", _bool)
    return out


def _section(field: str, value: Any, pseudonymise: Callable[[str], str]) -> Any:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        return UNRECOGNISED
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


def _flat(record: Mapping[Any, Any]) -> dict[Any, Any]:
    out: dict[Any, Any] = {}
    for key, value in record.items():
        if key == "spf_mechanisms":
            out["spf_mechanism_count"] = len(value) if isinstance(value, list) else None
        elif key == "dmarc_aggregate_addresses":
            out["dmarc_rua_count"] = len(value) if isinstance(value, list) else None
            out["dmarc_cisa_rua_present"] = _cisa(record, key, "dmarc_cisa_rua_present")
        elif key == "dmarc_aggregate_invalid":
            out["dmarc_rua_invalid_count"] = len(value) if isinstance(value, list) else None
        elif key == "tls_rpt_rua":
            out["tls_rpt_rua_count"] = len(value) if isinstance(value, list) else None
        elif key == "mta_sts_id":
            out["mta_sts_id_present"] = isinstance(value, str) and bool(value.strip())
        elif key == "spf_all_qualifier":
            out[key] = _vocab(value, _SPF_QUALIFIERS)
        elif key in ("dmarc_policy", "dmarc_subdomain_policy"):
            out[key] = _vocab(value, _DMARC_POLICIES)
        elif key == "mta_sts_policy_mode":
            out[key] = _vocab(value, _MTA_STS_MODES)
        else:
            out.setdefault(key, value)
    return out


def _scuba_row(record: Mapping[Any, Any], pseudonymise: Callable[[str], str]) -> dict[Any, Any]:
    out: dict[Any, Any] = {}
    for key, value in record.items():
        if key == "rdata":
            out["rdata_count"] = len(value) if isinstance(value, list) else None
        elif key == "query_answers":
            out["query_answer_count"] = len(value) if isinstance(value, list) else None
        elif key == "query_name":
            out["query_domain"] = _query_domain(record, pseudonymise)
        else:
            out.setdefault(key, value)
    return out


def _returned(record: Mapping[Any, Any]) -> dict[Any, Any] | None:
    rule = record.get("rule_id")
    if "returned_value" not in record or not isinstance(rule, str):
        return None
    value = record["returned_value"]
    if rule in _RETURNED_COUNT_RULES and not _is_int(value):
        replacement: Any = len(value) if isinstance(value, list) else None
    elif rule in _RETURNED_POLICY_RULES and value is not None:
        replacement = _vocab(value, _DMARC_POLICIES | {""})
    else:
        return None
    return {key: (replacement if key == "returned_value" else item) for key, item in record.items()}


def shareable_dns_record(record: Mapping[Any, Any], pseudonymise: Callable[[str], str]) -> Mapping[Any, Any]:
    """``record`` with DNS record text replaced by predicates, or ``record`` itself when it carries none.

    Recognised shapes: a domain posture with ``spf``/``dmarc``/``dkim``/``mta_sts``/``tls_rpt``/``bimi`` sections
    (Google normalised and raw, Microsoft 365 raw), a flat Microsoft 365 ``dns_posture`` record (normalised, and the
    ``evidence`` of a DNS finding), a SCuBA DNS row (``rdata``) or its resolver log entry (``query_answers``), and a
    DNS finding whose ``returned_value`` is copied from record text. ``pseudonymise`` maps a DNS name to its keyed
    pseudonym.
    """
    if isinstance(record.get("domain"), str) and any(isinstance(record.get(field), Mapping) for field in _RECORD_FIELDS):
        return {
            key: (_section(key, value, pseudonymise) if key in _RECORD_FIELDS else value)
            for key, value in record.items()
        }
    if any(key in record for key in _FLAT_FIELDS) and (
        record.get("kind") == "dns_posture" or any(key in record for key in _FLAT_TEXT_FIELDS)
    ):
        return _flat(record)
    if ("rdata" in record and isinstance(record.get("domain"), str)) or "query_answers" in record:
        return _scuba_row(record, pseudonymise)
    returned = _returned(record)
    return returned if returned is not None else record
