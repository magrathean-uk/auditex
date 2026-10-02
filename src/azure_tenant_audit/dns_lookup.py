"""DNS-over-HTTPS lookups and email-auth record parsers.

Used by the dns_posture collector to evaluate SPF, DKIM, DMARC, MTA-STS, TLS-RPT
(RFC 8460, https://datatracker.ietf.org/doc/html/rfc8460), and BIMI records for verified tenant domains without depending on system DNS resolvers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol

import requests

DEFAULT_DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
DEFAULT_TIMEOUT_SECONDS = 5.0


class DohError(RuntimeError):
    """Raised when a DoH query cannot be completed."""


class DnsResolver(Protocol):
    def query(self, name: str, record_type: str) -> list[str]: ...


@dataclass
class DohClient:
    """Minimal DNS-over-HTTPS client returning record data strings."""

    session: Any = field(default_factory=requests.Session)
    endpoint: str = DEFAULT_DOH_ENDPOINT
    timeout: float = DEFAULT_TIMEOUT_SECONDS

    def query(self, name: str, record_type: str) -> list[str]:
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
            raise DohError(f"DoH query failed for {record_type} {name}: {exc}") from exc
        if not isinstance(payload, dict):
            raise DohError(f"DoH response was not an object for {record_type} {name}")
        if int(payload.get("Status", 0)) >= 1 and not payload.get("Answer"):
            return []
        answer = payload.get("Answer") or []
        records: list[str] = []
        for entry in answer:
            if not isinstance(entry, dict):
                continue
            data = entry.get("data")
            if not isinstance(data, str):
                continue
            records.append(_decode_txt(data))
        return records


def _decode_txt(data: str) -> str:
    """Strip the surrounding quotes used by DoH and concatenate multi-string TXT records."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    if parts:
        return "".join(parts)
    return data.strip().strip('"')


def parse_spf(record: str) -> dict[str, Any] | None:
    text = record.strip()
    if not text.lower().startswith("v=spf1"):
        return None
    tokens = text.split()
    mechanisms = [token for token in tokens[1:] if not token.lower().startswith("v=")]
    all_qualifier = None
    for token in mechanisms:
        if token.lower().endswith("all"):
            qualifier = token[0]
            if qualifier in {"+", "-", "~", "?"}:
                all_qualifier = qualifier
            elif token.lower() == "all":
                all_qualifier = "+"
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
        posture["spf"] = _absent("spf")
        posture["dmarc"] = _absent("dmarc")
        posture["dkim"] = {"selectors_present": [], "selectors_missing": list(all_probed)}
        posture["mta_sts"] = {"dns_present": False}
        posture["tls_rpt"] = _absent("tls_rpt")
        posture["bimi"] = _absent("bimi")
        return posture

    posture["spf"] = _summarize_spf(spf_records)
    posture["dmarc"] = _summarize_dmarc(dmarc_records)
    posture["dkim"] = _summarize_dkim_collection(dkim_results)
    posture["mta_sts"] = _summarize_mta_sts(mta_sts_records)
    posture["tls_rpt"] = _summarize_tls_rpt(tls_rpt_records)
    posture["bimi"] = _summarize_bimi(bimi_records)
    return posture


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


def _summarize_dmarc(records: list[str]) -> dict[str, Any]:
    parsed = next((parse_dmarc(rec) for rec in records if parse_dmarc(rec)), None)
    if parsed is None:
        return _absent("dmarc")
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
