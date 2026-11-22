"""Unauthenticated, read-only public lookups for the audited tenant's own domains.

Two lookups live here, and both run only from the live ``dns_posture`` collector
against domains that Microsoft Graph reports as *verified* for the audited
tenant. Offline runs never reach this module.

* MTA-STS policy fetch (RFC 8461 section 3.3): ``GET https://mta-sts.<domain>/.well-known/mta-sts.txt``.
  Only issued when the ``_mta-sts.<domain>`` TXT record exists. Redirects are not
  followed (RFC 8461 section 3.3) and the body is capped.
  https://learn.microsoft.com/en-us/exchange/security-and-compliance/enhance-mail-flow-using-strict-transport-security
  https://datatracker.ietf.org/doc/html/rfc8461
* Entra OpenID discovery document:
  ``GET https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration``.
  This is the public metadata any outsider can read for a tenant domain.
  https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc

No username, account, or mailbox is ever probed. The undocumented
``getuserrealm.srf`` endpoint is deliberately not used.
"""
from __future__ import annotations

import json
import re
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

import requests

DEFAULT_TIMEOUT_SECONDS = 5.0
# The requests timeout bounds each socket read, not the response: a host that sends a byte every few seconds could
# hold one fetch for days. One fetch therefore stops at this wall-clock deadline (review R163).
DEFAULT_FETCH_DEADLINE_SECONDS = 15.0
_READ_CHUNK_BYTES = 8192
MAX_POLICY_BYTES = 64 * 1024
MAX_POLICY_AGE_SECONDS = 31557600  # RFC 8461 section 3.2: the largest max_age a sender accepts
OIDC_AUTHORITY = "https://login.microsoftonline.com"
_GUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)


class HttpsFetcher(Protocol):
    def get_text(self, url: str) -> tuple[int | None, str, str | None]:
        """Return ``(status_code, body, error)``. ``status_code`` is None on transport failure."""
        ...


@dataclass
class RequestsHttpsFetcher:
    """Minimal HTTPS GET helper: no redirects, no credentials, capped body."""

    session: Any = field(default_factory=requests.Session)
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    deadline: float = DEFAULT_FETCH_DEADLINE_SECONDS
    clock: Callable[[], float] = time.monotonic

    def get_text(self, url: str) -> tuple[int | None, str, str | None]:
        if not url.lower().startswith("https://"):
            return None, "", "refused_non_https_url"
        start = self.clock()
        try:
            # identity encoding and a hook that drops any redirect body: requests otherwise reads a redirect body in
            # full (resolve_redirects, even with allow_redirects=False) and urllib3 may loop raw reads inside one
            # decoding read1, both outside the deadline below.
            response = self.session.get(url, timeout=self.timeout, allow_redirects=False, stream=True,
                                        headers={"Accept-Encoding": "identity"}, hooks={"response": _drop_redirect_body})
            raw = self._read_body(response, start)
            if raw is None:
                close = getattr(response, "close", None)
                if callable(close):
                    close()
                return None, "", "fetch_deadline_exceeded"
            raw = _decode_body(raw, (getattr(response, "headers", None) or {}).get("Content-Encoding"))
            body = raw[:MAX_POLICY_BYTES].decode("utf-8", errors="replace")
            return int(response.status_code), body, None
        except Exception as exc:  # noqa: BLE001
            return None, "", f"{type(exc).__name__}: {exc}"[:300]

    def _read_body(self, response: Any, start: float) -> bytes | None:
        """At most MAX_POLICY_BYTES + 1 bytes, or None once the deadline passes. ``read1`` returns what one socket read
        delivers, so the deadline is overrun by at most one per-read timeout."""
        stream = response.raw
        if stream is None:
            return b""
        read = getattr(stream, "read1", None) or stream.read
        chunks: list[bytes] = []
        size = 0
        while size <= MAX_POLICY_BYTES:
            if self.clock() - start > self.deadline:
                return None
            chunk = read(min(_READ_CHUNK_BYTES, MAX_POLICY_BYTES + 1 - size), decode_content=False)
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if self.clock() - start > self.deadline:
            return None
        return b"".join(chunks)


def _drop_redirect_body(response: Any, *args: Any, **kwargs: Any) -> Any:
    """Response hook: a redirect is never followed (RFC 8461 section 3.3), so its body is never read."""
    if getattr(response, "is_redirect", False):
        response._content = b""
        response._content_consumed = True
        close = getattr(response, "close", None)
        if callable(close):
            close()
    return response


def _decode_body(raw: bytes, encoding: Any) -> bytes:
    """Decode a gzip or deflate body after the bounded raw read, never past MAX_POLICY_BYTES + 1 bytes of output."""
    name = str(encoding or "").strip().lower()
    if name in {"gzip", "x-gzip"}:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif name == "deflate":
        decoder = zlib.decompressobj(zlib.MAX_WBITS if raw[:1] == b"\x78" else -zlib.MAX_WBITS)
    else:
        return raw
    try:
        return decoder.decompress(raw, MAX_POLICY_BYTES + 1)
    except zlib.error:
        return b""


def is_safe_domain_name(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain or ""))


def parse_mta_sts_policy(text: str) -> dict[str, Any] | None:
    """Parse an RFC 8461 policy body (``key: value`` lines)."""
    if not isinstance(text, str) or not text.strip():
        return None
    fields: dict[str, Any] = {"mx": []}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "mx":
            fields["mx"].append(value)
        elif key in {"version", "mode", "max_age"}:
            fields[key] = value
    if str(fields.get("version") or "").lower() != "stsv1":
        return None
    mode = str(fields.get("mode") or "").strip().lower() or None
    max_age: int | None
    try:
        max_age = int(fields["max_age"]) if fields.get("max_age") is not None else None
    except (TypeError, ValueError):
        max_age = None
    return {
        "version": "STSv1",
        "mode": mode,
        "mode_valid": mode in {"enforce", "testing", "none"},
        "mx": list(fields["mx"]),
        "max_age": max_age,
    }


def fetch_mta_sts_policy(domain: str, fetcher: HttpsFetcher) -> dict[str, Any]:
    """Fetch and parse the MTA-STS policy for one verified domain."""
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    if not is_safe_domain_name(domain):
        return {"url": url, "fetch_status": "skipped", "error": "invalid_domain_name"}
    status, body, error = fetcher.get_text(url)
    if status is None:
        return {"url": url, "fetch_status": "unreachable", "http_status": None, "error": error}
    if status != 200:
        return {"url": url, "fetch_status": "http_error", "http_status": status}
    parsed = parse_mta_sts_policy(body)
    if parsed is None:
        return {"url": url, "fetch_status": "invalid_policy", "http_status": status}
    reasons = mta_sts_policy_problems(parsed)
    if reasons:
        return {"url": url, "fetch_status": "invalid_policy", "http_status": status, **parsed, "invalid_reasons": reasons}
    return {"url": url, "fetch_status": "ok", "http_status": status, **parsed}


def mta_sts_policy_problems(parsed: dict[str, Any]) -> list[str]:
    """Why RFC 8461 section 3.2 senders would treat a parsed STSv1 policy as invalid (review R113): an unknown mode,
    a missing or out-of-range max_age, or no mx line in enforce or testing mode. Empty when the policy is valid."""
    reasons = []
    if not parsed.get("mode_valid"):
        reasons.append("mode_invalid")
    max_age = parsed.get("max_age")
    if not isinstance(max_age, int) or not 0 <= max_age <= MAX_POLICY_AGE_SECONDS:
        reasons.append("max_age_invalid")
    if parsed.get("mode") in {"enforce", "testing"} and not any(str(mx).strip() for mx in parsed.get("mx") or []):
        reasons.append("mx_missing")
    return reasons


def parse_openid_configuration(payload: Any) -> dict[str, Any] | None:
    """Keep only the tenant-level public facts from an OIDC discovery document."""
    if not isinstance(payload, dict):
        return None
    issuer = str(payload.get("issuer") or "")
    match = _GUID_RE.search(issuer) or _GUID_RE.search(str(payload.get("token_endpoint") or ""))
    return {
        "tenant_id": match.group(0).lower() if match else None,
        "tenant_region_scope": payload.get("tenant_region_scope"),
        "tenant_region_sub_scope": payload.get("tenant_region_sub_scope"),
        "cloud_instance_name": payload.get("cloud_instance_name"),
        "issuer_host": issuer.split("/")[2] if issuer.count("/") >= 2 else None,
    }


def fetch_tenant_discovery(domain: str, fetcher: HttpsFetcher) -> dict[str, Any]:
    """Read the public OpenID discovery document for one verified tenant domain."""
    url = f"{OIDC_AUTHORITY}/{domain}/v2.0/.well-known/openid-configuration"
    if not is_safe_domain_name(domain):
        return {"url": url, "discovery_status": "skipped", "error": "invalid_domain_name"}
    status, body, error = fetcher.get_text(url)
    if status is None:
        return {"url": url, "discovery_status": "unreachable", "error": error}
    if status != 200:
        return {"url": url, "discovery_status": "not_found" if status in {400, 404} else "http_error", "http_status": status}
    try:
        parsed = parse_openid_configuration(json.loads(body))
    except ValueError:
        parsed = None
    if parsed is None:
        return {"url": url, "discovery_status": "invalid_document", "http_status": status}
    return {"url": url, "discovery_status": "ok", "http_status": status, **parsed}


def summarize_public_footprint(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Build ``report_pack["public_footprint"]``: what an outsider can learn without credentials."""
    domains = []
    tenant_ids: set[str] = set()
    for record in sorted(records, key=lambda item: str(item.get("domain") or "")):
        if record.get("tenant_id"):
            tenant_ids.add(str(record["tenant_id"]))
        domains.append(
            {
                "domain": record.get("domain"),
                "authentication_type": record.get("authentication_type"),
                "discovery_status": record.get("discovery_status"),
                "tenant_id_public": bool(record.get("tenant_id")),
                "tenant_region_scope": record.get("tenant_region_scope"),
                "cloud_instance_name": record.get("cloud_instance_name"),
                "evidence_ref": {
                    "artifact_path": "normalized/public_footprint_objects.json",
                    "artifact_kind": "normalized_json",
                    "collector": "dns_posture",
                    "record_key": record.get("key") or f"public_footprint:{record.get('domain')}",
                },
            }
        )
    return {
        "informational": True,
        "domains": domains,
        "tenant_ids_observed": sorted(tenant_ids),
        "federated_domain_count": sum(
            1 for item in domains if str(item.get("authentication_type") or "").lower() == "federated"
        ),
        "method": (
            "Unauthenticated read of the Entra OpenID discovery document for each verified domain. "
            "No usernames are probed and getuserrealm-style user lookups are not used."
        ),
    }
