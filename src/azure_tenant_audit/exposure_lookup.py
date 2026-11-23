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
import socket
import threading
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.poolmanager import ProxyManager

from .dns_lookup import safe_resolver_diagnostic

DEFAULT_TIMEOUT_SECONDS = 5.0
# The requests timeout bounds each socket read, not the response: a host that sends a byte every few seconds could
# hold one fetch for days. One fetch therefore stops at this wall-clock deadline (review R163).
DEFAULT_FETCH_DEADLINE_SECONDS = 15.0
_READ_CHUNK_BYTES = 8192
MAX_POLICY_BYTES = 64 * 1024
MAX_POLICY_AGE_SECONDS = 31557600  # RFC 8461 section 3.2: the largest max_age a sender accepts
OIDC_AUTHORITY = "https://login.microsoftonline.com"
_GUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
_MAX_AGE_RE = re.compile(r"[0-9]{1,10}")
# RFC 5321 section 4.1.2 Domain: ASCII letter, digit and hyphen labels. re.ASCII keeps Unicode case folding from
# admitting a Kelvin sign or a dotless i as k or i. The top-level label is alphabetic or an IDNA A-label (xn--).
_DOMAIN_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9](?:[a-z0-9-]{0,57}[a-z0-9])?)",
    re.IGNORECASE | re.ASCII,
)


class HttpsFetcher(Protocol):
    def get_text(self, url: str) -> tuple[int | None, str, str | None]:
        """Return ``(status_code, body, error)``. ``status_code`` is None on transport failure."""
        ...


@dataclass
class RequestsHttpsFetcher:
    """Minimal HTTPS GET helper: no redirects, no credentials, capped body."""

    session: Any = field(default_factory=lambda: _watched_session())
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    deadline: float = DEFAULT_FETCH_DEADLINE_SECONDS
    clock: Callable[[], float] = time.monotonic

    def get_text(self, url: str) -> tuple[int | None, str, str | None]:
        if not url.lower().startswith("https://"):
            return None, "", "refused_non_https_url"
        start = self.clock()
        # identity encoding and a hook that drops any redirect body: requests otherwise reads a redirect body in full
        # (resolve_redirects, even with allow_redirects=False) and urllib3 may loop raw reads inside one decoding read1.
        return self._fetch_within_deadline(
            lambda: self.session.get(url, timeout=self.timeout, allow_redirects=False, stream=True,
                                     headers={"Accept-Encoding": "identity"}, hooks={"response": _drop_redirect_body}),
            start,
        )

    def _fetch_within_deadline(self, request: Callable[[], Any], start: float) -> tuple[int | None, str, str | None]:
        """Run the request and the body read on one daemon thread and wait at most ``deadline`` seconds for them. One
        read can block inside http.client for as long as the host keeps sending (chunked trailer lines, repeated 100
        Continue status lines), so the deadline is held by the wait, not by checks between reads. On expiry the
        response socket is shut down to end a blocked read; the thread then closes the response, and closes a response
        that arrives only after the deadline as soon as it arrives."""
        attempt = _FetchAttempt()
        worker = threading.Thread(target=self._attempt, args=(request, start, attempt), name="auditex-https-fetch",
                                  daemon=True)
        worker.start()
        if attempt.done.wait(max(0.0, self.deadline)) and attempt.result is not None:
            return attempt.result
        attempt.abandon()
        return None, "", "fetch_deadline_exceeded"

    def _attempt(self, request: Callable[[], Any], start: float, attempt: _FetchAttempt) -> None:
        response = None
        close = False
        _WATCH.attempt = attempt
        try:
            response = request()
            if not attempt.adopt(response):
                close = True
                return
            raw = self._read_body(response, start, attempt.abandoned)
            if raw is None or attempt.abandoned.is_set():
                _close_quietly(response)  # before finish, so the caller never sees an open response after the deadline
                attempt.finish((None, "", "fetch_deadline_exceeded"))
                return
            raw = _decode_body(raw, (getattr(response, "headers", None) or {}).get("Content-Encoding"))
            body = raw[:MAX_POLICY_BYTES].decode("utf-8", errors="replace")
            attempt.finish((int(response.status_code), body, None))
        except Exception as exc:  # noqa: BLE001
            close = attempt.abandoned.is_set()
            attempt.finish((None, "", f"{type(exc).__name__}: {exc}"[:300]))
        finally:
            _WATCH.attempt = None
            attempt.release()
            if close and response is not None:
                _close_quietly(response)

    def _read_body(self, response: Any, start: float, stop: threading.Event | None = None) -> bytes | None:
        """At most MAX_POLICY_BYTES + 1 bytes, or None once the deadline passes or the fetch is abandoned."""
        stream = response.raw
        if stream is None:
            return b""
        read = getattr(stream, "read1", None) or stream.read
        chunks: list[bytes] = []
        size = 0
        while size <= MAX_POLICY_BYTES:
            if self.clock() - start > self.deadline or (stop is not None and stop.is_set()):
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


@dataclass
class _FetchAttempt:
    """What the fetch thread and the waiting caller share: the response once it exists, and whether the caller gave up."""

    done: threading.Event = field(default_factory=threading.Event)
    abandoned: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)
    response: Any = None
    result: tuple[int | None, str, str | None] | None = None
    sockets: list[Any] = field(default_factory=list)  # connection sockets this fetch used, shut down on abandon
    owned: list[Any] = field(default_factory=list)  # duplicates of new sockets, closed when the fetch thread ends

    def watch(self, sock: Any, owned: bool = False) -> None:
        """Track a socket the request is using; shut it down at once when the caller has already given up."""
        with self.lock:
            self.sockets.append(sock)
            if owned:
                self.owned.append(sock)
            abandoned = self.abandoned.is_set()
        if abandoned:
            _shutdown_quietly(sock)

    def release(self) -> None:
        """The fetch thread is done: close the duplicates it made and stop tracking its sockets."""
        with self.lock:
            owned, self.owned, self.sockets = self.owned, [], []
        for sock in owned:
            try:
                sock.close()
            except OSError:
                pass

    def adopt(self, response: Any) -> bool:
        """Record the response; False when the caller has already given up, so the thread closes it at once."""
        with self.lock:
            self.response = response
            return not self.abandoned.is_set()

    def finish(self, result: tuple[int | None, str, str | None]) -> None:
        self.result = result
        self.done.set()

    def abandon(self) -> None:
        with self.lock:
            self.abandoned.set()
            response = self.response
            sockets = list(self.sockets)
        for sock in sockets:  # a connect, TLS handshake or header read still in progress
            _shutdown_quietly(sock)
        if response is not None:
            _interrupt_read(response)


# The fetch thread's attempt, so the connections below can report their sockets to it. Before the response exists
# (connect, TLS handshake, status and header lines) no socket is reachable from the caller, and http.client reads
# 100 Continue status lines in a loop with no end, so the request itself can outlive the deadline (review of PR #186).
_WATCH = threading.local()


def _watch_socket(sock: Any, new: bool = False) -> None:
    attempt = getattr(_WATCH, "attempt", None)
    if attempt is None or sock is None:
        return
    if new:
        # A TLS wrap detaches the plain socket object before the handshake, so track a duplicate: shutting it down
        # ends the connection whatever object urllib3 holds by then. The fetch thread closes it when it ends.
        try:
            attempt.watch(sock.dup(), owned=True)
        except OSError:
            pass
    else:
        attempt.watch(sock)


class _WatchedConnectionMixin:
    def _new_conn(self) -> Any:
        sock = super()._new_conn()  # type: ignore[misc]
        _watch_socket(sock, new=True)
        return sock

    def getresponse(self, *args: Any, **kwargs: Any) -> Any:
        _watch_socket(getattr(self, "sock", None))  # a pooled connection reused by this fetch
        return super().getresponse(*args, **kwargs)  # type: ignore[misc]


class _WatchedHTTPConnection(_WatchedConnectionMixin, HTTPConnection):
    pass


class _WatchedHTTPSConnection(_WatchedConnectionMixin, HTTPSConnection):
    pass


class _WatchedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _WatchedHTTPConnection


class _WatchedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _WatchedHTTPSConnection


_WATCHED_POOLS = {"http": _WatchedHTTPConnectionPool, "https": _WatchedHTTPSConnectionPool}


class _WatchedAdapter(HTTPAdapter):
    """An adapter whose connections report their sockets to the running fetch, direct or through an HTTP proxy. A SOCKS
    proxy keeps its own pools, so there the fetch can only be cut short once the response exists."""

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = dict(_WATCHED_POOLS)

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        manager = super().proxy_manager_for(proxy, **proxy_kwargs)
        if type(manager) is ProxyManager:
            manager.pool_classes_by_scheme = dict(_WATCHED_POOLS)
        return manager


def _watched_session() -> requests.Session:
    session = requests.Session()
    adapter = _WatchedAdapter()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _shutdown_quietly(sock: Any) -> None:
    shutdown = getattr(sock, "shutdown", None)
    if callable(shutdown):
        try:
            shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def _response_socket(response: Any) -> Any:
    raw = getattr(response, "raw", None)
    sock = getattr(getattr(raw, "connection", None), "sock", None)
    if sock is None:  # urllib3 already released the connection: reach the socket under http.client's reader
        sock = getattr(getattr(getattr(getattr(raw, "_fp", None), "fp", None), "raw", None), "_sock", None)
    return sock


def _interrupt_read(response: Any) -> None:
    """End a read that blocks on the response socket; the fetch thread sees an error and closes the response."""
    _shutdown_quietly(_response_socket(response))


def _close_quietly(response: Any) -> None:
    close = getattr(response, "close", None)
    if callable(close):
        try:
            close()
        except Exception:  # noqa: BLE001
            pass


def _drop_redirect_body(response: Any, *args: Any, **kwargs: Any) -> Any:
    """Response hook: a redirect is never followed (RFC 8461 section 3.3), so its body is never read."""
    if getattr(response, "is_redirect", False):
        response._content = b""
        response._content_consumed = True
        close = getattr(response, "close", None)
        if callable(close):
            close()
    return response


def _inflate(raw: bytes, wbits: int) -> tuple[bytes, bool]:
    """Decompress one deflate stream, never past MAX_POLICY_BYTES + 1 bytes of output; True when the stream ended
    cleanly (for zlib, with a matching checksum) or the output already passes the cap."""
    decoder = zlib.decompressobj(wbits)
    try:
        out = decoder.decompress(raw, MAX_POLICY_BYTES + 1)
    except zlib.error:
        return b"", False
    return out, decoder.eof or len(out) > MAX_POLICY_BYTES


def _decode_body(raw: bytes, encoding: Any) -> bytes:
    """Decode a gzip or deflate body after the bounded raw read, never past MAX_POLICY_BYTES + 1 bytes of output."""
    name = str(encoding or "").strip().lower()
    if name == "deflate":
        # HTTP deflate is meant to be zlib-wrapped (RFC 9110 section 8.4.1.2) but servers also send raw deflate, and a
        # raw stream can begin with bytes that pass the zlib header check (a stored block starting 08 5b). Try the
        # wrapper first, any window size, and fall back to raw deflate when it does not decode to a whole stream.
        wrapped, ok = _inflate(raw, zlib.MAX_WBITS)
        if ok:
            return wrapped
        bare, ok = _inflate(raw, -zlib.MAX_WBITS)
        return bare if ok or not wrapped else wrapped
    if name not in {"gzip", "x-gzip"}:
        return raw
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = b""
    try:
        while True:
            out += decoder.decompress(raw, MAX_POLICY_BYTES + 1 - len(out))
            # gzip allows several members back to back (RFC 1952 section 2.2); read each, never past the cap
            if len(out) > MAX_POLICY_BYTES or not decoder.eof or not decoder.unused_data:
                return out
            raw = decoder.unused_data
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    except zlib.error:
        return out


def is_safe_domain_name(domain: str) -> bool:
    return isinstance(domain, str) and bool(_DOMAIN_RE.fullmatch(domain))


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
            fields.setdefault(key, value)  # RFC 8461 section 3.2: a repeated field takes its first value
    if str(fields.get("version") or "").lower() != "stsv1":
        return None
    mode = str(fields.get("mode") or "").strip().lower() or None
    # RFC 8461 section 3.2: max_age is 1 to 10 ASCII digits; int() would also take "+86400", "86_400" or other digits.
    raw_max_age = fields.get("max_age")
    max_age = int(raw_max_age) if isinstance(raw_max_age, str) and _MAX_AGE_RE.fullmatch(raw_max_age) else None
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
        return {"url": url, "fetch_status": "unreachable", "http_status": None,
                "error": safe_resolver_diagnostic(error) if error else error}
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
    a missing or out-of-range max_age, no mx line in enforce or testing mode, or there an mx value that is not a host
    name or a "*." wildcard host pattern. Empty when the policy is valid."""
    reasons = []
    if not parsed.get("mode_valid"):
        reasons.append("mode_invalid")
    max_age = parsed.get("max_age")
    if not isinstance(max_age, int) or not 0 <= max_age <= MAX_POLICY_AGE_SECONDS:
        reasons.append("max_age_invalid")
    if parsed.get("mode") in {"enforce", "testing"}:
        values = [str(mx).strip() for mx in parsed.get("mx") or []]
        if not any(values):
            reasons.append("mx_missing")
        elif not all(is_safe_domain_name(v[2:] if v.startswith("*.") else v) for v in values):
            reasons.append("mx_invalid")
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
        return {"url": url, "discovery_status": "unreachable", "error": safe_resolver_diagnostic(error) if error else error}
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
