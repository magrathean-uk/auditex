"""Collector for DNS / email-auth posture (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI).

Besides DNS-over-HTTPS lookups, the live collector performs two unauthenticated
HTTPS reads per verified tenant domain (see ``exposure_lookup``): the MTA-STS
policy file when the ``_mta-sts`` TXT record exists, and the public Entra OpenID
discovery document ("public footprint"). Both are read-only, never probe users,
and never run in offline mode because offline runs do not execute collectors.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from typing import Any

from ..collection_gaps import REASON_FANOUT_LIMIT, TRUNCATION_ERROR_CLASS
from ..dns_lookup import (
    DEFAULT_DOH_ENDPOINT,
    CachingResolver,
    DnsResolver,
    DohClient,
    DohError,
    collect_domain_posture,
    scuba_dkim_record,
    scuba_dmarc_record,
    scuba_spf_record,
    unknown_posture,
)
from ..exchange_protection import domain_text
from ..exposure_lookup import (
    HttpsFetcher,
    RequestsHttpsFetcher,
    fetch_mta_sts_policy,
    fetch_tenant_discovery,
)
from ..graph import GraphClient, GraphError
from .base import Collector, CollectorResult, _classify_graph_error

DEFAULT_DKIM_SELECTORS = ("selector1", "selector2")
# Probed only when DEFAULT_DKIM_SELECTORS all miss. Covers common non-M365 origins
# (Google Workspace ``google``; SendGrid/Mailchimp/MailerLite ``s1``/``s2``;
# manual rotations ``k1``; legacy ``default``/``mail``).
FALLBACK_DKIM_SELECTORS = ("s1", "s2", "google", "default", "k1", "mail")
# Upper bound on per-domain public HTTPS lookups so very large domain estates stay cheap.
MAX_PUBLIC_LOOKUP_DOMAINS = 25
# Bound only the new raw-record fanout; the existing posture loop is unchanged.
MAX_RECORD_DOMAINS = 200


def _policy_fetch_failed(policy: dict[str, Any]) -> bool:
    """Whether the MTA-STS policy read itself failed: no answer at all, or a throttling or server error status.

    A 404 or an unparseable file is an answer (the policy is not served, or is invalid) and stays a finding.
    """
    if policy.get("fetch_status") == "unreachable":
        return True
    status = policy.get("http_status")
    return policy.get("fetch_status") == "http_error" and isinstance(status, int) and (status == 429 or status >= 500)


class DnsPostureCollector(Collector):
    name = "dns_posture"
    description = (
        "DNS / email-authentication posture (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI) and the public "
        "tenant discovery footprint for verified tenant domains."
    )
    required_permissions = ["Directory.Read.All"]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient | None = context.get("client")
        log_event: Callable[[str, str, dict[str, Any] | None], None] | None = context.get("audit_logger")
        resolver = CachingResolver(
            context.get("dns_resolver") or DohClient(
                endpoint=context.get("doh_endpoint", DEFAULT_DOH_ENDPOINT)
            )
        )
        dkim_selectors: Iterable[str] = context.get("dkim_selectors", DEFAULT_DKIM_SELECTORS)
        dkim_fallback_selectors: Iterable[str] = context.get(
            "dkim_fallback_selectors", FALLBACK_DKIM_SELECTORS
        )

        # Public HTTPS lookups use an injected fetcher when provided. When a caller injects
        # its own DNS resolver but no fetcher (unit tests, embedded use), HTTPS lookups are
        # skipped so the collector never reaches the network behind the caller's back.
        https_fetcher: HttpsFetcher | None = context.get("https_fetcher")
        if https_fetcher is None and context.get("dns_resolver") is None and context.get("public_lookups", True):
            https_fetcher = RequestsHttpsFetcher()
        if not context.get("public_lookups", True):
            https_fetcher = None

        coverage: list[dict[str, Any]] = []
        payload: dict[str, Any] = {}
        domains_payload: list[dict[str, Any]] = []
        domains_status = "ok"
        domains_error_class: str | None = None
        domains_error: str | None = None

        start = time.perf_counter()
        try:
            domains_payload = list(self._fetch_domains(client))
        except Exception as exc:  # noqa: BLE001
            domains_status = "failed"
            domains_error_class, domains_error = _classify_graph_error(exc)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        coverage.append(
            {
                "collector": self.name,
                "type": "graph",
                "name": "domains",
                "endpoint": "/domains",
                "status": domains_status,
                "item_count": len(domains_payload),
                "duration_ms": duration_ms,
                "error_class": domains_error_class,
                "error": domains_error,
            }
        )
        if log_event:
            log_event(
                "collector.endpoint.finished",
                "Collector endpoint request completed",
                {
                    "collector": self.name,
                    "endpoint_name": "domains",
                    "status": domains_status,
                    "item_count": len(domains_payload),
                    "duration_ms": duration_ms,
                    "error_class": domains_error_class,
                },
            )

        verified_domains = [
            entry for entry in domains_payload if isinstance(entry, dict) and entry.get("isVerified")
        ]

        assessments: list[dict[str, Any]] = []
        for entry in verified_domains:
            domain_name = str(entry.get("id") or "").strip()
            if not domain_name:
                continue
            domain_start = time.perf_counter()
            try:
                posture = collect_domain_posture(
                    domain_name,
                    resolver,
                    dkim_selectors=dkim_selectors,
                    dkim_fallback_selectors=dkim_fallback_selectors,
                )
                status = "ok"
                error_class: str | None = None
                error: str | None = None
                if posture.get("resolver_error"):
                    # collect_domain_posture reports a resolver that did not answer on the record; the coverage row says
                    # so too, which makes the collector partial and raises a diagnostic with the resolver error.
                    status = "failed"
                    error_class = "dns_resolver_error"
                    error = str(posture["resolver_error"])
            except DohError as exc:
                attempted_selectors = list(dkim_selectors) + [
                    s for s in dkim_fallback_selectors if s not in dkim_selectors
                ]
                posture = {
                    "domain": domain_name,
                    "managed_by_microsoft": domain_name.lower().endswith(".onmicrosoft.com"),
                    "resolver_error": str(exc),
                    **unknown_posture(attempted_selectors),
                }
                status = "failed"
                error_class = "dns_resolver_error"
                error = str(exc)
            if (
                https_fetcher is not None
                and status == "ok"
                and (posture.get("mta_sts") or {}).get("dns_present")
                and not posture.get("managed_by_microsoft")
            ):
                policy = fetch_mta_sts_policy(domain_name, https_fetcher)
                posture["mta_sts"]["policy"] = policy
                if _policy_fetch_failed(policy):
                    # The policy file could not be read (no answer, or a server error): whatever the findings say about
                    # it, the read did not succeed, so its row fails and the collector is partial.
                    status = "failed"
                    error_class = "public_lookup_error"
                    error = str(policy.get("error") or f"mta-sts policy fetch {policy.get('fetch_status')}")
            posture.setdefault("isDefault", entry.get("isDefault"))
            posture.setdefault("authentication_type", entry.get("authenticationType"))
            assessments.append(posture)
            domain_duration_ms = round((time.perf_counter() - domain_start) * 1000, 2)
            coverage.append(
                {
                    "collector": self.name,
                    "type": "dns",
                    "name": f"posture:{domain_name}",
                    "endpoint": f"doh://{domain_name}",
                    "status": status,
                    "item_count": 1,
                    "duration_ms": domain_duration_ms,
                    "error_class": error_class,
                    "error": error,
                }
            )

        record_coverage: list[dict[str, Any]] = []
        records = self._scuba_records(
            verified_domains, resolver, record_coverage, domains_status, domains_error_class, domains_error,
            accepted_domains=context.get("exchange_accepted_domains"),
        )
        payload["domains"] = {"value": domains_payload}
        payload["domainPosture"] = {"value": assessments}
        if https_fetcher is not None and verified_domains:
            payload["publicFootprint"] = {
                "value": self._public_footprint(verified_domains, https_fetcher, coverage)
            }

        # Append after existing payload and coverage entries, including public HTTPS reads.
        payload.update(records)
        coverage.extend(record_coverage)
        partial = any(row.get("status") != "ok" for row in coverage)
        message = "DNS posture collection partially completed" if partial else ""
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=sum(int(row.get("item_count") or 0) for row in coverage),
            message=message,
            coverage=coverage,
        )

    def _scuba_records(
        self,
        verified_domains: list[dict[str, Any]],
        resolver: DnsResolver,
        coverage: list[dict[str, Any]],
        domains_status: str,
        domains_error_class: str | None,
        domains_error: str | None,
        *,
        accepted_domains: Any = None,
    ) -> dict[str, Any]:
        """Save bounded records for accepted domains, or the Graph mail-domain fallback.

        Deliberately fail closed on resolver errors, unlike ScubaGear's error-to-empty
        record behaviour: stop that operation, retain its prior rows, and try the others.
        """
        domains = self._accepted_record_domains(accepted_domains)
        universe = "accepted_domains"
        if domains is None:
            universe = "graph_email_service"
            # Preserve the original Graph-only filter, including absent/malformed
            # supportedServices, domain spelling and ordering.
            domains = [
                str(entry.get("id") or "").strip() for entry in verified_domains
                if not isinstance(entry.get("supportedServices"), list)
                or any(isinstance(service, str) and service.casefold() == "email"
                       for service in entry["supportedServices"])
            ]
            domains = [domain for domain in domains if domain]
        cut = len(domains) > MAX_RECORD_DOMAINS
        payload = {}
        for operation, kind, lookup in (
            ("spf_records", "spf", scuba_spf_record),
            ("dkim_records", "dkim", scuba_dkim_record),
            ("dmarc_records", "dmarc", scuba_dmarc_record),
        ):
            start = time.perf_counter()
            rows = []
            status = "ok"
            error_class = error = None
            if domains_status != "ok":
                status, error_class, error = "failed", domains_error_class, domains_error
            else:
                try:
                    for domain in domains[:MAX_RECORD_DOMAINS]:
                        record = lookup(domain, resolver)
                        if record is not None:
                            rows.append(record)
                except DohError as exc:
                    status, error_class, error = "failed", "dns_resolver_error", str(exc)
            envelope: dict[str, Any] = {"value": rows, "status": status}
            row = {
                "collector": self.name, "type": "dns", "name": operation,
                "endpoint": f"doh://records/{kind}", "status": status,
                "item_count": len(rows),
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                "error_class": error_class, "error": error,
                "domain_universe": universe,
            }
            if status == "failed":
                envelope.update(error_class=error_class, error=error)
            if cut and domains_status == "ok":
                truncation = {
                    "collection_truncated": True, "truncation_reason": REASON_FANOUT_LIMIT,
                    "result_limit": MAX_RECORD_DOMAINS, "rows_collected": len(rows),
                }
                envelope.update(truncation)
                row.update(truncation)
                if status == "ok":
                    row.update(
                        status="partial", error_class=TRUNCATION_ERROR_CLASS,
                        error=f"{operation}: collection stopped at {MAX_RECORD_DOMAINS} domains; the list is incomplete.",
                    )
            payload[operation] = envelope
            coverage.append(row)
        return payload

    @staticmethod
    def _accepted_record_domains(envelope: Any) -> list[str] | None:
        """Use only complete, usable same-run evidence; None requests the Graph fallback.

        The adapter's successful command envelopes need not carry a status. Older
        envelopes without the coexistence flag cannot safely exclude that domain.
        Reject an unusable list as a whole rather than silently dropping its rows.
        Every tenant has its initial accepted domain, so an empty list is unusable.
        """
        if (
            not isinstance(envelope, dict)
            or envelope.get("status") not in (None, "ok")
            or envelope.get("error")
            or envelope.get("error_class")
            or envelope.get("collection_truncated")
            or not isinstance(envelope.get("value"), list)
            or not envelope["value"]
        ):
            return None
        domains: dict[str, str] = {}
        for row in envelope["value"]:
            if not isinstance(row, dict) or not isinstance(row.get("IsCoexistenceDomain"), bool):
                return None
            name = domain_text(row.get("DomainName"))
            if name is None:
                return None
            if not row["IsCoexistenceDomain"]:
                # Preserve Exchange's spelling for the case-sensitive DKIM config join.
                domains.setdefault(name.casefold(), name)
        return list(domains.values())

    def _public_footprint(
        self,
        verified_domains: list[dict[str, Any]],
        fetcher: HttpsFetcher,
        coverage: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Record what an outsider can learn about each verified domain without credentials."""
        rows: list[dict[str, Any]] = []
        for entry in verified_domains[:MAX_PUBLIC_LOOKUP_DOMAINS]:
            domain_name = str(entry.get("id") or "").strip()
            if not domain_name:
                continue
            start = time.perf_counter()
            discovery = fetch_tenant_discovery(domain_name, fetcher)
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            lookup_failed = discovery.get("discovery_status") in {"unreachable", "http_error", "invalid_document"}
            rows.append(
                {
                    "domain": domain_name,
                    "authentication_type": entry.get("authenticationType"),
                    "is_default": entry.get("isDefault"),
                    **discovery,
                }
            )
            coverage.append(
                {
                    "collector": self.name,
                    "type": "https",
                    "name": f"public_footprint:{domain_name}",
                    "endpoint": discovery.get("url"),
                    "status": "failed" if lookup_failed else "ok",
                    "item_count": 1,
                    "duration_ms": duration_ms,
                    "error_class": "public_lookup_error" if lookup_failed else None,
                    "error": discovery.get("error") or (discovery.get("discovery_status") if lookup_failed else None),
                }
            )
        return rows

    @staticmethod
    def _fetch_domains(client: GraphClient | None) -> list[dict[str, Any]]:
        if client is None:
            raise GraphError("graph client unavailable", request="/domains")
        params = {"$select": "id,authenticationType,isDefault,isVerified,isRoot,supportedServices"}
        if hasattr(client, "get_all"):
            payload = client.get_all("/domains", params=params)
            if isinstance(payload, list):
                return [item for item in payload if isinstance(item, dict)]
            if isinstance(payload, dict):
                values = payload.get("value")
                if isinstance(values, list):
                    return [item for item in values if isinstance(item, dict)]
        if hasattr(client, "get_json"):
            payload = client.get_json("/domains", params=params)
            if isinstance(payload, dict):
                values = payload.get("value")
                if isinstance(values, list):
                    return [item for item in values if isinstance(item, dict)]
        raise GraphError("graph client missing get_all/get_json", request="/domains")
