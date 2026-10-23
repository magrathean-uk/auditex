from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


SYNC_SAMPLE_LIMIT = 100


class DomainsHybridCollector(Collector):
    name = "domains_hybrid"
    description = "Domain posture and sampled hybrid sync signals."
    required_permissions = [
        "Directory.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            {
                "organization": {"endpoint": "/organization", "params": {}, "page": False},
                "domains": {"endpoint": "/domains", "params": {"$select": "id,isDefault,isVerified,authenticationType,supportedServices"}},
                "syncSampleUsers": {
                    "endpoint": "/users",
                    "params": {
                        "$select": "id,userPrincipalName,onPremisesSyncEnabled,onPremisesImmutableId,onPremisesDomainName,onPremisesLastSyncDateTime"
                    },
                    # A sample by design: hybrid sync is judged from the first users, so this bound is not a gap.
                    "sample_limit": SYNC_SAMPLE_LIMIT,
                },
            },
            top=context.get("top"),
            page_size=context.get("page_size"),
            chunk_writer=context.get("chunk_writer"),
            log_event=context.get("audit_logger"),
        )
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Domains and hybrid collector partially completed" if partial else "",
            coverage=coverage,
        )
