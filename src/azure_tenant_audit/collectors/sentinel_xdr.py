"""Capability-gated collector for Microsoft Sentinel / unified XDR via Graph."""
from __future__ import annotations

from typing import Any

from ._capability_gated import build_collector_result, run_capability_gated_endpoints
from .base import Collector


class SentinelXdrCollector(Collector):
    name = "sentinel_xdr"
    description = (
        "Microsoft Sentinel / unified XDR posture via Graph: incidents and alerts. "
        "Capability-gated; returns structured diagnostics when the service is not licensed."
    )
    required_permissions = [
        "SecurityIncident.Read.All",
        "SecurityAlert.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> Any:
        payload, coverage = run_capability_gated_endpoints(
            self.name,
            context.get("client"),
            [
                ("xdrIncidents", "/security/incidents"),
                ("xdrAlerts", "/security/alerts_v2"),
            ],
            log_event=context.get("audit_logger"),
            skip_reason="no Graph client; Sentinel/XDR likely not provisioned",
        )
        return build_collector_result(
            self,
            payload,
            coverage,
            partial_message="Sentinel/XDR collection partial; check capability matrix",
        )
