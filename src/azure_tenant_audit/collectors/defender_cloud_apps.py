"""Capability-gated collector for Microsoft Defender for Cloud Apps (CASB) adjacent posture.

Microsoft Graph has no documented REST endpoint for Defender for Cloud Apps app
risk profiles (the former ``/security/cloudAppSecurityProfiles`` call returned
nothing usable and is not in the Graph reference), so this collector only reads
documented Graph surfaces: pending end-user app consent requests. CASB app risk
scores remain a portal-only review item.
"""
from __future__ import annotations

from typing import Any

from ._capability_gated import build_collector_result, run_capability_gated_endpoints
from .base import Collector


class DefenderCloudAppsCollector(Collector):
    name = "defender_cloud_apps"
    description = (
        "OAuth app consent request inventory via documented Graph endpoints. Defender for Cloud Apps "
        "app risk profiles have no Graph REST endpoint and are not collected; review them in the "
        "Defender portal. Capability-gated."
    )
    required_permissions = [
        "ConsentRequest.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> Any:
        payload, coverage = run_capability_gated_endpoints(
            self.name,
            context.get("client"),
            [
                ("appConsentRequests", "/identityGovernance/appConsent/appConsentRequests"),
            ],
            log_event=context.get("audit_logger"),
            skip_reason="no Graph client; app consent request inventory unavailable",
        )
        return build_collector_result(
            self,
            payload,
            coverage,
            partial_message="Defender for Cloud Apps collection partial; check capability matrix",
        )
