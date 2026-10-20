from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


def _site_kind_from_web_url(web_url: Any) -> str:
    url = str(web_url or "").lower()
    if "-my.sharepoint.com" in url:
        return "personal"
    if "/sites/" in url or "/teams/" in url:
        return "team"
    return "other"


class OneDrivePostureCollector(Collector):
    name = "onedrive_posture"
    description = "OneDrive sharing posture and sampled personal site inventory."
    required_permissions = [
        "Sites.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            {
                "sharePointSettings": {"endpoint": "/admin/sharepoint/settings", "page": False, "params": {}},
                "sites": {"endpoint": "/sites", "params": {"$select": "id,displayName,name,webUrl,createdDateTime"}},
            },
            top=context.get("top"),
            page_size=context.get("page_size"),
            chunk_writer=context.get("chunk_writer"),
            log_event=context.get("audit_logger"),
        )
        sites = payload.get("sites", {}).get("value", [])
        if not isinstance(sites, list):
            sites = []
        sharepoint_settings = payload.get("sharePointSettings", {}) if isinstance(payload.get("sharePointSettings"), dict) else {}
        sharing_capability = sharepoint_settings.get("sharingCapability")
        enriched_sites: list[dict[str, Any]] = []
        for site in sites:
            if not isinstance(site, dict):
                continue
            enriched_site = dict(site)
            enriched_site["siteKind"] = _site_kind_from_web_url(enriched_site.get("webUrl"))
            if sharing_capability is not None:
                enriched_site["sharingCapability"] = sharing_capability
            enriched_sites.append(enriched_site)

        if isinstance(payload.get("sites"), dict):
            payload["sites"]["value"] = enriched_sites
        else:
            payload["sites"] = {"value": enriched_sites}

        payload["oneDriveSites"] = {
            "value": [item for item in enriched_sites if item.get("siteKind") == "personal"]
        }
        payload["teamSites"] = {"value": [item for item in enriched_sites if item.get("siteKind") != "personal"]}
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="OneDrive posture collector partially completed" if partial else "",
            coverage=coverage,
        )
