from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from ..perf_runtime import EndpointAccumulator
from ._endpoint_reads import input_rows
from .base import Collector, CollectorResult, run_graph_endpoints

# Rows per chunk file of a derived site list that is streamed to disk.
DERIVED_CHUNK_ROWS = 500


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

    def _derived_section(self, name: str, rows: list[dict[str, Any]], chunk_writer: Any) -> dict[str, Any]:
        """A site list derived from ``sites``: inline when the source was kept whole, chunked when it was streamed."""
        if chunk_writer is None or not rows:
            return {"value": rows}
        accumulator = EndpointAccumulator(sample_limit=20)
        for page_number, start in enumerate(range(0, len(rows), DERIVED_CHUNK_ROWS), start=1):
            page = rows[start : start + DERIVED_CHUNK_ROWS]
            path = chunk_writer(self.name, name, page_number, page, {"derived_from": "sites", "page_number": page_number})
            accumulator.add_page(page, chunk_file=path)
        return accumulator.payload()

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
        sites_section = payload.get("sites") if isinstance(payload.get("sites"), dict) else {}
        # A live run streams the site list to chunk files and keeps only a 20-row sample inline: the kinds, the counts and
        # the OneDrive finding must cover every site that was read, so the rows come from the chunk-aware reader.
        chunked = bool(sites_section.get("chunk_files"))
        sites, read_issues, _failed, _cut = input_rows(sites_section, context.get("run_dir")) if chunked else ([], [], False, False)
        if not chunked or (read_issues and not sites):
            sites = sites_section.get("value", [])
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
            # /sites carries no sharing setting of its own, so a site gets the tenant value and says so:
            # a copied value is the tenant's single setting, not evidence about the site. A value a site
            # already carries (an offline export) is kept and marked as the site's own.
            if enriched_site.get("sharingCapability") not in (None, ""):
                enriched_site["sharingCapabilitySource"] = "site"
            elif sharing_capability is not None:
                enriched_site["sharingCapability"] = sharing_capability
                enriched_site["sharingCapabilitySource"] = "tenant"
            enriched_sites.append(enriched_site)

        if isinstance(payload.get("sites"), dict):
            inline = payload["sites"].get("value")
            payload["sites"]["value"] = enriched_sites[: len(inline)] if chunked and isinstance(inline, list) else enriched_sites
        else:
            payload["sites"] = {"value": enriched_sites}

        chunk_writer = context.get("chunk_writer")
        for name, rows in (
            ("oneDriveSites", [item for item in enriched_sites if item.get("siteKind") == "personal"]),
            ("teamSites", [item for item in enriched_sites if item.get("siteKind") != "personal"]),
        ):
            payload[name] = self._derived_section(name, rows, chunk_writer if chunked else None)
            if read_issues:
                payload[name].update(
                    {"error": "The site list could not be read in full.", "error_class": "incomplete_evidence"}
                )
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
