from __future__ import annotations

import time
from typing import Any

from ..collection_gaps import FANOUT_OBJECT_LIMIT, fanout_gap_row, section_total
from ..graph import GraphClient, GraphError
from ..normalize import _iter_permission_targets
from .base import Collector, CollectorResult, _classify_graph_error, run_graph_endpoints


def _site_kind_from_web_url(web_url: Any) -> str:
    url = str(web_url or "").lower()
    if "-my.sharepoint.com" in url:
        return "personal"
    if "/sites/" in url or "/teams/" in url:
        return "team"
    return "other"


def _summarize_permissions(permissions: list[dict[str, Any]]) -> dict[str, Any]:
    user_targets: set[str] = set()
    group_targets: set[str] = set()
    application_targets: set[str] = set()
    link_permission_count = 0
    anonymous_link_count = 0
    organization_link_count = 0
    write_like_permission_count = 0

    for permission in permissions:
        if not isinstance(permission, dict):
            continue

        roles = [str(role).lower() for role in permission.get("roles", []) if role is not None]
        if any(role not in {"read", "view"} for role in roles):
            write_like_permission_count += 1

        link = permission.get("link") if isinstance(permission.get("link"), dict) else {}
        link_scope = str(link.get("scope") or "").lower()
        if link_scope:
            link_permission_count += 1
            if link_scope == "anonymous":
                anonymous_link_count += 1
            elif link_scope == "organization":
                organization_link_count += 1

        for target_type, target in _iter_permission_targets(permission):
            target_id = str(target.get("id") or target.get("userPrincipalName") or target.get("displayName") or "")
            if not target_id:
                continue
            if target_type == "user":
                user_targets.add(target_id)
            elif target_type == "group":
                group_targets.add(target_id)
            elif target_type == "application":
                application_targets.add(target_id)

    principal_count = len(user_targets | group_targets | application_targets)
    if permissions:
        if principal_count == 0:
            ownership_state = "orphaned"
        elif principal_count <= 1:
            ownership_state = "weak"
        else:
            ownership_state = "sampled"
    else:
        ownership_state = "unknown"

    return {
        "permissionCount": len(permissions),
        "principalCount": principal_count,
        "userPrincipalCount": len(user_targets),
        "groupPrincipalCount": len(group_targets),
        "applicationPrincipalCount": len(application_targets),
        "linkPermissionCount": link_permission_count,
        "anonymousLinkCount": anonymous_link_count,
        "organizationLinkCount": organization_link_count,
        "writeLikePermissionCount": write_like_permission_count,
        "ownershipState": ownership_state,
    }


class SharePointAccessCollector(Collector):
    name = "sharepoint_access"
    description = "SharePoint and OneDrive sharing posture plus sampled site permission inventory."
    required_permissions = [
        "Sites.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top")
        page_size = context.get("page_size")
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            {
                "sharePointSettings": {
                    "endpoint": "/admin/sharepoint/settings",
                    "page": False,
                    "params": {},
                },
                "sites": {
                    "endpoint": "/sites",
                    "params": {
                        "$select": "id,name,displayName,webUrl,createdDateTime",
                    },
                },
            },
            top=top,
            page_size=page_size,
            chunk_writer=context.get("chunk_writer"),
            log_event=context.get("audit_logger"),
        )

        site_rows = payload.get("sites", {}).get("value", [])
        if not isinstance(site_rows, list):
            site_rows = []
        sharepoint_settings = payload.get("sharePointSettings", {}) if isinstance(payload.get("sharePointSettings"), dict) else {}
        sharing_capability = sharepoint_settings.get("sharingCapability")

        sampled_permissions: list[dict[str, Any]] = []
        fanout_specs: list[dict[str, Any]] = []
        for site in site_rows[:FANOUT_OBJECT_LIMIT]:
            site_id = site.get("id")
            if not isinstance(site_id, str) or not site_id:
                continue
            fanout_specs.append(
                {
                    "site": site,
                    "site_id": site_id,
                    "endpoint": f"/sites/{site_id}/permissions",
                }
            )

        batch_results: list[dict[str, Any]] | None = None
        if fanout_specs and hasattr(client, "get_batch"):
            batch_start = time.perf_counter()
            try:
                batch_results = client.get_batch(
                    [
                        {
                            "path": spec["endpoint"],
                            "params": {"$top": "50"},
                        }
                        for spec in fanout_specs
                    ]
                )
            except Exception:  # noqa: BLE001
                batch_results = None

        if batch_results is not None and len(batch_results) == len(fanout_specs):
            for spec, result in zip(fanout_specs, batch_results):
                endpoint = spec["endpoint"]
                site = spec["site"]
                site_id = spec["site_id"]
                status = result.get("status") if isinstance(result, dict) else None
                body = result.get("body") if isinstance(result, dict) else None
                if status == 200 and isinstance(body, dict):
                    permissions = body.get("value", [])
                    if not isinstance(permissions, list):
                        permissions = []
                    next_link = body.get("@odata.nextLink")
                    if isinstance(next_link, str) and next_link:
                        permissions = permissions + list(client.iter_items(next_link))
                    summary = _summarize_permissions(permissions)
                    sampled_permissions.append(
                        {
                            "siteId": site_id,
                            "siteName": site.get("displayName") or site.get("name"),
                            "webUrl": site.get("webUrl"),
                            "siteKind": _site_kind_from_web_url(site.get("webUrl")),
                            "sharingCapability": sharing_capability,
                            "permissions": permissions,
                            **summary,
                        }
                    )
                    coverage.append(
                        {
                            "collector": self.name,
                            "type": "graph",
                            "name": "sitePermissions",
                            "endpoint": endpoint,
                            "site_id": site_id,
                            "status": "ok",
                            "item_count": len(permissions),
                            "duration_ms": round((time.perf_counter() - batch_start) * 1000, 2),
                            "error_class": None,
                            "error": None,
                        }
                    )
                    continue

                error_code = result.get("error_code") if isinstance(result, dict) else None
                error_message = result.get("error") if isinstance(result, dict) else None
                if isinstance(body, dict):
                    error = body.get("error")
                    if isinstance(error, dict):
                        error_code = error_code or error.get("code")
                        error_message = error_message or error.get("message")
                    elif isinstance(error, str):
                        error_message = error_message or error
                error_exc = GraphError(
                    str(error_message or "Graph batch request failed."),
                    status=status if isinstance(status, int) else None,
                    request=endpoint,
                    error_code=error_code if isinstance(error_code, str) else None,
                )
                error_class, error = _classify_graph_error(error_exc)
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "graph",
                        "name": "sitePermissions",
                        "endpoint": endpoint,
                        "site_id": site_id,
                        "status": "failed",
                        "item_count": 0,
                        "duration_ms": round((time.perf_counter() - batch_start) * 1000, 2),
                        "error_class": error_class,
                        "error": error,
                    }
                )
        else:
            for site in site_rows[:FANOUT_OBJECT_LIMIT]:
                site_id = site.get("id")
                if not isinstance(site_id, str) or not site_id:
                    continue
                endpoint = f"/sites/{site_id}/permissions"
                start = time.perf_counter()
                try:
                    permissions = client.get_all(endpoint, params={"$top": "50"})
                    if not isinstance(permissions, list):
                        permissions = []
                    summary = _summarize_permissions(permissions)
                    sampled_permissions.append(
                        {
                            "siteId": site_id,
                            "siteName": site.get("displayName") or site.get("name"),
                            "webUrl": site.get("webUrl"),
                            "siteKind": _site_kind_from_web_url(site.get("webUrl")),
                            "sharingCapability": sharing_capability,
                            "permissions": permissions,
                            **summary,
                        }
                    )
                    coverage.append(
                        {
                            "collector": self.name,
                            "type": "graph",
                            "name": "sitePermissions",
                            "endpoint": endpoint,
                            "site_id": site_id,
                            "status": "ok",
                            "item_count": len(permissions),
                            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                            "error_class": None,
                            "error": None,
                        }
                    )
                except Exception as exc:  # noqa: BLE001
                    error_class, error = _classify_graph_error(exc)
                    coverage.append(
                        {
                            "collector": self.name,
                            "type": "graph",
                            "name": "sitePermissions",
                            "endpoint": endpoint,
                            "site_id": site_id,
                            "status": "failed",
                            "item_count": 0,
                            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                            "error_class": error_class,
                            "error": error,
                        }
                    )

        site_total = section_total(payload.get("sites"), site_rows)
        if site_total > FANOUT_OBJECT_LIMIT:
            # Orphaned and weak-ownership findings read these permissions, so the rest of the sites are a gap.
            coverage.append(
                fanout_gap_row(self.name, "sitePermissionsFanout", total=site_total, expanded=FANOUT_OBJECT_LIMIT, scope="Site permissions")
            )
        payload["sitePermissionsBySite"] = {"value": sampled_permissions}
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="SharePoint access collector partially completed" if partial else "",
            coverage=coverage,
        )
