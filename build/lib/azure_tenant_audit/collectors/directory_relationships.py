"""Read-only, bounded security-group links and application-registration owners."""
from __future__ import annotations

from itertools import islice
import time
from typing import Any
from uuid import UUID

from ..collection_gaps import REASON_FANOUT_LIMIT, REASON_OPERATOR_LIMIT, sampling
from ..graph import GraphError
from .base import Collector, CollectorResult, _classify_graph_error, context_limit


DIRECTORY_FANOUT_LIMIT = 100
RELATIONSHIP_ROW_LIMIT = 5000


class DirectoryRelationshipsCollector(Collector):
    name = "directory_relationships"
    description = "Security-group membership and ownership, and application-registration ownership."
    required_permissions = ["Directory.Read.All", "Group.Read.All", "Application.Read.All"]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context["client"]
        coverage: list[dict[str, Any]] = []
        requested = context_limit(context, default=500)
        parent_limit = min(requested if requested is not None else DIRECTORY_FANOUT_LIMIT, DIRECTORY_FANOUT_LIMIT)
        relation_limit = min(requested if requested is not None else RELATIONSHIP_ROW_LIMIT, RELATIONSHIP_ROW_LIMIT)
        page_size = max(1, min(int(context.get("page_size") or 100), 999))

        def fetch(name: str, path: str, params: dict[str, str], limit: int) -> list[dict[str, Any]] | None:
            started = time.perf_counter()
            row = {"collector": self.name, "type": "graph", "name": name, "endpoint": path,
                   "api_version": "v1.0", "status": "ok", "item_count": 0, "result_limit": limit,
                   "error_class": None, "error": None}
            try:
                query = {"$top": str(min(page_size, limit + 1)), **params}
                if hasattr(client, "iter_items"):
                    values = list(islice(client.iter_items(path, params=query), limit + 1))
                else:
                    values = client.get_all(path, params=query)
                if not isinstance(values, list) or any(not isinstance(value, dict) or not value.get("id") for value in values):
                    raise GraphError("Malformed directory relationship response", request=path)
                if len(values) > limit and sampling():
                    # A probe reads a few rows to test access; that is a sample, not a gap.
                    row.update(bounded_sample=True, collection_truncated=False)
                elif len(values) > limit:
                    # The operator's limit when it is what bound this read; otherwise the collector's own fan-out bound.
                    reason = REASON_OPERATOR_LIMIT if requested is not None and limit == requested else REASON_FANOUT_LIMIT
                    row.update(status="partial", error_class="collection_limit", error="Directory relationship collection limit reached.", collection_truncated=True, truncation_reason=reason)
                values = values[:limit]
                row["item_count"] = len(values)
                return values
            except Exception as error:  # noqa: BLE001
                error_class, message = _classify_graph_error(error)
                row.update(status="failed", error_class=error_class, error=message)
                return None
            finally:
                row["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
                coverage.append(row)

        groups = fetch("relationshipGroups", "/groups", {
            "$select": "id,displayName,isAssignableToRole", "$filter": "securityEnabled eq true",
        }, parent_limit)
        applications = fetch("relationshipApplications", "/applications", {
            "$select": "id,displayName,appId,signInAudience",
        }, parent_limit)
        edges, observations = [], []
        for kind, parents in (("group", groups), ("application", applications)):
            collection = "groups" if kind == "group" else "applications"
            for parent in parents or []:
                # A directory-provided ID must never become an arbitrary URL/path.
                try:
                    parent_id = str(UUID(parent["id"]))
                except (ValueError, TypeError, AttributeError):
                    coverage.append({"collector": self.name, "type": "graph", "name": "relationshipParent",
                                     "endpoint": f"/{collection}", "status": "failed", "item_count": 0,
                                     "error_class": "invalid_object_id", "error": "Invalid directory object UUID."})
                    continue
                for relation in (("members", "owners") if kind == "group" else ("owners",)):
                    path = f"/{collection}/{parent_id}/{relation}"
                    values = fetch(f"{kind}{relation.title()}", path, {"$select": "id,displayName"}, relation_limit)
                    observations.append({"parentId": parent_id, "parentType": kind, "relation": relation,
                                         "status": coverage[-1]["status"], "count": len(values) if values is not None else None})
                    for value in values or []:
                        edges.append({"parentId": parent_id, "parentType": kind,
                                      "parentDisplayName": parent.get("displayName"), "parentAppId": parent.get("appId"),
                                      "relation": relation, "objectId": value["id"],
                                      "objectType": value.get("@odata.type"), "displayName": value.get("displayName")})
        partial = any(row["status"] != "ok" for row in coverage)
        return CollectorResult(name=self.name, status="partial" if partial else "ok", item_count=len(edges),
                               message="Directory relationship coverage is partial" if partial else "",
                               payload={"directoryRelationships": {"value": edges},
                                        "relationshipCoverage": {"value": observations}}, coverage=coverage)
