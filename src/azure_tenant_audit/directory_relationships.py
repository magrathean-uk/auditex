"""Normalize explicit directory relationship observations and coverage."""
from __future__ import annotations

from typing import Any


def normalize_directory_relationships(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    sections = {}
    records = []
    for row in payload.get("directoryRelationships", {}).get("value", []):
        parent_id, object_id = str(row.get("parentId") or ""), str(row.get("objectId") or "")
        kind, relation = row.get("parentType"), row.get("relation")
        if not parent_id or not object_id or (kind, relation) not in {("group", "members"), ("group", "owners"), ("application", "owners")}:
            continue
        records.append({"key": f"directory_relationship:{kind}:{relation}:{parent_id}:{object_id}",
                        "kind": "directory_relationship", "collector": "directory_relationships",
                        "source": "directory_relationships.directoryRelationships", "source_name": "directoryRelationships",
                        "parent_id": parent_id, "parent_type": kind, "parent_display_name": row.get("parentDisplayName"),
                        "parent_app_id": row.get("parentAppId"), "relationship": relation,
                        "object_id": object_id, "object_type": row.get("objectType"), "object_display_name": row.get("displayName")})
    if records:
        sections["directory_relationship_objects"] = {"kind": "directory_relationship", "records": list({row["key"]: row for row in records}.values())}
    observations = [{"key": f"directory_relationship_coverage:{row['parentType']}:{row['relation']}:{row['parentId']}",
                     "kind": "directory_relationship_coverage", "collector": "directory_relationships",
                     "source": "directory_relationships.relationshipCoverage", "parent_id": row["parentId"],
                     "parent_type": row["parentType"], "relationship": row["relation"],
                     "status": row["status"], "count": row["count"]}
                    for row in payload.get("relationshipCoverage", {}).get("value", [])]
    if observations:
        sections["directory_relationship_coverage"] = {"kind": "directory_relationship_coverage", "records": observations}
    return sections
