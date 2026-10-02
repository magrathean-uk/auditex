from __future__ import annotations

import time
from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, _classify_graph_error, run_graph_endpoints

# Bound on the number of privileged groups expanded for members and owners.
_PRIVILEGED_GROUP_FANOUT_LIMIT = 50
_GROUP_RELATION_SELECT = "id,displayName,userPrincipalName"

# signInActivity needs AuditLog.Read.All plus Microsoft Entra ID P1/P2, and Graph caps
# the page size at 500 when it is selected. It is queried separately so a missing
# licence or scope leaves a coverage gap instead of blocking the core user inventory.
SIGNIN_ACTIVITY_SECTION = "userSignInActivity"
SIGNIN_ACTIVITY_MAX_PAGE_SIZE = 500
SIGNIN_ACTIVITY_GATED_ERRORS = {"license_required", "insufficient_permissions", "unauthenticated", "permission_stop"}


class IdentityCollector(Collector):
    name = "identity"
    description = "Directory and identity objects."
    required_permissions = [
        "Directory.Read.All",
        "User.Read.All",
        "Group.Read.All",
        "Application.Read.All",
        "AuditLog.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top", 500)
        page_size = context.get("page_size")
        selectors = {
            "organization": {
                "endpoint": "/organization",
                "page": False,
                "params": {"$select": "id,displayName,tenantType,city,country"},
            },
            "domains": {"endpoint": "/domains", "page": False, "params": {"$select": "id,authenticationType,isDefault,isVerified,isRoot"}},
            "users": {
                "endpoint": "/users",
                "params": {
                    "$select": "id,displayName,userPrincipalName,mail,jobTitle,department,userType,accountEnabled,lastPasswordChangeDateTime,createdDateTime",
                },
            },
            SIGNIN_ACTIVITY_SECTION: {
                "endpoint": "/users",
                "params": {"$select": "id,signInActivity"},
                "max_top": SIGNIN_ACTIVITY_MAX_PAGE_SIZE,
            },
            "groups": {
                "endpoint": "/groups",
                "params": {
                    "$select": "id,displayName,mail,groupTypes,createdDateTime,isAssignableToRole",
                    "$filter": "securityEnabled eq true",
                },
            },
            "applications": {
                "endpoint": "/applications",
                "params": {"$select": "id,displayName,createdDateTime,signInAudience"},
            },
            "servicePrincipals": {
                "endpoint": "/servicePrincipals",
                "params": {"$select": "id,displayName,appId,servicePrincipalType"},
            },
            "roleDefinitions": {
                "endpoint": "/roleManagement/directory/roleDefinitions",
                "params": {"$select": "id,displayName,description"},
                "apply_top": False,
            },
            "roleAssignments": {
                "endpoint": "/roleManagement/directory/roleAssignments",
                "params": {"$select": "id,principalId,roleDefinitionId"},
            },
        }
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            selectors,
            top=top,
            page_size=page_size,
            chunk_writer=context.get("chunk_writer"),
            log_event=context.get("audit_logger"),
        )
        payload.update(self._privileged_group_relations(client, payload, coverage))
        total_items = sum(entry.get("item_count", 0) for entry in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        message = "Identity collection partially completed" if partial else ""
        signin_row = next((row for row in coverage if row.get("name") == SIGNIN_ACTIVITY_SECTION), None)
        core_failed = any(
            row.get("status") != "ok" for row in coverage if row.get("name") != SIGNIN_ACTIVITY_SECTION
        )
        if signin_row is not None and signin_row.get("status") != "ok":
            error_class = str(signin_row.get("error_class") or "")
            signin_row["capability_gated"] = True
            signin_row["coverage_note"] = (
                "User sign-in activity is unavailable; stale-account findings are not evaluated. "
                "signInActivity requires AuditLog.Read.All and Microsoft Entra ID P1 or P2."
            )
            section = payload.get(SIGNIN_ACTIVITY_SECTION)
            if isinstance(section, dict):
                section["capability_gated"] = error_class in SIGNIN_ACTIVITY_GATED_ERRORS
            if not core_failed:
                message = f"Identity collected; user sign-in activity unavailable ({error_class or 'error'})"
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total_items,
            message=message,
            coverage=coverage,
        )

    def _privileged_group_relations(
        self,
        client: GraphClient,
        payload: dict[str, Any],
        coverage: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Read members and owners of role-assignable groups only.

        These are the groups that can hold directory roles, so their members
        inherit privileged roles and their owners can change who does. Nested
        groups found among the members are expanded too. The reads are
        GET-only and bounded by ``_PRIVILEGED_GROUP_FANOUT_LIMIT`` groups.
        """
        groups = (payload.get("groups") or {}).get("value") or []
        assignments = (payload.get("roleAssignments") or {}).get("value") or []
        role_principal_ids = {
            str(item.get("principalId")) for item in assignments if isinstance(item, dict) and item.get("principalId")
        }
        queue = [
            group
            for group in groups
            if isinstance(group, dict)
            and group.get("id")
            and (group.get("isAssignableToRole") is True or str(group.get("id")) in role_principal_ids)
        ]
        expanded: set[str] = set()
        members: list[dict[str, Any]] = []
        owners: list[dict[str, Any]] = []
        while queue and len(expanded) < _PRIVILEGED_GROUP_FANOUT_LIMIT:
            group = queue.pop(0)
            group_id = str(group["id"])
            if group_id in expanded:
                continue
            expanded.add(group_id)
            for name, relation, rows_out in (
                ("roleAssignableGroupMembers", "members", members),
                ("roleAssignableGroupOwners", "owners", owners),
            ):
                endpoint = f"/groups/{group_id}/{relation}"
                start = time.perf_counter()
                try:
                    rows = client.get_all(endpoint, params={"$select": _GROUP_RELATION_SELECT})
                    rows = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
                    rows_out.append({"groupId": group_id, "displayName": group.get("displayName"), relation: rows})
                    if relation == "members":
                        # Nested groups inherit the privileged group's roles; expand them too.
                        queue.extend(
                            row
                            for row in rows
                            if row.get("id")
                            and "group" in str(row.get("@odata.type") or "").lower()
                            and str(row.get("id")) not in expanded
                        )
                    status, error_class, error = "ok", None, None
                except Exception as exc:  # noqa: BLE001
                    rows = []
                    status = "failed"
                    error_class, error = _classify_graph_error(exc)
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "graph",
                        "name": name,
                        "endpoint": endpoint,
                        "group_id": group_id,
                        "status": status,
                        "item_count": len(rows),
                        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                        "error_class": error_class,
                        "error": error,
                    }
                )
        return {
            "roleAssignableGroupMembers": {"value": members},
            "roleAssignableGroupOwners": {"value": owners},
        }
