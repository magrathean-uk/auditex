"""Read-only privilege-escalation graph for Microsoft Entra tenants.

The graph is built only from the normalized snapshot that Auditex already
wrote for a run. Nodes are users, groups, applications, service principals,
directory roles, and Microsoft Graph permissions that are equivalent to
tier-0 control. Edges describe how one principal can gain the rights of the
next one, and each edge carries a MITRE ATT&CK technique id plus an evidence
reference to the normalized record it came from.

Path search walks from footholds (ordinary users, guests, users without MFA,
third-party or multi-tenant apps, apps with long-lived or expired secrets) to
tier-0 targets. Nothing here calls a tenant API.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from typing import Any, Iterable

DEFAULT_MAX_DEPTH = 5
DEFAULT_MAX_PATHS = 10

MICROSOFT_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

# Directory role template ids treated as tier-0, with a target weight.
TIER0_ROLE_TEMPLATES: dict[str, tuple[str, int]] = {
    "62e90394-69f5-4237-9190-012177145e10": ("Global Administrator", 10),
    "e8611ab8-c189-46e8-94e1-60213ab1f814": ("Privileged Role Administrator", 10),
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": ("Privileged Authentication Administrator", 10),
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": ("Application Administrator", 9),
    "158c047a-c907-4556-b7ef-446551a6b5f7": ("Cloud Application Administrator", 9),
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": ("Hybrid Identity Administrator", 9),
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8": ("Partner Tier2 Support", 9),
    "194ae4cb-b126-40b2-bd5b-6091b380977d": ("Security Administrator", 8),
    "29232cdf-9323-42fd-ade2-1d097af3e4de": ("Exchange Administrator", 8),
    "3a2c62db-5318-420d-8d74-23affee5d9d5": ("Intune Administrator", 8),
    "fe930be7-5e62-47db-91af-98c3a49a38b1": ("User Administrator", 8),
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": ("Authentication Administrator", 8),
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": ("Conditional Access Administrator", 8),
}
_TIER0_ROLE_NAMES = {name.lower(): template for template, (name, _weight) in TIER0_ROLE_TEMPLATES.items()}

# Roles whose holders can reset passwords or authentication methods of
# non-administrator users.
RESET_ROLE_TEMPLATES: dict[str, str] = {
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
}
_RESET_ROLE_NAMES = {name.lower(): template for template, name in RESET_ROLE_TEMPLATES.items()}

# Microsoft Graph permissions treated as tier-0 equivalent, with a weight.
TIER0_GRAPH_PERMISSIONS: dict[str, int] = {
    "RoleManagement.ReadWrite.Directory": 10,
    "AppRoleAssignment.ReadWrite.All": 10,
    "Application.ReadWrite.All": 9,
    "Directory.ReadWrite.All": 9,
    "Policy.ReadWrite.ConditionalAccess": 8,
    "UserAuthenticationMethod.ReadWrite.All": 8,
    "Group.ReadWrite.All": 7,
    "Mail.ReadWrite": 7,
    "Mail.Send": 7,
    "Sites.FullControl.All": 7,
}
# Stable Microsoft Graph application permission (app role) ids.
GRAPH_APP_ROLE_IDS: dict[str, str] = {
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
    "01c0a623-fc9b-48e9-b794-0756f8e8f067": "Policy.ReadWrite.ConditionalAccess",
    "50483e42-d915-4231-9639-7fdb7fd190e5": "UserAuthenticationMethod.ReadWrite.All",
    "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite",
    "b633e1c5-b582-4048-a93e-9f11b44c7e96": "Mail.Send",
    "a82116e5-55eb-4c41-a434-62fe8a61c773": "Sites.FullControl.All",
}
_DELEGATED_WEIGHT_PENALTY = 3

# Microsoft first-party publisher tenants; their apps are not third-party.
_FIRST_PARTY_TENANTS = {
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
}
_LONG_SECRET_DAYS = 730

EDGE_TECHNIQUES: dict[str, str] = {
    "member_of": "T1078.004",
    "has_role": "T1078.004",
    "guest_with_role": "T1078.004",
    "owns": "T1098.001",
    "owns_group": "T1098.003",
    "authenticates_as": "T1550.001",
    "has_app_role": "T1098.003",
    "consented": "T1528",
    "can_reset": "T1098",
    "no_mfa": "T1078.004",
    "credential": "T1552",
    "third_party": "T1199",
}
ENTRY_EDGES = frozenset({"no_mfa", "credential", "third_party"})
_EDGE_PREFERENCE = {
    "has_role": 0,
    "guest_with_role": 0,
    "member_of": 1,
    "has_app_role": 1,
    "authenticates_as": 2,
    "owns": 3,
    "owns_group": 3,
    "consented": 4,
    "can_reset": 5,
}
_EDGE_PHRASES = {
    "member_of": "is a member of",
    "has_role": "holds the role",
    "guest_with_role": "is a guest holding the role",
    "owns": "owns",
    "owns_group": "owns the privileged group",
    "authenticates_as": "signs in as",
    "has_app_role": "holds the Graph application permission",
    "consented": "holds the delegated Graph grant",
    "can_reset": "can reset the credentials of",
    "no_mfa": "can be signed in to with a password only as",
    "credential": "has a client credential usable for",
    "third_party": "is controlled outside this tenant for",
}
_FOOTHOLD_BONUS = {
    "no_mfa": 3,
    "guest": 2,
    "third_party_app": 2,
    "multi_tenant_app": 1,
    "expired_secret": 1,
    "long_lived_secret": 1,
    "ordinary_user": 0,
}
_FOOTHOLD_LABELS = {
    "no_mfa": "user without MFA",
    "guest": "guest user",
    "third_party_app": "third-party app",
    "multi_tenant_app": "multi-tenant app",
    "expired_secret": "app with an expired secret",
    "long_lived_secret": "app with a long-lived secret",
    "ordinary_user": "ordinary user",
}


@dataclass
class Edge:
    source: str
    target: str
    edge: str
    evidence_ref: dict[str, Any]
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def technique(self) -> str:
        return EDGE_TECHNIQUES.get(self.edge, "T1078.004")

    @property
    def signature(self) -> tuple[str, str, str]:
        return (self.source, self.target, self.edge)


@dataclass
class AttackGraph:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    _edge_keys: set[tuple[str, str, str, bool]] = field(default_factory=set)

    def add_node(self, node_id: str, node_type: str, label: str | None, **attrs: Any) -> str:
        node = self.nodes.get(node_id)
        if node is None:
            node = {"id": node_id, "type": node_type, "label": label or node_id.split(":", 1)[-1], "tier0": False}
            self.nodes[node_id] = node
        elif label and node["label"] == node_id.split(":", 1)[-1]:
            node["label"] = label
        for key, value in attrs.items():
            if value is not None and node.get(key) is None:
                node[key] = value
        return node_id

    def add_edge(self, source: str, target: str, edge: str, evidence_ref: dict[str, Any], **attrs: Any) -> None:
        key = (source, target, edge, bool(attrs.get("eligible")))
        if key in self._edge_keys or source == target:
            return
        self._edge_keys.add(key)
        self.edges.append(Edge(source, target, edge, evidence_ref, {k: v for k, v in attrs.items() if v is not None}))

    def out_edges(self) -> dict[str, list[Edge]]:
        result: dict[str, list[Edge]] = {}
        for edge in self.edges:
            result.setdefault(edge.source, []).append(edge)
        return result

    def in_edges(self) -> dict[str, list[Edge]]:
        result: dict[str, list[Edge]] = {}
        for edge in self.edges:
            result.setdefault(edge.target, []).append(edge)
        return result


def _records(snapshot: dict[str, Any], section: str) -> list[dict[str, Any]]:
    payload = snapshot.get(section)
    records = payload.get("records") if isinstance(payload, dict) else None
    return [item for item in records if isinstance(item, dict)] if isinstance(records, list) else []


def evidence_ref(section: str, record: dict[str, Any], collector: str) -> dict[str, Any]:
    """Evidence reference in the same shape as findings' normalized refs."""
    return {
        "artifact_path": f"normalized/{section}.json",
        "artifact_kind": "normalized_json",
        "collector": collector,
        "record_key": str(record.get("key") or record.get("id") or f"{section}:record"),
        "source_name": str(record.get("source_name") or section),
    }


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _secret_state(credentials: Any, now: datetime) -> str | None:
    """Return 'expired' or 'long_lived' for the riskiest client secret, else None."""
    state: str | None = None
    for credential in credentials if isinstance(credentials, list) else []:
        if not isinstance(credential, dict):
            continue
        start = _parse_datetime(credential.get("start_date_time"))
        end = _parse_datetime(credential.get("end_date_time"))
        if end is None or (start is not None and (end - start).days > _LONG_SECRET_DAYS):
            return "long_lived"
        if end < now:
            state = "expired"
    return state


def _scopes(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item for item in value.split() if item]
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return []


def _role_template(record: dict[str, Any]) -> str:
    role_id = str(record.get("id") or "")
    name = str(record.get("display_name") or "").strip().lower()
    if role_id in TIER0_ROLE_TEMPLATES or role_id in RESET_ROLE_TEMPLATES:
        return role_id
    return _TIER0_ROLE_NAMES.get(name) or _RESET_ROLE_NAMES.get(name) or role_id


def build_attack_graph(snapshot: dict[str, Any], *, now: datetime | None = None) -> AttackGraph:
    """Build the privilege graph from a normalized snapshot."""
    now = now or datetime.now(timezone.utc)
    graph = AttackGraph()
    principal_index: dict[str, str] = {}

    users = _records(snapshot, "users")
    for user in users:
        user_id = str(user.get("id") or "")
        if not user_id:
            continue
        node = graph.add_node(
            f"user:{user_id}",
            "user",
            user.get("principal_name") or user.get("display_name"),
            guest=str(user.get("user_type") or "").lower() == "guest",
            enabled=user.get("enabled"),
            record=("users", user, "identity"),
        )
        principal_index[user_id.lower()] = node
        if user.get("principal_name"):
            principal_index.setdefault(str(user["principal_name"]).lower(), node)

    for group in _records(snapshot, "groups"):
        group_id = str(group.get("id") or "")
        if group_id:
            principal_index[group_id.lower()] = graph.add_node(
                f"group:{group_id}",
                "group",
                group.get("display_name"),
                role_assignable=group.get("is_assignable_to_role"),
            )

    sp_by_app_id: dict[str, str] = {}
    sp_records: list[tuple[str, dict[str, Any], str]] = [
        ("service_principals", item, "identity") for item in _records(snapshot, "service_principals")
    ] + [
        ("service_principal_credential_objects", item, "app_credentials")
        for item in _records(snapshot, "service_principal_credential_objects")
    ]
    for section, sp, collector in sp_records:
        sp_id = str(sp.get("id") or "")
        if not sp_id:
            continue
        node = graph.add_node(
            f"sp:{sp_id}",
            "service_principal",
            sp.get("display_name"),
            app_id=sp.get("app_id"),
            owner_tenant=sp.get("app_owner_organization_id"),
        )
        if section == "service_principal_credential_objects":
            graph.nodes[node]["credential_record"] = (section, sp, collector)
        principal_index[sp_id.lower()] = node
        if sp.get("app_id"):
            sp_by_app_id[str(sp["app_id"]).lower()] = node
    for consent in _records(snapshot, "application_consents"):
        sp_id = str(consent.get("service_principal_id") or "")
        if sp_id and sp_id.lower() not in principal_index:
            principal_index[sp_id.lower()] = graph.add_node(
                f"sp:{sp_id}", "service_principal", consent.get("service_principal_name")
            )

    app_records: list[tuple[str, dict[str, Any], str]] = [
        ("applications", item, "identity") for item in _records(snapshot, "applications")
    ] + [
        ("application_credential_objects", item, "app_credentials")
        for item in _records(snapshot, "application_credential_objects")
    ]
    for section, app, collector in app_records:
        app_id = str(app.get("id") or "")
        if not app_id:
            continue
        node = graph.add_node(
            f"app:{app_id}",
            "application",
            app.get("display_name"),
            app_id=app.get("app_id"),
            audience=app.get("audience") or app.get("sign_in_audience"),
        )
        if section == "application_credential_objects":
            graph.nodes[node]["credential_record"] = (section, app, collector)
        graph.nodes[node].setdefault("record", (section, app, collector))
        principal_index[app_id.lower()] = node

    graph_sp_ids = {
        node_id.split(":", 1)[1]
        for node_id, node in graph.nodes.items()
        if node["type"] == "service_principal" and str(node.get("app_id") or "").lower() == MICROSOFT_GRAPH_APP_ID
    }

    role_nodes: dict[str, str] = {}
    for role in _records(snapshot, "role_definitions"):
        role_id = str(role.get("id") or "")
        if not role_id:
            continue
        template = _role_template(role)
        tier0 = TIER0_ROLE_TEMPLATES.get(template)
        node = graph.add_node(
            f"role:{template}",
            "directory_role",
            role.get("display_name") or (tier0[0] if tier0 else None),
            weight=tier0[1] if tier0 else None,
        )
        if tier0:
            graph.nodes[node]["tier0"] = True
        role_nodes[role_id.lower()] = node
        role_nodes.setdefault(template.lower(), node)

    def role_node(role_definition_id: Any) -> str | None:
        key = str(role_definition_id or "").lower()
        if not key:
            return None
        if key in role_nodes:
            return role_nodes[key]
        tier0 = TIER0_ROLE_TEMPLATES.get(key)
        node = graph.add_node(f"role:{key}", "directory_role", tier0[0] if tier0 else None, weight=tier0[1] if tier0 else None)
        if tier0:
            graph.nodes[node]["tier0"] = True
        role_nodes[key] = node
        return node

    def principal_node(principal_id: Any) -> str | None:
        key = str(principal_id or "").lower()
        if not key:
            return None
        if key not in principal_index:
            principal_index[key] = graph.add_node(f"principal:{key}", "principal", None)
        return principal_index[key]

    def add_role_edge(principal: str, role: str, ref: dict[str, Any], *, eligible: bool) -> None:
        edge = "guest_with_role" if graph.nodes[principal].get("guest") else "has_role"
        graph.add_edge(principal, role, edge, ref, eligible=eligible or None)

    roles_held: dict[str, set[str]] = {}
    for assignment in _records(snapshot, "role_assignments"):
        principal = principal_node(assignment.get("principal_id"))
        role = role_node(assignment.get("role_definition_id"))
        if principal and role:
            add_role_edge(principal, role, evidence_ref("role_assignments", assignment, "identity"), eligible=False)
            roles_held.setdefault(principal, set()).add(role)
    for item in _records(snapshot, "governance_objects"):
        kind = str(item.get("kind") or "")
        if kind not in {"role_assignment_schedule", "role_eligibility_schedule"}:
            continue
        principal = principal_node(item.get("principal_id"))
        role = role_node(item.get("role_definition_id"))
        if not principal or not role:
            continue
        eligible = kind == "role_eligibility_schedule"
        if not eligible and role in roles_held.get(principal, set()):
            continue
        add_role_edge(principal, role, evidence_ref("governance_objects", item, "identity_governance"), eligible=eligible)
        roles_held.setdefault(principal, set()).add(role)

    for item in _records(snapshot, "group_membership_edges"):
        group = principal_node(item.get("group_id"))
        member = principal_node(item.get("member_id"))
        if not group or not member:
            continue
        ref = evidence_ref("group_membership_edges", item, "identity")
        if item.get("relationship") == "owner":
            graph.add_edge(member, group, "owns_group", ref)
        else:
            graph.add_edge(member, group, "member_of", ref)

    for item in _records(snapshot, "app_owner_edges"):
        owner = principal_node(item.get("owner_id"))
        prefix = "app" if item.get("target_type") == "application" else "sp"
        target_id = str(item.get("target_id") or "")
        if not owner or not target_id:
            continue
        target = principal_index.get(target_id.lower()) or graph.add_node(
            f"{prefix}:{target_id}",
            "application" if prefix == "app" else "service_principal",
            item.get("target_display_name"),
        )
        principal_index.setdefault(target_id.lower(), target)
        graph.add_edge(owner, target, "owns", evidence_ref("app_owner_edges", item, str(item.get("collector") or "app_consent")))

    for node_id, node in list(graph.nodes.items()):
        if node["type"] != "application" or not node.get("app_id"):
            continue
        sp = sp_by_app_id.get(str(node["app_id"]).lower())
        if sp:
            section, record, collector = node.get("credential_record") or node["record"]
            graph.add_edge(node_id, sp, "authenticates_as", evidence_ref(section, record, collector))

    has_role_assignable_groups = any(
        node["type"] == "group" and (node.get("role_assignable") or node_id in roles_held)
        for node_id, node in graph.nodes.items()
    )

    def permission_node(name: str, *, delegated: bool) -> str | None:
        weight = TIER0_GRAPH_PERMISSIONS.get(name)
        if weight is None or (name == "Group.ReadWrite.All" and not has_role_assignable_groups):
            return None
        prefix = "graph_delegated" if delegated else "graph_app_role"
        node = graph.add_node(
            f"{prefix}:{name}",
            "graph_permission",
            f"Microsoft Graph {name}" + (" (delegated)" if delegated else ""),
            permission=name,
            delegated=delegated,
            weight=weight - (_DELEGATED_WEIGHT_PENALTY if delegated else 0),
        )
        graph.nodes[node]["tier0"] = True
        return node

    for consent in _records(snapshot, "application_consents"):
        ref = evidence_ref("application_consents", consent, "app_consent")
        if consent.get("source_name") == "servicePrincipalAppRoleAssignments":
            name = GRAPH_APP_ROLE_IDS.get(str(consent.get("app_role_id") or "").lower()) or str(
                consent.get("app_role_value") or ""
            )
            resource = str(consent.get("resource_id") or consent.get("service_principal_id") or "")
            if graph_sp_ids and resource and resource not in graph_sp_ids:
                continue
            principal_type = str(consent.get("principal_type") or "ServicePrincipal").lower()
            if principal_type != "serviceprincipal":
                continue
            principal = principal_node(consent.get("principal_id"))
            target = permission_node(name, delegated=False) if name else None
            if principal and target:
                graph.add_edge(principal, target, "has_app_role", ref)
            continue
        resource = str(consent.get("resource_id") or "")
        if graph_sp_ids and resource and resource not in graph_sp_ids:
            continue
        client = principal_node(consent.get("service_principal_id"))
        if not client:
            continue
        for scope in _scopes(consent.get("scope")):
            target = permission_node(scope, delegated=True)
            if target:
                graph.add_edge(
                    client,
                    target,
                    "consented",
                    ref,
                    consent_type=consent.get("consent_type"),
                    granted_for=consent.get("principal_id"),
                )

    # Password / authentication-method reset over non-administrators.
    users_with_roles = set(roles_held)
    reset_roles = [
        node_id
        for node_id in graph.nodes
        if node_id.startswith("role:")
        and node_id.split(":", 1)[1] in RESET_ROLE_TEMPLATES
        and any(edge.target == node_id for edge in graph.edges)
    ]
    if reset_roles:
        for user in users:
            node_id = f"user:{user.get('id')}"
            if node_id not in graph.nodes or node_id in users_with_roles or user.get("enabled") is False:
                continue
            for role in reset_roles:
                graph.add_edge(role, node_id, "can_reset", evidence_ref("users", user, "identity"))

    # Entry edges: how an outsider gets the foothold principal.
    for registration in _records(snapshot, "auth_method_registration_objects"):
        if registration.get("is_mfa_registered") is not False:
            continue
        node = principal_index.get(str(registration.get("id") or "").lower()) or principal_index.get(
            str(registration.get("user_principal_name") or "").lower()
        )
        if node and graph.nodes[node]["type"] == "user":
            graph.add_node("entry:password_only", "entry", "Password-only sign-in")
            graph.add_edge(
                "entry:password_only",
                node,
                "no_mfa",
                evidence_ref("auth_method_registration_objects", registration, "auth_methods"),
            )

    home_tenants = {
        str(graph.nodes[sp].get("owner_tenant") or "").lower()
        for node in graph.nodes.values()
        if node["type"] == "application" and node.get("app_id")
        for sp in [sp_by_app_id.get(str(node["app_id"]).lower())]
        if sp and graph.nodes[sp].get("owner_tenant")
    }
    for node_id, node in list(graph.nodes.items()):
        credential = node.get("credential_record")
        if node["type"] in {"application", "service_principal"} and credential:
            section, record, collector = credential
            secret = _secret_state(record.get("password_credentials"), now)
            has_credential = bool(record.get("password_credentials") or record.get("key_credentials"))
            if has_credential:
                graph.add_node("entry:app_credential", "entry", "Leaked or reused app credential")
                graph.add_edge(
                    "entry:app_credential",
                    node_id,
                    "credential",
                    evidence_ref(section, record, collector),
                    validity=secret,
                )
                if secret:
                    node["secret_state"] = secret
        owner_tenant = str(node.get("owner_tenant") or "").lower()
        third_party = (
            node["type"] == "service_principal"
            and owner_tenant
            and home_tenants
            and owner_tenant not in home_tenants
            and owner_tenant not in _FIRST_PARTY_TENANTS
        )
        multi_tenant = node["type"] == "application" and str(node.get("audience") or "") in {
            "AzureADMultipleOrgs",
            "AzureADandPersonalMicrosoftAccount",
        }
        if (third_party or multi_tenant) and (credential or node.get("record")):
            section, record, collector = credential or node["record"]
            node["external"] = "third_party_app" if third_party else "multi_tenant_app"
            graph.add_node("entry:external_tenant", "entry", "Publisher or another tenant")
            graph.add_edge(
                "entry:external_tenant",
                node_id,
                "third_party",
                evidence_ref(section, record, collector),
                reason=node["external"],
            )
    return graph


def _tier0_principals(graph: AttackGraph) -> set[str]:
    """Principals that hold a tier-0 role or Graph permission directly and actively."""
    tier0: set[str] = set()
    for edge in graph.edges:
        if edge.edge in {"has_role", "guest_with_role", "has_app_role"} and not edge.attrs.get("eligible"):
            if graph.nodes.get(edge.target, {}).get("tier0"):
                tier0.add(edge.source)
    return tier0


def _footholds(graph: AttackGraph, tier0: set[str]) -> dict[str, list[str]]:
    reasons: dict[str, list[str]] = {}
    entry_targets: dict[str, set[str]] = {}
    for edge in graph.edges:
        if edge.edge in ENTRY_EDGES:
            entry_targets.setdefault(edge.target, set()).add(edge.edge)
    for node_id, node in graph.nodes.items():
        kinds: list[str] = []
        if node["type"] == "user":
            if node_id in tier0 or node.get("enabled") is False:
                continue
            if "no_mfa" in entry_targets.get(node_id, set()):
                kinds.append("no_mfa")
            if node.get("guest"):
                kinds.append("guest")
            kinds.append("ordinary_user")
        elif node["type"] in {"application", "service_principal"}:
            if node.get("external"):
                kinds.append(str(node["external"]))
            if node.get("secret_state") == "expired":
                kinds.append("expired_secret")
            elif node.get("secret_state") == "long_lived":
                kinds.append("long_lived_secret")
        if kinds:
            reasons[node_id] = kinds
    return reasons


def _distances_to_targets(graph: AttackGraph, edges: Iterable[Edge], max_depth: int) -> dict[str, int]:
    incoming: dict[str, list[Edge]] = {}
    for edge in edges:
        if edge.edge not in ENTRY_EDGES:
            incoming.setdefault(edge.target, []).append(edge)
    dist = {node_id: 0 for node_id, node in graph.nodes.items() if node.get("tier0")}
    queue = deque(sorted(dist))
    while queue:
        node = queue.popleft()
        if dist[node] >= max_depth:
            continue
        for edge in sorted(incoming.get(node, []), key=lambda item: item.source):
            if edge.source not in dist:
                dist[edge.source] = dist[node] + 1
                queue.append(edge.source)
    return dist


def _reaches_tier0(graph: AttackGraph, source: str, outgoing: dict[str, list[Edge]], skip: Edge, max_depth: int) -> bool:
    seen = {source}
    frontier = [source]
    for _depth in range(max_depth):
        nxt: list[str] = []
        for node in frontier:
            for edge in outgoing.get(node, []):
                if edge is skip or edge.edge in ENTRY_EDGES or edge.target in seen:
                    continue
                if graph.nodes.get(edge.target, {}).get("tier0"):
                    return True
                seen.add(edge.target)
                nxt.append(edge.target)
        frontier = nxt
    return False


def _hop(graph: AttackGraph, edge: Edge) -> dict[str, Any]:
    hop = {
        "from": graph.nodes[edge.source]["label"],
        "from_id": edge.source,
        "from_type": graph.nodes[edge.source]["type"],
        "to": graph.nodes[edge.target]["label"],
        "to_id": edge.target,
        "to_type": graph.nodes[edge.target]["type"],
        "edge": edge.edge,
        "technique": edge.technique,
        "evidence_ref": dict(edge.evidence_ref),
    }
    if edge.attrs.get("eligible"):
        hop["eligible"] = True
    for key in ("consent_type", "validity", "reason"):
        if edge.attrs.get(key):
            hop[key] = edge.attrs[key]
    return hop


def _severity(score: int) -> str:
    if score >= 13:
        return "critical"
    if score >= 10:
        return "high"
    if score >= 7:
        return "medium"
    return "low"


def _summary_sentence(source_kind: str, source_label: str, target_label: str, hops: list[dict[str, Any]]) -> str:
    steps = "; ".join(
        f"{hop['from']} {_EDGE_PHRASES.get(hop['edge'], hop['edge'])} {hop['to']}"
        + (" (PIM-eligible)" if hop.get("eligible") else "")
        for hop in hops
        if hop["edge"] not in ENTRY_EDGES
    )
    count = sum(1 for hop in hops if hop["edge"] not in ENTRY_EDGES)
    return (
        f"{_FOOTHOLD_LABELS.get(source_kind, 'Foothold').capitalize()} {source_label} can reach tier-0 "
        f"{target_label} in {count} step{'s' if count != 1 else ''}: {steps}."
    )


def analyze_attack_graph(
    snapshot: dict[str, Any] | None,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_paths: int = DEFAULT_MAX_PATHS,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return ``{"summary": {...}, "paths": [...]}`` for a normalized snapshot."""
    graph = build_attack_graph(snapshot or {}, now=now)
    tier0 = _tier0_principals(graph)
    footholds = _footholds(graph, tier0)
    dist = _distances_to_targets(graph, graph.edges, max_depth)
    outgoing = graph.out_edges()
    entry_by_target: dict[str, list[Edge]] = {}
    for edge in graph.edges:
        if edge.edge in ENTRY_EDGES:
            entry_by_target.setdefault(edge.target, []).append(edge)

    candidates: list[dict[str, Any]] = []
    for source in sorted(footholds):
        if source not in dist or dist[source] == 0:
            continue
        chain: list[Edge] = []
        node = source
        while dist.get(node, 0) > 0:
            options = [
                edge
                for edge in outgoing.get(node, [])
                if edge.edge not in ENTRY_EDGES and dist.get(edge.target, max_depth + 1) == dist[node] - 1
            ]
            options.sort(key=lambda edge: (bool(edge.attrs.get("eligible")), _EDGE_PREFERENCE.get(edge.edge, 9), edge.target))
            chain.append(options[0])
            node = options[0].target
        kinds = footholds[source]
        primary_kind = kinds[0]
        entry_edge_name = {"no_mfa": "no_mfa", "third_party_app": "third_party", "multi_tenant_app": "third_party"}.get(
            primary_kind, "credential" if primary_kind in {"expired_secret", "long_lived_secret"} else None
        )
        entry = next(
            (edge for edge in entry_by_target.get(source, []) if edge.edge == entry_edge_name),
            None,
        )
        target = graph.nodes[node]
        eligible = any(edge.attrs.get("eligible") for edge in chain)
        score = int(target.get("weight") or 8) + (max_depth - len(chain)) + max(_FOOTHOLD_BONUS.get(kind, 0) for kind in kinds)
        if eligible:
            score -= 2
        candidates.append(
            {
                "source": source,
                "target": node,
                "kinds": kinds,
                "chain": chain,
                "entry": entry,
                "score": score,
                "eligible": eligible,
            }
        )

    # Collapse footholds that share the same privilege route after their first hop.
    grouped: dict[tuple[Any, ...], dict[str, Any]] = {}
    for candidate in sorted(candidates, key=lambda item: (-item["score"], len(item["chain"]), item["source"])):
        signature = (
            candidate["chain"][0].target,
            tuple(edge.signature for edge in candidate["chain"][1:]),
            candidate["chain"][0].edge,
        )
        existing = grouped.get(signature)
        if existing is None:
            candidate["also"] = []
            grouped[signature] = candidate
        else:
            existing["also"].append(candidate["source"])
    selected = sorted(grouped.values(), key=lambda item: (-item["score"], len(item["chain"]), item["source"]))[:max_paths]

    paths: list[dict[str, Any]] = []
    for candidate in selected:
        chain = candidate["chain"]
        hops = ([_hop(graph, candidate["entry"])] if candidate["entry"] else []) + [_hop(graph, edge) for edge in chain]
        source_label = graph.nodes[candidate["source"]]["label"]
        target_label = graph.nodes[candidate["target"]]["label"]
        breakpoints = [
            {
                "from": graph.nodes[edge.source]["label"],
                "to": graph.nodes[edge.target]["label"],
                "edge": edge.edge,
                "technique": edge.technique,
                "evidence_ref": dict(edge.evidence_ref),
            }
            for edge in chain
            if not _reaches_tier0(graph, candidate["source"], outgoing, edge, max_depth)
        ]
        digest = hashlib.sha1(
            "|".join([candidate["source"], candidate["target"], *(f"{e.source}>{e.edge}>{e.target}" for e in chain)]).encode("utf-8")
        ).hexdigest()[:12]
        path_id = f"attack_path:graph:{digest}"
        severity = _severity(candidate["score"])
        techniques = list(dict.fromkeys(hop["technique"] for hop in hops))
        also = [graph.nodes[item]["label"] for item in candidate["also"]]
        emits_finding = severity in {"high", "critical"}
        path = {
            "id": path_id,
            "kind": "privilege_graph",
            "source": source_label,
            "source_id": candidate["source"],
            "source_type": graph.nodes[candidate["source"]]["type"],
            "foothold": candidate["kinds"][0],
            "foothold_reasons": candidate["kinds"],
            "target": target_label,
            "target_id": candidate["target"],
            "hops": hops,
            "hop_count": len(chain),
            "eligible": candidate["eligible"],
            "risk_score": candidate["score"],
            "severity": severity,
            "techniques": techniques,
            "summary": _summary_sentence(candidate["kinds"][0], source_label, target_label, hops),
            "breakpoints": breakpoints,
            "foothold_count": 1 + len(also),
            "also_reachable_from": also[:10],
            # Compatibility with the stage-based attack path shape.
            "chain": [hop["edge"] for hop in hops],
            "stage_count": len(hops),
            "findings": [
                {
                    "stage": hop["edge"],
                    "finding_id": path_id if emits_finding else None,
                    "title": f"{hop['from']} → {hop['to']}",
                    "severity": severity,
                    "technique": hop["technique"],
                }
                for hop in hops
            ],
            "requires_premium_license": False,
            "requires_live_tenant": False,
        }
        if emits_finding:
            path["finding_id"] = path_id
        paths.append(path)

    edge_counts: dict[str, int] = {}
    for edge in graph.edges:
        edge_counts[edge.edge] = edge_counts.get(edge.edge, 0) + 1
    foothold_counts: dict[str, int] = {}
    for kinds in footholds.values():
        for kind in kinds:
            foothold_counts[kind] = foothold_counts.get(kind, 0) + 1
    disabled_tier0 = sorted(
        graph.nodes[node]["label"] for node in tier0 if graph.nodes[node].get("enabled") is False
    )
    summary = {
        "node_count": sum(1 for node in graph.nodes.values() if node["type"] != "entry"),
        "edge_count": len(graph.edges),
        # Lists rather than maps: edge and foothold names such as "credential"
        # must not become JSON keys in contract artifacts.
        "edge_counts": [{"edge": name, "count": count} for name, count in sorted(edge_counts.items())],
        "tier0_targets": sum(1 for node in graph.nodes.values() if node.get("tier0")),
        "tier0_principals": len(tier0),
        "tier0_principal_labels": sorted(graph.nodes[node]["label"] for node in tier0)[:25],
        "disabled_tier0_principals": disabled_tier0[:25],
        "footholds": len(footholds),
        "foothold_counts": [{"foothold": name, "count": count} for name, count in sorted(foothold_counts.items())],
        "paths_found": len(candidates),
        "path_count": len(paths),
        "max_depth": max_depth,
        "max_paths": max_paths,
        "read_only": True,
    }
    return {"summary": summary, "paths": paths}
