"""Synthetic Graph answers for the PIM role policy reads of ``identity_governance`` (no tenant, no network)."""
from __future__ import annotations

from typing import Any

from azure_tenant_audit.collectors.identity_governance import (
    IdentityGovernanceCollector,
)
from azure_tenant_audit.graph import GraphError
from azure_tenant_audit.normalize import build_normalized_snapshot

TENANT = "11111111-1111-4111-8111-111111111111"
GA = "62e90394-69f5-4237-9190-012177145e10"
EXO = "29232cdf-9323-42fd-ade2-1d097af3e4de"
READER = "5d6b6bb7-de71-4623-b4af-96380a352509"
ROLE_NAMES = {GA: "Global Administrator", EXO: "Exchange Administrator", READER: "Security Reader"}
ASSIGNMENTS_PATH = "/policies/roleManagementPolicyAssignments"
POLICY_PATH = "/policies/roleManagementPolicies/{}/rules"
ASSIGNMENT_FILTER = "scopeId eq '/' and scopeType eq 'DirectoryRole'"
RECIPIENT = "alerts@example.invalid"
PRINCIPALS = {name: f"22222222-2222-4222-8222-22222222222{index}" for index, name in enumerate(("a", "b", "c"), start=1)}

SCHEDULES = [
    {"id": "s1", "principalId": PRINCIPALS["a"], "roleDefinitionId": GA, "status": "Provisioned",
     "scheduleInfo": {"startDateTime": "2026-10-01T09:30:00Z", "expiration": {"type": "noExpiration"}}},
    {"id": "s2", "principalId": PRINCIPALS["b"], "roleDefinitionId": GA, "status": "Provisioned",
     "scheduleInfo": {"startDateTime": "2026-01-15T00:00:00Z",
                      "expiration": {"type": "afterDateTime", "endDateTime": "2026-10-01T09:30:00.1234567Z"}}},
    {"id": "s3", "principalId": PRINCIPALS["c"], "roleDefinitionId": EXO, "status": "Provisioned",
     "scheduleInfo": {"startDateTime": "2026-10-01T09:30:00Z", "expiration": {"type": "noExpiration"}}},
]
DEFINITIONS = [{"id": role, "displayName": name} for role, name in ROLE_NAMES.items()]


def policy_id(role: str) -> str:
    return f"DirectoryRole_{TENANT}_{role}"


def graph_rules(role: str) -> list[dict[str, Any]]:
    """The rules of one policy as Graph returns them, with the fields the collector must not keep."""
    prefix = "#microsoft.graph.unifiedRoleManagementPolicy"
    target = {"caller": "Admin", "operations": ["all"], "level": "Assignment", "inheritableSettings": [], "enforcedSettings": []}
    approvers = [{"@odata.type": "#microsoft.graph.singleUser", "userId": PRINCIPALS["a"], "description": "Synthetic Approver"}]
    return [
        {"@odata.type": f"{prefix}ApprovalRule", "id": "Approval_EndUser_Assignment", "target": target,
         "setting": {"isApprovalRequired": role == GA, "isRequestorJustificationRequired": True, "approvalMode": "SingleStage",
                     "approvalStages": [{"primaryApprovers": approvers, "isApproverJustificationRequired": True}]}},
        {"@odata.type": f"{prefix}AuthenticationContextRule", "id": "AuthenticationContext_EndUser_Assignment",
         "target": target, "isEnabled": False, "claimValue": None},
        {"@odata.type": f"{prefix}EnablementRule", "id": "Enablement_Admin_Assignment", "target": target,
         "enabledRules": ["MultiFactorAuthentication"]},
        {"@odata.type": f"{prefix}ExpirationRule", "id": "Expiration_Admin_Assignment", "target": target,
         "isExpirationRequired": False, "maximumDuration": "P365D"},
        {"@odata.type": f"{prefix}ExpirationRule", "id": "Expiration_Admin_Eligibility", "target": target,
         "isExpirationRequired": True, "maximumDuration": "P180D"},
        {"@odata.type": f"{prefix}NotificationRule", "id": "Notification_Admin_EndUser_Assignment", "target": target,
         "notificationType": "Email", "recipientType": "Admin", "notificationLevel": "All", "isDefaultRecipientsEnabled": True,
         "notificationRecipients": [RECIPIENT] if role == GA else []},
    ]


def assignment_row(role: str) -> dict[str, Any]:
    return {"id": f"{policy_id(role)}_{role}", "policyId": policy_id(role), "roleDefinitionId": role,
            "scopeId": "/", "scopeType": "DirectoryRole"}


class PolicyClient:
    """A Graph client for ``identity_governance``: one answer per path, ``fail`` maps a path (or a rules path) to an error."""

    def __init__(self, *, roles: tuple[str, ...] = (GA, EXO, READER), schedules: list[dict[str, Any]] | None = None,
                 fail: dict[str, GraphError] | None = None, batch: bool = False, assignments: list[dict[str, Any]] | None = None) -> None:
        self.roles = roles
        self.schedules = SCHEDULES if schedules is None else schedules
        self.fail = fail or {}
        self.assignments = [assignment_row(role) for role in roles] if assignments is None else assignments
        self.requests: list[tuple[str, dict[str, Any]]] = []
        self.batches: list[list[dict[str, Any]]] = []
        if batch:
            self.get_batch = self._get_batch  # type: ignore[method-assign]

    def _answer(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        if path in self.fail:
            raise self.fail[path]
        if path.startswith("/policies/roleManagementPolicies/") and "rules" in self.fail:
            raise self.fail["rules"]
        if path == ASSIGNMENTS_PATH:
            return self.assignments
        if path == "/roleManagement/directory/roleAssignmentSchedules":
            return self.schedules
        for role in self.roles:
            if path == POLICY_PATH.format(policy_id(role)):
                return graph_rules(role)
        return []

    def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        self.requests.append((path, dict(params or {})))
        return self._answer(path, dict(params or {}))

    def get_json(self, path: str, params: Any = None, full_url: bool = False) -> dict[str, Any]:  # noqa: ARG002
        return {"value": self.get_all(path, params)}

    def _get_batch(self, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        self.batches.append(requests)
        answers = []
        for request in requests:
            try:
                answers.append({"request": request, "status": 200, "body": {"value": self._answer(request["path"], request.get("params") or {})}})
            except GraphError as exc:
                answers.append({"request": request, "status": exc.status, "body": {"error": {"code": exc.error_code, "message": str(exc)}}})
        return answers


def forbidden(path: str = "/policies") -> GraphError:
    return GraphError("Insufficient privileges to complete the operation.", status=403, request=path, error_code="Forbidden")


def license_required(path: str = "/policies") -> GraphError:
    return GraphError("The tenant needs to have Microsoft Entra ID P2 or Governance license to use this feature.", status=403,
                      request=path, error_code="Forbidden")


def transient(path: str = "/policies") -> GraphError:
    return GraphError("The service is unavailable.", status=503, request=path, error_code="ServiceUnavailable")


def not_found(path: str = "/policies") -> GraphError:
    return GraphError("Resource not found for the segment 'roleManagementPolicyAssignments'.", status=404, request=path)


def collect(client: PolicyClient | None = None, **context: Any) -> Any:
    return IdentityGovernanceCollector().run({"client": client or PolicyClient(), "top": None, **context})


def snapshot(result: Any, *, definitions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """The normalized snapshot of a collector result together with the role definitions of the identity collector."""
    return build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads={
            "identity": {"roleDefinitions": {"value": DEFINITIONS if definitions is None else definitions}},
            "identity_governance": result.payload,
        },
        coverage_rows=result.coverage,
        result_rows=[{"name": "identity_governance", "status": result.status, "item_count": result.item_count}],
    )
