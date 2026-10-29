from __future__ import annotations

import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..collection_gaps import REASON_FANOUT_LIMIT, REASON_INPUT_LIMITED, TRUNCATION_ERROR_CLASS
from ..graph import GraphClient
from ._endpoint_reads import STATUS_OK, ObjectRead, input_rows, read_endpoints
from .base import Collector, CollectorResult, run_graph_endpoints

# PIM role management policies of the directory roles. ``roleManagementPolicyAssignments`` lists which policy governs which
# directory role; the rules of each policy (expiration, notification, approval and the others) are one GET per policy, so
# the read is bounded by the assignment list. PIM for Groups has its own policies and needs
# RoleManagementPolicy.Read.AzureADGroup: it is not read. The reads need no scope beyond RoleManagement.Read.Directory, which
# the collector already requires (a superset of RoleManagementPolicy.Read.Directory); that narrower scope is only the
# least-privilege alternative for a new app registration, so it is not in ``required_permissions``: scope names are compared
# exactly, and a tenant that granted the existing set would otherwise read as ``blocked_by_scope`` before the run.
POLICY_ASSIGNMENTS = "roleManagementPolicyAssignments"
POLICY_RULES = "roleManagementPolicyRules"
POLICY_RULES_ENDPOINT = "/policies/roleManagementPolicies/{id}/rules"
POLICY_RULES_FANOUT = f"{POLICY_RULES}Fanout"
# A licence refusal (Microsoft Entra ID P2 or Governance) is not a failed read of the tenant's data: see ``_policy_rules``.
LICENCE_ERROR_CLASS = "license_required"
# Every directory role (built in and custom) has one policy; a tenant with more roles than this gets a fan-out gap.
POLICY_RULES_FANOUT_LIMIT = 250
# The API requires both conditions to list the directory role policies.
POLICY_ASSIGNMENT_FILTER = "scopeId eq '/' and scopeType eq 'DirectoryRole'"
# Only the fields the normalized artefacts read are kept of a rule: the rest of a rule is the approvers' names and ids
# (``approvalStages``), the targets and the enablement and authentication context settings.
_RULE_FIELDS = ("@odata.type", "isExpirationRequired", "maximumDuration", "notificationType", "notificationRecipients")


def _rule_row(policy_id: str, rule: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {"policyId": policy_id, "id": rule["id"]}
    row.update({key: rule[key] for key in _RULE_FIELDS if key in rule})
    setting = rule.get("setting")
    if isinstance(setting, dict) and "isApprovalRequired" in setting:
        row["setting"] = {"isApprovalRequired": setting["isApprovalRequired"]}
    return row


class IdentityGovernanceCollector(Collector):
    name = "identity_governance"
    description = "Identity governance, entitlement management, privileged schedule and PIM role policy inventory."
    required_permissions = [
        "AccessReview.Read.All",
        "EntitlementManagement.Read.All",
        "RoleManagement.Read.Directory",
        "Directory.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top")
        page_size = context.get("page_size")
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            {
                "accessReviews": {
                    "endpoint": "/identityGovernance/accessReviews/definitions",
                    "params": {},
                },
                "entitlementCatalogs": {
                    "endpoint": "/identityGovernance/entitlementManagement/catalogs",
                    "params": {},
                },
                "accessPackages": {
                    "endpoint": "/identityGovernance/entitlementManagement/accessPackages",
                    "params": {},
                },
                "roleAssignmentSchedules": {
                    "endpoint": "/roleManagement/directory/roleAssignmentSchedules",
                    "params": {},
                },
                "roleEligibilitySchedules": {
                    "endpoint": "/roleManagement/directory/roleEligibilitySchedules",
                    "params": {},
                },
                "administrativeUnits": {
                    "endpoint": "/directory/administrativeUnits",
                    "params": {
                        "$select": "id,displayName,description",
                    },
                },
                POLICY_ASSIGNMENTS: {
                    "endpoint": "/policies/roleManagementPolicyAssignments",
                    "params": {"$filter": POLICY_ASSIGNMENT_FILTER},
                    # The endpoint accepts $filter and $expand only.
                    "apply_top": False,
                },
            },
            top=top,
            page_size=page_size,
            chunk_writer=context.get("chunk_writer"),
            log_event=context.get("audit_logger"),
        )
        rules_section, rules_coverage = self._policy_rules(client, payload, run_dir=context.get("run_dir"))
        if rules_section is not None:
            payload[POLICY_RULES] = rules_section
        coverage.extend(rules_coverage)
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Identity governance collector partially completed" if partial else "",
            coverage=coverage,
        )

    def _policy_rules(
        self,
        client: GraphClient,
        payload: dict[str, Any],
        *,
        run_dir: str | Path | None = None,
    ) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
        """Read the rules of every policy the assignment list names: one GET per policy, never more than the list holds.

        The reads are GET-only, one request per distinct policy (through ``$batch`` when the client has it) and bounded by
        ``POLICY_RULES_FANOUT_LIMIT``. ``/rules`` accepts no ``$top``. Nothing is requested, and no section is written,
        when the assignment list could not be read: that read already carries the failure. A policy that could not be read
        leaves the aggregate coverage row ``partial`` (``failed`` when none could be), so the collector is ``partial``.
        """
        started = time.perf_counter()
        rows, issues, failed_input, cut = input_rows(payload.get(POLICY_ASSIGNMENTS), run_dir)
        if failed_input or issues:
            return None, []
        policy_ids = list(dict.fromkeys(str(row["policyId"]) for row in rows if row.get("policyId")))
        targets = policy_ids[:POLICY_RULES_FANOUT_LIMIT]
        # The id is a path segment: encode every reserved character (a ``/`` included) so it cannot change the request.
        results = read_endpoints(
            client,
            [POLICY_RULES_ENDPOINT.format(id=quote(policy_id, safe="")) for policy_id in targets],
            rows=True,
            top=None,
        )
        values: list[dict[str, Any]] = []
        failures: list[ObjectRead] = []
        malformed = 0
        for policy_id, result in zip(targets, results):
            if result.status != STATUS_OK or result.rows is None:
                failures.append(result)
                continue
            seen: set[str] = set()
            for rule in result.rows:
                # A rule without an id, or an id twice in one policy, cannot be keyed: it is counted, not kept.
                if isinstance(rule.get("id"), str) and rule["id"] and rule["id"] not in seen:
                    seen.add(rule["id"])
                    values.append(_rule_row(policy_id, rule))
                else:
                    malformed += 1
        omitted = max(len(policy_ids) - len(targets), 0)
        limited = bool(omitted or cut)
        incomplete = bool(failures or malformed)
        # When every failed read was a licence refusal the fan-out row says so (it is licence-gated like the reads it
        # derives from), so the collector reads as licence-limited and not as incomplete evidence. A cut fan-out, or a
        # rule without a usable id, is never excused by a licence.
        licence_refused = bool(failures) and not (malformed or limited) and all(
            item.error_class == LICENCE_ERROR_CLASS for item in failures
        )
        fanout = {
            "fanout_scope": "directory_role_policies",
            "fanout_limit": POLICY_RULES_FANOUT_LIMIT,
            "input_record_count": len(rows),
            "input_complete": not cut,
            "input_collection_limited": cut,
            "fanout_total": len(policy_ids),
            "fanout_target_count": len(targets),
            "fanout_omitted_count": omitted,
            "failed_operation_count": len(failures),
            "malformed_rule_count": malformed,
            "collection_truncated": limited,
            "fanout_complete": not (limited or incomplete),
        }
        section: dict[str, Any] = {"value": values, "fanout": fanout, "collection_truncated": limited}
        if limited:
            section["truncation_reason"] = REASON_FANOUT_LIMIT if omitted else REASON_INPUT_LIMITED
        first = failures[0] if failures else None
        coverage: list[dict[str, Any]] = []
        if targets:
            coverage.append(
                {
                    "collector": self.name,
                    "type": "graph",
                    "name": POLICY_RULES,
                    "endpoint": POLICY_RULES_ENDPOINT,
                    "api_version": "v1.0",
                    "status": ("failed" if len(failures) == len(targets) else "partial") if failures else "ok",
                    "item_count": len(values),
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                    "error_class": first.error_class if first else None,
                    "error": first.error if first else None,
                }
            )
        coverage.append(
            {
                "collector": self.name,
                "type": "derived",
                "name": POLICY_RULES_FANOUT,
                "status": "partial" if limited or incomplete else "ok",
                "item_count": 0,
                "rows_collected": len(targets),
                "error_class": (
                    (LICENCE_ERROR_CLASS if licence_refused else "incomplete_evidence")
                    if incomplete
                    else TRUNCATION_ERROR_CLASS if limited else None
                ),
                "error": (
                    f"{POLICY_RULES}: every failed policy read was refused for want of a licence."
                    if licence_refused
                    else f"{POLICY_RULES}: some policy reads failed or returned a rule without a usable id."
                    if incomplete
                    else f"{POLICY_RULES}: only {len(targets)} policies were expanded (limit {POLICY_RULES_FANOUT_LIMIT}); the rest were not read."
                    if limited
                    else None
                ),
                "truncation_reason": (REASON_FANOUT_LIMIT if omitted else REASON_INPUT_LIMITED) if limited else None,
                **fanout,
            }
        )
        return section, coverage
