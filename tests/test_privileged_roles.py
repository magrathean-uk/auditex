"""PIM role policy reads of ``identity_governance`` and the ``privileged_roles`` artefact built from them.

Synthetic Graph answers only: no tenant, no network. A refused or missing read must be a gap and never an empty list.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import quote

import pytest

from azure_tenant_audit import privileged_roles as artefact
from azure_tenant_audit.baselines import _licence_limited_collectors
from azure_tenant_audit.collection_gaps import list_truncations, refusal_gap_records
from azure_tenant_audit.collectors import _endpoint_reads
from azure_tenant_audit.collectors import identity_governance as governance
from azure_tenant_audit.config import CollectorConfig
from azure_tenant_audit.contracts import _validate_record_key_uniqueness
from azure_tenant_audit.diagnostics import build_diagnostics, load_permission_hints
from azure_tenant_audit.graph import GraphError
from azure_tenant_audit.normalize import build_normalized_snapshot
from azure_tenant_audit.profiles import get_profile
from azure_tenant_audit.run import build_capability_matrix_rows, build_coverage_ledger, build_live_run_plan
from azure_tenant_audit.scope_catalog import build_m365_scope_catalog

from pim_support import (
    ASSIGNMENT_FILTER,
    ASSIGNMENTS_PATH,
    EXO,
    GA,
    POLICY_PATH,
    PRINCIPALS,
    READER,
    RECIPIENT,
    SCHEDULES,
    PolicyClient,
    collect,
    forbidden,
    graph_rules,
    license_required,
    not_found,
    policy_id,
    snapshot,
    transient,
)

RULES_ENDPOINT = "/policies/roleManagementPolicies/{id}/rules"
# What a rule may carry in the export shape; the projection rejects any other key.
RULE_KEYS = {"Id", "IsExpirationRequired", "MaximumDuration", "NotificationRecipients", "NotificationType", "RuleSource",
             "RuleSourceType", "Setting"}
DROPPED = ("target", "recipientType", "notificationLevel", "enabledRules", "approvalStages", "isEnabled", "claimValue",
           "isDefaultRecipientsEnabled", "isApprovalRequiredForExtension", "isRequestorJustificationRequired", "approvalMode")


def _rules(name: str, *, approval: bool, recipients: list[str]) -> list[dict[str, Any]]:
    base = {"RuleSource": name, "RuleSourceType": "Directory Role"}
    return [
        {"Id": "Approval_EndUser_Assignment", "Setting": {"IsApprovalRequired": approval}, **base},
        {"Id": "Expiration_Admin_Assignment", "IsExpirationRequired": False, "MaximumDuration": "P365D", **base},
        {"Id": "Expiration_Admin_Eligibility", "IsExpirationRequired": True, "MaximumDuration": "P180D", **base},
        {"Id": "Notification_Admin_EndUser_Assignment", "NotificationRecipients": recipients, "NotificationType": "Email", **base},
    ]


EXPECTED = [
    {
        "DisplayName": "Exchange Administrator",
        "RoleTemplateId": EXO,
        "Assignments": [{"PrincipalId": PRINCIPALS["c"], "StartDateTime": "/Date(1790847000000)/", "EndDateTime": None}],
        "Rules": _rules("Exchange Administrator", approval=False, recipients=[]),
    },
    {
        "DisplayName": "Global Administrator",
        "RoleTemplateId": GA,
        "Assignments": [
            {"PrincipalId": PRINCIPALS["a"], "StartDateTime": "/Date(1790847000000)/", "EndDateTime": None},
            # 2026-10-01T09:30:00.1234567Z: Graph's seven fractional digits are cut to milliseconds, never rounded up.
            {"PrincipalId": PRINCIPALS["b"], "StartDateTime": "/Date(1768435200000)/", "EndDateTime": "/Date(1790847000123)/"},
        ],
        "Rules": _rules("Global Administrator", approval=True, recipients=[RECIPIENT]),
    },
]


# The artefact rows also carry the ``key`` every normalized record has (the bundle contract and run comparison need it).
ARTEFACT = [{"key": f"privileged_role:{row['RoleTemplateId']}", **row} for row in EXPECTED]


# ---- collection ---------------------------------------------------------------------------------------------------


def test_the_collector_lists_directory_role_policies_with_the_required_filter_and_no_top() -> None:
    client = PolicyClient()
    result = collect(client, top=100)

    assert result.status == "ok"
    requests = dict(client.requests)
    assert requests[ASSIGNMENTS_PATH] == {"$filter": ASSIGNMENT_FILTER}, "the API needs this filter and takes no $top"
    for role in (GA, EXO, READER):
        assert requests[POLICY_PATH.format(policy_id(role))] == {}, "/rules accepts $select and $filter only"
    by_name = {row["name"]: row for row in result.coverage}
    assert by_name["roleManagementPolicyAssignments"]["api_version"] == "v1.0"
    assert by_name["roleManagementPolicyAssignments"]["top"] is None
    rules = by_name["roleManagementPolicyRules"]
    assert (rules["endpoint"], rules["api_version"], rules["status"], rules["item_count"]) == (RULES_ENDPOINT, "v1.0", "ok", 18)
    assert by_name["roleManagementPolicyRulesFanout"]["status"] == "ok"
    assert result.payload["roleManagementPolicyAssignments"]["value"] == client.assignments


def test_rule_rows_carry_the_policy_id_and_only_the_fields_the_artefacts_read() -> None:
    rows = collect().payload["roleManagementPolicyRules"]["value"]

    assert {row["policyId"] for row in rows} == {policy_id(role) for role in (GA, EXO, READER)}
    for row in rows:
        assert set(row) <= {"policyId", "id", "@odata.type", "isExpirationRequired", "maximumDuration", "notificationType",
                            "notificationRecipients", "setting"}
        assert not any(name in row for name in DROPPED)
        assert row.get("setting", {}).keys() <= {"isApprovalRequired"}, "the approvers' names and ids are not kept"
    ga = {row["id"]: row for row in rows if row["policyId"] == policy_id(GA)}
    assert ga["Notification_Admin_EndUser_Assignment"]["notificationRecipients"] == [RECIPIENT]
    assert "Synthetic Approver" not in json.dumps(rows)
    assert ga["Enablement_Admin_Assignment"] == {
        "policyId": policy_id(GA), "id": "Enablement_Admin_Assignment",
        "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"}


def test_a_policy_named_by_two_assignments_is_read_once() -> None:
    client = PolicyClient(assignments=[
        {"id": "a1", "policyId": policy_id(GA), "roleDefinitionId": GA, "scopeId": "/", "scopeType": "DirectoryRole"},
        {"id": "a2", "policyId": policy_id(GA), "roleDefinitionId": GA, "scopeId": "/", "scopeType": "DirectoryRole"},
    ])
    collect(client)

    assert [path for path, _ in client.requests if path.startswith("/policies/roleManagementPolicies/")] == [POLICY_PATH.format(policy_id(GA))]


def test_a_rule_id_repeated_within_a_policy_is_malformed_and_leaves_no_artefact_and_no_duplicate_key() -> None:
    class Client(PolicyClient):
        def _answer(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
            rows = super()._answer(path, params)
            return [*rows, rows[0]] if path == POLICY_PATH.format(policy_id(GA)) else rows

    result = collect(Client())
    fanout = result.payload["roleManagementPolicyRules"]["fanout"]

    assert result.status == "partial"
    assert (fanout["malformed_rule_count"], fanout["fanout_complete"]) == (1, False)
    normalized = snapshot(result)
    assert "privileged_roles" not in normalized
    keys = [row["key"] for row in normalized["governance_objects"]["records"]]
    assert len(keys) == len(set(keys))


def test_two_assignments_of_one_policy_keep_unique_governance_keys() -> None:
    client = PolicyClient(assignments=[
        {"id": "a1", "policyId": policy_id(GA), "roleDefinitionId": GA, "scopeId": "/", "scopeType": "DirectoryRole"},
        {"id": "a2", "policyId": policy_id(GA), "roleDefinitionId": GA, "scopeId": "/", "scopeType": "DirectoryRole"},
    ])
    keys = [row["key"] for row in snapshot(collect(client))["governance_objects"]["records"]]

    assert len(keys) == len(set(keys))
    assert {"role_management_policy_assignment:a1", "role_management_policy_assignment:a2"} <= set(keys)


def test_the_rule_reads_go_through_one_get_only_batch_without_top() -> None:
    client = PolicyClient(batch=True)
    result = collect(client)

    assert result.status == "ok"
    (batch,) = client.batches
    assert [(item["path"], item.get("params")) for item in batch] == [(POLICY_PATH.format(policy_id(role)), {}) for role in (GA, EXO, READER)]
    assert all(item.get("method", "GET") == "GET" for item in batch)
    assert len(result.payload["roleManagementPolicyRules"]["value"]) == 18


def test_the_rule_fan_out_is_bounded_and_the_cut_is_a_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(governance, "POLICY_RULES_FANOUT_LIMIT", 2)
    client = PolicyClient()
    result = collect(client)

    assert result.status == "partial"
    assert len([path for path, _ in client.requests if path.startswith("/policies/roleManagementPolicies/")]) == 2
    section = result.payload["roleManagementPolicyRules"]
    assert (section["collection_truncated"], section["truncation_reason"]) == (True, "fanout_limit")
    assert section["fanout"]["fanout_complete"] is False
    assert list_truncations(result.coverage) == [
        {"collector": "identity_governance", "list": "roleManagementPolicyRulesFanout", "rows_collected": 2, "reason": "fanout_limit"}]
    assert "privileged_roles" not in snapshot(result), "a cut fan-out never becomes a complete artefact"


def test_a_cut_assignment_list_is_an_input_gap_and_no_artefact() -> None:
    result = collect(PolicyClient(), top=2)

    assert result.status == "partial"
    assert result.payload["roleManagementPolicyAssignments"]["collection_truncated"] is True
    assert result.payload["roleManagementPolicyRules"]["truncation_reason"] == "input_limited"
    sources = {row["source"] for row in snapshot(result)["collection_gaps"]["records"]}
    assert {"identity_governance.roleManagementPolicyAssignments", "identity_governance.roleManagementPolicyRulesFanout"} <= sources
    assert "privileged_roles" not in snapshot(result)


def test_read_endpoints_can_omit_top_for_a_collection_that_rejects_it() -> None:
    client = PolicyClient(batch=True)
    _endpoint_reads.read_endpoints(client, [POLICY_PATH.format(policy_id(GA))], rows=True, top=None)
    plain = PolicyClient()
    _endpoint_reads.read_endpoints(plain, [POLICY_PATH.format(policy_id(GA))], rows=True, top=None)
    default = PolicyClient()
    _endpoint_reads.read_endpoints(default, [POLICY_PATH.format(policy_id(GA))], rows=True)

    assert client.batches[0][0]["params"] == {} and plain.requests[0][1] == {}
    assert default.requests[0][1] == {"$top": "50"}, "every other fan-out still asks for 50"


# ---- refused and missing reads ------------------------------------------------------------------------------------

REFUSALS = [
    pytest.param({ASSIGNMENTS_PATH: forbidden()}, "roleManagementPolicyAssignments", "insufficient_permissions", "read_failed",
                 "blocked_permission", id="assignments-403"),
    pytest.param({"rules": forbidden()}, "roleManagementPolicyRules", "insufficient_permissions", "read_failed",
                 "blocked_permission", id="rules-403"),
    pytest.param({ASSIGNMENTS_PATH: not_found()}, "roleManagementPolicyAssignments", "resource_not_found", "endpoint_unavailable",
                 "partial_success", id="assignments-404"),
]


@pytest.mark.parametrize("fail,operation,error_class,reason,ledger_status", REFUSALS)
def test_a_refused_or_missing_policy_read_is_a_gap_never_a_crash_or_an_empty_list(
    fail: dict[str, GraphError], operation: str, error_class: str, reason: str, ledger_status: str
) -> None:
    client = PolicyClient(fail=fail)
    result = collect(client)

    assert result.status == "partial"
    row = next(item for item in result.coverage if item["name"] == operation)
    assert (row["status"], row["error_class"]) == ("failed", error_class)

    normalized = snapshot(result)
    assert "privileged_roles" not in normalized
    gaps = {item["source"]: item for item in normalized["collection_gaps"]["records"]}
    gap = gaps[f"identity_governance.{operation}"]
    assert (gap["reason"], gap["status"], gap["error_classes"], gap["rows_collected"]) == (reason, "failed", [error_class], 0)

    result_rows = [{"name": "identity_governance", "status": result.status, "item_count": result.item_count}]
    diagnostics = build_diagnostics(result_rows=result_rows, coverage_rows=result.coverage, permission_hints={}, auditor_profile="global-reader")
    ledger = build_coverage_ledger(
        capability_rows=[{"collector": "identity_governance", "status": "supported_exact_scope"}],
        result_rows=result_rows, diagnostics=diagnostics)
    assert ledger[0]["coverage_status"] == ledger_status


def test_a_missing_assignment_endpoint_requests_no_rules_and_writes_no_rules_section() -> None:
    client = PolicyClient(fail={ASSIGNMENTS_PATH: not_found()})
    result = collect(client)

    assert not [path for path, _ in client.requests if path.startswith("/policies/roleManagementPolicies/")]
    assert "roleManagementPolicyRules" not in result.payload
    assert {row["name"] for row in result.coverage} >= {"roleManagementPolicyAssignments"}
    assert not any(row["name"].startswith("roleManagementPolicyRules") for row in result.coverage)


def test_the_refusal_gap_names_only_the_policy_operations() -> None:
    rows = [
        {"collector": "identity_governance", "name": "roleManagementPolicyAssignments", "status": "failed", "error_class": "resource_not_found"},
        {"collector": "identity_governance", "name": "roleManagementPolicyRules", "status": "partial", "error_class": "graph_transient", "item_count": 7},
        {"collector": "identity_governance", "name": "roleAssignmentSchedules", "status": "failed", "error_class": "insufficient_permissions"},
        {"collector": "identity", "name": "roleManagementPolicyRules", "status": "failed", "error_class": "insufficient_permissions"},
        {"collector": "identity_governance", "name": "roleManagementPolicyRules", "status": "ok"},
    ]
    assert refusal_gap_records(rows[:4]) == [
        {"collector": "identity_governance", "list": "roleManagementPolicyAssignments", "rows_collected": 0,
         "reason": "endpoint_unavailable", "status": "failed", "error_classes": ["resource_not_found"]},
        {"collector": "identity_governance", "list": "roleManagementPolicyRules", "rows_collected": 7,
         "reason": "read_failed", "status": "partial", "error_classes": ["graph_transient"]},
    ]
    # Graph answers a resource the API version does not serve with HTTP 400 and this text, not always with a 404.
    unserved = {**rows[0], "error_class": "bad_request", "error": "Resource not found for the segment 'roleManagementPolicyAssignments'."}
    assert refusal_gap_records([unserved])[0]["reason"] == "endpoint_unavailable"
    assert refusal_gap_records([{**unserved, "error": "The filter is invalid."}])[0]["reason"] == "read_failed"
    # A later ok observation of the same read replaces the failed one; a cut list is listed by list_truncations already.
    assert refusal_gap_records([rows[1], rows[4]]) == []
    assert refusal_gap_records([{**rows[0], "collection_truncated": True}]) == []
    # An offline or resumed bundle with no coverage row is read from the raw section.
    payloads = {"identity_governance": {"roleManagementPolicyAssignments": {"error": "gone", "error_class": "resource_not_found"},
                                        "roleManagementPolicyRules": {"value": []}}}
    assert [(item["list"], item["reason"]) for item in refusal_gap_records([], payloads)] == [
        ("roleManagementPolicyAssignments", "endpoint_unavailable")]


# ---- the normalized artefacts -------------------------------------------------------------------------------------


def test_the_policy_reads_become_governance_objects_with_keys_unique_per_policy() -> None:
    normalized = snapshot(collect())
    records = normalized["governance_objects"]["records"]
    kinds = {row["kind"] for row in records}
    assert {"role_management_policy_assignment", "role_management_policy_rule"} <= kinds

    assignments = [row for row in records if row["kind"] == "role_management_policy_assignment"]
    rules = [row for row in records if row["kind"] == "role_management_policy_rule"]
    assert {row["key"] for row in assignments} == {f"role_management_policy_assignment:{policy_id(role)}_{role}" for role in (GA, EXO, READER)}
    assert {row["policy_id"] for row in assignments} == {policy_id(role) for role in (GA, EXO, READER)}
    assert len(rules) == 18
    # Rule ids repeat across policies, so the key carries the policy id.
    assert len({row["rule_id"] for row in rules}) == 6
    assert {row["key"] for row in rules} == {f"role_management_policy_rule:{policy_id(role)}:{rule}" for role in (GA, EXO, READER)
                                             for rule in {row["rule_id"] for row in rules}}
    assert len({row["key"] for row in records}) == len(records)
    expiration = next(row for row in rules if row["key"].endswith(f"{policy_id(GA)}:Expiration_Admin_Eligibility"))
    assert (expiration["rule_type"], expiration["is_expiration_required"], expiration["maximum_duration"]) == (
        "unifiedRoleManagementPolicyExpirationRule", True, "P180D")
    approval = next(row for row in rules if row["key"].endswith(f"{policy_id(GA)}:Approval_EndUser_Assignment"))
    assert approval["is_approval_required"] is True
    assert "notification_recipients" not in next(row for row in rules if row["key"].endswith(f"{policy_id(EXO)}:Notification_Admin_EndUser_Assignment"))


def test_governance_record_keys_pass_the_bundle_contract(tmp_path: Path) -> None:
    normalized = snapshot(collect())
    (tmp_path / "normalized").mkdir()
    for name in ("governance_objects", "privileged_roles"):
        (tmp_path / "normalized" / f"{name}.json").write_text(json.dumps(normalized[name]))
    issues: list[dict[str, Any]] = []
    _validate_record_key_uniqueness(tmp_path, issues)

    assert issues == []


def test_privileged_roles_is_written_in_the_export_shape_with_the_pack_date_convention() -> None:
    normalized = snapshot(collect())
    section = normalized["privileged_roles"]

    assert section["records"] == ARTEFACT
    assert section["collection_status"] == "collected" and section["complete"] is True and section["kind"] == "privileged_roles"
    assert normalized["snapshot"]["object_counts"]["privileged_roles"] == 2
    for role in section["records"]:
        assert set(role) == {"key", "DisplayName", "RoleTemplateId", "Assignments", "Rules"}
        for rule in role["Rules"]:
            assert set(rule) <= RULE_KEYS and rule["Id"].startswith(("Expiration_", "Notification_", "Approval_"))
        for assignment in role["Assignments"]:
            assert set(assignment) <= {"PrincipalId", "StartDateTime", "EndDateTime"}
            assert all(value is None or value.startswith("/Date(") and value.endswith(")/")
                       for key, value in assignment.items() if key != "PrincipalId")
    names = {rule["RuleSource"] for role in section["records"] for rule in role["Rules"]}
    assert names == {"Exchange Administrator", "Global Administrator"}, "Security Reader is not a privileged role"
    assert not any(rule["Id"].startswith(("Enablement_", "AuthenticationContext_")) for role in section["records"] for rule in role["Rules"])


# The properties Graph returns for each rule type (the fields the collector keeps), and so all a rule row may carry.
FAMILY_KEYS = {
    "Expiration_": {"Id", "IsExpirationRequired", "MaximumDuration", "RuleSource", "RuleSourceType"},
    "Notification_": {"Id", "NotificationRecipients", "NotificationType", "RuleSource", "RuleSourceType"},
    "Approval_": {"Id", "RuleSource", "RuleSourceType", "Setting"},
}


def test_each_rule_family_carries_exactly_the_properties_graph_returned_for_it_and_no_padding() -> None:
    rules = [rule for role in snapshot(collect())["privileged_roles"]["records"] for rule in role["Rules"]]

    assert {rule["Id"].split("_")[0] + "_" for rule in rules} == set(FAMILY_KEYS)
    for rule in rules:
        family = rule["Id"].split("_")[0] + "_"
        assert set(rule) == FAMILY_KEYS[family], rule["Id"]
        assert rule["RuleSource"] in {"Exchange Administrator", "Global Administrator"} and rule["RuleSourceType"] == "Directory Role"
        if family == "Approval_":
            assert set(rule["Setting"]) == {"IsApprovalRequired"}
        # No not-applicable filler: a value is Graph's own, never a null or empty stand-in for a property of another type.
        if family == "Expiration_":
            assert isinstance(rule["IsExpirationRequired"], bool) and rule["MaximumDuration"]
    assert not any(None in rule.values() and rule["Id"].startswith(("Expiration_", "Approval_")) for rule in rules)


def test_no_frozen_pack_rule_shape_holds_an_expiration_or_approval_rule_as_graph_returns_it() -> None:
    """Why the artefact is withheld by the shape gate and not padded to match.

    The distinct rule shapes of the frozen v7 whole shapes (the committed fixture, so no pack needs to be mounted) are
    compared with the shape of each rule family as the normaliser writes it. The notification rule is held; an expiration
    rule would need ``NotificationRecipients`` and a ``Setting`` object, an approval rule ``IsExpirationRequired``,
    ``MaximumDuration`` and ``NotificationRecipients`` besides ``Setting``, and the pack has no null or empty form of them
    to stand in (``Setting`` is an object on every rule that carries ``IsExpirationRequired``). A pack that holds these
    shapes changes this test, ``PACK_SHAPE_DIGESTS`` and the output contract together.
    """
    from auditex.scuba_projection import _json, _shape

    fixture = json.loads((Path(__file__).parent / "fixtures" / "scuba-projection-shapes-v7.json").read_text())
    frozen = {item for whole in fixture["sections"]["privileged_roles"] for role in whole["array"]
              for item in json.loads(role)["object"]["Rules"]["array"]}
    shapes = [json.loads(item)["object"] for item in frozen]
    assert len(frozen) == 11

    written = {}
    for role in snapshot(collect())["privileged_roles"]["records"]:
        for rule in role["Rules"]:
            written.setdefault(rule["Id"].split("_")[0], set()).add(_json(_shape(rule)))
    assert all(item in frozen for item in written["Notification"])
    assert not any(item in frozen for item in written["Expiration"] | written["Approval"])

    # What the pack holds around the gap: every rule shape with IsExpirationRequired also has recipients and a Setting
    # object, and no rule shape with a Setting object lacks the expiration fields. There is no null stand-in to copy.
    for shape in shapes:
        if "IsExpirationRequired" in shape:
            assert shape["Setting"] == {"object": {"IsApprovalRequired": "bool"}} and "NotificationRecipients" in shape
            assert shape["MaximumDuration"] == "str"
        if shape.get("Setting") not in (None, "NoneType"):
            assert {"IsExpirationRequired", "MaximumDuration", "NotificationRecipients"} <= set(shape)


def test_the_artefact_is_deterministic_and_does_not_depend_on_collection_order() -> None:
    first = snapshot(collect(PolicyClient(roles=(GA, EXO, READER))))["privileged_roles"]
    reversed_ = snapshot(collect(PolicyClient(roles=(READER, EXO, GA), schedules=list(reversed(SCHEDULES)))))["privileged_roles"]

    assert first == reversed_


def test_a_tenant_without_privileged_role_definitions_has_a_known_empty_artefact() -> None:
    only_reader = [{"id": READER, "displayName": "Security Reader"}]
    section = snapshot(collect(), definitions=only_reader)["privileged_roles"]

    assert section["records"] == [] and section["complete"] is True and section["collection_status"] == "collected"


def _without_policy(role: str) -> PolicyClient:
    return PolicyClient(assignments=[row for row in PolicyClient().assignments if row["roleDefinitionId"] != role])


@pytest.mark.parametrize("name,client", [
    pytest.param("a privileged role without a policy", _without_policy(GA), id="no-policy"),
    pytest.param("an expiration without an end date", PolicyClient(schedules=[
        {**SCHEDULES[0], "scheduleInfo": {"startDateTime": "2026-10-01T09:30:00Z", "expiration": {"type": "afterDuration", "duration": "P30D"}}}]),
        id="after-duration-without-end"),
    pytest.param("a schedule without scheduleInfo", PolicyClient(schedules=[{**SCHEDULES[0], "scheduleInfo": None}]), id="no-schedule-info"),
    pytest.param("an unparseable date", PolicyClient(schedules=[
        {**SCHEDULES[0], "scheduleInfo": {"startDateTime": "yesterday", "expiration": {"type": "noExpiration"}}}]), id="bad-date"),
    pytest.param("a schedule without a principal", PolicyClient(schedules=[{**SCHEDULES[0], "principalId": None}]), id="no-principal"),
])
def test_an_input_that_cannot_be_read_without_guessing_leaves_no_artefact(name: str, client: PolicyClient) -> None:
    assert "privileged_roles" not in snapshot(collect(client)), name


def test_an_unusable_rule_leaves_no_artefact() -> None:
    class Client(PolicyClient):
        def _answer(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
            rows = super()._answer(path, params)
            if path == POLICY_PATH.format(policy_id(EXO)):
                rows = [{**row, "maximumDuration": None} if row["id"] == "Expiration_Admin_Eligibility" else row for row in rows]
            return rows

    assert "privileged_roles" not in snapshot(collect(Client()))


def test_a_failed_role_definition_read_leaves_no_artefact() -> None:
    result = collect()
    payloads = {"identity": {"roleDefinitions": {"error": "Forbidden", "error_class": "insufficient_permissions"}},
                "identity_governance": result.payload}
    normalized = build_normalized_snapshot(tenant_name="acme", run_id="r", collector_payloads=payloads, coverage_rows=result.coverage)

    assert "privileged_roles" not in normalized


def test_the_artefact_is_what_the_projection_adapter_accepts(tmp_path: Path) -> None:
    from auditex.scuba_projection import DEFAULT_SCAN_MAX_BYTES, DEFAULT_SCAN_MAX_CHUNKS, DEFAULT_SCAN_MAX_ROWS, Bundle, _roles

    normalized = snapshot(collect())
    (tmp_path / "normalized").mkdir()
    (tmp_path / "normalized" / "privileged_roles.json").write_text(json.dumps(normalized["privileged_roles"]))
    bundle = Bundle(tmp_path, DEFAULT_SCAN_MAX_ROWS, DEFAULT_SCAN_MAX_BYTES, DEFAULT_SCAN_MAX_CHUNKS)
    bundle.manifest = {}
    # Only the coverage evidence of the run is missing here; the adapter itself reads every field of every row.
    bundle.collector_health = lambda *_args, **_kwargs: None  # type: ignore[method-assign]

    assert _roles(bundle) == EXPECTED


# ---- scope: the policy reads need nothing beyond the set a registration already holds ------------------------------

POLICY_SCOPE = "RoleManagementPolicy.Read.Directory"
EXISTING_SCOPES = ["AccessReview.Read.All", "Directory.Read.All", "EntitlementManagement.Read.All", "RoleManagement.Read.Directory"]


def _scope_inputs() -> tuple[CollectorConfig, dict[str, dict[str, Any]]]:
    return CollectorConfig.from_path("configs/collector-definitions.json"), load_permission_hints(Path("configs/collector-permissions.json"))


def test_the_policy_reads_add_no_required_scope_to_the_existing_set() -> None:
    config, hints = _scope_inputs()
    catalog = build_m365_scope_catalog(collector_config=config, permission_hints=hints)
    recommendation = json.loads(Path("configs/collector-permissions.json").read_text(encoding="utf-8"))["global_app_recommendation"]

    # Scope names are compared exactly, so a scope listed here would block a tenant that holds only the existing set.
    assert sorted(governance.IdentityGovernanceCollector.required_permissions) == EXISTING_SCOPES
    assert sorted(config.collectors["identity_governance"].required_permissions) == EXISTING_SCOPES
    assert sorted(hints["identity_governance"]["graph_scopes"]) == EXISTING_SCOPES
    assert sorted(catalog["identity_governance"]["required_permissions"]) == EXISTING_SCOPES
    assert POLICY_SCOPE not in recommendation and "RoleManagement.Read.Directory" in recommendation
    # It is named as the least-privilege alternative for a new registration, in the notes and the guide only.
    notes = hints["identity_governance"]["notes"]
    assert POLICY_SCOPE in notes and "an existing registration needs no change" in notes
    guide = Path("docs/guides/admin-permission-guide.md").read_text(encoding="utf-8")
    assert POLICY_SCOPE in guide and "needs no change" in guide and "needs nothing more" not in guide


def test_a_tenant_that_granted_the_existing_scopes_is_not_blocked_by_scope_nor_asked_to_consent_again(tmp_path: Path) -> None:
    config, hints = _scope_inputs()
    (row,) = build_capability_matrix_rows(
        auth_context={"token_claims": {"app_roles": EXISTING_SCOPES}},
        selected_collectors=["identity_governance"],
        auditor_profile="global-reader",
        collector_config=config,
        permission_hints=hints,
    )
    assert (row["status"], row["reason"], row["missing_permissions"]) == ("supported_exact_scope", "required_permissions_present", [])

    args = SimpleNamespace(
        tenant_name="acme", collectors="identity_governance", exclude=None, include_exchange=False, offline=False, sample="sample.json",
        run_name=None, top=None, page_size=None, auditor_profile="global-reader", plane="full", since=None, until=None,
        collector_preset=None, interactive=True, scopes=None)
    plan = build_live_run_plan(args, output_dir=tmp_path, collector_config=config, permission_hints=hints, profile=get_profile("global-reader"))
    assert plan.selected_collectors == ["identity_governance"]
    assert plan.auth_scopes == EXISTING_SCOPES, "the interactive consent set is the existing one"


# ---- a policy id is one path segment ------------------------------------------------------------------------------

RESERVED_POLICY = f"DirectoryRole_t/with?reserved#chars%20and space_{GA}"
ENCODED_RULES_PATH = f"/policies/roleManagementPolicies/{quote(RESERVED_POLICY, safe='')}/rules"


class _ReservedIdClient(PolicyClient):
    def _answer(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        return graph_rules(GA) if path == ENCODED_RULES_PATH else super()._answer(path, params)


@pytest.mark.parametrize("batch", [False, True], ids=["get", "batch"])
def test_a_policy_id_with_reserved_characters_is_percent_encoded_as_one_path_segment(batch: bool) -> None:
    assignments = [{"id": "a1", "policyId": RESERVED_POLICY, "roleDefinitionId": GA, "scopeId": "/", "scopeType": "DirectoryRole"}]
    client = _ReservedIdClient(roles=(GA,), assignments=assignments, batch=batch)
    result = collect(client)

    assert result.status == "ok"
    requested = [item["path"] for batch_ in client.batches for item in batch_] if batch else [
        path for path, _ in client.requests if path.startswith("/policies/roleManagementPolicies/")]
    assert requested == [ENCODED_RULES_PATH]
    path = requested[0]
    assert path.count("/") == 4 and not any(char in path for char in "?# "), "no reserved character leaks into the URL"
    assert "%2F" in path and "%3F" in path and "%23" in path and "%25" in path
    # The rows and the artefact keep the id as Graph returned it, so the policy still joins to its role.
    assert {row["policyId"] for row in result.payload["roleManagementPolicyRules"]["value"]} == {RESERVED_POLICY}
    rows = snapshot(result, definitions=[{"id": GA, "displayName": "Global Administrator"}])["privileged_roles"]["records"]
    assert [row["DisplayName"] for row in rows] == ["Global Administrator"] and rows[0]["Rules"]


def test_an_ordinary_policy_id_is_requested_unchanged() -> None:
    client = PolicyClient()
    collect(client)

    assert POLICY_PATH.format(policy_id(GA)) in [path for path, _ in client.requests]


# ---- a licence refusal of every rule read --------------------------------------------------------------------------


def _ledger(result: Any) -> list[dict[str, Any]]:
    result_rows = [{"name": "identity_governance", "status": result.status, "item_count": result.item_count}]
    diagnostics = build_diagnostics(result_rows=result_rows, coverage_rows=result.coverage, permission_hints={}, auditor_profile="global-reader")
    return build_coverage_ledger(
        capability_rows=[{"collector": "identity_governance", "status": "supported_exact_scope"}],
        result_rows=result_rows, diagnostics=diagnostics)


def test_every_rule_read_refused_for_a_licence_is_licence_limited_not_incomplete_evidence() -> None:
    result = collect(PolicyClient(fail={"rules": license_required()}))
    by_name = {row["name"]: row for row in result.coverage}

    assert result.status == "partial"
    assert (by_name["roleManagementPolicyRules"]["status"], by_name["roleManagementPolicyRules"]["error_class"]) == ("failed", "license_required")
    fanout = by_name["roleManagementPolicyRulesFanout"]
    assert (fanout["status"], fanout["error_class"], fanout["collection_truncated"]) == ("partial", "license_required", False)
    assert result.payload["roleManagementPolicyRules"]["fanout"]["fanout_complete"] is False
    assert "privileged_roles" not in snapshot(result), "a licence refusal still leaves no artefact"
    ledger = _ledger(result)
    assert ledger[0]["coverage_status"] == "partial_success"
    assert _licence_limited_collectors(ledger) == {"identity_governance"}


def test_a_licence_refusal_does_not_excuse_another_failure_a_cut_or_a_malformed_rule() -> None:
    class Duplicate(PolicyClient):
        def _answer(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
            rows = super()._answer(path, params)
            return [*rows, rows[0]] if path == POLICY_PATH.format(policy_id(READER)) else rows

    refused = {POLICY_PATH.format(policy_id(GA)): license_required()}
    other = {POLICY_PATH.format(policy_id(EXO)): transient()}
    for client in (PolicyClient(fail={**refused, **other}), Duplicate(fail=refused)):
        result = collect(client)
        fanout = next(row for row in result.coverage if row["name"] == "roleManagementPolicyRulesFanout")
        assert fanout["error_class"] == "incomplete_evidence"
        assert _licence_limited_collectors(_ledger(result)) == set()


def test_a_cut_fan_out_with_licence_refusals_keeps_its_truncation_class(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(governance, "POLICY_RULES_FANOUT_LIMIT", 2)
    result = collect(PolicyClient(fail={"rules": license_required()}))
    fanout = next(row for row in result.coverage if row["name"] == "roleManagementPolicyRulesFanout")

    assert fanout["error_class"] == "incomplete_evidence" and fanout["collection_truncated"] is True
    assert _licence_limited_collectors(_ledger(result)) == set()


# ---- an artefact withheld although every read succeeded names why --------------------------------------------------


class _GaRules(PolicyClient):
    """The Global Administrator policy answers ``rows`` instead of its rules."""

    def __init__(self, rows: list[dict[str, Any]], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.rows = rows

    def _answer(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        return self.rows if path == POLICY_PATH.format(policy_id(GA)) else super()._answer(path, params)


class _UnreadableExpiration(PolicyClient):
    def _answer(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        rows = super()._answer(path, params)
        if path == POLICY_PATH.format(policy_id(EXO)):
            rows = [{**row, "maximumDuration": None} if row["id"] == "Expiration_Admin_Eligibility" else row for row in rows]
        return rows


_TWO_POLICIES_FOR_GA = [*PolicyClient().assignments, {"id": "a2", "policyId": f"{policy_id(GA)}_other", "roleDefinitionId": GA,
                                                     "scopeId": "/", "scopeType": "DirectoryRole"}]
_EXO_AND_READER = [row for row in PolicyClient().assignments if row["roleDefinitionId"] != GA]
_EXO_SCHEDULE_WITHOUT_PRINCIPAL = {**SCHEDULES[2], "principalId": None}

WITHHELD = [
    pytest.param(PolicyClient(assignments=[]), [artefact.REASON_EMPTY_POLICY_LIST], id="empty-policy-assignment-list"),
    pytest.param(_without_policy(GA), [f"role_without_policy:{GA}"], id="role-without-policy"),
    pytest.param(PolicyClient(assignments=_TWO_POLICIES_FOR_GA), [f"conflicting_policies:{GA}"], id="conflicting-policies"),
    pytest.param(_GaRules([]), [f"policy_without_rules:{GA}"], id="policy-without-rules"),
    pytest.param(_GaRules([row for row in graph_rules(GA) if row["id"].startswith(("Enablement_", "AuthenticationContext_"))]),
                 [f"policy_without_exportable_rules:{GA}"], id="policy-without-exportable-rules"),
    pytest.param(_UnreadableExpiration(), [f"unreadable_rule:{EXO}"], id="unreadable-rule"),
    pytest.param(PolicyClient(schedules=[{**SCHEDULES[0], "principalId": None}]), [f"unreadable_schedule:{GA}"], id="schedule-without-principal"),
    pytest.param(PolicyClient(schedules=[{**SCHEDULES[0], "scheduleInfo": {"startDateTime": "2026-10-01T09:30:00Z", "expiration": {
        "type": "afterDuration", "duration": "P30D"}}}]), [f"unreadable_schedule:{GA}"], id="schedule-without-end-date"),
    pytest.param(PolicyClient(schedules=[{**SCHEDULES[0], "scheduleInfo": {"startDateTime": "yesterday", "expiration": {
        "type": "noExpiration"}}}]), [f"unreadable_schedule:{GA}"], id="schedule-with-unparseable-date"),
    # Every failing role is named, in a stable order, not only the first one found.
    pytest.param(PolicyClient(assignments=_EXO_AND_READER, schedules=[SCHEDULES[0], _EXO_SCHEDULE_WITHOUT_PRINCIPAL]),
                 [f"role_without_policy:{GA}", f"unreadable_schedule:{EXO}"], id="several-roles"),
]


@pytest.mark.parametrize("client,reasons", WITHHELD)
def test_a_withheld_artefact_is_a_collection_gap_that_names_each_reason_and_the_collector_stays_ok(
    client: PolicyClient, reasons: list[str]
) -> None:
    result = collect(client)
    normalized = snapshot(result)

    assert result.status == "ok", "every read succeeded: the collector is not partial"
    assert "privileged_roles" not in normalized
    gaps = {row["source"]: row for row in normalized["collection_gaps"]["records"]}
    assert set(gaps) == {"identity_governance.privileged_roles"}
    gap = gaps["identity_governance.privileged_roles"]
    assert (gap["kind"], gap["collector"], gap["list"], gap["rows_collected"]) == ("collection_gap", "identity_governance", "privileged_roles", 0)
    assert gap["reason"] == artefact.GAP_REASON == "artefact_withheld"
    assert gap["reasons"] == reasons
    assert normalized["snapshot"]["collection_gap_count"] == 1
    assert normalized["snapshot"]["blocker_count"] == 0, "no diagnostic: the run is not made partial by a withheld artefact"


def test_a_role_without_a_name_is_a_named_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    original = artefact._privileged_roles
    monkeypatch.setattr(artefact, "_privileged_roles", lambda definitions: {
        role: ("" if role == GA.lower() else name, is_global) for role, (name, is_global) in original(definitions).items()})
    normalized = snapshot(collect())
    gap = {row["source"]: row for row in normalized["collection_gaps"]["records"]}["identity_governance.privileged_roles"]

    assert "privileged_roles" not in normalized and gap["reasons"] == [f"role_without_name:{GA}"]


def test_the_builder_returns_the_rows_or_every_reason() -> None:
    built = artefact.build_privileged_roles(
        role_definitions=[{"id": GA, "display_name": "Global Administrator"}, {"id": EXO, "display_name": "Exchange Administrator"}],
        policy_assignments=[PolicyClient().assignments[1]],
        policy_rules=[],
        assignment_schedules=[])

    assert built.rows is None
    assert built.reasons == sorted([f"role_without_policy:{GA}", f"policy_without_rules:{EXO}"])
    complete = artefact.build_privileged_roles(role_definitions=[], policy_assignments=[], policy_rules=[], assignment_schedules=[])
    assert (complete.rows, complete.reasons) == ([], []), "no privileged role: a known empty artefact, not a reason"


def test_a_complete_artefact_and_a_failed_or_missing_read_record_no_withheld_gap() -> None:
    sources = {"identity_governance.privileged_roles"}

    assert "collection_gaps" not in snapshot(collect()), "a written artefact is no gap"
    for fail in ({ASSIGNMENTS_PATH: forbidden()}, {"rules": forbidden()}, {ASSIGNMENTS_PATH: not_found()}):
        normalized = snapshot(collect(PolicyClient(fail=fail)))
        assert not sources & {row["source"] for row in normalized["collection_gaps"]["records"]}, "the failed read is the gap"
    # A bundle collected before these reads existed never made them: that is "not collected", not a withheld artefact.
    result = collect()
    payload = {name: section for name, section in result.payload.items() if not name.startswith("roleManagementPolicy")}
    coverage = [row for row in result.coverage if not row["name"].startswith("roleManagementPolicy")]
    normalized = build_normalized_snapshot(
        tenant_name="acme", run_id="r", coverage_rows=coverage,
        collector_payloads={"identity": {"roleDefinitions": {"value": [{"id": GA, "displayName": "Global Administrator"}]}},
                            "identity_governance": payload})
    assert "privileged_roles" not in normalized and "collection_gaps" not in normalized
