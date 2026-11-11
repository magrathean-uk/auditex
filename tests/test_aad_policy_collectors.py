"""Synthetic GET-only evidence and explicit gaps for AAD policy collection.

Fixture meta: constructed rows and pack train and validation rows from v3.9.1;
held-out test and pilot rows excluded. All rows here are constructed locally;
no pack/vector rows are imported.
"""
from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path

import pytest

from azure_tenant_audit.collectors.app_consent import (
    RISKY_RESOURCE_APP_IDS,
    AppConsentCollector,
)
from azure_tenant_audit.collectors.auth_methods import AuthMethodsCollector
from azure_tenant_audit.collectors.consent_policy import ConsentPolicyCollector
from azure_tenant_audit.collectors.identity import IdentityCollector
from azure_tenant_audit.config import AuthConfig
from azure_tenant_audit.graph import (
    GraphClient,
    GraphError,
    graph_url,
    read_only_violation,
)
from azure_tenant_audit.scuba_assessment import (
    COLLECTOR_ERROR_CLASSES,
    collector_error_class,
)
from azure_tenant_audit.secret_hygiene import SENSITIVE_KEY_RE

SETTINGS = "https://graph.microsoft.com/beta/settings"
CONFIGURATIONS = "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations"
POLICIES = "/policies/appManagementPolicies"
CLASSIFICATIONS = "delegatedPermissionClassifications"
TARGETS = "appManagementPolicyAppliesTo"


class FakeClient:
    """Only GET interfaces; unconfigured reads return synthetic empty evidence."""

    def __init__(self, *, lists=None, objects=None, resources=None):
        self.lists = lists or {}
        self.objects = {"/policies/defaultAppManagementPolicy": {"id": "constructed-default"}, **(objects or {})}
        self.resources = resources or []
        self.calls = []

    def _get(self, path, params, source):
        self.calls.append(("GET", path, deepcopy(params or {})))
        assert read_only_violation("GET", path if path.startswith("https:") else graph_url(path), {}) is None
        value = source.get(path, [] if source is self.lists else {})
        if isinstance(value, Exception):
            raise value
        return deepcopy(value)

    def get_all(self, path, params=None):
        if path == "/servicePrincipals" and "$filter" in (params or {}):
            return self._get(path, params, {path: self.resources})
        return self._get(path, params, self.lists)

    def get_json(self, path, params=None, full_url=False):
        assert full_url is False
        return self._get(path, params, self.objects)

    def iter_pages(self, path, params=None):
        yield {"value": self.get_all(path, params)}


def run(collector, client, **context):
    result = collector().run({"client": client, **context})
    assert client.calls and all(method == "GET" for method, _, _ in client.calls)
    assert all("$batch" not in path for _, path, _ in client.calls)
    return result


def summary(result, name):
    return next(row for row in result.coverage if row["name"] == name and row["type"] == "derived")


def policies_client(count=2, **kwargs):
    lists = {POLICIES: [{"id": f"policy-{index}"} for index in range(count)]}
    objects = {f"{POLICIES}/policy-{index}/appliesTo": {"value": [{"id": f"target-{index}", "displayName": "Discard"}]} for index in range(count)}
    objects.update(kwargs.pop("objects", {}))
    return FakeClient(lists=lists, objects=objects, **kwargs)


def resources(count=2):
    return [{"id": f"resource-{index}", "appId": app_id, "displayName": f"Mock resource {index}"}
            for index, app_id in enumerate(RISKY_RESOURCE_APP_IDS[:count])]


def classification_path(index):
    return f"/servicePrincipals/resource-{index}/{CLASSIFICATIONS}"


def real_paging_client(monkeypatch, *, pages=None, lookup=...):
    """Constructed responses only; keep all three GraphClient paging methods real."""
    client = GraphClient(AuthConfig(tenant_id="constructed-tenant", client_id="constructed-client"))
    client.calls = []
    pages = pages or {}
    lookup = {"value": resources(1)} if lookup is ... else lookup

    def get_json(path, params=None, full_url=False):
        client.calls.append(("GET", path, deepcopy(params or {})))
        path = path.removeprefix("https://graph.microsoft.com/v1.0")
        response = lookup if path == "/servicePrincipals" and "$filter" in (params or {}) else pages.get(path, (
            {"id": "constructed-default"} if path == "/policies/defaultAppManagementPolicy" else {"value": []}
        ))
        if isinstance(response, Exception):
            raise response
        return deepcopy(response)

    def refuse_network(*args, **kwargs):
        pytest.fail("Constructed paging tests must not access the network")

    monkeypatch.setattr(client, "get_json", get_json)
    monkeypatch.setattr(client, "_request", refuse_network)
    return client


def test_new_endpoint_specs_versions_selects_and_inline_minimisation():
    configs = [{"id": "MicrosoftAuthenticator", "@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration",
                "featureSettings": {"displayAppInformationRequiredState": {"state": "enabled"}}, "isSoftwareOathEnabled": False}]
    chunks = []
    client = FakeClient(lists={CONFIGURATIONS: configs})
    auth = run(AuthMethodsCollector, client, top=200, page_size=17, chunk_writer=lambda *args: chunks.append(args))
    assert ("GET", CONFIGURATIONS, {}) in client.calls
    assert auth.payload["authenticationMethodConfigurations"]["value"] == configs
    assert auth.payload["authenticationMethodConfigurations"]["status"] == "ok"
    assert not any(args[1] == "authenticationMethodConfigurations" for args in chunks)

    client = policies_client(objects={"/policies/defaultAppManagementPolicy": {"id": "default", "servicePrincipalRestrictions": {"mockField": "retained"}}})
    client.lists[SETTINGS] = [
        {"id": "settings-1", "displayName": "Mock consent", "templateId": "template-1", "extra": "discard",
         "values": [{"name": "BannedPasswordList", "value": "DO-NOT-RETAIN"},
                    {"name": "EnableAdminConsentRequests", "value": "true", "extra": "discard"}]},
        {"id": "settings-2", "displayName": "Mock other", "templateId": "template-2",
         "values": [{"name": "BannedPasswordList", "value": "DO-NOT-RETAIN"}]},
    ]
    result = run(ConsentPolicyCollector, client, top=200, page_size=17, chunk_writer=lambda *args: chunks.append(args))
    assert result.status == "ok"
    assert ("GET", SETTINGS, {}) in client.calls
    assert ("GET", POLICIES, {}) in client.calls
    assert ("GET", "/policies/defaultAppManagementPolicy", {}) in client.calls
    assert result.payload["defaultAppManagementPolicy"]["servicePrincipalRestrictions"] == {"mockField": "retained"}
    assert result.payload["appManagementPolicies"]["value"] == client.lists[POLICIES]
    assert result.payload["directorySettings"]["value"] == [
        {"id": "settings-1", "displayName": "Mock consent", "templateId": "template-1",
         "values": [{"name": "EnableAdminConsentRequests", "value": "true"}]},
        {"id": "settings-2", "displayName": "Mock other", "templateId": "template-2", "values": []},
    ]
    assert "DO-NOT-RETAIN" not in json.dumps(result.payload)
    assert not any(args[1] in {"directorySettings", "appManagementPolicies"} for args in chunks)
    assert {row["name"] for row in result.coverage if row.get("api_version") == "beta"} == {"directorySettings"}
    assert all(row.get("api_version", "v1.0") == "v1.0" for row in auth.coverage)


def test_policy_targets_success_and_ids_only():
    client = policies_client()
    result = run(ConsentPolicyCollector, client)
    assert result.status == "ok"
    assert result.payload[TARGETS]["value"] == [
        {"policyId": f"policy-{index}", "appliesTo": [{"id": f"target-{index}"}], "appliesToTruncated": False}
        for index in range(2)
    ]
    calls = [call for call in client.calls if call[1].endswith("/appliesTo")]
    assert len(calls) == 2
    assert all(params == {"$select": "id", "$top": "50"} for _, _, params in calls)
    assert summary(result, TARGETS)["status"] == "ok"


@pytest.mark.parametrize("count", [1, 2])
def test_policy_target_failure_has_no_failed_row_or_empty_value(count):
    client = policies_client(count, objects={f"{POLICIES}/policy-0/appliesTo": GraphError("Synthetic refusal", status=403)})
    result = run(ConsentPolicyCollector, client)
    assert result.status == "partial"
    assert summary(result, TARGETS)["status"] != "ok"
    section = result.payload[TARGETS]
    assert section["status"] == "partial"
    assert all(row["policyId"] != "policy-0" for row in section.get("value", []))
    if count == 1:
        assert "value" not in section
    failure = next(row for row in result.coverage if row.get("policy_id") == "policy-0")
    assert failure["status"] == "failed" and failure["error_class"] == "insufficient_permissions"


def test_policy_cap_is_a_gap_with_one_missing_policy():
    client = policies_client(101)
    result = run(ConsentPolicyCollector, client)
    assert result.status == "partial"
    assert len(result.payload[TARGETS]["value"]) == 100
    assert "policy-100" not in {row["policyId"] for row in result.payload[TARGETS]["value"]}
    gap = summary(result, TARGETS)
    assert gap["truncation_reason"] == "fanout_limit" and gap["fanout_total"] == 101
    assert gap["fanout_limit"] == 100 and gap["status"] != "ok"
    assert len([call for call in client.calls if call[1].endswith("/appliesTo")]) == 100


@pytest.mark.parametrize(("target_count", "next_link"), [(51, False), (50, True), (1, True)])
def test_policy_target_cap_or_next_link_is_visible(target_count, next_link):
    targets = [{"id": f"target-{index}", "other": "discard"} for index in range(target_count)]
    response = {"value": targets, **({"@odata.nextLink": "https://graph.microsoft.com/v1.0/mock-next"} if next_link else {})}
    client = policies_client(1, objects={f"{POLICIES}/policy-0/appliesTo": response})
    result = run(ConsentPolicyCollector, client)
    row = result.payload[TARGETS]["value"][0]
    assert len(row["appliesTo"]) == min(target_count, 50) and row["appliesToTruncated"] is True
    assert all(set(target) == {"id"} for target in row["appliesTo"])
    assert result.status == "partial" and summary(result, TARGETS)["status"] != "ok"
    coverage = next(row for row in result.coverage if row.get("policy_id") == "policy-0")
    assert coverage["status"] == "partial" and coverage["truncation_reason"] == "fanout_limit"
    if next_link:
        assert "fanout_total" not in coverage
        assert "a next-page link indicates additional unread targets" in coverage["error"]
        assert f"first {target_count} were expanded" in coverage["error"]
    else:
        assert coverage["fanout_total"] == 51
        assert "first 50 of 51" in coverage["error"]


def test_empty_custom_policies_is_legal():
    result = run(ConsentPolicyCollector, FakeClient())
    assert result.status == "ok"
    assert result.payload["appManagementPolicies"]["value"] == []
    assert result.payload[TARGETS]["value"] == []
    assert summary(result, TARGETS)["status"] == "ok"


@pytest.mark.parametrize("failure", [True, False])
def test_policy_input_failure_or_operator_cut_is_not_a_complete_fanout(failure):
    client = policies_client()
    if failure:
        client.lists[POLICIES] = GraphError("Synthetic unavailable", status=500)
    result = run(ConsentPolicyCollector, client, top=None if failure else 1)
    assert result.status == "partial" and summary(result, TARGETS)["status"] != "ok"
    if failure:
        assert "value" not in result.payload[TARGETS]
        assert not any(path.endswith("/appliesTo") for _, path, _ in client.calls)
    else:
        assert summary(result, TARGETS)["truncation_reason"] == "input_limited"


def test_classifications_unfiltered_and_exact_eight_id_lookup():
    classes = [{"id": f"class-{i}", "permissionId": f"permission-{i}", "permissionName": f"Mock.Permission.{i}", "classification": level}
               for i, level in enumerate(("low", "medium", "high", "unrecognised"))]
    client = FakeClient(resources=resources(), lists={classification_path(0): classes, classification_path(1): []})
    result = run(AppConsentCollector, client, top=1)
    assert result.status == "ok"
    assert result.payload[CLASSIFICATIONS]["value"] == [
        {"servicePrincipalId": "resource-0", "appId": RISKY_RESOURCE_APP_IDS[0], "displayName": "Mock resource 0", "classifications": classes},
        {"servicePrincipalId": "resource-1", "appId": RISKY_RESOURCE_APP_IDS[1], "displayName": "Mock resource 1", "classifications": []},
    ]
    lookup = next(params for _, path, params in client.calls if path == "/servicePrincipals" and "$filter" in params)
    assert lookup["$select"] == "id,appId,displayName" and "$top" not in lookup
    assert re.findall(r"appId eq '([^']+)'", lookup["$filter"]) == list(RISKY_RESOURCE_APP_IDS)
    assert len(set(RISKY_RESOURCE_APP_IDS)) == 8
    assert lookup["$filter"] == " or ".join(f"appId eq '{value}'" for value in RISKY_RESOURCE_APP_IDS)
    calls = [call for call in client.calls if call[1].endswith("/" + CLASSIFICATIONS)]
    assert len(calls) == 2
    assert all(params == {"$select": "id,permissionId,permissionName,classification"} for _, _, params in calls)
    assert all(row.get("api_version", "v1.0") == "v1.0" for row in result.coverage)
    assert summary(result, CLASSIFICATIONS)["status"] == "ok"


@pytest.mark.parametrize("count", [0, 7])
def test_absent_resource_is_not_a_failure(count):
    client = FakeClient(resources=resources(count))
    result = run(AppConsentCollector, client)
    assert result.status == "ok" and summary(result, CLASSIFICATIONS)["status"] == "ok"
    assert len(result.payload[CLASSIFICATIONS]["value"]) == count


@pytest.mark.parametrize("count", [1, 2])
def test_classification_failure_has_no_failed_row_or_empty_value(count):
    client = FakeClient(resources=resources(count), lists={classification_path(0): GraphError("Synthetic refusal", status=403)})
    result = run(AppConsentCollector, client)
    assert result.status == "partial" and summary(result, CLASSIFICATIONS)["status"] != "ok"
    assert all(row["servicePrincipalId"] != "resource-0" for row in result.payload[CLASSIFICATIONS].get("value", []))
    if count == 1:
        assert "value" not in result.payload[CLASSIFICATIONS]


def test_lookup_failure_has_no_empty_value():
    client = FakeClient()
    client.resources = GraphError("Synthetic lookup failure", status=503)
    result = run(AppConsentCollector, client)
    assert result.status == "partial" and "value" not in result.payload[CLASSIFICATIONS]
    assert summary(result, CLASSIFICATIONS)["status"] != "ok"


@pytest.mark.parametrize("malformed", [None, {}, [{"id": None}]])
def test_malformed_policy_targets_fail_closed(monkeypatch, malformed):
    client = real_paging_client(monkeypatch, pages={
        POLICIES: {"value": [{"id": "policy-0"}]},
        f"{POLICIES}/policy-0/appliesTo": {"value": malformed},
    })
    result = run(ConsentPolicyCollector, client)
    assert result.status == "partial" and "value" not in result.payload[TARGETS]
    coverage = next(row for row in result.coverage if row.get("policy_id") == "policy-0")
    assert coverage["error_class"] == "incomplete_evidence"
    assert coverage["error_class"] in COLLECTOR_ERROR_CLASSES
    assert collector_error_class(coverage["error_class"]) == "incomplete_evidence"


@pytest.mark.parametrize("next_link", [[], {}, "", 0, False, None], ids=["list", "dict", "empty-string", "zero", "false", "null"])
def test_policy_targets_validate_next_link_with_real_client(monkeypatch, next_link):
    client = real_paging_client(monkeypatch, pages={
        POLICIES: {"value": [{"id": "policy-0"}]},
        f"{POLICIES}/policy-0/appliesTo": {"value": [{"id": "target-0"}], "@odata.nextLink": next_link},
    })
    result = run(ConsentPolicyCollector, client)
    if next_link is None:
        # Null is terminal, matching GraphClient.iter_pages.
        assert result.status == "ok"
        assert result.payload[TARGETS]["value"] == [
            {"policyId": "policy-0", "appliesTo": [{"id": "target-0"}], "appliesToTruncated": False},
        ]
    else:
        assert result.status == "partial" and "value" not in result.payload[TARGETS]
        assert summary(result, TARGETS)["fanout_complete"] is False
        failure = next(row for row in result.coverage if row.get("policy_id") == "policy-0")
        assert failure["status"] == "failed" and failure["item_count"] == 0
        assert failure["error_class"] == "incomplete_evidence"


@pytest.mark.parametrize("malformed", [None, {}, [None]])
def test_malformed_classifications_fail_closed(monkeypatch, malformed):
    client = real_paging_client(monkeypatch, pages={classification_path(0): {"value": malformed}})
    result = run(AppConsentCollector, client)
    assert result.status == "partial" and "value" not in result.payload[CLASSIFICATIONS]
    coverage = next(row for row in result.coverage if row.get("service_principal_id") == "resource-0")
    assert coverage["error_class"] == "incomplete_evidence"
    assert coverage["error_class"] in COLLECTOR_ERROR_CLASSES
    assert collector_error_class(coverage["error_class"]) == "incomplete_evidence"


@pytest.mark.parametrize("malformed_page", [
    {}, {"value": {}}, {"value": None}, {"value": "invalid"}, {"value": [None]}, None,
    *[pytest.param({"value": [], "@odata.nextLink": link}, id=f"next-link-{name}")
      for name, link in (("list", []), ("dict", {}), ("empty-string", ""), ("zero", 0), ("false", False))],
])
@pytest.mark.parametrize("later_page", [False, True])
@pytest.mark.parametrize("operation", ["lookup", "classifications"])
def test_real_paging_malformed_pages_withhold_affected_evidence(monkeypatch, operation, later_page, malformed_page):
    next_link = graph_url("/constructed-next")
    good_rows = resources(1) if operation == "lookup" else [{"id": "classification-0", "classification": "low"}]
    first_page = {"value": good_rows, "@odata.nextLink": next_link} if later_page else malformed_page
    pages = {"/constructed-next": malformed_page}
    if operation == "lookup":
        client = real_paging_client(monkeypatch, pages=pages, lookup=first_page)
    else:
        pages[classification_path(0)] = first_page
        client = real_paging_client(monkeypatch, pages=pages)
    result = run(AppConsentCollector, client)
    assert result.status == "partial"
    assert "value" not in result.payload[CLASSIFICATIONS]
    gap = summary(result, CLASSIFICATIONS)
    assert gap["status"] == "partial" and gap["fanout_complete"] is False
    failure = next(row for row in result.coverage if row["name"] == CLASSIFICATIONS and row["status"] == "failed")
    assert failure["item_count"] == 0
    assert failure["error_class"] == "incomplete_evidence"
    assert collector_error_class(failure["error_class"]) == "incomplete_evidence"
    if operation == "lookup":
        assert gap["input_complete"] is False
        assert not any(path.endswith("/" + CLASSIFICATIONS) for _, path, _ in client.calls)


@pytest.mark.parametrize("later_page", [False, True])
@pytest.mark.parametrize("operation", ["lookup", "classifications"])
def test_real_paging_null_next_link_ends_collection(monkeypatch, operation, later_page):
    rows = resources(1) if operation == "lookup" else [{"id": "classification-0", "classification": "low"}]
    terminal_page = {"value": rows, "@odata.nextLink": None}
    first_page = {"value": [], "@odata.nextLink": graph_url("/constructed-next")} if later_page else terminal_page
    pages = {"/constructed-next": terminal_page}
    if operation == "lookup":
        client = real_paging_client(monkeypatch, pages=pages, lookup=first_page)
    else:
        pages[classification_path(0)] = first_page
        client = real_paging_client(monkeypatch, pages=pages)
    result = run(AppConsentCollector, client)
    assert result.status == "ok"
    assert summary(result, CLASSIFICATIONS)["fanout_complete"] is True
    evidence = result.payload[CLASSIFICATIONS]["value"]
    assert len(evidence) == 1 and evidence[0]["servicePrincipalId"] == "resource-0"
    assert evidence[0]["classifications"] == ([] if operation == "lookup" else rows)
    assert any(path.endswith("/constructed-next") for _, path, _ in client.calls) is later_page


@pytest.mark.parametrize("unsafe_link", ["https://example.invalid/constructed-next",
                                          "http://graph.microsoft.com/v1.0/constructed-next", "/constructed-next"])
@pytest.mark.parametrize("later_page", [False, True])
@pytest.mark.parametrize("operation", ["lookup", "classifications"])
def test_real_paging_unsafe_next_link_preserves_named_refusal(monkeypatch, operation, later_page, unsafe_link):
    unsafe_page = {"value": [], "@odata.nextLink": unsafe_link}
    rows = resources(1) if operation == "lookup" else [{"id": "classification-0"}]
    first_page = {"value": rows, "@odata.nextLink": graph_url("/constructed-next")} if later_page else unsafe_page
    pages = {"/constructed-next": unsafe_page}
    if operation == "lookup":
        client = real_paging_client(monkeypatch, pages=pages, lookup=first_page)
    else:
        pages[classification_path(0)] = first_page
        client = real_paging_client(monkeypatch, pages=pages)
    result = run(AppConsentCollector, client)
    assert result.status == "partial" and "value" not in result.payload[CLASSIFICATIONS]
    failure = next(row for row in result.coverage if row["name"] == CLASSIFICATIONS and row["status"] == "failed")
    assert failure["error_class"] == "next_link_refused" and failure["item_count"] == 0
    assert summary(result, CLASSIFICATIONS)["error_class"] == "incomplete_evidence"
    assert not any("example.invalid" in path for _, path, _ in client.calls)


@pytest.mark.parametrize("later_page", [False, True])
@pytest.mark.parametrize("operation", ["lookup", "classifications"])
@pytest.mark.parametrize(("status", "error_class"), [(401, "unauthenticated"), (403, "insufficient_permissions"),
                                                     (404, "resource_not_found"), (503, "graph_transient")])
def test_real_paging_preserves_http_error_classes(monkeypatch, operation, status, error_class, later_page):
    failure = GraphError("Constructed HTTP failure", status=status)
    first = {"value": resources(1) if operation == "lookup" else [{"id": "constructed-classification"}],
             "@odata.nextLink": graph_url("/constructed-next")} if later_page else failure
    client = real_paging_client(monkeypatch, lookup=first, pages={"/constructed-next": failure}) if operation == "lookup" else real_paging_client(
        monkeypatch, pages={classification_path(0): first, "/constructed-next": failure})
    result = run(AppConsentCollector, client)
    assert result.status == "partial" and "value" not in result.payload[CLASSIFICATIONS]
    row = next(row for row in result.coverage if row["name"] == CLASSIFICATIONS and row["status"] == "failed")
    assert row["error_class"] == error_class


@pytest.mark.parametrize("empty_lookup", [False, True])
def test_real_paging_valid_empty_lists_are_success(monkeypatch, empty_lookup):
    client = real_paging_client(monkeypatch, lookup={"value": [] if empty_lookup else resources(1)})
    result = run(AppConsentCollector, client)
    assert result.status == "ok"
    expected = [] if empty_lookup else [{**resources(1)[0], "servicePrincipalId": "resource-0", "classifications": []}]
    if expected:
        expected[0].pop("id")
    assert result.payload[CLASSIFICATIONS]["value"] == expected


def test_real_paging_collects_all_valid_pages_and_keeps_successful_resources(monkeypatch):
    client = real_paging_client(monkeypatch, lookup={"value": resources(1), "@odata.nextLink": graph_url("/lookup-next")}, pages={
        "/lookup-next": {"value": resources(2)[1:]},
        classification_path(0): {"value": [{"id": "classification-0"}], "@odata.nextLink": graph_url("/classification-next")},
        "/classification-next": {"value": [{"id": "classification-1"}]},
        classification_path(1): {},
    })
    result = run(AppConsentCollector, client)
    assert result.status == "partial"
    assert result.payload[CLASSIFICATIONS]["value"] == [{
        "servicePrincipalId": "resource-0", "appId": RISKY_RESOURCE_APP_IDS[0], "displayName": "Mock resource 0",
        "classifications": [{"id": "classification-0"}, {"id": "classification-1"}],
    }]


def test_identity_domain_selector():
    client = FakeClient()
    result = run(IdentityCollector, client)
    assert result.status == "ok"
    params = next(params for _, path, params in client.calls if path == "/domains")
    assert params == {"$select": "id,authenticationType,isDefault,isVerified,isRoot,passwordValidityPeriodInDays"}
    assert "domains" in result.payload


def test_new_raw_names_are_not_sensitive_keys_and_scope_membership_is_unchanged():
    names = ["passwordValidityPeriodInDays", "authenticationMethodConfigurations", "directorySettings", "defaultAppManagementPolicy",
             "appManagementPolicies", TARGETS, CLASSIFICATIONS, "policyId", "appliesTo", "appliesToTruncated", "servicePrincipalId",
             "permissionId", "permissionName", "classification", "EnableAdminConsentRequests", "servicePrincipalRestrictions", "maxLifetime"]
    assert not [name for name in names if SENSITIVE_KEY_RE.search(name)]
    expected = {
        "identity": {"Directory.Read.All", "User.Read.All", "Group.Read.All", "Application.Read.All", "AuditLog.Read.All"},
        "auth_methods": {"Policy.Read.All", "Reports.Read.All"},
        "consent_policy": {"Policy.Read.All", "Directory.Read.All", "Policy.Read.PermissionGrant"},
        "app_consent": {"Directory.Read.All", "DelegatedPermissionGrant.Read.All", "Application.Read.All"},
    }
    definitions = json.loads(Path("configs/collector-definitions.json").read_text())
    permissions = json.loads(Path("configs/collector-permissions.json").read_text())
    for cls in (IdentityCollector, AuthMethodsCollector, ConsentPolicyCollector, AppConsentCollector):
        assert set(cls.required_permissions) == expected[cls.name]
        assert set(definitions["collectors"][cls.name]["required_permissions"]) == expected[cls.name]
        assert set(permissions["collector_permissions"][cls.name]["graph_scopes"]) == expected[cls.name]



@pytest.mark.parametrize("bad_input", [{}, None, [{"id": None}], [{"id": []}], [{"id": "duplicate"}, {"id": "duplicate"}]])
def test_malformed_policy_inventory_has_no_empty_success(bad_input):
    result = run(ConsentPolicyCollector, FakeClient(lists={POLICIES: bad_input}))
    assert result.status == "partial"
    assert "value" not in result.payload[TARGETS]
    assert summary(result, TARGETS)["status"] != "ok"


@pytest.mark.parametrize("bad_input", [{}, None, [{"id": [], "appId": []}], resources(1) * 2])
def test_malformed_resource_lookup_has_no_empty_success(bad_input):
    client = FakeClient()
    client.resources = bad_input
    result = run(AppConsentCollector, client)
    assert result.status == "partial"
    assert "value" not in result.payload[CLASSIFICATIONS]
    assert summary(result, CLASSIFICATIONS)["status"] != "ok"
    assert not any(path.endswith("/" + CLASSIFICATIONS) for _, path, _ in client.calls)


def test_overfull_resource_lookup_is_a_gap_and_fanout_is_bounded():
    client = FakeClient(resources=resources(8) + [{"id": "resource-extra", "appId": RISKY_RESOURCE_APP_IDS[0]}])
    result = run(AppConsentCollector, client)
    assert result.status == "partial" and "value" not in result.payload[CLASSIFICATIONS]
    gap = summary(result, CLASSIFICATIONS)
    assert gap["truncation_reason"] == "fanout_limit" and gap["fanout_total"] == 9
    assert not any(path.endswith("/" + CLASSIFICATIONS) for _, path, _ in client.calls)


@pytest.mark.parametrize("bad_settings", [
    {"value": {"values": [{"name": "BannedPasswordList", "value": "DO-NOT-RETAIN"}]}},
    [{"id": "group-1", "values": {"BannedPasswordList": "DO-NOT-RETAIN"}}],
    [{"id": "group-1", "values": [None]}],
])
def test_malformed_directory_settings_withhold_raw_values(bad_settings):
    result = run(ConsentPolicyCollector, FakeClient(lists={SETTINGS: bad_settings}))
    assert result.status == "partial"
    assert "DO-NOT-RETAIN" not in json.dumps(result.payload)
    assert "value" not in result.payload["directorySettings"]
    coverage = next(row for row in result.coverage if row["name"] == "directorySettings")
    assert coverage["status"] == "failed" and coverage["error_class"] == "incomplete_evidence"
    assert result.payload["directorySettings"]["error_class"] == "incomplete_evidence"


def test_capped_target_get_stays_visible_in_api_inventory():
    from azure_tenant_audit.api_inventory import ApiInventoryRecorder

    client = policies_client(1, objects={f"{POLICIES}/policy-0/appliesTo": {
        "value": [{"id": f"target-{index}"} for index in range(51)]}})
    result = run(ConsentPolicyCollector, client)
    recorder = ApiInventoryRecorder(platform="m365", capability_rows=[])
    recorder.record_many(result.coverage)
    observed = recorder.observed_calls()
    target = next(call for call in observed if call["endpoint"].endswith("/appliesTo"))
    assert target["method"] == "GET" and target["status"] == "partial"
    settings = next(call for call in observed if call["endpoint"].endswith("/settings"))
    assert settings["api_version"] == "beta"


def test_directory_settings_envelope_cannot_carry_unminimised_values(monkeypatch):
    client = real_paging_client(monkeypatch, pages={SETTINGS: {"value": [], "values": [
        {"name": "BannedPasswordList", "value": "DO-NOT-RETAIN"}]}})
    result = run(ConsentPolicyCollector, client)
    assert result.status == "ok"
    assert result.payload["directorySettings"]["value"] == []
    assert "DO-NOT-RETAIN" not in json.dumps(result.payload)


def test_new_operations_are_declared_for_offline_replay_and_documented():
    definitions = json.loads(Path("configs/collector-definitions.json").read_text())["collectors"]
    catalog = Path("docs/reference/api-call-catalog.md").read_text()
    expected = {
        "auth_methods": {"authenticationMethodConfigurations"},
        "consent_policy": {"directorySettings", "defaultAppManagementPolicy", "appManagementPolicies", TARGETS},
        "app_consent": {CLASSIFICATIONS},
    }
    for collector, operations in expected.items():
        assert operations <= set(definitions[collector]["query_plan"])
        assert all(f"{collector}.{operation}" in catalog for operation in operations)
    assert definitions["consent_policy"]["description"] == ConsentPolicyCollector.description


# Each endpoint below is a list introduced by aadsp-1. Existing lists retain their
# previous behaviour; the risky lookup and classifications use the same validator.
STRICT_LISTS = [
    pytest.param(ConsentPolicyCollector, SETTINGS, "directorySettings", id="directory-settings"),
    pytest.param(ConsentPolicyCollector, POLICIES, "appManagementPolicies", id="app-policies"),
    pytest.param(AuthMethodsCollector, CONFIGURATIONS, "authenticationMethodConfigurations", id="auth-configurations"),
]
BAD_PAGES = [
    {}, None, [], "invalid", {"value": None}, {"value": {}}, {"value": "invalid"}, {"value": [None]},
    *[pytest.param({"value": [], "@odata.nextLink": link}, id=f"next-link-{name}")
      for name, link in (("false", False), ("empty", ""), ("zero", 0), ("list", []), ("object", {}))],
]
UNSAFE_LINKS = ["http://graph.microsoft.com/v1.0/constructed-next",
                "https://example.invalid/constructed-next", "/constructed-next"]


def failed_read(result, name):
    row = next(row for row in result.coverage if row["name"] == name and row["type"] == "graph")
    assert result.status == "partial" and row["status"] == "failed"
    assert row["item_count"] == 0
    section = result.payload[name]
    assert "value" not in section and "sample" not in section and "chunk_files" not in section
    assert any(row["name"] == name and row["error_class"] == "incomplete_evidence" for row in result.coverage)
    if name == "appManagementPolicies":
        assert "value" not in result.payload[TARGETS]
    return row


@pytest.mark.parametrize(("collector", "endpoint", "name"), STRICT_LISTS)
@pytest.mark.parametrize("later_page", [False, True])
@pytest.mark.parametrize("bad_page", BAD_PAGES)
def test_new_lists_validate_original_first_and_later_pages(monkeypatch, collector, endpoint, name, later_page, bad_page):
    first = {"value": [{"id": "constructed-prefix"}], "@odata.nextLink": graph_url("/constructed-next")} if later_page else bad_page
    client = real_paging_client(monkeypatch, pages={endpoint: first, "/constructed-next": bad_page})
    result = run(collector, client)
    assert failed_read(result, name)["error_class"] == "incomplete_evidence"
    assert "constructed-prefix" not in json.dumps(result.payload[name])
    assert not any(path.endswith("/appliesTo") for _, path, _ in client.calls)


@pytest.mark.parametrize(("collector", "endpoint", "name"), STRICT_LISTS)
@pytest.mark.parametrize("later_page", [False, True])
@pytest.mark.parametrize("unsafe_link", UNSAFE_LINKS)
def test_new_lists_refuse_unsafe_first_and_later_links(monkeypatch, collector, endpoint, name, later_page, unsafe_link):
    bad = {"value": [{"id": "constructed-unsafe"}], "@odata.nextLink": unsafe_link}
    first = {"value": [{"id": "constructed-prefix"}], "@odata.nextLink": graph_url("/constructed-next")} if later_page else bad
    client = real_paging_client(monkeypatch, pages={endpoint: first, "/constructed-next": bad})
    result = run(collector, client)
    assert failed_read(result, name)["error_class"] == "next_link_refused"
    assert not any(path == unsafe_link for _, path, _ in client.calls)


@pytest.mark.parametrize(("collector", "endpoint", "name"), STRICT_LISTS)
@pytest.mark.parametrize("later_page", [False, True])
@pytest.mark.parametrize(("status", "error_class"), [(401, "unauthenticated"), (403, "insufficient_permissions"),
                                                     (404, "resource_not_found"), (503, "graph_transient")])
def test_new_lists_withhold_http_failure_prefixes(monkeypatch, collector, endpoint, name, later_page, status, error_class):
    failure = GraphError("Constructed HTTP failure", status=status)
    first = {"value": [{"id": "constructed-prefix"}], "@odata.nextLink": graph_url("/constructed-next")} if later_page else failure
    client = real_paging_client(monkeypatch, pages={endpoint: first, "/constructed-next": failure})
    result = run(collector, client)
    assert failed_read(result, name)["error_class"] == error_class
    assert not any(path.endswith("/appliesTo") for _, path, _ in client.calls)


@pytest.mark.parametrize(("collector", "endpoint", "name"), STRICT_LISTS)
@pytest.mark.parametrize("later_page", [False, True])
@pytest.mark.parametrize("empty", [False, True])
def test_new_lists_accept_empty_and_null_terminal_pages(monkeypatch, collector, endpoint, name, later_page, empty):
    rows = [] if empty else [{"id": "constructed-policy"}]
    terminal = {"value": rows, "@odata.nextLink": None}
    first = {"value": [], "@odata.nextLink": graph_url("/constructed-next")} if later_page else terminal
    client = real_paging_client(monkeypatch, pages={endpoint: first, "/constructed-next": terminal,
                                                f"{POLICIES}/constructed-policy/appliesTo": {"value": []}})
    result = run(collector, client)
    assert result.status == "ok"
    expected = [{"id": "constructed-policy", "values": []}] if name == "directorySettings" and rows else rows
    assert result.payload[name]["value"] == expected


@pytest.mark.parametrize("bad_object", [{}, None, [], "invalid", 0, False, {"isEnabled": True},
                                        {"id": None}, {"id": ""}, {"id": []}, {"id": 0}])
def test_default_policy_requires_nonempty_object_and_id(monkeypatch, bad_object):
    client = real_paging_client(monkeypatch, pages={"/policies/defaultAppManagementPolicy": bad_object})
    result = run(ConsentPolicyCollector, client)
    row = failed_read(result, "defaultAppManagementPolicy")
    assert row["error_class"] == "incomplete_evidence"
    assert set(result.payload["defaultAppManagementPolicy"]) == {"status", "error", "error_class"}


def test_default_policy_accepts_valid_object_without_filtering_policy_fields(monkeypatch):
    policy = {"id": "constructed-default", "isEnabled": False, "applicationRestrictions": {"passwordCredentials": []}}
    client = real_paging_client(monkeypatch, pages={"/policies/defaultAppManagementPolicy": policy})
    result = run(ConsentPolicyCollector, client)
    assert result.status == "ok"
    assert result.payload["defaultAppManagementPolicy"] == {**policy, "status": "ok"}


def cycling_client(monkeypatch, operation, *, rows, two_page=False, bounded=False):
    endpoints = {"settings": (ConsentPolicyCollector, SETTINGS, "directorySettings"),
                 "policies": (ConsentPolicyCollector, POLICIES, "appManagementPolicies"),
                 "configurations": (AuthMethodsCollector, CONFIGURATIONS, "authenticationMethodConfigurations"),
                 "lookup": (AppConsentCollector, "/servicePrincipals", CLASSIFICATIONS),
                 "classifications": (AppConsentCollector, classification_path(0), CLASSIFICATIONS)}
    collector, endpoint, name = endpoints[operation]
    values = (resources(1) if operation == "lookup" else [{"id": "constructed-cycle"}]) if rows else []
    page = {"value": values, "@odata.nextLink": graph_url("/cycle-a")}
    pages = {"/cycle-a": {"value": values, "@odata.nextLink": graph_url("/cycle-b" if two_page or bounded else "/cycle-a")},
             "/cycle-b": {"value": values, "@odata.nextLink": graph_url("/cycle-c" if bounded else "/cycle-a")}}
    if operation == "lookup":
        client = real_paging_client(monkeypatch, lookup=page, pages=pages)
    else:
        pages[endpoint] = page
        client = real_paging_client(monkeypatch, pages=pages)
    return collector, name, client


@pytest.mark.parametrize("operation", ["settings", "policies", "configurations", "lookup", "classifications"])
@pytest.mark.parametrize("rows", [False, True], ids=["empty", "nonempty"])
@pytest.mark.parametrize("two_page", [False, True], ids=["self-cycle", "two-page-cycle"])
def test_real_client_cycles_withhold_whole_section(monkeypatch, operation, rows, two_page):
    collector, name, client = cycling_client(monkeypatch, operation, rows=rows, two_page=two_page)
    result = run(collector, client)
    if name == CLASSIFICATIONS:
        assert result.status == "partial" and "value" not in result.payload[name]
        assert summary(result, name)["error_class"] == "incomplete_evidence"
        failures = [row for row in result.coverage if row["name"] == name and row["status"] == "failed"]
        assert len(failures) == 1 and failures[0]["error_class"] == "incomplete_evidence"
        assert failures[0]["item_count"] == 0
    else:
        assert failed_read(result, name)["error_class"] == "incomplete_evidence"
    cycle_calls = [path for _, path, _ in client.calls if "/cycle-" in path]
    assert len(cycle_calls) == (2 if two_page else 1)
    assert len(set(cycle_calls)) == len(cycle_calls)


@pytest.mark.parametrize("operation", ["settings", "policies", "configurations", "lookup", "classifications"])
@pytest.mark.parametrize("rows", [False, True], ids=["empty", "nonempty"])
@pytest.mark.parametrize("bound_source", ["client", "strict"])
def test_real_client_page_bound_withholds_whole_section(monkeypatch, operation, rows, bound_source):
    from azure_tenant_audit.collectors import base

    collector, name, client = cycling_client(monkeypatch, operation, rows=rows, bounded=True)
    if bound_source == "client":
        client.max_pages = 2
    else:
        assert client.max_pages is None
        monkeypatch.setattr(base, "STRICT_MAX_PAGES", 2)
    result = run(collector, client)
    if name == CLASSIFICATIONS:
        assert result.status == "partial" and "value" not in result.payload[name]
        assert summary(result, name)["error_class"] == "incomplete_evidence"
    else:
        assert failed_read(result, name)["error_class"] == "incomplete_evidence"
    assert sum("/cycle-" in path for _, path, _ in client.calls) == (1 if bound_source == "client" else 2)


@pytest.mark.parametrize("unsafe_link", UNSAFE_LINKS)
@pytest.mark.parametrize("later_policy", [False, True])
def test_targets_refuse_unsafe_links_before_adding_derived_row(monkeypatch, unsafe_link, later_policy):
    policy_id = "policy-1" if later_policy else "policy-0"
    pages = {POLICIES: {"value": [{"id": "policy-0"}, *([{"id": "policy-1"}] if later_policy else [])]},
             f"{POLICIES}/policy-0/appliesTo": {"value": [{"id": "constructed-good-target"}]},
             f"{POLICIES}/{policy_id}/appliesTo": {"value": [{"id": "constructed-unsafe-target"}], "@odata.nextLink": unsafe_link}}
    client = real_paging_client(monkeypatch, pages=pages)
    result = run(ConsentPolicyCollector, client)
    assert result.status == "partial" and summary(result, TARGETS)["error_class"] == "incomplete_evidence"
    assert all(row["policyId"] != policy_id for row in result.payload[TARGETS].get("value", []))
    assert ("value" in result.payload[TARGETS]) is later_policy
    failure = next(row for row in result.coverage if row.get("policy_id") == policy_id)
    assert failure["error_class"] == "next_link_refused" and failure["item_count"] == 0
    assert not any(path == unsafe_link for _, path, _ in client.calls)


@pytest.mark.parametrize("target_count", [1, 50, 51])
def test_real_client_valid_target_next_link_preserves_50_target_cap(monkeypatch, target_count):
    next_link = graph_url("/unread-targets")
    client = real_paging_client(monkeypatch, pages={
        POLICIES: {"value": [{"id": "constructed-policy"}]},
        f"{POLICIES}/constructed-policy/appliesTo": {
            "value": [{"id": f"constructed-target-{i}"} for i in range(target_count)], "@odata.nextLink": next_link},
    })
    result = run(ConsentPolicyCollector, client)
    target = result.payload[TARGETS]["value"][0]
    assert target["appliesToTruncated"] is True
    assert len(target["appliesTo"]) == min(target_count, 50)
    row = next(row for row in result.coverage if row.get("policy_id") == "constructed-policy")
    assert row["status"] == "partial" and row["truncation_reason"] == "fanout_limit"
    assert "fanout_total" not in row
    assert not any(path == next_link for _, path, _ in client.calls)
