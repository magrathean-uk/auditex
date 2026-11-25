"""M13 L03: the Policy API read widened to the SCuBA setting types, minimised, with a completeness signal.

Synthetic data only; every expected value is a literal.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from auditex.google_workspace import client as client_module
from auditex.google_workspace.client import GoogleWorkspaceClient
from auditex.google_workspace.collectors import (
    COLLECTOR_SECTIONS,
    GooglePoliciesCollector,
)
from auditex.google_workspace.findings import build_google_findings
from auditex.google_workspace.normalize import build_google_normalized_snapshot
from azure_tenant_audit.data_minimisation import (
    minimise_policy_settings,
    minimise_user_text,
)

ADDRESSES = ("partner@example.org", "alerts@example.com", "ops@example.net")

FILTER = (
    'customer == "customers/C123" && '
    "setting.type.matches('^settings/((gmail|security|drive_and_docs|calendar|chat|meet|classroom|"
    "groups_for_business|sites|takeout|data_regions|workspace_marketplace|api_controls|provisioning|multi_party_approval|"
    "enterprise_service_restrictions|early_access_apps|gemini_app|access_approval|access_management)"
    r"\\..*|blogger\\.user_takeout|books\\.user_takeout|location_history\\.user_takeout|maps\\.user_takeout|"
    r"pay\\.user_takeout|photos\\.user_takeout|play\\.user_takeout|play_console\\.user_takeout|youtube\\.user_takeout|"
    r"rule\\.system_defined_alerts)$')"
)


class _Credentials:
    def __init__(self, subject: str | None = None, scopes: tuple[str, ...] = ()) -> None:
        self.subject = subject
        self.scopes = scopes

    def with_subject(self, subject: str) -> _Credentials:
        return _Credentials(subject, self.scopes)

    def with_scopes(self, scopes: list[str]) -> _Credentials:
        return _Credentials(self.subject, tuple(scopes))


class _Request:
    def __init__(self, payload: dict[str, Any] | Exception) -> None:
        self.payload = payload

    def execute(self) -> dict[str, Any]:
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


class _Policies:
    """A Cloud Identity ``policies`` resource with ``list`` only: any other method call fails the test."""

    def __init__(self, rows: list[dict[str, Any]], *, fail_after_first_page: bool = False) -> None:
        self.rows = rows
        self.calls: list[dict[str, Any]] = []
        self.fail_after_first_page = fail_after_first_page

    def policies(self) -> _Policies:
        return self

    def list(self, **kwargs: Any) -> _Request:
        self.calls.append(kwargs)
        size = kwargs.get("pageSize") or 100
        start = int(kwargs.get("pageToken") or 0)
        if start and self.fail_after_first_page:
            return _Request(RuntimeError("page refused"))
        payload: dict[str, Any] = {"policies": self.rows[start : start + size]}
        if start + size < len(self.rows):
            payload["nextPageToken"] = str(start + size)
        return _Request(payload)


def _two_step_root() -> dict[str, Any]:
    return {
        "name": "policies/p-2sv",
        "customer": "customers/C123",
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
        "setting": {"type": "settings/security.two_step_verification_enforcement", "value": {"enforcedFrom": "2020-01-01T00:00:00Z"}},
        "type": "ADMIN",
    }


def _rows() -> list[dict[str, Any]]:
    return [
        _two_step_root(),
        {
            "name": "policies/p-lists",
            "customer": "customers/C123",
            "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
            "setting": {
                "type": "settings/gmail.email_address_lists",
                "value": {
                    "emailAddressList": [
                        {
                            "id": "list-1",
                            "name": "Partners",
                            "addressList": {"address": [{"address": "partner@example.org"}, {"address": "example.net"}]},
                        },
                        {"id": "list-2", "name": "Blocked", "blockedAddressList": {"address": [{"address": "example.com"}]}},
                    ]
                },
            },
            "type": "ADMIN",
        },
        {
            "name": "policies/p-spam",
            "customer": "customers/C123",
            "policyQuery": {"orgUnit": "orgUnits/sales", "sortOrder": 2},
            "setting": {
                "type": "settings/gmail.spam_override_lists",
                "value": {"spamOverride": [{"ruleId": "list-1", "description": "Ask ops@example.net", "bypassSelectedSenders": True, "bypassSenderAllowlist": ["list-1"]}]},
            },
            "type": "ADMIN",
        },
        {
            "name": "policies/p-alerts",
            "customer": "customers/C123",
            "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
            "setting": {
                "type": "settings/rule.system_defined_alerts",
                "value": {"displayName": "Leaked password", "state": "ACTIVE", "action": {"recipients": ["alerts@example.com"]}},
            },
            "type": "SYSTEM",
        },
        {
            "name": "policies/p-group",
            "customer": "customers/C123",
            "policyQuery": {"group": "groups/g1", "orgUnit": "orgUnits/root", "sortOrder": 5},
            "setting": {"type": "settings/drive_and_docs.external_sharing", "value": {}},
            "type": "ADMIN",
        },
    ]


def _client(service: _Policies, *, page_size: int = 100) -> GoogleWorkspaceClient:
    client = GoogleWorkspaceClient(_Credentials("admin@example.com"), customer_id="C123", page_size=page_size, delegated=True)
    assert client._services is not None
    client._services[("cloudidentity", "v1")] = service
    return client


def _normalise(payload: dict[str, Any], status: str, coverage: list[dict[str, Any]], directory: dict[str, Any] | None = None) -> dict[str, Any]:
    payloads: dict[str, dict[str, Any]] = {"google_policies": payload}
    if directory is not None:
        payloads["google_directory"] = directory
    return build_google_normalized_snapshot(
        tenant_name="T",
        run_id="r1",
        collector_payloads=payloads,
        result_rows=[{"name": "google_policies", "status": status}, {"name": "google_directory", "status": "ok"}],
        coverage_rows=coverage,
    )


def _read_state(normalized: dict[str, Any], section: str = "google_policy_settings") -> dict[str, Any]:
    (state,) = [item for item in normalized[section]["records"] if item["id"] == "read_state"]
    return state


def test_the_filter_is_the_pinned_allow_list_and_never_requests_dlp_rules() -> None:
    service = _Policies(_rows())
    GooglePoliciesCollector().run({"client": _client(service)})

    assert [call["filter"] for call in service.calls] == [FILTER]
    pattern = re.compile(FILTER.split("matches('", 1)[1][: -len("')")].replace("\\\\", "\\"))
    assert pattern.match("settings/rule.dlp") is None
    assert pattern.match("settings/rule.system_defined_alerts") is not None
    assert pattern.match("settings/rule.system_defined_alerts_extra") is None
    assert pattern.match("settings/gmail.email_address_lists") is not None
    assert pattern.match("settings/appsheet.service_status") is None


def test_one_read_fills_the_unchanged_two_step_payload_and_a_minimised_settings_payload() -> None:
    service = _Policies(_rows())
    result = GooglePoliciesCollector().run({"client": _client(service)})

    assert result.status == "ok" and result.item_count == 5
    assert COLLECTOR_SECTIONS["google_policies"] == ("twoStepVerificationPolicies", "policySettings")
    # The 2-step verification subset keeps today's raw shape, without the customer id and the policy's resource name.
    assert result.payload["twoStepVerificationPolicies"] == {
        "value": [
            {
                "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
                "setting": {"type": "settings/security.two_step_verification_enforcement", "value": {"enforcedFrom": "2020-01-01T00:00:00Z"}},
                "type": "ADMIN",
            }
        ]
    }
    assert "customers/" not in json.dumps(result.payload) and "policies/" not in json.dumps(result.payload)
    assert result.payload["policySettings"] == {
        "value": [
            {
                "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
                "setting": {"type": "settings/security.two_step_verification_enforcement", "value": {"enforcedFrom": "2020-01-01T00:00:00Z"}},
                "type": "ADMIN",
            },
            {
                "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
                "setting": {
                    "type": "settings/gmail.email_address_lists",
                    "value": {
                        "emailAddressList": [
                            {"id": "list-1", "entry_count": 2, "domain_entry_count": 1},
                            {"id": "list-2", "entry_count": 1, "domain_entry_count": 1},
                        ]
                    },
                },
                "type": "ADMIN",
            },
            {
                "policyQuery": {"orgUnit": "orgUnits/sales", "sortOrder": 2},
                "setting": {"type": "settings/gmail.spam_override_lists", "value": {"spamOverride": [{"ruleId": "list-1", "bypassSelectedSenders": True, "bypassSenderAllowlist": ["list-1"]}]}},
                "type": "ADMIN",
            },
            {
                "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
                "setting": {
                    "type": "settings/rule.system_defined_alerts",
                    "value": {"displayName": "Leaked password", "state": "ACTIVE"},
                },
                "type": "SYSTEM",
            },
            {
                "policyQuery": {"group": "groups/g1", "orgUnit": "orgUnits/root", "sortOrder": 5},
                "setting": {"type": "settings/drive_and_docs.external_sharing", "value": {}},
                "type": "ADMIN",
            },
        ]
    }
    text = json.dumps(result.payload["policySettings"])
    assert not any(address in text for address in ADDRESSES)
    assert "customers/" not in text and "C123" not in text and "policies/" not in text
    assert "Partners" not in text and "Ask " not in text
    (row,) = result.coverage
    assert row["name"] == "policySettings" and row["status"] == "ok" and row["collection_truncated"] is False


def test_the_normalised_settings_hold_sections_units_and_values_and_no_address() -> None:
    service = _Policies(_rows())
    result = GooglePoliciesCollector().run({"client": _client(service)})

    normalized = _normalise(result.payload, result.status, result.coverage, _SALES_DIRECTORY)

    records = normalized["google_policy_settings"]["records"]
    assert [(r["section"], r["unit_kind"], r.get("org_unit"), r.get("group"), r.get("sort_order"), r.get("policy_type")) for r in records[:-1]] == [
        ("security_two_step_verification_enforcement", "org_unit", "root", None, 1, "ADMIN"),
        ("gmail_email_address_lists", "org_unit", "root", None, 1, "ADMIN"),
        ("gmail_spam_override_lists", "org_unit", "sales", None, 2, "ADMIN"),
        ("rule_system_defined_alerts", "org_unit", "root", None, 1, "SYSTEM"),
        ("drive_and_docs_external_sharing", "group", "root", "g1", 5, "ADMIN"),
    ]
    assert records[1]["value"] == {
        "emailAddressList": [
            {"id": "list-1", "entry_count": 2, "domain_entry_count": 1},
            {"id": "list-2", "entry_count": 1, "domain_entry_count": 1},
        ]
    }
    assert records[4]["value"] == {}  # an empty value is a setting at its defaults and stays
    assert records[-1] == {
        "kind": "google_policy_settings_read_state",
        "source": "google_policies.policySettings",
        "id": "read_state",
        "key": "google_policy_settings_read_state:read_state",
        "complete": True,
        "record_count": 5,
        "malformed_count": 0,
        "unusable_sections": [],
        "unusable_scopes": [],
    }
    text = json.dumps(normalized["google_policy_settings"])
    assert not any(address in text for address in ADDRESSES)
    assert "customers/" not in text and "C123" not in text and "policies/" not in text
    # The 2-step verification view is the one it was before the widening.
    assert normalized["snapshot"]["two_step_policy_status"] == "enforcing"
    assert [r["setting_type"] for r in normalized["google_two_step_policies"]["records"]] == ["security.two_step_verification_enforcement"]


def test_raw_addresses_in_a_replayed_sample_never_reach_the_normalised_or_written_output() -> None:
    raw = _rows()
    # Normalised straight from an unminimised sample.
    normalized = _normalise({"policySettings": {"value": raw}}, "ok", [])
    text = json.dumps(normalized["google_policy_settings"])
    assert not any(address in text for address in ADDRESSES)
    # The bundle writer's pass (minimise_user_text) leaves no address in a raw policy object either.
    written = json.dumps(minimise_user_text({"policySettings": {"value": raw}}))
    assert not any(address in written for address in ADDRESSES)
    assert minimise_policy_settings(minimise_policy_settings(raw)) == minimise_policy_settings(raw)


def test_an_address_list_whose_entries_cannot_be_read_has_unknown_counts_not_zero() -> None:
    policies = [
        {
            "policyQuery": {"orgUnit": "orgUnits/root"},
            "setting": {
                "type": "settings/gmail.email_address_lists",
                "value": {
                    "emailAddressList": [
                        {"id": "a", "addressList": {"address": "partner@example.org"}},
                        {"id": "b", "addressList": {"address": [{"address": 7}]}},
                        {"id": "c"},
                        {"id": "d", "addressList": {}},
                    ]
                },
            },
        }
    ]

    (policy,) = minimise_policy_settings(policies)

    assert policy["setting"]["value"] == {
        "emailAddressList": [
            {"id": "a", "entry_count": None, "domain_entry_count": None},
            {"id": "b", "entry_count": None, "domain_entry_count": None},
            {"id": "c", "entry_count": None, "domain_entry_count": None},
            {"id": "d", "entry_count": 0, "domain_entry_count": 0},
        ]
    }


def test_the_operator_top_never_cuts_the_policies_read_so_two_step_matches_the_uncut_read() -> None:
    # Four SCuBA settings first, then the shipped sample's three 2-step verification policies, read two per page with
    # ``--top 1``: the read must still finish, and the 2SV records and finding must be those of the uncut read on main.
    sample = json.loads(Path("examples/google_workspace_sample.json").read_text(encoding="utf-8"))
    widened = _rows()[1:]
    for policy in widened:
        policy["policyQuery"]["orgUnit"] += "-ou"
    service = _Policies(widened + sample["google_policies"]["twoStepVerificationPolicies"]["value"])
    result = GooglePoliciesCollector().run({"client": _client(service, page_size=2), "top": 1})

    assert result.status == "ok"
    (row,) = result.coverage
    assert (row["name"], row["status"], row["collection_truncated"], row.get("result_limit")) == ("policySettings", "ok", False, None)
    assert [call["pageSize"] for call in service.calls] == [2, 2, 2, 2]
    assert len(result.payload["policySettings"]["value"]) == 7
    normalized = _normalise(result.payload, result.status, result.coverage, directory=sample["google_directory"])
    assert _read_state(normalized)["complete"] is True
    assert normalized["snapshot"]["two_step_policy_status"] == "partial"
    assert [
        (r["id"], r["policy_scope"], r["org_unit"], r["setting_type"], r.get("enforced_from"), r["source"])
        for r in normalized["google_two_step_policies"]["records"]
    ] == [
        ("security.two_step_verification_enforcement:orgUnits/root-ou", "organisation", "orgUnits/root-ou", "security.two_step_verification_enforcement", None, "google_policies.twoStepVerificationPolicies"),
        ("security.two_step_verification_enforcement:orgUnits/sales-ou", "org_unit", "orgUnits/sales-ou", "security.two_step_verification_enforcement", "2020-01-01T00:00:00Z", "google_policies.twoStepVerificationPolicies"),
        ("security.two_step_verification_enrollment:orgUnits/root-ou", "organisation", "orgUnits/root-ou", "security.two_step_verification_enrollment", None, "google_policies.twoStepVerificationPolicies"),
    ]
    findings = build_google_findings(normalized, now=datetime(2026, 11, 25, tzinfo=UTC))
    (finding,) = [item for item in findings if item["rule_id"] == "google.org_2sv_policy_not_enforced"]
    assert (finding["id"], finding["severity"]) == ("google.org_2sv_policy_not_enforced:organisation", "medium")
    assert finding["returned_value"] == {
        "status": "partial",
        "policies_read": 3,
        "organisation_level": "not in force",
        "enforced_scopes": [{"scope": "org_unit", "org_unit": "orgUnits/sales-ou", "enforced_from": "2020-01-01T00:00:00Z"}],
    }
    assert [ref["record_key"] for ref in finding["evidence_refs"]] == [
        "google_two_step_policy:security.two_step_verification_enforcement:orgUnits/root-ou",
        "google_two_step_policy:security.two_step_verification_enforcement:orgUnits/sales-ou",
    ]


def test_a_read_cut_at_the_safety_cap_is_partial_and_incomplete(monkeypatch: Any) -> None:
    monkeypatch.setattr(client_module, "POLICY_SETTINGS_ROW_CAP", 2)
    service = _Policies(_rows())
    result = GooglePoliciesCollector().run({"client": _client(service, page_size=100)})

    assert result.status == "partial"
    (row,) = result.coverage
    assert (row["status"], row["collection_truncated"], row["truncation_reason"], row["result_limit"]) == (
        "partial",
        True,
        "pagination_not_followed",
        2,
    )
    assert row["error"] == "policySettings: collection stopped because the collector's safety cap of 2 rows was hit; the list is incomplete."
    assert len(result.payload["policySettings"]["value"]) == 2
    normalized = _normalise(result.payload, result.status, result.coverage)
    assert _read_state(normalized)["complete"] is False
    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"


def test_a_later_page_error_makes_the_read_partial_and_incomplete() -> None:
    service = _Policies(_rows(), fail_after_first_page=True)
    result = GooglePoliciesCollector().run({"client": _client(service, page_size=2)})

    assert result.status == "partial"
    (row,) = result.coverage
    assert row["status"] == "partial" and row["collection_truncated"] is True
    assert len(result.payload["policySettings"]["value"]) == 2
    normalized = _normalise(result.payload, result.status, result.coverage)
    assert _read_state(normalized)["complete"] is False
    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"


def test_a_failed_read_is_incomplete_and_leaves_two_step_status_unknown() -> None:
    payload = {"twoStepVerificationPolicies": {"value": []}, "policySettings": {"value": []}}
    coverage = [{"collector": "google_policies", "name": "policySettings", "status": "failed", "error_class": "insufficient_permissions"}]

    normalized = _normalise(payload, "partial", coverage)

    assert normalized["google_policy_settings"]["records"] == [
        {
            "kind": "google_policy_settings_read_state",
            "source": "google_policies.policySettings",
            "id": "read_state",
            "key": "google_policy_settings_read_state:read_state",
            "complete": False,
            "record_count": 0,
            "malformed_count": 0,
            "unusable_sections": [],
            "unusable_scopes": [],
        }
    ]
    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"


def test_a_malformed_policy_or_section_makes_the_read_incomplete() -> None:
    bad_rows = [
        {"policyQuery": {"orgUnit": "orgUnits/root"}, "setting": {"type": "settings/gmail.auto_forwarding", "value": "on"}},
        {"policyQuery": {"orgUnit": "orgUnits/root"}, "setting": {"value": {}}},
        {"policyQuery": {}, "setting": {"type": "settings/gmail.imap_access", "value": {}}},
        "not a policy",
    ]
    state = _read_state(_normalise({"policySettings": {"value": bad_rows}}, "ok", []))
    assert (state["complete"], state["record_count"], state["malformed_count"]) == (False, 0, 4)

    state = _read_state(_normalise({"policySettings": {"value": "cut"}}, "ok", []))
    assert (state["complete"], state["malformed_count"]) == (False, 1)

    cut = {"value": [], "collection_truncated": True}
    assert _read_state(_normalise({"policySettings": cut}, "ok", []))["complete"] is False
    # No collector row: the read cannot be shown complete.
    no_row = build_google_normalized_snapshot(
        tenant_name="T", run_id="r1", collector_payloads={"google_policies": {"policySettings": {"value": []}}}
    )
    assert _read_state(no_row)["complete"] is False


def test_an_older_bundle_without_policy_settings_leaves_the_section_absent() -> None:
    payload = {"twoStepVerificationPolicies": {"value": [_two_step_root()]}}
    coverage = [{"collector": "google_policies", "name": "twoStepVerificationPolicies", "status": "ok", "collection_truncated": False}]

    normalized = _normalise(payload, "ok", coverage)

    assert "google_policy_settings" not in normalized
    assert len(normalized["google_two_step_policies"]["records"]) == 1


def test_the_offline_sample_keeps_its_two_step_records_and_finding(tmp_path: Path) -> None:
    from auditex.google_workspace.run import run_google_offline

    rc = run_google_offline(
        sample_path=Path("examples/google_workspace_sample.json"),
        out=tmp_path,
        tenant_name="Example",
        run_name="g",
        domain="example.com",
        customer_id="C123",
    )

    assert rc == 0
    normalized = tmp_path / "Example-g" / "normalized"
    assert not (normalized / "google_policy_settings.json").exists()
    records = json.loads((normalized / "google_two_step_policies.json").read_text(encoding="utf-8"))["records"]
    assert [(r["id"], r["policy_scope"]) for r in records] == [
        ("security.two_step_verification_enforcement:orgUnits/root-ou", "organisation"),
        ("security.two_step_verification_enforcement:orgUnits/sales-ou", "org_unit"),
        ("security.two_step_verification_enrollment:orgUnits/root-ou", "organisation"),
    ]
    findings = json.loads((tmp_path / "Example-g" / "findings" / "findings.json").read_text(encoding="utf-8"))
    rows = findings if isinstance(findings, list) else findings.get("findings") or findings.get("records") or []
    assert "google.org_2sv_policy_not_enforced:organisation" in {row.get("id") for row in rows}


def test_org_units_keep_ids_parents_and_the_root_but_never_a_path_or_name() -> None:
    directory = {
        "orgUnits": {
            "value": [
                {"orgUnitId": "id:sales", "parentOrgUnitId": "id:root", "parentOrgUnitPath": "/", "orgUnitPath": "/Sales", "name": "Sales"},
                {"orgUnitId": "id:emea", "parentOrgUnitId": "id:sales", "parentOrgUnitPath": "/Sales", "orgUnitPath": "/Sales/EMEA", "name": "EMEA"},
            ]
        }
    }
    coverage = [{"collector": "google_directory", "name": "orgUnits", "status": "ok", "collection_truncated": False}]

    normalized = _normalise({}, "ok", coverage, directory)

    assert normalized["google_org_units"]["records"] == [
        {"kind": "google_org_unit", "source": "google_directory.orgUnits", "id": "sales", "key": "google_org_unit:sales", "parent_id": "root", "is_root": False},
        {"kind": "google_org_unit", "source": "google_directory.orgUnits", "id": "emea", "key": "google_org_unit:emea", "parent_id": "sales", "is_root": False},
        {"kind": "google_org_unit", "source": "google_directory.orgUnits", "id": "root", "key": "google_org_unit:root", "parent_id": None, "is_root": True},
        {
            "kind": "google_org_units_read_state",
            "source": "google_directory.orgUnits",
            "id": "read_state",
            "key": "google_org_units_read_state:read_state",
            "complete": True,
            "root_id_known": True,
            "record_count": 3,
            "malformed_count": 0,
        },
    ]
    text = json.dumps(normalized["google_org_units"])
    assert "Sales" not in text and "EMEA" not in text and "/" not in text


def test_an_org_unit_read_that_failed_was_cut_or_names_no_root_is_incomplete() -> None:
    units = {"value": [{"orgUnitId": "id:sales", "parentOrgUnitId": "id:root", "parentOrgUnitPath": "/"}]}
    failed = [{"collector": "google_directory", "name": "orgUnits", "status": "failed", "error_class": "insufficient_permissions"}]
    assert _read_state(_normalise({}, "ok", failed, {"orgUnits": units}), "google_org_units")["complete"] is False

    cut = [{"collector": "google_directory", "name": "orgUnits", "status": "partial", "collection_truncated": True}]
    assert _read_state(_normalise({}, "ok", cut, {"orgUnits": units}), "google_org_units")["complete"] is False

    orphan = {"value": [{"orgUnitId": "id:emea", "parentOrgUnitId": "id:sales", "parentOrgUnitPath": "/Sales"}]}
    state = _read_state(_normalise({}, "ok", [], {"orgUnits": orphan}), "google_org_units")
    assert (state["complete"], state["root_id_known"]) == (False, False)

    # A complete, empty list: the root is the only unit, but its id is not in the list.
    state = _read_state(_normalise({}, "ok", [], {"orgUnits": {"value": []}}), "google_org_units")
    assert (state["complete"], state["root_id_known"], state["record_count"]) == (True, False, 0)

    # Another directory list failing does not make the unit tree unknown.
    other = [{"collector": "google_directory", "name": "groupMembers", "status": "failed"}]
    assert _read_state(_normalise({}, "ok", other, {"orgUnits": units}), "google_org_units")["complete"] is True
    assert "google_org_units" not in _normalise({}, "ok", [], {"users": {"value": []}})


def test_a_replayed_bundle_holds_no_policy_address_or_list_name_in_any_file(tmp_path: Path) -> None:
    from auditex.google_workspace.run import run_google_offline

    sample = json.loads(Path("examples/google_workspace_sample.json").read_text(encoding="utf-8"))
    sample["google_policies"] = _widened(_rows())  # both payloads of one read, as the collector writes them
    sample["google_directory"]["orgUnits"] = _SALES_DIRECTORY["orgUnits"]
    path = tmp_path / "sample.json"
    path.write_text(json.dumps(sample), encoding="utf-8")

    rc = run_google_offline(sample_path=path, out=tmp_path / "out", tenant_name="E", run_name="g", domain="example.com", customer_id="C123")

    assert rc == 0
    run_dir = tmp_path / "out" / "E-g"
    state = json.loads((run_dir / "normalized" / "google_policy_settings.json").read_text(encoding="utf-8"))["records"][-1]
    assert (state["complete"], state["record_count"]) == (True, 5)
    # The 2SV payload is a subset of the one read, so the replayed collector counts the five policies once, not 3 + 5.
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert [row["item_count"] for row in summary["collectors"] if row["name"] == "google_policies"] == [5]
    for file in run_dir.rglob("*"):
        if file.is_file():
            text = file.read_text(encoding="utf-8", errors="replace")
            assert not any(address in text for address in ADDRESSES), file.name
            assert "Partners" not in text and "Ask ops" not in text, file.name


def test_lens_fixes_unknown_keys_addresses_outside_values_and_kept_siblings() -> None:
    renamed = {"policyQuery": {"orgUnit": "orgUnits/root"}, "setting": {"type": "settings/gmail.email_address_lists", "value": {
        "emailAddressList": [{"id": "x", "addressList": {"addresses": [{"address": "partner@example.org"}]}}]}}}
    odd = {
        "name": "policies/p",
        "customer": "customers/C123",
        "policyQuery": {"group": "groups/ops@example.net", "orgUnit": "orgUnits/root"},
        "setting": {"type": "settings/chat.chat_file_sharing", "note": "alerts@example.com", "value": {
            "a": {"addressList": {"address": ["partner@example.org"]}, "enabled": True}}},
    }

    renamed_out, odd_out = minimise_policy_settings([renamed, odd])

    # A container key the minimiser does not know is unreadable, never an empty list.
    assert renamed_out["setting"]["value"] == {"emailAddressList": [{"id": "x", "entry_count": None, "domain_entry_count": None}]}
    # Only the fields the audit reads are kept: a target holding text is a constant (still not a target), and a
    # setting field other than its type and value is dropped.
    assert odd_out == {
        "policyQuery": {"group": "redacted:text", "orgUnit": "orgUnits/root"},
        "setting": {"type": "settings/chat.chat_file_sharing", "value": {}},
    }
    # The writer's pass drops customer and name from a replayed policySettings section too.
    written = minimise_user_text({"policySettings": {"value": [odd]}})
    assert "customer" not in written["policySettings"]["value"][0] and "name" not in written["policySettings"]["value"][0]
    assert not any(address in json.dumps(written) for address in ADDRESSES)


def test_lens_fixes_wrong_type_targets_and_conflicting_units_are_malformed() -> None:
    rows = [
        {"policyQuery": {"orgUnit": {"id": "root"}}, "setting": {"type": "settings/gmail.imap_access", "value": {}}},
        {"policyQuery": {"orgUnit": "orgUnits/root", "group": ["g1"]}, "setting": {"type": "settings/gmail.imap_access", "value": {}}},
    ]
    state = _read_state(_normalise({"policySettings": {"value": rows}}, "ok", []))
    assert (state["complete"], state["record_count"], state["malformed_count"]) == (False, 0, 2)

    units = {"value": [
        {"orgUnitId": "id:sales", "parentOrgUnitId": "id:root", "parentOrgUnitPath": "/"},
        {"orgUnitId": "id:sales", "parentOrgUnitId": "id:other", "parentOrgUnitPath": "/Other"},
    ]}
    state = _read_state(_normalise({}, "ok", [], {"orgUnits": units}), "google_org_units")
    assert (state["complete"], state["malformed_count"]) == (False, 1)


# M13 L03 repair: the review's counterexamples, each pinned with literal expectations.


class _ScriptedPolicies:
    """A ``policies`` resource answering a fixed script of pages (a payload or an error); page ``n`` has cursor ``p<n>``.

    ``repeat_last`` answers the last scripted page for every further request, up to 50 requests, after which the
    request fails, so an unbounded loop shows up as a call count instead of a hang.
    """

    def __init__(self, pages: list[Any], *, repeat_last: bool = False) -> None:
        self.pages = pages
        self.repeat_last = repeat_last
        self.calls: list[dict[str, Any]] = []

    def policies(self) -> _ScriptedPolicies:
        return self

    def list(self, **kwargs: Any) -> _Request:
        self.calls.append(kwargs)
        index = len(self.calls) - 1
        if index >= 50:
            return _Request(AssertionError("runaway read"))
        if index >= len(self.pages):
            if not self.repeat_last:
                return _Request(AssertionError("no such page"))
            index = len(self.pages) - 1
        page = self.pages[index]
        if callable(page):
            page = page(len(self.calls) - 1)
        return _Request(page)


def _gmail_row(**query: Any) -> dict[str, Any]:
    return {
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1, **query},
        "setting": {"type": "settings/gmail.auto_forwarding", "value": {"enableAutoForwarding": False}},
        "type": "ADMIN",
    }


def _collect(pages: list[Any], **kwargs: Any) -> tuple[Any, _ScriptedPolicies]:
    service = _ScriptedPolicies(pages, **kwargs)
    return GooglePoliciesCollector().run({"client": _client(service)}), service


def test_b1_a_page_holding_a_non_object_policy_is_not_a_complete_read() -> None:
    result, _service = _collect([{"policies": [None]}])

    assert result.status == "partial"
    (row,) = result.coverage
    assert (row["status"], row["error_class"], row["item_count"]) == ("failed", "malformed_response", 0)
    assert result.payload["policySettings"]["error_class"] == "malformed_response"
    normalized = _normalise(result.payload, result.status, result.coverage)
    assert (_read_state(normalized)["complete"], normalized["snapshot"]["two_step_policy_status"]) == (False, "unknown")


def test_b1_a_later_page_that_cannot_be_read_keeps_the_rows_and_marks_the_read_cut() -> None:
    result, service = _collect([{"policies": [_gmail_row()], "nextPageToken": "page-2"}, {"policies": "unreadable"}])

    assert len(service.calls) == 2 and result.status == "partial"
    (row,) = result.coverage
    assert (row["status"], row["error_class"], row["collection_truncated"], row["truncation_reason"]) == (
        "partial",
        "malformed_response",
        True,
        "pagination_failed",
    )
    assert row["error"] == "A later page of the Cloud Identity policies read could not be read; the rows read before it are kept."
    assert result.payload["policySettings"]["collection_truncated"] is True
    assert result.payload["policySettings"]["truncation_reason"] == "pagination_failed"
    assert len(result.payload["policySettings"]["value"]) == 1
    normalized = _normalise(result.payload, result.status, result.coverage)
    assert _read_state(normalized)["complete"] is False
    # No 2-step verification policy was retained, but the read was cut: unknown, never "not enforced".
    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"


def test_b1_an_items_list_is_not_a_policies_answer_and_an_empty_read_is_not_complete() -> None:
    result, _service = _collect([{"items": [_gmail_row()]}])
    (row,) = result.coverage
    assert (row["status"], row["error_class"]) == ("failed", "malformed_response")
    assert result.payload["policySettings"]["value"] == []

    result, _service = _collect([{"policies": []}])
    (row,) = result.coverage
    assert (row["status"], row["error_class"], row["error"]) == (
        "failed",
        "malformed_response",
        "The Cloud Identity policies read returned no readable policies, so no setting could be read.",
    )
    normalized = _normalise(result.payload, result.status, result.coverage)
    assert (_read_state(normalized)["complete"], normalized["snapshot"]["two_step_policy_status"]) == (False, "unknown")
    # The same empty section with no coverage marker (a hand-made sample) is still not a complete read.
    assert _read_state(_normalise({"policySettings": {"value": []}}, "ok", []))["complete"] is False


def _replay(
    tmp_path: Path, policies: Any, *, directory: dict[str, Any] | None = None, as_of: datetime | None = None,
) -> tuple[int, Path]:
    from auditex.google_workspace.run import run_google_offline

    sample = json.loads(Path("examples/google_workspace_sample.json").read_text(encoding="utf-8"))
    sample["google_policies"] = policies
    sample["google_directory"]["orgUnits"] = (directory if directory is not None else _SALES_DIRECTORY)["orgUnits"]
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "sample.json"
    path.write_text(json.dumps(sample), encoding="utf-8")
    rc = run_google_offline(sample_path=path, out=tmp_path / "out", tenant_name="E", run_name="g", domain="example.com", customer_id="C123", as_of=as_of)
    return rc, tmp_path / "out" / "E-g"


def _bundle_state(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "normalized" / "google_policy_settings.json").read_text(encoding="utf-8"))["records"][-1]


def test_b2_a_replayed_raw_payload_of_a_cut_read_stays_incomplete_and_fails_the_run(tmp_path: Path) -> None:
    result, _service = _collect([{"policies": [_gmail_row()], "nextPageToken": "page-2"}, RuntimeError("page refused")])
    assert result.payload["twoStepVerificationPolicies"] == {
        "value": [],
        "collection_truncated": True,
        "truncation_reason": "pagination_failed",
        "item_count": 0,
    }

    rc, run_dir = _replay(tmp_path, json.loads(json.dumps(result.payload)))

    assert rc == 1
    assert _bundle_state(run_dir)["complete"] is False
    assert not (run_dir / "normalized" / "google_two_step_policies.json").exists()  # none was read
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert [row["status"] for row in summary["collectors"] if row["name"] == "google_policies"] == ["partial"]


def test_b2_a_malformed_or_null_policies_section_fails_the_run_and_is_not_absent(tmp_path: Path) -> None:
    rc, run_dir = _replay(tmp_path / "a", {"policySettings": {"value": ["unreadable"]}})
    assert rc == 1
    state = _bundle_state(run_dir)
    assert (state["complete"], state["malformed_count"]) == (False, 1)

    rc, run_dir = _replay(tmp_path / "b", {"twoStepVerificationPolicies": {"value": []}, "policySettings": None})
    assert rc == 1
    assert _bundle_state(run_dir) == {
        "kind": "google_policy_settings_read_state",
        "source": "google_policies.policySettings",
        "id": "read_state",
        "key": "google_policy_settings_read_state:read_state",
        "complete": False,
        "record_count": 0,
        "malformed_count": 1,
        "unusable_sections": [],
        "unusable_scopes": [],
    }


def test_b3_unknown_precedence_or_a_missing_value_makes_the_setting_unusable() -> None:
    rows = [
        {"policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": {"position": 5}}, "setting": {"type": "settings/gmail.auto_forwarding", "value": {"enableAutoForwarding": True}}},
        {"policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1}, "setting": {"type": "settings/gmail.auto_forwarding", "value": {"enableAutoForwarding": False}}},
        {"policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1}, "setting": {"type": "settings/gmail.imap_access"}},
        {"policyQuery": {"orgUnit": "orgUnits/sales"}, "setting": {"type": "settings/chat.chat_history", "value": {"historyOnByDefault": True}}},
        {"policyQuery": {"orgUnit": "orgUnits/sales"}, "setting": {"type": "settings/chat.chat_history", "value": {"historyOnByDefault": False}}},
        {"policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 2.5}, "setting": {"type": "settings/meet.safety_access", "value": {}}},
    ]

    records = _normalise({"policySettings": {"value": rows}}, "ok", [{"collector": "google_policies", "name": "policySettings", "status": "ok"}], _SALES_DIRECTORY)[
        "google_policy_settings"
    ]["records"]

    # Only the decimal-ordered setting with its explicit empty value survives; the other three units are unusable.
    assert [(r["section"], r["sort_order"], r["value"]) for r in records[:-1]] == [("meet_safety_access", 2.5, {})]
    assert records[-1]["complete"] is False
    assert records[-1]["malformed_count"] == 2
    assert records[-1]["unusable_sections"] == []
    assert records[-1]["unusable_scopes"] == [
        {"section": "chat_chat_history", "org_unit": "sales", "group": None},
        {"section": "gmail_auto_forwarding", "org_unit": "root", "group": None},
        {"section": "gmail_imap_access", "org_unit": "root", "group": None},
    ]


def test_b4_a_query_with_an_exception_is_never_unconditional_org_unit_evidence() -> None:
    exception = "entity.org_units.exists(o, o.org_unit_id == orgUnitId('root')) && !entity.groups.exists(g, g.group_id == groupId('g1'))"
    plain = "entity.org_units.exists(o, o.org_unit_id == orgUnitId('root'))"
    rows = [
        {"policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1, "query": exception}, "setting": {"type": "settings/gmail.auto_forwarding", "value": {"enableAutoForwarding": False}}},
        {"policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1, "query": plain}, "setting": {"type": "settings/gmail.imap_access", "value": {"enableImapAccess": False}}},
    ]
    state = _read_state(_normalise({"policySettings": {"value": rows}}, "ok", [{"collector": "google_policies", "name": "policySettings", "status": "ok"}], _SALES_DIRECTORY))
    assert (state["complete"], state["record_count"], state["unusable_sections"]) == (False, 1, [])
    assert state["unusable_scopes"] == [{"section": "gmail_auto_forwarding", "org_unit": "root", "group": None}]

    # The 2-step verification enforcement at the root, except for group g1: not organisation-wide enforcement.
    enforcing = {
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1, "query": exception},
        "setting": {"type": "settings/security.two_step_verification_enforcement", "value": {"enforcedFrom": "2020-01-01T00:00:00Z"}},
        "type": "ADMIN",
    }
    directory = {"orgUnits": {"value": [{"orgUnitId": "id:sales", "parentOrgUnitId": "id:root", "parentOrgUnitPath": "/"}]}}
    coverage = [{"collector": "google_directory", "name": "orgUnits", "status": "ok"}, {"collector": "google_policies", "name": "policySettings", "status": "ok"}]
    normalized = _normalise({"twoStepVerificationPolicies": {"value": [enforcing]}, "policySettings": {"value": [enforcing]}}, "ok", coverage, directory)
    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"
    assert [r["policy_scope"] for r in normalized["google_two_step_policies"]["records"]] == ["unclassified"]


def test_b5_no_customer_id_policy_id_or_local_path_in_either_raw_section_or_the_bundle(tmp_path: Path) -> None:
    two_step = {
        "name": "policies/sample-resource",
        "customer": "customers/C0example01",
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
        "setting": {"type": "settings/security.two_step_verification_enforcement", "value": {}},
        "type": "ADMIN",
    }
    widened = {
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
        "setting": {"type": "settings/chat.chat_apps_access", "value": {"friendlyName": "see /srv/example/notes.txt", "other": "D:\\example\\notes.txt"}},
    }
    lists = {
        "policyQuery": {"orgUnit": "orgUnits/sales", "sortOrder": 1},
        "setting": {"type": "settings/gmail.email_address_lists", "value": {"emailAddressList": "example.com"}},
    }
    listed = {
        "policyQuery": {"orgUnit": "orgUnits/eng", "sortOrder": 1},
        "setting": {"type": "settings/gmail.email_address_lists", "value": {"emailAddressList": ["example.org"]}},
    }
    result, _service = _collect([{"policies": [two_step, widened, lists, listed]}])

    text = json.dumps(result.payload)
    assert "C0example01" not in text and "sample-resource" not in text
    assert "/srv/" not in text and "D:\\\\example" not in text
    assert '"example.com"' not in text and '"example.org"' not in text
    assert result.payload["policySettings"]["value"][1]["setting"]["value"] == {}
    assert result.payload["policySettings"]["value"][2]["setting"]["value"] == {"emailAddressList": None}
    assert result.payload["policySettings"]["value"][3]["setting"]["value"] == {
        "emailAddressList": [{"id": None, "entry_count": None, "domain_entry_count": None}]
    }
    # The bundle writer's pass on a legacy 2-step verification section drops both fields too.
    assert minimise_user_text({"twoStepVerificationPolicies": {"value": [two_step]}}) == {
        "twoStepVerificationPolicies": {
            "value": [
                {
                    "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
                    "setting": {"type": "settings/security.two_step_verification_enforcement", "value": {}},
                    "type": "ADMIN",
                }
            ]
        }
    }
    # Replaying the shipped sample (whose 2SV rows carry a customer id and resource names) writes neither.
    sample = json.loads(Path("examples/google_workspace_sample.json").read_text(encoding="utf-8"))
    rc, run_dir = _replay(tmp_path, sample["google_policies"], directory=sample["google_directory"])
    assert rc == 0
    for relative in ("raw/google_policies.json", "normalized/google_two_step_policies.json", "findings/findings.json"):
        written = (run_dir / relative).read_text(encoding="utf-8")
        assert "customers/" not in written and "policies/two-step" not in written, relative


class _HttpError(Exception):
    """The shape of ``googleapiclient.errors.HttpError``: its text names the request URL with the customer id."""

    def __init__(self) -> None:
        super().__init__(
            '<HttpError 400 when requesting https://cloudidentity.googleapis.com/v1/policies?pageSize=100&'
            'filter=customer+%3D%3D+%22customers%2FC0example01%22 returned "Invalid filter">'
        )
        self.resp = type("Resp", (), {"status": 400})()


def test_b6_a_first_page_failure_never_publishes_the_request_url() -> None:
    from auditex.google_workspace.run import _preflight_call

    result, _service = _collect([_HttpError()])
    (row,) = result.coverage
    assert (row["status"], row["error_class"], row["error"]) == ("failed", "client_error", "The Cloud Identity policies read failed (HTTP 400).")
    assert result.payload["policySettings"]["error"] == "The Cloud Identity policies read failed (HTTP 400)."
    assert "C0example01" not in json.dumps(result.payload)

    probe = _preflight_call("google_policies", "policySettings", lambda: _client(_ScriptedPolicies([_HttpError()])).list_policies(limit=1))
    assert (probe["status"], probe["error_class"], probe["error"]) == ("failed", "client_error", "The Cloud Identity policies read failed (HTTP 400).")

    refusal = RuntimeError("('unauthorized_client: Client is unauthorized for sa@example.iam.gserviceaccount.com', {})")
    result, _service = _collect([refusal])
    (row,) = result.coverage
    assert row["error_class"] == "insufficient_permissions"
    assert row["error"] == (
        "The token exchange for the Cloud Identity policies scope was refused (unauthorized_client): "
        "the domain-wide delegation does not grant that scope."
    )


def test_b7_a_malformed_two_step_target_answers_unknown_instead_of_aborting() -> None:
    row = {"policyQuery": ["unreadable"], "setting": {"type": "settings/security.two_step_verification_enforcement", "value": {}}}
    result, _service = _collect([{"policies": [row, _gmail_row()]}])

    (coverage_row,) = result.coverage
    assert (coverage_row["status"], coverage_row["error_class"]) == ("partial", "malformed_response")
    assert coverage_row["error"] == "1 of 2 policies returned by the read cannot be read; the settings they hold are unknown."
    normalized = _normalise(result.payload, result.status, result.coverage)
    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"
    state = _read_state(normalized)
    assert (state["complete"], state["malformed_count"], state["unusable_sections"]) == (
        False,
        1,
        ["security_two_step_verification_enforcement"],
    )


def test_m1_an_orphan_a_cycle_or_a_non_string_id_is_not_a_complete_unit_tree() -> None:
    top = {"orgUnitId": "id:a", "parentOrgUnitId": "id:root", "parentOrgUnitPath": "/"}
    for extra in (
        {"orgUnitId": "id:b", "parentOrgUnitId": "id:missing", "parentOrgUnitPath": "/Unset"},
        {"orgUnitId": "id:b", "parentOrgUnitId": "id:b", "parentOrgUnitPath": "/B"},
        {"orgUnitId": 123, "parentOrgUnitId": "id:a", "parentOrgUnitPath": "/A"},
    ):
        normalized = _normalise({}, "ok", [], {"orgUnits": {"value": [top, extra]}})
        state = _read_state(normalized, "google_org_units")
        assert (state["complete"], state["root_id_known"], state["malformed_count"]) == (False, False, 1), extra
        assert "123" not in {r["id"] for r in normalized["google_org_units"]["records"]}


def test_m2_blank_entries_ids_and_contradictory_counts_are_unknown_not_counts() -> None:
    def summary(value: dict[str, Any]) -> Any:
        (policy,) = minimise_policy_settings(
            [{"policyQuery": {"orgUnit": "orgUnits/root"}, "setting": {"type": "settings/gmail.email_address_lists", "value": value}}]
        )
        return policy["setting"]["value"]["emailAddressList"]

    assert summary({"emailAddressList": [{"id": "a", "addressList": {"address": [{"address": ""}, {"address": "www.example"}]}}]}) == [
        {"id": "a", "entry_count": None, "domain_entry_count": None}
    ]
    assert summary({"emailAddressList": [{"id": "a", "entry_count": 0, "domain_entry_count": 2}]}) == [
        {"id": "a", "entry_count": None, "domain_entry_count": None}
    ]
    assert summary({"emailAddressList": [{"id": "", "addressList": {"address": [{"address": "www.example"}]}}]}) == [
        {"id": None, "entry_count": None, "domain_entry_count": None}
    ]
    # The pinned domain regex still decides what a readable entry is.
    assert summary({"emailAddressList": [{"id": "a", "addressList": {"address": [{"address": "www.example"}, {"address": "localhost"}]}}]}) == [
        {"id": "a", "entry_count": 2, "domain_entry_count": 1}
    ]
    rows = [{"policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1}, "setting": {"type": "settings/gmail.email_address_lists", "value": {
        "emailAddressList": [{"id": "a", "addressList": {"address": [{"address": ""}]}}]}}}]
    state = _read_state(_normalise({"policySettings": {"value": rows}}, "ok", [{"collector": "google_policies", "name": "policySettings", "status": "ok"}]))
    assert (state["complete"], state["unusable_sections"]) == (False, [])
    assert state["unusable_scopes"] == [{"section": "gmail_email_address_lists", "org_unit": "root", "group": None}]


def test_m3_a_repeated_cursor_empty_pages_or_the_page_budget_stop_the_read_incomplete(monkeypatch: Any) -> None:
    # An empty first page with no cursor is a read that returned nothing: failed after one request.
    result, service = _collect([{"policies": []}])
    assert len(service.calls) == 1
    (row,) = result.coverage
    assert (row["status"], row["error_class"]) == ("failed", "malformed_response")

    # Empty pages that carry a cursor are followed (round three, B4) until the cursor comes back: not followed, cut.
    result, service = _collect([{"policies": [], "nextPageToken": "repeat"}], repeat_last=True)
    assert len(service.calls) == 2
    (row,) = result.coverage
    assert (row["status"], row["collection_truncated"], row["truncation_reason"]) == ("partial", True, "pagination_not_followed")
    result, service = _collect([{"policies": [_gmail_row()], "nextPageToken": "c0"}, {"policies": [], "nextPageToken": "c1"}], repeat_last=True)
    assert len(service.calls) == 3
    (row,) = result.coverage
    assert (row["status"], row["collection_truncated"], row["truncation_reason"]) == ("partial", True, "pagination_not_followed")

    # A cursor handed out a second time.
    result, service = _collect(
        [{"policies": [_gmail_row()], "nextPageToken": "c0"}, {"policies": [_gmail_row(orgUnit="orgUnits/sales")], "nextPageToken": "c0"}],
        repeat_last=True,
    )
    assert len(service.calls) == 2
    (row,) = result.coverage
    assert (row["status"], row["collection_truncated"], row["truncation_reason"]) == ("partial", True, "pagination_not_followed")
    assert result.payload["policySettings"]["collection_truncated"] is True

    monkeypatch.setattr(client_module, "POLICY_PAGE_BUDGET", 3)
    result, service = _collect([lambda index: {"policies": [_gmail_row(sortOrder=index + 1)], "nextPageToken": f"c{index}"}], repeat_last=True)
    assert len(service.calls) == 3
    (row,) = result.coverage
    assert (row["status"], row["collection_truncated"], row["truncation_reason"]) == ("partial", True, "pagination_not_followed")
    normalized = _normalise(result.payload, result.status, result.coverage)
    assert _read_state(normalized)["complete"] is False


# ---- M13 L03 repair round two: the round-two review's counterexamples and the field validation table ---------------

_ENFORCED = {"enforcedFrom": "2020-01-01T00:00:00Z"}
_SALES_DIRECTORY = {"orgUnits": {"value": [{"orgUnitId": "id:sales", "parentOrgUnitId": "id:root", "parentOrgUnitPath": "/"}]}}
_OK_COVERAGE = [
    {"collector": "google_directory", "name": "orgUnits", "status": "ok"},
    {"collector": "google_policies", "name": "policySettings", "status": "ok"},
]


def _two_step(org_unit: str = "orgUnits/root", value: dict[str, Any] | None = None, **query: Any) -> dict[str, Any]:
    return {
        "policyQuery": {"orgUnit": org_unit, "sortOrder": 1, **query},
        "setting": {"type": "settings/security.two_step_verification_enforcement", "value": dict(value or {})},
        "type": "ADMIN",
    }


def _widened(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Both payloads of one read holding ``rows``, as the collector writes them."""
    two_step = [row for row in rows if row["setting"]["type"].startswith("settings/security.two_step_verification_")]
    return {"twoStepVerificationPolicies": {"value": two_step}, "policySettings": {"value": rows}}


def _bundle_text(run_dir: Path) -> str:
    return "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in sorted(run_dir.rglob("*")) if path.is_file())


def _bundle_two_step_status(run_dir: Path) -> str:
    return json.loads((run_dir / "normalized" / "snapshot.json").read_text(encoding="utf-8"))["two_step_policy_status"]


def test_r2_b1_an_empty_later_page_is_a_cut_read_and_never_supports_a_two_step_finding() -> None:
    result, service = _collect([{"policies": [_gmail_row()], "nextPageToken": "p2"}, {"policies": []}])

    assert len(service.calls) == 2 and result.status == "partial"
    (row,) = result.coverage
    assert (row["status"], row["error_class"], row["collection_truncated"], row["truncation_reason"]) == (
        "partial",
        "malformed_response",
        True,
        "pagination_failed",
    )
    normalized = _normalise(result.payload, result.status, result.coverage, _SALES_DIRECTORY)
    assert (_read_state(normalized)["complete"], normalized["snapshot"]["two_step_policy_status"]) == (False, "unknown")
    assert "google.org_2sv_policy_not_enforced" not in {item["rule_id"] for item in build_google_findings(normalized)}


def test_r2_b1_a_complete_widened_read_without_the_organisation_enforcement_policy_is_unknown() -> None:
    normalized = _normalise(_widened([_gmail_row()]), "ok", _OK_COVERAGE, _SALES_DIRECTORY)

    assert _read_state(normalized)["complete"] is True
    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"
    # The organisation's own enforcement policy, read and not in force, is the positive evidence a finding needs.
    normalized = _normalise(_widened([_gmail_row(), _two_step()]), "ok", _OK_COVERAGE, _SALES_DIRECTORY)
    assert normalized["snapshot"]["two_step_policy_status"] == "not_enforced"


def test_r2_b1_a_replay_of_empty_or_unreadable_sections_fails_the_run(tmp_path: Path) -> None:
    rc, run_dir = _replay(tmp_path / "a", {"twoStepVerificationPolicies": {"value": []}, "policySettings": {"value": []}})
    assert rc == 1
    assert _bundle_two_step_status(run_dir) == "unknown"
    assert _bundle_state(run_dir)["complete"] is False

    unreadable = {
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
        "setting": {"type": "settings/gmail.email_address_lists", "value": {"emailAddressList": "unreadable"}},
    }
    rc, run_dir = _replay(tmp_path / "b", {"policySettings": {"value": [unreadable]}})
    assert rc == 1
    assert _bundle_state(run_dir)["complete"] is False


def test_r2_b1_the_probe_does_not_report_an_empty_or_null_page_as_a_complete_read() -> None:
    from auditex.google_workspace.run import _preflight_call

    for page in ({"policies": []}, {"policies": [None]}, {}):
        probe = _preflight_call("google_policies", "policySettings", lambda page=page: _client(_ScriptedPolicies([page])).list_policies(limit=1))
        assert (probe["status"], probe["error_class"], probe["item_count"]) == ("failed", "malformed_response", 0), page
        assert probe["error"] == "The Cloud Identity policies read returned no readable policies, so no setting could be read."
    probe = _preflight_call(
        "google_policies",
        "policySettings",
        lambda: _client(_ScriptedPolicies([{"policies": [_gmail_row()], "nextPageToken": "p2"}, {"policies": [None]}])).list_policies(limit=5),
    )
    assert (probe["status"], probe["error_class"]) == ("partial", "malformed_response")


def test_r2_b2_an_out_of_range_json_number_is_unreadable_not_an_overflow(tmp_path: Path) -> None:
    huge = json.loads('{"policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1' + "0" * 400 + '}, '
                      '"setting": {"type": "settings/gmail.auto_forwarding", "value": {"enableAutoForwarding": false}}}')
    result, _service = _collect([{"policies": [huge, _gmail_row(orgUnit="orgUnits/sales")]}])

    (row,) = result.coverage
    assert (row["status"], row["error_class"]) == ("partial", "malformed_response")
    assert row["error"] == "1 of 2 policies returned by the read cannot be read; the settings they hold are unknown."
    rc, run_dir = _replay(tmp_path, {"policySettings": {"value": [huge]}})
    assert rc == 1
    assert _bundle_state(run_dir)["unusable_scopes"] == [{"section": "gmail_auto_forwarding", "org_unit": "root", "group": None}]


def test_r2_b3_a_query_naming_another_unit_or_a_blank_group_is_not_organisation_evidence() -> None:
    other_unit = _two_step(value=_ENFORCED, query="entity.org_units.exists(o, o.org_unit_id == orgUnitId('sales'))")
    normalized = _normalise(_widened([other_unit]), "ok", _OK_COVERAGE, _SALES_DIRECTORY)
    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"
    assert [(r["policy_scope"], r["scope_supported"]) for r in normalized["google_two_step_policies"]["records"]] == [("unclassified", False)]
    state = _read_state(normalized)
    assert (state["complete"], state["unusable_scopes"]) == (
        False,
        [{"section": "security_two_step_verification_enforcement", "org_unit": "root", "group": None}],
    )
    # The legacy section alone gives the same answer.
    legacy = _normalise({"twoStepVerificationPolicies": {"value": [other_unit]}}, "ok", _OK_COVERAGE, _SALES_DIRECTORY)
    assert legacy["snapshot"]["two_step_policy_status"] == "unknown"

    blank_group = _two_step(value=_ENFORCED, group="groups/")
    normalized = _normalise(_widened([blank_group]), "ok", _OK_COVERAGE, _SALES_DIRECTORY)
    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"
    assert "google_two_step_policies" not in normalized
    state = _read_state(normalized)
    assert (state["complete"], state["record_count"], state["unusable_sections"]) == (False, 0, ["security_two_step_verification_enforcement"])


def test_r2_b4_no_local_path_reaches_a_raw_or_normalised_policy_file(tmp_path: Path) -> None:
    keyed = {
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
        "setting": {"type": "settings/chat.chat_apps_access", "value": {"/srv/synthetic/notes.txt": True}},
    }
    factor = {
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
        "setting": {"type": "settings/security.two_step_verification_enforcement_factor", "value": {"allowedSignInFactorSet": "/srv/synthetic/notes.txt"}},
        "type": "ADMIN",
    }
    rc, run_dir = _replay(tmp_path, _widened([keyed, factor]))

    assert rc == 1  # the factor set cannot be read
    assert "/srv/synthetic" not in _bundle_text(run_dir)
    raw = json.loads((run_dir / "raw" / "google_policies.json").read_text(encoding="utf-8"))
    assert [row["setting"]["value"] for row in raw["policySettings"]["value"]] == [{}, {"allowedSignInFactorSet": None}]
    records = json.loads((run_dir / "normalized" / "google_policy_settings.json").read_text(encoding="utf-8"))["records"]
    assert [r["value"] for r in records if r["id"] != "read_state"] == [{}]
    assert not (run_dir / "normalized" / "google_two_step_policies.json").exists()


def test_r2_b5_replayed_and_live_policy_errors_carry_fixed_text_only(tmp_path: Path) -> None:
    rc, run_dir = _replay(tmp_path, {"policySettings": {"value": [], "error": "Request failed for customers/C0SyntheticOnly"}})
    assert rc == 1
    assert "C0SyntheticOnly" not in _bundle_text(run_dir)
    raw = json.loads((run_dir / "raw" / "google_policies.json").read_text(encoding="utf-8"))
    assert {key: raw["policySettings"][key] for key in ("error_class", "error")} == {
        "error_class": "client_error",
        "error": "policySettings: the Cloud Identity policies read failed (client_error).",
    }

    class _ReasonedError(Exception):
        def __init__(self) -> None:
            super().__init__("<HttpError 400 returned SyntheticSecretToken>")
            self.resp = type("Resp", (), {"status": 400})()
            self.error_details = [{"reason": "SyntheticSecretToken"}, {"reason": "badRequest"}]

    result, _service = _collect([_ReasonedError()])
    (row,) = result.coverage
    assert row["error"] == "The Cloud Identity policies read failed (HTTP 400; reason badRequest)."
    assert "SyntheticSecretToken" not in json.dumps(result.payload)


def test_r2_b6_an_unreadable_enforcement_date_leaves_enforcement_unknown() -> None:
    normalized = _normalise(_widened([_two_step(value={"enforcedFrom": "not-a-timestamp"})]), "ok", _OK_COVERAGE, _SALES_DIRECTORY)

    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"
    assert "google.org_2sv_policy_not_enforced" not in {item["rule_id"] for item in build_google_findings(normalized)}
    # The explicit empty value (the shipped sample's root policy) is still the organisation's policy not in force.
    normalized = _normalise(_widened([_two_step(value={})]), "ok", _OK_COVERAGE, _SALES_DIRECTORY)
    assert normalized["snapshot"]["two_step_policy_status"] == "not_enforced"


def test_r2_b7_an_unreadable_org_unit_row_never_makes_child_enforcement_organisation_wide() -> None:
    directory = {"orgUnits": {"value": [None]}}
    normalized = _normalise(_widened([_two_step("orgUnits/sales", _ENFORCED)]), "ok", _OK_COVERAGE, directory)

    assert _read_state(normalized, "google_org_units")["complete"] is False
    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"
    assert [r["policy_scope"] for r in normalized["google_two_step_policies"]["records"]] == ["unclassified"]
    legacy = _normalise({"twoStepVerificationPolicies": {"value": [_two_step("orgUnits/sales", _ENFORCED)]}}, "ok", _OK_COVERAGE, directory)
    assert legacy["snapshot"]["two_step_policy_status"] == "unknown"


def test_r2_m1_a_list_id_that_needs_redaction_has_unknown_counts() -> None:
    (policy,) = minimise_policy_settings(
        [
            {
                "policyQuery": {"orgUnit": "orgUnits/root"},
                "setting": {
                    "type": "settings/gmail.email_address_lists",
                    "value": {
                        "emailAddressList": [
                            {"id": "/srv/synthetic/notes.txt", "addressList": {"address": [{"address": "www.example"}]}},
                            {"id": "ops@example.net", "addressList": {"address": [{"address": "www.example"}]}},
                            {"id": "list-1", "addressList": {"address": [{"address": "www.example"}]}},
                        ]
                    },
                },
            }
        ]
    )
    assert policy["setting"]["value"]["emailAddressList"] == [
        {"id": None, "entry_count": None, "domain_entry_count": None},
        {"id": None, "entry_count": None, "domain_entry_count": None},
        {"id": "list-1", "entry_count": 1, "domain_entry_count": 1},
    ]


def test_r2_m2_an_unsupported_child_scope_keeps_the_root_setting() -> None:
    child = _gmail_row(orgUnit="orgUnits/sales", sortOrder=2, query="!entity.groups.exists(g, g.group_id == groupId('restricted'))")
    normalized = _normalise({"policySettings": {"value": [_gmail_row(), child]}}, "ok", _OK_COVERAGE, _SALES_DIRECTORY)

    records = normalized["google_policy_settings"]["records"]
    assert [(r["section"], r["org_unit"], r["value"]) for r in records[:-1]] == [
        ("gmail_auto_forwarding", "root", {"enableAutoForwarding": False})
    ]
    assert {key: records[-1][key] for key in ("complete", "record_count", "unusable_sections", "unusable_scopes")} == {
        "complete": False,
        "record_count": 1,
        "unusable_sections": [],
        "unusable_scopes": [{"section": "gmail_auto_forwarding", "org_unit": "sales", "group": None}],
    }


def _base_policy() -> dict[str, Any]:
    return {
        "name": "policies/p1",
        "customer": "customers/C1",
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1, "query": "entity.org_units.exists(o, o.org_unit_id == orgUnitId('root'))"},
        "setting": {"type": "settings/security.two_step_verification_enforcement", "value": {"enforcedFrom": "2020-01-01T00:00:00Z"}},
        "type": "ADMIN",
    }


_MISSING = object()


def _variant(path: tuple[str, ...], value: Any) -> Any:
    policy = _base_policy()
    if not path:
        return value
    node: Any = policy
    for key in path[:-1]:
        node = node[key]
    if value is _MISSING:
        node.pop(path[-1], None)
    else:
        node[path[-1]] = value
    return policy


# Every field the collector and normaliser read, with absent, null, wrong-typed, blank, malformed, out-of-range and
# contradictory values, and the literal problem codes each must produce. ``()`` is a sound policy.
_FIELD_TABLE: list[tuple[tuple[str, ...], Any, tuple[str, ...]]] = [
    ((), None, ("policy_invalid",)),
    ((), ["policy"], ("policy_invalid",)),
    (("name",), _MISSING, ()),
    (("name",), 5, ("name_invalid",)),
    (("customer",), None, ("name_invalid",)),
    (("type",), _MISSING, ()),
    (("type",), None, ("policy_type_invalid",)),
    (("type",), "CUSTOM", ("policy_type_invalid",)),
    (("setting",), _MISSING, ("setting_invalid",)),
    (("setting",), None, ("setting_invalid",)),
    (("setting",), "settings/gmail.x", ("setting_invalid",)),
    (("setting", "type"), _MISSING, ("setting_type_invalid",)),
    (("setting", "type"), None, ("setting_type_invalid",)),
    (("setting", "type"), 5, ("setting_type_invalid",)),
    (("setting", "type"), "", ("setting_type_invalid",)),
    (("setting", "type"), "settings/", ("setting_type_invalid",)),
    (("setting", "type"), "settings/Gmail Auto", ("setting_type_invalid",)),
    (("setting", "type"), "settings/rule.dlp", ("setting_type_not_requested",)),
    (("setting", "value"), _MISSING, ("value_missing",)),
    (("setting", "value"), None, ("value_invalid",)),
    (("setting", "value"), [], ("value_invalid",)),
    (("setting", "value"), "on", ("value_invalid",)),
    (("setting", "value"), {}, ()),
    (("setting", "value", "enforcedFrom"), None, ("two_step_value_invalid",)),
    (("setting", "value", "enforcedFrom"), "", ("two_step_value_invalid",)),
    (("setting", "value", "enforcedFrom"), 5, ("two_step_value_invalid",)),
    (("setting", "value", "enforcedFrom"), "not-a-timestamp", ("two_step_value_invalid",)),
    (("setting", "value", "enforcedFrom"), "2020-01-01", ("two_step_value_invalid",)),
    (("setting", "value", "enforcedFrom"), "2020-13-01T00:00:00Z", ("two_step_value_invalid",)),
    (("setting", "value", "enforcedFrom"), "2020-01-01T00:00:00", ("two_step_value_invalid",)),
    (("setting", "value", "enforced_from"), "2021-01-01T00:00:00Z", ("two_step_value_conflict",)),
    (("setting", "value", "enforced_from"), "2020-01-01T00:00:00Z", ()),
    (("setting", "value", "allowEnrollment"), "yes", ("two_step_value_invalid",)),
    (("setting", "value", "allowedSignInFactorSet"), "/srv/synthetic/notes.txt", ("two_step_value_invalid",)),
    (("setting", "value", "allowedSignInFactorSet"), "passkey only", ("two_step_value_invalid",)),
    (("setting", "value", "enrollmentGracePeriod"), "7 days", ("two_step_value_invalid",)),
    (("setting", "value", "enrollmentGracePeriod"), "604800s", ()),
    (("policyQuery",), _MISSING, ("query_object_invalid",)),
    (("policyQuery",), None, ("query_object_invalid",)),
    (("policyQuery",), ["orgUnits/root"], ("query_object_invalid",)),
    (("policyQuery", "orgUnit"), _MISSING, ("target_missing",)),
    (("policyQuery", "orgUnit"), None, ("org_unit_invalid",)),
    (("policyQuery", "orgUnit"), "", ("target_missing",)),
    (("policyQuery", "orgUnit"), 5, ("org_unit_invalid",)),
    (("policyQuery", "orgUnit"), "root", ("org_unit_invalid",)),
    (("policyQuery", "orgUnit"), "orgUnits/", ("org_unit_invalid",)),
    (("policyQuery", "orgUnit"), "orgUnits/../sales", ("org_unit_invalid",)),
    (("policyQuery", "orgUnit"), "orgUnits/Sales Team", ("org_unit_invalid",)),
    (("policyQuery", "group"), "groups/", ("group_invalid",)),
    (("policyQuery", "group"), "g1@example.com", ("group_invalid",)),
    (("policyQuery", "group"), 7, ("group_invalid",)),
    (("policyQuery", "group"), "", ()),
    (("policyQuery", "group"), None, ("group_invalid",)),
    (("policyQuery", "group"), "WORKSPACE_ALL_ADMIN_GROUP", ()),
    (("policyQuery", "group"), "UNCONSENTED_CHILD_GROUP", ()),
    (("policyQuery", "group"), "ALL_STAFF", ("group_invalid",)),
    (("policyQuery", "sortOrder"), _MISSING, ()),
    (("policyQuery", "sortOrder"), None, ("sort_order_invalid",)),
    (("policyQuery", "sortOrder"), "1", ("sort_order_invalid",)),
    (("policyQuery", "sortOrder"), True, ("sort_order_invalid",)),
    (("policyQuery", "sortOrder"), float("nan"), ("sort_order_invalid",)),
    (("policyQuery", "sortOrder"), float("inf"), ("sort_order_invalid",)),
    (("policyQuery", "sortOrder"), 10**400, ("sort_order_invalid",)),
    (("policyQuery", "sortOrder"), {"position": 5}, ("sort_order_invalid",)),
    (("policyQuery", "sortOrder"), 2.5, ()),
    (("policyQuery", "query"), 5, ("query_invalid",)),
    (("policyQuery", "query"), None, ("query_invalid",)),
    (("policyQuery", "query_scope"), "unreadable", ("query_invalid",)),
    (("policyQuery", "query_scope"), "targets", ()),
    (("setting", "value", "enforcedFrom"), "2020-01-01T00:00:00.123456789Z", ()),
    (("setting", "value", "enforcedFrom"), "2020-01-01T00:00:00.1234567891Z", ("two_step_value_invalid",)),
    (("policyQuery", "query"), "x" * 5000, ("query_invalid",)),
]


def test_r2_every_policy_field_has_a_validation_row_and_no_bad_value_is_complete_evidence() -> None:
    from auditex.google_workspace.collectors import policy_problems

    for path, value, expected in _FIELD_TABLE:
        policy = _variant(path, value)
        assert policy_problems(policy) == expected, (path, value)
        if not expected:
            continue
        # Collected beside a sound policy: the read is partial (failed for a page holding a non-object), the
        # normalised read incomplete and 2SV unknown.
        result, _service = _collect([{"policies": [policy, _gmail_row(orgUnit="orgUnits/sales")]}])
        (row,) = result.coverage
        status = "failed" if expected == ("policy_invalid",) else "partial"
        assert (row["status"], row["error_class"]) == (status, "malformed_response"), (path, value)
        normalized = _normalise(result.payload, result.status, result.coverage, {"orgUnits": {"value": []}})
        assert _read_state(normalized)["complete"] is False, (path, value)
        assert normalized["snapshot"]["two_step_policy_status"] == "unknown", (path, value)


def test_r2_a_query_scope_the_targets_cannot_represent_is_unsupported() -> None:
    org = "entity.org_units.exists(o, o.org_unit_id == orgUnitId('{}'))"
    group = "entity.groups.exists(g, g.group_id == groupId('{}'))"
    cases = [
        ({"orgUnit": "orgUnits/root"}, org.format("root"), True),
        ({"orgUnit": "orgUnits/root"}, "", True),
        ({"orgUnit": "orgUnits/root"}, org.format("sales"), False),
        ({"orgUnit": "orgUnits/root"}, f"{org.format('root')} && {org.format('root')}", False),
        ({"orgUnit": "orgUnits/root"}, f"{org.format('root')} || {group.format('g1')}", False),
        ({"orgUnit": "orgUnits/root"}, f"{org.format('root')} && {group.format('g1')}", False),
        ({"orgUnit": "orgUnits/root", "group": "groups/g1"}, f"{org.format('root')} && {group.format('g1')}", True),
        ({"orgUnit": "orgUnits/root", "group": "groups/g1"}, group.format("g1"), True),
        ({"orgUnit": "orgUnits/root", "group": "groups/g1"}, group.format("g2"), False),
        ({"orgUnit": "orgUnits/root", "group": "groups/g1"}, org.format("root"), False),
        ({"group": "groups/g1"}, f"{org.format('root')} && {group.format('g1')}", False),
        ({"orgUnit": "orgUnits/root"}, "entity.licenses.exists(l, l.sku == 'x')", False),
    ]
    for targets, query, supported in cases:
        policy = _gmail_row(**targets, query=query)
        if "orgUnit" not in targets:
            policy["policyQuery"].pop("orgUnit")
        state = _read_state(_normalise({"policySettings": {"value": [policy]}}, "ok", _OK_COVERAGE, _SALES_DIRECTORY))
        assert (state["record_count"], bool(state["unusable_scopes"])) == ((1, False) if supported else (0, True)), (targets, query)


# ---- M13 L03 repair round three: the round-three review's counterexamples ------------------------------------------

_DIRECTORY_OK = {"collector": "google_directory", "name": "orgUnits", "status": "ok"}
_SALES_QUERY = "entity.org_units.exists(org_unit, org_unit.org_unit_id == orgUnitId('sales'))"


def _policy_records(normalized: dict[str, Any]) -> list[tuple[Any, ...]]:
    return [
        (r["section"], r["unit_kind"], r.get("org_unit"), r.get("group"), r.get("sort_order"), r["value"])
        for r in normalized["google_policy_settings"]["records"]
        if r["id"] != "read_state"
    ]


def test_r3_b1_admin_written_setting_text_and_queries_never_reach_raw_or_normalised_files(tmp_path: Path) -> None:
    message = {
        "type": "ADMIN",
        "customer": "customers/C0SyntheticPolicyRef",
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1, "query": "entity.org_units.exists(o, o.org_unit_id == orgUnitId('root'))"},
        "setting": {
            "type": "settings/api_controls.custom_user_message",
            "value": {"errorText": "Contact support with reference C0SyntheticPolicyRef"},
        },
    }
    alerts = {
        "type": "ADMIN",
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
        "setting": {
            "type": "settings/rule.system_defined_alerts",
            "value": {"rules": [{"displayName": "Leaked password", "state": "ACTIVE"}, {"displayName": "Night shift escalation", "state": "ACTIVE"}]},
        },
    }
    result, _service = _collect([{"policies": [message, alerts]}])

    assert result.status == "ok"
    (written_message, written_alerts) = result.payload["policySettings"]["value"]
    assert written_message == {
        "type": "ADMIN",
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1, "query_scope": "targets"},
        "setting": {"type": "settings/api_controls.custom_user_message", "value": {}},
    }
    assert written_alerts["setting"]["value"] == {
        "rules": [{"displayName": "Leaked password", "state": "ACTIVE"}, {"displayName": "unrecognised", "state": "ACTIVE"}]
    }
    normalized = _normalise(result.payload, result.status, result.coverage, _SALES_DIRECTORY)
    assert ("api_controls_custom_user_message", "org_unit", "root", None, 1, {}) in _policy_records(normalized)

    rc, run_dir = _replay(tmp_path, json.loads(json.dumps(result.payload)))
    assert rc == 0
    text = _bundle_text(run_dir)
    for secret in ("C0SyntheticPolicyRef", "Contact support", "Night shift", "entity.org_units", "orgUnitId("):
        assert secret not in text, secret
    raw = json.loads((run_dir / "raw" / "google_policies.json").read_text(encoding="utf-8"))
    assert "errorText" not in json.dumps(raw)


def test_r3_b1_the_query_is_kept_only_as_its_parsed_scope() -> None:
    rows = minimise_policy_settings(
        [
            _gmail_row(query="entity.org_units.exists(o, o.org_unit_id == orgUnitId('root'))"),
            _gmail_row(query=_SALES_QUERY),
            _gmail_row(query=7),
            _gmail_row(query=""),
        ]
    )
    assert [row["policyQuery"] for row in rows] == [
        {"orgUnit": "orgUnits/root", "sortOrder": 1, "query_scope": "targets"},
        {"orgUnit": "orgUnits/root", "sortOrder": 1, "query_scope": "other"},
        {"orgUnit": "orgUnits/root", "sortOrder": 1, "query_scope": "unreadable"},
        {"orgUnit": "orgUnits/root", "sortOrder": 1},
    ]
    assert minimise_policy_settings(rows) == rows


def test_r3_b2_a_policy_for_a_deleted_unit_never_confirms_organisation_enforcement() -> None:
    empty_tree = {"orgUnits": {"value": []}}
    rows = [_two_step("orgUnits/root", {}), _two_step("orgUnits/deleted", _ENFORCED, sortOrder=2)]
    normalized = _normalise(_widened(rows), "ok", _OK_COVERAGE, empty_tree)

    assert [r["policy_scope"] for r in normalized["google_two_step_policies"]["records"]] == ["unclassified", "unclassified"]
    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"

    # With a unit tree, a unit it does not hold cannot be placed either.
    normalized = _normalise(_widened(rows), "ok", _OK_COVERAGE, _SALES_DIRECTORY)
    assert [r["policy_scope"] for r in normalized["google_two_step_policies"]["records"]] == ["organisation", "unclassified"]
    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"

    # Only Directory evidence can identify the root even with one policy target.
    normalized = _normalise(_widened([_two_step("orgUnits/root", _ENFORCED)]), "ok", _OK_COVERAGE, empty_tree)
    assert [r["policy_scope"] for r in normalized["google_two_step_policies"]["records"]] == ["unclassified"]
    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"


def test_r3_b3_a_system_group_policy_keeps_its_group_and_the_root_policy() -> None:
    root = {
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
        "setting": {"type": "settings/chat.space_history", "value": {"historyState": "HISTORY_ALWAYS_ON"}},
        "type": "ADMIN",
    }
    admins = {
        "policyQuery": {"orgUnit": "orgUnits/root", "group": "WORKSPACE_ALL_ADMIN_GROUP", "sortOrder": 2},
        "setting": {"type": "settings/chat.space_history", "value": {"historyState": "DEFAULT_HISTORY_ON"}},
        "type": "ADMIN",
    }
    result, _service = _collect([{"policies": [root, admins]}])

    assert result.status == "ok"
    (row,) = result.coverage
    assert row["status"] == "ok"
    normalized = _normalise(result.payload, result.status, result.coverage, _SALES_DIRECTORY)
    assert _policy_records(normalized) == [
        ("chat_space_history", "org_unit", "root", None, 1, {"historyState": "HISTORY_ALWAYS_ON"}),
        ("chat_space_history", "group", "root", "WORKSPACE_ALL_ADMIN_GROUP", 2, {"historyState": "DEFAULT_HISTORY_ON"}),
    ]
    state = _read_state(normalized)
    assert (state["complete"], state["unusable_sections"], state["unusable_scopes"]) == (True, [], [])
    # Any other group id without the prefix is still not a group.
    assert _collect([{"policies": [_gmail_row(group="ALL_STAFF")]}])[0].status == "partial"


def test_r3_b4_an_empty_page_that_carries_a_cursor_is_followed() -> None:
    for empty in ({"policies": [], "nextPageToken": "p3"}, {"nextPageToken": "p3"}):
        pages = [{"policies": [_gmail_row()], "nextPageToken": "p2"}, empty, {"policies": [_two_step("orgUnits/root", _ENFORCED)]}]
        result, service = _collect(pages)

        assert len(service.calls) == 3, empty
        assert [call["pageToken"] for call in service.calls] == [None, "p2", "p3"]
        (row,) = result.coverage
        assert (result.status, row["status"], bool(row.get("collection_truncated"))) == ("ok", "ok", False)
        normalized = _normalise(result.payload, result.status, [*result.coverage, _DIRECTORY_OK], _SALES_DIRECTORY)
        assert _read_state(normalized)["record_count"] == 2
        assert normalized["snapshot"]["two_step_policy_status"] == "enforcing"


def test_r3_b5_a_nanosecond_enforcement_timestamp_is_readable() -> None:
    result, _service = _collect([{"policies": [_two_step("orgUnits/root", {"enforcedFrom": "2020-01-01T00:00:00.123456789Z"})]}])

    assert result.status == "ok"
    normalized = _normalise(result.payload, result.status, [*result.coverage, _DIRECTORY_OK], _SALES_DIRECTORY)
    assert _read_state(normalized)["complete"] is True
    assert normalized["snapshot"]["two_step_policy_status"] == "enforcing"
    (record,) = normalized["google_two_step_policies"]["records"]
    assert record["enforced_from"] == "2020-01-01T00:00:00.123456789Z"
    # Ten fractional digits is not a ProtoJSON timestamp.
    assert _collect([{"policies": [_two_step("orgUnits/root", {"enforcedFrom": "2020-01-01T00:00:00.1234567891Z"})]}])[0].status == "partial"


def test_r3_m1_an_explicit_null_scope_field_or_cursor_is_not_an_omitted_one() -> None:
    for query in ({"group": None}, {"query": None}, {"group": None, "query": None}):
        result, _service = _collect([{"policies": [_two_step("orgUnits/root", _ENFORCED, **query)]}])
        (row,) = result.coverage
        assert (result.status, row["status"], row["error_class"]) == ("partial", "partial", "malformed_response"), query
        normalized = _normalise(result.payload, result.status, [*result.coverage, _DIRECTORY_OK], _SALES_DIRECTORY)
        assert (_read_state(normalized)["complete"], normalized["snapshot"]["two_step_policy_status"]) == (False, "unknown"), query
    result, _service = _collect([{"policies": [_two_step("orgUnits/root", _ENFORCED, orgUnit=None, group="groups/g1")]}])
    assert result.status == "partial"

    result, service = _collect([{"policies": [_gmail_row()], "nextPageToken": None}])
    assert len(service.calls) == 1
    (row,) = result.coverage
    assert (row["status"], row["error_class"]) == ("failed", "malformed_response")
    result, service = _collect([{"policies": [_gmail_row()], "nextPageToken": "p2"}, {"policies": [_gmail_row(sortOrder=2)], "nextPageToken": None}])
    (row,) = result.coverage
    assert (row["status"], row["collection_truncated"], row["truncation_reason"]) == ("partial", True, "pagination_failed")


def test_r3_m2_a_query_contradicting_its_targets_makes_the_collector_and_replay_partial(tmp_path: Path) -> None:
    contradicted = _two_step("orgUnits/root", _ENFORCED, query=_SALES_QUERY)
    result, _service = _collect([{"policies": [contradicted]}])

    assert result.status == "partial"
    (row,) = result.coverage
    assert (row["status"], row["error_class"], row["error"]) == (
        "partial",
        "malformed_response",
        "1 of 1 policies hold a scope their targets cannot show; the settings they hold for those units are unknown.",
    )

    replayed = _two_step("orgUnits/root-ou", _ENFORCED, query="entity.org_units.exists(o, o.org_unit_id == orgUnitId('sales-ou'))")
    rc, run_dir = _replay(tmp_path, _widened([replayed]))
    assert rc == 1
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert [row["status"] for row in summary["collectors"] if row["name"] == "google_policies"] == ["partial"]
    assert _bundle_state(run_dir)["complete"] is False


def test_r3_m3_the_probe_never_counts_an_unreadable_policy_as_a_read() -> None:
    from auditex.google_workspace.run import _preflight_call

    probe = _preflight_call("google_policies", "policySettings", lambda: _client(_ScriptedPolicies([{"policies": [{}]}])).list_policies(limit=1))
    assert (probe["status"], probe["error_class"], probe["item_count"], probe.get("authenticated_read")) == ("failed", "malformed_response", 0, None)

    probe = _preflight_call("google_policies", "policySettings", lambda: _client(_ScriptedPolicies([{"policies": [_gmail_row(), {}]}])).list_policies(limit=5))
    assert (probe["status"], probe["error_class"], probe["error"]) == (
        "partial",
        "malformed_response",
        "Some policies returned by the Cloud Identity policies read cannot be read; the settings they hold are unknown.",
    )


def test_r3_m4_an_earlier_placeholder_list_id_has_unknown_counts() -> None:
    legacy = {
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
        "setting": {
            "type": "settings/gmail.email_address_lists",
            "value": {"emailAddressList": [{"id": "redacted:path", "entry_count": 1, "domain_entry_count": 1}]},
        },
        "type": "ADMIN",
    }
    (policy,) = minimise_policy_settings([legacy])
    assert policy["setting"]["value"] == {"emailAddressList": [{"id": None, "entry_count": None, "domain_entry_count": None}]}
    state = _read_state(_normalise({"policySettings": {"value": [legacy]}}, "ok", _OK_COVERAGE))
    assert (state["complete"], state["unusable_scopes"]) == (
        False,
        [{"section": "gmail_email_address_lists", "org_unit": "root", "group": None}],
    )


def test_r3_m5_legacy_two_step_evidence_needs_a_placed_root_and_an_uncut_section() -> None:
    no_root = {"orgUnits": {"value": [None]}}
    legacy = {"twoStepVerificationPolicies": {"value": [_two_step("orgUnits/sales", {})]}}
    assert _normalise(legacy, "ok", _OK_COVERAGE, no_root)["snapshot"]["two_step_policy_status"] == "unknown"

    cut = {"twoStepVerificationPolicies": {"value": [_two_step("orgUnits/root", _ENFORCED)], "collection_truncated": True}}
    assert _normalise(cut, "ok", _OK_COVERAGE, _SALES_DIRECTORY)["snapshot"]["two_step_policy_status"] == "unknown"


def test_structural_b1_enum_shaped_admin_text_never_reaches_policy_artifacts(tmp_path: Path) -> None:
    message = {
        "type": "ADMIN",
        "customer": "customers/C0SYNTH731",
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
        "setting": {
            "type": "settings/api_controls.custom_user_message",
            "value": {"errorText": "INTERNAL_INCIDENT_731", "error_text": "INCIDENT_C0SYNTH731"},
        },
    }
    rc, run_dir = _replay(tmp_path, _widened([message]), directory=_SALES_DIRECTORY)
    assert rc == 0
    for name in ("raw/google_policies.json", "normalized/google_policy_settings.json"):
        artifact = (run_dir / name).read_text(encoding="utf-8")
        for text in ("INTERNAL_INCIDENT_731", "C0SYNTH731", "errorText", "error_text"):
            assert text not in artifact


def test_structural_b2_one_deleted_unit_cannot_supply_an_empty_tree_root(tmp_path: Path) -> None:
    rows = [_two_step("orgUnits/deleted", _ENFORCED)]
    empty_tree = {"orgUnits": {"value": []}}
    rc, run_dir = _replay(tmp_path, _widened(rows), directory=empty_tree)
    assert (_bundle_two_step_status(run_dir), rc, _bundle_state(run_dir)["complete"]) == ("unknown", 1, False)
    assert _bundle_state(run_dir)["unusable_scopes"] == [
        {"section": "security_two_step_verification_enforcement", "org_unit": "deleted", "group": None},
    ]


def test_structural_b3_gmail_spam_bypass_references_join_to_the_list_summary(tmp_path: Path) -> None:
    list_id = "a1234-synthetic012:00synthetic03"
    rule_id = "b1234-synthetic012:00synthetic04"
    rows = [
        _policy_setting("gmail.email_address_lists", {"emailAddressList": [
            {"id": list_id, "addressList": {"address": [{"address": "domain.example"}]}},
        ]}),
        _policy_setting("gmail.rule_states", {"ruleStates": [{"ruleId": rule_id, "enabled": True}]}),
        _policy_setting("gmail.spam_override_lists", {"spamOverride": [
            {"ruleId": rule_id, "bypassSelectedSenders": True, "bypassSenderAllowlist": [list_id]},
        ]}),
    ]
    result, _service = _collect([{"policies": rows}])
    rc, run_dir = _replay(tmp_path, result.payload, directory=_SALES_DIRECTORY)
    assert (rc, _bundle_state(run_dir)["complete"]) == (0, True)
    assert "domain.example" not in _bundle_text(run_dir)
    raw = json.loads((run_dir / "raw/google_policies.json").read_text())
    normalized = json.loads((run_dir / "normalized/google_policy_settings.json").read_text())
    expected = [
        {"emailAddressList": [{"id": "a1234-synthetic012:00synthetic03", "entry_count": 1, "domain_entry_count": 1}]},
        {"ruleStates": [{"ruleId": "b1234-synthetic012:00synthetic04", "enabled": True}]},
        {"spamOverride": [{"ruleId": "b1234-synthetic012:00synthetic04", "bypassSelectedSenders": True,
                          "bypassSenderAllowlist": ["a1234-synthetic012:00synthetic03"]}]},
    ]
    assert [row["setting"]["value"] for row in raw["policySettings"]["value"]] == expected
    assert [row["value"] for row in normalized["records"] if row["id"] != "read_state"] == expected


def _policy_setting(section: str, value: dict[str, Any], **query: Any) -> dict[str, Any]:
    return {
        "type": "SYSTEM",
        "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1, **query},
        "setting": {"type": f"settings/{section}", "value": value},
    }


def test_m13_b1_distinct_system_alert_rules_at_the_same_order_keep_the_read_complete() -> None:
    # ScubaGoggles 08a08ce1, policyapi_get_policies5.json: keep the rule names, states and order,
    # and replace the root ID and omit resource names and customer metadata.
    rows = [_two_step()] + [
        _policy_setting("rule.system_defined_alerts", {"displayName": name, "state": state}, sortOrder=1) | {"type": "ADMIN"}
        for name, state in (
            ("User-reported phishing", "ACTIVE"),
            ("User suspended for spamming through relay", "ACTIVE"),
            ("User suspended (Google identity alert)", "ACTIVE"),
            ("App Maker Cloud SQL setup", "INACTIVE"),
            ("Suspicious login", "ACTIVE"),
            ("Super admin password reset", "ACTIVE"),
            ("Government-backed attacks", "ACTIVE"),
        )
    ]
    result, _ = _collect([{"policies": rows}])
    assert (result.status, result.item_count) == ("ok", 8)
    root = {"orgUnits": {"value": [{"orgUnitId": "id:root", "orgUnitPath": "/"}]}}
    snapshot = _normalise(result.payload, result.status, result.coverage, root)
    *records, state = snapshot["google_policy_settings"]["records"]
    assert (state["complete"], state["record_count"], state["malformed_count"], state["unusable_scopes"]) == (True, 7, 0, [])
    assert [(r["org_unit"], r["sort_order"], r["value"]) for r in records if r["section"] == "rule_system_defined_alerts"] == [
        ("root", 1, {"displayName": "User-reported phishing", "state": "ACTIVE"}),
        ("root", 1, {"displayName": "User suspended for spamming through relay", "state": "ACTIVE"}),
        ("root", 1, {"displayName": "User suspended (Google identity alert)", "state": "ACTIVE"}),
        ("root", 1, {"displayName": "Suspicious login", "state": "ACTIVE"}),
        ("root", 1, {"displayName": "Super admin password reset", "state": "ACTIVE"}),
        ("root", 1, {"displayName": "Government-backed attacks", "state": "ACTIVE"}),
    ]
    assert len({r["id"] for r in records}) == 7


def test_m13_b1_only_conflicting_alert_values_for_the_same_name_need_precedence() -> None:
    active = {"displayName": "Suspicious login", "state": "ACTIVE"}
    inactive = {"displayName": "Suspicious login", "state": "INACTIVE"}
    scope = {"section": "rule_system_defined_alerts", "org_unit": "root", "group": None}
    for value, order, expected in (
        (active, 1, (True, 3, [])),
        (inactive, 2, (True, 3, [])),
        (inactive, 1, (False, 1, [scope])),
        ({"rules": [inactive]}, 1, (False, 1, [scope])),
    ):
        rows = [
            _two_step(),
            _policy_setting("rule.system_defined_alerts", active),
            _policy_setting("rule.system_defined_alerts", value, sortOrder=order),
        ]
        snapshot = _normalise(_widened(rows), "ok", _OK_COVERAGE, _SALES_DIRECTORY)
        state = _read_state(snapshot)
        assert (state["complete"], state["record_count"], state["unusable_scopes"]) == expected


def test_m13_b1_gmail_rule_ties_are_checked_by_rule_id() -> None:
    rows = [
        _two_step(),
        _policy_setting("gmail.rule_states", {"ruleStates": [{"ruleId": "rule-1", "enabled": True}]}),
        _policy_setting("gmail.rule_states", {"ruleStates": [
            {"ruleId": "rule-2", "enabled": False}, {"ruleId": "rule-1", "enabled": True},
        ]}),
    ]
    snapshot = _normalise(_widened(rows), "ok", _OK_COVERAGE, _SALES_DIRECTORY)
    state = _read_state(snapshot)
    assert (state["complete"], state["record_count"], state["unusable_scopes"]) == (True, 3, [])

    rows.append(_policy_setting("gmail.rule_states", {"ruleStates": [{"ruleId": "rule-1", "enabled": False}]}))
    snapshot = _normalise(_widened(rows), "ok", _OK_COVERAGE, _SALES_DIRECTORY)
    state = _read_state(snapshot)
    assert (state["complete"], state["record_count"], state["unusable_scopes"]) == (
        False, 1, [{"section": "gmail_rule_states", "org_unit": "root", "group": None}],
    )


def test_m13_followup_n1_unlisted_google_alert_keeps_the_policy_read_complete(tmp_path: Path) -> None:
    rows = [
        _two_step(), _two_step("orgUnits/sales", _ENFORCED),
        _policy_setting("rule.system_defined_alerts", {"displayName": "Leaked password", "state": "ACTIVE"}),
        _policy_setting("rule.system_defined_alerts", {"displayName": "App Maker Cloud SQL setup", "state": "INACTIVE"}),
    ]
    result, _ = _collect([{"policies": rows}])
    assert (result.status, result.item_count) == ("ok", 4)
    assert result.payload["policySettings"]["value"][3]["setting"]["value"] == {
        "displayName": "unrecognised", "state": "INACTIVE",
    }
    rc, run_dir = _replay(tmp_path, _widened(rows))
    assert (rc, _bundle_two_step_status(run_dir), _bundle_state(run_dir)["complete"]) == (0, "partial", True)
    assert _bundle_state(run_dir)["malformed_count"] == 0
    assert "App Maker Cloud SQL setup" not in _bundle_text(run_dir)
    assert "Leaked password" in (run_dir / "normalized/google_policy_settings.json").read_text(encoding="utf-8")


def test_m13_followup_n2_single_ou_keeps_root_settings_and_the_two_step_finding(tmp_path: Path) -> None:
    class Directory:
        def orgunits(self) -> Directory:
            return self

        def list(self, **kwargs: Any) -> _Request:
            units = [{"orgUnitId": "id:root", "orgUnitPath": "/"}] if kwargs["type"] == "allIncludingParent" else []
            return _Request({"organizationUnits": units})

    client = _client(_Policies([]))
    assert client._services is not None
    client._services[("admin", "directory_v1")] = Directory()
    directory = {"orgUnits": {"value": client.list_directory("orgUnits")}}
    for name, value, status in (("disabled", {}, "not_enforced"), ("enabled", _ENFORCED, "enforcing")):
        rc, run_dir = _replay(tmp_path / name, _widened([_two_step(value=value), _gmail_row()]), directory=directory)
        assert (rc, _bundle_two_step_status(run_dir), _bundle_state(run_dir)["complete"]) == (0, status, True)
        assert _bundle_state(run_dir)["record_count"] == 2
        records = json.loads((run_dir / "normalized/google_policy_settings.json").read_text(encoding="utf-8"))["records"]
        assert [(row["org_unit"], row["value"]) for row in records if row.get("section") == "gmail_auto_forwarding"] == [
            ("root", {"enableAutoForwarding": False}),
        ]
        findings = (run_dir / "findings/findings.json").read_text(encoding="utf-8")
        assert ("google.org_2sv_policy_not_enforced" in findings) is (name == "disabled")


def test_m13_followup_n3_unlisted_gmail_setting_keeps_readable_two_step_evidence(tmp_path: Path) -> None:
    rows = [
        _two_step(), _two_step("orgUnits/sales", _ENFORCED), _gmail_row(),
        _policy_setting("gmail.future_setting", {"enabled": True, "text": "INTERNAL_SETTING_731"}),
    ]
    result, _ = _collect([{"policies": rows}])
    assert (result.status, result.item_count) == ("ok", 4)
    assert result.payload["policySettings"]["value"][3] == {"setting": {"type": "unrecognised"}}
    rc, run_dir = _replay(tmp_path, _widened(rows))
    assert (rc, _bundle_two_step_status(run_dir), _bundle_state(run_dir)["complete"]) == (0, "partial", True)
    assert _bundle_state(run_dir)["record_count"] == 3
    assert "google.org_2sv_policy_not_enforced" in (run_dir / "findings/findings.json").read_text(encoding="utf-8")
    raw = json.loads((run_dir / "raw/google_policies.json").read_text(encoding="utf-8"))
    assert raw["policySettings"]["value"][3] == {"setting": {"type": "unrecognised"}}
    assert "future_setting" not in _bundle_text(run_dir) and "INTERNAL_SETTING_731" not in _bundle_text(run_dir)


def test_m13_followup_n4_all_nine_takeout_types_are_requested_and_projected() -> None:
    apps = ("blogger", "books", "location_history", "maps", "pay", "photos", "play", "play_console", "youtube")
    rows = [_policy_setting(f"{app}.user_takeout", {"takeout_status": "ENABLED"}) for app in apps]
    service = _Policies(rows)
    result = GooglePoliciesCollector().run({"client": _client(service)})
    setting_filter = service.calls[0]["filter"]
    pattern = re.compile(setting_filter.split("matches('", 1)[1][:-len("')")].replace("\\\\", "\\"))
    assert all(pattern.fullmatch(f"settings/{app}.user_takeout") for app in apps)
    assert pattern.fullmatch("settings/blogger_user_takeout.service_status") is None
    assert pattern.fullmatch("settings/blogger.service_status") is None
    normalized = _normalise(result.payload, result.status, result.coverage, _SALES_DIRECTORY)
    assert (result.status, _read_state(normalized)["complete"]) == ("ok", True)
    assert _policy_records(normalized) == [
        (f"{app}_user_takeout", "org_unit", "root", None, 1, {"takeoutStatus": "ENABLED"}) for app in apps
    ]


def test_structural_b4_licence_qualifier_does_not_suppress_readable_2sv() -> None:
    gmail = _policy_setting(
        "gmail.confidential_mode", {"enableConfidentialMode": True},
        query="entity.org_units.exists(o, o.org_unit_id == orgUnitId('root')) && "
        "entity.licenses.exists(license, license in ['/product/Google-Apps/sku/1010020020'])",
    )
    rows = [_two_step("orgUnits/root", {}), _two_step("orgUnits/sales", _ENFORCED), gmail]
    result, _service = _collect([{"policies": rows}])
    normalized = _normalise(result.payload, result.status, result.coverage, _SALES_DIRECTORY)
    assert normalized["snapshot"]["two_step_policy_status"] == "partial"
    assert any(f["rule_id"] == "google.org_2sv_policy_not_enforced" for f in build_google_findings(normalized))
    state = _read_state(normalized)
    assert state["complete"] is False
    assert state["unusable_scopes"] == [{"section": "gmail_confidential_mode", "org_unit": "root", "group": None}]


def test_structural_b5_nanosecond_after_as_of_is_scheduled(tmp_path: Path) -> None:
    rows = [_two_step(value={"enforcedFrom": "2026-11-25T12:00:00.000000001Z"})]
    rc, run_dir = _replay(tmp_path, _widened(rows), directory=_SALES_DIRECTORY, as_of=datetime(2026, 11, 25, 12, tzinfo=UTC))
    assert (rc, _bundle_two_step_status(run_dir)) == (0, "scheduled")


def test_structural_m1_empty_legacy_policy_evidence_has_no_finding_and_fails(tmp_path: Path) -> None:
    rc, run_dir = _replay(tmp_path, {"twoStepVerificationPolicies": {"value": []}})
    assert (rc, _bundle_two_step_status(run_dir)) == (1, "unknown")
    assert "google.org_2sv_policy_not_enforced" not in (run_dir / "findings/findings.json").read_text(encoding="utf-8")


def test_structural_m2_probe_counts_only_readable_rows() -> None:
    from auditex.google_workspace.run import _preflight_call

    client = _client(_ScriptedPolicies([{"policies": [_gmail_row(), {}]}]))
    probe = _preflight_call("google_policies", "policySettings", lambda: client.list_policies(limit=5))
    assert (probe["status"], probe["error_class"], probe["item_count"]) == ("partial", "malformed_response", 1)


def test_policy_allow_list_marks_unreadable_typed_fields_partial() -> None:
    cases = [
        ("gmail.auto_forwarding", {"enableAutoForwarding": "false"}, {"enableAutoForwarding": None}),
        ("rule.system_defined_alerts", {"state": "INACTIVE"}, {"displayName": None, "state": "INACTIVE"}),
        ("rule.system_defined_alerts", {"displayName": False, "state": "INACTIVE"}, {"displayName": None, "state": "INACTIVE"}),
        ("meet.safety_access", {"meetingsAllowedToJoin": "INCIDENT_1234"}, {"meetingsAllowedToJoin": None}),
        ("security.password", {"minimumLength": True}, {"minimumLength": None}),
        ("security.password", {"minimumLength": 10**30}, {"minimumLength": None}),
        ("security.password", {"expirationDuration": []}, {"expirationDuration": None}),
        ("gmail.email_spam_filter_ip_allowlist", {"allowedIpAddresses": [None]}, {"allowedIpAddresses": [None]}),
        ("gmail.rule_states", {"ruleStates": [{}]}, {"ruleStates": [{"ruleId": None, "enabled": None}]}),
        ("gmail.auto_forwarding", {"enableAutoForwarding": True, "enable_auto_forwarding": False}, {"enableAutoForwarding": None}),
        ("gmail.spam_override_lists", {"spamOverride": [
            {"rule_id": "rule-1", "bypass_selected_senders": True},
        ]}, {"spamOverride": [
            {"ruleId": "rule-1", "bypassSelectedSenders": True, "bypassSenderAllowlist": None},
        ]}),
        ("api_controls.google_services", {"services": {}}, {"services": None}),
        ("gmail.spam_override_lists", {"spamOverride": [
            {"ruleId": "rule-1", "bypassSelectedSenders": True, "bypassSenderAllowlist": ["ref-C0SYNTH731"]},
        ]}, {"spamOverride": [
            {"ruleId": "rule-1", "bypassSelectedSenders": True, "bypassSenderAllowlist": [None]},
        ]}),
    ]
    for section, supplied, expected in cases:
        result, _ = _collect([{"policies": [_policy_setting(section, supplied)]}])
        assert result.status == "partial", section
        assert result.payload["policySettings"]["value"][0]["setting"]["value"] == expected, section
        state = _read_state(_normalise(result.payload, result.status, result.coverage, _SALES_DIRECTORY))
        assert (state["record_count"], state["malformed_count"], state["complete"]) == (0, 1, False), section


def test_licence_inclusion_and_exclusion_are_conditional_on_replay(tmp_path: Path) -> None:
    gmail = _policy_setting(
        "gmail.confidential_mode", {"enableConfidentialMode": True},
        query="entity.org_units.exists(o, o.org_unit_id == orgUnitId('root')) && "
        "entity.licenses.exists(lic, lic in ['/product/Google-Apps/sku/1010020020', 'GOOGLE-IDENTITY']) && "
        "!entity.licenses.exists(lic, lic in ['/product/Google-Apps/sku/1010060005'])",
    )
    result, _ = _collect([{"policies": [_two_step(), _two_step("orgUnits/sales", _ENFORCED), gmail]}])
    assert result.payload["policySettings"]["value"][2]["policyQuery"]["query_scope"] == "licences"
    rc, run_dir = _replay(tmp_path, result.payload)
    assert (rc, _bundle_two_step_status(run_dir)) == (1, "partial")
    for sku in ("1010020020", "GOOGLE-IDENTITY", "1010060005"):
        assert sku not in _bundle_text(run_dir)


def test_two_step_finding_excludes_a_scope_scheduled_one_nanosecond_ahead() -> None:
    directory = {"orgUnits": {"value": [
        {"orgUnitId": "id:sales", "parentOrgUnitId": "id:root", "parentOrgUnitPath": "/"},
        {"orgUnitId": "id:eng", "parentOrgUnitId": "id:root", "parentOrgUnitPath": "/"},
    ]}}
    instant = datetime(2026, 11, 25, 12, tzinfo=UTC)
    policies = _widened([
        _two_step(), _two_step("orgUnits/sales", {"enforcedFrom": "2026-11-25T13:30:00+01:30"}),
        _two_step("orgUnits/eng", {"enforcedFrom": "2026-11-25T13:30:00.000000001+01:30"}),
    ])
    snapshot = build_google_normalized_snapshot(
        tenant_name="T", run_id="r1", collector_payloads={"google_directory": directory, "google_policies": policies},
        result_rows=[{"name": "google_policies", "status": "ok"}], coverage_rows=_OK_COVERAGE, as_of=instant,
    )
    (finding,) = [f for f in build_google_findings(snapshot, now=instant) if f["rule_id"] == "google.org_2sv_policy_not_enforced"]
    assert finding["returned_value"]["enforced_scopes"] == [
        {"scope": "org_unit", "org_unit": "orgUnits/sales", "enforced_from": "2026-11-25T12:00:00Z"},
    ]
    assert snapshot["google_two_step_policies"]["records"][2]["enforced_from"] == "2026-11-25T12:00:00.000000001Z"


def test_l03b_a_policy_target_is_dangling_only_against_a_complete_directory_read() -> None:
    # M13-L03b: without a complete org unit read no target can be called absent, so the policies read is not marked
    # partial; the 2SV status goes unknown instead (tests/test_gate_integrity.py keeps the compare reason).
    from auditex.google_workspace.normalize import unplaced_policy_count

    policies = {"google_policies": _widened([_two_step("orgUnits/root", _ENFORCED), _two_step("orgUnits/deleted", _ENFORCED)])}
    partial = [{"collector": "google_directory", "name": "orgUnits", "status": "partial"}]
    cut = {"orgUnits": {"value": [], "collection_truncated": True}}
    for directory, coverage in (
        (None, _OK_COVERAGE),
        ({}, _OK_COVERAGE),
        ({"orgUnits": None}, _OK_COVERAGE),
        (_SALES_DIRECTORY, partial),
        (cut, _OK_COVERAGE),
        ({"orgUnits": {"value": [None]}}, _OK_COVERAGE),
    ):
        payloads = {**policies, "google_directory": directory}
        assert unplaced_policy_count(payloads, coverage) == 0, directory
    # A complete tree holds the root but not the deleted unit; a complete empty tree holds neither.
    assert unplaced_policy_count({**policies, "google_directory": _SALES_DIRECTORY}, _OK_COVERAGE) == 1
    assert unplaced_policy_count({**policies, "google_directory": {"orgUnits": {"value": []}}}, _OK_COVERAGE) == 2


def test_l03b_a_present_but_malformed_org_unit_read_fails_the_replay(tmp_path: Path) -> None:
    # A present, unreadable orgUnits section is a Directory read failure: no dangling target is counted, but the run is
    # partial and exits non-zero. The 2SV status stays unknown.
    policies = _widened([_two_step("orgUnits/root", _ENFORCED)])
    for index, orgunits in enumerate(({"value": [None]}, None, {"value": "unreadable"})):
        rc, run_dir = _replay(tmp_path / str(index), policies, directory={"orgUnits": orgunits})
        manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
        summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
        assert rc == 1, orgunits
        assert manifest["overall_status"] == "partial", orgunits
        assert [row["status"] for row in summary["collectors"] if row["name"] == "google_directory"] == ["partial"], orgunits
        assert _bundle_two_step_status(run_dir) == "unknown", orgunits
