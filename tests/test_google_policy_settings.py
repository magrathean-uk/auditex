"""M13 L03: the Policy API read widened to the SCuBA setting types, minimised, with a completeness signal.

Synthetic data only; every expected value is a literal.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from auditex.google_workspace.client import GoogleWorkspaceClient
from auditex.google_workspace.collectors import (
    COLLECTOR_SECTIONS,
    GooglePoliciesCollector,
)
from auditex.google_workspace.normalize import build_google_normalized_snapshot
from azure_tenant_audit.data_minimisation import (
    minimise_policy_settings,
    minimise_user_text,
)

ADDRESSES = ("partner@example.org", "alerts@example.com", "ops@example.net")

FILTER = (
    'customer == "customers/C123" && '
    "setting.type.matches('^settings/((gmail|security|drive_and_docs|calendar|chat|meet|classroom|"
    "groups_for_business|sites|takeout|blogger_user_takeout|books_user_takeout|location_history_user_takeout|"
    "maps_user_takeout|pay_user_takeout|photos_user_takeout|play_user_takeout|play_console_user_takeout|"
    "youtube_user_takeout|data_regions|workspace_marketplace|api_controls|provisioning|multi_party_approval|"
    "enterprise_service_restrictions|early_access_apps|gemini_app|access_approval|access_management)"
    r"\\..*|rule\\.system_defined_alerts)$')"
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
                "value": {"spamOverride": [{"ruleId": "list-1", "description": "Ask ops@example.net", "bypassSelectedSenders": True}]},
            },
            "type": "ADMIN",
        },
        {
            "name": "policies/p-alerts",
            "customer": "customers/C123",
            "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
            "setting": {
                "type": "settings/rule.system_defined_alerts",
                "value": {"displayName": "Leaked password", "action": {"recipients": ["alerts@example.com"]}},
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
    # The 2-step verification subset keeps today's raw shape, name and customer included.
    assert result.payload["twoStepVerificationPolicies"] == {"value": [_two_step_root()]}
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
                "setting": {"type": "settings/gmail.spam_override_lists", "value": {"spamOverride": [{"ruleId": "list-1", "bypassSelectedSenders": True}]}},
                "type": "ADMIN",
            },
            {
                "policyQuery": {"orgUnit": "orgUnits/root", "sortOrder": 1},
                "setting": {
                    "type": "settings/rule.system_defined_alerts",
                    "value": {"displayName": "Leaked password", "action": {"recipients": ["redacted:address"]}},
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

    normalized = _normalise(result.payload, result.status, result.coverage)

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
    }
    text = json.dumps(normalized["google_policy_settings"])
    assert not any(address in text for address in ADDRESSES)
    assert "customers/" not in text and "C123" not in text and "policies/" not in text
    # The 2-step verification view is the one it was before the widening.
    assert normalized["snapshot"]["two_step_policy_status"] == "unknown"  # no org unit list: root unknown
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


def test_an_operator_limit_cut_makes_the_read_partial_and_incomplete() -> None:
    service = _Policies(_rows())
    result = GooglePoliciesCollector().run({"client": _client(service, page_size=2), "top": 2})

    assert result.status == "partial"
    (row,) = result.coverage
    assert row["status"] == "partial" and row["collection_truncated"] is True and row["result_limit"] == 2
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
        ("policies/two-step-enforcement-root", "organisation"),
        ("policies/two-step-enforcement-sales", "org_unit"),
        ("policies/two-step-enrollment-root", "organisation"),
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
    sample["google_policies"]["policySettings"] = {"value": _rows()}
    path = tmp_path / "sample.json"
    path.write_text(json.dumps(sample), encoding="utf-8")

    rc = run_google_offline(sample_path=path, out=tmp_path / "out", tenant_name="E", run_name="g", domain="example.com", customer_id="C123")

    assert rc == 0
    run_dir = tmp_path / "out" / "E-g"
    state = json.loads((run_dir / "normalized" / "google_policy_settings.json").read_text(encoding="utf-8"))["records"][-1]
    assert (state["complete"], state["record_count"]) == (True, 5)
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
    assert odd_out == {
        "policyQuery": {"group": "redacted:address", "orgUnit": "orgUnits/root"},
        "setting": {"type": "settings/chat.chat_file_sharing", "note": "redacted:address", "value": {
            "a": {"id": None, "enabled": True, "entry_count": 1, "domain_entry_count": 0}}},
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
