"""OneDrive, SharePoint and Teams external sharing (CE+ product review, action 8).

Sharing is a tenant setting. These tests cover reading it in each spelling it arrives in, the one
graded OneDrive finding in place of a finding per site, the SharePoint rules that read the link and
domain settings, and the Teams rule that fires only for federation with no allow list.
"""
from __future__ import annotations

from typing import Any

import pytest

from azure_tenant_audit import external_sharing as sharing
from azure_tenant_audit.baselines import build_baseline_alignment, rule_inputs_gap
from azure_tenant_audit.collectors.onedrive_posture import OneDrivePostureCollector
from azure_tenant_audit.collectors.teams_policy import TeamsPolicyCollector
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot

ANYONE = "externalUserAndGuestSharing"


# ---- reading the settings ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("externalUserAndGuestSharing", "externalUserAndGuestSharing"),
        ("ExternalUserAndGuestSharing", "externalUserAndGuestSharing"),
        ("existingExternalUserSharingOnly", "existingExternalUserSharingOnly"),
        ("ExternalUserSharingOnly", "externalUserSharingOnly"),
        ("disabled", "disabled"),
        (0, "disabled"),
        (1, "externalUserSharingOnly"),
        (2, "externalUserAndGuestSharing"),
        (3, "existingExternalUserSharingOnly"),
        ("2", "externalUserAndGuestSharing"),
        (9, None),
        (True, None),
        ("everyone", None),
        (None, None),
    ],
)
def test_the_sharing_capability_reads_names_and_numbers(value: Any, expected: str | None) -> None:
    assert sharing.canonical_sharing_capability(value) == expected


def test_a_graph_payload_and_a_sharepoint_shell_payload_read_alike() -> None:
    graph = sharing.tenant_settings_fields(
        {
            "sharingCapability": "externalUserAndGuestSharing",
            "sharingDomainRestrictionMode": "allowList",
            "sharingAllowedDomainList": ["partner.example", "other.example"],
            "sharingBlockedDomainList": [],
        }
    )
    shell = sharing.tenant_settings_fields(
        {
            "SharingCapability": 2,
            "SharingDomainRestrictionMode": 1,
            "SharingAllowedDomainList": "partner.example other.example",
            "DefaultSharingLinkType": "Direct",
            "RequireAnonymousLinksExpireInDays": 30,
            "FileAnonymousLinkType": "View",
            "FolderAnonymousLinkType": 2,
            "ODBSharingCapability": 3,
        }
    )

    assert graph == {
        "sharing_capability": ANYONE,
        "sharing_domain_restriction_mode": "allowList",
        "allowed_domain_count": 2,
        "blocked_domain_count": 0,
    }
    assert shell == {
        "sharing_capability": ANYONE,
        "onedrive_sharing_capability": "existingExternalUserSharingOnly",
        "sharing_domain_restriction_mode": "allowList",
        "allowed_domain_count": 2,
        "default_sharing_link_type": "direct",
        "anonymous_link_expiry_days": 30,
        "file_anonymous_link_type": "view",
        "folder_anonymous_link_type": "edit",
    }


def test_a_setting_that_is_absent_is_unknown_and_one_that_is_unrecognised_is_listed() -> None:
    fields = sharing.tenant_settings_fields({"sharingCapability": "somethingNew", "defaultSharingLinkType": ""})

    assert fields == {"unrecognised": {"sharing_capability": "somethingNew"}}
    assert sharing.tenant_settings_fields({}) == {}


@pytest.mark.parametrize(
    ("value", "days"),
    [(30, 30), ("45", 45), (0, 0), (-1, 0), (None, None), ("never", None), (True, None)],
)
def test_the_anonymous_link_expiry_reads_no_expiry_as_zero(value: Any, days: int | None) -> None:
    assert sharing.anonymous_link_expiry_days(value) == days


@pytest.mark.parametrize(
    ("value", "state", "count"),
    [
        ("AllowAllKnownDomains", "open", 0),
        ({}, "open", 0),
        ({"AllowedDomain": []}, "allow_list", 0),
        ("", "unknown", 0),
        ("  ", "unknown", 0),
        ([], "unknown", 0),
        ({"AllowedDomain": [{"Domain": "partner.example"}, {"Domain": "other.example"}]}, "allow_list", 2),
        (["partner.example"], "allow_list", 1),
        ("partner.example, other.example", "allow_list", 2),
        (None, "unknown", 0),
        ({"Surprise": 7}, "unknown", 0),
    ],
)
def test_the_federation_allow_list_is_open_only_when_no_list_restricts_it(value: Any, state: str, count: int) -> None:
    assert sharing.federation_allow_list(value) == (state, count)


def test_the_blocked_domain_count_is_none_when_it_was_not_collected() -> None:
    assert sharing.federation_block_count(None) is None
    assert sharing.federation_block_count([]) == 0
    assert sharing.federation_block_count([{"Domain": "a.example"}, "b.example"]) == 2


# ---- grading -----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("capability", "anyone", "known", "severity"),
    [
        ("disabled", 0, 5, None),
        ("existingExternalUserSharingOnly", 0, 5, None),
        ("externalUserSharingOnly", 0, 5, "low"),
        (ANYONE, 5, 5, "high"),
        (ANYONE, 0, 0, "high"),
        (ANYONE, 3, 5, "high"),
        (ANYONE, 2, 5, "medium"),
        (None, 0, 0, None),
    ],
)
def test_onedrive_sharing_is_graded_by_capability_and_share_of_sites(
    capability: str | None, anyone: int, known: int, severity: str | None
) -> None:
    assert sharing.grade_onedrive_sharing(capability, anyone_sites=anyone, known_sites=known) == severity


def test_anyone_links_stay_high_unless_expiry_and_view_only_are_both_known() -> None:
    base = {"sharing_capability": ANYONE}

    assert sharing.grade_anyone_links({"sharing_capability": "externalUserSharingOnly"})[0] is None
    assert sharing.grade_anyone_links(base)[0] == "high"
    severity, mitigations, not_read = sharing.grade_anyone_links(base)
    assert mitigations == [] and not_read == [
        "anonymous_link_expiry_days", "file_anonymous_link_type", "folder_anonymous_link_type"
    ]
    full = {**base, "anonymous_link_expiry_days": 14, "file_anonymous_link_type": "view", "folder_anonymous_link_type": "view"}
    assert sharing.grade_anyone_links(full)[0] == "medium"
    assert sharing.grade_anyone_links({**full, "anonymous_link_expiry_days": 90})[0] == "high"
    assert sharing.grade_anyone_links({**full, "anonymous_link_expiry_days": 0})[0] == "high"
    assert sharing.grade_anyone_links({**full, "folder_anonymous_link_type": "edit"})[0] == "high"
    assert sharing.grade_anyone_links({**base, "anonymous_link_expiry_days": 14})[0] == "high"


def _breaches(grade: dict[str, Any] | None) -> dict[str, bool] | None:
    return grade["breaches"] if grade else None


def test_the_capability_is_graded_against_what_each_benchmark_allows() -> None:
    assert sharing.grade_external_sharing({"sharing_capability": "disabled"}) is None
    assert sharing.grade_external_sharing({"sharing_capability": "existingExternalUserSharingOnly"}) is None
    assert sharing.grade_external_sharing({}) is None
    guests = sharing.grade_external_sharing({"sharing_capability": "externalUserSharingOnly"})
    anyone = sharing.grade_external_sharing({"sharing_capability": ANYONE})

    # CIS 7.2.3 allows new and existing guests; ScubaGear's MS.SHAREPOINT.1.1v1 does not.
    assert guests["severity"] == "low" and guests["breaches"] == {"cis_m365_v7": False, "cisa_scuba": True, "cyber_essentials": False}
    assert anyone["severity"] == "high" and anyone["breaches"] == {"cis_m365_v7": True, "cisa_scuba": True, "cyber_essentials": True}


def test_domain_restriction_is_graded_against_what_each_benchmark_allows() -> None:
    def grade(capability: str | None, mode: str | None) -> dict[str, Any] | None:
        settings = {key: value for key, value in (("sharing_capability", capability), ("sharing_domain_restriction_mode", mode)) if value}
        return sharing.grade_domain_restriction(settings)

    assert grade("disabled", "none") is None, "sharing off: nothing to restrict"
    assert grade(ANYONE, "allowList") is None
    assert grade(ANYONE, None) is None, "unread is unknown"
    none_list = grade(ANYONE, "none")
    assert none_list["severity"] == "medium" and none_list["breaches"] == {"cis_m365_v7": True, "cisa_scuba": True}
    assert grade("existingExternalUserSharingOnly", "none")["severity"] == "low"
    # CIS 7.2.6 accepts a block list; ScubaGear's MS.SHAREPOINT.1.3v1 passes only an allow list.
    block = grade(ANYONE, "blockList")
    assert block["severity"] == "low" and block["breaches"] == {"cis_m365_v7": False, "cisa_scuba": True}


def test_the_default_link_type_must_be_specific_people_for_both_benchmarks() -> None:
    def grade(link_type: str | None) -> dict[str, Any] | None:
        return sharing.grade_default_link_type({"default_sharing_link_type": link_type} if link_type else {})

    assert grade("direct") is None and grade(None) is None
    assert {link_type: grade(link_type)["severity"] for link_type in ("anonymous", "internal", "none")} == {
        "anonymous": "high", "internal": "low", "none": "low",
    }
    assert all(_breaches(grade(link_type)) == {"cis_m365_v7": True, "cisa_scuba": True} for link_type in ("anonymous", "internal", "none"))


# ---- collectors ---------------------------------------------------------------------------------------


class _Client:
    def __init__(self, settings: Any, sites: list[dict[str, Any]]) -> None:
        self._settings = settings
        self._sites = sites

    def get_json(self, path: str, params: Any = None, full_url: bool = False) -> Any:  # noqa: ARG002
        assert path == "/admin/sharepoint/settings"
        return self._settings

    def get_all(self, path: str, params: Any = None) -> list[dict[str, Any]]:  # noqa: ARG002
        assert path == "/sites"
        return self._sites


def test_the_onedrive_collector_marks_a_copied_tenant_value_and_keeps_a_site_s_own() -> None:
    sites = [
        {"id": "a", "webUrl": "https://t-my.sharepoint.com/personal/a"},
        {"id": "b", "webUrl": "https://t-my.sharepoint.com/personal/b", "sharingCapability": "disabled"},
    ]
    result = OneDrivePostureCollector().run({"client": _Client({"sharingCapability": ANYONE}, sites), "audit_logger": None})

    by_id = {site["id"]: site for site in result.payload["oneDriveSites"]["value"]}
    assert (by_id["a"]["sharingCapability"], by_id["a"]["sharingCapabilitySource"]) == (ANYONE, "tenant")
    assert (by_id["b"]["sharingCapability"], by_id["b"]["sharingCapabilitySource"]) == ("disabled", "site")


def test_the_teams_collector_selects_the_allow_and_block_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[str] = []

    class _Adapter:
        def run(self, command: str, **_kwargs: Any) -> dict[str, Any]:
            commands.append(command)
            return {"value": []}

    monkeypatch.setattr("azure_tenant_audit.collectors.teams_policy.get_adapter", lambda _name: _Adapter())

    TeamsPolicyCollector().run({"audit_logger": None})

    (federation,) = [command for command in commands if command.startswith("Get-CsTenantFederationConfiguration")]
    selected = federation.split("Select-Object", 1)[1].strip().split(",")
    assert selected == ["AllowFederatedUsers", "AllowTeamsConsumer", "AllowPublicUsers", "AllowedDomains", "BlockedDomains"]


# ---- normalization -----------------------------------------------------------------------------------


def _snapshot(**payloads: Any) -> dict[str, Any]:
    return build_normalized_snapshot(tenant_name="acme", run_id="r", collector_payloads=payloads)


def test_teams_federation_is_normalized_with_allow_and_block_state() -> None:
    snapshot = _snapshot(
        teams_policy={
            "tenantFederationConfiguration": {
                "value": [
                    {
                        "Identity": "Global",
                        "AllowFederatedUsers": True,
                        "AllowTeamsConsumer": True,
                        "AllowPublicUsers": False,
                        "AllowedDomains": {"AllowedDomain": [{"Domain": "partner.example"}]},
                        "BlockedDomains": [],
                    }
                ]
            }
        }
    )

    (record,) = snapshot["teams_policy_objects"]["records"]
    assert record["allowed_domains_state"] == "allow_list" and record["allowed_domain_count"] == 1
    assert record["blocked_domain_count"] == 0 and record["allow_teams_consumer"] is True
    assert "partner.example" not in str(record), "domain names are kept as counts"


def test_the_onedrive_site_record_carries_where_its_value_came_from() -> None:
    snapshot = _snapshot(
        onedrive_posture={
            "oneDriveSites": {
                "value": [
                    {"id": "a", "siteKind": "personal", "sharingCapability": ANYONE, "sharingCapabilitySource": "tenant"},
                    {"id": "b", "siteKind": "personal", "sharingCapability": "disabled", "sharingCapabilitySource": "site"},
                ]
            }
        }
    )

    sources = {row["id"]: row["sharing_capability_source"] for row in snapshot["onedrive_posture_objects"]["records"]}
    assert sources == {"a": "tenant", "b": "site"}


def test_the_tenant_settings_section_records_each_read_and_whether_it_succeeded() -> None:
    snapshot = _snapshot(
        onedrive_posture={"sharePointSettings": {"sharingCapability": ANYONE, "sharingDomainRestrictionMode": "none"}},
        sharepoint_access={"sharePointSettings": {"error": "Forbidden", "error_class": "insufficient_permissions"}},
    )

    rows = {row["collector"]: row for row in snapshot[sharing.SECTION]["records"]}
    assert rows["onedrive_posture"]["read_state"] == "collected"
    assert rows["onedrive_posture"]["sharing_capability"] == ANYONE
    assert rows["sharepoint_access"]["read_state"] == "blocked" and "sharing_capability" not in rows["sharepoint_access"]
    merged = sharing.tenant_settings(snapshot)
    assert merged["read"] is True and merged["collectors"] == ["onedrive_posture"]


# ---- the OneDrive finding ----------------------------------------------------------------------------


def _onedrive_snapshot(settings: dict[str, Any] | None, sites: list[dict[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {"oneDriveSites": {"value": sites}}
    if settings is not None:
        payload["sharePointSettings"] = settings
    return _snapshot(onedrive_posture=payload)


def _personal(count: int, *, value: str | None = ANYONE, source: str = "tenant") -> list[dict[str, Any]]:
    return [
        {
            "id": f"site-{index}",
            "displayName": f"OneDrive {index}",
            "webUrl": f"https://t-my.sharepoint.com/personal/user{index}",
            "siteKind": "personal",
            **({"sharingCapability": value, "sharingCapabilitySource": source} if value else {}),
        }
        for index in range(count)
    ]


def _rules(findings: list[dict[str, Any]], rule_id: str) -> list[dict[str, Any]]:
    return [item for item in findings if item["rule_id"] == rule_id]


def test_many_sites_with_one_tenant_setting_are_one_graded_finding_with_the_sites_in_the_evidence() -> None:
    snapshot = _onedrive_snapshot({"sharingCapability": ANYONE}, _personal(40))

    findings = _rules(build_findings([], normalized_snapshot=snapshot), "onedrive.external_sharing_enabled")

    (finding,) = findings
    assert finding["id"] == "onedrive_posture:tenant:external_sharing_enabled"
    assert finding["severity"] == "high"
    evidence = finding["evidence"]
    assert evidence["personal_site_count"] == 40 and evidence["sites_with_anyone_links"] == 40
    assert evidence["site_values"] == "tenant_default" and evidence["capability_basis"] == "sharepoint_setting_inherited"
    assert len(evidence["sites"]) == 40 and not evidence["sites_listed_truncated"]
    assert evidence["sites"][0]["name"] == "OneDrive 0" and evidence["sites"][0]["value_source"] == "tenant"
    assert finding["returned_value"]["personal_sites"] == 40
    sections = {ref["artifact_path"] for ref in finding["evidence_refs"]}
    assert "normalized/sharepoint_tenant_settings.json" in sections and "normalized/onedrive_posture_objects.json" in sections


def test_a_large_site_list_is_capped_in_the_evidence_but_counted_in_full() -> None:
    snapshot = _onedrive_snapshot({"sharingCapability": ANYONE}, _personal(120))

    (finding,) = _rules(build_findings([], normalized_snapshot=snapshot), "onedrive.external_sharing_enabled")

    assert finding["evidence"]["sites_with_anyone_links"] == 120
    assert len(finding["evidence"]["sites"]) == sharing.SITE_EVIDENCE_LIMIT and finding["evidence"]["sites_listed_truncated"]


@pytest.mark.parametrize(
    ("capability", "severity"),
    [(ANYONE, "high"), ("externalUserSharingOnly", "low"), ("existingExternalUserSharingOnly", None), ("disabled", None)],
)
def test_the_tenant_capability_sets_the_onedrive_severity(capability: str, severity: str | None) -> None:
    snapshot = _onedrive_snapshot({"sharingCapability": capability}, _personal(3, value=capability))

    findings = _rules(build_findings([], normalized_snapshot=snapshot), "onedrive.external_sharing_enabled")

    assert [item["severity"] for item in findings] == ([severity] if severity else [])


def test_the_onedrive_setting_is_graded_even_when_the_site_inventory_is_empty() -> None:
    # Graph does not list personal sites, so the inventory is usually empty: the setting still stands.
    snapshot = _onedrive_snapshot({"sharingCapability": ANYONE}, [])

    (finding,) = _rules(build_findings([], normalized_snapshot=snapshot), "onedrive.external_sharing_enabled")

    assert finding["severity"] == "high" and finding["evidence"]["personal_site_count"] == 0
    assert finding["evidence"]["share_of_sites_with_anyone_links"] is None


def test_the_onedrive_own_setting_overrides_the_inherited_sharepoint_value() -> None:
    snapshot = _onedrive_snapshot(
        {"sharingCapability": ANYONE, "oneDriveSharingCapability": "existingExternalUserSharingOnly"}, _personal(2)
    )

    assert not _rules(build_findings([], normalized_snapshot=snapshot), "onedrive.external_sharing_enabled")
    softer = _onedrive_snapshot({"sharingCapability": ANYONE, "oneDriveSharingCapability": "externalUserSharingOnly"}, [])
    (finding,) = _rules(build_findings([], normalized_snapshot=softer), "onedrive.external_sharing_enabled")
    assert finding["severity"] == "low" and finding["evidence"]["capability_basis"] == "onedrive_setting"


def test_a_minority_of_sites_at_the_anyone_level_softens_the_grade_and_an_exceeding_site_is_listed() -> None:
    sites = [
        *_personal(1, value=ANYONE, source="site"),
        *[{**site, "id": f"strict-{index}"} for index, site in enumerate(_personal(4, value="disabled", source="site"))],
    ]
    snapshot = _onedrive_snapshot({"sharingCapability": ANYONE}, sites)

    (finding,) = _rules(build_findings([], normalized_snapshot=snapshot), "onedrive.external_sharing_enabled")

    assert finding["severity"] == "medium"
    assert finding["evidence"]["sites_with_anyone_links"] == 1 and finding["evidence"]["site_values"] == "site_specific"
    assert finding["evidence"]["sites_exceeding_tenant_setting"] == []


def test_a_site_more_permissive_than_the_tenant_is_listed_and_counts_at_its_own_level() -> None:
    sites = _personal(1, value=ANYONE, source="site")
    snapshot = _onedrive_snapshot({"sharingCapability": "existingExternalUserSharingOnly"}, sites)

    (finding,) = _rules(build_findings([], normalized_snapshot=snapshot), "onedrive.external_sharing_enabled")

    assert finding["severity"] == "high"
    (exceeding,) = finding["evidence"]["sites_exceeding_tenant_setting"]
    assert exceeding["effective_sharing_capability"] == ANYONE


def test_a_bundle_without_the_tenant_settings_section_grades_from_the_copied_site_value() -> None:
    legacy = {"onedrive_posture_objects": {"records": [{"id": "o1", "site_kind": "personal", "sharing_capability": "ExternalUserSharingOnly"}]}}

    (finding,) = _rules(build_findings([], normalized_snapshot=legacy), "onedrive.external_sharing_enabled")

    assert finding["severity"] == "low"


def test_a_payload_with_only_the_onedrive_capability_can_still_be_judged() -> None:
    snapshot = _onedrive_snapshot({"ODBSharingCapability": 2}, [])

    assert rule_inputs_gap("onedrive.external_sharing_enabled", snapshot) is None
    (finding,) = _rules(build_findings([], normalized_snapshot=snapshot), "onedrive.external_sharing_enabled")
    assert finding["evidence"]["capability_basis"] == "onedrive_setting"
    assert rule_inputs_gap("sharepoint.external_sharing_broad", snapshot) == "sharing_setting_not_read:sharing_capability"


def test_nothing_is_raised_when_the_settings_were_not_read() -> None:
    snapshot = _onedrive_snapshot({"error": "Forbidden", "error_class": "insufficient_permissions"}, _personal(2, value=None))

    assert not _rules(build_findings([], normalized_snapshot=snapshot), "onedrive.external_sharing_enabled")
    assert rule_inputs_gap("onedrive.external_sharing_enabled", snapshot) == "sharepoint_settings_not_collected"


# ---- the SharePoint settings rules -------------------------------------------------------------------


def _sharepoint_findings(settings: dict[str, Any]) -> dict[str, dict[str, Any]]:
    snapshot = _snapshot(sharepoint_access={"sharePointSettings": settings})
    return {
        item["rule_id"]: item
        for item in build_findings([], normalized_snapshot=snapshot)
        if item["rule_id"].startswith("sharepoint.") and item["id"].startswith("sharepoint_tenant:")
    }


def test_graph_settings_alone_raise_anyone_links_high_and_the_domain_rule() -> None:
    found = _sharepoint_findings({"sharingCapability": ANYONE, "sharingDomainRestrictionMode": "none"})

    assert set(found) == {"sharepoint.external_sharing_broad", "sharepoint.sharing_domains_unrestricted"}
    anyone = found["sharepoint.external_sharing_broad"]
    assert anyone["id"] == "sharepoint_tenant:external_sharing_broad" and anyone["title"] == "SharePoint and OneDrive allow anyone links"
    assert anyone["severity"] == "high"
    assert anyone["evidence"]["settings_not_read"] == [
        "anonymous_link_expiry_days", "file_anonymous_link_type", "folder_anonymous_link_type"
    ]
    assert found["sharepoint.sharing_domains_unrestricted"]["severity"] == "medium"
    assert anyone["collector"] == "sharepoint_access"
    assert anyone["framework_mappings"]["cis_m365_v7"] == ["7.2.3"]
    assert anyone["framework_mappings"]["cisa_scuba"] == ["MS.SHAREPOINT.1.1v1"]
    assert found["sharepoint.sharing_domains_unrestricted"]["framework_mappings"]["cis_m365_v7"] == ["7.2.6"]
    assert found["sharepoint.sharing_domains_unrestricted"]["framework_mappings"]["cisa_scuba"] == ["MS.SHAREPOINT.1.3v1"]
    assert {row["framework"]: row["breached"] for row in anyone["framework_thresholds"]} == {
        "cis_m365_v7": True,
        "cisa_scuba": True,
        "cyber_essentials": True,
    }


def test_expiring_view_only_anyone_links_are_medium_and_the_mitigations_are_named() -> None:
    found = _sharepoint_findings(
        {
            "SharingCapability": 2,
            "SharingDomainRestrictionMode": 1,
            "RequireAnonymousLinksExpireInDays": 14,
            "FileAnonymousLinkType": "View",
            "FolderAnonymousLinkType": "View",
            "DefaultSharingLinkType": "Direct",
        }
    )

    assert set(found) == {"sharepoint.external_sharing_broad"}
    anyone = found["sharepoint.external_sharing_broad"]
    assert anyone["severity"] == "medium"
    assert anyone["evidence"]["mitigations_observed"] == ["anonymous links expire within 14 days", "anonymous links are view-only"]
    assert anyone["evidence"]["settings_not_read"] == []


def test_new_and_existing_guests_are_a_low_finding_that_breaches_scuba_but_not_cis() -> None:
    found = _sharepoint_findings({"sharingCapability": "externalUserSharingOnly", "sharingDomainRestrictionMode": "allowList"})

    assert set(found) == {"sharepoint.external_sharing_broad"}
    finding = found["sharepoint.external_sharing_broad"]
    assert finding["severity"] == "low" and finding["title"] == "SharePoint and OneDrive allow sharing with new guests"
    # Authenticated guests are not anonymous access, so Cyber Essentials (users authenticated before access) is not breached.
    assert {row["framework"]: row["breached"] for row in finding["framework_thresholds"]} == {
        "cis_m365_v7": False,
        "cisa_scuba": True,
        "cyber_essentials": False,
    }
    assert finding["framework_thresholds"][1]["control_ids"] == ["MS.SHAREPOINT.1.1v1"]


def test_the_default_link_type_rule_grades_anyone_high_and_organisation_or_unset_low() -> None:
    def link(value: str) -> dict[str, Any]:
        return _sharepoint_findings({"sharingCapability": "disabled", "defaultSharingLinkType": value}).get("sharepoint.default_link_type_broad", {})

    assert link("anonymous")["severity"] == "high"
    assert link("internal")["severity"] == "low"
    assert link("none")["severity"] == "low"
    assert not link("direct")
    mapping = link("anonymous")["framework_mappings"]
    assert mapping["cis_m365_v7"] == ["7.2.7"] and mapping["cisa_scuba"] == ["MS.SHAREPOINT.2.1v1"]


def test_a_block_list_is_low_and_breaches_scuba_but_not_cis() -> None:
    found = _sharepoint_findings({"sharingCapability": "existingExternalUserSharingOnly", "sharingDomainRestrictionMode": "blockList"})

    assert set(found) == {"sharepoint.sharing_domains_unrestricted"}
    finding = found["sharepoint.sharing_domains_unrestricted"]
    assert finding["severity"] == "low"
    assert {row["framework"]: row["breached"] for row in finding["framework_thresholds"]} == {"cis_m365_v7": False, "cisa_scuba": True}


def test_sharing_off_or_existing_guests_with_an_allow_list_raise_nothing() -> None:
    assert not _sharepoint_findings({"sharingCapability": "disabled", "sharingDomainRestrictionMode": "none"})
    assert not _sharepoint_findings({"sharingCapability": "existingExternalUserSharingOnly", "sharingDomainRestrictionMode": "allowList"})


_SPO_CONTROLS = {
    "cis_m365_v7": ("7.2.3", "7.2.6", "7.2.7"),
    "cisa_scuba": ("MS.SHAREPOINT.1.1v1", "MS.SHAREPOINT.1.3v1", "MS.SHAREPOINT.2.1v1"),
}


def _control_statuses(settings: dict[str, Any]) -> dict[str, str]:
    """Baseline status of each SharePoint sharing control, from the shipped mappings, for these settings."""
    snapshot = _snapshot(sharepoint_access={"sharePointSettings": settings})
    findings = build_findings([], normalized_snapshot=snapshot)
    alignment = build_baseline_alignment(
        findings,
        normalized_snapshot=snapshot,
        coverage_ledger=[{"collector": "sharepoint_access", "coverage_status": "complete_exact_scope"}],
    )
    statuses: dict[str, str] = {}
    for framework, controls in _SPO_CONTROLS.items():
        rows = {row["control_id"]: row["status"] for row in alignment["frameworks"][framework]["controls"]}
        statuses.update({control: rows[control] for control in controls})
    return statuses


_PASS = "pass"
_FAIL = "fail"


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        # ScubaGear MS.SHAREPOINT.1.1v1 passes only Disabled or ExistingExternalUserSharingOnly; CIS 7.2.3 also allows new guests.
        ({"SharingCapability": 0, "SharingDomainRestrictionMode": 0, "DefaultSharingLinkType": 1},
         {"7.2.3": _PASS, "7.2.6": _PASS, "7.2.7": _PASS, "MS.SHAREPOINT.1.1v1": _PASS, "MS.SHAREPOINT.1.3v1": _PASS, "MS.SHAREPOINT.2.1v1": _PASS}),
        ({"SharingCapability": 3, "SharingDomainRestrictionMode": 1, "DefaultSharingLinkType": 1},
         {"7.2.3": _PASS, "7.2.6": _PASS, "7.2.7": _PASS, "MS.SHAREPOINT.1.1v1": _PASS, "MS.SHAREPOINT.1.3v1": _PASS, "MS.SHAREPOINT.2.1v1": _PASS}),
        ({"SharingCapability": 1, "SharingDomainRestrictionMode": 1, "DefaultSharingLinkType": 1},
         {"7.2.3": _PASS, "7.2.6": _PASS, "7.2.7": _PASS, "MS.SHAREPOINT.1.1v1": _FAIL, "MS.SHAREPOINT.1.3v1": _PASS, "MS.SHAREPOINT.2.1v1": _PASS}),
        ({"SharingCapability": 2, "SharingDomainRestrictionMode": 1, "DefaultSharingLinkType": 1},
         {"7.2.3": _FAIL, "7.2.6": _PASS, "7.2.7": _PASS, "MS.SHAREPOINT.1.1v1": _FAIL, "MS.SHAREPOINT.1.3v1": _PASS, "MS.SHAREPOINT.2.1v1": _PASS}),
        # A block list passes CIS 7.2.6 but not MS.SHAREPOINT.1.3v1, which wants SharingDomainRestrictionMode 1 (allow list).
        ({"SharingCapability": 3, "SharingDomainRestrictionMode": 2, "DefaultSharingLinkType": 1},
         {"7.2.3": _PASS, "7.2.6": _PASS, "7.2.7": _PASS, "MS.SHAREPOINT.1.1v1": _PASS, "MS.SHAREPOINT.1.3v1": _FAIL, "MS.SHAREPOINT.2.1v1": _PASS}),
        ({"SharingCapability": 3, "SharingDomainRestrictionMode": 0, "DefaultSharingLinkType": 1},
         {"7.2.3": _PASS, "7.2.6": _FAIL, "7.2.7": _PASS, "MS.SHAREPOINT.1.1v1": _PASS, "MS.SHAREPOINT.1.3v1": _FAIL, "MS.SHAREPOINT.2.1v1": _PASS}),
        # DefaultSharingLinkType must be 1 (Direct): None (0), organisation (2) and anyone (3) all fail both controls.
        *[
            (
                {"SharingCapability": 0, "SharingDomainRestrictionMode": 0, "DefaultSharingLinkType": link},
                {"7.2.3": _PASS, "7.2.6": _PASS, "7.2.7": _FAIL, "MS.SHAREPOINT.1.1v1": _PASS, "MS.SHAREPOINT.1.3v1": _PASS, "MS.SHAREPOINT.2.1v1": _FAIL},
            )
            for link in (0, 2, 3)
        ],
    ],
)
def test_the_sharing_controls_fail_when_the_benchmark_would_fail(settings: dict[str, Any], expected: dict[str, str]) -> None:
    assert _control_statuses(settings) == expected


@pytest.mark.parametrize(
    ("rule", "settings", "reason"),
    [
        ("sharepoint.external_sharing_broad", {"sharingDomainRestrictionMode": "none"}, "sharing_setting_not_read:sharing_capability"),
        ("sharepoint.sharing_domains_unrestricted", {"sharingCapability": ANYONE}, "sharing_setting_not_read:sharing_domain_restriction_mode"),
        ("sharepoint.default_link_type_broad", {"sharingCapability": ANYONE}, "sharing_setting_not_read:default_sharing_link_type"),
        ("sharepoint.default_link_type_broad", {"sharingCapability": ANYONE, "defaultSharingLinkType": "direct"}, None),
    ],
)
def test_a_rule_whose_setting_was_not_read_is_not_assessed(rule: str, settings: dict[str, Any], reason: str | None) -> None:
    snapshot = _snapshot(sharepoint_access={"sharePointSettings": settings})

    assert rule_inputs_gap(rule, snapshot) == reason


def test_baseline_alignment_reads_an_unread_default_link_type_as_not_assessed_not_pass() -> None:
    snapshot = _snapshot(sharepoint_access={"sharePointSettings": {"sharingCapability": "disabled", "sharingDomainRestrictionMode": "none"}})
    ledger = [{"collector": "sharepoint_access", "coverage_status": "complete_exact_scope"}]

    alignment = build_baseline_alignment(
        [],
        normalized_snapshot=snapshot,
        coverage_ledger=ledger,
        mappings={
            "sharepoint.default_link_type_broad": {"cis_m365_v7": ["7.2.7"]},
            "sharepoint.external_sharing_broad": {"cis_m365_v7": ["7.2.3"]},
        },
    )

    controls = {control["control_id"]: control for control in alignment["frameworks"]["cis_m365_v7"]["controls"]}
    assert controls["7.2.3"]["status"] == "pass"
    assert controls["7.2.7"]["status"] == "not_assessed"
    assert controls["7.2.7"]["rule_statuses"][0]["reason"] == "sharing_setting_not_read:default_sharing_link_type"


# ---- the Teams rule ----------------------------------------------------------------------------------


def _teams(**configuration: Any) -> list[dict[str, Any]]:
    snapshot = _snapshot(
        teams_policy={"tenantFederationConfiguration": {"value": [{"Identity": "Global", **configuration}]}}
    )
    return _rules(build_findings([], normalized_snapshot=snapshot), "teams.external_federation_open")


def test_federation_with_no_allow_list_is_open() -> None:
    (finding,) = _teams(AllowFederatedUsers=True, AllowedDomains="AllowAllKnownDomains", BlockedDomains=[], AllowTeamsConsumer=True)

    assert finding["severity"] == "medium" and finding["id"] == "teams_policy:Global:external_federation_open"
    assert finding["returned_value"]["allowed_domains"] == "all known domains (no allow list)"
    assert finding["returned_value"]["allow_teams_consumer"] is True and finding["returned_value"]["blocked_domain_count"] == 0


def test_a_block_list_does_not_make_federation_selective() -> None:
    (finding,) = _teams(AllowFederatedUsers=True, AllowedDomains={}, BlockedDomains=[{"Domain": "bad.example"}])

    assert finding["returned_value"]["blocked_domain_count"] == 1


def test_an_allow_list_with_no_domains_allows_federation_with_none_and_is_not_open() -> None:
    assert not _teams(AllowFederatedUsers=True, AllowedDomains={"AllowedDomain": []})
    assert not _teams(AllowFederatedUsers=True, AllowedDomains="")


def test_a_non_boolean_federation_setting_is_not_a_reading_and_is_not_assessed() -> None:
    for value in ("True", "false", 1, 0):
        snapshot = _snapshot(
            teams_policy={"tenantFederationConfiguration": {"value": [{"Identity": "Global", "AllowFederatedUsers": value, "AllowedDomains": "AllowAllKnownDomains"}]}}
        )
        assert not _rules(build_findings([], normalized_snapshot=snapshot), "teams.external_federation_open")
        assert rule_inputs_gap("teams.external_federation_open", snapshot) == "federation_setting_not_read", value


def test_federation_to_an_allow_list_is_not_reported() -> None:
    assert not _teams(AllowFederatedUsers=True, AllowedDomains={"AllowedDomain": [{"Domain": "partner.example"}]}, AllowTeamsConsumer=True)


def test_federation_that_is_off_is_not_reported_whatever_the_consumer_flags_say() -> None:
    assert not _teams(AllowFederatedUsers=False, AllowedDomains="AllowAllKnownDomains", AllowTeamsConsumer=True, AllowPublicUsers=True)


def test_federation_whose_allow_list_was_not_collected_is_not_guessed_and_is_not_assessed() -> None:
    snapshot = _snapshot(teams_policy={"tenantFederationConfiguration": {"value": [{"Identity": "Global", "AllowFederatedUsers": True}]}})

    assert not _rules(build_findings([], normalized_snapshot=snapshot), "teams.external_federation_open")
    assert rule_inputs_gap("teams.external_federation_open", snapshot) == "federation_allow_list_not_read"
    off = _snapshot(teams_policy={"tenantFederationConfiguration": {"value": [{"Identity": "Global", "AllowFederatedUsers": False}]}})
    assert rule_inputs_gap("teams.external_federation_open", off) is None
    silent = _snapshot(teams_policy={"tenantFederationConfiguration": {"value": [{"Identity": "Global"}]}})
    assert rule_inputs_gap("teams.external_federation_open", silent) == "federation_setting_not_read"
    assert rule_inputs_gap("teams.external_federation_open", _snapshot()) == "federation_configuration_not_collected"
