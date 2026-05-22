from __future__ import annotations

from azure_tenant_audit.collectors.app_consent import AppConsentCollector
from azure_tenant_audit.collectors.consent_policy import ConsentPolicyCollector
from azure_tenant_audit.collectors.domains_hybrid import DomainsHybridCollector
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
from azure_tenant_audit.collectors.external_identity import ExternalIdentityCollector
from azure_tenant_audit.collectors.identity_governance import IdentityGovernanceCollector
from azure_tenant_audit.collectors.intune_depth import IntuneDepthCollector
from azure_tenant_audit.collectors.licensing import LicensingCollector
from azure_tenant_audit.collectors.onedrive_posture import OneDrivePostureCollector
from azure_tenant_audit.collectors.reports_usage import ReportsUsageCollector
from azure_tenant_audit.collectors.sharepoint_access import SharePointAccessCollector
from azure_tenant_audit.collectors.service_health import ServiceHealthCollector
from azure_tenant_audit.collectors.teams_policy import TeamsPolicyCollector
from azure_tenant_audit.graph import GraphError


class _SharePointAccessClient:
    def __init__(self) -> None:
        self.batch_calls: list[list[str]] = []

    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        if path == "/admin/sharepoint/settings":
            return {
                "isLoopEnabled": True,
                "sharingCapability": "externalUserAndGuestSharing",
            }
        raise AssertionError(f"unexpected path: {path}")

    def get_all(self, path, params=None):  # noqa: ANN001, ARG002
        if path == "/sites":
            return [
                {
                    "id": "site-1",
                    "name": "Executive",
                    "webUrl": "https://contoso-my.sharepoint.com/personal/alice_contoso_com",
                },
                {"id": "site-2", "name": "Projects", "webUrl": "https://contoso.sharepoint.com/sites/projects"},
            ]
        raise AssertionError(f"unexpected path: {path}")

    def get_batch(self, requests):  # noqa: ANN001
        paths = [request["path"] for request in requests]
        self.batch_calls.append(paths)
        responses = []
        for request in requests:
            if request["path"] == "/sites/site-1/permissions":
                responses.append(
                    {
                        "request": request,
                        "status": 200,
                        "body": {
                            "value": [
                                {
                                    "id": "perm-1",
                                    "roles": ["read"],
                                    "grantedToIdentitiesV2": [
                                        {"user": {"id": "user-1", "displayName": "Alice Example"}}
                                    ],
                                    "link": {"scope": "anonymous", "type": "view"},
                                }
                            ]
                        },
                    }
                )
                continue
            if request["path"] == "/sites/site-2/permissions":
                responses.append(
                    {
                        "request": request,
                        "status": 403,
                        "body": {
                            "error": {
                                "code": "Authorization_RequestDenied",
                                "message": "Forbidden",
                            }
                        },
                        "error_code": "Authorization_RequestDenied",
                        "error": "Forbidden",
                    }
                )
                continue
            raise AssertionError(f"unexpected batch path: {request['path']}")
        return responses


class _AppConsentClient:
    def __init__(self) -> None:
        self.batch_calls: list[list[str]] = []

    def get_all(self, path, params=None):  # noqa: ANN001, ARG002
        if path == "/servicePrincipals":
            return [
                {
                    "id": "sp-1",
                    "displayName": "Contoso App",
                    "appId": "app-1",
                    "servicePrincipalType": "Application",
                    "verifiedPublisher": {"displayName": "Contoso"},
                }
            ]
        if path == "/oauth2PermissionGrants":
            return [
                {
                    "id": "grant-1",
                    "clientId": "sp-1",
                    "resourceId": "resource-1",
                    "scope": "Directory.Read.All Mail.Read",
                    "consentType": "AllPrincipals",
                }
            ]
        raise AssertionError(f"unexpected path: {path}")

    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        values = self.get_all(path, params=params)
        return {"value": values}

    def get_batch(self, requests):  # noqa: ANN001
        paths = [request["path"] for request in requests]
        self.batch_calls.append(paths)
        responses = []
        for request in requests:
            if request["path"] == "/servicePrincipals/sp-1/owners":
                responses.append(
                    {
                        "request": request,
                        "status": 200,
                        "body": {
                            "value": [
                                {
                                    "id": "owner-1",
                                    "displayName": "Owner User",
                                    "userPrincipalName": "owner@example.com",
                                }
                            ]
                        },
                    }
                )
                continue
            if request["path"] == "/servicePrincipals/sp-1/appRoleAssignedTo":
                responses.append(
                    {
                        "request": request,
                        "status": 200,
                        "body": {
                            "value": [
                                {
                                    "id": "assignment-1",
                                    "principalDisplayName": "All Users",
                                    "principalType": "Group",
                                }
                            ]
                        },
                    }
                )
                continue
            raise AssertionError(f"unexpected batch path: {request['path']}")
        return responses


class _LicensingClient:
    def get_all(self, path, params=None):  # noqa: ANN001, ARG002
        if path == "/subscribedSkus":
            return [
                {
                    "skuId": "sku-1",
                    "skuPartNumber": "ENTERPRISEPREMIUM",
                    "consumedUnits": 12,
                    "prepaidUnits": {"enabled": 25},
                    "servicePlans": [{"servicePlanName": "EXCHANGE_S_ENTERPRISE"}],
                }
            ]
        if path == "/users":
            return [
                {
                    "id": "user-1",
                    "displayName": "Alice Example",
                    "userPrincipalName": "alice@example.com",
                    "assignedLicenses": [{"skuId": "sku-1"}],
                    "licenseAssignmentStates": [{"assignedByGroup": None, "skuId": "sku-1", "state": "Active"}],
                }
            ]
        if path == "/groups":
            return [{"id": "group-1", "displayName": "Licensed Group", "assignedLicenses": [{"skuId": "sku-1"}]}]
        raise AssertionError(f"unexpected path: {path}")

    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        values = self.get_all(path, params=params)
        return {"value": values}


class _IdentityGovernanceClient:
    def get_all(self, path, params=None):  # noqa: ANN001, ARG002
        responses = {
            "/identityGovernance/accessReviews/definitions": [{"id": "review-1", "displayName": "Admins review"}],
            "/identityGovernance/entitlementManagement/catalogs": [{"id": "catalog-1", "displayName": "Main catalog"}],
            "/identityGovernance/entitlementManagement/accessPackages": [{"id": "package-1", "displayName": "App access"}],
            "/roleManagement/directory/roleAssignmentSchedules": [{"id": "assignment-schedule-1"}],
            "/roleManagement/directory/roleEligibilitySchedules": [{"id": "eligibility-schedule-1"}],
            "/directory/administrativeUnits": [{"id": "au-1", "displayName": "EMEA"}],
        }
        if path not in responses:
            raise AssertionError(f"unexpected path: {path}")
        return responses[path]

    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        values = self.get_all(path, params=params)
        return {"value": values}


class _IntuneDepthClient:
    def __init__(self) -> None:
        self.batch_calls: list[list[str]] = []

    def get_all(self, path, params=None):  # noqa: ANN001, ARG002
        responses = {
            "/deviceManagement/deviceConfigurations": [{"id": "config-1", "displayName": "Windows baseline"}],
            "/deviceManagement/groupPolicyConfigurations": [{"id": "gp-1", "displayName": "Edge hardening"}],
            "/deviceManagement/deviceManagementScripts": [{"id": "script-1", "displayName": "Repair script"}],
            "/deviceAppManagement/androidManagedAppProtections": [{"id": "mam-android-1", "displayName": "Android MAM"}],
            "/deviceAppManagement/iosManagedAppProtections": [{"id": "mam-ios-1", "displayName": "iOS MAM"}],
        }
        if path not in responses:
            raise AssertionError(f"unexpected path: {path}")
        return responses[path]

    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        values = self.get_all(path, params=params)
        return {"value": values}

    def get_batch(self, requests):  # noqa: ANN001
        paths = [request["path"] for request in requests]
        self.batch_calls.append(paths)
        responses = []
        for request in requests:
            if request["path"] == "/deviceManagement/deviceConfigurations/config-1/assignments":
                responses.append(
                    {
                        "request": request,
                        "status": 200,
                        "body": {
                            "value": [
                                {"id": "assign-1", "target": {"groupId": "group-1"}}
                            ]
                        },
                    }
                )
                continue
            raise AssertionError(f"unexpected batch path: {request['path']}")
        return responses


class _ServiceHealthClient:
    def get_all(self, path, params=None):  # noqa: ANN001, ARG002
        responses = {
            "/admin/serviceAnnouncement/healthOverviews": [{"id": "exchange", "service": "Exchange Online", "status": "serviceOperational"}],
            "/admin/serviceAnnouncement/issues": [{"id": "issue-1", "service": "Microsoft Teams", "status": "serviceDegradation"}],
            "/admin/serviceAnnouncement/messages": [{"id": "msg-1", "title": "Planned maintenance"}],
        }
        if path not in responses:
            raise AssertionError(f"unexpected path: {path}")
        return responses[path]

    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        return {"value": self.get_all(path, params=params)}


class _ReportsUsageClient:
    def get_content(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        responses = {
            "/reports/getOffice365ActiveUserCounts(period='D30')": "Report Refresh Date,Exchange,SharePoint\n2026-04-18,10,8\n",
            "/reports/getSharePointSiteUsageDetail(period='D30')": "Report Refresh Date,Site Id,Owner Principal Name,Is Deleted\n2026-04-18,site-1,owner@contoso.test,False\n",
            "/reports/getOneDriveUsageAccountDetail(period='D30')": "Report Refresh Date,Owner Principal Name,Site URL,Is Deleted\n2026-04-18,user@contoso.test,https://contoso-my.sharepoint.com/personal/user,False\n",
            "/reports/getMailboxUsageDetail(period='D30')": "Report Refresh Date,User Principal Name,Storage Used (Byte)\n2026-04-18,user@contoso.test,1024\n",
        }
        if path not in responses:
            raise AssertionError(f"unexpected path: {path}")
        return responses[path]


class _ExternalIdentityClient:
    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        responses = {
            "/policies/crossTenantAccessPolicy": {"id": "xtap", "displayName": "Cross-tenant"},
            "/policies/authorizationPolicy": {"id": "authz", "allowInvitesFrom": "everyone"},
            "/policies/authenticationFlowsPolicy": {"id": "flows", "displayName": "Flows"},
        }
        if path not in responses:
            raise AssertionError(f"unexpected path: {path}")
        return responses[path]


class _ConsentPolicyClient:
    def get_all(self, path, params=None):  # noqa: ANN001, ARG002
        responses = {
            "/policies/permissionGrantPolicies": [{"id": "grant-policy-1", "displayName": "Default user consent"}],
        }
        if path not in responses:
            raise AssertionError(f"unexpected path: {path}")
        return responses[path]

    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        responses = {
            "/policies/adminConsentRequestPolicy": {"id": "admin-consent", "isEnabled": False},
            "/policies/authorizationPolicy": {"id": "authz", "defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": ["grant-policy-1"]}},
        }
        if path in responses:
            return responses[path]
        return {"value": self.get_all(path, params=params)}


class _DomainsHybridClient:
    def get_all(self, path, params=None):  # noqa: ANN001, ARG002
        responses = {
            "/domains": [{"id": "contoso.com", "isDefault": True, "isVerified": True, "authenticationType": "Managed"}],
            "/users": [
                {
                    "id": "user-1",
                    "userPrincipalName": "user@contoso.com",
                    "onPremisesSyncEnabled": True,
                    "onPremisesImmutableId": "imm-1",
                    "onPremisesDomainName": "contoso.local",
                }
            ],
        }
        if path not in responses:
            raise AssertionError(f"unexpected path: {path}")
        return responses[path]

    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        if path == "/organization":
            return {"value": [{"id": "org-1", "displayName": "Contoso"}]}
        return {"value": self.get_all(path, params=params)}


class _OneDrivePostureClient:
    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        if path == "/admin/sharepoint/settings":
            return {"sharingCapability": "externalUserAndGuestSharing"}
        raise AssertionError(f"unexpected path: {path}")

    def get_all(self, path, params=None):  # noqa: ANN001, ARG002
        if path == "/sites":
            return [
                {
                    "id": "od-1",
                    "displayName": "Alice OneDrive",
                    "webUrl": "https://contoso-my.sharepoint.com/personal/alice_contoso_com",
                    "createdDateTime": "2026-04-18T00:00:00Z",
                },
                {
                    "id": "team-1",
                    "displayName": "Team Site",
                    "webUrl": "https://contoso.sharepoint.com/sites/team",
                    "createdDateTime": "2026-04-18T00:00:00Z",
                },
            ]
        raise AssertionError(f"unexpected path: {path}")


class _FakeAdapter:
    def __init__(self, responses):
        self.name = "powershell_graph"
        self._responses = responses

    def dependency_check(self) -> bool:
        return True

    def run(self, command, log_event=None):  # noqa: ANN001, ARG002
        response = self._responses.get(command)
        if response is None:
            return {"error": "missing response", "error_class": "command_not_simulated", "command": command}
        payload = dict(response)
        payload.setdefault("command", command)
        return payload


def test_sharepoint_access_collector_collects_site_permissions_and_marks_partial_when_one_site_is_blocked() -> None:
    collector = SharePointAccessCollector()
    client = _SharePointAccessClient()
    result = collector.run({"client": client, "top": 100, "audit_logger": None})

    assert result.status == "partial"
    assert result.payload["sharePointSettings"]["sharingCapability"] == "externalUserAndGuestSharing"
    permissions = result.payload["sitePermissionsBySite"]["value"]
    assert permissions[0]["siteId"] == "site-1"
    assert permissions[0]["siteKind"] == "personal"
    assert permissions[0]["sharingCapability"] == "externalUserAndGuestSharing"
    assert permissions[0]["principalCount"] == 1
    assert permissions[0]["anonymousLinkCount"] == 1
    assert permissions[0]["ownershipState"] == "weak"
    assert permissions[0]["permissions"][0]["id"] == "perm-1"
    failed_rows = [row for row in (result.coverage or []) if row["status"] != "ok"]
    assert failed_rows[0]["error_class"] == "insufficient_permissions"
    assert client.batch_calls == [["/sites/site-1/permissions", "/sites/site-2/permissions"]]


def test_app_consent_collector_collects_grants_owners_and_app_role_assignments() -> None:
    collector = AppConsentCollector()
    client = _AppConsentClient()
    result = collector.run({"client": client, "top": 100, "audit_logger": None})

    assert result.status == "ok"
    assert result.payload["servicePrincipals"]["value"][0]["id"] == "sp-1"
    assert result.payload["oauth2PermissionGrants"]["value"][0]["id"] == "grant-1"
    assert result.payload["servicePrincipalOwners"]["value"][0]["owners"][0]["id"] == "owner-1"
    assert result.payload["servicePrincipalAppRoleAssignments"]["value"][0]["assignments"][0]["id"] == "assignment-1"
    assert client.batch_calls == [["/servicePrincipals/sp-1/owners", "/servicePrincipals/sp-1/appRoleAssignedTo"]]


def test_licensing_collector_collects_subscribed_skus_and_license_assignments() -> None:
    collector = LicensingCollector()
    result = collector.run({"client": _LicensingClient(), "top": 100, "audit_logger": None})

    assert result.status == "ok"
    assert result.payload["subscribedSkus"]["value"][0]["skuPartNumber"] == "ENTERPRISEPREMIUM"
    assert result.payload["licensedUsers"]["value"][0]["assignedLicenses"][0]["skuId"] == "sku-1"
    assert result.payload["licensedGroups"]["value"][0]["displayName"] == "Licensed Group"


def test_identity_governance_collector_collects_reviews_packages_and_role_schedules() -> None:
    collector = IdentityGovernanceCollector()
    result = collector.run({"client": _IdentityGovernanceClient(), "top": 100, "audit_logger": None})

    assert result.status == "ok"
    assert result.payload["accessReviews"]["value"][0]["id"] == "review-1"
    assert result.payload["entitlementCatalogs"]["value"][0]["id"] == "catalog-1"
    assert result.payload["roleEligibilitySchedules"]["value"][0]["id"] == "eligibility-schedule-1"
    assert result.payload["administrativeUnits"]["value"][0]["id"] == "au-1"


def test_intune_depth_collector_collects_configurations_scripts_and_assignments() -> None:
    collector = IntuneDepthCollector()
    client = _IntuneDepthClient()
    result = collector.run({"client": client, "top": 100, "audit_logger": None})

    assert result.status == "ok"
    assert result.payload["deviceConfigurations"]["value"][0]["id"] == "config-1"
    assert result.payload["deviceManagementScripts"]["value"][0]["id"] == "script-1"
    assert result.payload["deviceConfigurationAssignments"]["value"][0]["assignments"][0]["id"] == "assign-1"
    assert client.batch_calls == [["/deviceManagement/deviceConfigurations/config-1/assignments"]]


def test_service_health_collector_collects_health_issues_and_messages() -> None:
    collector = ServiceHealthCollector()
    result = collector.run({"client": _ServiceHealthClient(), "top": 100, "audit_logger": None})

    assert result.status == "ok"
    assert result.payload["healthOverviews"]["value"][0]["service"] == "Exchange Online"
    assert result.payload["serviceIssues"]["value"][0]["id"] == "issue-1"
    assert result.payload["messages"]["value"][0]["id"] == "msg-1"


def test_reports_usage_collector_collects_csv_report_samples() -> None:
    collector = ReportsUsageCollector()
    result = collector.run({"client": _ReportsUsageClient(), "top": 100, "audit_logger": None})

    assert result.status == "ok"
    assert result.payload["office365ActiveUserCounts"]["value"][0]["Exchange"] == "10"
    assert result.payload["oneDriveUsageAccountDetail"]["value"][0]["Owner Principal Name"] == "user@contoso.test"


def test_external_identity_collector_collects_cross_tenant_and_policy_posture() -> None:
    collector = ExternalIdentityCollector()
    result = collector.run({"client": _ExternalIdentityClient(), "top": 100, "audit_logger": None})

    assert result.status == "ok"
    assert result.payload["crossTenantAccessPolicy"]["id"] == "xtap"
    assert result.payload["authorizationPolicy"]["allowInvitesFrom"] == "everyone"


def test_consent_policy_collector_collects_admin_consent_and_grant_policies() -> None:
    collector = ConsentPolicyCollector()
    result = collector.run({"client": _ConsentPolicyClient(), "top": 100, "audit_logger": None})

    assert result.status == "ok"
    assert result.payload["adminConsentRequestPolicy"]["isEnabled"] is False
    assert result.payload["permissionGrantPolicies"]["value"][0]["id"] == "grant-policy-1"


def test_domains_hybrid_collector_collects_domains_and_sync_signals() -> None:
    collector = DomainsHybridCollector()
    result = collector.run({"client": _DomainsHybridClient(), "top": 100, "audit_logger": None})

    assert result.status == "ok"
    assert result.payload["domains"]["value"][0]["id"] == "contoso.com"
    assert result.payload["syncSampleUsers"]["value"][0]["onPremisesSyncEnabled"] is True


def test_onedrive_posture_collector_distinguishes_personal_and_team_sites() -> None:
    collector = OneDrivePostureCollector()
    result = collector.run({"client": _OneDrivePostureClient(), "top": 100, "audit_logger": None})

    assert result.status == "ok"
    assert result.payload["oneDriveSites"]["value"][0]["id"] == "od-1"
    assert result.payload["oneDriveSites"]["value"][0]["siteKind"] == "personal"
    assert result.payload["oneDriveSites"]["value"][0]["sharingCapability"] == "externalUserAndGuestSharing"
    assert result.payload["teamSites"]["value"][0]["id"] == "team-1"
    assert result.payload["teamSites"]["value"][0]["siteKind"] == "team"
    assert result.payload["teamSites"]["value"][0]["sharingCapability"] == "externalUserAndGuestSharing"


def test_exchange_policy_collector_collects_command_sections(monkeypatch) -> None:
    transport_command = (
        "Get-TransportRule | Select-Object "
        "Name,State,Priority,Mode,RedirectMessageTo,BlindCopyTo,CopyTo,ApplyHtmlDisclaimerText"
    )
    adapter = _FakeAdapter(
        {
            transport_command: {"value": [{"Name": "Block Forwarding", "RedirectMessageTo": ["external@example.net"]}]},
            "Get-InboundConnector | Select-Object Name,Enabled,ConnectorType": {"value": [{"Name": "Inbound 1"}]},
            "Get-OutboundConnector | Select-Object Name,Enabled,ConnectorType": {"value": [{"Name": "Outbound 1"}]},
            "Get-AcceptedDomain | Select-Object Name,DomainName,DomainType,Default": {"value": [{"Name": "contoso.com"}]},
            "Get-RemoteDomain | Select-Object Name,DomainName,TrustedMailOutboundEnabled,AutoReplyEnabled,AutoForwardEnabled": {
                "value": [{"Name": "Default"}]
            },
            "Get-EXOMailbox -ResultSize 50 | Select-Object DisplayName,PrimarySmtpAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward": {"value": [{"DisplayName": "Alice Example"}]},
        }
    )
    monkeypatch.setattr("azure_tenant_audit.collectors.exchange_policy.get_adapter", lambda _name: adapter)

    collector = ExchangePolicyCollector()
    result = collector.run({"audit_logger": None})

    assert result.status == "ok"
    assert result.payload["transportRules"]["value"][0]["Name"] == "Block Forwarding"
    assert result.payload["mailboxForwarding"]["value"][0]["DisplayName"] == "Alice Example"


def test_teams_policy_collector_collects_command_sections(monkeypatch) -> None:
    adapter = _FakeAdapter(
        {
            "Get-CsTenantFederationConfiguration | Select-Object AllowFederatedUsers,AllowTeamsConsumer,AllowPublicUsers": {"value": [{"AllowFederatedUsers": True}]},
            "Get-CsTeamsMessagingPolicy | Select-Object Identity,AllowOwnerDeleteMessage,AllowUserDeleteMessage,AllowUserEditMessage": {"value": [{"Identity": "Global"}]},
            "Get-CsTeamsMeetingPolicy | Select-Object Identity,AllowCloudRecording,AllowIPVideo,ScreenSharingMode": {"value": [{"Identity": "Global"}]},
            "Get-CsTeamsAppPermissionPolicy | Select-Object Identity,GlobalCatalogAppsType": {"value": [{"Identity": "Global"}]},
            "Get-CsTeamsAppSetupPolicy | Select-Object Identity,AllowSideLoading": {"value": [{"Identity": "Global"}]},
        }
    )
    monkeypatch.setattr("azure_tenant_audit.collectors.teams_policy.get_adapter", lambda _name: adapter)

    collector = TeamsPolicyCollector()
    result = collector.run({"audit_logger": None})

    assert result.status == "ok"
    assert result.payload["tenantFederationConfiguration"]["value"][0]["AllowFederatedUsers"] is True
    assert result.payload["meetingPolicies"]["value"][0]["Identity"] == "Global"
