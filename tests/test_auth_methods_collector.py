from __future__ import annotations

from azure_tenant_audit.collectors.auth_methods import AuthMethodsCollector


class _AuthMethodsClient:
    def __init__(self) -> None:
        self.registration_params: dict[str, str] = {}

    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        if path == "/policies/authenticationMethodsPolicy":
            return {"id": "policy-1", "state": "enabled"}
        raise AssertionError(f"unexpected path: {path}")

    def get_all(self, path, params=None):  # noqa: ANN001
        if path == "/reports/authenticationMethods/userRegistrationDetails":
            assert params["$top"] == "200"
            self.registration_params = dict(params)
            return [{"id": "user-1", "userPrincipalName": "user1@contoso.com"}]
        raise AssertionError(f"unexpected path: {path}")


def test_auth_methods_collector_collects_policy_and_registration_details() -> None:
    collector = AuthMethodsCollector()
    client = _AuthMethodsClient()
    result = collector.run({"client": client, "top": 200, "audit_logger": None})

    assert result.status == "ok"
    assert result.payload["authenticationMethodsPolicy"]["id"] == "policy-1"
    assert result.payload["userRegistrationDetails"]["value"][0]["id"] == "user-1"
    # isAdmin and userType identify privileged and guest accounts; the select stays metadata-only.
    selected = client.registration_params["$select"].split(",")
    assert {"isAdmin", "userType", "isMfaRegistered"} <= set(selected)
    assert not {"methodsRegistered", "defaultMfaMethod", "userPreferredMethodForSecondaryAuthentication"} & set(selected)
