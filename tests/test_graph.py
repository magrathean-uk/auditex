from __future__ import annotations

from support import fake_graph_client, graph_response

from azure_tenant_audit.collectors.base import _classify_graph_error
from azure_tenant_audit.graph import GraphError


def test_graph_error_includes_http_status_and_code(monkeypatch) -> None:
    client = fake_graph_client()

    def _request(method, url, **kwargs):  # noqa: ARG001
        return graph_response(
            403,
            {
                "error": {
                    "code": "Authorization_RequestDenied",
                    "message": "Access denied due to insufficient privileges",
                }
            },
        )

    monkeypatch.setattr(client, "_request", _request)

    exc = None
    try:
        client.get_json("/me")
    except Exception as caught:  # noqa: BLE001
        exc = caught

    assert isinstance(exc, GraphError)
    assert exc.status == 403
    assert exc.error_code == "Authorization_RequestDenied"
    assert "Access denied" in str(exc)


def test_classify_graph_error_known_statuses() -> None:
    error = GraphError("AADSTS500113: No reply address is registered for the application.", status=400)
    error_class, _ = _classify_graph_error(error)
    assert error_class == "app_missing_reply_url"

    forbidden = GraphError("insufficient privileges", status=403)
    error_class, _ = _classify_graph_error(forbidden)
    assert error_class == "insufficient_permissions"


def test_get_all_requires_dict_payload(monkeypatch) -> None:
    client = fake_graph_client()

    def _request(method, url, **kwargs):  # noqa: ARG001
        return graph_response(200, [1, 2, 3])

    monkeypatch.setattr(client, "_request", _request)

    exc = None
    try:
        client.get_all("/users")
    except Exception as caught:  # noqa: BLE001
        exc = caught

    assert isinstance(exc, GraphError)
    assert exc.request == "https://graph.microsoft.com/v1.0/users"


def test_graph_client_retries_429_with_retry_after(monkeypatch) -> None:
    client = fake_graph_client(throttle_mode="safe")
    sleeps: list[float] = []
    responses = [
        graph_response(
            429,
            {"error": {"code": "TooManyRequests", "message": "slow down"}},
            headers={"Retry-After": "3"},
        ),
        graph_response(200, {"value": [{"id": "1"}]}),
    ]

    monkeypatch.setattr("azure_tenant_audit.graph.time.sleep", lambda seconds: sleeps.append(seconds))
    monkeypatch.setattr("azure_tenant_audit.graph.random.uniform", lambda start, end: 0.0)
    monkeypatch.setattr(
        client.session,
        "request",
        lambda method, url, headers=None, timeout=None, **kwargs: responses.pop(0),
    )

    payload = client.get_json("/users")

    assert payload["value"][0]["id"] == "1"
    assert sleeps[0] == 3.0


def test_graph_client_stops_after_repeated_permission_failures(monkeypatch) -> None:
    client = fake_graph_client(throttle_mode="safe")
    calls = {"count": 0}

    def _request(method, url, headers=None, timeout=None, **kwargs):  # noqa: ARG001
        calls["count"] += 1
        return graph_response(
            403,
            {
                "error": {
                    "code": "Authorization_RequestDenied",
                    "message": "Access denied",
                }
            },
        )

    monkeypatch.setattr(client.session, "request", _request)

    for _ in range(2):
        try:
            client.get_json("/security/alerts")
        except GraphError:
            pass

    exc = None
    try:
        client.get_json("/security/alerts")
    except Exception as caught:  # noqa: BLE001
        exc = caught

    assert isinstance(exc, GraphError)
    assert exc.error_code == "PermissionStop"
    assert calls["count"] == 2

    # A sibling endpoint needs a different permission, so it is still tried.
    sibling = None
    try:
        client.get_json("/security/incidents")
    except GraphError as caught:
        sibling = caught
    assert sibling is not None and sibling.error_code != "PermissionStop"
    assert calls["count"] == 3


def test_graph_client_uses_shared_package_user_agent(monkeypatch) -> None:
    client = fake_graph_client()
    captured: dict[str, object] = {}

    def _request(method, url, headers=None, timeout=None, **kwargs):  # noqa: ANN001, ARG001
        captured["headers"] = headers
        return graph_response(200, {"value": [{"id": "1"}]})

    monkeypatch.setattr("azure_tenant_audit.graph.package_user_agent", lambda: "auditex/9.9.9")
    monkeypatch.setattr(client.session, "request", _request)

    payload = client.get_json("/users")

    assert payload["value"][0]["id"] == "1"
    assert captured["headers"]["User-Agent"] == "auditex/9.9.9"


def test_graph_client_batches_get_requests_in_chunks_of_20_and_preserves_order(monkeypatch) -> None:
    client = fake_graph_client(throttle_mode="fast")
    calls: list[dict[str, object]] = []

    def _request(method, url, **kwargs):  # noqa: ANN001, ARG001
        calls.append({"method": method, "url": url, "body": kwargs.get("json")})
        requests = kwargs["json"]["requests"]
        responses = []
        for request in requests:
            responses.append(
                {
                    "id": request["id"],
                    "status": 200,
                    "body": {
                        "value": [
                            {
                                "id": request["id"],
                                "url": request["url"],
                            }
                        ]
                    },
                }
            )
        return graph_response(200, {"responses": responses})

    monkeypatch.setattr(client, "_request", _request)

    requests = [{"path": f"/users/{index}", "params": {"$select": "id"}} for index in range(21)]
    responses = client.get_batch(requests)

    assert len(calls) == 2
    assert calls[0]["method"] == "POST"
    assert calls[0]["url"] == "https://graph.microsoft.com/v1.0/$batch"
    assert len(calls[0]["body"]["requests"]) == 20
    assert len(calls[1]["body"]["requests"]) == 1
    assert responses[0]["body"]["value"][0]["id"] == "0"
    assert responses[20]["request"]["path"] == "/users/20"


def test_graph_client_batches_get_requests_exposes_item_errors(monkeypatch) -> None:
    client = fake_graph_client(throttle_mode="fast")

    def _request(method, url, **kwargs):  # noqa: ANN001, ARG001
        requests = kwargs["json"]["requests"]
        return graph_response(
            200,
            {
                "responses": [
                    {
                        "id": requests[0]["id"],
                        "status": 403,
                        "body": {
                            "error": {
                                "code": "Authorization_RequestDenied",
                                "message": "Access denied",
                            }
                        },
                    }
                ]
            },
        )

    monkeypatch.setattr(client, "_request", _request)

    responses = client.get_batch([{ "path": "/me" }])

    assert responses[0]["status"] == 403
    assert responses[0]["error_code"] == "Authorization_RequestDenied"
    assert "Access denied" in responses[0]["error"]


def test_classify_graph_error_separates_license_gaps_from_permission_gaps() -> None:
    from azure_tenant_audit.collectors.base import _classify_graph_error

    premium = GraphError("Tenant is not a B2C tenant and doesn't have premium license", status=403, request="/auditLogs/signIns")
    spo = GraphError("Tenant does not have a SPO license.", status=400, request="/sites")
    intune = GraphError('{"ErrorCode":"Forbidden","Message":"An error has occurred"}', status=401, request="/deviceManagement/managedDevices")
    expired = GraphError("Lifetime validation failed, the token is expired.", status=401, request="/users")

    assert _classify_graph_error(premium)[0] == "license_required"
    assert _classify_graph_error(spo)[0] == "license_required"
    assert _classify_graph_error(intune)[0] == "insufficient_permissions"
    assert _classify_graph_error(expired)[0] == "unauthenticated"


def test_classify_graph_error_recognises_p2_and_unprovisioned_defender() -> None:
    p2 = GraphError("The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license.", status=400, request="/x")
    defender = GraphError("Unauthorized request - Account is not provisioned.", status=401, request="/security/alerts_v2")

    assert _classify_graph_error(p2)[0] == "license_required"
    assert _classify_graph_error(defender)[0] == "service_not_available"


def test_permission_stop_families_separate_security_endpoints() -> None:
    from azure_tenant_audit.graph import GraphClient

    family = GraphClient._request_family
    assert family(None, "https://graph.microsoft.com/v1.0/security/alerts_v2?$top=5") == "security/alerts_v2"
    assert family(None, "https://graph.microsoft.com/v1.0/security/secureScores") == "security/secureScores"
    assert family(None, "https://graph.microsoft.com/beta/reports/getX(period='D30')") == "reports/getX"


def test_failed_redirect_hop_error_has_no_signed_query(monkeypatch) -> None:
    """R158: a connect failure on the download hop must not carry the pre-authenticated query into evidence."""
    import pytest
    from requests.exceptions import ConnectionError as RequestsConnectionError

    client = fake_graph_client(throttle_mode="safe")
    signed = "https://reports.office.com/data/download/abc123?sig=TOPSECRETSIGNATURE&se=2026"

    def _request(method, url, headers=None, timeout=None, **kwargs):  # noqa: ANN001, ANN003
        if url.startswith("https://graph.microsoft.com"):
            return graph_response(302, {}, headers={"Location": signed})
        raise RequestsConnectionError(f"HTTPSConnectionPool(host='reports.office.com', port=443): Max retries exceeded with url: {url}")

    monkeypatch.setattr(client.session, "request", _request)
    with pytest.raises(RequestsConnectionError) as caught:
        client.get_json("/reports/getOffice365ActiveUserDetail(period='D7')")
    message, classified = str(caught.value), _classify_graph_error(caught.value)
    assert "TOPSECRETSIGNATURE" not in message and "sig=" not in message
    assert "reports.office.com" in message
    assert classified[0] == "client_error" and "TOPSECRETSIGNATURE" not in classified[1]
    assert caught.value.__cause__ is None and caught.value.__suppress_context__


def test_download_host_error_body_does_not_carry_signed_query(monkeypatch) -> None:
    """R158 (review): an HTTP error body from the download host that echoes the signed URL is not kept."""
    import pytest

    client = fake_graph_client(throttle_mode="safe")
    signed = "https://reports.office.com/data/download/abc123?sig=TOPSECRETSIGNATURE&se=2026"

    def _request(method, url, headers=None, timeout=None, **kwargs):  # noqa: ANN001, ANN003
        if url.startswith("https://graph.microsoft.com"):
            return graph_response(302, {}, headers={"Location": signed})
        denied = graph_response(403, f"AuthenticationFailed: signature mismatch for {url}")
        denied.url = url
        return denied

    monkeypatch.setattr(client.session, "request", _request)
    for call in (client.get_content, client.get_json):
        with pytest.raises(GraphError) as caught:
            call("/reports/getOffice365ActiveUserDetail(period='D7')")
        assert caught.value.status == 403
        assert "TOPSECRETSIGNATURE" not in str(caught.value) and "TOPSECRETSIGNATURE" not in str(caught.value.request)
        assert _classify_graph_error(caught.value)[0] == "insufficient_permissions"


def test_failed_redirect_hop_error_holds_no_signed_request(monkeypatch) -> None:
    """R158: the re-raised hop error keeps no request object naming the signed URL."""
    import pytest
    import requests
    from requests.exceptions import ConnectionError as RequestsConnectionError

    client = fake_graph_client(throttle_mode="safe")
    signed = "https://reports.office.com/data/download/abc123?sig=TOPSECRETSIGNATURE&se=2026"

    def _request(method, url, headers=None, timeout=None, **kwargs):  # noqa: ANN001, ANN003
        if url.startswith("https://graph.microsoft.com"):
            return graph_response(302, {}, headers={"Location": signed})
        raise RequestsConnectionError(f"failed: {url}", request=requests.Request("GET", url).prepare())

    monkeypatch.setattr(client.session, "request", _request)
    with pytest.raises(RequestsConnectionError) as caught:
        client.get_content("/reports/getOffice365ActiveUserDetail(period='D7')")
    assert caught.value.request is None and "TOPSECRETSIGNATURE" not in repr(caught.value.args)
