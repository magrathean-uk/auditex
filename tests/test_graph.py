from __future__ import annotations

from azure_tenant_audit.collectors.base import _classify_graph_error
from azure_tenant_audit.graph import GraphError
from support import fake_graph_client, graph_response


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
        client.get_json("/security/incidents")
    except Exception as caught:  # noqa: BLE001
        exc = caught

    assert isinstance(exc, GraphError)
    assert exc.error_code == "PermissionStop"
    assert calls["count"] == 2


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
