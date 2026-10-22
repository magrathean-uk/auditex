"""GraphClient._request sends reads only: GET, and POST solely to /$batch with GET-only inner requests."""
from __future__ import annotations

from typing import Any

import pytest

from azure_tenant_audit.graph import (
    GRAPH_BETA_ROOT,
    GRAPH_ROOT,
    READ_ONLY_VIOLATION,
    GraphClient,
    GraphError,
    read_only_violation,
)
from support import graph_auth, graph_response


class _Recorder:
    """Fake requests.Session that records every request; the tests assert on what reached it."""

    def __init__(self, responses: list[Any] | None = None) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.token_posts: list[str] = []
        self._responses = responses if responses is not None else []

    def request(self, method: str, url: str, headers=None, timeout=None, **kwargs: Any):  # noqa: ANN001, ARG002
        self.calls.append((method, url, kwargs))
        return self._responses.pop(0) if self._responses else graph_response(200, {"value": []})

    def post(self, url: str, **kwargs: Any):  # noqa: ARG002
        self.token_posts.append(url)
        raise AssertionError("a refused request must not even ask for a token")


def _client(session: _Recorder, events: list[tuple[str, dict[str, Any]]], **auth: Any) -> GraphClient:
    client = GraphClient(
        graph_auth(**auth),
        session=session,  # type: ignore[arg-type]
        audit_event=lambda event, message, details=None: events.append((event, dict(details or {}))),
    )
    return client


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "post", "HEAD", "OPTIONS", "TRACE", "", None])
def test_non_read_methods_are_refused_before_any_network_call(method) -> None:
    session = _Recorder()
    events: list[tuple[str, dict[str, Any]]] = []
    # No access token and no client secret: ensure_token() would fail or reach the token endpoint if called.
    client = _client(session, events, auth_mode="app", access_token=None, client_secret="s")

    with pytest.raises(GraphError) as caught:
        client._request(method, f"{GRAPH_ROOT}/users/u1", json={"accountEnabled": False})

    assert caught.value.error_code == READ_ONLY_VIOLATION
    assert session.calls == []
    assert session.token_posts == []
    refused = [details for event, details in events if event == "graph.request.refused"]
    assert len(refused) == 1
    assert refused[0]["url"] == f"{GRAPH_ROOT}/users/u1"
    assert refused[0]["reason"]
    # The refusal is the only transport event: nothing was started.
    assert not [event for event, _ in events if event == "graph.request.started"]


def test_refusal_is_not_retried_or_paced() -> None:
    session = _Recorder()
    events: list[tuple[str, dict[str, Any]]] = []
    client = _client(session, events)

    with pytest.raises(GraphError):
        client._request("DELETE", f"{GRAPH_ROOT}/users/u1")

    assert [event for event, _ in events] == ["graph.request.refused"]


def test_get_is_sent_and_logged() -> None:
    session = _Recorder([graph_response(200, {"value": [{"id": "1"}]})])
    events: list[tuple[str, dict[str, Any]]] = []
    client = _client(session, events)

    payload = client.get_json("/users", params={"$top": 1})

    assert payload["value"][0]["id"] == "1"
    assert [call[0] for call in session.calls] == ["GET"]
    assert [event for event, _ in events if event.startswith("graph.request.") and event != "graph.request.pacing"] == [
        "graph.request.started",
        "graph.request.completed",
    ]


def test_get_with_a_body_is_refused() -> None:
    session = _Recorder()
    client = _client(session, [])

    for body in ({"json": {"a": 1}}, {"data": "x"}, {"files": {"f": b"x"}}):
        with pytest.raises(GraphError) as caught:
            client._request("GET", f"{GRAPH_ROOT}/users", **body)
        assert caught.value.error_code == READ_ONLY_VIOLATION
    assert session.calls == []


def test_batch_of_gets_is_allowed_and_inner_requests_are_logged() -> None:
    inner = [{"id": "0", "method": "GET", "url": "/users/u1/manager"}, {"id": "1", "method": "GET", "url": "/groups/g1/owners"}]
    session = _Recorder([graph_response(200, {"responses": [{"id": "0", "status": 200, "body": {}}, {"id": "1", "status": 200, "body": {}}]})])
    events: list[tuple[str, dict[str, Any]]] = []
    client = _client(session, events)

    results = client.get_batch([{"path": "/users/u1/manager"}, {"path": "/groups/g1/owners"}])

    assert [row["status"] for row in results] == [200, 200]
    assert [call[:2] for call in session.calls] == [("POST", f"{GRAPH_ROOT}/$batch")]
    assert session.calls[0][2]["json"]["requests"] == inner
    started = [details for event, details in events if event == "graph.request.started"]
    assert started[0]["batch"] == {"size": 2, "methods": ["GET"], "urls": ["/users/u1/manager", "/groups/g1/owners"]}


@pytest.mark.parametrize(
    "requests_body",
    [
        [{"id": "0", "method": "DELETE", "url": "/users/u1"}],
        [{"id": "0", "method": "GET", "url": "/users/u1"}, {"id": "1", "method": "patch", "url": "/users/u1"}],
        [{"id": "0", "method": "POST", "url": "/users/u1/assignLicense"}],
        [{"id": "0", "method": "GET", "url": "/users/u1", "body": {"a": 1}}],
        [{"id": "0", "method": "GET", "url": "https://evil.example/users"}],
        [{"id": "0", "method": "GET", "url": "//evil.example/users"}],
        [{"id": "0", "url": "/users/u1"}],
        [{"id": "0", "method": "GET", "url": "/users/u1", "extra": 1}],
        ["not-a-dict"],
    ],
)
def test_batch_with_any_non_get_or_non_relative_inner_request_is_refused(requests_body) -> None:
    session = _Recorder()
    events: list[tuple[str, dict[str, Any]]] = []
    client = _client(session, events)

    with pytest.raises(GraphError) as caught:
        client._request("POST", f"{GRAPH_ROOT}/$batch", json={"requests": requests_body})

    assert caught.value.error_code == READ_ONLY_VIOLATION
    assert session.calls == []
    assert [event for event, _ in events] == ["graph.request.refused"]


@pytest.mark.parametrize(
    "url",
    [
        f"{GRAPH_ROOT}/users",
        f"{GRAPH_ROOT}/$batch?x=1",
        "https://evil.example/v1.0/$batch",
        "http://graph.microsoft.com/v1.0/$batch",
        f"{GRAPH_ROOT}/$batch/extra",
        "/$batch",
    ],
)
def test_post_is_only_allowed_to_the_graph_batch_endpoint(url: str) -> None:
    session = _Recorder()
    client = _client(session, [])

    with pytest.raises(GraphError) as caught:
        client._request("POST", url, json={"requests": [{"id": "0", "method": "GET", "url": "/users"}]})

    assert caught.value.error_code == READ_ONLY_VIOLATION
    assert session.calls == []


def test_batch_body_must_be_a_plain_requests_list() -> None:
    for kwargs in (
        {},
        {"data": "x"},
        {"json": {"requests": []}, "params": {"a": 1}},
        {"json": {"requests": [], "extra": 1}},
        {"json": {"requests": "nope"}},
        {"json": []},
    ):
        assert read_only_violation("POST", f"{GRAPH_ROOT}/$batch", kwargs) is not None


def test_beta_batch_endpoint_is_allowed() -> None:
    body = {"requests": [{"id": "0", "method": "GET", "url": "/deviceManagement/groupPolicyConfigurations"}]}
    assert read_only_violation("POST", f"{GRAPH_BETA_ROOT}/$batch", {"json": body}) is None


def test_get_batch_still_refuses_non_get_specs_locally() -> None:
    session = _Recorder()
    client = _client(session, [])

    with pytest.raises(GraphError):
        client.get_batch([{"method": "DELETE", "path": "/users/u1"}])

    assert session.calls == []


# --- bypasses found in review ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    ["X-HTTP-Method-Override", "x-http-method-override", "X-Method-Override", "X-HTTP-Method", " X-HTTP-Method-Override "],
)
def test_method_override_headers_are_refused_on_get_and_batch(header: str) -> None:
    session = _Recorder()
    events: list[tuple[str, dict[str, Any]]] = []
    client = _client(session, events)

    with pytest.raises(GraphError) as get_error:
        client._request("GET", f"{GRAPH_ROOT}/users/u1", headers={header: "DELETE"})
    with pytest.raises(GraphError) as batch_error:
        client._request(
            "POST",
            f"{GRAPH_ROOT}/$batch",
            headers={header: "DELETE"},
            json={"requests": [{"id": "0", "method": "GET", "url": "/users/u1"}]},
        )

    assert get_error.value.error_code == batch_error.value.error_code == READ_ONLY_VIOLATION
    assert session.calls == []
    assert [event for event, _ in events] == ["graph.request.refused", "graph.request.refused"]


def test_method_override_header_inside_a_batch_inner_request_is_refused() -> None:
    body = {"requests": [{"id": "0", "method": "GET", "url": "/users/u1", "headers": {"X-HTTP-Method-Override": "DELETE"}}]}

    assert read_only_violation("POST", f"{GRAPH_ROOT}/$batch", {"json": body}) is not None


def test_ordinary_headers_are_still_allowed() -> None:
    session = _Recorder([graph_response(200, {"value": []})])
    client = _client(session, [])

    client._request("GET", f"{GRAPH_ROOT}/users", headers={"ConsistencyLevel": "eventual"}, params={"$count": "true"})

    assert [call[0] for call in session.calls] == ["GET"]
    inner_ok = {"requests": [{"id": "0", "method": "GET", "url": "/users", "headers": {"ConsistencyLevel": "eventual"}}]}
    assert read_only_violation("POST", f"{GRAPH_ROOT}/$batch", {"json": inner_ok}) is None


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/v1.0/users",
        "http://graph.microsoft.com/v1.0/users",
        "https://graph.microsoft.com.evil.example/v1.0/users",
        "https://evil.example/graph.microsoft.com/v1.0/users",
        "ftp://graph.microsoft.com/v1.0/users",
        "/v1.0/users",
        "",
    ],
)
def test_the_bearer_token_never_goes_to_another_host(url: str) -> None:
    session = _Recorder()
    events: list[tuple[str, dict[str, Any]]] = []
    client = _client(session, events, auth_mode="app", access_token=None, client_secret="s")

    for call in (
        lambda: client.get_json(url, full_url=True),
        lambda: client.get_content(url, full_url=True),
        lambda: client._request("GET", url),
    ):
        with pytest.raises(GraphError):
            call()

    assert session.calls == []
    assert session.token_posts == []  # no token was even requested


def test_a_full_url_on_the_graph_host_is_still_allowed() -> None:
    session = _Recorder([graph_response(200, {"value": []}), graph_response(200, "csv,data")])
    client = _client(session, [])

    assert client.get_json(f"{GRAPH_BETA_ROOT}/deviceManagement/groupPolicyConfigurations", full_url=True) == {"value": []}
    assert client.get_content(f"{GRAPH_ROOT}/reports/getMailboxUsageDetail(period='D30')", full_url=True) == "csv,data"
    assert [call[1] for call in session.calls] == [
        f"{GRAPH_BETA_ROOT}/deviceManagement/groupPolicyConfigurations",
        f"{GRAPH_ROOT}/reports/getMailboxUsageDetail(period='D30')",
    ]


def test_a_refused_full_url_is_recorded_as_a_refused_next_link() -> None:
    events: list[tuple[str, dict[str, Any]]] = []
    client = _client(_Recorder(), events)

    with pytest.raises(GraphError) as caught:
        client.get_json("https://evil.example/x", full_url=True)

    assert caught.value.error_code == "NextLinkRefused"
    assert [event for event, _ in events] == ["graph.request.next_link_refused"]
