"""Per-item 429, 503 and 504 retry inside a Graph ``$batch`` response (synthetic answers, injected clock, no network)."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from support import graph_auth, graph_response

from azure_tenant_audit.graph import (
    GRAPH_BATCH_CHUNK_SIZE,
    THROTTLE_POLICIES,
    GraphClient,
    GraphError,
    read_only_violation,
)

Answer = Callable[[str, int], dict[str, Any]]


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.waits: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.waits.append(seconds)
        self.now += seconds


def ok(url: str) -> dict[str, Any]:
    return {"status": 200, "body": {"value": [{"id": url}]}}


def throttled(retry_after: str | None = None, status: int = 429) -> dict[str, Any]:
    item: dict[str, Any] = {"status": status, "body": {"error": {"code": "TooManyRequests", "message": "Too many requests."}}}
    if retry_after is not None:
        item["headers"] = {"Retry-After": retry_after}
    return item


class BatchSession:
    """Answers each ``$batch`` POST through ``answer(url, attempt)``; the attempt counts the sends of that inner url."""

    def __init__(self, answer: Answer) -> None:
        self.answer = answer
        self.posts: list[list[dict[str, Any]]] = []
        self.sends: dict[str, int] = {}

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        assert method == "POST" and url.endswith("/$batch")
        inner = kwargs["json"]["requests"]
        self.posts.append(inner)
        responses = []
        for item in inner:
            self.sends[item["url"]] = self.sends.get(item["url"], 0) + 1
            responses.append({"id": item["id"], **self.answer(item["url"], self.sends[item["url"]])})
        return graph_response(200, {"responses": responses})


def client_for(answer: Answer, *, mode: str = "fast") -> tuple[GraphClient, BatchSession, FakeClock, list[tuple[str, dict]]]:
    clock = FakeClock()
    events: list[tuple[str, dict]] = []
    session = BatchSession(answer)
    client = GraphClient(
        graph_auth(throttle_mode=mode),
        session=session,  # type: ignore[arg-type]
        audit_event=lambda name, _message, details: events.append((name, details or {})),
        clock=lambda: clock.now,
        sleep=clock.sleep,
    )
    return client, session, clock, events


def paths(count: int) -> list[dict[str, Any]]:
    return [{"path": f"/policies/roleManagementPolicies/p{index}/rules"} for index in range(count)]


def test_a_429_item_is_re_sent_alone_and_then_read() -> None:
    client, session, clock, _ = client_for(lambda url, n: throttled("2") if url.endswith("p1/rules") and n == 1 else ok(url))

    results = client.get_batch(paths(3))

    assert [item["status"] for item in results] == [200, 200, 200]
    assert results[1]["body"]["value"][0]["id"] == "/policies/roleManagementPolicies/p1/rules"
    assert results[1]["attempts"] == 2 and "retry_exhausted" not in results[1]
    assert [len(post) for post in session.posts] == [3, 1]
    assert session.posts[1][0]["url"] == "/policies/roleManagementPolicies/p1/rules"
    assert clock.waits == [2.0]


def test_retry_after_is_honoured_and_its_absence_uses_the_policy_back_off() -> None:
    client, _, clock, _ = client_for(lambda url, n: throttled("7") if n == 1 else ok(url))
    client.get_batch(paths(1))
    assert clock.waits == [7.0]

    # No Retry-After, or one that is not a number of seconds: the safe policy's exponential back-off (1.5, 3.0).
    for header in (None, "Wed, 21 Oct 2026 07:28:00 GMT", "nan", "inf"):
        client, _, clock, _ = client_for(lambda url, n, header=header: throttled(header) if n <= 2 else ok(url), mode="safe")
        results = client.get_batch(paths(1))
        assert results[0]["status"] == 200
        assert clock.waits == [1.5, 3.0], header


def test_the_attempt_bound_is_reached_and_the_item_is_a_named_gap() -> None:
    client, session, clock, events = client_for(lambda url, n: throttled("1"))  # fast: rate_limit_retries=3

    (result,) = client.get_batch(paths(1))

    policy = THROTTLE_POLICIES["fast"]
    assert len(session.posts) == policy.rate_limit_retries + 1
    assert result["status"] == 429 and result["retry_exhausted"] is True
    assert result["attempts"] == policy.rate_limit_retries + 1
    assert "still answered HTTP 429 after 4 attempts" in result["error"]
    assert clock.waits == [1.0, 1.0, 1.0]
    (exhausted,) = [details for name, details in events if name == "graph.batch.retry_exhausted"]
    assert exhausted["urls"] == ["/policies/roleManagementPolicies/p0/rules"] and exhausted["statuses"] == [429]


def test_the_total_wait_bound_stops_the_retries() -> None:
    # safe allows 4 retries but only 120 seconds of waiting: a second 100-second wait would pass it.
    client, session, clock, _ = client_for(lambda url, n: throttled("100"), mode="safe")

    (result,) = client.get_batch(paths(1))

    assert clock.waits == [100.0]
    assert len(session.posts) == 2
    assert result["retry_exhausted"] is True and result["status"] == 429


def test_503_and_504_are_bounded_by_the_server_error_retries() -> None:
    client, session, clock, _ = client_for(lambda url, n: throttled(status=503 if url.endswith("p0/rules") else 504))

    results = client.get_batch(paths(2))

    policy = THROTTLE_POLICIES["fast"]
    assert len(session.posts) == policy.server_error_retries + 1
    assert [item["status"] for item in results] == [503, 504]
    assert all(item["retry_exhausted"] for item in results)
    assert clock.waits == [1.0, 2.0]


def test_mixed_outcomes_re_send_only_the_retryable_items() -> None:
    first = {"p0": ok, "p1": lambda url: throttled("3"), "p2": lambda url: throttled(status=503),
             "p3": lambda url: throttled(status=504), "p4": lambda url: {"status": 404, "body": {"error": {"code": "NotFound"}}},
             "p5": lambda url: {"status": 403, "body": {"error": {"code": "Forbidden", "message": "denied"}}}}

    def answer(url: str, n: int) -> dict[str, Any]:
        key = url.split("/")[3]
        return first[key](url) if n == 1 else ok(url)

    client, session, clock, events = client_for(answer)
    results = client.get_batch(paths(6))

    assert [item["status"] for item in results] == [200, 200, 200, 200, 404, 403]
    assert sorted(item["url"] for item in session.posts[1]) == [f"/policies/roleManagementPolicies/p{i}/rules" for i in (1, 2, 3)]
    assert len(session.posts) == 2
    assert clock.waits == [3.0]
    (retry,) = [details for name, details in events if name == "graph.batch.retry"]
    assert retry["item_count"] == 3 and retry["attempt"] == 1 and retry["statuses"] == [429, 503, 504]


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 412])
def test_no_other_4xx_is_retried(status: int) -> None:
    client, session, clock, events = client_for(lambda url, n: {"status": status, "body": {"error": {"code": "X", "message": "m"}}})

    (result,) = client.get_batch(paths(1))

    assert result["status"] == status and "retry_exhausted" not in result and "attempts" not in result
    assert len(session.posts) == 1 and clock.waits == []
    assert not [name for name, _ in events if name.startswith("graph.batch.")]


def test_retries_stay_within_their_chunk_and_keep_the_order() -> None:
    count = GRAPH_BATCH_CHUNK_SIZE + 3
    client, session, _, _ = client_for(lambda url, n: throttled("1") if n == 1 and url.endswith(("p0/rules", "p21/rules")) else ok(url))

    results = client.get_batch(paths(count))

    assert [item["status"] for item in results] == [200] * count
    assert [item["request"]["path"] for item in results] == [item["path"] for item in paths(count)]
    assert [len(post) for post in session.posts] == [GRAPH_BATCH_CHUNK_SIZE, 1, 3, 1]


@pytest.mark.parametrize("method", ["POST", "PATCH", "PUT", "DELETE"])
def test_a_batch_carries_get_items_only(method: str) -> None:
    client, session, _, _ = client_for(lambda url, n: ok(url))

    with pytest.raises(GraphError, match="only supports GET"):
        client.get_batch([{"path": "/users"}, {"path": "/users/1", "method": method}])
    assert session.posts == []
    # The read guard refuses the same body if it reached the transport.
    body = {"json": {"requests": [{"id": "0", "method": method, "url": "/users/1"}]}}
    assert "non-GET" in str(read_only_violation("POST", "https://graph.microsoft.com/v1.0/$batch", body))


def test_a_re_sent_batch_is_get_only_and_recorded_in_the_run_ledger() -> None:
    client, session, _, events = client_for(lambda url, n: throttled("2") if n == 1 and url.endswith("p1/rules") else ok(url))

    client.get_batch(paths(2))

    assert all(item["method"] == "GET" for post in session.posts for item in post)
    started = [details["batch"] for name, details in events if name == "graph.request.started"]
    assert [entry["urls"] for entry in started] == [
        ["/policies/roleManagementPolicies/p0/rules", "/policies/roleManagementPolicies/p1/rules"],
        ["/policies/roleManagementPolicies/p1/rules"],
    ]
    assert all(entry["methods"] == ["GET"] for entry in started)
    (retry,) = [details for name, details in events if name == "graph.batch.retry"]
    assert retry["urls"] == ["/policies/roleManagementPolicies/p1/rules"]
    assert retry["wait_seconds"] == 2.0 and retry["statuses"] == [429]


def test_a_missing_item_answer_is_not_retried() -> None:
    class Missing(BatchSession):
        def request(self, method: str, url: str, **kwargs: Any) -> Any:
            self.posts.append(kwargs["json"]["requests"])
            return graph_response(200, {"responses": []})

    client, _, clock, _ = client_for(lambda url, n: ok(url))
    client.session = Missing(lambda url, n: ok(url))  # type: ignore[assignment]

    (result,) = client.get_batch(paths(1))

    assert result["error_code"] == "BatchMissingResponse" and clock.waits == []


def test_one_item_over_the_wait_budget_does_not_hold_back_the_others() -> None:
    # safe: 120 seconds of waiting. p0 asks for 150 (over the budget, a gap at once); p1 asks for 2 and is re-sent.
    client, session, clock, events = client_for(
        lambda url, n: throttled("150") if url.endswith("p0/rules") else (throttled("2") if n == 1 else ok(url)), mode="safe"
    )

    results = client.get_batch(paths(2))

    assert results[0]["status"] == 429 and results[0]["retry_exhausted"] is True and "attempts" not in results[0]
    assert results[1]["status"] == 200 and results[1]["attempts"] == 2 and "retry_exhausted" not in results[1]
    assert [[item["url"] for item in post] for post in session.posts][1] == ["/policies/roleManagementPolicies/p1/rules"]
    assert clock.waits == [2.0]
    (exhausted,) = [details for name, details in events if name == "graph.batch.retry_exhausted"]
    assert exhausted["urls"] == ["/policies/roleManagementPolicies/p0/rules"]


def test_transport_retries_of_a_re_send_share_the_wait_budget() -> None:
    # The first send throttles the item for 100 seconds; the re-sent POST is itself throttled for 15 seconds, twice.
    # safe allows 120 seconds in all: the first 15 fits (115), the second would pass the bound and is not slept.
    class OuterThrottle(BatchSession):
        def request(self, method: str, url: str, **kwargs: Any) -> Any:
            if self.posts:
                self.posts.append(kwargs["json"]["requests"])
                return graph_response(
                    429, {"error": {"code": "TooManyRequests", "message": "slow down"}}, headers={"Retry-After": "15"}
                )
            return super().request(method, url, **kwargs)

    client, _, clock, events = client_for(lambda url, n: throttled("100"), mode="safe")
    session = OuterThrottle(lambda url, n: throttled("100"))
    client.session = session  # type: ignore[assignment]

    (result,) = client.get_batch(paths(1))

    assert clock.waits == [100.0, 15.0] and sum(clock.waits) <= THROTTLE_POLICIES["safe"].max_retry_wait_seconds
    assert len(session.posts) == 3
    assert result["status"] == 429 and result["retry_exhausted"] is True
    assert "Retry request failed" in result["error"]
    assert [name for name, _ in events if name == "graph.request.retry_budget_exhausted"] == ["graph.request.retry_budget_exhausted"]


def test_a_failed_re_send_keeps_the_settled_answers_and_reads_nothing_twice() -> None:
    from requests import RequestException

    from azure_tenant_audit.collectors._endpoint_reads import STATUS_OK, read_endpoints

    class FailingResend(BatchSession):
        def __init__(self, answer: Answer) -> None:
            super().__init__(answer)
            self.calls: list[tuple[str, str]] = []

        def request(self, method: str, url: str, **kwargs: Any) -> Any:
            self.calls.append((method, url))
            if self.posts:
                raise RequestException("connection reset")
            return super().request(method, url, **kwargs)

    answers = {
        "p0": ok,
        "p1": lambda url: {"status": 403, "body": {"error": {"code": "Forbidden", "message": "denied"}}},
        "p2": lambda url: throttled("1"),
    }
    client, _, _, events = client_for(lambda url, n: ok(url))
    session = FailingResend(lambda url, n: answers[url.split("/")[3]](url))
    client.session = session  # type: ignore[assignment]

    results = client.get_batch(paths(3))

    assert [item["status"] for item in results] == [200, 403, 429]
    assert results[0]["body"] == {"value": [{"id": "/policies/roleManagementPolicies/p0/rules"}]}
    assert "retry_exhausted" not in results[1]
    assert results[2]["retry_exhausted"] is True and "Retry request failed: connection reset" in results[2]["error"]
    assert [name for name, _ in events if name == "graph.batch.retry_failed"] == ["graph.batch.retry_failed"]

    # Through the endpoint reader: no fallback re-read of the chunk, only the two $batch POSTs.
    session.calls.clear()
    session.posts.clear()
    session.sends.clear()
    reads = read_endpoints(client, [item["path"] for item in paths(3)], rows=True)
    assert [method for method, _ in session.calls] == ["POST", "POST"]
    assert reads[0].status == STATUS_OK and reads[1].status != STATUS_OK and reads[2].status != STATUS_OK
