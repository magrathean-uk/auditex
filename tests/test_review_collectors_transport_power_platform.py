"""R110: the Power Platform client retries a throttled or unavailable answer, honouring a capped Retry-After."""
from __future__ import annotations

import pytest

from azure_tenant_audit.power_platform import PowerPlatformClient, PowerPlatformError

TOKEN = "constructed-bap-token"


class _Response:
    def __init__(self, status=200, raw=None, headers=None):
        self.status_code, self.raw, self.headers = status, raw, headers or {}
        self.content = b"{}" if raw is not None else b""

    def json(self):
        return self.raw


class _Session:
    def __init__(self, answers):
        self.answers, self.calls = list(answers), 0

    def request(self, method, url, **kwargs):
        self.calls += 1
        return self.answers.pop(0)

    def post(self, url, **kwargs):
        self.calls += 1
        return self.answers.pop(0)


def test_get_retries_429_after_its_retry_after():
    waits: list[float] = []
    session = _Session([_Response(429, headers={"Retry-After": "4"}), _Response(200, {"value": [1]})])
    client = PowerPlatformClient(token=TOKEN, session=session, sleep=waits.append)
    assert client.get("/scopes/admin/environments") == {"value": [1]}
    assert waits == [4.0] and session.calls == 2


def test_post_read_retries_503_and_caps_a_huge_retry_after():
    waits: list[float] = []
    session = _Session([_Response(503, headers={"Retry-After": "3600"}), _Response(200, {"value": []})])
    client = PowerPlatformClient(token=TOKEN, session=session, sleep=waits.append)
    assert client.post_read("/providers/Microsoft.BusinessAppPlatform/listTenantSettings") == {"value": []}
    assert waits and max(waits) <= 30.0


def test_retries_are_bounded_and_the_last_status_is_raised():
    session = _Session([_Response(429) for _ in range(10)])
    client = PowerPlatformClient(token=TOKEN, session=session, sleep=lambda _s: None)
    with pytest.raises(PowerPlatformError) as caught:
        client.get("/scopes/admin/environments")
    assert caught.value.status == 429
    assert session.calls == 3


def test_a_refusal_is_not_retried():
    session = _Session([_Response(403), _Response(200, {})])
    client = PowerPlatformClient(token=TOKEN, session=session, sleep=lambda _s: None)
    with pytest.raises(PowerPlatformError):
        client.get("/scopes/admin/environments")
    assert session.calls == 1
