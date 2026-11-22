"""R006 follow-up: the folder-ID lookup must not trip the per-family permission stop or repeat a refused read."""
from __future__ import annotations

from urllib.parse import urlparse

import pytest
from support import fake_graph_client, graph_response

from azure_tenant_audit.collectors.mailbox_forwarding import MailboxForwardingCollector

USERS = [
    {"id": f"u{n}", "userPrincipalName": f"user{n}@contoso.com", "mail": f"user{n}@contoso.com", "userType": "Member"}
    for n in (1, 2, 3)
]
DENIED = {"error": {"code": "ErrorAccessDenied", "message": "Access is denied. Check credentials and try again."}}


def _session(sent: list[str]):
    def _request(method, url, headers=None, timeout=None, params=None, json=None, **kwargs):  # noqa: ARG001
        path = urlparse(url).path.removeprefix("/v1.0")
        sent.append(f"{method} {path}")
        if path == "/$batch":
            return graph_response(200, {"responses": [
                {"id": item["id"], "status": 403, "body": DENIED} for item in json["requests"]
            ]})
        if path == "/users":
            return graph_response(200, {"value": USERS})
        if path == "/domains":
            return graph_response(200, {"value": [{"id": "contoso.com", "isVerified": True}]})
        if path.endswith("/messageRules"):
            return graph_response(200, {"value": [{
                "id": "r1", "displayName": ".", "isEnabled": True, "conditions": {},
                "actions": {"moveToFolder": "AAMkADhmFOLDERID000AAA=", "markAsRead": True},
            }]})
        if path.endswith("/mailboxSettings"):
            return graph_response(200, {})
        if "/mailFolders" in path:
            return graph_response(403, DENIED)
        raise AssertionError(path)

    return _request


@pytest.mark.parametrize("mode", ["safe", "ultra-safe"])
def test_a_refused_folder_lookup_leaves_the_users_other_reads_alone(monkeypatch, mode) -> None:
    client = fake_graph_client(throttle_mode=mode)
    client.sleep = lambda _seconds: None
    sent: list[str] = []
    monkeypatch.setattr(client.session, "request", _session(sent))
    result = MailboxForwardingCollector().run({"client": client})
    by_name = {row["name"]: row for row in result.coverage}
    # The refusal never reaches the user's later reads through the permission stop.
    for user in USERS:
        assert by_name[f"mailboxSettings:{user['id']}"]["status"] == "ok", by_name[f"mailboxSettings:{user['id']}"]
    # One refused lookup is enough: later users' rules are unknown without sending the same refused read again.
    folder_reads = [line for line in sent if ("/mailFolders" in line and "messageRules" not in line) or line.endswith("/$batch")]
    assert len(folder_reads) == 1, folder_reads
    gaps = [row for row in result.coverage if row["name"].startswith("mailFolders")]
    assert len(gaps) == 1 and gaps[0]["status"] == "failed"
    assert gaps[0]["error_class"] == "insufficient_permissions"
    assert gaps[0]["unresolved_user_count"] == 3
    rules = result.payload["messageRules"]["value"]
    assert {row["hide_from_user_state"] for row in rules} == {"unknown"}
    assert result.status == "partial"
