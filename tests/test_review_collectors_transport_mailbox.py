"""Mailbox forwarding review fixes: R006 (moveToFolder is a folder ID) and R046 (mailbox-less users)."""
from __future__ import annotations

from typing import Any

from azure_tenant_audit.collectors.mailbox_forwarding import MailboxForwardingCollector
from azure_tenant_audit.graph import GraphError

RSS_ID = "AAMkADhmRSSFEEDS0000AAA="
JUNK_ID = "AAMkADhmJUNK000000000AAA="
INBOX_SUB_ID = "AAMkADhmPROJECTS00000AAA="
USERS = [{"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "userType": "Member"}]
DOMAINS = [{"id": "contoso.com", "isVerified": True}]


def _rule(rule_id: str, folder: str) -> dict[str, Any]:
    return {"id": rule_id, "displayName": ".", "isEnabled": True, "conditions": {},
            "actions": {"moveToFolder": folder, "markAsRead": True}}


class _Client:
    def __init__(self, rules, *, folders_error: Exception | None = None, users=USERS, mailbox_errors=None):
        self.rules, self.folders_error, self.users = rules, folders_error, users
        self.mailbox_errors = mailbox_errors or {}
        self.paths: list[str] = []

    def get_all(self, path, params=None):
        self.paths.append(path)
        if path == "/users":
            return list(self.users)
        if path == "/domains":
            return list(DOMAINS)
        if path.endswith("/mailFolders"):
            assert params and set(params["$select"].split(",")) == {"id", "displayName"}
            if self.folders_error:
                raise self.folders_error
            return [{"id": "AAMkADhmINBOX", "displayName": "Inbox"}, {"id": RSS_ID, "displayName": "RSS Feeds"}]
        raise AssertionError(path)

    def get_batch(self, requests):
        self.paths.extend(spec["path"] for spec in requests)
        if self.folders_error:
            raise self.folders_error
        ids = {"junkemail": JUNK_ID, "deleteditems": "AAMkADhmDELETED", "conversationhistory": "AAMkADhmCONV"}
        out = []
        for spec in requests:
            name = spec["path"].rsplit("/", 1)[-1]
            assert spec["params"] == {"$select": "id"}
            out.append({"status": 200, "body": {"id": ids[name]}} if name in ids
                       else {"status": 404, "body": {"error": {"code": "ErrorItemNotFound"}}})
        return out

    def get_json(self, path, params=None, full_url=False):
        self.paths.append(path)
        user_id = path.split("/")[2]
        if user_id in self.mailbox_errors:
            raise self.mailbox_errors[user_id]
        if path.endswith("/messageRules"):
            return {"value": self.rules.get(user_id, [])}
        if path.endswith("/mailboxSettings"):
            return {}
        raise AssertionError(path)


def _by_id(result) -> dict[str, dict[str, Any]]:
    return {row["rule_id"]: row for row in result.payload["messageRules"]["value"]}


def test_move_to_rss_or_junk_by_folder_id_hides_from_user() -> None:
    client = _Client({"u1": [_rule("r-rss", RSS_ID), _rule("r-junk", JUNK_ID), _rule("r-ok", INBOX_SUB_ID)]})
    result = MailboxForwardingCollector().run({"client": client})
    rows = _by_id(result)
    assert rows["r-rss"]["hide_from_user"] is True
    assert rows["r-junk"]["hide_from_user"] is True
    assert rows["r-ok"]["hide_from_user"] is False
    assert result.status == "ok"
    # Folder metadata only: no message is read.
    assert not any("/messages" in path for path in client.paths)


def test_unresolved_folder_ids_leave_the_hide_state_unknown_and_record_a_gap() -> None:
    client = _Client({"u1": [_rule("r-rss", RSS_ID)]}, folders_error=GraphError("denied", status=403))
    result = MailboxForwardingCollector().run({"client": client})
    row = _by_id(result)["r-rss"]
    assert row["hide_from_user"] is None
    assert row["hide_from_user_state"] == "unknown"
    assert result.status == "partial"
    gap = [r for r in result.coverage if r["name"] == "mailFolders:u1"]
    assert gap and gap[0]["status"] == "failed" and gap[0]["error_class"] == "insufficient_permissions"


def test_users_without_move_rules_need_no_folder_read() -> None:
    client = _Client({"u1": [{"id": "r", "displayName": ".", "actions": {"delete": True}, "conditions": {}}]})
    MailboxForwardingCollector().run({"client": client})
    assert not any("mailFolders/" in path and "messageRules" not in path for path in client.paths)
    assert not any(path.endswith("/mailFolders") for path in client.paths)
