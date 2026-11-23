from __future__ import annotations

from typing import Any

from azure_tenant_audit.collectors.mailbox_forwarding import MailboxForwardingCollector


class _FakeClient:
    def __init__(
        self,
        users: list[dict[str, Any]],
        domains: list[dict[str, Any]],
        inbox_rules: dict[str, Any],
        mailbox_settings: dict[str, Any] | None = None,
    ) -> None:
        self._users = users
        self._domains = domains
        self._inbox_rules = inbox_rules
        self._mailbox_settings = mailbox_settings or {}
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        self.calls.append((path, dict(params or {})))
        if path == "/users":
            return list(self._users)
        if path == "/domains":
            return list(self._domains)
        raise AssertionError(f"unexpected path: {path}")

    def get_json(self, path: str, params: dict[str, Any] | None = None, full_url: bool = False) -> dict[str, Any]:
        self.calls.append((path, dict(params or {})))
        if path.startswith("/users/") and path.endswith("/mailFolders/inbox/messageRules"):
            user_id = path.split("/")[2]
            response = self._inbox_rules.get(user_id, [])
            if isinstance(response, Exception):
                raise response
            return {"value": response}
        if path.startswith("/users/") and path.endswith("/mailboxSettings"):
            user_id = path.split("/")[2]
            response = self._mailbox_settings.get(user_id, {})
            if isinstance(response, Exception):
                raise response
            return response
        raise AssertionError(f"unexpected path: {path}")


def test_collector_flags_external_forwarding_rule() -> None:
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [
        {"id": "contoso.com", "isVerified": True, "isDefault": True},
        {"id": "contoso.onmicrosoft.com", "isVerified": True, "isDefault": False},
    ]
    rules = {
        "u1": [
            {
                "id": "rule-1",
                "displayName": "Forward to external",
                "isEnabled": True,
                "actions": {
                    "forwardTo": [
                        {"emailAddress": {"address": "attacker@evil.example", "name": "attacker"}}
                    ]
                },
                "conditions": {},
            }
        ]
    }
    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    assert result.status == "ok"
    rules_payload = result.payload["messageRules"]["value"]
    assert len(rules_payload) == 1
    rule = rules_payload[0]
    assert rule["forwards_externally"] is True
    assert rule["external_recipients"] == ["attacker@evil.example"]


def test_collector_classifies_internal_only_forwarding() -> None:
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [
        {"id": "contoso.com", "isVerified": True, "isDefault": True},
    ]
    rules = {
        "u1": [
            {
                "id": "rule-1",
                "displayName": "Forward internally",
                "isEnabled": True,
                "actions": {
                    "forwardTo": [
                        {"emailAddress": {"address": "bob@contoso.com"}}
                    ]
                },
                "conditions": {},
            }
        ]
    }
    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    rule = result.payload["messageRules"]["value"][0]
    assert rule["forwards_externally"] is False
    assert rule["external_recipients"] == []
    assert rule["forwards_internally"] is True


def test_collector_detects_hide_from_user_pattern() -> None:
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": True}]
    rules = {
        "u1": [
            {
                "id": "rule-1",
                "displayName": ".",
                "isEnabled": True,
                "actions": {
                    "moveToFolder": "RSS Feeds",
                    "delete": True,
                },
                "conditions": {
                    "subjectContains": ["invoice", "payment", "wire"],
                },
            }
        ]
    }
    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    rule = result.payload["messageRules"]["value"][0]
    assert rule["hide_from_user"] is True


def test_collector_records_mailbox_forwarding_settings() -> None:
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": True}]
    settings = {
        "u1": {
            "automaticRepliesSetting": {"status": "disabled"},
            "delegateMeetingMessageDeliveryOptions": "sendToDelegateAndInformationToPrincipal",
        }
    }
    collector = MailboxForwardingCollector()
    result = collector.run(
        {
            "client": _FakeClient(users, domains, inbox_rules={"u1": []}, mailbox_settings=settings),
            "top": 100,
        }
    )

    forwarding = result.payload["mailboxSettings"]["value"]
    assert forwarding[0]["user_id"] == "u1"


def test_collector_skips_users_without_mail() -> None:
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": None, "accountEnabled": True},
        {"id": "u2", "userPrincipalName": "bob@contoso.com", "mail": "bob@contoso.com", "accountEnabled": True},
    ]
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": True}]
    rules = {"u2": []}
    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    coverage = result.coverage or []
    assert any(row["name"] == "messageRules:u2" for row in coverage)
    assert all(row["name"] != "messageRules:u1" for row in coverage)


def test_collector_records_per_user_403_in_coverage() -> None:
    from azure_tenant_audit.graph import GraphError

    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": True}]
    rules = {"u1": GraphError("forbidden", status=403, request="/users/u1/mailFolders/inbox/messageRules")}

    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    assert result.status == "partial"
    coverage = result.coverage or []
    assert any(
        row["status"] == "failed" and row["error_class"] == "insufficient_permissions"
        for row in coverage
    )


# ----- A4: forwarding-action coverage + casing + display-name + shared mailbox -----


def test_collector_classifies_forward_as_attachment_to_external() -> None:
    """``forwardAsAttachmentTo`` is the sneaky cousin — historically used to attach
    sensitive mail as a forwarded attachment to bypass content filters."""
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": True}]
    rules = {
        "u1": [
            {
                "id": "rule-1",
                "displayName": "Stash via attachment",
                "isEnabled": True,
                "actions": {
                    "forwardAsAttachmentTo": [
                        {"emailAddress": {"address": "exfil@evil.example"}}
                    ]
                },
                "conditions": {},
            }
        ]
    }
    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    rule = result.payload["messageRules"]["value"][0]
    assert rule["forwards_externally"] is True
    assert rule["external_recipients"] == ["exfil@evil.example"]


def test_collector_classifies_redirect_to_external() -> None:
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": True}]
    rules = {
        "u1": [
            {
                "id": "rule-1",
                "displayName": "Redirect",
                "isEnabled": True,
                "actions": {
                    "redirectTo": [
                        {"emailAddress": {"address": "out@evil.example"}}
                    ]
                },
                "conditions": {},
            }
        ]
    }
    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    rule = result.payload["messageRules"]["value"][0]
    assert rule["forwards_externally"] is True
    assert rule["external_recipients"] == ["out@evil.example"]


def test_collector_internal_forwarding_tolerant_of_address_casing() -> None:
    """``Alice@CONTOSO.COM`` is internal even though ``contoso.com`` is the verified domain."""
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": True}]
    rules = {
        "u1": [
            {
                "id": "rule-1",
                "displayName": "Forward",
                "isEnabled": True,
                "actions": {
                    "forwardTo": [
                        {"emailAddress": {"address": "Bob@CONTOSO.COM"}}
                    ]
                },
                "conditions": {},
            }
        ]
    }
    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    rule = result.payload["messageRules"]["value"][0]
    assert rule["forwards_internally"] is True
    assert rule["forwards_externally"] is False
    assert rule["internal_recipients"] == ["bob@contoso.com"]


def test_collector_extracts_address_from_display_name_brackets() -> None:
    """Defensive: if Graph ever returns the ``"Alice" <alice@contoso.com>`` form, we
    must still extract the SMTP and classify correctly."""
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": True}]
    rules = {
        "u1": [
            {
                "id": "rule-1",
                "displayName": "Forward",
                "isEnabled": True,
                "actions": {
                    "forwardTo": [
                        {"emailAddress": {"address": '"Carol" <carol@contoso.com>'}}
                    ]
                },
                "conditions": {},
            }
        ]
    }
    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    rule = result.payload["messageRules"]["value"][0]
    assert rule["internal_recipients"] == ["carol@contoso.com"]


def test_collector_classifies_mixed_internal_and_external_recipients() -> None:
    users = [
        {"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}
    ]
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": True}]
    rules = {
        "u1": [
            {
                "id": "rule-1",
                "displayName": "Forward to many",
                "isEnabled": True,
                "actions": {
                    "forwardTo": [
                        {"emailAddress": {"address": "bob@contoso.com"}},
                        {"emailAddress": {"address": "exfil@evil.example"}},
                    ]
                },
                "conditions": {},
            }
        ]
    }
    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    rule = result.payload["messageRules"]["value"][0]
    assert rule["forwards_externally"] is True
    assert rule["forwards_internally"] is True
    assert rule["external_recipients"] == ["exfil@evil.example"]
    assert rule["internal_recipients"] == ["bob@contoso.com"]


def test_collector_processes_shared_mailbox_inbox_rules() -> None:
    """Shared mailboxes (``accountEnabled=False``) still expose inbox rules to a
    delegate; the collector must not skip them."""
    users = [
        {
            "id": "u-shared",
            "userPrincipalName": "support@contoso.com",
            "mail": "support@contoso.com",
            "accountEnabled": False,
            "userType": "Member",
        },
    ]
    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": True}]
    rules = {
        "u-shared": [
            {
                "id": "rule-1",
                "displayName": "Cover-up",
                "isEnabled": True,
                "actions": {
                    "forwardTo": [
                        {"emailAddress": {"address": "exfil@evil.example"}}
                    ]
                },
                "conditions": {},
            }
        ]
    }
    collector = MailboxForwardingCollector()
    result = collector.run({"client": _FakeClient(users, domains, rules), "top": 100})

    rules_payload = result.payload["messageRules"]["value"]
    assert len(rules_payload) == 1
    assert rules_payload[0]["forwards_externally"] is True
    assert rules_payload[0]["user_principal_name"] == "support@contoso.com"


def test_extract_smtp_helper_normalises_inputs() -> None:
    from azure_tenant_audit.collectors.mailbox_forwarding import _extract_smtp

    assert _extract_smtp("alice@contoso.com") == "alice@contoso.com"
    assert _extract_smtp("Alice@CONTOSO.com") == "alice@contoso.com"
    assert _extract_smtp('"Alice" <alice@contoso.com>') == "alice@contoso.com"
    assert _extract_smtp("  bob@contoso.com  ") == "bob@contoso.com"
    assert _extract_smtp("mailto:carol@contoso.com") == "carol@contoso.com"
    assert _extract_smtp("not-an-email") == ""
    assert _extract_smtp(None) == ""
    assert _extract_smtp("") == ""


_HIDDEN_RSS_ID = "AAMkADhmHIDDENRSS000AAA="


class _FolderClient(_FakeClient):
    """Folder metadata reads by ``$batch``; the top-level list follows Graph and leaves out hidden folders unless asked."""

    def __init__(self, rules: dict[str, Any], *, top_level_body: Any = None) -> None:
        super().__init__(
            [{"id": "u1", "userPrincipalName": "alice@contoso.com", "mail": "alice@contoso.com", "accountEnabled": True}],
            [{"id": "contoso.com", "isVerified": True, "isDefault": True}],
            rules,
        )
        self._top_level_body = top_level_body
        self.batches: list[list[dict[str, Any]]] = []

    def get_batch(self, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        self.batches.append(requests)
        answers: list[dict[str, Any]] = []
        for spec in requests:
            if spec["path"].endswith("/mailFolders"):
                if self._top_level_body is not None:
                    answers.append({"status": 200, "body": self._top_level_body})
                    continue
                folders = [{"id": "AAMkADhmINBOX", "displayName": "Inbox"}]
                if spec["params"].get("includeHiddenFolders") == "true":
                    folders.append({"id": _HIDDEN_RSS_ID, "displayName": "RSS Feeds", "isHidden": True})
                answers.append({"status": 200, "body": {"value": folders}})
            else:
                answers.append({"status": 404, "body": {"error": {"code": "ErrorItemNotFound"}}})
        return answers


def _move_rule(folder_id: str) -> dict[str, Any]:
    return {"id": "r-move", "displayName": ".", "isEnabled": True, "conditions": {},
            "actions": {"moveToFolder": folder_id, "markAsRead": True}}


def test_a_move_to_a_hidden_rss_folder_hides_from_user() -> None:
    client = _FolderClient({"u1": [_move_rule(_HIDDEN_RSS_ID)]})
    result = MailboxForwardingCollector().run({"client": client, "top": 100})

    rule = result.payload["messageRules"]["value"][0]
    assert rule["hide_from_user"] is True
    top_level = client.batches[0][0]
    assert top_level["params"]["$select"] == "id,displayName"
    assert not any("/messages" in spec["path"] for batch in client.batches for spec in batch)


def test_a_malformed_top_level_folder_answer_leaves_the_move_rule_unknown() -> None:
    for body in ({"value": None}, {}):
        client = _FolderClient({"u1": [_move_rule(_HIDDEN_RSS_ID)]}, top_level_body=body)
        result = MailboxForwardingCollector().run({"client": client, "top": 100})

        rule = result.payload["messageRules"]["value"][0]
        assert rule["hide_from_user"] is None, body
        assert rule["hide_from_user_state"] == "unknown", body
        folders = [row for row in result.coverage if row["name"] == "mailFolders:u1"]
        assert folders and folders[0]["status"] == "failed", body
        assert result.status == "partial", body


def test_an_empty_top_level_folder_list_still_resolves_the_move_rule() -> None:
    client = _FolderClient({"u1": [_move_rule(_HIDDEN_RSS_ID)]}, top_level_body={"value": []})
    result = MailboxForwardingCollector().run({"client": client, "top": 100})

    rule = result.payload["messageRules"]["value"][0]
    assert rule["hide_from_user"] is False
    assert rule["hide_from_user_state"] == "resolved"
