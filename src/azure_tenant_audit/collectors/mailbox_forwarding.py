"""Collector for mailbox forwarding settings and inbox rules.

Targets the #1 BEC indicator: rules that forward to external recipients or
hide messages from the user (move to RSS Feeds, Junk, or Deleted Items with a
broad subject filter). Reads via Microsoft Graph so a Global Reader / Global
Admin with `MailboxSettings.Read` can audit a tenant without Exchange Online
PowerShell. Message content is never read, so `Mail.Read` is not requested. Rule move targets are folder IDs,
resolved from folder metadata with the optional `MailboxFolder.Read.All`. Auto-reply message
bodies come back with mailboxSettings and are dropped before they reach raw or normalized output.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from typing import Any

from ..data_minimisation import minimise_mailbox_settings
from ..graph import GraphClient, GraphError
from .base import Collector, CollectorResult, _classify_graph_error

_USER_SELECT = "id,userPrincipalName,mail,accountEnabled,userType"
_HIDE_FROM_USER_FOLDERS = {
    "rss feeds",
    "rss subscriptions",
    "junk email",
    "junk e-mail",
    "deleted items",
    "archive",
    "conversation history",
}
# Well-known folder names Graph resolves in any mailbox language (R006). RSS Feeds has none, so it is matched by its
# display name in the top-level folder list.
_HIDE_FROM_USER_WELL_KNOWN = ("junkemail", "deleteditems", "archive", "conversationhistory")


class MailboxForwardingCollector(Collector):
    name = "mailbox_forwarding"
    description = "Mailbox forwarding settings and inbox rules per licensed user."
    required_permissions = [
        "User.Read.All",
        "MailboxSettings.Read",
    ]
    # Folder metadata for inbox-rule move targets (R006); without it those rules read unknown, never clean.
    optional_permissions = ["MailboxFolder.Read.All"]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient | None = context.get("client")
        log_event: Callable[[str, str, dict[str, Any] | None], None] | None = context.get("audit_logger")
        coverage: list[dict[str, Any]] = []
        payload: dict[str, Any] = {
            "messageRules": {"value": []},
            "mailboxSettings": {"value": []},
        }

        users = self._fetch_users(client, coverage, log_event)
        accepted_domains = self._fetch_accepted_domains(client, coverage, log_event)

        all_rules: list[dict[str, Any]] = []
        all_settings: list[dict[str, Any]] = []
        folder_refusal: dict[str, Any] | None = None
        for user in users:
            mail = user.get("mail")
            user_id = user.get("id")
            if not user_id or not mail:
                continue
            if str(user.get("userType") or "").strip().lower() == "guest":
                # A B2B guest's mail is its home address: it has no mailbox in this tenant to read (R046).
                continue
            user_rules, rules_status = self._fetch_inbox_rules(
                client, user_id, log_event=log_event
            )
            coverage.append(rules_status)
            # Graph returns moveToFolder as a folder ID, so the user's hide-from-user folders are resolved to IDs,
            # but only when a rule moves mail somewhere a display name does not already settle.
            hide_folder_ids: set[str] | None = set()
            if any(_needs_folder_resolution(rule) for rule in user_rules):
                if folder_refusal is not None:
                    # The folder read was already refused for the run's credential: later users' move rules stay
                    # unknown on that one gap row instead of sending the same refused read per user.
                    hide_folder_ids = None
                    folder_refusal["unresolved_user_count"] += 1
                else:
                    hide_folder_ids, folders_status = self._resolve_hide_folders(client, user_id)
                    coverage.append(folders_status)
                    if folders_status.get("error_class") in _FOLDER_REFUSAL_CLASSES:
                        folder_refusal = folders_status
            for rule in user_rules:
                classified = _classify_message_rule(rule, user, accepted_domains, hide_folder_ids)
                all_rules.append(classified)

            if rules_status.get("reason") == NO_MAILBOX:
                # The rules read already showed there is no mailbox; its settings are not requested.
                user_settings, settings_status = None, {
                    **rules_status, "name": f"mailboxSettings:{user_id}", "endpoint": f"/users/{user_id}/mailboxSettings",
                    "duration_ms": 0.0,
                }
            else:
                user_settings, settings_status = self._fetch_mailbox_settings(client, user_id)
            if user_settings is not None:
                all_settings.append(
                    {
                        "user_id": user_id,
                        "user_principal_name": user.get("userPrincipalName"),
                        "settings": user_settings,
                    }
                )
            if settings_status is not None:
                coverage.append(settings_status)

        payload["messageRules"] = {"value": all_rules}
        payload["mailboxSettings"] = {"value": all_settings}

        # A user without a mailbox is a skipped row, not a failed read, so it does not make the collection partial.
        partial = any(row.get("status") not in {"ok", "skipped"} for row in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=len(all_rules) + len(all_settings),
            message="Mailbox forwarding collection partially completed" if partial else "",
            coverage=coverage,
        )

    def _fetch_users(
        self,
        client: GraphClient | None,
        coverage: list[dict[str, Any]],
        log_event: Callable[[str, str, dict[str, Any] | None], None] | None,
    ) -> list[dict[str, Any]]:
        start = time.perf_counter()
        users: list[dict[str, Any]] = []
        status = "ok"
        error_class: str | None = None
        error: str | None = None
        try:
            if client is None or not hasattr(client, "get_all"):
                raise GraphError("graph client unavailable", request="/users")
            raw = client.get_all("/users", params={"$select": _USER_SELECT})
            if isinstance(raw, list):
                users = [item for item in raw if isinstance(item, dict)]
        except Exception as exc:  # noqa: BLE001
            status = "failed"
            error_class, error = _classify_graph_error(exc)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        coverage.append(
            {
                "collector": self.name,
                "type": "graph",
                "name": "users",
                "endpoint": "/users",
                "status": status,
                "item_count": len(users),
                "duration_ms": duration_ms,
                "error_class": error_class,
                "error": error,
            }
        )
        if log_event:
            log_event(
                "collector.endpoint.finished",
                "Collector endpoint request completed",
                {
                    "collector": self.name,
                    "endpoint_name": "users",
                    "status": status,
                    "item_count": len(users),
                    "duration_ms": duration_ms,
                    "error_class": error_class,
                },
            )
        return users

    def _fetch_accepted_domains(
        self,
        client: GraphClient | None,
        coverage: list[dict[str, Any]],
        log_event: Callable[[str, str, dict[str, Any] | None], None] | None,
    ) -> set[str]:
        start = time.perf_counter()
        accepted: set[str] = set()
        status = "ok"
        error_class: str | None = None
        error: str | None = None
        try:
            if client is None or not hasattr(client, "get_all"):
                raise GraphError("graph client unavailable", request="/domains")
            raw = client.get_all("/domains", params={"$select": "id,isVerified"})
            if isinstance(raw, list):
                for domain in raw:
                    if isinstance(domain, dict) and domain.get("isVerified"):
                        domain_id = domain.get("id")
                        if isinstance(domain_id, str) and domain_id:
                            accepted.add(domain_id.lower())
        except Exception as exc:  # noqa: BLE001
            status = "failed"
            error_class, error = _classify_graph_error(exc)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        coverage.append(
            {
                "collector": self.name,
                "type": "graph",
                "name": "domains",
                "endpoint": "/domains",
                "status": status,
                "item_count": len(accepted),
                "duration_ms": duration_ms,
                "error_class": error_class,
                "error": error,
            }
        )
        if log_event:
            log_event(
                "collector.endpoint.finished",
                "Collector endpoint request completed",
                {
                    "collector": self.name,
                    "endpoint_name": "domains",
                    "status": status,
                    "item_count": len(accepted),
                    "duration_ms": duration_ms,
                    "error_class": error_class,
                },
            )
        return accepted

    def _fetch_inbox_rules(
        self,
        client: GraphClient | None,
        user_id: str,
        *,
        log_event: Callable[[str, str, dict[str, Any] | None], None] | None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        start = time.perf_counter()
        rules: list[dict[str, Any]] = []
        status = "ok"
        error_class: str | None = None
        error: str | None = None
        path = f"/users/{user_id}/mailFolders/inbox/messageRules"
        try:
            if client is None or not hasattr(client, "get_json"):
                raise GraphError("graph client unavailable", request=path)
            response = client.get_json(path)
            if isinstance(response, dict):
                values = response.get("value", [])
                if isinstance(values, list):
                    rules = [item for item in values if isinstance(item, dict)]
        except Exception as exc:  # noqa: BLE001
            status = "skipped" if _no_mailbox(exc) else "failed"
            if status == "failed":
                error_class, error = _classify_graph_error(exc)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        coverage_row = {
            "collector": self.name,
            "type": "graph",
            "name": f"messageRules:{user_id}",
            "endpoint": path,
            "status": status,
            "item_count": len(rules),
            "duration_ms": duration_ms,
            "error_class": error_class,
            "error": error,
        }
        if status == "skipped":
            coverage_row["reason"] = NO_MAILBOX
        if log_event:
            log_event(
                "collector.endpoint.finished",
                "Collector endpoint request completed",
                {
                    "collector": self.name,
                    "endpoint_name": f"messageRules:{user_id}",
                    "status": status,
                    "item_count": len(rules),
                    "duration_ms": duration_ms,
                    "error_class": error_class,
                },
            )
        return rules, coverage_row

    def _resolve_hide_folders(self, client: GraphClient | None, user_id: str) -> tuple[set[str] | None, dict[str, Any]]:
        """IDs of the user's hide-from-user folders, or None when they could not be read.

        Folder metadata only (``$select=id,displayName`` on the top-level list and ``$select=id`` on the well-known
        folders); no message is read. The reads go in one ``$batch``, so a refused folder read never counts toward the
        per-family permission stop that guards the user's other reads.
        """
        start = time.perf_counter()
        path = f"/users/{user_id}/mailFolders"
        ids: set[str] | None = set()
        error_class: str | None = None
        error: str | None = None
        try:
            if client is None or not hasattr(client, "get_batch"):
                raise GraphError("graph client unavailable", request=path)
            answers = client.get_batch(
                [{"path": path, "params": {"$select": "id,displayName", "$top": "100"}}]
                + [{"path": f"{path}/{name}", "params": {"$select": "id"}} for name in _HIDE_FROM_USER_WELL_KNOWN]
            )
            if not isinstance(answers, list) or len(answers) != 1 + len(_HIDE_FROM_USER_WELL_KNOWN):
                raise GraphError("folder lookup answer incomplete", request=path)
            for index, answer in enumerate(answers):
                status = answer.get("status") if isinstance(answer, dict) else None
                body = answer.get("body") if isinstance(answer, dict) else None
                if status == 200 and isinstance(body, dict) and index == 0:
                    folders = body.get("value") if isinstance(body.get("value"), list) else []
                    next_link = body.get("@odata.nextLink")
                    if isinstance(next_link, str) and next_link:
                        folders = folders + list(client.iter_items(next_link))
                    for folder in folders:
                        if isinstance(folder, dict) and str(folder.get("displayName") or "").strip().lower() in _HIDE_FROM_USER_FOLDERS:
                            ids.add(str(folder.get("id") or ""))
                elif status == 200 and isinstance(body, dict) and body.get("id"):
                    ids.add(str(body["id"]))
                elif not (status == 404 and index > 0):  # 404: the mailbox has no such folder (an archive is optional)
                    raise GraphError(
                        str((answer or {}).get("error") or "mail folder not read"),
                        status=status if isinstance(status, int) else None,
                        error_code=(answer or {}).get("error_code"),
                        request=path,
                    )
            ids.discard("")
        except Exception as exc:  # noqa: BLE001
            ids = None
            error_class, error = _classify_graph_error(exc)
        row: dict[str, Any] = {
            "collector": self.name,
            "type": "graph",
            "name": f"mailFolders:{user_id}",
            "endpoint": path,
            "status": "ok" if ids is not None else "failed",
            "item_count": len(ids or ()),
            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            "error_class": error_class,
            "error": error,
        }
        if ids is None:
            row["unresolved_user_count"] = 1
        return ids, row

    def _fetch_mailbox_settings(
        self,
        client: GraphClient | None,
        user_id: str,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        if client is None or not hasattr(client, "get_json"):
            return None, None
        path = f"/users/{user_id}/mailboxSettings"
        start = time.perf_counter()
        try:
            response = client.get_json(path)
        except Exception as exc:  # noqa: BLE001
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            if _no_mailbox(exc):
                return None, {
                    "collector": self.name,
                    "type": "graph",
                    "name": f"mailboxSettings:{user_id}",
                    "endpoint": path,
                    "status": "skipped",
                    "reason": NO_MAILBOX,
                    "item_count": 0,
                    "duration_ms": duration_ms,
                    "error_class": None,
                    "error": None,
                }
            error_class, error = _classify_graph_error(exc)
            return None, {
                "collector": self.name,
                "type": "graph",
                "name": f"mailboxSettings:{user_id}",
                "endpoint": path,
                "status": "failed",
                "item_count": 0,
                "duration_ms": duration_ms,
                "error_class": error_class,
                "error": error,
            }
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        if not isinstance(response, dict):
            response = {}
        return minimise_mailbox_settings(response), {
            "collector": self.name,
            "type": "graph",
            "name": f"mailboxSettings:{user_id}",
            "endpoint": path,
            "status": "ok",
            "item_count": 1,
            "duration_ms": duration_ms,
            "error_class": None,
            "error": None,
        }


NO_MAILBOX = "no_mailbox"
# A folder read refused for the run's credential (the mail-folder permission is not granted): it is not retried per user.
_FOLDER_REFUSAL_CLASSES = frozenset({"insufficient_permissions", "unauthenticated", "permission_stop"})
_NO_MAILBOX_CODES = frozenset({"mailboxnotenabledforrestapi", "errornonexistentmailbox"})


def _no_mailbox(exc: Exception) -> bool:
    """Graph's answer for a mail-enabled user with no Exchange Online mailbox (a 404 with a named code)."""
    return (
        isinstance(exc, GraphError)
        and exc.status == 404
        and str(exc.error_code or "").lower() in _NO_MAILBOX_CODES
    )


def _needs_folder_resolution(rule: dict[str, Any]) -> bool:
    actions = rule.get("actions") if isinstance(rule, dict) else None
    if not isinstance(actions, dict):
        return False
    target = str(actions.get("moveToFolder") or "").strip().lower()
    return bool(target) and target not in _HIDE_FROM_USER_FOLDERS and not target.endswith(":\\rss feeds")


def _classify_message_rule(
    rule: dict[str, Any],
    user: dict[str, Any],
    accepted_domains: Iterable[str],
    hide_folder_ids: set[str] | None = frozenset(),
) -> dict[str, Any]:
    accepted_set = {item.lower() for item in accepted_domains}
    actions = rule.get("actions") or {}
    conditions = rule.get("conditions") or {}

    forwards_to: list[str] = []
    for action_key in ("forwardTo", "forwardAsAttachmentTo", "redirectTo"):
        for entry in actions.get(action_key, []) or []:
            if not isinstance(entry, dict):
                continue
            email = _extract_smtp((entry.get("emailAddress") or {}).get("address"))
            # Fall back to ``name`` if Graph stuffed the angle-bracket form there.
            if not email:
                email = _extract_smtp((entry.get("emailAddress") or {}).get("name"))
            if email:
                forwards_to.append(email)

    external_recipients = [
        address for address in forwards_to if not _is_accepted_address(address, accepted_set)
    ]
    internal_recipients = [
        address for address in forwards_to if _is_accepted_address(address, accepted_set)
    ]

    move_target = str(actions.get("moveToFolder") or "").strip().lower()
    delete_action = bool(actions.get("delete") or actions.get("permanentDelete"))
    hide_from_user = (
        move_target in _HIDE_FROM_USER_FOLDERS
        or delete_action
        or move_target.endswith(":\\rss feeds")
    )
    if hide_from_user:
        broad_filter = _is_broad_filter(conditions)
        if not broad_filter and move_target not in _HIDE_FROM_USER_FOLDERS and not delete_action:
            hide_from_user = False
    hide_state = "resolved"
    if not hide_from_user and _needs_folder_resolution(rule):
        if hide_folder_ids is None:
            # The folder ID could not be resolved: the rule is not reported as clean (R006).
            hide_from_user, hide_state = None, "unknown"
        elif str(actions.get("moveToFolder")).strip() in hide_folder_ids:
            hide_from_user = True

    return {
        "rule_id": str(rule.get("id") or ""),
        "user_id": user.get("id"),
        "user_principal_name": user.get("userPrincipalName"),
        "user_mail": user.get("mail"),
        "display_name": rule.get("displayName"),
        "is_enabled": bool(rule.get("isEnabled", False)),
        "sequence": rule.get("sequence"),
        "actions": actions,
        "conditions": conditions,
        "forwards_to": forwards_to,
        "forwards_externally": bool(external_recipients),
        "forwards_internally": bool(internal_recipients),
        "external_recipients": sorted(external_recipients),
        "internal_recipients": sorted(internal_recipients),
        "move_to_folder": actions.get("moveToFolder"),
        "delete_action": delete_action,
        "hide_from_user": hide_from_user,
        "hide_from_user_state": hide_state,
    }


def _is_accepted_address(address: str, accepted: set[str]) -> bool:
    if "@" not in address:
        return False
    domain = address.rsplit("@", 1)[-1].lower()
    return domain in accepted


def _extract_smtp(raw: Any) -> str:
    """Best-effort extraction of an SMTP address from a Graph emailAddress payload.

    Tolerates:
    - ``"Alice" <alice@example.com>`` display-name form
    - bare SMTP with surrounding whitespace
    - mixed case (lowercased on return so accepted-domain comparison is stable)
    - ``None`` and non-string inputs

    Returns an empty string when no SMTP-like substring is found.
    """
    if not isinstance(raw, str):
        return ""
    text = raw.strip()
    if not text:
        return ""
    if "<" in text and ">" in text:
        start = text.rfind("<")
        end = text.rfind(">")
        if start < end:
            text = text[start + 1 : end].strip()
    # Strip a possible "mailto:" scheme before validating.
    if text.lower().startswith("mailto:"):
        text = text[len("mailto:") :].strip()
    if "@" not in text:
        return ""
    return text.lower()


def _is_broad_filter(conditions: dict[str, Any]) -> bool:
    if not isinstance(conditions, dict) or not conditions:
        return True
    interesting = ("subjectContains", "bodyContains", "fromAddresses", "senderContains")
    for key in interesting:
        value = conditions.get(key)
        if isinstance(value, list) and any(isinstance(token, str) and token.strip() for token in value):
            return False
    return True
