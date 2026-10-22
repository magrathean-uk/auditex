"""Drop user-authored mailbox text before it reaches raw or normalized output.

Gmail vacation-responder text, Gmail send-as signatures and Microsoft Graph automatic-reply
message bodies are written by the mailbox owner and are mailbox content in all but name. The
findings read only the booleans around them, so only whether a field is set and how long it is
leave the collectors: each dropped field ``f`` becomes ``fLength`` (an integer) and ``hasF`` (a
boolean).

These functions run on live collection, on the offline replay path (the normalizers) and in the
bundle writer, so the statement holds however a bundle was produced. They never mutate their
input and are idempotent.
"""
from __future__ import annotations

from typing import Any

VACATION_TEXT_FIELDS = ("responseSubject", "responseBodyPlainText", "responseBodyHtml")
SEND_AS_TEXT_FIELDS = ("signature",)
AUTO_REPLY_TEXT_FIELDS = ("internalReplyMessage", "externalReplyMessage")


def strip_text_fields(item: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Copy of ``item`` with each text field replaced by ``<field>Length`` and ``has<Field>``.

    A field that is already gone (or never present) leaves any existing length untouched.
    """
    result = dict(item)
    for name in fields:
        if name not in result:
            continue
        value = result.pop(name)
        length = len(value) if isinstance(value, str) else 0
        result.setdefault(f"{name}Length", length)
        result.setdefault(f"has{name[0].upper()}{name[1:]}", length > 0)
    return result


def minimise_gmail_settings(payload: dict[str, Any]) -> dict[str, Any]:
    """Gmail settings for one user without vacation-responder or signature text."""
    result = dict(payload)
    vacation = result.get("vacation")
    if isinstance(vacation, dict):
        result["vacation"] = strip_text_fields(vacation, VACATION_TEXT_FIELDS)
    send_as = result.get("sendAs")
    if isinstance(send_as, list):
        result["sendAs"] = [
            strip_text_fields(item, SEND_AS_TEXT_FIELDS) if isinstance(item, dict) else item for item in send_as
        ]
    return result


def minimise_mailbox_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Graph mailbox settings without the automatic-reply message bodies."""
    result = dict(settings)
    auto_reply = result.get("automaticRepliesSetting")
    if isinstance(auto_reply, dict):
        result["automaticRepliesSetting"] = strip_text_fields(auto_reply, AUTO_REPLY_TEXT_FIELDS)
    return result


def minimise_user_text(value: Any) -> Any:
    """Copy of any JSON-shaped value with the mailbox text fields removed wherever they appear.

    Keyed on the shape of the data, so it covers a payload whatever collector or replay fixture
    produced it: a ``vacation`` object or any object with ``enableAutoReply``; an object with
    ``sendAsEmail`` (a Gmail send-as entry); any object with an automatic-reply message field.
    """
    if isinstance(value, list):
        return [minimise_user_text(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {key: minimise_user_text(item) for key, item in value.items()}
    if "enableAutoReply" in result:
        result = strip_text_fields(result, VACATION_TEXT_FIELDS)
    if isinstance(result.get("vacation"), dict):
        result["vacation"] = strip_text_fields(result["vacation"], VACATION_TEXT_FIELDS)
    if "sendAsEmail" in result:
        result = strip_text_fields(result, SEND_AS_TEXT_FIELDS)
    if any(name in result for name in AUTO_REPLY_TEXT_FIELDS):
        result = strip_text_fields(result, AUTO_REPLY_TEXT_FIELDS)
    return result
