"""Drop user-authored mailbox text before it reaches raw or normalized output.

Gmail vacation-responder text, Gmail send-as signatures and Microsoft Graph automatic-reply
message bodies are written by the mailbox owner and are mailbox content in all but name. The
findings read only the booleans around them, so only whether a field is set and how long it is
leave the collectors: each dropped field ``f`` becomes ``fLength`` (an integer) and ``hasF`` (a
boolean).

The words an owner chose for an inbox rule (``subjectContains``, ``bodyContains`` and the like) or a
Gmail filter (``query``, ``negatedQuery``, ``subject``) say what the owner expects to find in mail
bodies and subjects. No rule reads them (broadness is decided where the rule is read), so each list
becomes ``fCount`` and ``hasF``, each string ``fLength`` and ``hasF``. Address lists such as
``fromAddresses`` stay: forwarding classification needs them. A responder who needs the keywords of
a suspect rule goes back to the tenant for them.

These functions run on live collection, on the offline replay path (the normalizers) and in the
bundle writer, so the statement holds however a bundle was produced. Intune custom-profile records (``/deviceManagement/deviceConfigurations``) carry ``payload``, the
base64 ``.mobileconfig`` bytes an admin uploaded. No rule or finding reads it, nor the ``payloadName``
and ``payloadFileName`` labels, so ``payload`` becomes ``payloadLength`` and ``hasPayload`` and the two
labels are dropped, from every record of the section and before any chunk callback sees the rows
(``minimise_device_configurations``).

They never mutate their
input and are idempotent.
"""
from __future__ import annotations

from typing import Any

VACATION_TEXT_FIELDS = ("responseSubject", "responseBodyPlainText", "responseBodyHtml")
SEND_AS_TEXT_FIELDS = ("signature",)
AUTO_REPLY_TEXT_FIELDS = ("internalReplyMessage", "externalReplyMessage")
# Graph messageRule predicates holding words the owner chose (arrays of strings); the address predicates stay.
RULE_CONDITION_WORD_FIELDS = (
    "subjectContains",
    "bodyContains",
    "bodyOrSubjectContains",
    "headerContains",
    "senderContains",
    "recipientContains",
)
GMAIL_FILTER_TEXT_FIELDS = ("query", "negatedQuery", "subject")
DEVICE_CONFIGURATION_PAYLOAD_FIELDS = ("payload",)
DEVICE_CONFIGURATION_LABEL_FIELDS = ("payloadName", "payloadFileName")
DEVICE_CONFIGURATION_SECTION_KEYS = ("deviceConfigurations", "deviceConfigurationProfiles")


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


def strip_word_lists(item: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Copy of ``item`` with each list of owner-chosen words replaced by ``<field>Count`` and ``has<Field>``."""
    result = dict(item)
    for name in fields:
        if name not in result:
            continue
        value = result.pop(name)
        if isinstance(value, list):
            count = sum(1 for word in value if isinstance(word, str) and word.strip())
        else:
            count = 1 if isinstance(value, str) and value.strip() else 0
        result.setdefault(f"{name}Count", count)
        result.setdefault(f"has{name[0].upper()}{name[1:]}", count > 0)
    return result


def _strip_custom_profile(item: dict[str, Any]) -> dict[str, Any]:
    result = strip_text_fields(item, DEVICE_CONFIGURATION_PAYLOAD_FIELDS)
    for name in DEVICE_CONFIGURATION_LABEL_FIELDS:
        result.pop(name, None)
    return result


def _is_custom_profile(item: dict[str, Any]) -> bool:
    odata_type = item.get("@odata.type")
    return "payload" in item and (
        "payloadFileName" in item
        or "payloadName" in item
        or (isinstance(odata_type, str) and odata_type.lower().endswith("customconfiguration"))
    )


def minimise_device_configurations(value: Any) -> Any:
    """Copy of an Intune deviceConfigurations section (or any nesting of it) without custom-profile payload.

    Inside the known deviceConfigurations boundary every ``payload`` is removed, whatever optional hints the
    record carries, along with the ``payloadName`` and ``payloadFileName`` labels, at any position (``value``
    rows, accumulator samples, chunk rows).
    """
    if isinstance(value, list):
        return [minimise_device_configurations(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {key: minimise_device_configurations(item) for key, item in value.items()}
    if "payload" in result or any(name in result for name in DEVICE_CONFIGURATION_LABEL_FIELDS):
        result = _strip_custom_profile(result)
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
    if _is_custom_profile(result):
        result = _strip_custom_profile(result)
    for section in DEVICE_CONFIGURATION_SECTION_KEYS:
        if isinstance(result.get(section), (dict, list)):
            result[section] = minimise_device_configurations(result[section])
    if isinstance(result.get("conditions"), dict) and isinstance(result.get("actions"), dict):
        # A Graph inbox rule: the words it matches on are the owner's, the actions and addresses are what is judged.
        result["conditions"] = strip_word_lists(result["conditions"], RULE_CONDITION_WORD_FIELDS)
    if isinstance(result.get("criteria"), dict) and isinstance(result.get("action"), dict):
        # A Gmail filter: its search terms are the owner's; the forward target and labels are what is judged.
        result["criteria"] = strip_text_fields(result["criteria"], GMAIL_FILTER_TEXT_FIELDS)
    return result


class _MinimisingChunkWriter:
    """Chunk callback that minimises one section's rows and forwards rollback to the wrapped writer."""

    def __init__(self, chunk_writer: Any, section_key: str) -> None:
        self._chunk_writer = chunk_writer
        self._section_key = section_key

    def __call__(self, collector: Any, key: Any, page_number: Any, rows: Any, meta: Any) -> Any:
        if key == self._section_key:
            rows = minimise_device_configurations(rows)
        return self._chunk_writer(collector, key, page_number, rows, meta)

    def __getattr__(self, name: str) -> Any:
        # Everything else, notably ``discard`` for a withheld section, is the wrapped writer's own behaviour.
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self._chunk_writer, name)


def minimising_chunk_writer(chunk_writer: Any, section_key: str) -> Any:
    """Wrap a chunk callback so rows of the deviceConfigurations section are minimised before it sees them.

    The wrapper keeps the wrapped writer's other attributes, so a safety stop can still roll back stored chunks
    through ``discard``; a writer without ``discard`` stays without it.
    """
    if chunk_writer is None:
        return None
    return _MinimisingChunkWriter(chunk_writer, section_key)
