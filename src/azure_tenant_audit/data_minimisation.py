"""Drop user-authored mailbox text before it reaches raw or normalized output.

Gmail vacation-responder text, Gmail send-as signatures and Microsoft Graph automatic-reply
message bodies are written by the mailbox owner and are mailbox content in all but name. The
findings read only the booleans around them, so only whether a field is set and how long it is
leave the collectors for the Graph reply bodies: each dropped field ``f`` becomes ``fLength`` (an integer)
and ``hasF`` (a boolean). The Gmail fields are excluded at request level (DEC-012, ``fields`` masks in
``google_workspace/client.py``) and these functions only drop them, leaving no length or flag behind.

The words an owner chose for an inbox rule (``subjectContains``, ``bodyContains`` and the like) or a
Gmail filter (``query``, ``negatedQuery``, ``subject``) say what the owner expects to find in mail
bodies and subjects. No rule reads them. Graph word lists become ``fCount`` and ``hasF``; Gmail filter
terms are dropped outright. Address lists such as
``fromAddresses`` stay: forwarding classification needs them. A responder who needs the keywords of
a suspect rule goes back to the tenant for them.

These functions run on live collection, on the offline replay path (the normalizers) and in the
bundle writer, so the statement holds however a bundle was produced. Intune custom-profile records (``/deviceManagement/deviceConfigurations``) carry ``payload``, the
base64 ``.mobileconfig`` bytes an admin uploaded. No rule or finding reads it, nor the ``payloadName``
and ``payloadFileName`` labels, so ``payload`` becomes ``payloadLength`` and ``hasPayload`` and the two
labels are dropped, from every record of the section and before any chunk callback sees the rows
(``minimise_device_configurations``).

Cloud Identity Policy API settings (``minimise_policy_settings``) are admin configuration, but a few Gmail
setting types carry address lists an admin typed in (``gmail.email_address_lists``) and free-text list
descriptions. No rule needs an address: each address list becomes its id, its entry count and its count of
domain-shaped entries (``^[^@]+\\.[^@]+$``, ScubaGoggles' own test), list names and descriptions are dropped,
and any other string in a setting value that holds an address is replaced by a constant. A list whose entries
cannot be read keeps ``None`` counts (unknown), never zero.

They never mutate their
input and are idempotent.
"""
from __future__ import annotations

import re
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


def strip_text_fields(item: dict[str, Any], fields: tuple[str, ...], *, keep_presence: bool = True) -> dict[str, Any]:
    """Copy of ``item`` with each text field removed.

    With ``keep_presence`` each is replaced by ``<field>Length`` and ``has<Field>``; without it nothing is
    left in its place (Gmail, DEC-012). A field that is already gone leaves any existing length untouched.
    """
    result = dict(item)
    for name in fields:
        if name not in result:
            continue
        value = result.pop(name)
        if not keep_presence:
            continue
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
        result["vacation"] = strip_text_fields(vacation, VACATION_TEXT_FIELDS, keep_presence=False)
    send_as = result.get("sendAs")
    if isinstance(send_as, list):
        result["sendAs"] = [
            strip_text_fields(item, SEND_AS_TEXT_FIELDS, keep_presence=False) if isinstance(item, dict) else item for item in send_as
        ]
    return result


# Policy API objects: the tenant's customer id and the opaque policy resource name are dropped from the
# SCuBA settings payload; neither is read by a rule.
POLICY_DROPPED_FIELDS = ("customer", "name")
# The containers of one Gmail address list's entries (an allow list or a block list).
POLICY_ADDRESS_LIST_KEYS = ("addressList", "blockedAddressList")
# Gmail setting types whose entries carry an admin-written description.
POLICY_DESCRIBED_LIST_TYPES = ("settings/gmail.blocked_sender_lists", "settings/gmail.spam_override_lists")
POLICY_ADDRESS_LISTS_TYPE = "settings/gmail.email_address_lists"
REDACTED_ADDRESS = "redacted:address"
REDACTED_PATH = "redacted:path"
_ADDRESS = re.compile(r"[^@\s]+@[^@\s]+")
_DOMAIN_ENTRY = re.compile(r"^[^@]+\.[^@]+$")
# An absolute local path anywhere in a string: POSIX (``/a/b``, ``~/a``), Windows drive or UNC, or a file URL.
_LOCAL_PATH = re.compile(r"(?:^|[\s\"'(=,;])(?:~?/[^/\s]+/|~/|[A-Za-z]:[\\/]|\\\\[^\\\s]+\\)|file:/", re.IGNORECASE)


def _scrub_addresses(value: Any) -> Any:
    """``value`` with every string (and mapping key) that holds an address or a local path replaced by a constant."""
    if isinstance(value, str):
        if _ADDRESS.search(value):
            return REDACTED_ADDRESS
        return REDACTED_PATH if _LOCAL_PATH.search(value) else value
    if isinstance(value, list):
        return [_scrub_addresses(item) for item in value]
    if not isinstance(value, dict):
        return value
    if any(key in value for key in POLICY_ADDRESS_LIST_KEYS):
        return _address_list_summary(value, keep_siblings=True)
    result: dict[str, Any] = {}
    for index, (key, item) in enumerate(value.items()):
        name = f"{REDACTED_ADDRESS}:{index}" if isinstance(key, str) and _ADDRESS.search(key) else key
        result[name] = _scrub_addresses(item)
    return result


def _address_entries(container: Any) -> list[str] | None:
    """The entries of one address-list container, or ``None`` when it cannot be read."""
    if not isinstance(container, dict) or any(key != "address" for key in container):
        # An unknown key may be the entries under a new name: unreadable, not empty. ``{}`` is an empty list
        # (proto3 JSON omits an empty repeated field).
        return None
    entries = container.get("address", [])
    if not isinstance(entries, list):
        return None
    texts: list[str] = []
    for entry in entries:
        text = entry.get("address") if isinstance(entry, dict) else entry
        if not isinstance(text, str) or not text.strip():
            # A blank entry is unreadable, not an entry that is or is not a domain.
            return None
        texts.append(text.strip())
    return texts


_SUMMARY_FIELDS = ("id", "name", "entry_count", "domain_entry_count", *POLICY_ADDRESS_LIST_KEYS)


def _address_list_summary(entry: dict[str, Any], *, keep_siblings: bool = False) -> dict[str, Any]:
    """One Gmail address list as ``{id, entry_count, domain_entry_count}``; unreadable entries give ``None`` counts.

    ``keep_siblings`` keeps the entry's other fields (scrubbed), for an address list met outside
    ``gmail.email_address_lists``; the list's name is dropped either way.
    """
    list_id = entry.get("id")
    id_readable = isinstance(list_id, str) and bool(list_id.strip()) and not _ADDRESS.search(list_id)
    summary: dict[str, Any] = {"id": _scrub_addresses(list_id) if isinstance(list_id, (str, int)) else None}
    if keep_siblings:
        for index, (key, item) in enumerate(entry.items()):
            if key not in _SUMMARY_FIELDS:
                name = f"{REDACTED_ADDRESS}:{index}" if isinstance(key, str) and _ADDRESS.search(key) else key
                summary[name] = _scrub_addresses(item)
    elif not id_readable:
        # A list of ``gmail.email_address_lists`` is referenced by its id: without one its counts mean nothing.
        summary.update(id=None, entry_count=None, domain_entry_count=None)
        return summary
    if "entry_count" in entry and not any(key in entry for key in POLICY_ADDRESS_LIST_KEYS):
        # Already minimised: keep the counts only when they are consistent counts, else both are unknown.
        total, domains = entry.get("entry_count"), entry.get("domain_entry_count")
        consistent = all(isinstance(count, int) and not isinstance(count, bool) and count >= 0 for count in (total, domains))
        consistent = consistent and domains <= total
        summary["entry_count"] = total if consistent else None
        summary["domain_entry_count"] = domains if consistent else None
        return summary
    containers = [entry[key] for key in POLICY_ADDRESS_LIST_KEYS if key in entry]
    texts: list[str] | None = [] if containers else None
    for container in containers:
        read = _address_entries(container)
        if read is None or texts is None:
            texts = None
            break
        texts.extend(read)
    summary["entry_count"] = len(texts) if texts is not None else None
    summary["domain_entry_count"] = sum(1 for text in texts if _DOMAIN_ENTRY.match(text)) if texts is not None else None
    return summary


def _drop_descriptions(value: Any) -> Any:
    if isinstance(value, list):
        return [_drop_descriptions(item) for item in value]
    if isinstance(value, dict):
        return {key: _drop_descriptions(item) for key, item in value.items() if key != "description"}
    return value


def minimise_policy_value(setting_type: Any, value: Any) -> Any:
    """One Policy API setting value with address lists reduced to counts and no address or list description left."""
    if setting_type == POLICY_ADDRESS_LISTS_TYPE and isinstance(value, dict) and "emailAddressList" in value:
        lists = value["emailAddressList"]
        unreadable = {"id": None, "entry_count": None, "domain_entry_count": None}
        # A list that is not a list of objects is unreadable: its content is dropped and its counts are unknown.
        value = {
            **value,
            "emailAddressList": [
                _address_list_summary(item) if isinstance(item, dict) else dict(unreadable) for item in lists
            ]
            if isinstance(lists, list)
            else None,
        }
    if setting_type in POLICY_DESCRIBED_LIST_TYPES:
        value = _drop_descriptions(value)
    return _scrub_addresses(value)


def _minimise_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """A Policy API object with its setting value minimised (``customer`` and ``name`` are left to the caller)."""
    setting = policy.get("setting")
    if not isinstance(setting, dict) or "value" not in setting:
        return policy
    return {**policy, "setting": {**setting, "value": minimise_policy_value(setting.get("type"), setting["value"])}}


def _is_policy(value: dict[str, Any]) -> bool:
    setting = value.get("setting")
    return isinstance(setting, dict) and isinstance(setting.get("type"), str) and setting["type"].startswith("settings/")


# The raw sections of the Google policies read: both hold Policy API objects, minimised the same way.
POLICY_SECTION_KEYS = ("policySettings", "twoStepVerificationPolicies")


def minimise_policy_settings(policies: Any) -> Any:
    """Cloud Identity policies for the SCuBA settings payload: no ``customer``, no ``name``, no address.

    A row that is not an object is kept with its addresses scrubbed, so the normaliser can still count it as
    malformed instead of the read looking complete.
    """
    if not isinstance(policies, list):
        return _scrub_addresses(policies)
    result: list[Any] = []
    for policy in policies:
        if not isinstance(policy, dict):
            result.append(_scrub_addresses(policy))
            continue
        kept = {
            key: item if key == "setting" else _scrub_addresses(item)
            for key, item in policy.items()
            if key not in POLICY_DROPPED_FIELDS
        }
        setting = kept.get("setting")
        if isinstance(setting, dict):
            # The setting's type and value are kept as read; any other setting field is scrubbed like the rest.
            kept["setting"] = {key: item if key in ("type", "value") else _scrub_addresses(item) for key, item in setting.items()}
            if "value" in setting:
                kept = _minimise_policy(kept)
        elif setting is not None:
            kept["setting"] = _scrub_addresses(setting)
        result.append(kept)
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
        result = strip_text_fields(result, VACATION_TEXT_FIELDS, keep_presence=False)
    if isinstance(result.get("vacation"), dict):
        result["vacation"] = strip_text_fields(result["vacation"], VACATION_TEXT_FIELDS, keep_presence=False)
    if "sendAsEmail" in result:
        result = strip_text_fields(result, SEND_AS_TEXT_FIELDS, keep_presence=False)
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
    if _is_policy(result):
        # A Cloud Identity policy, wherever it sits: no customer id or policy name, address lists become counts and
        # no address or local path is kept.
        (result,) = minimise_policy_settings([result])
    for key in POLICY_SECTION_KEYS:
        if isinstance(result.get(key), dict) and "value" in result[key]:
            # The Google policies payloads, replayed or written: every row, even one that cannot be read, minimised.
            result[key] = {**result[key], "value": minimise_policy_settings(result[key]["value"])}
    if isinstance(result.get("criteria"), dict) and isinstance(result.get("action"), dict):
        # A Gmail filter: its search terms are the owner's; the forward target and labels are what is judged.
        result["criteria"] = strip_text_fields(result["criteria"], GMAIL_FILTER_TEXT_FIELDS, keep_presence=False)
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
