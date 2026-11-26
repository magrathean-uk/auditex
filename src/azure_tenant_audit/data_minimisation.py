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

Cloud Identity Policy API settings (``minimise_policy_settings``) are admin configuration, but some setting
values are text an admin typed (a custom user message, a rule name, a description, Gmail address lists) and a
policy's CEL query can name units and groups. A policy is projected onto the fields the audit reads: its type, its
targets and order, the parsed scope of its query (``query_scope``, never the query; a licence scope also keeps
``licence_terms`` over SKU digests, never a SKU id) and its setting's type and value. Each setting has a field allow-list with typed fields and fixed enum membership. Administrator text and
unrecognised fields are discarded. An unreadable allow-listed value remains marked as unknown.
Each Gmail address list becomes its id, its entry count and its count of domain-shaped entries
(``^[^@]+\\.[^@]+$``, ScubaGoggles' own test). A list whose entries or id cannot be read keeps ``None`` counts
(unknown), never zero.

They never mutate their
input and are idempotent.
"""
from __future__ import annotations

import math
import re
import sys
from hashlib import sha256
from typing import Any, Literal

from .collection_gaps import REASON_UNKNOWN, TRUNCATION_REASONS, section_was_cut
from .google_policy_schema import (
    CUSTOMER_ID,
    POLICY_VALUE_SCHEMAS,
    TAKEOUT_SETTING_TYPES,
    RequiredPolicyField,
    policy_reference,
    policy_scalar,
)

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


def _policy_vocabulary() -> tuple[tuple[str, ...], tuple[str, ...], frozenset[str], tuple[str, ...]]:
    """Google's address-list keys, policy types and system groups, and the product's query scopes. They are returned
    from a function body rather than written in module-level constants, so none becomes a product field name the
    shareable redaction keeps (``output_redaction._D5_FIELD_NAMES``, DEC-171); a person or group with that name is
    still pseudonymised where it is a mapping key."""
    return (
        ("addressList", "blockedAddressList"),
        ("ADMIN", "SYSTEM", "POLICY_TYPE_UNSPECIFIED"),
        frozenset({"WORKSPACE_ALL_ADMIN_GROUP", "UNCONSENTED_CHILD_GROUP"}),
        ("targets", "licences", "licences_unit", "licences_wide", "conditional", "other", "unreadable"),
    )


# Policy API objects. A policy keeps only what the audit reads, in a fixed shape: its ``type``, its targets and order
# (``policyQuery.orgUnit``, ``group`` and ``sortOrder``), the scope its CEL ``query`` was parsed into
# (``policyQuery.query_scope``, never the query text, and for a licence scope ``licence_terms`` over SKU digests) and
# its setting's ``type`` and projected ``value``. The tenant's
# customer id, the policy resource name and every other field are dropped.
POLICY_ADDRESS_LIST_KEYS, POLICY_TYPES, POLICY_SYSTEM_GROUPS, POLICY_QUERY_SCOPES = _policy_vocabulary()
POLICY_SETTING_TYPE = re.compile(r"settings/[a-z0-9_]+(?:\.[a-z0-9_]+)+")
# SCuBA's service prefixes and exact setting types, shared by the request and response checks.
POLICY_TYPE_PATTERN = (
    r"^settings/((gmail|security|drive_and_docs|calendar|chat|meet|classroom|groups_for_business|sites|takeout|"
    r"data_regions|workspace_marketplace|api_controls|provisioning|multi_party_approval|"
    r"enterprise_service_restrictions|early_access_apps|gemini_app|access_approval|access_management)\..*|"
    rf"{'|'.join(map(re.escape, TAKEOUT_SETTING_TYPES))}|rule\.system_defined_alerts)$"
)
POLICY_TYPE_ALLOWED = re.compile(POLICY_TYPE_PATTERN)
TWO_STEP_SETTING_PREFIX = "settings/security.two_step_verification_"
UNRECOGNISED_POLICY_SETTING = "unrecognised"
POLICY_UNIT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
POLICY_QUERY_MAX = 4_096
_DOMAIN_ENTRY = re.compile(r"^[^@]+\.[^@]+$")
# The names of Google's system-defined alert rules read by ScubaGoggles v1.1.0 (parsers/system_rules_parser.py).
UNRECOGNISED_SYSTEM_ALERT_NAME = "unrecognised"
POLICY_SYSTEM_ALERT_NAMES = frozenset(
    {
        "Account suspension warning",
        "Calendar settings changed",
        "Device compromised",
        "Domain data export initiated",
        "Drive settings changed",
        "Email settings changed",
        "Gmail potential employee spoofing",
        "Google Operations",
        "Government-backed attacks",
        "Leaked password",
        "Malware message detected post-delivery",
        "Mobile settings changed",
        "Phishing in inboxes due to bad whitelist",
        "Phishing message detected post-delivery",
        "Rate limited recipient",
        "SSO profile added",
        "SSO profile updated",
        "Spike in user-reported spam",
        "Super admin password reset",
        "Suspicious device activity",
        "Suspicious login",
        "Suspicious message reported",
        "Suspicious programmatic login",
        "User granted Admin privilege",
        "User suspended (Google identity alert)",
        "User suspended due to suspicious activity",
        "User suspended for spamming",
        "User suspended for spamming through relay",
        "User's Admin privilege revoked",
        "User-reported phishing",
    }
)


def finite_policy_number(value: Any) -> bool:
    """Check an API double without converting a potentially out-of-range integer."""
    if type(value) is int:
        return -sys.float_info.max <= value <= sys.float_info.max
    return isinstance(value, float) and math.isfinite(value)


def policy_unit_id(value: Any) -> bool:
    return isinstance(value, str) and bool(POLICY_UNIT_ID.fullmatch(value)) and CUSTOMER_ID.search(value) is None


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


def _address_list_summary(entry: Any) -> dict[str, Any]:
    """Keep a usable list ID and counts, or unknown counts when any entries cannot be read."""
    unknown = {"id": None, "entry_count": None, "domain_entry_count": None}
    if not isinstance(entry, dict) or not policy_reference(entry.get("id")):
        return unknown
    unknown["id"] = entry["id"]
    containers = [entry[key] for key in POLICY_ADDRESS_LIST_KEYS if key in entry]
    if not containers:
        # A previously minimised list needs both consistent counts.
        total, domains = entry.get("entry_count"), entry.get("domain_entry_count")
        if type(total) is int and type(domains) is int and 0 <= domains <= total:
            return {"id": entry["id"], "entry_count": total, "domain_entry_count": domains}
        return unknown
    texts: list[str] = []
    for container in containers:
        entries = _address_entries(container)
        if entries is None:
            return unknown
        texts.extend(entries)
    return {
        "id": entry["id"],
        "entry_count": len(texts),
        "domain_entry_count": sum(1 for text in texts if _DOMAIN_ENTRY.fullmatch(text)),
    }


_CAMEL_BOUNDARY = re.compile(r"(?<!^)(?=[A-Z])")


def _snake_policy_field(key: str) -> str:
    return _CAMEL_BOUNDARY.sub("_", key).lower()


def _project_policy_object(value: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, field in schema.items():
        alias = _snake_policy_field(key)
        # The legacy 2SV aliases have their own checked keys in the schema.
        if alias in schema:
            alias = key
        if key in value or alias in value:
            projected = _project_policy_field(value.get(key, value.get(alias)), field)
            if key != alias and key in value and alias in value and projected != _project_policy_field(value[alias], field):
                projected = None
            result[key] = projected
        elif isinstance(field, RequiredPolicyField) and (
            field.when is None or value.get(field.when, value.get(_snake_policy_field(field.when))) is True
        ):
            result[key] = None
    return result


def _project_policy_field(value: Any, schema: Any) -> Any:
    if isinstance(schema, RequiredPolicyField):
        return _project_policy_field(value, schema.schema)
    if isinstance(schema, dict):
        return _project_policy_object(value, schema) if isinstance(value, dict) else None
    if isinstance(schema, list):
        return [_project_policy_field(item, schema[0]) for item in value] if isinstance(value, list) else None
    if schema == "address-lists":
        return [_address_list_summary(item) for item in value] if isinstance(value, list) else None
    if schema == "system-alert-name":
        if not isinstance(value, str):
            return None
        return value if value in POLICY_SYSTEM_ALERT_NAMES else UNRECOGNISED_SYSTEM_ALERT_NAME
    return policy_scalar(value, schema)


def policy_value_schema(setting_type: Any) -> dict[str, Any] | None:
    if isinstance(setting_type, str) and setting_type.startswith("settings/"):
        return POLICY_VALUE_SCHEMAS.get(setting_type.removeprefix("settings/"))
    return None


def policy_is_unrecognised(policy: Any) -> bool:
    """An unsupported setting of a requested type, or its fixed marker in saved evidence."""
    setting = policy.get("setting") if isinstance(policy, dict) else None
    setting_type = setting.get("type") if isinstance(setting, dict) else None
    return isinstance(setting_type, str) and (
        setting_type == UNRECOGNISED_POLICY_SETTING
        or (
            not setting_type.startswith(TWO_STEP_SETTING_PREFIX)
            and POLICY_SETTING_TYPE.fullmatch(setting_type) is not None
            and POLICY_TYPE_ALLOWED.fullmatch(setting_type) is not None
            and policy_value_schema(setting_type) is None
        )
    )


def minimise_policy_value(setting_type: Any, value: Any) -> Any:
    """Project only named fields of the setting's schema; nulls preserve read failures on replay."""
    schema = policy_value_schema(setting_type)
    if schema is not None and setting_type == "settings/rule.system_defined_alerts" and isinstance(value, dict) and "rules" in value:
        # Older widened samples can carry the alert entries in a single list.
        schema = {"rules": schema["rules"]}
    return _project_policy_field(value, schema) if schema is not None else None


# What a Google policies section may carry besides its rows: the outcome markers of the read, with fixed values only.
POLICY_ERROR_CLASSES = (
    "client_error",
    "insufficient_permissions",
    "unauthenticated",
    "resource_not_found",
    "rate_limited",
    "google_transient",
    "malformed_response",
)


def minimise_policy_section(name: str, section: dict[str, Any]) -> dict[str, Any]:
    """One Google policies section (``policySettings`` or ``twoStepVerificationPolicies``) with fixed markers only.

    The rows are minimised. An error marker keeps its class when it is a known one (else ``client_error``) and gets a
    fixed text, so a sample or an earlier writer cannot carry a customer id, a path or other free text through it. A
    cut marker keeps a known reason (else ``unknown``) and whole counts. Any other key is dropped.
    """
    result: dict[str, Any] = {}
    if "value" in section:
        result["value"] = minimise_policy_settings(section["value"])
    if section.get("error") or section.get("error_class"):
        error_class = section.get("error_class")
        error_class = error_class if error_class in POLICY_ERROR_CLASSES else "client_error"
        result["error_class"] = error_class
        result["error"] = f"{name}: the Cloud Identity policies read failed ({error_class})."
    if section_was_cut(section):
        result["collection_truncated"] = True
        reason = section.get("truncation_reason")
        result["truncation_reason"] = reason if reason in TRUNCATION_REASONS else REASON_UNKNOWN
    for key in ("item_count", "result_limit"):
        count = section.get(key)
        if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
            result[key] = count
    return result


def policy_target(value: Any, prefix: str) -> str | None | Literal[False]:
    """A target's bare ID, None for the unset string, or False for an invalid target."""
    if value == "":
        return None
    if not isinstance(value, str):
        return False
    if prefix == "groups/" and value in POLICY_SYSTEM_GROUPS:
        return value
    if not value.startswith(prefix):
        return False
    bare = value[len(prefix) :]
    return bare if policy_unit_id(bare) else False


# The CEL terms a policy query may hold and still be represented by its ``orgUnit`` and ``group`` fields alone. The
# captured id must be a sound id and must name the same unit or group as the field. Google writes the id bare or,
# for some settings (``provisioning.*``), with its resource prefix (``orgUnitId('orgUnits/<id>')``).
_QUERY_ORG_UNIT_TERM = re.compile(
    r"entity\.org_units\.exists\(\s*([A-Za-z_]\w*)\s*,\s*\1\.org_unit_id\s*==\s*orgUnitId\(\s*'(?:orgUnits/)?([A-Za-z0-9][A-Za-z0-9_-]{0,127})'\s*\)\s*\)"
)
_QUERY_GROUP_TERM = re.compile(
    r"entity\.groups\.exists\(\s*([A-Za-z_]\w*)\s*,\s*\1\.group_id\s*==\s*groupId\(\s*'(?:groups/)?([A-Za-z0-9][A-Za-z0-9_-]{0,127})'\s*\)\s*\)"
)
_LICENCE_SKU = r"(?:/product/[A-Za-z0-9-]+/sku/[A-Za-z0-9-]+|CHROMEBOOK-SOFTWARE|GOOGLE-IDENTITY)"
_LICENCE_TERM = re.compile(
    r"(!)?\s*entity\.licenses\.exists\(\s*([A-Za-z_]\w*)\s*,\s*\2\s+in\s*"
    rf"\[\s*'{_LICENCE_SKU}'(?:\s*,\s*'{_LICENCE_SKU}')*\s*\]\s*\)"
)


def licence_atom(sku: str) -> str:
    """A fixed-length digest standing for one licence SKU in a minimised query: the same SKU always gives the same
    atom, so policies can be ranked against one another, but the SKU id itself is not kept."""
    return sha256(("google-licence-sku:" + sku).encode()).hexdigest()[:16]


LICENCE_ATOM = re.compile(r"[0-9a-f]{16}")
# Above this many distinct SKUs in one unit and section the populations are not enumerated (2**n assignments).
LICENCE_ATOM_MAX = 10


def _query_conjunction(conjunction: str) -> tuple[list[str], list[str], dict[str, list[str]]] | None:
    """The org-unit ids, group ids and licence clauses (``holds_any``: SKUs of which the user holds one;
    ``holds_none``: SKUs the user holds none of) of one ``&&`` conjunction. None for any other term, for two licence
    clauses of the same polarity, or for a conjunction no user can meet (every SKU it asks for is also excluded)."""
    org_ids: list[str] = []
    group_ids: list[str] = []
    licences: dict[str, list[str]] = {}
    for term in conjunction.split("&&"):
        term = term.strip()
        while term.startswith("(") and term.endswith(")") and _QUERY_ORG_UNIT_TERM.fullmatch(term) is None:
            term = term[1:-1].strip()
        if match := _QUERY_ORG_UNIT_TERM.fullmatch(term):
            org_ids.append(match.group(2))
        elif match := _QUERY_GROUP_TERM.fullmatch(term):
            group_ids.append(match.group(2))
        elif licence := _LICENCE_TERM.fullmatch(term):
            key = "holds_none" if licence.group(1) is not None else "holds_any"
            if key in licences:
                return None
            licences[key] = sorted({licence_atom(sku) for sku in re.findall(rf"'({_LICENCE_SKU})'", term)})
        else:
            return None
    if "holds_any" in licences and set(licences["holds_any"]) <= set(licences.get("holds_none", ())):
        raise _ImpossiblePopulation
    return org_ids, group_ids, licences


class _ImpossiblePopulation(Exception):
    """A conjunction no user can meet: every SKU it asks for is also excluded."""


def _query_bounded(query: str, org_id: Any, group_id: Any) -> bool:
    """Whether every ``||`` disjunct of a query holds, as one of its ``&&`` terms, the positive org-unit term naming
    the ``orgUnit`` field's unit (when it is set) and the positive group term naming the ``group`` field's group (when
    it is set): whatever else it says, the policy then holds only inside its unit and group. A split that breaks a
    parenthesised term leaves that disjunct without the term, so an unclear query is never read as bounded."""
    for disjunct in query.split("||"):
        has_org = has_group = False
        for term in disjunct.split("&&"):
            term = term.strip()
            while term.startswith("(") and term.endswith(")") and _QUERY_ORG_UNIT_TERM.fullmatch(term) is None \
                    and _QUERY_GROUP_TERM.fullmatch(term) is None:
                term = term[1:-1].strip()
            if (match := _QUERY_ORG_UNIT_TERM.fullmatch(term)) and match.group(2) == org_id:
                has_org = True
            elif (match := _QUERY_GROUP_TERM.fullmatch(term)) and match.group(2) == group_id:
                has_group = True
        if (isinstance(org_id, str) and not has_org) or (isinstance(group_id, str) and not has_group):
            return False
    return isinstance(org_id, str) or isinstance(group_id, str)


def policy_query_terms(query: Any, org_unit: Any, group: Any) -> tuple[str, list[dict[str, list[str]]] | None]:
    """What a policy's CEL ``query`` says about its scope, against its raw ``orgUnit`` and ``group`` fields, and the
    licence predicate it keeps (``None`` unless the word is a licence word).

    The query is read as a disjunction (``||``) of conjunctions (``&&``, which binds tighter in CEL) of org-unit
    membership, group membership and Google's include/exclude licence SKU clauses (at most one of each polarity).

    ``targets``: one conjunction of at most one org-unit term naming the ``orgUnit`` field's unit and a group term
    present exactly when the ``group`` field is, naming that group. ``licences_unit``: every conjunction names those
    targets, and some hold licence clauses: the policy holds for the unit's users who meet one conjunction's
    clauses. ``licences_wide``: as ``licences_unit``, except that some conjunction leaves out the org-unit term of a
    policy that names an org unit, so it is not bounded to that unit; only the top unit, which every user is under,
    can stand for it (the normaliser's call). The predicate is a list of conjunctions, each ``holds_any`` and
    ``holds_none`` lists of SKU digests (:func:`licence_atom`). ``conditional``: any other scope that every
    disjunct still bounds to the policy's unit and group (:func:`_query_bounded`), such as an exception: the unit's
    setting is unknown. ``other``: a scope that may reach users outside the unit or group (a disjunct without the
    targets, another unit, a conjunction every user meets) or a licence conjunction no user can meet: the section is
    unknown. ``unreadable``: not a string of bounded length. The query text and the SKU ids never leave the
    minimiser.
    """
    if not isinstance(query, str) or len(query) > POLICY_QUERY_MAX:
        return "unreadable", None
    org_id, group_id = policy_target(org_unit, "orgUnits/"), policy_target(group, "groups/")
    word = _query_word(query, org_id, group_id)
    if word is not None:
        return word
    return "conditional" if _query_bounded(query, org_id, group_id) else "other", None


def _query_word(query: str, org_id: Any, group_id: Any) -> tuple[str, list[dict[str, list[str]]] | None] | None:
    """The scope word and predicate of a query made only of target and licence terms; ``None`` for any other query
    (:func:`policy_query_terms` then tells a bounded condition from an unbounded one)."""
    try:
        conjunctions = [_query_conjunction(part) for part in query.split("||")]
    except _ImpossiblePopulation:
        return "other", None  # a population no user can meet is never a value for any unit
    if any(parts is None for parts in conjunctions):
        return None
    licensed = wide = False
    terms: list[dict[str, list[str]]] = []
    for org_ids, group_ids, licences in conjunctions:  # type: ignore[misc]
        if len(org_ids) > 1 or (org_ids and org_ids[0] != org_id):
            return None
        if group_ids != ([group_id] if isinstance(group_id, str) else []):
            return None  # a conjunction without the policy's group reaches users outside it
        if not org_ids and not group_ids and not licences:
            return None  # a conjunction every user meets
        if not org_ids and isinstance(org_id, str):
            wide = True  # this conjunction is not bounded to the policy's unit
        licensed = licensed or bool(licences)
        terms.append({"holds_any": licences.get("holds_any", []), "holds_none": licences.get("holds_none", [])})
    if not licensed:
        return ("targets", None) if len(conjunctions) == 1 else None
    unique = sorted({(tuple(term["holds_any"]), tuple(term["holds_none"])) for term in terms})
    predicate = [{"holds_any": list(holds_any), "holds_none": list(holds_none)} for holds_any, holds_none in unique]
    return ("licences_wide" if wide else "licences_unit"), predicate


def policy_query_scope(query: Any, org_unit: Any, group: Any) -> str:
    """The scope word of :func:`policy_query_terms`; only this word and the licence predicate are kept."""
    return policy_query_terms(query, org_unit, group)[0]


def licence_terms_readable(scope: Any, terms: Any) -> bool:
    """Whether a minimised query's ``licence_terms`` fit its ``query_scope``: present exactly for a licence word, a
    non-empty list of conjunctions of sorted, distinct SKU digests that some user can meet."""
    if scope not in ("licences_unit", "licences_wide"):
        return terms is None
    if not isinstance(terms, list) or not terms:
        return False
    for term in terms:
        if not isinstance(term, dict) or set(term) != {"holds_any", "holds_none"}:
            return False
        for atoms in term.values():
            if (not isinstance(atoms, list) or not all(isinstance(atom, str) and LICENCE_ATOM.fullmatch(atom) for atom in atoms)
                    or atoms != sorted(set(atoms))):
                return False
        if term["holds_any"] and set(term["holds_any"]) <= set(term["holds_none"]):
            return False
    return True


def _minimise_target(value: Any, prefix: str) -> Any:
    """A target field: a sound target, ``""`` (unset) or null as read; any other text a constant (still invalid)."""
    if value is None or policy_target(value, prefix) is not False:
        return value
    return "redacted:text"


def policy_query_parsed(query: dict[str, Any]) -> tuple[str, list[dict[str, list[str]]] | None] | None:
    """Parse raw CEL, or retain the fixed classification and licence predicate of minimised evidence (checked);
    ``None`` when the policy holds no query."""
    if "query" in query and query["query"] != "":
        scope, terms = policy_query_terms(query["query"], query.get("orgUnit"), query.get("group"))
        if "query_scope" in query and (scope != query["query_scope"] or terms != query.get("licence_terms")):
            return "unreadable", None
        return scope, terms
    if "query_scope" in query:
        value, terms = query["query_scope"], query.get("licence_terms")
        if value not in POLICY_QUERY_SCOPES or not licence_terms_readable(value, terms):
            return "unreadable", None
        return value, terms
    if "licence_terms" in query:
        return "unreadable", None
    return None


def policy_query_classification(query: dict[str, Any]) -> str | None:
    """Classify raw CEL or retain the fixed classification from minimised evidence."""
    parsed = policy_query_parsed(query)
    return None if parsed is None else parsed[0]


def _minimise_policy_query(query: Any) -> Any:
    """``policyQuery`` with its targets and order and the parsed scope of its CEL query; nothing else."""
    if not isinstance(query, dict):
        return None
    result: dict[str, Any] = {}
    for key, prefix in (("orgUnit", "orgUnits/"), ("group", "groups/")):
        if key in query:
            result[key] = _minimise_target(query[key], prefix)
    if "sortOrder" in query:
        result["sortOrder"] = query["sortOrder"] if finite_policy_number(query["sortOrder"]) else None
    if (parsed := policy_query_parsed(query)) is not None:
        result["query_scope"] = parsed[0]
        if parsed[1] is not None:
            result["licence_terms"] = parsed[1]
    return result


def _minimise_setting(setting: Any) -> Any:
    """``setting`` with its type and projected value only."""
    if not isinstance(setting, dict):
        return None
    result: dict[str, Any] = {}
    setting_type = setting.get("type")
    if "type" in setting:
        result["type"] = setting_type if policy_value_schema(setting_type) is not None else None
    if "value" in setting:
        result["value"] = minimise_policy_value(setting_type, setting["value"])
    return result


def _is_policy(value: dict[str, Any]) -> bool:
    setting = value.get("setting")
    return isinstance(setting, dict) and isinstance(setting.get("type"), str) and (
        setting["type"].startswith("settings/") or setting["type"] == UNRECOGNISED_POLICY_SETTING
    )


# The raw sections of the Google policies read: both hold Policy API objects, minimised the same way.
POLICY_SECTION_KEYS = ("policySettings", "twoStepVerificationPolicies")


def minimise_policy_settings(policies: Any) -> Any:
    """Cloud Identity policies projected onto the fields the audit reads: no ``customer``, ``name`` or free text.

    Each policy keeps ``type``, ``policyQuery`` (``orgUnit``, ``group``, ``sortOrder`` and ``query_scope``) and
    ``setting`` (``type`` and the projected ``value``). Unreadable fields or rows remain invalid after projection.
    Unrecognised requested settings outside 2SV keep only a fixed type marker.
    """
    if not isinstance(policies, list):
        return None
    result: list[Any] = []
    for policy in policies:
        if not isinstance(policy, dict):
            result.append(None)
            continue
        if policy_is_unrecognised(policy):
            result.append({"setting": {"type": UNRECOGNISED_POLICY_SETTING}})
            continue
        kept: dict[str, Any] = {}
        if "type" in policy:
            kept["type"] = policy["type"] if policy["type"] in POLICY_TYPES else None
        if "policyQuery" in policy:
            kept["policyQuery"] = _minimise_policy_query(policy["policyQuery"])
        if "setting" in policy:
            kept["setting"] = _minimise_setting(policy["setting"])
            if isinstance(kept["setting"], dict) and any(
                key in policy and not isinstance(policy[key], str) for key in ("name", "customer")
            ):
                kept["setting"]["value"] = None
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
        if isinstance(result.get(key), dict) and ("value" in result[key] or result[key].get("error") or result[key].get("error_class")):
            # The Google policies payloads, replayed or written: every row, even one that cannot be read, minimised,
            # and only fixed values in the read's outcome markers.
            result[key] = minimise_policy_section(key, result[key])
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
