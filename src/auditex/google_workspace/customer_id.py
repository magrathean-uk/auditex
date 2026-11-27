"""Learn Google customer IDs from explicit fields and requests, then withhold their values."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime
from functools import cache, cached_property
from typing import Any
from urllib.parse import unquote

MY_CUSTOMER = "my_customer"
WITHHELD = "<customer-id>"
WITHHELD_ERROR_CLASS = "customer_id_withheld"

_ERROR_KEYS = frozenset({"error", "errors", "message", "reason", "detail", "details", "errormessage", "statusmessage"})
_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_REQUEST_CUSTOMER = re.compile(
    r"(?:[?&]customer(?:Id)?=|/customers?/|customers?%2F)([A-Za-z0-9_%+-]+)", re.IGNORECASE,
)
_MISSING_CUSTOMER = re.compile(r"(?i:\bcustomer\s+)(C[0-9][A-Za-z0-9_-]*)(?=\s+was not found\b)")
# A Google customer id is "C" and a digit, then 6 to 10 letters or digits (real ones are 9 characters, "C03az79cb"). In
# failure text one may be quoted in any wording, so it is also masked by shape. The id may follow a URL (%3D) or JSON
# (=) escape, or an underscore of a compound token such as customer_<id>_lookup.
_CUSTOMER_ID_SHAPE = re.compile(
    r"(?:(?<![A-Za-z0-9])|(?<=%[0-9A-Fa-f]{2})|(?<=\\u[0-9A-Fa-f]{4})|(?<=\\[nrt]))C[0-9][A-Za-z0-9]{6,10}(?![A-Za-z0-9])"
)
_ENCODED_CUSTOMER_FILTER = re.compile(r"customer%3D(?:%3D)?%22customers%2F[A-Za-z0-9_%+-]+", re.IGNORECASE)


def bundle_customer_id(value: Any) -> str | None:
    return MY_CUSTOMER if isinstance(value, str) and value.strip() == MY_CUSTOMER else None


def _norm(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _identity(norm: str, member: Any) -> bool:
    """Whether ``member`` is a customer identity object, such as a Reports API ``ownerIdentity[].customerIdentity``."""
    return norm == "customeridentity" and isinstance(member, dict)


def _explicit_id(norm: str, *, identity: bool) -> bool:
    """A field that holds a Google customer id: ``customerId``, or the ``id`` of a customer identity object."""
    return norm == "customerid" or (identity and norm == "id")


def _no_value(member: Any) -> bool:
    """A field value that holds nothing to withhold: null, an empty string or the ``my_customer`` alias."""
    return member is None or member == "" or bundle_customer_id(member) is not None


def _malformed_container(norm: str, member: Any) -> bool:
    """A field that names the customer but does not have its shape, so whatever it holds is withheld whole.

    ``customerIdentity`` must be an object whose every ``id`` member is a string (at least one); ``customer`` must be
    a ``customers/<id>`` string. Anything else under those keys (a list, a string, a number, an object without a
    string id) may hold the customer id before it is learnt, so it is never copied (LIVE-FIX-5 B2).
    """
    if _no_value(member):
        return False
    if norm == "customeridentity":
        if not isinstance(member, dict):
            return True
        ids = [value for key, value in member.items() if _norm(key) == "id"]
        return not ids or not all(isinstance(value, str) for value in ids)
    if norm == "customer":
        return not (isinstance(member, str) and member.startswith("customers/"))
    return False


# Fixed Reports API objects on a customer id path (admin.reports_v1 discovery document): Activity.id,
# Activity.resourceDetails and each entry, UsageReport.entity, ResourceDetails.ownerDetails and its ownerIdentity
# entries. Each must have its documented shape, member names (exact) and member types included; a value of any other
# shape may hold the customer id under another key or none, before it is learnt, so it is withheld whole, as a
# malformed customerIdentity is (LIVE-FIX-6 B2a, LIVE-FIX-7 B2a).
_ACTIVITY_KIND = "admin#reports#activity"
_USAGE_REPORT_KIND = "admin#reports#usageReport"
# int64 in decimal (the discovery document's "format": "int64" string), RFC 3339 date-time, and a Reports application
# name (lower-case letters, digits and underscores, as every documented applicationName is). A customer id ("C" and
# a digit) has none of these forms.
_INT64 = re.compile(r"-?[0-9]{1,19}")
_RFC3339 = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?(?:[Zz]|[+-]([0-9]{2}):([0-9]{2}))"
)
_APPLICATION_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")


def _report_members() -> tuple[frozenset[str], ...]:
    """Normalised names of an Activity's own members other than ``id``, ``kind`` and ``etag`` (any of them marks an
    object as an activity). Kept out of module constants, as every member name below is: they are what the shape
    checks read, not field names Auditex writes, so they never join the redaction's field-name exemption."""
    return (
        frozenset({"actor", "events", "ipaddress", "ownerdomain", "resourcedetails", "networkinfo", "userdeviceinfo",
                   "isagenticaction"}),
    )


def _string(value: Any) -> bool:
    return isinstance(value, str)


def _int64_text(value: Any) -> bool:
    """A decimal int64 string (the discovery document's ``format: int64``); a number, or any other text, is not one."""
    return isinstance(value, str) and bool(_INT64.fullmatch(value)) and -(2**63) <= int(value) < 2**63


def _rfc3339(value: Any) -> bool:
    """An RFC 3339 date-time string with a real calendar date and time (``format: date-time``)."""
    match = _RFC3339.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return False
    year, month, day, hour, minute, second, offset_hour, offset_minute = (
        int(part) if part is not None else 0 for part in match.groups()
    )
    try:
        datetime(year, month, day, hour, minute, min(second, 59))
    except ValueError:
        return False
    return second <= 60 and offset_hour <= 23 and offset_minute <= 59


def _application_name(value: Any) -> bool:
    return isinstance(value, str) and bool(_APPLICATION_NAME.fullmatch(value))


@cache
def _report_shapes() -> dict[str, tuple[tuple[str, Any], ...]]:
    """Every Admin Reports v1 object reachable from a customer id path, by discovery schema name (an inline object by
    its owner and member, ``Activity.id``): its members (exact names) and each member's type.

    A type is ``string``, ``boolean``, ``int64`` (a decimal string, the discovery ``format: int64``), ``int32`` (an
    integer), ``date-time`` (an RFC 3339 string), ``application-name`` (a string of Reports application form), the
    name of another schema here (an object of that type) or ``("array", <item type>)``. A test reads the discovery
    document shipped with google-api-python-client and fails when this table and it disagree on any schema, member or
    type. Pairs, not mapping displays: these are the names the checks read, not field names Auditex writes, so they
    never join the redaction's field-name exemption (``time`` among them must stay masked as a mapping key)."""
    return dict((
        ("Activity.id", (
            ("applicationName", "application-name"), ("customerId", "string"), ("time", "date-time"),
            ("uniqueQualifier", "int64"),
        )),
        ("UsageReport.entity", tuple(
            (name, "string") for name in ("customerId", "entityId", "profileId", "type", "userEmail")
        )),
        ("ResourceDetails", (
            ("appliedLabels", ("array", "AppliedLabel")), ("id", "string"), ("ownerDetails", "OwnerDetails"),
            ("relation", "string"), ("title", "string"), ("type", "string"),
        )),
        ("AppliedLabel", (
            ("fieldValues", ("array", "FieldValue")), ("id", "string"), ("reason", "Reason"), ("title", "string"),
        )),
        ("FieldValue", (
            ("dateValue", "Date"), ("displayName", "string"), ("id", "string"), ("integerValue", "int64"),
            ("longTextValue", "string"), ("reason", "Reason"), ("selectionListValue", "FieldValueSelectionListValue"),
            ("selectionValue", "FieldValueSelectionValue"), ("textListValue", "FieldValueTextListValue"),
            ("textValue", "string"), ("type", "string"), ("unsetValue", "boolean"),
            ("userListValue", "FieldValueUserListValue"), ("userValue", "FieldValueUserValue"),
        )),
        ("Date", (("day", "int32"), ("month", "int32"), ("year", "int32"))),
        ("Reason", (("reasonType", "string"),)),
        ("FieldValueSelectionListValue", (("values", ("array", "FieldValueSelectionValue")),)),
        ("FieldValueSelectionValue", (("badged", "boolean"), ("displayName", "string"), ("id", "string"))),
        ("FieldValueTextListValue", (("values", ("array", "string")),)),
        ("FieldValueUserListValue", (("values", ("array", "FieldValueUserValue")),)),
        ("FieldValueUserValue", (("email", "string"),)),
        ("OwnerDetails", (("ownerIdentity", ("array", "OwnerIdentity")), ("ownerType", "string"))),
        ("OwnerIdentity", (
            ("customerIdentity", "CustomerIdentity"), ("groupIdentity", "GroupIdentity"),
            ("sharedDriveIdentity", "SharedDriveIdentity"), ("userIdentity", "UserIdentity"),
        )),
        ("CustomerIdentity", (("id", "string"),)),
        ("GroupIdentity", (("groupEmail", "string"), ("id", "string"))),
        ("SharedDriveIdentity", (("id", "string"), ("sharedDriveName", "string"))),
        ("UserIdentity", (("id", "string"), ("userEmail", "string"))),
    ))


def _int32(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and -(2**31) <= value < 2**31


@cache
def _scalar_check(kind: str) -> Callable[[Any], bool] | None:
    return dict((
        ("string", _string), ("boolean", lambda value: isinstance(value, bool)), ("int64", _int64_text),
        ("int32", _int32), ("date-time", _rfc3339), ("application-name", _application_name),
    )).get(kind)


def _own_field(key: str) -> bool:
    """A member the scrub checks as a field of its own (``ownerDetails``, ``ownerIdentity``), against the same table,
    so a malformed one is withheld alone rather than with the object that holds it."""
    return _norm(key) in ("ownerdetails", "owneridentity")


def _conforms(value: Any, kind: Any) -> bool:
    """Whether ``value`` has the Reports discovery type ``kind`` (see :func:`_report_shapes`), recursively: an object
    holds only its own members (exact names), each of its own type; an array holds only items of its item type. Nothing
    is accepted as any object or any list. Only :meth:`CustomerIds._scrub` reads a result, and it checks every value
    under an accepted one again on its way down: a member that is a field of its own (:func:`_own_field`) and a
    ``customerIdentity`` that :func:`_malformed_container` refuses are withheld there as their own fields."""
    if isinstance(kind, tuple):
        return isinstance(value, list) and all(_conforms(item, kind[1]) for item in value)
    scalar = _scalar_check(kind)
    if scalar is not None:
        return scalar(value)
    if kind == "CustomerIdentity" and _malformed_container("customeridentity", value):
        return True
    members = dict(_report_shapes()[kind])
    return isinstance(value, dict) and all(
        isinstance(key, str) and key in members and (_own_field(key) or _conforms(item, members[key]))
        for key, item in value.items()
    )


def valid_activity_id(value: Any) -> bool:
    """Whether a Reports Activity.id has its discovery shape: an object of ``applicationName`` (a Reports application
    name), ``customerId`` (a string), ``time`` (RFC 3339) and ``uniqueQualifier`` (a decimal int64 string), nothing
    else. Only such an id may name a normalised activity record."""
    return _conforms(value, "Activity.id")


def _activity_row(row: Any) -> bool:
    """Whether ``row`` is a Reports activity: its ``kind`` says so, or it has no ``kind`` and holds a member only an
    activity has (in the Google discovery documents Auditex reads, only Activity has any of them). An object of another
    ``kind`` (a normalised ``google_activity`` record, a Directory row) is not one."""
    if not isinstance(row, dict):
        return False
    if "kind" in row:
        return row["kind"] == _ACTIVITY_KIND
    activity_members = _report_members()[0]
    return any(_norm(key) in activity_members for key in row)


def _usage_report_row(row: Any) -> bool:
    return isinstance(row, dict) and (row.get("kind") == _USAGE_REPORT_KIND or ("date" in row and "parameters" in row))


def _malformed_report_field(norm: str, member: Any, *, activity: bool, usage: bool) -> bool:
    """A Reports field on a customer id path whose value does not have its documented shape (withheld whole).

    ``id`` of an activity must pass :func:`valid_activity_id`; ``resourceDetails`` must be a list of ResourceDetails,
    ``ownerDetails`` an OwnerDetails and ``ownerIdentity`` a list of OwnerIdentity, each checked through every object
    beneath it (:func:`_conforms`); ``entity`` must be an object (a UsageReport.entity on a usage report). Null, an
    empty string and ``my_customer`` hold nothing.
    """
    if _no_value(member):
        return False
    if norm == "id" and activity:
        return not valid_activity_id(member)
    if norm == "resourcedetails":
        return not _conforms(member, ("array", "ResourceDetails"))
    if norm == "entity":
        return not (_conforms(member, "UsageReport.entity") if usage else isinstance(member, dict))
    if norm == "ownerdetails":
        return not _conforms(member, "OwnerDetails")
    if norm == "owneridentity":
        return not _conforms(member, ("array", "OwnerIdentity"))
    return False


class CustomerIds:
    def __init__(self, *values: Any) -> None:
        self.values: set[str] = set()
        for value in values:
            self.add(value)

    def add(self, value: Any) -> None:
        if isinstance(value, str):
            value = value.strip()
            if value and value not in {MY_CUSTOMER, WITHHELD} and value not in self.values:
                self.values.add(value)
                self.__dict__.pop("_pattern", None)

    @cached_property
    def _pattern(self) -> re.Pattern[str] | None:
        if not self.values:
            return None
        values = "|".join(map(re.escape, sorted(self.values, key=lambda value: (-len(value), value))))
        return re.compile(rf"(?<![A-Za-z0-9])(?:{values})(?![A-Za-z0-9])")

    def text(self, value: str, marker: str = WITHHELD) -> str:
        return self._pattern.sub(lambda _: marker, value) if self._pattern else value

    def _request_text(self, text: str, *, learn: bool) -> str:
        """Learn from the named customer parameter of an API URL or an encoded Cloud Identity filter."""
        def mask(match: re.Match[str]) -> str:
            encoded = match[1].split("%22", 1)[0]
            value = unquote(encoded)
            if value == MY_CUSTOMER or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
                return match[0]
            if learn:
                self.add(value)
            elif value not in self.values:
                return match[0]
            return match[0][:match.start(1) - match.start()] + WITHHELD + match[1][len(encoded):]

        text = _URL.sub(lambda url: _REQUEST_CUSTOMER.sub(mask, url[0]), text)
        return _ENCODED_CUSTOMER_FILTER.sub(lambda query: _REQUEST_CUSTOMER.sub(mask, query[0]), text)

    def failure_text(self, text: str, *, learn: bool = True) -> str:
        """API failure text with every learned id and every customer-id-shaped token withheld."""
        if learn:
            text = self.learn_error(text)
        else:
            text = self._request_text(text, learn=False)
        return _CUSTOMER_ID_SHAPE.sub(WITHHELD, self.text(text))

    def learn_error(self, text: str) -> str:
        for match in _MISSING_CUSTOMER.finditer(text):
            self.add(match[1])
        return self._request_text(text, learn=True)

    def learn(self, value: Any, *, error: bool = False, identity: bool = False) -> None:
        if isinstance(value, dict):
            for key, member in value.items():
                norm = _norm(key)
                if _explicit_id(norm, identity=identity):
                    self.add(member)
                elif norm == "customer" and isinstance(member, str) and member.startswith("customers/"):
                    self.add(member.removeprefix("customers/"))
                # A customer identity of the wrong shape teaches nothing: its members are never read as its id.
                self.learn(member, error=error or norm in _ERROR_KEYS,
                           identity=_identity(norm, member) and not _malformed_container(norm, member))
        elif isinstance(value, (list, tuple)):
            for member in value:
                self.learn(member, error=error)
        elif error and isinstance(value, str):
            self.learn_error(value)

    def scrub(self, value: Any) -> Any:
        return self._scrub(value, error=True, failure=False)[0]

    def scrub_legacy_output(self, value: Any) -> Any:
        return self.scrub(value) if self.values else value

    def evidence(self, value: Any) -> tuple[Any, bool]:
        """Return scrubbed evidence and whether a field used as evidence could have changed."""
        return self._scrub(value, error=False, failure=False)

    def _scrub(
        self, value: Any, *, error: bool, failure: bool, identity: bool = False, rows: str | None = None,
    ) -> tuple[Any, bool]:
        """``rows`` is what a section holds: ``activities`` for a Reports stream (``<application>Activities``), whose
        rows are activities even when they carry no member that shows it, and ``activity`` for one such row."""
        if isinstance(value, dict):
            out: dict[Any, Any] = {}
            changed = False
            activity = rows == "activity" or _activity_row(value)
            usage = _usage_report_row(value)
            for key, member in value.items():
                norm = _norm(key)
                safe_key = self.text(key) if isinstance(key, str) else key
                member_rows = (
                    "activities" if norm.endswith("activities") or (rows == "activities" and norm in {"value", "items"})
                    else None
                )
                if (
                    (_explicit_id(norm, identity=identity) and not _no_value(member))
                    or _malformed_container(norm, member)
                    or _malformed_report_field(norm, member, activity=activity, usage=usage)
                ):
                    # A malformed ID field, or a customer field of the wrong shape, can contain arbitrary nested data.
                    safe_member = WITHHELD
                    member_changed = False
                elif norm == "customer" and isinstance(member, str) and member.startswith("customers/"):
                    safe_member = self.text(member)
                    member_changed = False
                else:
                    safe_member, member_changed = self._scrub(
                        member, error=error or norm in _ERROR_KEYS, failure=failure or norm in _ERROR_KEYS,
                        identity=_identity(norm, member), rows=member_rows,
                    )
                out[safe_key] = safe_member
                changed |= member_changed or (not error and safe_key != key)
            return out, changed
        if isinstance(value, (list, tuple)):
            member_rows = "activity" if rows == "activities" else None
            members = [self._scrub(member, error=error, failure=failure, rows=member_rows) for member in value]
            safe_list = [member for member, _ in members]
            return (tuple(safe_list) if isinstance(value, tuple) else safe_list), any(changed for _, changed in members)
        if isinstance(value, str):
            if failure:
                safe = self.failure_text(value, learn=False)
            else:
                safe = self.text(self._request_text(value, learn=False) if "://" in value or "%2" in value else value)
            return safe, not error and safe != value
        return value, False


_active_ids: ContextVar[CustomerIds | None] = ContextVar("google_customer_ids", default=None)


@contextmanager
def collect_customer_ids(ids: CustomerIds) -> Iterator[None]:
    token = _active_ids.set(ids)
    # The discovery library can log entire HTTP error responses before our classifier sees them.
    # Auditex emits its own diagnostics after it has learned and masked the customer IDs.
    library_logs = (
        logging.getLogger("googleapiclient.http"),
        logging.getLogger("googleapiclient.discovery"),
    )

    def outside_collection(_record: logging.LogRecord) -> bool:
        return _active_ids.get() is not ids

    for logger in library_logs:
        logger.addFilter(outside_collection)
    try:
        yield
    finally:
        for logger in library_logs:
            logger.removeFilter(outside_collection)
        _active_ids.reset(token)


def learn_response_customer_ids(response: Any) -> None:
    ids = _active_ids.get()
    if ids is not None:
        ids.learn(response)


def withhold_request_customer_ids(text: str, details: Any = None) -> str:
    ids = _active_ids.get() or CustomerIds()
    ids.learn(details, error=True)
    return ids.failure_text(text)


def legacy_google_customer_ids(manifest: Mapping[str, Any]) -> CustomerIds:
    if manifest.get("platform") == "google_workspace":
        return CustomerIds(*(manifest.get(key) for key in ("customer_id", "tenant_id", "tenant_id_requested")))
    return CustomerIds()


def withheld_coverage_row(collector: str) -> dict[str, Any]:
    return {
        "collector": collector,
        "name": "customer_id_withheld",
        "type": "privacy",
        "status": "partial",
        "item_count": 0,
        "error_class": WITHHELD_ERROR_CLASS,
        "error": "a Google customer id was withheld from the collected evidence",
    }
