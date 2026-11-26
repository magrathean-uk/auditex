"""Learn Google customer IDs from explicit fields and requests, then withhold their values."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from functools import cached_property
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

    def learn(self, value: Any, *, error: bool = False) -> None:
        if isinstance(value, dict):
            for key, member in value.items():
                norm = _norm(key)
                if norm == "customerid":
                    self.add(member)
                elif norm == "customer" and isinstance(member, str) and member.startswith("customers/"):
                    self.add(member.removeprefix("customers/"))
                self.learn(member, error=error or norm in _ERROR_KEYS)
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

    def _scrub(self, value: Any, *, error: bool, failure: bool) -> tuple[Any, bool]:
        if isinstance(value, dict):
            out: dict[Any, Any] = {}
            changed = False
            for key, member in value.items():
                norm = _norm(key)
                safe_key = self.text(key) if isinstance(key, str) else key
                if norm == "customerid" and member is not None and member != "" and bundle_customer_id(member) is None:
                    # A malformed ID field can contain arbitrary nested data.
                    safe_member = WITHHELD
                    member_changed = False
                elif norm == "customer" and isinstance(member, str) and member.startswith("customers/"):
                    safe_member = self.text(member)
                    member_changed = False
                else:
                    safe_member, member_changed = self._scrub(
                        member, error=error or norm in _ERROR_KEYS, failure=failure or norm in _ERROR_KEYS,
                    )
                out[safe_key] = safe_member
                changed |= member_changed or (not error and safe_key != key)
            return out, changed
        if isinstance(value, (list, tuple)):
            members = [self._scrub(member, error=error, failure=failure) for member in value]
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
