"""The Google Workspace customer id never enters a run bundle, a log, a console payload or an export (PRIV-CUSTOMER-ID).

The configured ``--customer-id`` is used only for the API calls. The bundle records the ``my_customer`` alias as it is
(it names "the signed-in customer", so every tenant has it) and any other configured value as ``null``. Its tenant
identity is a keyed pseudonym of the configured id (``tenant_pseudonym``) under the operator's private tenant key, so
compare and drift still tell tenants apart without the id.

A customer id the API returns or an error quotes is withheld by shape (``C``, a digit, then five to eleven lower-case
letters and digits) and the configured value by its spelling.
Only a value under an id-bearing key (``customerId``, a policy's ``customers/...`` name) or text matching that shape
is changed: an organisational-unit path such as ``/customers/Finance`` is kept as it is. A value under ``customerId``
that is not text (a malformed object or list) is withheld whole.
"""

from __future__ import annotations

import re
from typing import Any

from ..tenant_pseudonym import TenantKeyError, tenant_pseudonym  # noqa: F401 (re-exported for the run)

MY_CUSTOMER = "my_customer"
WITHHELD = "<customer-id>"
# The coverage row a collector gets when its evidence (not its error text) held a customer id that was withheld: the
# read can no longer be shown complete, since a withheld value may have been an organisational unit's name.
WITHHELD_ERROR_CLASS = "customer_id_withheld"

_WORD = "0-9A-Za-z_"
# Google's customer id: ``C``, a digit, then its alphabet of lower-case letters and digits (``C03az79cb``). Inside text
# it is a whole token, never part of a longer word, so a word such as ``Config2`` is not one.
_ID = "C[0-9][0-9a-z]{5,11}"
_ID_RE = re.compile(rf"(?<![{_WORD}]){_ID}(?![{_WORD}])")
# A URL-encoded resource name (``customers%2FC0abc``) puts a letter right before the id.
_ENCODED_RE = re.compile(rf"(?i:(customers?%2F)){_ID}(?![{_WORD}])")
# Keys whose text is failure text (a coverage row's ``error``, an exception message, an API error reason).
_ERROR_KEYS = frozenset({"error", "errors", "message", "reason", "detail", "details", "errormessage", "statusmessage"})


def bundle_customer_id(value: Any) -> str | None:
    """The configured customer id as a bundle records it: the ``my_customer`` alias, else ``None``."""
    return MY_CUSTOMER if isinstance(value, str) and value.strip() == MY_CUSTOMER else None


def _configured(value: Any) -> str | None:
    text = value.strip() if isinstance(value, str) else ""
    return text if len(text) >= 4 and text != MY_CUSTOMER else None


def withhold_customer_text(text: str, configured: Any = None) -> str:
    """``text`` with every customer-id-shaped token and the configured id itself replaced by the marker."""
    literal = _configured(configured)
    if literal:
        text = text.replace(literal, WITHHELD)
    text = _ENCODED_RE.sub(lambda m: m.group(1) + WITHHELD, text)
    return _ID_RE.sub(WITHHELD, text)


def _norm(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


class _Walk:
    def __init__(self, configured: Any) -> None:
        self.configured = configured
        self.evidence_changed = False

    def text(self, value: str, *, error: bool) -> str:
        safe = withhold_customer_text(value, self.configured)
        if safe != value and not error:
            self.evidence_changed = True
        return safe

    def value(self, value: Any, *, error: bool = False) -> Any:
        if isinstance(value, dict):
            out: dict[Any, Any] = {}
            for key, member in value.items():
                norm = _norm(key)
                if norm == "customerid":
                    keep = member is None or member == "" or (isinstance(member, str) and member.strip() == MY_CUSTOMER)
                    out[key] = member if keep else WITHHELD
                elif norm == "customer" and isinstance(member, str) and member.startswith("customers/"):
                    rest = member.removeprefix("customers/")
                    out[key] = member if rest == MY_CUSTOMER else "customers/" + WITHHELD
                else:
                    out[key] = self.value(member, error=error or norm in _ERROR_KEYS)
            return out
        if isinstance(value, list):
            return [self.value(member, error=error) for member in value]
        if isinstance(value, tuple):
            return tuple(self.value(member, error=error) for member in value)
        if isinstance(value, str):
            return self.text(value, error=error)
        return value


def withhold_customer_ids(value: Any, configured: Any = None) -> Any:
    """A copy of ``value`` with no customer id. Keys, types and shapes are unchanged except that a non-text value under
    a ``customerId`` key becomes the marker."""
    return _Walk(configured).value(value)


def withhold_customer_evidence(value: Any, configured: Any = None) -> tuple[Any, bool]:
    """``withhold_customer_ids`` and whether any evidence text (not an id-bearing field, not failure text) changed."""
    walk = _Walk(configured)
    return walk.value(value), walk.evidence_changed


def withheld_coverage_row(collector: str) -> dict[str, Any]:
    """The partial coverage row for a collector whose evidence text held a customer id."""
    return {
        "collector": collector,
        "name": "customer_id_withheld",
        "type": "privacy",
        "status": "partial",
        "item_count": 0,
        "error_class": WITHHELD_ERROR_CLASS,
        "error": "a value shaped like a Google customer id was withheld from the collected evidence",
    }


class CustomerIdWithheldCollector:
    """A collector whose result (payload, coverage rows, message, error) and crash text carry no customer id, so the
    runner writes none to the raw file, the coverage index, the checkpoint or the run log. Evidence that held one is
    reported partial, never complete."""

    def __init__(self, collector: Any, configured: Any) -> None:
        self._collector = collector
        self._configured = configured

    def __getattr__(self, name: str) -> Any:
        return getattr(self._collector, name)

    def run(self, context: Any) -> Any:
        try:
            result = self._collector.run(context)
        except Exception as exc:
            text = str(exc)
            safe = withhold_customer_text(text, self._configured)
            if safe == text:
                raise
            raise RuntimeError(safe) from None
        result.payload, changed = withhold_customer_evidence(result.payload, self._configured)
        result.coverage = withhold_customer_ids(result.coverage, self._configured)
        result.message = withhold_customer_text(result.message, self._configured) if isinstance(result.message, str) else result.message
        result.error = withhold_customer_text(result.error, self._configured) if isinstance(result.error, str) else result.error
        if changed:
            name = str(getattr(self._collector, "name", "") or getattr(result, "name", ""))
            result.coverage = [*(result.coverage or []), withheld_coverage_row(name)]
            if result.status == "ok":
                result.status = "partial"
        return result
