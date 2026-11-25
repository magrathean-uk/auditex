"""The Google Workspace customer id never enters a run bundle (PRIV-CUSTOMER-ID).

The configured ``--customer-id`` is used only for the API calls. The bundle records the ``my_customer`` alias as it is
(it names "the signed-in customer", so every tenant has it) and any other configured value as ``null``. A customer id
the API returns (a ``customerId`` field, a Cloud Identity policy's ``customer`` name) or an error text quotes (the
request URL of a failed read) is replaced by a fixed marker before it reaches a raw file, a coverage row, a log or a
normalised record.
"""

from __future__ import annotations

import re
from typing import Any

from azure_tenant_audit.output_redaction import google_customer_id

MY_CUSTOMER = "my_customer"
WITHHELD = "<customer-id>"

# A request URL's customer, in a path (``/customer/C0abc/roles``, ``customers/C0abc``, ``customers%2FC0abc``) or a
# query (``?customer=C0abc``, ``&customerId=C0abc``).
_PATH_RE = re.compile(r"(?i)((?<![A-Za-z_])customers?(?:/|%2F))[A-Za-z0-9_-]+")
_QUERY_RE = re.compile(r"(?i)([?&]customer(?:Id)?=)[^&#\s\"'<>]+")


def bundle_customer_id(value: Any) -> str | None:
    """The configured customer id as a bundle records it: the ``my_customer`` alias, else ``None``."""
    return MY_CUSTOMER if isinstance(value, str) and value.strip() == MY_CUSTOMER else None


def withhold_customer_text(text: str, configured: Any = None) -> str:
    """``text`` with every customer id in a request URL, and the configured id itself, replaced by the marker."""
    text = _QUERY_RE.sub(lambda m: m.group(1) + WITHHELD, _PATH_RE.sub(lambda m: m.group(1) + WITHHELD, text))
    literal = google_customer_id(configured)
    return text.replace(literal, WITHHELD) if literal else text


def _norm(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def withhold_customer_ids(value: Any, configured: Any = None) -> Any:
    """A copy of ``value`` with no customer id: values under a ``customerId`` (or ``customer_id``) key and a policy's
    ``customer`` name become the marker (the ``my_customer`` alias and empty values are kept), and every string is
    passed through :func:`withhold_customer_text`. Keys, types and shapes are unchanged."""
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, member in value.items():
            norm = _norm(key)
            if norm == "customerid" and isinstance(member, str) and member.strip() and member.strip() != MY_CUSTOMER:
                out[key] = WITHHELD
            elif norm == "customer" and isinstance(member, str) and member.startswith("customers/"):
                out[key] = "customers/" + WITHHELD
            else:
                out[key] = withhold_customer_ids(member, configured)
        return out
    if isinstance(value, list):
        return [withhold_customer_ids(member, configured) for member in value]
    if isinstance(value, tuple):
        return tuple(withhold_customer_ids(member, configured) for member in value)
    if isinstance(value, str):
        return withhold_customer_text(value, configured)
    return value


class CustomerIdWithheldCollector:
    """A collector whose result (payload, coverage rows, message, error) and crash text carry no customer id, so the
    runner writes none to the raw file, the coverage index, the checkpoint or the run log."""

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
        result.payload = withhold_customer_ids(result.payload, self._configured)
        result.coverage = withhold_customer_ids(result.coverage, self._configured)
        result.message = withhold_customer_ids(result.message, self._configured)
        result.error = withhold_customer_ids(result.error, self._configured)
        return result
