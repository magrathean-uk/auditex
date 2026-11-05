"""Read-only Conditional Access scope evidence for the model assessment post-check.

The scope summary lives in ``azure_tenant_audit.scuba_scope``. This module only supplies the policies:
the projected section when there is one, else the bundle's own raw payload, so that the envelope can say
which policies are scope-narrowed even when the projection withheld the section (a location, platform
or device condition withholds it). The raw read goes through the projection's bundle reader, with its
health checks, its no-symlink opens and the same scan bounds; nothing is written.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from azure_tenant_audit.scuba_scope import SECTION, ScopeEntry, ScopeOversize, scope_entries, scope_summary

from .scuba_projection import Bundle, Unavailable, _EMAIL

_COLLECTOR, _OPERATION = "conditional_access", "conditionalAccessPolicies"
_REASONS = {"missing_artifact", "incomplete_shape", "oversize", "not_applicable_to_platform"}


@dataclass(frozen=True)
class ScopeEvidence:
    """The post-check inputs: retained entries (None when not evaluated) and the envelope record."""

    entries: list[ScopeEntry] | None
    summary: dict[str, Any]


def _mask_email(name: str) -> str:
    return _EMAIL.sub(lambda match: "***@" + match[1], name) if "@" in name else name


def _not_evaluated(reason: str) -> ScopeEvidence:
    return ScopeEvidence(None, {"status": "not_evaluated", "source": None, "reason": reason, "count": 0, "policies": []})


def _raw_entries(root: Path, bounds: tuple[int, int, int], mask: Callable[[str], str] | None) -> list[ScopeEntry]:
    bundle = Bundle(root, *bounds)
    try:
        manifest = bundle.read("run-manifest.json")
        if not isinstance(manifest, dict):
            raise Unavailable()
    except Unavailable as exc:
        if exc.reason != "missing_artifact":
            raise
        manifest = {}
    bundle.manifest = manifest
    if manifest.get("platform", "m365") != "m365":
        raise Unavailable("not_applicable_to_platform")
    # The iterator's closing checks (item count, an empty collection's completeness) run when it is exhausted.
    return scope_entries(bundle.scan(_COLLECTOR, _OPERATION), mask=mask)


def collect_scope_evidence(root: Path, projection: Any, *, redact: bool, max_items: int,
                           scan_max_rows: int, scan_max_bytes: int, scan_max_chunks: int) -> ScopeEvidence:
    """Entries from the projected section, else from the raw payload; never raises for unreadable evidence."""
    projected = projection.report["sections"].get(SECTION, {}).get("status") == "projected"
    # The projected section is already masked for the prompt. The raw names are masked for e-mail local parts the
    # same way, before they are cut to the name limit, so that a cut cannot leave part of an address visible.
    mask = None if projected or not redact else _mask_email
    try:
        entries = scope_entries(projection[SECTION], mask=mask) if projected else _raw_entries(
            root, (scan_max_rows, scan_max_bytes, scan_max_chunks), mask)
    except ScopeOversize:
        return _not_evaluated("oversize")
    except Unavailable as exc:
        return _not_evaluated(exc.reason if exc.reason in _REASONS else "incomplete_shape")
    except (ValueError, TypeError, KeyError, OverflowError):
        return _not_evaluated("incomplete_shape")
    source = "projection" if projected else "raw"
    return ScopeEvidence(entries, {"status": "evaluated", "source": source, "reason": None,
                                   **scope_summary(entries, max_items=max_items)})
