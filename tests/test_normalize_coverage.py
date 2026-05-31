"""A7: every collector in the registry must be consumed by normalize, or
listed in the documented-exceptions set. This test fails the build if a new
collector is added without wiring it into normalize."""
from __future__ import annotations

import re
from pathlib import Path

from azure_tenant_audit.collectors import REGISTRY


_NORMALIZE_PATH = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "azure_tenant_audit"
    / "normalize.py"
)


# Collectors that intentionally bypass normalize. Keep rationales beside the
# exceptions so they stay with the test that enforces the coverage rule.
_INTENTIONAL_EXCEPTIONS = {
    "security",  # sign-ins / directory-audits — too noisy to flatten
    "teams",     # overlaps with groups (M365 groups + Team flag)
}


def test_every_collector_is_consumed_by_normalize() -> None:
    """Walks the registry and confirms each collector name appears as a
    ``collector_payloads.get("<name>"...)`` call inside normalize.py."""
    source = _NORMALIZE_PATH.read_text(encoding="utf-8")
    consumed = set(re.findall(r'collector_payloads\.get\("([a-z_]+)"', source))

    missing = []
    for name in REGISTRY:
        if name in _INTENTIONAL_EXCEPTIONS:
            continue
        if name not in consumed:
            missing.append(name)

    assert not missing, (
        f"Collectors not consumed by normalize.py and not on the exceptions "
        f"list: {sorted(missing)}. Either add a section in normalize.py or "
        f"add the collector name to the exceptions set with a documented "
        f"rationale."
    )


def test_intentional_exceptions_match_registry() -> None:
    """Prevent the exceptions set from drifting away from the registry — a
    rename would silently mask the coverage gap otherwise."""
    stale = _INTENTIONAL_EXCEPTIONS - set(REGISTRY)
    assert not stale, (
        f"Exceptions list references non-existent collectors {sorted(stale)}. "
        f"Update either REGISTRY or the exceptions set."
    )
