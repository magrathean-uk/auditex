"""A6: shape parity for capability-gated collectors.

When a tenant lacks the underlying license (Power Platform admin, Sentinel
workspace, Defender for Cloud Apps, Copilot governance), the gated collector
must degrade to a structured diagnostic rather than crashing the run. This
file pins the contract: every gated collector emits coverage rows with the
canonical 9 keys, and at least one row carries
``status="skipped"`` plus ``error_class in {"service_not_available","insufficient_permissions"}``.
"""
from __future__ import annotations

import pytest

from azure_tenant_audit.collectors import REGISTRY


_CANONICAL_COVERAGE_KEYS = {
    "collector",
    "type",
    "name",
    "endpoint",
    "status",
    "item_count",
    "duration_ms",
    "error_class",
    "error",
}

_GATED_COLLECTORS = (
    "power_platform",
    "sentinel_xdr",
    "defender_cloud_apps",
    "copilot_governance",
    "identity_protection",
)

_VALID_GATED_ERROR_CLASSES = {"service_not_available", "insufficient_permissions"}


@pytest.mark.parametrize("collector_name", _GATED_COLLECTORS)
def test_capability_gated_collector_emits_canonical_coverage_shape(
    collector_name: str,
) -> None:
    """Every gated collector must produce coverage rows with all 9 canonical keys."""
    collector = REGISTRY[collector_name]
    result = collector.run({})  # No client(s), no licence — gated path

    assert result.status in {"partial", "ok"}, (
        f"{collector_name}.run({{}}) must not raise or return failed; got {result.status}"
    )
    assert result.coverage is not None and result.coverage, (
        f"{collector_name} must emit coverage rows even when gated"
    )
    for row in result.coverage:
        missing = _CANONICAL_COVERAGE_KEYS - row.keys()
        extra = row.keys() - _CANONICAL_COVERAGE_KEYS
        assert not missing, f"{collector_name}: coverage row missing keys {missing}"
        assert not extra, f"{collector_name}: coverage row has unexpected keys {extra}"
        assert isinstance(row["status"], str)
        assert isinstance(row["item_count"], int)
        assert isinstance(row["duration_ms"], (int, float))


@pytest.mark.parametrize("collector_name", _GATED_COLLECTORS)
def test_capability_gated_collector_emits_skip_diagnostic_with_known_error_class(
    collector_name: str,
) -> None:
    """At least one coverage row from the gated path must surface a structured
    ``service_not_available`` or ``insufficient_permissions`` diagnostic."""
    collector = REGISTRY[collector_name]
    result = collector.run({})

    skip_rows = [
        row
        for row in (result.coverage or [])
        if row.get("status") == "skipped" and row.get("error_class") in _VALID_GATED_ERROR_CLASSES
    ]
    assert skip_rows, (
        f"{collector_name} did not emit a skip-row with a known error_class; got: "
        f"{[(r.get('status'), r.get('error_class')) for r in (result.coverage or [])]}"
    )


@pytest.mark.parametrize("collector_name", _GATED_COLLECTORS)
def test_capability_gated_collector_payload_remains_well_formed(
    collector_name: str,
) -> None:
    """Even when gated, the payload must be a dict with each declared section
    present and shaped as ``{value: [...]}``. Downstream normalisation depends
    on this contract; a missing key cascades into evidence-DB rebuild errors.
    """
    collector = REGISTRY[collector_name]
    result = collector.run({})

    assert isinstance(result.payload, dict)
    for key, section in result.payload.items():
        assert isinstance(section, dict), (
            f"{collector_name}: payload[{key!r}] is not a dict ({type(section).__name__})"
        )
        assert "value" in section, (
            f"{collector_name}: payload[{key!r}] missing 'value' key"
        )
