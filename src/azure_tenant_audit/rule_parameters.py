"""The thresholds a run's rules were judged with, recorded on the run manifest.

Several rules depend on an operator-set window (days without a Intune check-in, days without a guest
sign-in, Google stale-user and stale-device days). A finding that is gone from a later run was only
resolved if the later run judged it with the same window or a stricter one: a laxer window hides the
same stale object without anything having been fixed. ``run-manifest.json`` therefore records the
effective values under ``rule_parameters`` and run comparison, ``auditex compare`` and
``auditex gate-drift`` read them back.

Every parameter here is a number of days, and a larger number is laxer. Nothing here reads a tenant.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import endpoint_posture

RULE_PARAMETERS_KEY = "rule_parameters"
RULE_PARAMETERS_SCHEMA_VERSION = "2026-10-22"

# The parameters that decide whether a rule raises a finding, per rule id. A rule that is not listed
# has no operator-set window.
RULE_PARAMETER_NAMES: dict[str, tuple[str, ...]] = {
    "intune.device_stale_sync": ("stale_sync_days",),
    "identity.stale_guest": ("stale_guest_days",),
    "identity.stale_enabled_account": ("stale_account_days",),
    "identity.privileged_stale_account": ("stale_account_days",),
    "google.stale_user": ("stale_user_days",),
    "google.admin_stale_login": ("stale_user_days",),
    "google.mobile_device_stale_sync": ("stale_device_days",),
    "google.chromeos_device_stale_sync": ("stale_device_days",),
}


def effective_rule_parameters(
    *, stale_sync_days: int | str | None = None, stale_guest_days: int | None = None
) -> dict[str, Any]:
    """The Microsoft 365 rule windows in force for a run: the argument, then the environment, then the default."""
    from . import findings

    return {
        "schema_version": RULE_PARAMETERS_SCHEMA_VERSION,
        "stale_sync_days": endpoint_posture.stale_sync_days(stale_sync_days),
        "stale_guest_days": findings.stale_guest_days(stale_guest_days),
        "stale_account_days": int(getattr(findings, "_STALE_ACCOUNT_DAYS", 90)),
    }


def google_rule_parameters(*, stale_user_days: int, stale_device_days: int) -> dict[str, Any]:
    """The Google Workspace rule windows in force for a run."""
    return {
        "schema_version": RULE_PARAMETERS_SCHEMA_VERSION,
        "stale_user_days": int(stale_user_days),
        "stale_device_days": int(stale_device_days),
    }


def recorded_rule_parameters(manifest: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """The parameters a manifest recorded, or ``None`` for a bundle written before they were recorded."""
    value = manifest.get(RULE_PARAMETERS_KEY) if isinstance(manifest, Mapping) else None
    return dict(value) if isinstance(value, Mapping) else None


def _days(parameters: Mapping[str, Any] | None, name: str) -> int | None:
    value = parameters.get(name) if isinstance(parameters, Mapping) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def rule_parameter_gap(
    rule_id: str,
    baseline: Mapping[str, Any] | None,
    current: Mapping[str, Any] | None,
) -> str | None:
    """Why a vanished finding of ``rule_id`` cannot be called resolved because of its window, or ``None``.

    ``rule_parameters_unrecorded:<name>`` when either run did not record the window (the finding may
    have vanished under a laxer one, and nobody can tell), ``rule_parameters_laxer:<name>`` when the
    later run used a larger window. A smaller or equal window judged the same objects as strictly or
    more strictly, so the finding really is gone.
    """
    for name in RULE_PARAMETER_NAMES.get(rule_id, ()):
        before, after = _days(baseline, name), _days(current, name)
        if before is None or after is None:
            return f"rule_parameters_unrecorded:{name}"
        if after > before:
            return f"rule_parameters_laxer:{name}"
    return None


def changed_rule_parameters(
    baseline: Mapping[str, Any] | None, current: Mapping[str, Any] | None
) -> list[dict[str, Any]]:
    """Every window that differs between two runs, for the gate-drift report."""
    names = sorted(
        {
            str(key)
            for source in (baseline, current)
            if isinstance(source, Mapping)
            for key, value in source.items()
            if isinstance(value, int) and not isinstance(value, bool)
        }
    )
    changes: list[dict[str, Any]] = []
    for name in names:
        before, after = _days(baseline, name), _days(current, name)
        if before != after:
            changes.append({"parameter": name, "baseline": before, "current": after})
    return changes
