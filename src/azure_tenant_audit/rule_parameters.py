"""The thresholds a run's rules were judged with, recorded on the run manifest.

Several rules depend on an operator-set window (days without a Intune check-in, days without a guest
sign-in, Google stale-user and stale-device days). A finding that is gone from a later run was only
resolved if the later run judged it with the same window or a stricter one: a laxer window hides the
same stale object without anything having been fixed. ``run-manifest.json`` therefore records the
effective values under ``rule_parameters`` and run comparison, ``auditex compare`` and
``auditex gate-drift`` read them back.

Most parameters here are a number of days, and a larger number is laxer. The emergency-access list
(``break_glass_accounts``) is the exception: it is an operator-supplied set of principals that the
Conditional Access verdicts exempt, so a later run that lists more of them (a staff group, say) judges the
same policies as enforced and its findings vanish without anything having been fixed. The list is recorded,
and a vanished finding of a rule that reads it is only resolved when both runs used the same list.
Nothing here reads a tenant.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from . import break_glass, endpoint_posture

RULE_PARAMETERS_KEY = "rule_parameters"
RULE_PARAMETERS_SCHEMA_VERSION = "2026-10-22"
BREAK_GLASS_PARAMETER = "break_glass_accounts"

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
# The Conditional Access rules (every ``ca.*`` rule) judge the policies with the operator's emergency-access
# accounts exempted: the MFA, administrator MFA, legacy-authentication and break-glass verdicts all read the list.
BREAK_GLASS_RULE_PREFIX = "ca."


def reads_break_glass_list(rule_id: str) -> bool:
    """Whether a rule's finding depends on the emergency-access list the run was given."""
    return rule_id.startswith(BREAK_GLASS_RULE_PREFIX)


def recorded_break_glass_accounts(accounts: Iterable[str] | str | None = None) -> list[str]:
    """The emergency-access list a run judged with, as recorded: the argument, else the environment, de-duplicated.

    The same resolution the verdicts use (``--break-glass-accounts``, then ``AUDITEX_BREAK_GLASS_ACCOUNTS``),
    sorted so that two runs given the same accounts in a different order record the same list.
    """
    configured = break_glass.configured_accounts(None if accounts is None else break_glass.parse_accounts(accounts))
    return sorted(configured, key=lambda entry: (entry.lower(), entry))


def effective_rule_parameters(
    *,
    stale_sync_days: int | str | None = None,
    stale_guest_days: int | None = None,
    break_glass_accounts: Sequence[str] | str | None = None,
) -> dict[str, Any]:
    """The Microsoft 365 rule parameters in force for a run: the argument, then the environment, then the default."""
    from . import findings

    return {
        "schema_version": RULE_PARAMETERS_SCHEMA_VERSION,
        "stale_sync_days": endpoint_posture.stale_sync_days(stale_sync_days),
        "stale_guest_days": findings.stale_guest_days(stale_guest_days),
        "stale_account_days": int(getattr(findings, "_STALE_ACCOUNT_DAYS", 90)),
        BREAK_GLASS_PARAMETER: recorded_break_glass_accounts(break_glass_accounts),
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


def _accounts(parameters: Mapping[str, Any] | None) -> frozenset[str] | None:
    value = parameters.get(BREAK_GLASS_PARAMETER) if isinstance(parameters, Mapping) else None
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return None
    return frozenset(item.strip().lower() for item in value if item.strip())


def rule_parameter_gap(
    rule_id: str,
    baseline: Mapping[str, Any] | None,
    current: Mapping[str, Any] | None,
) -> str | None:
    """Why a vanished finding of ``rule_id`` cannot be called resolved because of its parameters, or ``None``.

    ``rule_parameters_unrecorded:<name>`` when either run did not record the window (the finding may
    have vanished under a laxer one, and nobody can tell), ``rule_parameters_laxer:<name>`` when the
    later run used a larger window. A smaller or equal window judged the same objects as strictly or
    more strictly, so the finding really is gone.

    A Conditional Access rule (``ca.*``, which exempts the emergency-access accounts) reads ``rule_parameters_unrecorded:break_glass_accounts``
    when either run did not record the list and ``rule_parameters_changed:break_glass_accounts`` when the two
    lists differ: a longer list exempts more principals, so the finding may have vanished because of the list.
    """
    for name in RULE_PARAMETER_NAMES.get(rule_id, ()):
        before, after = _days(baseline, name), _days(current, name)
        if before is None or after is None:
            return f"rule_parameters_unrecorded:{name}"
        if after > before:
            return f"rule_parameters_laxer:{name}"
    if reads_break_glass_list(rule_id):
        before_accounts, after_accounts = _accounts(baseline), _accounts(current)
        if before_accounts is None or after_accounts is None:
            return f"rule_parameters_unrecorded:{BREAK_GLASS_PARAMETER}"
        if before_accounts != after_accounts:
            return f"rule_parameters_changed:{BREAK_GLASS_PARAMETER}"
    return None


def changed_rule_parameters(
    baseline: Mapping[str, Any] | None, current: Mapping[str, Any] | None
) -> list[dict[str, Any]]:
    """Every window and list that differs between two runs, for the gate-drift report."""
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
    if _accounts(baseline) != _accounts(current):
        changes.append(
            {
                "parameter": BREAK_GLASS_PARAMETER,
                "baseline": _recorded_list(baseline),
                "current": _recorded_list(current),
            }
        )
    return changes


def _recorded_list(parameters: Mapping[str, Any] | None) -> list[str] | None:
    value = parameters.get(BREAK_GLASS_PARAMETER) if isinstance(parameters, Mapping) else None
    return [str(item) for item in value] if isinstance(value, list) else None
