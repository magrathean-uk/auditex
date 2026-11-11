from __future__ import annotations

from collections.abc import Iterable

from .presets import resolve_collector_selection


def select_collectors(
    *,
    available: Iterable[str],
    profile_default_collectors: Iterable[str] = (),
    preset_name: str | None = None,
    presets: dict[str, object] | None = None,
    explicit_collectors: list[str] | None = None,
    excluded_collectors: list[str] | None = None,
    include_exchange: bool = False,
    auth_mode: str = "app",
) -> list[str]:
    ordered_available = list(available)
    selected = resolve_collector_selection(
        available=ordered_available,
        profile_default_collectors=tuple(profile_default_collectors),
        preset_name=preset_name,
        presets=presets or {},
        explicit_collectors=explicit_collectors,
        excluded_collectors=excluded_collectors,
    )
    if auth_mode != "app" and not explicit_collectors:
        selected = [name for name in selected if name not in {"exchange_policy", "dns_posture"}]
        if not selected:
            raise ValueError("No collectors selected for this authentication mode.")
    excluded = set(excluded_collectors or [])
    if include_exchange and "exchange" in ordered_available and "exchange" not in excluded and "exchange" not in selected:
        selected.append("exchange")
    return selected
