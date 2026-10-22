"""Operating-system end of life, read from the dated table in ``configs/os-end-of-life.json``.

Intune reports ``operatingSystem`` ("Windows", "iOS", "macOS", "Android") and ``osVersion`` as text.
This module turns the pair into one of four states and never guesses:

* ``supported`` - the release is in the table and its end-of-support date has not passed (or the
  vendor still patches it and has published no end date).
* ``past_end_of_life`` - the release is in the table and every edition's end-of-support date has passed,
  including the Long-Term Servicing edition that shares a Windows build.
* ``edition_dependent`` - Windows only: the Home and Pro date has passed but the Enterprise and Education
  date has not, or the general date has passed but a Long-Term Servicing (LTSC, LTSB, IoT) edition that
  shares the build is still supported, and ``osVersion`` does not show the edition, so the device may or
  may not be supported.
* ``unknown`` - the version is missing or cannot be parsed, the platform is not covered, or the release is
  not in the table. The reason says which. Unknown is never reported as supported.

The table is shipped with the product and read from disk only; a lookup makes no network call. Dates
are compared with the ``today`` the caller passes, so a run is reproducible for a fixed date.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Any

from .resources import resolve_resource_path

TABLE_PATH = Path("configs/os-end-of-life.json")

FAMILY_WINDOWS = "windows"
FAMILY_MACOS = "macos"
FAMILY_IOS = "ios"
FAMILY_ANDROID = "android"
FAMILIES = (FAMILY_WINDOWS, FAMILY_MACOS, FAMILY_IOS, FAMILY_ANDROID)
MOBILE_FAMILIES = frozenset({FAMILY_IOS, FAMILY_ANDROID})

STATE_SUPPORTED = "supported"
STATE_PAST_END_OF_LIFE = "past_end_of_life"
STATE_EDITION_DEPENDENT = "edition_dependent"
STATE_UNKNOWN = "unknown"

REASON_VERSION_MISSING = "os_version_missing"
REASON_VERSION_UNPARSABLE = "os_version_unparsable"
REASON_PLATFORM_NOT_COVERED = "platform_not_covered"
REASON_NOT_IN_TABLE = "release_not_in_table"

_WINDOWS_VERSION = re.compile(r"^\s*(\d+)\.(\d+)\.(\d+)(?:\.\d+)*\s*$")
_LEADING_NUMBER = re.compile(r"^\s*v?(\d+)(?:\.\d+)*")
_NO_VERSION_WORDS = frozenset({"", "unknown", "n/a", "none", "null"})


@dataclass(frozen=True)
class Lifecycle:
    """The outcome of one lookup; ``state`` decides, the rest is evidence for a finding."""

    state: str
    family: str | None = None
    reason: str | None = None
    release_id: str | None = None
    release_name: str | None = None
    end_of_support: str | None = None
    end_of_support_home_pro: str | None = None
    ltsc_end_of_support: str | None = None
    extended_support_until: str | None = None
    confidence: str | None = None
    basis: str | None = None
    sources: tuple[str, ...] = field(default_factory=tuple)
    note: str | None = None

    def evidence(self) -> dict[str, Any]:
        """Non-empty fields, for the ``evidence`` block of a finding."""
        fields = {
            "state": self.state,
            "os_family": self.family,
            "reason": self.reason,
            "release": self.release_name,
            "end_of_support": self.end_of_support,
            "end_of_support_home_pro": self.end_of_support_home_pro,
            "ltsc_end_of_support": self.ltsc_end_of_support,
            "extended_support_until": self.extended_support_until,
            "confidence": self.confidence,
            "basis": self.basis,
            "sources": list(self.sources) or None,
            "note": self.note,
        }
        return {key: value for key, value in fields.items() if value not in (None, "", [])}


@lru_cache(maxsize=1)
def load_table() -> dict[str, Any]:
    """The shipped table, or an empty one when it cannot be read (every lookup is then unknown)."""
    try:
        payload = json.loads(resolve_resource_path(TABLE_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def table_verified_on(table: dict[str, Any] | None = None) -> str | None:
    value = (table if table is not None else load_table()).get("verified_on")
    return str(value) if value else None


def os_family(operating_system: Any) -> str | None:
    """``windows``, ``macos``, ``ios`` or ``android`` for an Intune ``operatingSystem`` value, else ``None``."""
    text = str(operating_system or "").strip().lower()
    if not text:
        return None
    # Windows Server shares build numbers with Windows 10 releases but follows its own lifecycle.
    if text.startswith("windows") and "phone" not in text and "server" not in text:
        return FAMILY_WINDOWS
    if text.startswith(("ios", "ipados", "iphone", "ipad")):
        return FAMILY_IOS
    if text.startswith(("macos", "mac os", "osx")):
        return FAMILY_MACOS
    if text.startswith("android"):
        return FAMILY_ANDROID
    return None


def _iso_date(value: Any) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None


def _release_key(family: str, os_version: str) -> int | None:
    """The number the table matches on: the Windows build, or the major version of the other platforms."""
    if family == FAMILY_WINDOWS:
        match = _WINDOWS_VERSION.match(os_version)
        # Windows 10 and 11 both report 10.0.<build>; any other kernel version is not in the table.
        return int(match.group(3)) if match and (match.group(1), match.group(2)) == ("10", "0") else None
    match = _LEADING_NUMBER.match(os_version)
    return int(match.group(1)) if match else None


def _releases(table: dict[str, Any], family: str) -> list[dict[str, Any]]:
    platforms = table.get("platforms")
    platform = platforms.get(family) if isinstance(platforms, dict) else None
    releases = platform.get("releases") if isinstance(platform, dict) else None
    return [row for row in releases if isinstance(row, dict)] if isinstance(releases, list) else []


def lookup(operating_system: Any, os_version: Any, table: dict[str, Any] | None = None) -> tuple[str | None, dict[str, Any] | None, str | None]:
    """``(family, release, reason)``: the table row for the device, or the reason there is none.

    The result does not depend on the date, so it is safe to count in normalization.
    """
    table = table if table is not None else load_table()
    family = os_family(operating_system)
    if family is None:
        return None, None, REASON_PLATFORM_NOT_COVERED
    text = str(os_version or "").strip()
    if text.lower() in _NO_VERSION_WORDS:
        return family, None, REASON_VERSION_MISSING
    key = _release_key(family, text)
    if key is None:
        # A Windows version that is not 10.0.<build> is a release the table does not describe, not garbage.
        return family, None, (REASON_NOT_IN_TABLE if family == FAMILY_WINDOWS and _WINDOWS_VERSION.match(text) else REASON_VERSION_UNPARSABLE)
    releases = _releases(table, family)
    match_field = "build" if family == FAMILY_WINDOWS else "major"
    for row in releases:
        if row.get(match_field) == key:
            return family, row, None
    for row in releases:
        below = row.get("major_below")
        if family != FAMILY_WINDOWS and isinstance(below, int) and not isinstance(below, bool) and key < below:
            return family, row, None
    return family, None, REASON_NOT_IN_TABLE


def classify(operating_system: Any, os_version: Any, today: date, table: dict[str, Any] | None = None) -> Lifecycle:
    """Lifecycle state of one device on ``today``."""
    family, release, reason = lookup(operating_system, os_version, table)
    if release is None:
        return Lifecycle(state=STATE_UNKNOWN, family=family, reason=reason)
    end = _iso_date(release.get("end_of_support"))
    earliest = _iso_date(release.get("end_of_support_home_pro"))
    ltsc = _iso_date(release.get("ltsc_end_of_support"))
    if (end is None and release.get("end_of_support")) or (ltsc is None and release.get("ltsc_end_of_support")):
        # A date that does not parse is not a date; never read it as "still supported".
        state, reason = STATE_UNKNOWN, REASON_NOT_IN_TABLE
    elif end is None:
        state = STATE_SUPPORTED
    elif today > (max(end, ltsc) if ltsc else end):
        # Every edition that shares the build, the Long-Term Servicing one included, is past its date.
        state = STATE_PAST_END_OF_LIFE
    elif ltsc is not None and today > end:
        state = STATE_EDITION_DEPENDENT
    elif earliest is not None and today > earliest:
        state = STATE_EDITION_DEPENDENT
    else:
        state = STATE_SUPPORTED
    sources = release.get("sources")
    return Lifecycle(
        state=state,
        family=family,
        reason=reason if state == STATE_UNKNOWN else None,
        release_id=str(release.get("id") or "") or None,
        release_name=str(release.get("name") or "") or None,
        end_of_support=str(release["end_of_support"]) if release.get("end_of_support") else None,
        end_of_support_home_pro=str(release["end_of_support_home_pro"]) if release.get("end_of_support_home_pro") else None,
        ltsc_end_of_support=str(release["ltsc_end_of_support"]) if release.get("ltsc_end_of_support") else None,
        extended_support_until=str(release["extended_support_until"]) if release.get("extended_support_until") else None,
        confidence=str(release.get("confidence") or "") or None,
        basis=str(release.get("basis") or "") or None,
        sources=tuple(str(item) for item in sources) if isinstance(sources, list) else (),
        note=str(release.get("note") or "") or None,
    )
