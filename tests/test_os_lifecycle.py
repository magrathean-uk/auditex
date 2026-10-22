"""The dated operating-system end-of-life table and the lookup that reads it."""
from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit import os_lifecycle
from azure_tenant_audit.os_lifecycle import (
    REASON_NOT_IN_TABLE,
    REASON_PLATFORM_NOT_COVERED,
    REASON_VERSION_MISSING,
    REASON_VERSION_UNPARSABLE,
    STATE_EDITION_DEPENDENT,
    STATE_PAST_END_OF_LIFE,
    STATE_SUPPORTED,
    STATE_UNKNOWN,
    classify,
    os_family,
)

_TABLE_PATH = Path(__file__).resolve().parent.parent / "configs" / "os-end-of-life.json"
_TABLE: dict[str, Any] = json.loads(_TABLE_PATH.read_text(encoding="utf-8"))
_VERIFIED = date.fromisoformat(_TABLE["verified_on"])
_BASES = {"vendor_lifecycle", "apple_n_minus_2_practice", "apple_last_security_release", "aosp_last_security_bulletin"}
_STATUSES = {"supported", "end_of_life", "edition_dependent"}
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}")
_TODAY = date(2026, 10, 22)


def _releases() -> list[tuple[str, dict[str, Any]]]:
    return [(family, row) for family, platform in _TABLE["platforms"].items() for row in platform["releases"]]


def _date(value: Any) -> date | None:
    return date.fromisoformat(value) if value else None


# ---- the table ------------------------------------------------------------------------------------------


def test_the_table_records_when_it_was_verified_and_covers_the_four_platform_families() -> None:
    assert _ISO.fullmatch(_TABLE["verified_on"]) and _VERIFIED <= date.today()
    assert _ISO.fullmatch(_TABLE["schema_version"])
    assert set(_TABLE["platforms"]) == set(os_lifecycle.FAMILIES)
    for family, platform in _TABLE["platforms"].items():
        assert platform["match"] == ("build" if family == "windows" else "major"), family
        assert platform["releases"], family
    assert _TABLE["_documentation"].strip() and _TABLE["scope"].strip()


def test_every_release_has_an_identity_a_basis_a_confidence_and_https_sources() -> None:
    ids = [row["id"] for _family, row in _releases()]
    assert len(ids) == len(set(ids)), "release ids must be unique"
    for family, row in _releases():
        assert re.fullmatch(r"[a-z0-9-]+", row["id"]) and row["name"].strip(), row["id"]
        assert row["basis"] in _BASES, row["id"]
        assert row["confidence"] in {"vendor_published", "derived"}, row["id"]
        assert row["status"] in _STATUSES, row["id"]
        assert isinstance(row["sources"], list) and row["sources"], f"{row['id']} has no source"
        assert all(url.startswith("https://") for url in row["sources"]), row["id"]
        # A date the vendor publishes is cited from the vendor; Apple and Android dates are derived and say so.
        if row["confidence"] == "vendor_published":
            assert row["basis"] == "vendor_lifecycle" and family == "windows", row["id"]
            assert any(url.startswith("https://learn.microsoft.com/") for url in row["sources"]), row["id"]
        else:
            assert family != "windows" and row.get("note"), row["id"]


def test_releases_are_keyed_uniquely_on_the_build_or_the_major_version() -> None:
    for family, platform in _TABLE["platforms"].items():
        keys = []
        for row in platform["releases"]:
            if family == "windows":
                assert isinstance(row["build"], int) and "major" not in row and "major_below" not in row, row["id"]
                keys.append(row["build"])
            else:
                assert ("major" in row) != ("major_below" in row), row["id"]
                assert all(isinstance(row.get(name, 0), int) for name in ("major", "major_below")), row["id"]
                keys.append(row.get("major", f"below-{row.get('major_below')}"))
        assert len(keys) == len(set(keys)), family


def test_dates_are_iso_and_ordered() -> None:
    for _family, row in _releases():
        for name in ("end_of_support", "end_of_support_home_pro", "ltsc_end_of_support", "extended_support_until"):
            assert row.get(name) is None or _ISO.fullmatch(row[name]), (row["id"], name)
        end, earliest, ltsc, extended = (
            _date(row.get(name)) for name in ("end_of_support", "end_of_support_home_pro", "ltsc_end_of_support", "extended_support_until")
        )
        if earliest:
            assert end and earliest <= end, row["id"]
        if ltsc:
            assert end and ltsc >= end, row["id"]
        if extended:
            assert end and extended >= end, row["id"]


def test_status_agrees_with_the_dates_on_the_verification_date() -> None:
    """No release whose last day has passed is called supported, and none without a date lacks a source and a note."""
    for _family, row in _releases():
        end, earliest, ltsc = (_date(row.get(name)) for name in ("end_of_support", "end_of_support_home_pro", "ltsc_end_of_support"))
        if end is None:
            assert row["status"] == "supported", row["id"]
            # A release with no end date is "still patched" only because the vendor says so; the entry must say where.
            assert row["sources"] and row.get("note"), f"{row['id']} is current with no cited evidence"
        elif _VERIFIED > (max(end, ltsc) if ltsc else end):
            assert row["status"] == "end_of_life", f"{row['id']} ended {end} but is labelled {row['status']}"
        elif (ltsc and _VERIFIED > end) or (earliest and _VERIFIED > earliest):
            assert row["status"] == "edition_dependent", row["id"]
        else:
            assert row["status"] == "supported", row["id"]


def test_the_windows_table_covers_every_release_of_windows_10_and_11_that_intune_reports() -> None:
    builds = {row["build"] for row in _TABLE["platforms"]["windows"]["releases"]}
    # Windows 10 1507 to 22H2 and Windows 11 21H2 to 26H2.
    assert {10240, 14393, 17763, 19044, 19045, 22000, 22621, 22631, 26100, 26200, 28000, 26300} <= builds
    windows_10 = next(row for row in _TABLE["platforms"]["windows"]["releases"] if row["build"] == 19045)
    assert windows_10["end_of_support"] == "2025-10-14"
    assert windows_10["extended_support_until"] == "2028-10-10", "the paid ESU window must be recorded"


def test_every_build_a_long_term_servicing_edition_shares_records_its_later_end_date() -> None:
    by_build = {row["build"]: row for row in _TABLE["platforms"]["windows"]["releases"]}
    # LTSC 2019 (17763), LTSC 2021 and IoT LTSC 2021 (19044), LTSC and IoT LTSC 2024 (26100), LTSB 2016 (14393) and 2015 (10240).
    assert {build: by_build[build].get("ltsc_end_of_support") for build in (10240, 14393, 17763, 19044, 26100)} == {
        10240: "2025-10-14",
        14393: "2026-10-13",
        17763: "2029-01-09",
        19044: "2032-01-13",
        26100: "2034-10-10",
    }
    # Builds with no Long-Term Servicing release carry no such date.
    assert all("ltsc_end_of_support" not in row for build, row in by_build.items() if build not in (10240, 14393, 17763, 19044, 26100))


def test_lifecycle_lookups_use_only_the_shipped_table(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("a lifecycle lookup must not touch the network")

    import socket

    monkeypatch.setattr(socket, "socket", refuse)
    assert classify("Windows", "10.0.19045.5371", _TODAY).state == STATE_PAST_END_OF_LIFE


# ---- classification -------------------------------------------------------------------------------------


def test_windows_builds_are_judged_on_their_end_of_support_date() -> None:
    windows_10 = classify("Windows", "10.0.19045.5371", _TODAY)
    assert windows_10.state == STATE_PAST_END_OF_LIFE
    assert windows_10.release_name == "Windows 10 22H2" and windows_10.end_of_support == "2025-10-14"
    assert windows_10.extended_support_until == "2028-10-10" and windows_10.confidence == "vendor_published"
    assert any("learn.microsoft.com" in url for url in windows_10.sources)
    assert classify("Windows", "10.0.26200.6584", _TODAY).state == STATE_SUPPORTED
    assert classify("Windows", "10.0.22000.1", _TODAY).state == STATE_PAST_END_OF_LIFE


def test_the_last_day_is_still_supported_and_the_day_after_is_not() -> None:
    assert classify("Windows", "10.0.19045.1", date(2025, 10, 14)).state == STATE_SUPPORTED
    assert classify("Windows", "10.0.19045.1", date(2025, 10, 15)).state == STATE_PAST_END_OF_LIFE


def test_a_windows_build_a_long_term_servicing_edition_shares_is_edition_dependent_until_that_edition_ends() -> None:
    # 1809: general availability ended 2021-05-11, LTSC 2019 runs to 2029-01-09; osVersion does not show the edition.
    assert classify("Windows", "10.0.17763.5000", _TODAY).state == STATE_EDITION_DEPENDENT
    assert classify("Windows", "10.0.17763.5000", date(2029, 1, 9)).state == STATE_EDITION_DEPENDENT
    assert classify("Windows", "10.0.17763.5000", date(2029, 1, 10)).state == STATE_PAST_END_OF_LIFE
    assert classify("Windows", "10.0.17763.5000", date(2021, 5, 11)).state == STATE_EDITION_DEPENDENT, "Home/Pro ended earlier still"
    assert classify("Windows", "10.0.17763.5000", date(2020, 1, 1)).state == STATE_SUPPORTED
    # 21H2 and its LTSC 2021 / IoT LTSC 2021 (to 2032-01-13), and the 24H2 LTSC 2024 (to 2034-10-10 for IoT).
    result = classify("Windows", "10.0.19044.4000", _TODAY)
    assert result.state == STATE_EDITION_DEPENDENT and result.ltsc_end_of_support == "2032-01-13"
    assert result.evidence()["ltsc_end_of_support"] == "2032-01-13"
    assert classify("Windows", "10.0.19044.4000", date(2032, 1, 14)).state == STATE_PAST_END_OF_LIFE
    assert classify("Windows", "10.0.26100.6584", date(2027, 10, 13)).state == STATE_EDITION_DEPENDENT
    # LTSB 2016 ended 2026-10-13, so build 14393 is past end of life for every edition from 2026-10-14.
    assert classify("Windows", "10.0.14393.7000", date(2026, 10, 13)).state == STATE_EDITION_DEPENDENT
    assert classify("Windows", "10.0.14393.7000", _TODAY).state == STATE_PAST_END_OF_LIFE
    # Builds with no Long-Term Servicing edition are unaffected: Windows 10 22H2 is past end of life for everyone.
    assert classify("Windows", "10.0.19045.5371", _TODAY).state == STATE_PAST_END_OF_LIFE


def test_a_windows_build_between_the_home_pro_and_enterprise_dates_depends_on_the_edition() -> None:
    # 24H2: Home and Pro ended 2026-10-13, Enterprise and Education end 2027-10-12; osVersion does not show the edition.
    assert classify("Windows", "10.0.26100.6584", _TODAY).state == STATE_EDITION_DEPENDENT
    assert classify("Windows", "10.0.26100.6584", date(2026, 10, 13)).state == STATE_SUPPORTED
    assert classify("Windows", "10.0.22631.4602", date(2025, 11, 12)).state == STATE_EDITION_DEPENDENT
    assert classify("Windows", "10.0.22631.4602", date(2026, 11, 11)).state == STATE_PAST_END_OF_LIFE


def test_apple_and_android_releases_are_matched_on_the_major_version() -> None:
    assert classify("macOS", "14.5", _TODAY).state == STATE_PAST_END_OF_LIFE
    assert classify("macOS", "15.1", _TODAY).state == STATE_SUPPORTED
    assert classify("macOS", "14.5", _TODAY).confidence == "derived"
    # Releases older than the oldest listed major ended no later than the floor entry's date.
    assert classify("macOS", "10.15.7", _TODAY).state == STATE_PAST_END_OF_LIFE
    # Apple still patched iPadOS 17 (17.7.11) and iOS 16 and 15 in May 2026, so none is called end of life.
    for system, version in (("iOS", "17.7.7"), ("iPadOS", "17.7.11"), ("iOS", "16.7.16"), ("iOS", "15.8.8")):
        assert classify(system, version, _TODAY).state == STATE_SUPPORTED, (system, version)
    ios_17 = classify("iPadOS", "17.1", _TODAY)
    assert ios_17.release_id == "ios-17" and ios_17.end_of_support is None and "17.7.11" in str(ios_17.note)
    assert classify("iOS", "14.8.1", _TODAY).state == STATE_PAST_END_OF_LIFE
    assert classify("iOS", "18.5", _TODAY).state == STATE_SUPPORTED
    assert classify("Android", "13", _TODAY).state == STATE_PAST_END_OF_LIFE
    assert classify("Android (device administrator)", "12.1", _TODAY).state == STATE_PAST_END_OF_LIFE
    assert classify("Android", "14", _TODAY).state == STATE_SUPPORTED


@pytest.mark.parametrize(
    ("operating_system", "os_version", "reason"),
    [
        ("Windows", None, REASON_VERSION_MISSING),
        ("Windows", "", REASON_VERSION_MISSING),
        ("iOS", "Unknown", REASON_VERSION_MISSING),
        ("Windows", "not a version", REASON_VERSION_UNPARSABLE),
        ("Windows", "11", REASON_VERSION_UNPARSABLE),
        ("macOS", "Sonoma", REASON_VERSION_UNPARSABLE),
        ("Android", "S", REASON_VERSION_UNPARSABLE),
        ("Windows", "6.3.9600", REASON_NOT_IN_TABLE),
        ("Windows", "10.0.99999.1", REASON_NOT_IN_TABLE),
        ("macOS", "99.0", REASON_NOT_IN_TABLE),
        ("iOS", "12.5.8", REASON_NOT_IN_TABLE),
        ("Android", "6.0", REASON_NOT_IN_TABLE),
        ("Linux", "6.1", REASON_PLATFORM_NOT_COVERED),
        ("Windows Phone", "10.0.15254", REASON_PLATFORM_NOT_COVERED),
        (None, "10.0.19045", REASON_PLATFORM_NOT_COVERED),
    ],
)
def test_a_version_that_cannot_be_judged_is_unknown_with_a_reason(operating_system: Any, os_version: Any, reason: str) -> None:
    result = classify(operating_system, os_version, _TODAY)
    assert result.state == STATE_UNKNOWN and result.reason == reason
    assert result.release_name is None and result.end_of_support is None


def test_a_windows_version_without_a_revision_still_matches_its_build() -> None:
    assert classify("Windows", "10.0.19045", _TODAY).state == STATE_PAST_END_OF_LIFE


def test_a_missing_or_damaged_table_makes_every_device_unknown_never_supported() -> None:
    assert classify("Windows", "10.0.19045.1", _TODAY, table={}).state == STATE_UNKNOWN
    broken = {
        "platforms": {
            "windows": {"releases": [{"id": "w", "name": "W", "build": 19045, "end_of_support": "someday", "sources": ["https://example.invalid"]}]}
        }
    }
    result = classify("Windows", "10.0.19045.1", _TODAY, table=broken)
    assert result.state == STATE_UNKNOWN and result.reason == REASON_NOT_IN_TABLE


def test_family_detection_reads_the_intune_operating_system_names() -> None:
    assert [os_family(name) for name in ("Windows", "iOS", "iPadOS", "macOS", "Android", "Android Enterprise")] == [
        "windows", "ios", "ios", "macos", "android", "android",
    ]
    assert [os_family(name) for name in ("Linux", "Windows Phone", "ChromeOS", "", None)] == [None] * 5
    # Windows Server shares build numbers with Windows 10 releases but follows its own lifecycle.
    assert [os_family(name) for name in ("Windows Server 2019", "Windows Server", "windows server 2016 datacenter")] == [None] * 3
    assert classify("Windows Server 2019", "10.0.17763.5000", _TODAY).reason == REASON_PLATFORM_NOT_COVERED


def test_the_evidence_block_drops_empty_fields() -> None:
    evidence = classify("Windows", "10.0.19045.1", _TODAY).evidence()
    assert evidence["state"] == STATE_PAST_END_OF_LIFE and evidence["release"] == "Windows 10 22H2"
    assert "reason" not in evidence and evidence["sources"]
    assert classify("Linux", "6.1", _TODAY).evidence() == {"state": "unknown", "reason": REASON_PLATFORM_NOT_COVERED}
