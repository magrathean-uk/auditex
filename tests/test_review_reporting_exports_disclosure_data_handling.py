"""Deep-review lane reporting-exports-disclosure: data-handling notices and scope classes (R083, R088, X1)."""
from __future__ import annotations

import pytest

from azure_tenant_audit.data_handling import (
    build_data_handling_summary,
    classify_auth_scope,
    collector_activity_notices,
)
from azure_tenant_audit.dns_lookup import DEFAULT_DOH_ENDPOINT, DOH_ENDPOINT_ENV


@pytest.fixture(autouse=True)
def _no_resolver_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(DOH_ENDPOINT_ENV, raising=False)


def test_r083_google_dns_posture_discloses_the_doh_resolver() -> None:
    notices = collector_activity_notices(["google_directory", "google_dns_posture"], "live")
    text = " ".join(notices)
    assert DEFAULT_DOH_ENDPOINT in text
    assert "--exclude google_dns_posture" in text
    # Exchange and the M365 DNS collector are not part of a Google run, so their switches are not offered.
    assert "exchange_policy" not in text


def test_r083_google_workspace_data_handling_carries_the_notice() -> None:
    summary = build_data_handling_summary(
        platform="google_workspace", mode="live", plane="audit", collectors=["google_directory", "google_dns_posture"]
    )
    assert any(DEFAULT_DOH_ENDPOINT in notice for notice in summary["collection_notices"])
    assert summary["dns_resolver"] == "cloudflare-dns.com"


def test_r083_google_run_without_dns_has_no_notice_and_no_resolver() -> None:
    summary = build_data_handling_summary(
        platform="google_workspace", mode="live", plane="audit", collectors=["google_directory"]
    )
    assert summary["collection_notices"] == []
    assert summary["dns_resolver"] is None


def test_r083_offline_google_dns_posture_says_no_requests() -> None:
    assert collector_activity_notices(["google_dns_posture"], "offline") == [
        "Offline replay: no Exchange Online PowerShell session or public DNS/HTTPS requests are made."
    ]


@pytest.mark.parametrize(
    "scope",
    [
        "Sites.Read.All",
        "Files.Read.All",
        "Files.Read",
        "Mail.Read",
        "Mail.Read.Shared",
        "Chat.Read.All",
        "ChannelMessage.Read.All",
        "Notes.Read.All",
    ],
)
def test_r088_m365_content_capable_scopes_are_not_read_only(scope: str) -> None:
    assert classify_auth_scope(scope) == "content_capable"


@pytest.mark.parametrize("scope", ["User.Read.All", "MailboxSettings.Read", "Mail.ReadBasic.All", "Channel.ReadBasic.All"])
def test_r088_metadata_scopes_stay_read_only(scope: str) -> None:
    assert classify_auth_scope(scope) == "read_only"


def test_r088_sharepoint_selection_reports_content_capable_scope_risk() -> None:
    summary = build_data_handling_summary(
        platform="m365", mode="live", plane="audit", collectors=["sharepoint"],
        auth_scopes=["Directory.Read.All", "Sites.Read.All"],
    )
    assert summary["scope_risk"] == "content_capable_scope_present"
    assert summary["auth_scope_summary"]["content_capable"] == ["Sites.Read.All"]


def test_x1_dns_notice_names_the_configured_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DOH_ENDPOINT_ENV, "https://doh.example.net/dns-query")
    text = " ".join(collector_activity_notices(["dns_posture"], "live"))
    assert "the configured DNS-over-HTTPS resolver (https://doh.example.net/dns-query)" in text
    assert "Cloudflare" not in text
    summary = build_data_handling_summary(platform="m365", mode="live", plane="audit", collectors=["dns_posture"])
    assert summary["dns_resolver"] == "doh.example.net"


def test_x1_explicit_endpoint_wins_over_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DOH_ENDPOINT_ENV, "https://doh.example.net/dns-query")
    text = " ".join(collector_activity_notices(["dns_posture"], "live", doh_endpoint="https://resolver.example.org/q"))
    assert "resolver.example.org" in text and "doh.example.net" not in text


def test_x1_invalid_configured_resolver_never_crashes_or_echoes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DOH_ENDPOINT_ENV, "https://user:token123@doh.example.net/q")
    text = " ".join(collector_activity_notices(["dns_posture"], "live"))
    assert "token123" not in text
    assert DOH_ENDPOINT_ENV in text
    summary = build_data_handling_summary(platform="m365", mode="live", plane="audit", collectors=["dns_posture"])
    assert summary["dns_resolver"] is None
