"""Repair-round regression tests for the collectors-transport lane (independent review blockers)."""
from __future__ import annotations

import pytest
from support import fake_graph_client, graph_response

from azure_tenant_audit.collectors.base import run_graph_endpoints


def test_licence_coded_403_with_generic_text_is_license_required(monkeypatch) -> None:
    """R004: the licence error code alone, with a generic message, classes the read license_required."""
    client = fake_graph_client(throttle_mode="safe")
    client.sleep = lambda _seconds: None
    monkeypatch.setattr(
        client.session,
        "request",
        lambda *a, **k: graph_response(403, {"error": {"code": "AadPremiumLicenseRequired", "message": "Forbidden"}}),
    )
    _payload, coverage = run_graph_endpoints(
        "identity_governance",
        client,
        {"roleEligibilitySchedules": {"endpoint": "/roleManagement/directory/roleEligibilitySchedules"}},
        None,
    )
    assert coverage[0]["status"] == "failed"
    assert coverage[0]["error_class"] == "license_required"


@pytest.mark.parametrize("error_name", ["ReadTimeout", "ConnectionError"])
def test_exhausted_transport_retries_are_graph_transient(monkeypatch, error_name) -> None:
    """R033: a read whose transport retries all fail is recorded as graph_transient, not client_error."""
    import requests.exceptions as rex

    client = fake_graph_client(throttle_mode="safe")
    client.sleep = lambda _seconds: None

    def _request(*_a, **_k):
        raise getattr(rex, error_name)("network blip")

    monkeypatch.setattr(client.session, "request", _request)
    _payload, coverage = run_graph_endpoints(
        "conditional_access",
        client,
        {"conditionalAccessPolicies": {"endpoint": "/identity/conditionalAccess/policies"}},
        None,
    )
    assert coverage[0]["status"] == "failed"
    assert coverage[0]["error_class"] == "graph_transient"


def test_a_falsey_injected_dns_resolver_is_used_not_a_crash() -> None:
    """X1 / R164: an injected resolver whose truth value is false (an empty cache) is still the resolver used."""
    from azure_tenant_audit.collectors.dns_posture import DnsPostureCollector

    class _EmptyResolver:
        def __init__(self) -> None:
            self.asked: list[tuple[str, str]] = []

        def __len__(self) -> int:
            return 0

        def query(self, name: str, record_type: str) -> list[str]:
            self.asked.append((name, record_type))
            return []

    class _Client:
        def get_all(self, _path, params=None):  # noqa: ARG002
            return [{"id": "example.com", "isVerified": True}]

    resolver = _EmptyResolver()
    assert not resolver
    result = DnsPostureCollector().run({"client": _Client(), "dns_resolver": resolver, "public_lookups": False})
    assert result.status in {"ok", "partial"}
    assert ("example.com", "TXT") in resolver.asked or any(n.endswith("example.com") for n, _ in resolver.asked)


def test_a_truncated_site_permission_list_gives_no_ownership_verdict() -> None:
    """R045 repair: ownership worked out from a cut permission list is unknown, so no orphaned-site finding fires."""
    from test_review_collectors_transport_fanout import _NextPageFails

    from azure_tenant_audit.collectors.sharepoint_access import SharePointAccessCollector

    fake = _NextPageFails(
        "/sites/site-1/permissions",
        lists={"/sites": [{"id": "site-1", "displayName": "Team", "webUrl": "https://contoso.sharepoint.com/sites/team"}]},
        objects={"/admin/sharepoint/settings": {"sharingCapability": "externalUserSharingOnly"}},
    )
    result = SharePointAccessCollector().run({"client": fake, "top": None})
    sites = [e for e in result.payload["sitePermissionsBySite"]["value"] if e.get("siteId") == "site-1"]
    assert sites and sites[0]["collection_truncated"] is True
    assert sites[0]["ownershipState"] == "unknown"


def _normalized(collector_payloads: dict) -> dict:
    from azure_tenant_audit.normalize import build_normalized_snapshot

    return build_normalized_snapshot(tenant_name="t", run_id="r", collector_payloads=collector_payloads)


def _records(snapshot: dict, kind: str) -> list[dict]:
    return [
        record
        for section in snapshot.values()
        if isinstance(section, dict)
        for record in (section.get("records") or [])
        if isinstance(record, dict) and record.get("kind") == kind
    ]


def test_an_unresolved_inbox_rule_target_stays_unknown_after_normalisation() -> None:
    """R006 repair: a rule whose move target was not resolved is unknown in normalised evidence, never false."""
    rules = [
        {"user_id": "u1", "rule_id": "r1", "move_to_folder": "AAMkAD-unread=", "hide_from_user": None,
         "hide_from_user_state": "unknown"},
        {"user_id": "u1", "rule_id": "r2", "move_to_folder": "AAMkAD-inbox=", "hide_from_user": False,
         "hide_from_user_state": "resolved"},
    ]
    records = {r["rule_id"]: r for r in _records(_normalized({"mailbox_forwarding": {"messageRules": {"value": rules}}}),
                                                "inbox_rule")}
    assert records["r1"].get("hide_from_user") is None
    assert records["r1"]["hide_from_user_state"] == "unknown"
    assert records["r2"]["hide_from_user"] is False


def test_unread_federated_credentials_stay_distinct_from_none_configured() -> None:
    """R032 repair: a failed federated-credential read is named per application after normalisation."""
    apps = [
        {"id": "a1", "display_name": "Unread", "federated_credentials": None},
        {"id": "a2", "display_name": "Empty", "federated_credentials": []},
    ]
    records = {r["id"]: r for r in _records(_normalized({"app_credentials": {"applicationCredentials": {"value": apps}}}),
                                           "application_credentials")}
    assert records["a1"]["federated_credentials_state"] == "unknown"
    assert "federated_credentials_state" not in records["a2"]


def test_the_folder_lookup_scope_and_read_are_declared() -> None:
    """R006 repair: the folder-metadata read is in the shipped query plan and its optional scope is declared."""
    import json
    from pathlib import Path

    from azure_tenant_audit.collectors.mailbox_forwarding import MailboxForwardingCollector

    configs = Path(__file__).resolve().parents[1] / "configs"
    permissions = json.loads((configs / "collector-permissions.json").read_text(encoding="utf-8"))
    definitions = json.loads((configs / "collector-definitions.json").read_text(encoding="utf-8"))
    entry = permissions["collector_permissions"]["mailbox_forwarding"]
    assert entry["optional_graph_scopes"] == MailboxForwardingCollector.optional_permissions == ["MailboxFolder.Read.All"]
    assert "MailboxFolder.Read.All" not in entry["graph_scopes"]
    assert "mailFolders" in definitions["collectors"]["mailbox_forwarding"]["query_plan"]
    assert "never a message" in entry["notes"]
