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

    from azure_tenant_audit.collectors.sharepoint_access import (
        SharePointAccessCollector,
    )

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

    from azure_tenant_audit.collectors.mailbox_forwarding import (
        MailboxForwardingCollector,
    )

    configs = Path(__file__).resolve().parents[1] / "configs"
    permissions = json.loads((configs / "collector-permissions.json").read_text(encoding="utf-8"))
    definitions = json.loads((configs / "collector-definitions.json").read_text(encoding="utf-8"))
    entry = permissions["collector_permissions"]["mailbox_forwarding"]
    assert entry["optional_graph_scopes"] == MailboxForwardingCollector.optional_permissions == ["MailboxFolder.Read.All"]
    assert "MailboxFolder.Read.All" not in entry["graph_scopes"]
    assert "mailFolders" in definitions["collectors"]["mailbox_forwarding"]["query_plan"]
    assert "never a message" in entry["notes"]


def _lab_token(tenant_id: str) -> str:
    import base64
    import json

    def part(value: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    return f"{part({'alg': 'none'})}.{part({'tid': tenant_id, 'aud': 'https://outlook.office365.com'})}.constructed"


def _response_config(tmp_path, **overrides):
    from azure_tenant_audit.response import ResponseConfig

    values = dict(tenant_name="lab", out_dir=tmp_path, tenant_id="lab-tenant", action="message_trace",
                  target="user@example.com", intent="lab check", auditor_profile="exchange-reader", execute=True,
                  allow_lab_response=True, run_name="r",
                  exchange_session={"kind": "exchange_online", "access_token": _lab_token("lab-tenant"),
                                    "organization": "lab.onmicrosoft.com"})
    values.update(overrides)
    return ResponseConfig(**values)


class _RecordingAdapter:
    name = "powershell_graph"

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def dependency_check(self) -> bool:
        return True

    def run(self, command, log_event=None, session=None, **kwargs):  # noqa: ANN001, ARG002
        self.calls.append({"command": command, **kwargs})
        return {"command": command, "value": [], "duration_ms": 1.0}


def _response_blockers(tmp_path) -> list[dict]:
    import json

    return json.loads((tmp_path / "lab-r" / "blockers" / "blockers.json").read_text(encoding="utf-8"))


def test_response_execution_needs_the_response_toggle(tmp_path, monkeypatch) -> None:
    """R086 repair: the embedded path enforces AUDITEX_ENABLE_RESPONSE before any tenant command runs."""
    from azure_tenant_audit.response import run_response

    adapter = _RecordingAdapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"lab-tenant"})
    monkeypatch.delenv("AUDITEX_ENABLE_RESPONSE", raising=False)
    assert run_response(_response_config(tmp_path)) == 1
    assert adapter.calls == []
    assert ("lab_guard", "response_disabled") in {(b["error_class"], b.get("reason")) for b in _response_blockers(tmp_path)}


def test_an_exchange_session_for_another_tenant_is_refused(tmp_path, monkeypatch) -> None:
    """R086 repair: the supplied session must belong to the allow-listed lab tenant, or nothing runs."""
    from azure_tenant_audit.response import run_response

    adapter = _RecordingAdapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"lab-tenant"})
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")
    session = {"kind": "exchange_online", "access_token": _lab_token("customer-tenant"), "organization": "x.onmicrosoft.com"}
    assert run_response(_response_config(tmp_path, exchange_session=session)) == 1
    assert adapter.calls == []
    assert ("lab_guard", "session_tenant_mismatch") in {
        (b["error_class"], b.get("reason")) for b in _response_blockers(tmp_path)}


def test_response_trace_rows_never_reach_the_command_log(tmp_path, monkeypatch) -> None:
    """R086 repair: a response read's output is evidence only; the command log keeps no stdout sample."""
    import subprocess

    from azure_tenant_audit.adapters import powershell_graph
    from azure_tenant_audit.response import run_response

    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"lab-tenant"})
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")
    monkeypatch.setattr(powershell_graph.shutil, "which", lambda _name: "pwsh")
    rows = '[{"Subject": "Quarterly merger plan", "SenderAddress": "boss@example.com", "Status": "Delivered"}]'
    monkeypatch.setattr(
        powershell_graph.subprocess, "run",
        lambda argv, **_kw: subprocess.CompletedProcess(argv, 0, stdout=rows, stderr=""),
    )
    assert run_response(_response_config(tmp_path, since="2026-01-01T00:00:00Z", until="2026-01-02T00:00:00Z")) == 0
    run_dir = tmp_path / "lab-r"
    # raw/ and normalized/ hold the read's evidence by design; the run's logs must not copy it.
    logs = [p for p in run_dir.rglob("*") if p.is_file() and p.name.startswith("audit-")]
    assert logs
    leaked = [str(p.relative_to(run_dir)) for p in logs if "merger" in p.read_text(encoding="utf-8", errors="ignore")]
    assert leaked == [], leaked
