"""Section-scoped gaps reach the run: manifest, collection gaps, handoff and gate (review v3 defects 2, 3 and 15).

A read whose gap belongs to its own section (the Defender state of each device, the assignments of each Intune
policy, the beta update profile lists) keeps its collector ``ok``, so the rules that read it say ``not_assessed``
themselves. The run used to say nothing: exit code 0, ``coverage_gaps: []``, a passing gate and a clean handoff. These
tests run the whole live path against a scripted Graph client and read what the run, the gate and the handoff report.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from graph_fakes import (
    COMPLIANCE_POLICY,
    RING,
    FakeGraph,
    devices,
    intune_lists,
    load,
    rule_statuses,
    run_collectors,
)

from auditex.gate import gate_findings
from auditex.reporting import enterprise_handoff
from azure_tenant_audit.collection_gaps import list_truncations, section_gap_records
from azure_tenant_audit.graph import GraphError


@pytest.mark.parametrize("probe_first", [False, True])
def test_no_teams_token_leaves_run_ok_and_customer_limitations_visible(monkeypatch, tmp_path, probe_first):
    from azure_tenant_audit import cli
    from azure_tenant_audit.collectors.base import CollectorResult
    from azure_tenant_audit.collectors.teams_policy import TeamsPolicyCollector

    class AllOkCollector:
        name = "licensing"

        def run(self, context):
            return CollectorResult(name=self.name, status="ok", item_count=0, payload={"skus": {"value": []}},
                                   coverage=[{"collector": self.name, "name": "skus", "type": "graph",
                                              "endpoint": "/subscribedSkus", "status": "ok", "item_count": 0}])

    def forbidden_adapter(name):
        raise AssertionError(f"Unexpected Teams adapter: {name}")

    monkeypatch.setattr(cli, "REGISTRY", {"teams_policy": TeamsPolicyCollector(), "licensing": AllOkCollector()})
    monkeypatch.setattr("azure_tenant_audit.collectors.teams_policy.get_adapter", forbidden_adapter)
    # The other collector supplies a successful coverage row even for an empty list.
    extra = ("--probe-first",) if probe_first else ()
    rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(), "teams_policy,licensing", *extra)

    assert rc == 0
    manifest = load(run_dir, "run-manifest.json")
    assert manifest["overall_status"] == "ok"
    readiness = load(run_dir, "live-readiness.json")
    assert readiness["trust_level"] == "partial"
    assert readiness["trusted_collectors"] == ["licensing"]
    assert readiness["unverified_collectors"] == ["teams_policy"]
    assert load(run_dir, "validation.json")["valid"] is True
    teams_rows = [row for row in load(run_dir, "coverage.json") if row["collector"] == "teams_policy"]
    assert len(teams_rows) == 7 and all(row["status"] == "skipped" for row in teams_rows)
    ledger = {row["collector"]: row for row in load(run_dir, "normalized/coverage_ledger.json")["records"]}
    assert ledger["teams_policy"]["actual_status"] == "ok"
    assert ledger["teams_policy"]["coverage_status"] != "not_applicable"
    assert len(_section_gaps(run_dir)) == 7
    customer_text = "not collected: certificate token for the Teams admin API not available"
    from auditex.explorer import _collector_rows

    explorer_rows = {row["collector"]: row for row in _collector_rows(run_dir, manifest, {})}
    assert explorer_rows["teams_policy"]["status"] == "not_verified"
    assert explorer_rows["teams_policy"]["reason"] == customer_text
    assert explorer_rows["licensing"]["status"] == "verified"
    assert load(run_dir, "ai_context.json")["known_limitations"] == ["teams_policy"]
    pack = load(run_dir, "reports/report-pack.json")
    assert customer_text in str(pack["summary"]["coverage_gaps"])
    assert pack["summary"]["coverage_gaps"][0]["message"].count(customer_text) == 1
    summary_gaps = (run_dir / "summary.md").read_text().split("## Coverage Gaps", 1)[1]
    assert summary_gaps.count(customer_text) == 1
    handoff = enterprise_handoff(run_dir)
    assert handoff["handoff_status"] == "ready_with_limitations"
    assert customer_text in str(handoff["limitations"])
    teams_statuses = rule_statuses(run_dir)["teams.external_federation_open"]
    assert {status for status, _reason in teams_statuses} == {"not_assessed"}
    assert not [row for row in (load(run_dir, "findings/findings.json") or []) if row.get("collector") == "teams_policy"]


@pytest.mark.parametrize("probe_first", [False, True])
def test_teams_token_runs_five_rest_reads_and_skips_commands_without_partial_run(monkeypatch, tmp_path, probe_first):
    from test_teams_admin_rest import TOKEN, Response, command_reader, connect

    from azure_tenant_audit import cli
    from azure_tenant_audit.adapters import teams_admin_rest as rest
    from azure_tenant_audit.collectors.teams_policy import TeamsPolicyCollector

    class CertificateGraph(FakeGraph):
        graph_endpoint = "https://graph.microsoft.com/v1.0"

        def app_token_for(self, scope):
            assert scope == rest.TEAMS_ADMIN_SCOPE
            return TOKEN

    monkeypatch.setattr(cli, "REGISTRY", {"teams_policy": TeamsPolicyCollector()})
    commands = command_reader(monkeypatch)
    # probe-first also performs five reads in the capability preflight.
    session = connect(monkeypatch, [Response() for _ in range(10 if probe_first else 5)])
    extra = ("--probe-first",) if probe_first else ()
    rc, run_dir = run_collectors(monkeypatch, tmp_path, CertificateGraph(), "teams_policy", *extra)

    assert rc == 0 and commands.calls == []
    assert len(session.calls) == (10 if probe_first else 5)
    manifest = load(run_dir, "run-manifest.json")
    assert manifest["overall_status"] == "ok"
    readiness = load(run_dir, "live-readiness.json")
    assert readiness["trust_level"] == "live_verified"
    assert readiness["trusted_collectors"] == ["teams_policy"]
    assert load(run_dir, "validation.json")["valid"] is True
    rows = load(run_dir, "coverage.json")
    assert len(rows) == 7
    assert sum(row["status"] == "ok" for row in rows) == 5
    skipped = {row["name"]: row for row in rows if row["status"] == "skipped"}
    assert set(skipped) == {"messagingPolicies", "appSetupPolicies"}
    assert all(row["reason"] == "teams_powershell_not_supported" for row in skipped.values())
    assert len(_section_gaps(run_dir)) == 2
    assert "Teams PowerShell sessions are not supported" in str(enterprise_handoff(run_dir)["limitations"])
    assert load(run_dir, "ai_context.json")["known_limitations"] == ["teams_policy"]

    from auditex.explorer import _collector_rows

    explorer_rows = {row["collector"]: row for row in _collector_rows(run_dir, manifest, {})}
    assert explorer_rows["teams_policy"]["status"] == "verified"
    assert explorer_rows["teams_policy"]["reason"] == "Collected; not collected: Teams PowerShell sessions are not supported"


def _section_gaps(run_dir: Path) -> dict[tuple[str, str], dict[str, Any]]:
    manifest = load(run_dir, "run-manifest.json")
    return {
        (item["collector"], item["section"]): item
        for gap in manifest["coverage_gaps"]
        for item in gap.get("section_gaps", [])
    }


def _assert_named_everywhere(run_dir: Path, section: tuple[str, str], *, collector_status: str = "ok") -> None:
    """The gap is a section gap in the manifest, collection_gaps.json, the handoff and the gate, and the run stays ok."""
    collector, name = section
    manifest = load(run_dir, "run-manifest.json")
    assert manifest["overall_status"] == "ok"
    ledger = {row["collector"]: row["coverage_status"] for row in load(run_dir, "normalized/coverage_ledger.json")["records"]}
    assert ledger[collector].startswith("complete"), "a section-scoped gap must not make its collector partial"

    gaps = _section_gaps(run_dir)
    assert section in gaps, sorted(gaps)
    gap = next(item for item in manifest["coverage_gaps"] if section in {(g["collector"], g["section"]) for g in item["section_gaps"]})
    assert gap["status"] == "partial" and gap["scope"] == "section" and name in gap["message"]
    assert any(item["status"] == "partial" for item in manifest["surface_coverage"])

    records = {record["source"]: record for record in load(run_dir, "normalized/collection_gaps.json")["records"]}
    assert f"{collector}.{name}" in records and records[f"{collector}.{name}"]["section_scoped"] is True

    handoff = enterprise_handoff(run_dir)
    assert handoff["handoff_status"] == "ready_with_limitations"
    assert any(name in str(limitation.get("message")) for limitation in handoff["limitations"])

    result = gate_findings(run_dir=str(run_dir), fail_on="critical")
    assert result["status"] == "pass", result.get("reason")
    assert any(f"{collector}.{name}" in warning for warning in result["warnings"]), result["warnings"]
    assert {(item["collector"], item["section"]) for item in result["coverage"]["section_gaps"]} >= {section}
    assert load(run_dir, "validation.json")["valid"] is True


def test_a_defender_state_read_for_100_of_150_devices_is_named_by_the_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    lists, objects = intune_lists(devices(150))

    rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(lists=lists, objects=objects), "intune,intune_depth")

    assert rc == 0
    _assert_named_everywhere(run_dir, ("intune", "windowsProtectionStates"))
    gap = _section_gaps(run_dir)[("intune", "windowsProtectionStates")]
    assert gap["reason"] == "fanout_limit" and gap["rows_collected"] == 100 and gap["fanout_total"] == 150
    statuses = rule_statuses(run_dir)
    assert statuses["intune.defender_av_off"] == {("not_assessed", "defender_state_truncated")}


def test_refused_beta_update_profile_lists_are_named_by_the_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    lists, objects = intune_lists(devices(5), configs=())
    fake = FakeGraph(
        lists=lists,
        objects=objects,
        errors={
            "beta:/deviceManagement/windowsQualityUpdateProfiles": (403, "Forbidden"),
            "beta:/deviceManagement/windowsFeatureUpdateProfiles": (403, "Forbidden"),
        },
    )

    rc, run_dir = run_collectors(monkeypatch, tmp_path, fake, "intune,intune_depth")

    assert rc == 0
    for section in ("windowsQualityUpdateProfiles", "windowsFeatureUpdateProfiles"):
        _assert_named_everywhere(run_dir, ("intune_depth", section))
        gap = _section_gaps(run_dir)[("intune_depth", section)]
        assert gap["status"] == "failed" and gap["reason"] == "read_failed" and gap["error_classes"]
    assert rule_statuses(run_dir)["intune_depth.update_ring_not_assigned"] == {("not_assessed", "update_profiles_blocked")}


def test_a_refused_compliance_assignment_read_is_named_by_the_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    lists, objects = intune_lists(devices(5))
    fake = FakeGraph(
        lists=lists,
        objects=objects,
        batch_errors={"/deviceManagement/deviceCompliancePolicies/cp-1/assignments": (403, "Forbidden")},
    )

    rc, run_dir = run_collectors(monkeypatch, tmp_path, fake, "intune,intune_depth")

    assert rc == 0
    _assert_named_everywhere(run_dir, ("intune", "deviceCompliancePolicyAssignments"))
    assert _section_gaps(run_dir)[("intune", "deviceCompliancePolicyAssignments")]["status"] == "failed"
    assert rule_statuses(run_dir)["intune.compliance_policy_missing_platform"] == {
        ("not_assessed", "policy_assignments_not_read_for_every_policy")
    }


def test_a_refused_windows_protection_state_on_every_device_is_named_by_the_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lists, objects = intune_lists(devices(5))
    fake = FakeGraph(
        lists=lists,
        objects=objects,
        batch_errors={f"/deviceManagement/managedDevices/dev-Windows-{index}/windowsProtectionState": (403, "Forbidden") for index in range(5)},
    )

    rc, run_dir = run_collectors(monkeypatch, tmp_path, fake, "intune,intune_depth")

    assert rc == 0
    _assert_named_everywhere(run_dir, ("intune", "windowsProtectionStates"))
    assert _section_gaps(run_dir)[("intune", "windowsProtectionStates")]["status"] == "failed"
    assert {status for status, _reason in rule_statuses(run_dir)["intune.defender_av_off"]} == {"not_assessed"}


def test_111_compliance_policies_cut_at_100_are_named_by_the_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ios = [{**COMPLIANCE_POLICY, "id": f"cp-{index}", "@odata.type": "#microsoft.graph.iosCompliancePolicy"} for index in range(110)]
    windows = {**COMPLIANCE_POLICY, "id": "cp-win"}
    lists, objects = intune_lists(devices(5), compliance=(*ios, windows))
    for index in range(110):
        lists[f"/deviceManagement/deviceCompliancePolicies/cp-{index}/assignments"] = []

    rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(lists=lists, objects=objects), "intune,intune_depth")

    assert rc == 0
    _assert_named_everywhere(run_dir, ("intune", "deviceCompliancePolicyAssignments"))
    gap = _section_gaps(run_dir)[("intune", "deviceCompliancePolicyAssignments")]
    assert gap["reason"] == "fanout_limit" and gap["fanout_total"] == 111


class _PageFails(FakeGraph):
    def iter_pages(self, path: str, params: Any = None):
        for number, page in enumerate(super().iter_pages(path, params), start=1):
            if number == 2 and "windowsQualityUpdateProfiles" in path:
                raise GraphError("Service unavailable", status=503, request=path)
            yield page


def test_a_failed_beta_page_leaves_a_valid_bundle_and_a_named_gap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    quality = [{"id": f"q{index}", "displayName": f"Q{index}"} for index in range(150)]
    lists, objects = intune_lists(devices(3), quality=tuple(quality), configs=())

    rc, run_dir = run_collectors(monkeypatch, tmp_path, _PageFails(lists=lists, objects=objects), "intune,intune_depth")

    assert rc == 0
    validation = load(run_dir, "validation.json")
    assert validation["valid"] is True, [issue["code"] for issue in validation["issues"]]
    rows = {row["name"]: row for row in load(run_dir, "coverage.json")}
    assert rows["windowsQualityUpdateProfiles"]["section_scoped"] is True
    # The row still says how it was cut; it is a section gap, never a truncation of the collector.
    assert rows["windowsQualityUpdateProfiles"]["truncation_reason"] == "pagination_failed"
    assert ("intune_depth", "windowsQualityUpdateProfiles") in _section_gaps(run_dir)
    assert gate_findings(run_dir=str(run_dir), fail_on="critical")["status"] == "pass"


def test_top_cutting_a_beta_update_profile_list_leaves_a_valid_bundle_and_a_named_gap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    quality = tuple({"id": f"q{index}", "displayName": f"Q{index}"} for index in range(5))
    lists, objects = intune_lists(devices(2), quality=quality, configs=())

    rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(lists=lists, objects=objects), "intune_depth", "--top", "2")

    assert rc == 0
    validation = load(run_dir, "validation.json")
    assert validation["valid"] is True, [issue["code"] for issue in validation["issues"]]
    gap = _section_gaps(run_dir)[("intune_depth", "windowsQualityUpdateProfiles")]
    assert gap["reason"] == "operator_limit" and gap["rows_collected"] == 2
    assert rule_statuses(run_dir)["intune_depth.update_ring_not_assigned"] == {("not_assessed", "update_profiles_truncated")}


def test_list_truncations_leave_out_a_section_scoped_row_and_section_gaps_name_it() -> None:
    rows = [
        {"collector": "c", "name": "whole", "status": "partial", "collection_truncated": True, "truncation_reason": "operator_limit", "result_limit": 5},
        {
            "collector": "c", "name": "scoped", "status": "partial", "collection_truncated": True,
            "truncation_reason": "operator_limit", "result_limit": 5, "section_scoped": True, "error_class": "collection_limit",
            "item_count": 5,
        },
        {"collector": "c", "name": "scopedFanout", "type": "derived", "status": "partial", "section_scoped": True, "fanout_total": 9, "rows_collected": 3},
        {"collector": "c", "name": "fine", "status": "ok", "section_scoped": True},
    ]

    assert [item["list"] for item in list_truncations(rows)] == ["whole"]
    records = section_gap_records(rows)
    assert [(item["collector"], item["section"], item["status"]) for item in records] == [("c", "scoped", "partial")]
    assert records[0]["reason"] == "operator_limit" and records[0]["fanout_total"] == 9 and records[0]["rows_collected"] == 5


def test_the_validator_warns_when_the_manifest_does_not_name_a_section_gap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import json

    from azure_tenant_audit.contracts import build_validation_report

    lists, objects = intune_lists(devices(150))
    _rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(lists=lists, objects=objects), "intune,intune_depth")
    manifest_path = run_dir / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for gap in manifest["coverage_gaps"]:
        gap.pop("section_gaps", None)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = build_validation_report(run_dir=run_dir, read_only=True)

    warnings = [issue for issue in report["issues"] if issue["code"] == "section_gap_not_recorded"]
    assert warnings and warnings[0]["severity"] == "warning"
    assert warnings[0]["details"][0]["section"] == "windowsProtectionStates"


def test_a_tenant_with_more_than_ten_profiles_keeps_its_update_ring_rules(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The 10-profile assignment fan-out is a section gap: it must not make intune_depth, and the ring rules, not assessed."""
    profiles = tuple({"id": f"cfg-{index}", "displayName": f"Profile {index}", "@odata.type": "#microsoft.graph.windows10GeneralConfiguration"} for index in range(12))
    lists, objects = intune_lists(devices(5), configs=(RING, *profiles))

    rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(lists=lists, objects=objects), "intune,intune_depth")

    assert rc == 0
    ledger = {row["collector"]: row["coverage_status"] for row in load(run_dir, "normalized/coverage_ledger.json")["records"]}
    assert ledger["intune_depth"].startswith("complete")
    statuses = rule_statuses(run_dir)
    for rule in ("intune_depth.update_ring_not_assigned", "intune_depth.update_ring_deferral_excessive"):
        assert statuses[rule] == {("pass", "")}, (rule, statuses[rule])
    # The unassigned-policy rule still reports that it saw a sample of the profiles.
    assert all(status == "not_assessed" for status, _reason in statuses["intune_depth.policies_without_assignments"])
    gap = _section_gaps(run_dir)[("intune_depth", "deviceConfigurationAssignments")]
    assert gap["reason"] == "fanout_limit"


@pytest.mark.parametrize("error_class,reason", [
    ("command_not_found", "pwsh"),
    ("module_not_found", "ExchangeOnlineManagement"),
    ("session_not_connected", "session failed"),
    ("command_not_authenticated", "admin consent"),
    ("command_error", "Global Reader"),
])
@pytest.mark.parametrize("preflight", [False, True])
def test_default_exchange_failure_is_partial_exit_zero_with_unassessed_policies(
    monkeypatch, tmp_path, caplog, error_class, reason, preflight
):
    from auditex.reporting import render_enterprise_handoff_markdown
    from auditex.scuba_projection import project_run
    from azure_tenant_audit import cli

    class RefusedAdapter:
        def run(self, command, **kwargs):
            return {"error": "constructed Exchange refusal", "error_class": error_class}

    monkeypatch.setattr("azure_tenant_audit.collectors.exchange_policy.get_adapter", lambda _: RefusedAdapter())
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    caplog.set_level("INFO", logger="azure_tenant_audit")
    rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(), "exchange_policy", *(["--probe-first"] if preflight else []))

    assert rc == 0
    assert load(run_dir, "run-manifest.json")["overall_status"] == "partial"
    ledger = load(run_dir, "normalized/coverage_ledger.json")["records"]
    assert not ledger[0]["coverage_status"].startswith("complete")
    assert reason in ledger[0]["message"]
    assert any(reason in row["customer_reason"] for row in load(run_dir, "diagnostics.json"))
    statuses = rule_statuses(run_dir)
    assert statuses["detection.unified_audit_log_disabled"] == {("not_assessed", "collector_not_complete:exchange_policy")}
    projection = project_run(run_dir)
    assert projection.report["sections"]["transport_config"]["status"] == "not_collected"
    handoff = enterprise_handoff(run_dir)
    assert any(reason in row["message"] for row in handoff["limitations"])
    assert "Exchange Online PowerShell session" in render_enterprise_handoff_markdown(handoff)
    assert "Selected Exchange policy collection" in caplog.text
    assert load(run_dir, "validation.json")["valid"] is True
    assert gate_findings(run_dir=str(run_dir), fail_on="critical")["status"] != "pass"


def test_default_dns_unreachable_is_partial_exit_zero_with_unknown_records(monkeypatch, tmp_path, caplog):
    from auditex.reporting import render_enterprise_handoff_markdown
    from auditex.scuba_projection import project_run
    from azure_tenant_audit import cli
    from azure_tenant_audit.dns_lookup import DohError

    class UnreachableResolver:
        def query(self, name, kind):
            raise DohError("constructed DoH unreachable")

    monkeypatch.setattr("azure_tenant_audit.collectors.dns_posture.DohClient", lambda **_: UnreachableResolver())
    # Never instantiate a real HTTP fetcher; the DNS failure does not advertise MTA-STS.
    monkeypatch.setattr("azure_tenant_audit.collectors.dns_posture.RequestsHttpsFetcher", lambda: None)
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    caplog.set_level("INFO", logger="azure_tenant_audit")
    fake = FakeGraph(lists={"/domains": [{"id": "constructed.example", "isVerified": True, "supportedServices": ["Email"]}]})
    rc, run_dir = run_collectors(monkeypatch, tmp_path, fake, "dns_posture")

    assert rc == 0
    assert load(run_dir, "run-manifest.json")["overall_status"] == "partial"
    assert "Cloudflare" in load(run_dir, "normalized/coverage_ledger.json")["records"][0]["message"]
    assert all(row["spf"]["present"] is None for row in load(run_dir, "raw/dns_posture.json")["domainPosture"]["value"])
    for section in ("spf_records", "dkim_records", "dmarc_records"):
        diagnostic = project_run(run_dir).report["sections"][section]
        assert diagnostic["status"] == "not_collected" and diagnostic["reason"] == "collector_error"
    assert any(status == "not_assessed" for status, _ in rule_statuses(run_dir)["dns_posture.spf_missing"])
    records = load(run_dir, "normalized/collection_gaps.json")["records"]
    assert any("Cloudflare" in row.get("customer_reason", "") for row in records)
    text = render_enterprise_handoff_markdown(enterprise_handoff(run_dir))
    for phrase in ("Cloudflare", "https://cloudflare-dns.com/dns-query", "Only domain names, no user data", "MTA-STS", "OpenID discovery"):
        assert phrase in text and phrase in caplog.text
    assert load(run_dir, "validation.json")["valid"] is True


@pytest.mark.parametrize("collectors,expected_rc", [
    ("exchange_policy", 0), ("dns_posture", 0),
    ("exchange_policy,dns_posture", 0), ("identity", 1),
    ("identity,exchange_policy,dns_posture", 1),
])
def test_optional_collector_crashes_do_not_mask_required_collector_failure(monkeypatch, tmp_path, collectors, expected_rc):
    from azure_tenant_audit import cli

    class Crashed:
        def run(self, context):
            raise RuntimeError("constructed collector failure")

    for name in collectors.split(","):
        monkeypatch.setitem(cli.REGISTRY, name, Crashed())
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(), collectors)
    assert rc == expected_rc
    assert load(run_dir, "run-manifest.json")["overall_status"] == "partial"
    if expected_rc == 0:
        assert load(run_dir, "coverage.json")
        assert all("Not assessed:" in row["message"] for row in load(run_dir, "normalized/coverage_ledger.json")["records"])


def test_offline_disclosure_does_not_claim_network_activity(tmp_path):
    from azure_tenant_audit.data_handling import build_data_handling_summary

    payload = build_data_handling_summary(platform="m365", mode="offline", plane="inventory", collectors=["exchange_policy", "dns_posture"])
    assert payload["collection_notices"] == ["Offline replay: no Exchange Online PowerShell session or public DNS/HTTPS requests are made."]


def test_required_graph_authentication_failure_still_exits_one(monkeypatch, tmp_path):
    from azure_tenant_audit import cli

    class Crashed:
        def run(self, context):
            raise RuntimeError("constructed optional session failure")

    for name in ("exchange_policy", "dns_posture"):
        monkeypatch.setitem(cli.REGISTRY, name, Crashed())
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(errors={"/users": (401, "Unauthenticated")}),
                                 "identity,exchange_policy,dns_posture")
    assert rc == 1
    assert load(run_dir, "run-manifest.json")["overall_status"] == "partial"
    assert any(row.get("collector") == "identity" and row.get("error_class") == "unauthenticated"
               for row in load(run_dir, "diagnostics.json"))


@pytest.mark.parametrize("preflight", [False, True])
def test_dns_domain_read_refusal_is_a_named_non_fatal_gap(monkeypatch, tmp_path, preflight):
    from azure_tenant_audit import cli
    from azure_tenant_audit.collectors.dns_posture import DnsPostureCollector

    class NoNetworkDns(DnsPostureCollector):
        def run(self, context):
            return super().run({**context, "public_lookups": False})

    monkeypatch.setitem(cli.REGISTRY, "dns_posture", NoNetworkDns())
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(errors={"/domains": (403, "Forbidden")}),
                                 "dns_posture", *(["--probe-first"] if preflight else []))
    assert rc == 0
    assert load(run_dir, "run-manifest.json")["overall_status"] == "partial"
    assert load(run_dir, "normalized/collection_gaps.json")["records"]
    assert "Graph verified domains" in load(run_dir, "normalized/coverage_ledger.json")["records"][0]["message"]


@pytest.mark.parametrize("preflight", [False, True])
@pytest.mark.parametrize("healthy", [True, False])
def test_ipps_skip_keeps_healthy_app_run_ok_and_real_exchange_failure_partial(monkeypatch, tmp_path, preflight, healthy):
    from auditex.explorer import _collector_rows
    from auditex.reporting import render_enterprise_handoff_markdown
    from azure_tenant_audit import cli
    from azure_tenant_audit.collection_gaps import IPPS_SKIP_TEXT

    fake = FakeGraph(lists={"/domains": [{"id": "constructed.onmicrosoft.com", "isInitial": True}]})
    fake.app_token_for = lambda scope: "constructed-token"
    calls = []

    class Adapter:
        def run(self, command, *, session, **kwargs):
            assert session["kind"] == "exchange_online"
            assert "Get-ProtectionAlert" not in command
            calls.append(command)
            if not healthy:
                return {"error": "constructed real Exchange session failure", "error_class": "session_not_connected"}
            return {"value": [{"Name": "constructed policy"}], "command": command}

    monkeypatch.setattr("azure_tenant_audit.collectors.exchange_policy.get_adapter", lambda _: Adapter())
    monkeypatch.setattr(cli, "GraphClient", lambda *args, **kwargs: fake)
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    args = cli.build_parser().parse_args([
        "--tenant-name", "acme", "--tenant-id", "constructed", "--client-id", "constructed-app",
        "--client-secret", "constructed-secret", "--collectors", "licensing,exchange_policy",
        "--out", str(tmp_path), "--run-name", "ipps", *(["--probe-first"] if preflight else []),
    ])
    assert cli.run_live(args) == 0
    run_dir = tmp_path / "acme-ipps"
    manifest = load(run_dir, "run-manifest.json")
    assert manifest["overall_status"] == ("ok" if healthy else "partial")
    summary = {row["name"]: row for row in load(run_dir, "summary.json")["collectors"]}
    assert summary["exchange_policy"]["status"] == ("ok" if healthy else "partial")
    from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector
    assert len(calls) == len(ExchangePolicyCollector.command_collectors) - 1
    row = next(row for row in load(run_dir, "coverage.json") if row["name"] == "protectionAlerts")
    assert row["status"] == "skipped" and row["section_scoped"] is True
    assert row["reason"] == row["error_class"] == "ipps_session_not_opened"
    assert _section_gaps(run_dir)[("exchange_policy", "protectionAlerts")]["status"] == "skipped"
    records = load(run_dir, "normalized/collection_gaps.json")["records"]
    assert any(row["source"] == "exchange_policy.protectionAlerts" and row["reason"] == "ipps_session_not_opened" for row in records)
    assert IPPS_SKIP_TEXT in render_enterprise_handoff_markdown(enterprise_handoff(run_dir))
    summary_gaps = load(run_dir, "reports/report-pack.json")["summary"]["coverage_gaps"]
    assert sum(gap["message"].count(IPPS_SKIP_TEXT) for gap in summary_gaps) == 1
    assert "exchange_policy" in load(run_dir, "ai_context.json")["known_limitations"]
    explorer = next(row for row in _collector_rows(run_dir, manifest, {}) if row["collector"] == "exchange_policy")
    assert explorer["status"] == ("verified" if healthy else "not_verified")
    if healthy:
        assert IPPS_SKIP_TEXT in explorer["reason"]
        assert gate_findings(run_dir=str(run_dir), fail_on="critical")["status"] == "pass"
        assert not load(run_dir, "diagnostics.json")
    else:
        assert "Exchange.ManageAsApp admin consent" in explorer["reason"]
        assert gate_findings(run_dir=str(run_dir), fail_on="critical")["status"] == "blocked"
        ledger = load(run_dir, "normalized/coverage_ledger.json")["records"]
        assert "Exchange.ManageAsApp admin consent" in next(row for row in ledger if row["collector"] == "exchange_policy")["message"]
    assert load(run_dir, "validation.json")["valid"] is True


def test_offline_notice_only_when_selected_and_no_console_exit_text_in_artifacts():
    from azure_tenant_audit.data_handling import collector_activity_notices
    from azure_tenant_audit.dns_lookup import DEFAULT_DOH_ENDPOINT

    assert not collector_activity_notices(["identity"], "offline")
    text = " ".join(collector_activity_notices(["exchange_policy", "dns_posture"], "app"))
    assert "Will collect" not in text and "process exit" not in text
    # Pin the named resolver to its shipped endpoint, so a constant change cannot silently mislabel it.
    assert DEFAULT_DOH_ENDPOINT == "https://cloudflare-dns.com/dns-query"
    assert "Cloudflare" in text and DEFAULT_DOH_ENDPOINT in text


def test_explicit_delegated_exchange_is_selected_and_reports_auth_mode_reason(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from azure_tenant_audit import cli
    from azure_tenant_audit.adapters import powershell_graph
    from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter

    monkeypatch.setattr(cli, 'GraphClient', lambda *args, **kwargs: FakeGraph())
    monkeypatch.setattr(cli, '_acquire_azure_cli_access_token', lambda *args, **kwargs: 'constructed')
    monkeypatch.setattr(cli, '_capture_signed_in_context', lambda *args, **kwargs: {})
    monkeypatch.setattr(cli.run_core, 'collector_pause_seconds', lambda _: 0)
    monkeypatch.setattr('azure_tenant_audit.collectors.exchange_policy.get_adapter', lambda _: PowerShellGraphAdapter())
    monkeypatch.setattr('azure_tenant_audit.adapters.powershell_graph.shutil.which', lambda _: '/usr/bin/pwsh')
    monkeypatch.setattr('azure_tenant_audit.adapters.powershell_graph.subprocess.run', lambda *args, **kwargs:
        SimpleNamespace(returncode=1, stdout='', stderr='The term Get-Read is not recognized'))
    native_calls = []

    def forbidden_native_process(*args, **kwargs):
        native_calls.append(True)
        raise AssertionError('This delegated fixture must not start a native process')

    monkeypatch.setattr(powershell_graph, '_run_bounded', lambda *args, **kwargs:
        SimpleNamespace(returncode=1, stdout=b'', stderr='The term Get-Read is not recognized',
                        stdout_total=0, stderr_total=35, overflow=False, timed_out=False, duration_ms=0, pid=0))
    monkeypatch.setattr(powershell_graph.subprocess, 'Popen', forbidden_native_process)
    args = cli.build_parser().parse_args([
        '--tenant-name', 'acme', '--tenant-id', 'constructed', '--use-azure-cli-token',
        '--collectors', 'exchange_policy', '--out', str(tmp_path), '--run-name', 'explicit',
    ])
    assert cli.run_live(args) == 0
    run_dir = tmp_path / 'acme-explicit'
    manifest = load(run_dir, 'run-manifest.json')
    assert manifest['selected_collectors'] == ['exchange_policy']
    assert manifest['overall_status'] == 'partial'
    ledger = load(run_dir, 'normalized/coverage_ledger.json')['records']
    assert 'cannot open an Exchange Online policy session' in ledger[0]['message']
    assert gate_findings(run_dir=str(run_dir), fail_on='critical')['status'] == 'blocked'
    assert native_calls == []
