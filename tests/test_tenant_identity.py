from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from auditex.compare import compare_runs, require_same_tenant_runs
from auditex.explorer import ExplorerCompareError, build_explorer_bundle, build_explorer_data, render_explorer_html
from auditex.run_bundle import RunBundle
from azure_tenant_audit.ai_context import build_privacy_block
from azure_tenant_audit.contracts import build_validation_report
from azure_tenant_audit.evidence_db import build_run_evidence_index
from azure_tenant_audit.output import AuditWriter
from azure_tenant_audit.provider_runtime import ProviderFinalizePlan, write_provider_bundle
from azure_tenant_audit.tenant_identity import IDENTITY_FIELDS, resolve_tenant_identity


TENANT = "a1234567-1234-4123-8123-123456789abc"
OTHER = "b1234567-1234-4123-8123-123456789abc"
DOMAIN = "customer.onmicrosoft.com"


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _prepare(
    root: Path, *, mode: str = "app", label: str = "Customer", requested: str | None = DOMAIN,
    organization: str | None = TENANT, claim: str | None = TENANT, synthetic: bool = False,
    completed: bool = False,
) -> tuple[AuditWriter, ProviderFinalizePlan]:
    writer = AuditWriter(root, tenant_name=label, run_name="audit")
    if organization:
        payload = {"organization": {"value": [{
            "id": organization, "displayName": label,
            "verifiedDomains": [{"name": DOMAIN, "isDefault": True}],
        }]}}
        if mode == "offline":
            writer.write_raw("sample_input", {"identity": payload})
        else:
            writer.write_raw("identity", payload)
    if claim:
        writer.write_normalized("auth_context", {
            "auth_mode": mode, "tenant_id": requested,
            "token_claims": {
                "tenant_id": claim, "audience": "https://graph.microsoft.com",
                "delegated_scopes": ["Directory.Read.All"] if mode == "delegated" else [],
                "app_roles": ["Directory.Read.All"] if mode == "app" else [],
            },
        })
    snapshot = {"snapshot": {"normalized_counts": {}}}
    writer.write_normalized("snapshot", snapshot["snapshot"])
    ledger = [{"collector": "identity", "coverage_status": "complete_exact_scope"}] if completed else []
    if ledger:
        writer.write_normalized("coverage_ledger", {"kind": "coverage_ledger", "records": ledger})
    plan = ProviderFinalizePlan(
        tenant_name=label, tenant_id=requested, executed_by="azure_tenant_audit",
        selected_collectors=["identity"] if completed else [],
        overall_status="ok", duration_seconds=0, mode=mode, auditor_profile="auto", plane="inventory",
        findings=[], blockers=[], evidence_paths=[], normalized_snapshot=snapshot, capability_rows=[],
        coverage_ledger=ledger,
        privacy=build_privacy_block(safe_for_external_llm=False),
        bundle_metadata={"platform": "m365", "fixture_provenance": {"synthetic": True} if synthetic else None},
    )
    return writer, plan


def _bundle(root: Path, **kwargs) -> Path:
    writer, plan = _prepare(root, **kwargs)
    write_provider_bundle(writer=writer, plan=plan)
    return writer.run_dir


def _mirrors(run: Path) -> list[dict]:
    with sqlite3.connect(run / "index/evidence.sqlite") as conn:
        meta = dict(conn.execute("SELECT key, value FROM run_meta"))
    indexed = {
        "tenant_id": meta["tenant_id"] or None,
        "tenant_id_requested": meta["tenant_id_requested"] or None,
        "tenant_identity": json.loads(meta["tenant_identity"]),
    }
    return [
        _read(run / "run-manifest.json"), _read(run / "summary.json"),
        _read(run / "reports/report-pack.json")["summary"], _read(run / "ai_context.json")["run"],
        indexed, json.loads(meta["summary"]),
    ]


@pytest.mark.parametrize("mode,organization,claim", [
    ("app", TENANT.upper(), TENANT),
    ("app", None, TENANT.upper()),
    ("delegated", TENANT, TENANT.upper()),
    ("delegated", None, TENANT),
    ("offline", TENANT.upper(), None),
])
def test_real_shaped_evidence_stamps_one_canonical_identity_everywhere(tmp_path, mode, organization, claim):
    run = _bundle(tmp_path, mode=mode, organization=organization, claim=claim)
    mirrors = _mirrors(run)
    expected = {key: mirrors[0][key] for key in IDENTITY_FIELDS}
    assert expected["tenant_id"] == TENANT
    assert expected["tenant_id_requested"] == DOMAIN
    assert expected["tenant_identity"]["status"] == "verified"
    assert all({key: surface[key] for key in IDENTITY_FIELDS} == expected for surface in mirrors)
    for source in expected["tenant_identity"]["sources"]:
        assert source["tenant_id"] == TENANT
        assert set(source) == {"tenant_id", "source", "artifact_path", "json_pointer"}
        assert (run / source["artifact_path"]).is_file()
    assert _read(run / "validation.json")["valid"] is True
    assert RunBundle(run).metadata()["tenant_id"] == TENANT


@pytest.mark.parametrize("requested", [None, "organizations", DOMAIN, TENANT, "not-a-uuid", "00000000-0000-0000-0000-000000000000"])
def test_input_and_label_alone_never_establish_a_uuid(tmp_path, requested):
    run = _bundle(tmp_path, label=TENANT, requested=requested, organization=None, claim=None)
    for surface in _mirrors(run):
        assert surface["tenant_id"] is None
        assert surface["tenant_id_requested"] == requested
        assert surface["tenant_identity"]["status"] == "unknown"
    assert _read(run / "validation.json")["valid"] is True
    assert RunBundle(run).metadata()["tenant_id"] is None


def test_drift_gate_blocks_different_tenants_before_loading_findings(tmp_path, monkeypatch):
    from auditex.cli import gate_drift

    before = _bundle(tmp_path / "before")
    after = _bundle(tmp_path / "after", organization=OTHER, claim=OTHER, requested=OTHER)
    monkeypatch.setattr(RunBundle, "finding_rows", lambda self: pytest.fail("cross-tenant findings must not be loaded"))
    result = gate_drift(baseline_run_dir=str(before), current_run_dir=str(after), fail_on="high")
    assert result["pass"] is False and result["status"] == "blocked"
    assert "tenant_id_mismatch" in result["reason"]


def test_drift_gate_allows_renamed_verified_tenant_and_reports_identity_basis(tmp_path):
    from auditex.cli import gate_drift

    # The gate only trusts runs in which a collector completed, so these bundles carry one.
    before = _bundle(tmp_path / "before", label="Previous name", completed=True)
    after = _bundle(tmp_path / "after", label="Current name", completed=True)
    result = gate_drift(baseline_run_dir=str(before), current_run_dir=str(after), fail_on="high")
    assert result["pass"] is True
    assert result["compare_context"]["identity_basis"] == "verified_tenant_id"


def test_explicit_synthetic_uuid_is_not_verified_as_a_real_tenant(tmp_path):
    run = _bundle(tmp_path, mode="offline", synthetic=True, claim=None)
    assert _read(run / "validation.json")["valid"] is True
    for surface in _mirrors(run):
        assert surface["tenant_id"] is None
        assert surface["tenant_identity"]["reason"] == "synthetic_fixture"
    assert RunBundle(run).metadata()["tenant_identity"]["status"] == "unknown"


@pytest.mark.parametrize("variant", ["claim", "organizations", "two_claims", "requested_uuid", "requested_domain"])
def test_disagreeing_observations_or_requests_record_invalid_non_comparable_bundle(tmp_path, variant):
    writer, plan = _prepare(tmp_path)
    if variant == "claim":
        writer.write_normalized("auth_context", {"token_claims": {"tenant_id": OTHER}})
    elif variant == "organizations":
        writer.write_raw("domains_hybrid", {"organization": {"value": [{"id": OTHER}]}})
    elif variant == "two_claims":
        writer.write_normalized("auth_context", {"token_claims": {"tenant_id": TENANT, "tid": OTHER}})
    else:
        plan = replace(plan, tenant_id=OTHER if variant == "requested_uuid" else "other.onmicrosoft.com")
    write_provider_bundle(writer=writer, plan=plan)
    for surface in _mirrors(writer.run_dir):
        assert surface["tenant_id"] is None
        assert surface["tenant_identity"]["status"] == "conflict"
        assert surface["tenant_identity"]["conflicts"]
    assert _read(writer.run_dir / "run-manifest.json")["contract_status"] == "invalid"
    assert "tenant_identity_conflict" in {issue["code"] for issue in _read(writer.run_dir / "validation.json")["issues"]}
    other_run = _bundle(tmp_path / "comparison")
    comparison = compare_runs([writer.run_dir, other_run], allow_cross_tenant=True)
    assert comparison["baseline_diff"]["status"] == "blocked"
    assert comparison["baseline_diff"]["reason"] == "tenant_identity_conflict"


def test_incomplete_domain_sample_does_not_falsely_reject_an_alias(tmp_path):
    writer, plan = _prepare(tmp_path, organization=None)
    writer.write_raw("identity", {
        "organization": {"value": [{"id": TENANT}]},
        "domains": {"value": [{"id": "first.example", "isVerified": True}], "item_count": 21, "sample_truncated": True},
    })
    write_provider_bundle(writer=writer, plan=plan)
    identity = _read(writer.run_dir / "run-manifest.json")["tenant_identity"]
    assert identity["status"] == "verified"
    assert identity["requested_match"] == "unknown"


@pytest.mark.parametrize("artifact,section", [
    ("run-manifest.json", None), ("summary.json", None),
    ("reports/report-pack.json", "summary"), ("reports/report-pack.json", None),
    ("ai_context.json", "run"), ("index/evidence.sqlite", None),
])
def test_stale_or_mislabeled_metadata_is_rejected_in_contract_and_comparison(tmp_path, artifact, section):
    run = _bundle(tmp_path / "run")
    other_run = _bundle(tmp_path / "other")
    if artifact.endswith("sqlite"):
        with sqlite3.connect(run / artifact) as conn:
            conn.execute("UPDATE run_meta SET value = ? WHERE key = 'tenant_id'", (OTHER,))
    else:
        payload = _read(run / artifact)
        target = payload[section] if section else payload
        target["tenant_id"] = OTHER
        _write(run / artifact, payload)
    assert _read(run / "validation.json")["valid"] is True  # stale marker must not hide drift
    report = build_validation_report(run_dir=run, read_only=True)
    assert "tenant_identity_conflict" in {issue["code"] for issue in report["issues"]}
    assert RunBundle(run).metadata()["tenant_identity"]["status"] == "conflict"
    assert compare_runs([run, other_run], allow_cross_tenant=True)["baseline_diff"]["status"] == "blocked"
    with pytest.raises(ExplorerCompareError, match="tenant_identity_conflict"):
        build_explorer_bundle([run, other_run])


def test_same_verified_uuid_allows_a_renamed_label(tmp_path):
    left = _bundle(tmp_path / "old", label="Old name", requested=TENANT.upper())
    right = _bundle(tmp_path / "new", label="New name", requested=DOMAIN)
    result = compare_runs([left, right])
    assert result["baseline_diff"]["status"] == "ok"
    assert result["compare_context"]["identity_basis"] == "verified_tenant_id"
    assert result["compare_context"]["identity_verified"] is True
    assert require_same_tenant_runs([left, right])["legacy_fallback"] is False
    assert build_explorer_bundle([left, right])["compare"]["compare_context"]["identity_verified"] is True


def test_same_label_cannot_override_different_established_uuids(tmp_path):
    left = _bundle(tmp_path / "one")
    right = _bundle(tmp_path / "two", organization=OTHER, claim=OTHER)
    for allow_cross_tenant in (False, True):
        result = compare_runs([left, right], allow_cross_tenant=allow_cross_tenant)
        assert result["baseline_diff"]["status"] == "blocked"
        assert result["baseline_diff"]["reason"] == "tenant_id_mismatch"
    with pytest.raises(ValueError, match="tenant_id_mismatch"):
        require_same_tenant_runs([left, right])
    with pytest.raises(ExplorerCompareError, match="tenant_id_mismatch"):
        build_explorer_bundle([left, right])
    with pytest.raises(ExplorerCompareError, match="tenant_id_mismatch"):
        render_explorer_html({"runs": [build_explorer_data(left), build_explorer_data(right)]})


def _legacy(root: Path, *, tenant_id: str | None = None, label: str = "Customer") -> Path:
    manifest = {"tenant_name": label, "run_id": root.name, "platform": "m365"}
    if tenant_id:
        manifest["tenant_id"] = tenant_id
    _write(root / "run-manifest.json", manifest)
    return root


def test_legacy_unknown_label_and_domain_fallbacks_are_explicit(tmp_path):
    left, right = [_legacy(tmp_path / name) for name in ("a", "b")]
    result = compare_runs([left, right])
    assert result["baseline_diff"]["status"] == "ok"
    assert result["compare_context"]["identity_basis"] == "legacy_tenant_name"
    assert result["compare_context"]["identity_verified"] is False
    assert result["compare_context"]["unknown_identity_count"] == 2
    left = _legacy(tmp_path / "domain-a", tenant_id=DOMAIN, label="Old")
    right = _legacy(tmp_path / "domain-b", tenant_id=DOMAIN.upper(), label="New")
    metadata = RunBundle(left).metadata()
    assert metadata["tenant_id"] is None
    assert metadata["tenant_id_requested"] == DOMAIN
    assert metadata["tenant_identity"]["status"] == "unknown"
    assert compare_runs([left, right])["compare_context"]["identity_basis"] == "domain_alias"


def test_legacy_uuid_case_and_conflicts_are_respected_without_claiming_verification(tmp_path):
    left = _legacy(tmp_path / "one", tenant_id=TENANT.upper(), label="Old")
    right = _legacy(tmp_path / "two", tenant_id=TENANT, label="New")
    result = compare_runs([left, right])
    assert result["baseline_diff"]["status"] == "ok"
    assert result["compare_context"]["identity_verified"] is False
    assert result["compare_context"]["identity_basis"] == "legacy_tenant_id"
    other = _legacy(tmp_path / "other", tenant_id=OTHER, label="Old")
    assert compare_runs([left, other], allow_cross_tenant=True)["baseline_diff"]["status"] == "blocked"


def test_legacy_manifest_without_id_recovers_recorded_evidence_and_detects_wrong_labels(tmp_path):
    run = _legacy(tmp_path / "legacy")
    _write(run / "raw/identity.json", {"organization": {"value": [{"id": TENANT.upper()}]}})
    _write(run / "normalized/auth_context.json", {"tenant_id": DOMAIN, "token_claims": {"tenant_id": TENANT}})
    _write(run / "ai_context.json", {"run": {"tenant_id": DOMAIN}})
    assert RunBundle(run).metadata()["tenant_id"] == TENANT
    assert RunBundle(run).metadata()["tenant_id_requested"] == DOMAIN
    _write(run / "summary.json", {"tenant_id": OTHER})
    assert RunBundle(run).metadata()["tenant_identity"]["status"] == "conflict"


def test_legacy_bundle_without_optional_fields_still_validates(tmp_path):
    run = _bundle(tmp_path, organization=None, claim=None, requested=None)
    for artifact, section in (("run-manifest.json", None), ("summary.json", None), ("reports/report-pack.json", "summary"), ("ai_context.json", "run")):
        payload = _read(run / artifact)
        target = payload[section] if section else payload
        for key in IDENTITY_FIELDS:
            target.pop(key, None)
        _write(run / artifact, payload)
    build_run_evidence_index(run)
    assert build_validation_report(run_dir=run, read_only=True)["valid"] is True


def test_refinalization_cannot_reassign_an_established_bundle(tmp_path):
    writer, plan = _prepare(tmp_path)
    write_provider_bundle(writer=writer, plan=plan)
    writer.write_raw("identity", {"organization": {"value": [{"id": OTHER}]}})
    writer.write_normalized("auth_context", {"token_claims": {"tenant_id": OTHER}})
    plan = replace(plan, tenant_id=OTHER)
    write_provider_bundle(writer=writer, plan=plan)
    first = _read(writer.run_dir / "run-manifest.json")
    assert first["tenant_identity"]["status"] == "conflict"
    assert {"code": "existing_tenant_mismatch", "tenant_id": TENANT} in first["tenant_identity"]["conflicts"]
    write_provider_bundle(writer=writer, plan=plan)
    assert _read(writer.run_dir / "run-manifest.json")["tenant_identity"] == first["tenant_identity"]


@pytest.mark.parametrize("customer_id", ["my_customer", "C012345"])
def test_google_customer_and_domain_semantics_are_separate_from_entra(tmp_path, customer_id):
    writer, plan = _prepare(tmp_path, organization=None, claim=None)
    plan = replace(plan, tenant_id=customer_id, bundle_metadata={
        "platform": "google_workspace", "customer_id": customer_id, "workspace_domain": "workspace.example",
    })
    write_provider_bundle(writer=writer, plan=plan)
    for surface in _mirrors(writer.run_dir):
        assert surface["tenant_id"] == (None if customer_id == "my_customer" else customer_id)
        assert surface["tenant_identity"]["kind"] == "google_customer_id"
        assert surface["tenant_identity"]["status"] != "verified"
    assert _read(writer.run_dir / "validation.json")["valid"] is True


def test_google_auth_relative_alias_does_not_identify_two_domains_as_one_tenant(tmp_path):
    runs = []
    for domain in ("one.example", "two.example"):
        run = tmp_path / domain
        _write(run / "run-manifest.json", {"tenant_name": "Same label", "platform": "google_workspace", "customer_id": "my_customer", "workspace_domain": domain})
        runs.append(run)
    assert compare_runs(runs)["baseline_diff"]["status"] == "blocked"


def test_ids_of_partner_tenants_and_resources_are_not_identity_evidence(tmp_path):
    _write(tmp_path / "normalized/cross_tenant_access_objects.json", {"records": [{"tenant_id": TENANT}]})
    _write(tmp_path / "raw/identity.json", {"users": {"value": [{"id": TENANT}]}})
    fields = resolve_tenant_identity(tmp_path, requested=TENANT)
    assert fields["tenant_id"] is None
    assert fields["tenant_identity"]["status"] == "unknown"


@pytest.mark.parametrize("conflict", [False, True])
def test_identity_finalization_is_idempotent(tmp_path, conflict):
    writer, plan = _prepare(tmp_path, claim=OTHER if conflict else TENANT)
    write_provider_bundle(writer=writer, plan=plan)
    artifacts = ("summary.json", "reports/report-pack.json", "ai_context.json", "validation.json")
    before = {name: (writer.run_dir / name).read_bytes() for name in artifacts}
    write_provider_bundle(writer=writer, plan=plan)
    assert {name: (writer.run_dir / name).read_bytes() for name in artifacts} == before


def test_mismatched_legacy_domain_metadata_is_not_silently_promoted(tmp_path):
    run = _legacy(tmp_path / "legacy")
    _write(run / "raw/identity.json", {"organization": {"value": [{"id": TENANT, "verifiedDomains": [{"name": DOMAIN}]}]}})
    _write(run / "summary.json", {"tenant_id": "wrong.example"})
    assert RunBundle(run).metadata()["tenant_identity"]["status"] == "conflict"


def test_removing_evidence_does_not_turn_established_identity_into_label_fallback(tmp_path):
    writer, plan = _prepare(tmp_path)
    write_provider_bundle(writer=writer, plan=plan)
    (writer.run_dir / "raw/identity.json").unlink()
    (writer.run_dir / "normalized/auth_context.json").unlink()
    assert RunBundle(writer.run_dir).metadata()["tenant_identity"]["status"] == "conflict"
    write_provider_bundle(writer=writer, plan=plan)
    assert _read(writer.run_dir / "run-manifest.json")["tenant_identity"]["status"] == "conflict"


def test_mixed_legacy_unknown_and_verified_bundle_discloses_fallback(tmp_path):
    verified = _bundle(tmp_path / "verified")
    unknown = _legacy(tmp_path / "unknown")
    context = require_same_tenant_runs([verified, unknown])
    assert context["identity_verified"] is False
    assert context["legacy_fallback"] is True
    assert context["identity_basis"] == "legacy_tenant_name"
    assert context["unknown_identity_count"] == 1


@pytest.mark.parametrize("field", ["tenant_id", "tenant_id_requested", "tenant_identity"])
def test_missing_identity_mirror_cannot_be_treated_as_a_legacy_bundle(tmp_path, field):
    run = _bundle(tmp_path)
    manifest = _read(run / "run-manifest.json")
    manifest.pop(field)
    _write(run / "run-manifest.json", manifest)
    assert build_validation_report(run_dir=run, read_only=True)["valid"] is False
    assert RunBundle(run).metadata()["tenant_identity"]["status"] == "conflict"


def test_fixture_marker_cannot_demote_an_existing_verified_identity(tmp_path):
    run = _bundle(tmp_path)
    manifest = _read(run / "run-manifest.json")
    manifest["fixture_provenance"] = {"synthetic": True}
    _write(run / "run-manifest.json", manifest)
    assert RunBundle(run).metadata()["tenant_identity"]["status"] == "conflict"
