from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from support import FAKE_CERTIFICATE_ARGS, use_fake_certificate

from azure_tenant_audit.collectors.base import CollectorResult
from azure_tenant_audit.probe import ProbeConfig, _build_probe_snapshot, run_live_probe

# The reader app and its certificate for the app probe; use_fake_certificate makes the certificate load.
CERTIFICATE = {"client_id": "constructed-app", "certificate_path": FAKE_CERTIFICATE_ARGS[1],
               "certificate_thumbprint": FAKE_CERTIFICATE_ARGS[3]}


class _FakeCollector:
    name = "identity"

    def run(self, _context):
        return CollectorResult(
            name="identity",
            status="ok",
            item_count=1,
            message="ok",
            payload={"users": {"value": [{"id": "1", "displayName": "User One"}]}},
            coverage=[
                {
                    "collector": "identity",
                    "type": "graph",
                    "name": "users",
                    "endpoint": "/users",
                    "status": "ok",
                    "item_count": 1,
                }
            ],
        )


class _FakeClient:
    def __init__(self, auth, audit_event=None):
        self.auth = auth
        self.audit_event = audit_event


def test_probe_live_writes_capability_and_toolchain_artifacts(tmp_path: Path, monkeypatch) -> None:
    use_fake_certificate(monkeypatch)
    monkeypatch.setattr("azure_tenant_audit.probe.GraphClient", _FakeClient)
    monkeypatch.setattr(
        "azure_tenant_audit.probe._probe_toolchain_statuses",
        lambda **_: [
            {
                "collector": "toolchain",
                "surface": "pwsh",
                "type": "toolchain",
                "name": "pwsh",
                "toolchain": "pwsh",
                "status": "supported",
                "item_count": 1,
                "message": "PowerShell is available.",
            }
        ],
    )
    monkeypatch.setattr("azure_tenant_audit.probe.REGISTRY", {"identity": _FakeCollector()})

    rc = run_live_probe(
        ProbeConfig(
            tenant_name="contoso",
            output_dir=tmp_path,
            tenant_id="tenant-id",
            mode="app",
            surface="identity",
            run_name="probe-live",
            **CERTIFICATE,
        )
    )
    assert rc == 0

    run_dir = tmp_path / "contoso-probe-live"
    capability_matrix = json.loads((run_dir / "capability-matrix.json").read_text(encoding="utf-8"))
    toolchain = json.loads((run_dir / "toolchain-readiness.json").read_text(encoding="utf-8"))
    live_readiness = json.loads((run_dir / "live-readiness.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))

    assert capability_matrix[0]["surface"] == "identity"
    assert capability_matrix[0]["toolchain"] == "graph"
    assert live_readiness["trust_level"] == "live_verified"
    assert live_readiness["trusted_collectors"] == ["identity"]
    assert toolchain["pwsh"]["status"] == "supported"
    assert manifest["probe_mode"] == "app" and manifest["mode"] == "app" and manifest["auth_path"] == "app"
    assert manifest["probe_surface"] == "identity"
    assert manifest["capability_matrix_path"] == "capability-matrix.json"
    assert manifest["toolchain_readiness_path"] == "toolchain-readiness.json"
    assert manifest["live_readiness_path"] == "live-readiness.json"
    assert manifest["provider_adapter_version"] == "2026-05-31"
    assert manifest["api_inventory_recorder_version"] == "2026-05-31"
    assert (run_dir / "index" / "evidence.sqlite").exists()


def test_windows365_probe_carries_successful_empty_read_into_trust(tmp_path: Path, monkeypatch) -> None:
    use_fake_certificate(monkeypatch)
    monkeypatch.setattr("azure_tenant_audit.probe.GraphClient", _FakeClient)
    monkeypatch.setattr("azure_tenant_audit.probe._probe_toolchain_statuses", lambda **_: [])

    def windows_probe(_cfg, *, client, writer):
        row = {"collector": "windows365", "type": "graph", "name": "cloudPCs", "status": "ok", "item_count": 0}
        return {"name": "windows365", "status": "ok", "item_count": 0, "coverage_rows": 1}, [row], {}

    monkeypatch.setattr("azure_tenant_audit.probe._run_windows365_probe", windows_probe)
    rc = run_live_probe(ProbeConfig(
        tenant_name="contoso", output_dir=tmp_path, tenant_id="constructed", mode="app",
        surface="windows365", run_name="windows", **CERTIFICATE,
    ))

    assert rc == 0
    run_dir = tmp_path / "contoso-windows"
    readiness = json.loads((run_dir / "live-readiness.json").read_text())
    plan = json.loads((run_dir / "audit-plan.json").read_text())
    assert readiness["trust_level"] == "live_verified"
    assert readiness["trusted_collectors"] == ["windows365"]
    assert plan["evidence_gates"] == readiness["evidence_gates"]


def test_repeated_probe_labels_and_per_object_endpoints_have_distinct_indexed_keys(tmp_path: Path, monkeypatch) -> None:
    class _RepeatedCollector:
        def __init__(self, name, endpoints):
            self.name = name
            self.endpoints = endpoints

        def run(self, _context):
            return CollectorResult(
                name=self.name, status="ok", item_count=0, message="ok", payload={},
                coverage=[{
                    "collector": self.name, "type": "graph", "name": name,
                    "endpoint": endpoint, "status": "ok", "item_count": 0,
                } for name, endpoint in self.endpoints],
            )

    use_fake_certificate(monkeypatch)
    monkeypatch.setattr("azure_tenant_audit.probe.GraphClient", _FakeClient)
    monkeypatch.setattr("azure_tenant_audit.probe._probe_toolchain_statuses", lambda **_: [])
    monkeypatch.setattr("azure_tenant_audit.probe.REGISTRY", {
        "identity": _RepeatedCollector("identity", [("servicePrincipals", "/servicePrincipals")]),
        "app_consent": _RepeatedCollector("app_consent", [
            ("servicePrincipals", "/servicePrincipals"),
            ("servicePrincipalOwners", "/servicePrincipals/app-one/owners"),
            ("servicePrincipalOwners", "/servicePrincipals/app-two/owners"),
            ("servicePrincipalOwners", "/servicePrincipals/app-two/owners"),
        ]),
    })

    assert run_live_probe(ProbeConfig(
        tenant_name="fixture", tenant_id="tenant-id", output_dir=tmp_path,
        surface="identity,app_consent", run_name="overlap", **CERTIFICATE,
    )) == 0
    run = tmp_path / "fixture-overlap"
    rows = json.loads((run / "normalized/capabilities.json").read_text())["records"]
    assert len(rows) == len({row["key"] for row in rows}) == 5
    assert json.loads((run / "validation.json").read_text())["valid"] is True
    with sqlite3.connect(run / "index/evidence.sqlite") as connection:
        indexed = connection.execute(
            "SELECT COUNT(*), COUNT(DISTINCT record_key) FROM normalized_records WHERE section_name = ?",
            ("probe_capability",),
        ).fetchone()
    assert indexed == (5, 5)


def test_probe_keys_survive_reordering_and_changed_results_without_rewriting_raw_rows() -> None:
    rows = [{"surface": "app_consent", "collector": "app_consent", "type": "graph",
             "name": "owners", "endpoint": f"/servicePrincipals/{app}/owners", "status": "blocked"}
            for app in ("one", "two")]
    def keys(selected):
        snapshot = _build_probe_snapshot(
            tenant_name="fixture", run_id="run", capability_matrix=selected,
            toolchain_rows=[], blockers=[], session_context={},
        )
        return {row["endpoint"]: row["key"] for row in snapshot["capabilities"]["records"]}

    changed = [{**row, "status": "supported_exact_scope", "item_count": 3, "duration_ms": 5}
               for row in reversed(rows)]
    assert keys(rows) == keys(changed)
    assert all("key" not in row for row in rows)


def test_response_probe_requires_lab_guard_but_still_writes_blockers(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "azure_tenant_audit.probe._probe_toolchain_statuses",
        lambda **_: [],
    )

    rc = run_live_probe(
        ProbeConfig(
            tenant_name="contoso",
            output_dir=tmp_path,
            tenant_id="not-lab-tenant",
            auditor_profile="exchange-reader",
            mode="response",
            surface="all",
            run_name="probe-response",
            allow_lab_response=True,
        )
    )
    assert rc == 1

    run_dir = tmp_path / "contoso-probe-response"
    blockers = json.loads((run_dir / "blockers" / "blockers.json").read_text(encoding="utf-8"))
    capability_matrix = json.loads((run_dir / "capability-matrix.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))

    assert blockers[0]["error_class"] == "lab_guard"
    assert capability_matrix[0]["surface"] == "response.lab_guard"
    assert capability_matrix[0]["status"] == "blocked"
    assert manifest["lab_guard_state"] == "blocked"


@pytest.mark.parametrize("missing", ["client_id", "certificate_path", "certificate_thumbprint"])
def test_app_probe_without_the_reader_app_or_certificate_writes_auth_blocker(tmp_path: Path, monkeypatch, missing) -> None:
    use_fake_certificate(monkeypatch)
    monkeypatch.setattr("azure_tenant_audit.probe._probe_toolchain_statuses", lambda **_: [])
    monkeypatch.setattr("azure_tenant_audit.probe.GraphClient", lambda *args, **kwargs: pytest.fail("no client without it"))
    fields = {**CERTIFICATE, missing: None}

    rc = run_live_probe(ProbeConfig(
        tenant_name="contoso", output_dir=tmp_path, tenant_id="tenant-id", mode="app", surface="identity",
        run_name="probe-missing-auth", **fields,
    ))
    assert rc == 1

    run_dir = tmp_path / "contoso-probe-missing-auth"
    blockers = json.loads((run_dir / "blockers" / "blockers.json").read_text(encoding="utf-8"))
    assert blockers[0]["collector"] == "probe_auth"
    assert blockers[0]["error_class"] == "missing_app_credentials"
    assert "reader app with a certificate" in blockers[0]["error"]


def test_app_probe_with_an_unusable_certificate_writes_a_fixed_text_blocker(tmp_path: Path, monkeypatch) -> None:
    from azure_tenant_audit import probe
    from azure_tenant_audit.certificate_auth import CertificateAuthError

    def refuse(*_args, **_kwargs):
        raise CertificateAuthError("certificate_thumbprint_mismatch")

    monkeypatch.setattr(probe, "load_certificate_credential", refuse)
    monkeypatch.setattr("azure_tenant_audit.probe._probe_toolchain_statuses", lambda **_: [])
    monkeypatch.setattr("azure_tenant_audit.probe.GraphClient", lambda *args, **kwargs: pytest.fail("no client"))
    rc = run_live_probe(ProbeConfig(
        tenant_name="contoso", output_dir=tmp_path, tenant_id="tenant-id", mode="app", surface="identity",
        run_name="probe-bad-certificate", **CERTIFICATE,
    ))
    assert rc == 1
    run_dir = tmp_path / "contoso-probe-bad-certificate"
    blockers = json.loads((run_dir / "blockers" / "blockers.json").read_text(encoding="utf-8"))
    assert blockers[0]["error_class"] == "certificate_thumbprint_mismatch"
    assert FAKE_CERTIFICATE_ARGS[1] not in json.dumps(blockers)


def test_app_probe_refuses_a_certificate_inside_its_output_folder(tmp_path: Path, monkeypatch, certificate_material) -> None:
    import shutil

    monkeypatch.setattr("azure_tenant_audit.probe._probe_toolchain_statuses", lambda **_: [])
    monkeypatch.setattr("azure_tenant_audit.probe.GraphClient", lambda *args, **kwargs: pytest.fail("no client"))
    out = tmp_path / "probes"
    out.mkdir()
    key = out / "reader-app.pem"
    shutil.copy2(certificate_material.pem, key)
    key.chmod(0o600)
    rc = run_live_probe(ProbeConfig(
        tenant_name="contoso", output_dir=out, tenant_id="tenant-id", mode="app", surface="identity",
        run_name="probe-key-inside", client_id="constructed-app", certificate_path=str(key),
        certificate_thumbprint=certificate_material.thumbprint,
    ))
    assert rc == 1
    blockers = json.loads((out / "contoso-probe-key-inside" / "blockers" / "blockers.json").read_text(encoding="utf-8"))
    assert blockers[0]["error_class"] == "certificate_source_in_output"


@pytest.mark.parametrize("removed", [
    {"access_token": "constructed-token"}, {"use_azure_cli_token": True}, {"auth_context": "customer-token"},
    {"client_secret": "constructed-secret"}, {"mode": "delegated"},
])
def test_probe_refuses_the_removed_sign_in_ways_before_writing_anything(tmp_path: Path, monkeypatch, removed) -> None:
    monkeypatch.setattr("azure_tenant_audit.probe._probe_toolchain_statuses", lambda **_: pytest.fail("no probe"))
    with pytest.raises(ValueError) as caught:
        run_live_probe(ProbeConfig(tenant_name="contoso", output_dir=tmp_path, tenant_id="tenant-id",
                                   **{**CERTIFICATE, **removed}))
    assert "reader app with a certificate" in str(caught.value)
    assert "constructed" not in str(caught.value) and "customer-token" not in str(caught.value)
    assert list(tmp_path.iterdir()) == []


def test_probe_config_never_renders_a_removed_secret_field() -> None:
    cfg = ProbeConfig(tenant_name="contoso", output_dir=Path("o"), access_token="constructed-token",
                      client_secret="constructed-secret")
    assert "constructed" not in repr(cfg)


def test_probe_live_app_mode_writes_token_claims(tmp_path: Path, monkeypatch) -> None:
    class _FakeAppClient(_FakeClient):
        def token_claims(self):
            return {
                "tenant_id": "tenant-app",
                "audience": "https://graph.microsoft.com",
                "delegated_scopes": [],
                "app_roles": ["AuditLog.Read.All", "Directory.Read.All", "Application.ReadWrite.All"],
                "app_id": "app-id",
            }

    use_fake_certificate(monkeypatch)
    monkeypatch.setattr("azure_tenant_audit.probe.GraphClient", _FakeAppClient)
    monkeypatch.setattr(
        "azure_tenant_audit.probe._probe_toolchain_statuses",
        lambda **_: [],
    )
    monkeypatch.setattr("azure_tenant_audit.probe.REGISTRY", {"identity": _FakeCollector()})

    rc = run_live_probe(
        ProbeConfig(
            tenant_name="contoso",
            output_dir=tmp_path,
            tenant_id="tenant-app",
            mode="app",
            surface="identity",
            **{**CERTIFICATE, "client_id": "app-id"},
            run_name="probe-app-context",
        )
    )
    assert rc == 0

    run_dir = tmp_path / "contoso-probe-app-context"
    auth_context = json.loads((run_dir / "auth-context.json").read_text(encoding="utf-8"))
    assert auth_context["auth_mode"] == "app"
    assert auth_context["token_claims"]["app_roles"] == ["Application.ReadWrite.All", "AuditLog.Read.All", "Directory.Read.All"]
    safety = json.loads((run_dir / "api-inventory.json").read_text())["safety"]
    assert safety["scope_risk"] == "write_capable_scope_present"
    assert safety["write_capable_scopes"] == ["Application.ReadWrite.All"]
    assert safety["read_only"] is True and safety["write_actions"] is False


def test_probe_dns_accepted_domain_handoff(tmp_path: Path, monkeypatch) -> None:
    envelope = {"value": [{"DomainName": "Contoso.com", "IsCoexistenceDomain": False}]}
    calls = []
    contexts = {}

    class _Collector:
        def __init__(self, name):
            self.name = name

        def run(self, context):
            calls.append(self.name)
            contexts[self.name] = dict(context)
            payload = {"acceptedDomains": envelope} if self.name == "exchange_policy" else {}
            return CollectorResult(name=self.name, status="ok", item_count=1, message="ok", payload=payload)

    use_fake_certificate(monkeypatch)
    monkeypatch.setattr("azure_tenant_audit.probe.GraphClient", _FakeClient)
    monkeypatch.setattr("azure_tenant_audit.probe._probe_toolchain_statuses", lambda **_: [])
    monkeypatch.setattr("azure_tenant_audit.probe.REGISTRY", {
        name: _Collector(name) for name in ("dns_posture", "exchange_policy", "identity")
    })
    assert run_live_probe(ProbeConfig(
        tenant_name="fixture", tenant_id="tenant-id", output_dir=tmp_path,
        surface="dns_posture,exchange_policy,identity", run_name="handoff", **CERTIFICATE,
    )) == 0
    assert calls == ["exchange_policy", "dns_posture", "identity"]
    assert contexts["dns_posture"]["exchange_accepted_domains"] == envelope
    assert "exchange_accepted_domains" not in contexts["exchange_policy"]
    assert "exchange_accepted_domains" not in contexts["identity"]


def test_app_probe_all_includes_default_workloads_and_only_app_and_response_modes_exist():
    from azure_tenant_audit.probe import _resolve_requested_surfaces, probe_mode_choices

    assert {"exchange_policy", "dns_posture"} <= set(_resolve_requested_surfaces("all", "app"))
    assert probe_mode_choices() == ("app", "response")


@pytest.mark.parametrize('surface,expected', [
    ('all', ('Exchange Online PowerShell session', 'Cloudflare')),
    ('exchange_policy', ('Exchange Online PowerShell session',)),
    ('dns_posture', ('Cloudflare',)),
    ('identity', ()),
])
def test_probe_prints_selected_activity_before_toolchain_or_tenant_reads(tmp_path, monkeypatch, capsys, surface, expected):
    def toolchains(**kwargs):
        text = capsys.readouterr().out
        for phrase in ('Exchange Online PowerShell session', 'Cloudflare'):
            assert (phrase in text) == (phrase in expected)
        assert text.count('Collection notice:') == len(expected)
        assert '--exclude' not in text  # Probes select with --surface.
        return []

    monkeypatch.setattr('azure_tenant_audit.probe._probe_toolchain_statuses', toolchains)
    monkeypatch.setattr('azure_tenant_audit.probe.GraphClient', lambda *args, **kwargs: pytest.fail('No tenant reads'))
    assert run_live_probe(ProbeConfig(
        tenant_name='constructed', tenant_id='constructed', output_dir=tmp_path,
        mode='app', surface=surface,
    )) == 1  # A missing certificate stops the probe after its notices.
