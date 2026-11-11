from __future__ import annotations

from pathlib import Path


def test_run_bundle_builder_writes_contract_shaped_artifacts(tmp_path: Path) -> None:
    from support import RunBundleBuilder

    run_dir = (
        RunBundleBuilder(tmp_path)
        .manifest(tenant_name="acme", run_id="run-1", report_pack_path="custom/report-pack.json")
        .summary(overall_status="partial")
        .report_pack(path="custom/report-pack.json", findings=[{"id": "f1"}])
        .blockers([{"collector": "identity"}])
        .build()
    )

    assert (run_dir / "run-manifest.json").exists()
    assert (run_dir / "summary.json").exists()
    assert (run_dir / "custom" / "report-pack.json").exists()
    assert (run_dir / "blockers" / "blockers.json").exists()


def test_fake_doctor_toolchain_installs_bootstrap_adapter(monkeypatch) -> None:
    from support import FakeDoctorToolchain

    from auditex import bootstrap

    toolchain = FakeDoctorToolchain(
        blocked_tools={"pwsh"},
        exchange_auth={"status": "blocked", "error": "module_not_found"},
    )
    toolchain.install(monkeypatch, bootstrap)

    report = bootstrap.build_doctor_report()

    assert report["python"]["status"] == "supported"
    assert report["tools"]["pwsh"]["status"] == "blocked"
    assert report["auth"]["exchange"]["error"] == "module_not_found"


def test_fake_graph_helpers_make_token_client_without_network() -> None:
    from support import fake_graph_client, graph_response

    client = fake_graph_client()
    response = graph_response(200, {"value": [{"id": "1"}]})

    assert client.auth.access_token == "x"
    assert response.json()["value"][0]["id"] == "1"
