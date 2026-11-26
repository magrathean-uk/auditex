"""PRIV-CUSTOMER-ID: the Google Workspace customer id never reaches a run bundle file or a shareable export.

The operator's ``--customer-id`` is used for the API calls only; the bundle records the ``my_customer`` alias as it is
and any other configured value as ``null``. A customer id the API returns or an error quotes is replaced by a marker.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from auditex import cli as auditex_cli

CUSTOMER_ID = "C0zq7x91k"
SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "google_workspace_sample.json"


def _files_holding(root: Path, needle: str) -> list[str]:
    raw = needle.encode("utf-8")
    return sorted(
        str(path.relative_to(root)) for path in root.rglob("*") if path.is_file() and raw in path.read_bytes()
    )


def _offline_run(out: Path, customer_id: str = CUSTOMER_ID) -> Path:
    rc = auditex_cli.main(
        [
            "google", "run", "--offline", "--sample", str(SAMPLE), "--domain", "example.com",
            "--customer-id", customer_id, "--tenant-name", "Example", "--run-name", "cid", "--out", str(out),
        ]
    )
    assert rc == 0
    return out / "Example-cid"


def test_offline_google_run_and_its_exports_hold_no_customer_id(tmp_path: Path, capsys) -> None:
    from auditex.cli import run_exporter, verify_customer_pack, write_customer_pack
    from auditex.reporting import render_report
    from azure_tenant_audit.output_redaction import PROFILE_LOCAL, PROFILE_SHAREABLE

    run_dir = _offline_run(tmp_path / "out")

    assert _files_holding(run_dir, CUSTOMER_ID) == []
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    # A null value is left out of the manifest.
    assert manifest.get("customer_id") is None
    assert manifest.get("tenant_id") is None
    assert manifest.get("tenant_id_requested") is None
    assert manifest["workspace_domain"] == "example.com"
    snapshot = json.loads((run_dir / "normalized" / "snapshot.json").read_text(encoding="utf-8"))
    assert snapshot["customer_id"] is None
    summary = json.loads((run_dir / "ai_safe" / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["customer_id"] is None
    assert json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))["valid"] is True

    exports = tmp_path / "exports"
    for profile in (PROFILE_SHAREABLE, PROFILE_LOCAL):
        for format_name in ("json", "md", "csv", "html", "sarif", "oscal"):
            render_report(
                run_dir=str(run_dir), format_name=format_name, profile=profile,
                output_path=str(exports / f"{profile}-report.{format_name}"),
            )
    for format_name in ("json", "md", "csv", "html", "sarif", "oscal"):
        run_exporter(name=format_name, run_dir=str(run_dir), output_path=str(exports / f"export.{format_name}"))
    write_customer_pack(str(run_dir), str(tmp_path / "pack"))
    assert verify_customer_pack(str(tmp_path / "pack"))["valid"] is True

    assert len(list(exports.iterdir())) == 18
    assert any((tmp_path / "pack").rglob("*.json"))
    assert _files_holding(exports, CUSTOMER_ID) == []
    assert _files_holding(tmp_path / "pack", CUSTOMER_ID) == []
    assert _files_holding(run_dir, CUSTOMER_ID) == []
    captured = capsys.readouterr()
    assert CUSTOMER_ID not in captured.out + captured.err


def test_offline_google_run_keeps_the_my_customer_alias(tmp_path: Path) -> None:
    run_dir = _offline_run(tmp_path / "out", "my_customer")

    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["customer_id"] == "my_customer"
    assert manifest.get("tenant_id") is None


def test_offline_sample_customer_ids_are_withheld(tmp_path: Path) -> None:
    from auditex.google_workspace.run import run_google_offline

    sample = json.loads(SAMPLE.read_text(encoding="utf-8"))
    users = sample["google_directory"]["users"]["value"]
    users[0]["customerId"] = "C0learnt42"
    sample["google_alert_center"]["alerts"] = {
        "value": [], "error_class": "insufficient_permissions",
        "error": "HttpError 403 when requesting https://x.example/v1/customer/C0learnt42/a?customerId=C0learnt43",
    }
    path = tmp_path / "sample.json"
    path.write_text(json.dumps(sample), encoding="utf-8")

    rc = run_google_offline(
        sample_path=path, out=tmp_path / "out", tenant_name="Example", run_name="cid", domain="example.com",
        customer_id="my_customer",
    )

    # The fixture injects a failed alert read: the run is partial, never a success (review L1).
    assert rc == 1
    run_dir = tmp_path / "out" / "Example-cid"
    assert _files_holding(run_dir, "C0learnt42") == []
    assert _files_holding(run_dir, "C0learnt43") == []
    raw = json.loads((run_dir / "raw" / "google_directory.json").read_text(encoding="utf-8"))
    assert raw["users"]["value"][0]["customerId"] == "<customer-id>"


def test_live_google_run_withholds_configured_and_returned_customer_ids(tmp_path: Path, monkeypatch) -> None:
    from auditex.google_workspace import run as google_run
    from auditex.google_workspace.run import GoogleRunConfig, run_google_live
    from azure_tenant_audit.collectors.base import CollectorResult

    class _FakeCollector:
        name = "google_directory"
        required_scopes = ("scope://directory.readonly",)

        def run(self, _context):
            return CollectorResult(
                name=self.name,
                status="partial",
                item_count=1,
                message=f"read customer {CUSTOMER_ID}",
                payload={
                    "users": {"value": [{"id": "u1", "primaryEmail": "user@example.com", "customerId": "C0learnt42"}]},
                    "policies": {"value": [{"name": "policies/p1", "customer": "customers/C0learnt42"}]},
                },
                coverage=[
                    {"collector": self.name, "name": "users", "type": "google_api", "status": "ok", "item_count": 1},
                    {
                        "collector": self.name, "name": "roles", "type": "google_api", "status": "failed",
                        "item_count": 0, "error_class": "insufficient_permissions",
                        "error": f"<HttpError 403 when requesting https://admin.example/v1/customer/{CUSTOMER_ID}/roles?alt=json>",
                    },
                ],
            )

    monkeypatch.setattr(google_run, "REGISTRY", {"google_directory": _FakeCollector()})
    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True, "missing": [], "install_hint": ""})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: object())
    monkeypatch.setattr(google_run, "GoogleWorkspaceClient", lambda *_args, **_kwargs: object())

    run_google_live(
        GoogleRunConfig(
            tenant_name="Example", out=tmp_path, run_name="live", domain="example.com", customer_id=CUSTOMER_ID,
            subject="admin@example.com", service_account_key=tmp_path / "service-account.json",
            collectors="google_directory",
        ),
        command_line=["auditex", "google", "run", "--customer-id", CUSTOMER_ID, "--domain", "example.com"],
    )

    run_dir = tmp_path / "Example-live"
    assert (run_dir / "run-manifest.json").is_file()
    assert _files_holding(run_dir, CUSTOMER_ID) == []
    assert _files_holding(run_dir, "C0learnt42") == []
    auth_context = json.loads((run_dir / "auth-context.json").read_text(encoding="utf-8"))
    assert auth_context["customer_id"] is None
    raw = json.loads((run_dir / "raw" / "google_directory.json").read_text(encoding="utf-8"))
    assert raw["users"]["value"][0]["customerId"] == "<customer-id>"
    assert raw["policies"]["value"][0]["customer"] == "customers/<customer-id>"


def test_b1_live_id_learned_on_a_later_read_is_withheld_from_earlier_failures(tmp_path: Path, monkeypatch, caplog) -> None:
    from auditex.google_workspace import run as google_run
    from auditex.google_workspace.client import _execute
    from azure_tenant_audit.collectors.base import CollectorResult

    class FailedAlert:
        name = "google_alert_center"

        def run(self, context):
            message = "Customer customer_Account731_lookup was not found."
            logging.getLogger("googleapiclient.http").warning("HTTP library diagnostic: %s", message)
            logging.getLogger("googleapiclient.discovery").debug("HTTP library request: %s", message)
            context["audit_logger"]("collector.endpoint.finished", message, None)
            return CollectorResult(self.name, "failed", {"error": message}, 0, message)

    class PolicyRead:
        name = "google_policies"

        def run(self, _context):
            # The API returns the ID before its allow-list projection discards the customer field.
            _execute(lambda: {"policies": [{"customer": "customers/Account731"}]})
            return CollectorResult(self.name, "ok", {}, 0, "read policy")

    caplog.set_level(logging.DEBUG, logger="googleapiclient.discovery")
    monkeypatch.setattr(google_run, "REGISTRY", {"google_alert_center": FailedAlert(), "google_policies": PolicyRead()})
    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: object())
    assert google_run.run_google_live(google_run.GoogleRunConfig(
        tenant_name="Example", out=tmp_path, run_name="live", customer_id="my_customer",
        collectors="google_alert_center,google_policies", subject="admin@Account731.example",
    )) == 1
    run = tmp_path / "Example-live"
    assert "customer_<customer-id>_lookup" in (run / "audit-log.jsonl").read_text(encoding="utf-8")
    assert _files_holding(run, "Account731") == []
    assert "Account731" not in caplog.text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "<HttpError 403 when requesting https://admin.example/v1/users?customer=C0zq7x91k&alt=json returned x>",
            "<HttpError 403 when requesting https://admin.example/v1/users?customer=<customer-id>&alt=json returned x>",
        ),
        (
            "requesting https://admin.example/v1/customer/C0zq7x91k/roles?alt=json",
            "requesting https://admin.example/v1/customer/<customer-id>/roles?alt=json",
        ),
        ("filter=customer%3D%3D%22customers%2FC0zq7x91k%22", "filter=customer%3D%3D%22customers%2F<customer-id>%22"),
        ("orgunits?customerId=my_customer&type=all", "orgunits?customerId=my_customer&type=all"),
        ("Config2 Chrome126 /customers/Finance", "Config2 Chrome126 /customers/Finance"),
        ("HTTP 403 forbidden", "HTTP 403 forbidden"),
    ],
)
def test_google_error_text_withholds_the_customer_id(text: str, expected: str) -> None:
    from auditex.google_workspace.client import classify_google_error

    assert classify_google_error(RuntimeError(text))[1] == expected


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["--customer-id", CUSTOMER_ID], ["--customer-id", "***redacted***"]),
        ([f"--customer-id={CUSTOMER_ID}"], ["--customer-id=***redacted***"]),
    ],
)
def test_google_command_line_redacts_the_customer_id(argv: list[str], expected: list[str]) -> None:
    from auditex.google_workspace.run import scrub_google_command_line

    assert scrub_google_command_line(argv) == expected



# -- repair round 1 (review B1-B5) ---------------------------------------------------------------------------------


def test_mcp_command_withholds_the_customer_id_in_other_arguments() -> None:
    from auditex.command_runner import redact_command

    assert redact_command(["google", "probe", "--customer-id", "C0privA123", "--tenant-name", "C0privA123"]) == [
        "google", "probe", "--customer-id", "***redacted***", "--tenant-name", "***redacted***",
    ]


def _write_sample(path: Path, sample: dict) -> Path:
    path.write_text(json.dumps(sample), encoding="utf-8")
    return path


def _replay(
    out: Path, run_name: str, *, customer_id: str, domain: str = "example.com", sample: Path = SAMPLE,
    tenant_name: str = "Example",
) -> int:
    return auditex_cli.main(
        [
            "google", "run", "--offline", "--sample", str(sample), "--domain", domain, "--customer-id", customer_id,
            "--tenant-name", tenant_name, "--run-name", run_name, "--out", str(out),
        ]
    )


def _shareable_exports(run_dir: Path, out: Path) -> Path:
    from auditex.cli import write_customer_pack
    from auditex.reporting import render_report
    from azure_tenant_audit.output_redaction import PROFILE_SHAREABLE

    for format_name in ("json", "md", "csv", "html", "sarif", "oscal"):
        render_report(
            run_dir=str(run_dir), format_name=format_name, profile=PROFILE_SHAREABLE,
            output_path=str(out / f"report.{format_name}"),
        )
    write_customer_pack(str(run_dir), str(out / "pack"))
    return out


def test_b1_api_learned_customer_id_in_failure_text_and_malformed_values_is_withheld(tmp_path: Path) -> None:
    sample = json.loads(SAMPLE.read_text(encoding="utf-8"))
    users = sample["google_directory"]["users"]["value"]
    users[0]["customerId"] = "C0learn987"
    users[0]["customSchemas"] = {"Customers": {"C0learn987": True}}
    users[1 % len(users)]["customerId"] = {"value": "C0malformed7"}
    sample["google_alert_center"]["alerts"] = {
        "value": [], "error_class": "resource_not_found",
        "error": '<HttpError 404 when requesting https://alertcenter.googleapis.com/v1beta1/alerts?customerId='
                 'C123&alt=json returned "Customer customer_C0learn987_lookup was not found">',
    }
    path = _write_sample(tmp_path / "sample.json", sample)

    assert _replay(tmp_path / "out", "learned", customer_id="my_customer", sample=path) == 1

    run_dir = tmp_path / "out" / "Example-learned"
    exports = _shareable_exports(run_dir, tmp_path / "exports")
    for needle in ("C0learn987", "C0malformed7", "C123"):
        assert _files_holding(run_dir, needle) == []
        assert _files_holding(exports, needle) == []
    raw = json.loads((run_dir / "raw" / "google_directory.json").read_text(encoding="utf-8"))
    assert raw["users"]["value"][1 % len(users)]["customerId"] == "<customer-id>"
    blockers = (run_dir / "blockers" / "blockers.json").read_text(encoding="utf-8")
    assert raw["users"]["value"][0]["customSchemas"] == {"Customers": {"<customer-id>": True}}
    assert "Customer customer_<customer-id>_lookup was not found" in blockers
    assert "customerId=<customer-id>&alt=json" in blockers


def test_b1_live_classifier_withholds_a_customer_id_in_the_api_reason() -> None:
    from auditex.google_workspace.client import classify_google_error

    class _HttpError(Exception):
        def __init__(self) -> None:
            super().__init__('<HttpError 404 when requesting https://admin.googleapis.com/admin/directory/v1/users'
                             '?customerId=C123&alt=json returned "Customer customer_C123_lookup was not found">')
            self.resp = type("Resp", (), {"status": 404})()

    error_class, message = classify_google_error(_HttpError())
    assert message == ('<HttpError 404 when requesting https://admin.googleapis.com/admin/directory/v1/users'
                       '?customerId=<customer-id>&alt=json returned "Customer customer_<customer-id>_lookup was not found">')
    assert error_class == "resource_not_found"


def test_b1_classifier_learns_customer_id_from_error_metadata() -> None:
    from auditex.google_workspace.client import classify_google_error

    error = RuntimeError("Customer customer_Account731_lookup was not found")
    error.status_code = 404
    error.error_details = [{"metadata": {"customerId": "Account731"}}]
    assert classify_google_error(error) == ("resource_not_found", "Customer customer_<customer-id>_lookup was not found")


def test_b2_sample_filename_and_run_labels_are_withheld(tmp_path: Path, capsys) -> None:
    import hashlib

    data = SAMPLE.read_bytes()
    path = tmp_path / "C0privA123.json"
    path.write_bytes(data)

    assert _replay(
        tmp_path / "out", "C0privA123-run", customer_id="C0privA123", sample=path.resolve(), tenant_name="C0privA123",
    ) == 0

    run_dir = tmp_path / "out" / "customer-id-withheld-customer-id-withheld-run"
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["tenant_name"] == "customer-id-withheld"
    assert manifest["run_id"] == "customer-id-withheld-run"
    assert manifest["replay_source"] == {"file": "<customer-id>.json", "sha256": hashlib.sha256(data).hexdigest()}
    assert _files_holding(run_dir, "C0privA123") == []
    printed = capsys.readouterr()
    assert "C0privA123" not in printed.out + printed.err



def _probe_argv(out: Path) -> list[str]:
    return [
        "google", "probe", "--customer-id", "C0privA123", "--collectors", "google_directory", "--domain",
        "example.com", "--subject", "admin@example.com", "--tenant-name", "Example", "--run-name", "probe",
        "--out", str(out),
    ]


def test_b2_probe_failure_json_and_doctor_json_carry_no_customer_id(tmp_path: Path, monkeypatch, capsys) -> None:
    from auditex.google_workspace import run as google_run

    def refuse(_config):
        raise RuntimeError("synthetic sign-in refusal for customer C0privA123")

    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True, "missing": [], "install_hint": ""})
    monkeypatch.setattr(google_run, "build_google_credentials", refuse)

    assert auditex_cli.main(_probe_argv(tmp_path / "out")) == 2
    printed = capsys.readouterr()
    assert "C0privA123" not in printed.out + printed.err
    assert json.loads(printed.out)["target"] == {"domain": "example.com", "customer_id": None}
    assert _files_holding(tmp_path / "out", "C0privA123") == []

    assert auditex_cli.main(
        ["google", "doctor", "--json", "--customer-id", "C0privA123", "--domain", "C0privA123.example"],
    ) == 0
    printed = capsys.readouterr()
    assert "C0privA123" not in printed.out + printed.err
    assert json.loads(printed.out)["target"] == {"domain": "<customer-id>.example", "customer_id": None}


def test_b2_probe_withholds_the_id_learned_from_the_api(tmp_path: Path, monkeypatch, capsys) -> None:
    from auditex.google_workspace import run as google_run
    from auditex.google_workspace.client import _execute

    def preflight(*_args, **_kwargs):
        _execute(lambda: {"users": [{"customerId": "C123"}]})
        return [{
            "collector": "google_directory", "name": "users", "status": "failed", "item_count": 0,
            "error_class": "resource_not_found", "error": "Unknown customer_C123_lookup",
        }]

    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True, "missing": [], "install_hint": ""})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: object())
    monkeypatch.setattr(google_run, "build_google_preflight_rows", preflight)
    assert auditex_cli.main([
        "google", "probe", "--customer-id", "my_customer", "--collectors", "google_directory",
        "--domain", "C123.example", "--subject", "admin@C123.example", "--out", str(tmp_path),
        "--tenant-name", "Example", "--run-name", "learned",
    ]) == 1
    printed = capsys.readouterr()
    assert "C123" not in printed.out + printed.err
    result = json.loads(printed.out)
    assert result["target"] == {"domain": "<customer-id>.example", "customer_id": "my_customer"}
    assert result["preflight"][0]["error"] == "Unknown customer_<customer-id>_lookup"
    assert _files_holding(tmp_path / "Example-learned", "C123") == []


def test_b3_probe_without_dependencies_prints_no_customer_id(tmp_path: Path, monkeypatch, capsys) -> None:
    from auditex.google_workspace import run as google_run

    monkeypatch.setattr(
        google_run, "google_dependency_status", lambda: {"available": False, "missing": ["x"], "install_hint": "pip"},
    )
    assert auditex_cli.main(_probe_argv(tmp_path / "out")) == 2
    printed = capsys.readouterr()
    assert "C0privA123" not in printed.out + printed.err
    assert _files_holding(tmp_path / "out", "C0privA123") == []


def test_compare_and_drift_use_the_workspace_domain(tmp_path: Path) -> None:
    from auditex.compare import compare_run_directories
    from auditex.gate import gate_drift

    out = tmp_path / "out"
    assert _replay(out, "a", customer_id="C0privA123") == 0
    assert _replay(out, "b", customer_id="C0privB456") == 0
    assert _replay(out, "c", customer_id="C0privA123", domain="other.example") == 0
    run_a, run_b, run_c = (out / f"Example-{name}" for name in ("a", "b", "c"))

    different = compare_run_directories([run_a, run_c])
    assert different["compare_context"]["gate"] == "same_tenant_required"
    assert different["baseline_diff"]["status"] == "blocked"
    assert gate_drift(baseline_run_dir=str(run_a), current_run_dir=str(run_c), fail_on="high")["code"] == "tenant_guard"

    same = compare_run_directories([run_a, run_b])
    assert same["compare_context"]["gate"] == "same_tenant"
    assert same["compare_context"]["identity_basis"] == "domain_alias"
    assert same["baseline_diff"]["status"] == "ok"
    drift = gate_drift(baseline_run_dir=str(run_a), current_run_dir=str(run_b), fail_on="high")
    assert (drift["status"], drift["pass"]) == ("pass", True)


@pytest.fixture
def mixed_version_runs(tmp_path: Path, monkeypatch) -> tuple[Path, Path]:
    from dataclasses import replace

    from auditex.google_workspace import run as google_run

    out = tmp_path / "out"
    finalize = google_run.write_provider_bundle

    def finalize_legacy(*, plan, **kwargs):
        # Seal the legacy ID through the regular finaliser on every mirrored surface.
        metadata = {**plan.bundle_metadata, "customer_id": "C0privA123"}
        return finalize(plan=replace(plan, tenant_id="C0privA123", bundle_metadata=metadata), **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(google_run, "write_provider_bundle", finalize_legacy)
        assert _replay(out, "legacy", customer_id="C0privA123") == 0
    assert _replay(out, "new", customer_id="C0privA123") == 0
    legacy, new = (out / f"Example-{name}" for name in ("legacy", "new"))
    assert json.loads((legacy / "run-manifest.json").read_text(encoding="utf-8"))["tenant_id"] == "C0privA123"
    assert json.loads((legacy / "validation.json").read_text(encoding="utf-8"))["valid"] is True
    return legacy, new


def test_b3_legacy_bundle_compares_and_passes_drift_without_disclosing_id(mixed_version_runs, capsys) -> None:
    legacy, new = map(str, mixed_version_runs)

    assert auditex_cli.main(["compare", "--run-dir", legacy, "--run-dir", new, "--format", "json"]) == 0
    captured = capsys.readouterr()
    assert "C0privA123" not in captured.out + captured.err
    compare = json.loads(captured.out)
    assert compare["baseline_diff"]["status"] == "ok"
    assert compare["compare_context"]["identity_basis"] == "domain_alias"

    assert auditex_cli.main(["diff", legacy, new]) == 0
    captured = capsys.readouterr()
    assert "C0privA123" not in captured.out + captured.err
    assert json.loads(captured.out)["status"] == "ok"

    assert auditex_cli.main(["gate-drift", "--baseline", legacy, "--current", new, "--fail-on", "high"]) == 0
    captured = capsys.readouterr()
    assert "C0privA123" not in captured.out + captured.err
    drift = json.loads(captured.out)
    assert (drift["status"], drift["pass"]) == ("pass", True)


def test_m3_legacy_and_current_sarif_use_the_same_fingerprints(tmp_path: Path, mixed_version_runs, monkeypatch) -> None:
    from auditex.reporting import render_report

    monkeypatch.setenv("AUDITEX_EXPORT_FINGERPRINT_KEY", "synthetic-fingerprint-key")
    fingerprints = []
    for position, run in enumerate(mixed_version_runs):
        target = tmp_path / f"report-{position}.sarif"
        render_report(run_dir=str(run), format_name="sarif", profile="shareable", output_path=str(target))
        assert "C0privA123" not in target.read_text(encoding="utf-8")
        rows = json.loads(target.read_text(encoding="utf-8"))["runs"][0]["results"]
        fingerprints.append(sorted((row["ruleId"], json.dumps(row["partialFingerprints"], sort_keys=True)) for row in rows))
    assert len(fingerprints[0]) > 0
    assert fingerprints[0] == fingerprints[1]


def test_b5_nested_tenant_key_override_creates_no_file(tmp_path: Path, monkeypatch) -> None:
    out = tmp_path / "out"
    run = out / "Example-nested"
    key = run / "reports" / "operator-tenant.key"
    monkeypatch.setenv("AUDITEX_TENANT_KEY_PATH", str(key))

    assert _replay(out, "nested", customer_id="C0privA123") == 0
    assert json.loads((run / "validation.json").read_text(encoding="utf-8"))["valid"] is True
    assert not key.exists()
    assert "operator-tenant.key" not in (run / "bundle-hashes.json").read_text(encoding="utf-8")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires a POSIX FIFO")
def test_m1_fifo_tenant_key_override_does_not_block_startup(tmp_path: Path, monkeypatch) -> None:
    key = tmp_path / "key.fifo"
    os.mkfifo(key, mode=0o600)
    monkeypatch.setenv("AUDITEX_TENANT_KEY_PATH", str(key))
    argv = [
        sys.executable, "-m", "auditex", "google", "run", "--offline", "--sample", str(SAMPLE),
        "--out", str(tmp_path / "out"), "--tenant-name", "Example", "--run-name", "fifo", "--customer-id", CUSTOMER_ID,
    ]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr
    assert CUSTOMER_ID not in result.stdout + result.stderr


def test_m2_tenant_key_visible_before_its_first_write_is_ignored(tmp_path: Path, monkeypatch) -> None:
    # This is the filesystem state seen by the second process while the first still holds the newly created key open.
    key = tmp_path / "tenant.key"
    monkeypatch.setenv("AUDITEX_TENANT_KEY_PATH", str(key))
    with key.open("xb"):
        key.chmod(0o600)
        assert _replay(tmp_path / "out", "concurrent", customer_id="C0privA123") == 0
    assert key.read_bytes() == b""


_OU_DIRECTORY = [
    {"orgUnitId": "id:finance-ou", "name": "Finance", "orgUnitPath": "/customers/Finance",
     "parentOrgUnitPath": "/customers", "parentOrgUnitId": "id:customers-ou"},
    {"orgUnitId": "id:hr-ou", "name": "HR", "orgUnitPath": "/customers/HR",
     "parentOrgUnitPath": "/customers", "parentOrgUnitId": "id:customers-ou"},
    {"orgUnitId": "id:customers-ou", "name": "customers", "orgUnitPath": "/customers",
     "parentOrgUnitPath": "/", "parentOrgUnitId": "id:root-ou"},
]


def _caa_event(org_unit: str) -> dict:
    return {
        "id": {"time": "2026-11-20T10:00:00Z", "customerId": "C0learn987"},
        "events": [{"name": "TOGGLE_CAA_ENABLEMENT", "parameters": [
            {"name": "ORG_UNIT_NAME", "value": org_unit}, {"name": "NEW_VALUE", "value": "DISABLED"},
        ]}],
    }


def _event_run(tmp_path: Path, org_unit: str) -> tuple[Path, list[dict]]:
    sample = json.loads(SAMPLE.read_text(encoding="utf-8"))
    sample["google_directory"]["orgUnits"]["value"].extend(_OU_DIRECTORY)
    sample["google_setting_events"] = {"settingEvents": {"value": [_caa_event(org_unit)]}}
    path = _write_sample(tmp_path / "sample.json", sample)
    rc = _replay(tmp_path / "out", "events", customer_id="my_customer", sample=path)
    run_dir = tmp_path / "out" / "Example-events"
    events = json.loads((run_dir / "normalized" / "google_setting_events.json").read_text(encoding="utf-8"))
    return run_dir, [rc, *events["records"]]


def test_organisational_unit_paths_under_customers_are_kept(tmp_path: Path) -> None:
    run_dir, (rc, *records) = _event_run(tmp_path, "/customers/Finance")

    assert rc == 0
    raw = json.loads((run_dir / "raw" / "google_directory.json").read_text(encoding="utf-8"))
    paths = {unit["orgUnitPath"] for unit in raw["orgUnits"]["value"]}
    assert {"/customers/Finance", "/customers/HR"} <= paths
    event = next(row for row in records if row.get("event") == "TOGGLE_CAA_ENABLEMENT")
    assert event["org_unit"] == "finance-ou"
    assert records[-1]["complete"] is True
    assert _files_holding(run_dir, "C0learn987") == []


def test_setting_evidence_that_held_a_customer_id_is_not_complete(tmp_path: Path) -> None:
    run_dir, (rc, *records) = _event_run(tmp_path, "/customers/C0learn987")

    assert rc == 1
    event = next(row for row in records if row.get("event") == "TOGGLE_CAA_ENABLEMENT")
    assert event.get("org_unit") is None
    assert records[-1]["complete"] is False
    assert _files_holding(run_dir, "C0learn987") == []


def test_b4_unrelated_id_shaped_org_unit_paths_stay_distinct(tmp_path: Path) -> None:
    sample = json.loads(SAMPLE.read_text(encoding="utf-8"))
    units = sample["google_directory"]["orgUnits"]["value"]
    units.extend([
        {"orgUnitId": "id:finance-ou", "orgUnitPath": "/Teams/C0finance1", "name": "C0finance1",
         "parentOrgUnitId": "id:teams-ou", "parentOrgUnitPath": "/Teams"},
        {"orgUnitId": "id:hr-ou", "orgUnitPath": "/Teams/C0humanres", "name": "C0humanres",
         "parentOrgUnitId": "id:teams-ou", "parentOrgUnitPath": "/Teams"},
        {"orgUnitId": "id:teams-ou", "orgUnitPath": "/Teams", "name": "Teams",
         "parentOrgUnitId": "id:root-ou", "parentOrgUnitPath": "/"},
    ])
    sample["google_setting_events"] = {"settingEvents": {"value": [_caa_event("/Teams/C0finance1")]}}
    path = _write_sample(tmp_path / "sample.json", sample)
    assert _replay(tmp_path / "out", "events", customer_id="my_customer", sample=path) == 0

    run = tmp_path / "out" / "Example-events"
    raw = json.loads((run / "raw" / "google_directory.json").read_text(encoding="utf-8"))
    assert {"/Teams/C0finance1", "/Teams/C0humanres"} <= {row["orgUnitPath"] for row in raw["orgUnits"]["value"]}
    events = json.loads((run / "normalized" / "google_setting_events.json").read_text(encoding="utf-8"))["records"]
    event = next(row for row in events if row.get("event") == "TOGGLE_CAA_ENABLEMENT")
    assert event["org_unit"] == "finance-ou"
    assert events[-1]["complete"] is True
    assert _files_holding(run, "C0learn987") == []
