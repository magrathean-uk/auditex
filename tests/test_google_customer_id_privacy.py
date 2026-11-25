"""PRIV-CUSTOMER-ID: the Google Workspace customer id never reaches a run bundle file or a shareable export.

The operator's ``--customer-id`` is used for the API calls only; the bundle records the ``my_customer`` alias as it is
and any other configured value as ``null``. A customer id the API returns or an error quotes is replaced by a marker.
"""

from __future__ import annotations

import json
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


def test_offline_google_run_and_its_shareable_exports_hold_no_customer_id(tmp_path: Path) -> None:
    from auditex.cli import write_customer_pack
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
    write_customer_pack(str(run_dir), str(tmp_path / "pack"))

    assert len(list(exports.iterdir())) == 12
    assert any((tmp_path / "pack").rglob("*.json"))
    assert _files_holding(exports, CUSTOMER_ID) == []
    assert _files_holding(tmp_path / "pack", CUSTOMER_ID) == []
    assert _files_holding(run_dir, CUSTOMER_ID) == []


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

    assert rc in {0, 1}
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
        ("orgunits?customerId=my_customer&type=all", "orgunits?customerId=<customer-id>&type=all"),
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
