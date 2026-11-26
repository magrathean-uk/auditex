"""PRIV-CUSTOMER-ID: the Google Workspace customer id never reaches a run bundle file or a shareable export.

The operator's ``--customer-id`` is used for the API calls only; the bundle records the ``my_customer`` alias as it is
and any other configured value as ``null``. A customer id the API returns or an error quotes is replaced by a marker.
"""

from __future__ import annotations

import json
import re
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
    # The tenant id is the keyed pseudonym of the configured id (repair round 1, B4).
    assert re.fullmatch(r"gws-[0-9a-f]{8}-[0-9a-f]{16}", manifest["tenant_id"])
    assert manifest["tenant_id_requested"] == manifest["tenant_id"]
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
        ("<HttpError 404 ... returned \"Customer C0learn987 was not found\">",
         "<HttpError 404 ... returned \"Customer <customer-id> was not found\">"),
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


def _write_sample(path: Path, sample: dict) -> Path:
    path.write_text(json.dumps(sample), encoding="utf-8")
    return path


def _replay(out: Path, run_name: str, *, customer_id: str, domain: str = "example.com", sample: Path = SAMPLE) -> int:
    return auditex_cli.main(
        [
            "google", "run", "--offline", "--sample", str(sample), "--domain", domain, "--customer-id", customer_id,
            "--tenant-name", "Example", "--run-name", run_name, "--out", str(out),
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
    users[1 % len(users)]["customerId"] = {"value": "C0malformed7"}
    sample["google_alert_center"]["alerts"] = {
        "value": [], "error_class": "not_found",
        "error": '<HttpError 404 when requesting https://alertcenter.googleapis.com/v1beta1/alerts?customerId='
                 'my_customer&alt=json returned "Customer C0learn987 was not found">',
    }
    path = _write_sample(tmp_path / "sample.json", sample)

    assert _replay(tmp_path / "out", "learned", customer_id="my_customer", sample=path) == 1

    run_dir = tmp_path / "out" / "Example-learned"
    exports = _shareable_exports(run_dir, tmp_path / "exports")
    for needle in ("C0learn987", "C0malformed7"):
        assert _files_holding(run_dir, needle) == []
        assert _files_holding(exports, needle) == []
    raw = json.loads((run_dir / "raw" / "google_directory.json").read_text(encoding="utf-8"))
    assert raw["users"]["value"][1 % len(users)]["customerId"] == "<customer-id>"
    blockers = (run_dir / "blockers" / "blockers.json").read_text(encoding="utf-8")
    assert "Customer <customer-id> was not found" in blockers


def test_b1_live_classifier_withholds_a_customer_id_in_the_api_reason() -> None:
    from auditex.google_workspace.client import classify_google_error

    class _HttpError(Exception):
        def __init__(self) -> None:
            super().__init__('<HttpError 404 when requesting https://admin.googleapis.com/admin/directory/v1/users'
                             '?customer=my_customer&alt=json returned "Customer C0learn987 was not found">')
            self.resp = type("Resp", (), {"status": 404})()

    error_class, message = classify_google_error(_HttpError())
    assert "C0learn987" not in message
    assert "Customer <customer-id> was not found" in message
    assert error_class


def test_b2_sample_file_named_after_the_customer_id_leaves_no_trace(tmp_path: Path) -> None:
    import hashlib

    data = SAMPLE.read_bytes()
    path = tmp_path / "C0privA123.json"
    path.write_bytes(data)

    assert _replay(tmp_path / "out", "label", customer_id="C0privA123", sample=path.resolve()) == 0

    run_dir = tmp_path / "out" / "Example-label"
    assert _files_holding(run_dir, "C0privA123") == []
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["replay_source"] == {"file": "<customer-id>.json", "sha256": hashlib.sha256(data).hexdigest()}


def _probe_argv(out: Path) -> list[str]:
    return [
        "google", "probe", "--customer-id", "C0privA123", "--collectors", "google_directory", "--domain",
        "example.com", "--subject", "admin@example.com", "--tenant-name", "Example", "--run-name", "probe",
        "--out", str(out),
    ]


def test_b3_probe_failure_json_and_doctor_json_carry_no_customer_id(tmp_path: Path, monkeypatch, capsys) -> None:
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

    assert auditex_cli.main(["google", "doctor", "--json", "--customer-id", "C0privA123", "--domain", "example.com"]) in {0, 2}
    printed = capsys.readouterr()
    assert "C0privA123" not in printed.out + printed.err
    assert json.loads(printed.out)["target"] == {"domain": "example.com", "customer_id": None}


def test_b3_probe_without_dependencies_prints_no_customer_id(tmp_path: Path, monkeypatch, capsys) -> None:
    from auditex.google_workspace import run as google_run

    monkeypatch.setattr(
        google_run, "google_dependency_status", lambda: {"available": False, "missing": ["x"], "install_hint": "pip"},
    )
    assert auditex_cli.main(_probe_argv(tmp_path / "out")) == 2
    printed = capsys.readouterr()
    assert "C0privA123" not in printed.out + printed.err
    assert _files_holding(tmp_path / "out", "C0privA123") == []


def test_b4_compare_and_drift_tell_configured_customers_apart(tmp_path: Path) -> None:
    from auditex.compare import compare_run_directories
    from auditex.gate import gate_drift

    out = tmp_path / "out"
    assert _replay(out, "a", customer_id="C0privA123") == 0
    assert _replay(out, "b", customer_id="C0privB456") == 0
    assert _replay(out, "c", customer_id="C0privA123", domain="other.example") == 0
    run_a, run_b, run_c = (out / f"Example-{name}" for name in ("a", "b", "c"))
    for run_dir in (run_a, run_b, run_c):
        assert _files_holding(run_dir, "C0privA123") == []
        assert _files_holding(run_dir, "C0privB456") == []

    different = compare_run_directories([run_a, run_b])
    assert different["compare_context"]["gate"] == "same_tenant_required"
    assert different["baseline_diff"]["status"] == "blocked"
    assert gate_drift(baseline_run_dir=str(run_a), current_run_dir=str(run_b), fail_on="high")["code"] == "tenant_guard"

    same = compare_run_directories([run_a, run_c])
    assert same["compare_context"]["gate"] == "same_tenant"
    assert same["compare_context"]["identity_basis"] == "legacy_tenant_id"
    assert same["baseline_diff"]["status"] != "blocked"
    assert gate_drift(baseline_run_dir=str(run_a), current_run_dir=str(run_c), fail_on="high").get("code") != "tenant_guard"


def test_b4_a_legacy_bundle_with_the_raw_customer_id_still_compares_with_a_new_one(tmp_path: Path, monkeypatch) -> None:
    from auditex.compare import compare_run_directories
    from auditex.gate import gate_drift
    from auditex.google_workspace import run as google_run

    out = tmp_path / "out"
    with monkeypatch.context() as patch:
        # The base-format bundle recorded the configured id itself as the tenant id.
        patch.setattr(google_run, "tenant_pseudonym", lambda value, **_: value)
        assert _replay(out, "legacy", customer_id="C0privA123") == 0
    assert _replay(out, "new", customer_id="C0privA123") == 0
    assert _replay(out, "other", customer_id="C0privB456") == 0
    legacy, new, other = (out / f"Example-{name}" for name in ("legacy", "new", "other"))
    assert json.loads((legacy / "run-manifest.json").read_text(encoding="utf-8"))["tenant_id"] == "C0privA123"

    assert compare_run_directories([legacy, new])["compare_context"]["gate"] == "same_tenant"
    assert gate_drift(baseline_run_dir=str(legacy), current_run_dir=str(new), fail_on="high").get("code") != "tenant_guard"
    assert compare_run_directories([legacy, other])["compare_context"]["gate"] == "same_tenant_required"
    assert gate_drift(baseline_run_dir=str(legacy), current_run_dir=str(other), fail_on="high")["code"] == "tenant_guard"


def test_b4_pseudonyms_from_two_tenant_keys_never_match_or_fall_back_to_the_domain(tmp_path: Path, monkeypatch) -> None:
    from auditex.compare import compare_run_directories

    out = tmp_path / "out"
    monkeypatch.setenv("AUDITEX_TENANT_KEY_PATH", str(tmp_path / "key-one"))
    assert _replay(out, "one", customer_id="C0privA123") == 0
    monkeypatch.setenv("AUDITEX_TENANT_KEY_PATH", str(tmp_path / "key-two"))
    assert _replay(out, "two", customer_id="C0privA123") == 0

    result = compare_run_directories([out / "Example-one", out / "Example-two"])
    assert result["compare_context"]["gate"] == "tenant_key_mismatch"
    assert result["baseline_diff"]["status"] == "blocked"


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


def test_b5_organisational_unit_paths_under_customers_are_kept(tmp_path: Path) -> None:
    run_dir, (rc, *records) = _event_run(tmp_path, "/customers/Finance")

    assert rc == 0
    raw = json.loads((run_dir / "raw" / "google_directory.json").read_text(encoding="utf-8"))
    paths = {unit["orgUnitPath"] for unit in raw["orgUnits"]["value"]}
    assert {"/customers/Finance", "/customers/HR"} <= paths
    event = next(row for row in records if row.get("event") == "TOGGLE_CAA_ENABLEMENT")
    assert event["org_unit"] == "finance-ou"
    assert records[-1]["complete"] is True
    assert _files_holding(run_dir, "C0learn987") == []


def test_b5_setting_evidence_that_held_a_customer_id_is_not_complete(tmp_path: Path) -> None:
    run_dir, (rc, *records) = _event_run(tmp_path, "/customers/C0learn987")

    assert rc == 1
    event = next(row for row in records if row.get("event") == "TOGGLE_CAA_ENABLEMENT")
    assert event.get("org_unit") is None
    assert records[-1]["complete"] is False
    assert _files_holding(run_dir, "C0learn987") == []
