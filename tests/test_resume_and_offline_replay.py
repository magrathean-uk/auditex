"""A resumed run and an offline replay carry the gaps they were given instead of reading complete over them."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit import cli
from azure_tenant_audit.collectors.base import CollectorResult

REPO_ROOT = Path(__file__).resolve().parents[1]
ADMIN_SET_SAMPLE = REPO_ROOT / "examples" / "sample_audit_bundle" / "admin_set_result.json"


class _FakeClient:
    def __init__(self, auth: Any, audit_event: Any = None) -> None:
        self.audit_event = audit_event

    def get_json(self, path: str, **_: Any) -> dict[str, Any]:
        return {}

    def get_all(self, path: str, params: Any = None) -> list[Any]:  # noqa: ARG002
        return []


class _Collector:
    """A collector with a scripted status: ``statuses`` is consumed one run at a time, the last one repeats."""

    def __init__(self, name: str, *statuses: str) -> None:
        self.name = name
        self.statuses = list(statuses) or ["ok"]
        self.run_calls = 0

    def run(self, context: dict[str, Any]) -> CollectorResult:  # noqa: ARG002
        status = self.statuses[min(self.run_calls, len(self.statuses) - 1)]
        self.run_calls += 1
        coverage = [
            {
                "collector": self.name,
                "type": "graph",
                "name": "rows",
                "endpoint": f"/{self.name}",
                "status": "ok" if status == "ok" else "failed",
                "item_count": 1,
                "error_class": None if status == "ok" else "service_unavailable",
                "error": None if status == "ok" else "503 Service Unavailable",
            }
        ]
        return CollectorResult(
            name=self.name,
            status=status,
            item_count=1,
            message="ok" if status == "ok" else "partial",
            error=None if status == "ok" else "503 Service Unavailable",
            payload={"rows": {"value": [{"id": f"{self.name}-1"}]}},
            coverage=coverage,
        )


def _args(tmp_path: Path, collectors: str, *extra: str):
    return cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--use-azure-cli-token",
            "--collectors",
            collectors,
            "--out",
            str(tmp_path),
            "--run-name",
            "resume",
            *extra,
        ]
    )


def _live(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, registry: dict[str, _Collector], collectors: str, *extra: str) -> int:
    monkeypatch.setattr(cli, "GraphClient", _FakeClient)
    monkeypatch.setattr(cli, "REGISTRY", registry)
    monkeypatch.setattr(cli, "_acquire_azure_cli_access_token", lambda *_, **__: "cached-token")
    return cli.run_live(_args(tmp_path, collectors, *extra))


def _ledger(run_dir: Path) -> dict[str, dict[str, Any]]:
    payload = json.loads((run_dir / "normalized" / "coverage_ledger.json").read_text(encoding="utf-8"))
    return {row["collector"]: row for row in payload["records"]}


def _manifest(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))


def test_a_resumed_run_keeps_an_earlier_partial_collector_partial(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    identity = _Collector("identity", "partial")
    licensing = _Collector("licensing")
    registry = {"identity": identity, "licensing": licensing}
    assert _live(monkeypatch, tmp_path, registry, "identity") == 1
    run_dir = tmp_path / "acme-resume"

    # The resumed run adds a collector. The 503 on identity persists, so the run must stay partial.
    rc = _live(monkeypatch, tmp_path, registry, "identity,licensing", "--resume-from", str(run_dir))

    assert rc == 1
    assert _manifest(run_dir)["overall_status"] == "partial"
    ledger = _ledger(run_dir)
    assert ledger["identity"]["coverage_status"] == "partial_success"
    assert ledger["identity"]["actual_status"] == "partial"
    assert ledger["licensing"]["coverage_status"].startswith("complete")


def test_the_gate_blocks_a_resumed_run_with_an_earlier_partial_collector(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from auditex.gate import gate_findings

    registry = {"identity": _Collector("identity", "partial"), "licensing": _Collector("licensing")}
    _live(monkeypatch, tmp_path, registry, "identity")
    run_dir = tmp_path / "acme-resume"
    _live(monkeypatch, tmp_path, registry, "identity,licensing", "--resume-from", str(run_dir))

    result = gate_findings(run_dir=str(run_dir), fail_on="critical")

    assert result["pass"] is False
    assert result["status"] == "blocked"
    assert result["code"] == "incomplete_coverage"
    assert {row["collector"] for row in result["coverage"]["incomplete_collectors"]} == {"identity"}


def test_a_partial_collector_is_re_run_on_resume_and_replaces_its_earlier_rows(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    identity = _Collector("identity", "partial", "ok")
    registry = {"identity": identity, "licensing": _Collector("licensing")}
    assert _live(monkeypatch, tmp_path, registry, "identity") == 1
    run_dir = tmp_path / "acme-resume"

    rc = _live(monkeypatch, tmp_path, registry, "identity,licensing", "--resume-from", str(run_dir))

    assert identity.run_calls == 2
    assert rc == 0
    assert _manifest(run_dir)["overall_status"] == "ok"
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert [row["status"] for row in summary["collectors"] if row["name"] == "identity"] == ["ok"]
    coverage = json.loads((run_dir / "coverage.json").read_text(encoding="utf-8"))
    assert [row["status"] for row in coverage if row["collector"] == "identity"] == ["ok"]


def test_a_finished_collector_is_carried_forward_as_complete_not_as_not_applicable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    identity = _Collector("identity")
    registry = {"identity": identity, "licensing": _Collector("licensing")}
    assert _live(monkeypatch, tmp_path, registry, "identity") == 0
    run_dir = tmp_path / "acme-resume"

    assert _live(monkeypatch, tmp_path, registry, "identity,licensing", "--resume-from", str(run_dir)) == 0

    assert identity.run_calls == 1, "an ok collector is not run again"
    ledger = _ledger(run_dir)
    assert ledger["identity"]["actual_status"] == "ok"
    assert ledger["identity"]["coverage_status"].startswith("complete")
    assert ledger["identity"]["coverage_status"] != "not_applicable"


def test_an_incomplete_collector_outside_the_resumed_session_keeps_the_run_partial(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    registry = {"identity": _Collector("identity", "partial"), "licensing": _Collector("licensing")}
    assert _live(monkeypatch, tmp_path, registry, "identity,licensing") == 1
    run_dir = tmp_path / "acme-resume"

    # Resuming with licensing alone must not read ok while identity's gap is in the same bundle.
    rc = _live(monkeypatch, tmp_path, registry, "licensing", "--resume-from", str(run_dir))

    assert rc == 1
    assert _manifest(run_dir)["overall_status"] == "partial"


def test_an_ok_collector_whose_raw_payload_is_gone_is_re_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    identity = _Collector("identity")
    registry = {"identity": identity}
    assert _live(monkeypatch, tmp_path, registry, "identity") == 0
    run_dir = tmp_path / "acme-resume"
    (run_dir / "raw" / "identity.json").unlink()

    assert _live(monkeypatch, tmp_path, registry, "identity", "--resume-from", str(run_dir)) == 0

    assert identity.run_calls == 2


def test_a_collector_the_preflight_skipped_is_not_carried_as_finished(tmp_path: Path) -> None:
    from azure_tenant_audit.output import AuditWriter

    run_dir = tmp_path / "acme-resume"
    writer = AuditWriter(tmp_path, "acme", run_name="resume")
    (writer.raw_dir / "licensing.json").write_text("{}", encoding="utf-8")
    writer.write_checkpoint("licensing", {"status": "ok", "item_count": 0})
    writer.write_checkpoint(
        "teams",
        {"name": "teams", "status": "skipped", "message": cli._PREFLIGHT_SKIP_MESSAGE, "error_class": cli._PREFLIGHT_BLOCKED},
    )
    writer.write_checkpoint("identity_protection", {"status": "skipped", "message": "no licence"})
    reopened = AuditWriter(tmp_path, "acme", run_dir=run_dir)

    carried = cli._resume_carried_collectors(reopened, reopened.load_collector_checkpoint_state())

    assert set(carried) == {"licensing", "identity_protection"}


# ---- offline replay -------------------------------------------------------------------------------------


def _admin_set_sample(tmp_path: Path, *, truncate_users: bool = False, block_registration: bool = False) -> Path:
    sample = json.loads(ADMIN_SET_SAMPLE.read_text(encoding="utf-8"))
    if truncate_users:
        sample["identity"]["users"].update(
            {"collection_truncated": True, "truncation_reason": "operator_limit", "result_limit": 5}
        )
    if block_registration:
        sample["auth_methods"]["userRegistrationDetails"] = {
            "error": "Forbidden",
            "error_class": "insufficient_permissions",
        }
    path = tmp_path / "sample.json"
    path.write_text(json.dumps(sample), encoding="utf-8")
    return path


def _replay(tmp_path: Path, sample: Path, name: str) -> tuple[int, Path]:
    rc = cli.run_offline(sample, tmp_path / "out", "contoso", name)
    return rc, tmp_path / "out" / f"contoso-{name}"


def _rule_statuses(run_dir: Path) -> dict[str, set[str]]:
    pack = json.loads((run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))
    statuses: dict[str, set[str]] = {}
    for framework in pack["baseline_alignment"]["frameworks"].values():
        for control in framework.get("controls", []):
            for rule in control.get("rule_statuses", []):
                statuses.setdefault(rule["rule_id"], set()).add(rule["status"])
    return statuses


def test_a_clean_sample_still_replays_complete(tmp_path: Path) -> None:
    rc, run_dir = _replay(tmp_path, _admin_set_sample(tmp_path), "clean")

    assert rc == 0
    assert _manifest(run_dir)["overall_status"] == "ok"
    assert {row["coverage_status"] for row in _ledger(run_dir).values()} == {"complete_offline_sample"}
    assert not (run_dir / "coverage.json").exists()


def test_offline_replay_honours_error_and_truncation_markers(tmp_path: Path) -> None:
    sample = _admin_set_sample(tmp_path, truncate_users=True, block_registration=True)

    rc, run_dir = _replay(tmp_path, sample, "marked")

    assert rc == 1
    manifest = _manifest(run_dir)
    assert manifest["overall_status"] == "partial"
    ledger = _ledger(run_dir)
    assert ledger["identity"]["coverage_status"] == "partial_success"
    assert ledger["auth_methods"]["coverage_status"] == "blocked_permission"
    assert ledger["licensing"]["coverage_status"] == "complete_offline_sample"
    coverage = json.loads((run_dir / "coverage.json").read_text(encoding="utf-8"))
    by_name = {(row["collector"], row["name"]): row for row in coverage}
    assert by_name[("identity", "users")]["collection_truncated"] is True
    assert by_name[("identity", "users")]["truncation_reason"] == "operator_limit"
    assert by_name[("auth_methods", "userRegistrationDetails")]["status"] == "failed"
    assert manifest["coverage_gaps"], "the cut list and the blocked read reach the manifest gaps"
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    assert validation["valid"] is True, validation["issues"]


def test_blocked_mfa_evidence_in_a_replay_does_not_read_pass(tmp_path: Path) -> None:
    clean_rc, clean = _replay(tmp_path, _admin_set_sample(tmp_path), "clean-mfa")
    blocked_rc, blocked = _replay(tmp_path, _admin_set_sample(tmp_path, block_registration=True), "blocked-mfa")

    mfa_rules = {
        "identity.user_mfa_not_registered",
        "identity.global_admin_mfa_not_registered",
        "identity.privileged_mfa_not_registered",
    }
    assert clean_rc == 0 and blocked_rc == 1
    blocked_statuses = _rule_statuses(blocked)
    for rule in mfa_rules & set(blocked_statuses):
        assert "pass" not in blocked_statuses[rule], (rule, blocked_statuses[rule])
        assert "fail" not in blocked_statuses[rule]
    assert mfa_rules & set(blocked_statuses)


def test_the_gate_blocks_a_replay_with_a_cut_list(tmp_path: Path) -> None:
    from auditex.gate import gate_findings

    _, run_dir = _replay(tmp_path, _admin_set_sample(tmp_path, truncate_users=True), "gate")

    result = gate_findings(run_dir=str(run_dir), fail_on="critical")

    assert result["status"] == "blocked"
    assert result["code"] == "incomplete_coverage"


def test_google_offline_replay_honours_markers(tmp_path: Path) -> None:
    from auditex.google_workspace.run import run_google_offline

    sample = json.loads((REPO_ROOT / "examples" / "google_workspace_sample.json").read_text(encoding="utf-8"))
    sample["google_policies"]["twoStepVerificationPolicies"] = {
        "error": "Forbidden",
        "error_class": "insufficient_permissions",
    }
    sample_path = tmp_path / "google.json"
    sample_path.write_text(json.dumps(sample), encoding="utf-8")

    rc = run_google_offline(
        sample_path=sample_path, out=tmp_path / "out", tenant_name="acme", run_name="g", domain="example.com", customer_id=None
    )

    run_dir = tmp_path / "out" / "acme-g"
    assert rc == 1
    assert _manifest(run_dir)["overall_status"] == "partial"
    assert _ledger(run_dir)["google_policies"]["coverage_status"] != "complete_offline_sample"
