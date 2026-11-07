"""Exit status and operator notice for incomplete default workload collectors."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditex.gate import gate_findings
from azure_tenant_audit import cli
from azure_tenant_audit.collectors.base import CollectorResult


CANARY = "private-tenant.example: alice@private-tenant.example; sensitive failure detail"
OPERATIONS = {"identity": "users", "exchange_policy": "transportConfig", "dns_posture": "spf_records"}
ERROR_CLASSES = {"identity": "unauthenticated", "exchange_policy": "session_not_connected", "dns_posture": "dns_resolver_error"}


def _notice(*names: str) -> str:
    return f"Partial: {', '.join(sorted(names))} did not finish; run status partial, exit 0; see diagnostics"


def _assert_notice(run_dir: Path, stderr: str, names: tuple[str, ...]) -> None:
    summary = json.loads((run_dir / "summary.json").read_text())
    markdown = (run_dir / "summary.md").read_text()
    if not names:
        assert stderr == ""
        assert "partial_workload_notice" not in summary
        assert "Partial: " not in markdown
        return
    notice = _notice(*names)
    assert stderr.splitlines() == [notice]
    assert summary["partial_workload_notice"] == notice
    assert markdown.splitlines().count(f"- {notice}") == 1
    assert CANARY not in notice and "private-tenant.example" not in notice and "sensitive failure" not in notice


@pytest.mark.parametrize(
    "failures, expected_rc, notice_names",
    [
        ((), 0, ()),
        (("dns_posture",), 0, ("dns_posture",)),
        (("exchange_policy",), 0, ("exchange_policy",)),
        (("exchange_policy", "dns_posture"), 0, ("exchange_policy", "dns_posture")),
        (("identity",), 1, ()),
        (("identity", "dns_posture"), 1, ()),
    ],
    ids=["healthy", "dns", "exchange", "both-workloads", "required", "required-and-workload"],
)
def test_offline_exit_and_partial_workload_notice(tmp_path: Path, capsys, failures, expected_rc, notice_names) -> None:
    payload = {
        name: {operation: {"value": [], **(
            {"error_class": ERROR_CLASSES[name], "error": CANARY} if name in failures else {}
        )}}
        for name, operation in OPERATIONS.items()
    }
    if "dns_posture" in failures:
        # More than one failed read of the same collector still produces one name and one line.
        payload["dns_posture"]["dmarc_records"] = {"error_class": "dns_resolver_error", "error": CANARY}
    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps(payload))

    assert cli.run_offline(sample, tmp_path, "fixture", "offline") == expected_rc

    run_dir = tmp_path / "fixture-offline"
    assert json.loads((run_dir / "run-manifest.json").read_text())["overall_status"] == ("partial" if failures else "ok")
    if failures:
        assert gate_findings(run_dir=str(run_dir), fail_on="critical")["status"] == "blocked"
    _assert_notice(run_dir, capsys.readouterr().err, notice_names)


@pytest.mark.parametrize(
    "failures, expected_rc, notice_names",
    [
        ((), 0, ()),
        (("dns_posture",), 0, ("dns_posture",)),
        (("exchange_policy",), 0, ("exchange_policy",)),
        (("exchange_policy", "dns_posture"), 0, ("exchange_policy", "dns_posture")),
        (("identity",), 1, ()),
        (("identity", "dns_posture"), 1, ()),
    ],
    ids=["healthy", "dns", "exchange", "both-workloads", "required", "required-and-workload"],
)
def test_live_exit_and_partial_workload_notice(tmp_path: Path, monkeypatch, capsys, failures, expected_rc, notice_names) -> None:
    class Collector:
        def __init__(self, name: str) -> None:
            self.name = name

        def run(self, context):
            failed = self.name in failures
            row = {
                "collector": self.name, "name": OPERATIONS[self.name], "type": "graph",
                "status": "failed" if failed else "ok", "item_count": 0,
                "error_class": ERROR_CLASSES[self.name] if failed else None,
                "error": CANARY if failed else None,
            }
            return CollectorResult(name=self.name, status="partial" if failed else "ok", item_count=0,
                                   message="partial" if failed else "ok", payload={}, coverage=[row])

    monkeypatch.setattr(cli, "GraphClient", lambda *args, **kwargs: object())
    monkeypatch.setattr(cli, "REGISTRY", {name: Collector(name) for name in OPERATIONS})
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    args = cli.build_parser().parse_args([
        "--tenant-name", "fixture", "--tenant-id", "constructed", "--access-token", "constructed",
        "--collectors", ",".join(OPERATIONS), "--out", str(tmp_path), "--run-name", "live",
    ])

    assert cli.run_live(args) == expected_rc

    run_dir = tmp_path / "fixture-live"
    assert json.loads((run_dir / "run-manifest.json").read_text())["overall_status"] == ("partial" if failures else "ok")
    if failures:
        assert gate_findings(run_dir=str(run_dir), fail_on="critical")["status"] == "blocked"
    _assert_notice(run_dir, capsys.readouterr().err, notice_names)


def test_resume_notice_names_an_unselected_incomplete_workload(tmp_path: Path, monkeypatch, capsys) -> None:
    class Healthy:
        name = "identity"

        def run(self, context):
            return CollectorResult(name=self.name, status="ok", item_count=0, message="ok", payload={})

    run_dir = tmp_path / "fixture-resume"
    checkpoint = run_dir / "checkpoints" / "checkpoint-state.json"
    checkpoint.parent.mkdir(parents=True)
    checkpoint.write_text(json.dumps({"run_id": "resume", "collectors": {
        "dns_posture": {"status": "partial", "message": CANARY, "item_count": 0},
    }}))
    monkeypatch.setattr(cli, "GraphClient", lambda *args, **kwargs: object())
    monkeypatch.setattr(cli, "REGISTRY", {"identity": Healthy()})
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    args = cli.build_parser().parse_args([
        "--tenant-name", "fixture", "--tenant-id", "constructed", "--access-token", "constructed",
        "--collectors", "identity", "--out", str(tmp_path), "--resume-from", str(run_dir),
    ])

    assert cli.run_live(args) == 0
    assert json.loads((run_dir / "run-manifest.json").read_text())["overall_status"] == "partial"
    assert gate_findings(run_dir=str(run_dir), fail_on="critical")["status"] == "blocked"
    _assert_notice(run_dir, capsys.readouterr().err, ("dns_posture",))


def test_live_notice_includes_incomplete_normalized_workload_evidence(tmp_path: Path, monkeypatch, capsys) -> None:
    class Healthy:
        name = "dns_posture"

        def run(self, context):
            return CollectorResult(name=self.name, status="ok", item_count=0, message="ok", payload={})

    monkeypatch.setattr(cli, "GraphClient", lambda *args, **kwargs: object())
    monkeypatch.setattr(cli, "REGISTRY", {"dns_posture": Healthy()})
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    monkeypatch.setattr(cli, "build_normalization_diagnostics", lambda _: [{
        "collector": "dns_posture", "status": "partial", "error_class": "incomplete_evidence", "error": CANARY,
    }])
    args = cli.build_parser().parse_args([
        "--tenant-name", "fixture", "--tenant-id", "constructed", "--access-token", "constructed",
        "--collectors", "dns_posture", "--out", str(tmp_path), "--run-name", "normalized",
    ])

    assert cli.run_live(args) == 0
    run_dir = tmp_path / "fixture-normalized"
    assert json.loads((run_dir / "run-manifest.json").read_text())["overall_status"] == "partial"
    assert gate_findings(run_dir=str(run_dir), fail_on="critical")["status"] == "blocked"
    _assert_notice(run_dir, capsys.readouterr().err, ("dns_posture",))


def test_resume_after_workload_recovers_drops_the_old_notice(tmp_path: Path, monkeypatch, capsys) -> None:
    class Recovers:
        name = "exchange_policy"
        calls = 0

        def run(self, context):
            self.calls += 1
            failed = self.calls == 1
            return CollectorResult(name=self.name, status="partial" if failed else "ok", item_count=0,
                                   message="partial" if failed else "ok", payload={})

    monkeypatch.setattr(cli, "GraphClient", lambda *args, **kwargs: object())
    monkeypatch.setattr(cli, "REGISTRY", {"exchange_policy": Recovers()})
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    argv = ["--tenant-name", "fixture", "--tenant-id", "constructed", "--access-token", "constructed",
            "--collectors", "exchange_policy", "--out", str(tmp_path), "--run-name", "recovery"]
    run_dir = tmp_path / "fixture-recovery"

    assert cli.run_live(cli.build_parser().parse_args(argv)) == 0
    _assert_notice(run_dir, capsys.readouterr().err, ("exchange_policy",))
    assert cli.run_live(cli.build_parser().parse_args([*argv, "--resume-from", str(run_dir)])) == 0
    assert json.loads((run_dir / "run-manifest.json").read_text())["overall_status"] == "ok"
    _assert_notice(run_dir, capsys.readouterr().err, ())
