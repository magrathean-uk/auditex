"""Customer pack delivery preserves verification without copying private values."""
from __future__ import annotations

import json
import os
import signal
from pathlib import Path

import pytest
from gate_support import offline_run, rehash

OWNER = "D3 PRIVATE OWNER 726"
NOTES = "D3 PRIVATE NOTES 726"
GUID = "b0b0b0b0-1234-4567-8abc-0123456789ab"


@pytest.fixture
def planted_run(tmp_path: Path) -> Path:
    run = offline_run(tmp_path, "d3")
    path = run / "reports" / "report-pack.json"
    report = json.loads(path.read_text())
    report["executive_summary"] = {"owner": OWNER, "notes": NOTES, "tenant_id": GUID}
    report["action_plan"] = [{"id": "finding-1", "title": "Fix sharing", "owner": OWNER, "target": GUID}]
    path.write_text(json.dumps(report))
    rehash(run)
    return run


def test_customer_pack_redacts_all_files_and_verifies(planted_run: Path, tmp_path: Path) -> None:
    from auditex.reporting import (
        verify_enterprise_handoff_pack,
        write_enterprise_handoff_pack,
    )

    target = tmp_path / "pack"
    result = write_enterprise_handoff_pack(planted_run, target)
    texts = {p.relative_to(target): p.read_text() for p in target.rglob("*") if p.is_file()}
    assert texts and "<redacted-text>" in texts[Path("report.md")]
    for path, text in texts.items():
        assert all(value not in text for value in (OWNER, NOTES, GUID)), path
    rows = [row for row in result["source_artifacts"] if row.get("source_path") == "reports/report-pack.json"]
    assert len(rows) == 1 and rows[0]["transformed"] == "customer_pack_redaction"
    assert rows[0]["source_sha256"] != rows[0]["sha256"]
    assert verify_enterprise_handoff_pack(target)["valid"]
    assert OWNER in (planted_run / "reports" / "report-pack.json").read_text()


def test_customer_pack_refuses_unreadable_normalised_input_before_output(planted_run: Path, tmp_path: Path) -> None:
    from auditex.reporting import write_enterprise_handoff_pack
    from azure_tenant_audit.output_redaction import ContextIncompleteError

    # An added invalid evidence file is detected by the bundle gate or discovery;
    # either must refuse the pack rather than publish it.
    (planted_run / "normalized" / "bad.json").write_text("not JSON")
    rehash(planted_run)
    target = tmp_path / "refused-pack"
    with pytest.raises((ContextIncompleteError, ValueError)):
        write_enterprise_handoff_pack(planted_run, target)
    assert not target.exists()


def test_customer_pack_return_redacts_guid_in_run_and_output_names(tmp_path: Path) -> None:
    from auditex.reporting import write_enterprise_handoff_pack

    run = offline_run(tmp_path, GUID)
    target = tmp_path / f"pack-{GUID}"
    result = write_enterprise_handoff_pack(run, target)
    assert target.exists()
    assert GUID not in json.dumps(result)


@pytest.mark.parametrize("route", ["pack", "mcp", "cli"])
def test_handoff_routes_refuse_normalised_fifo_before_validation(planted_run: Path, tmp_path: Path, route: str) -> None:
    from auditex import cli, mcp_server
    from auditex.reporting import write_enterprise_handoff_pack
    from azure_tenant_audit.output_redaction import ContextIncompleteError

    os.mkfifo(planted_run / "normalized" / "fifo.json")

    def timeout(_signum, _frame):
        raise RuntimeError("handoff blocked on normalised FIFO")

    previous = signal.signal(signal.SIGALRM, timeout)
    signal.alarm(2)
    try:
        with pytest.raises(ContextIncompleteError, match="incomplete"):
            if route == "pack":
                write_enterprise_handoff_pack(planted_run, tmp_path / "refused")
            elif route == "mcp":
                mcp_server.enterprise_handoff(str(planted_run))
            else:
                cli.main(["report", "handoff", str(planted_run)])
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
