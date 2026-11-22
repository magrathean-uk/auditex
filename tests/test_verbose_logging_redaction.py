"""R157: --verbose must not let urllib3 log request lines, whose query can be a pre-authenticated credential."""
from __future__ import annotations

import logging
from pathlib import Path

from gate_support import SAMPLE


def test_verbose_run_does_not_log_signed_request_query(tmp_path: Path, caplog, monkeypatch) -> None:
    from azure_tenant_audit.cli import main

    monkeypatch.setattr(logging.getLogger("urllib3"), "level", logging.NOTSET)
    caplog.set_level(logging.DEBUG)
    argv = [
        "--offline", "--sample", str(SAMPLE), "--out", str(tmp_path / "out"),
        "--tenant-name", "contoso", "--run-name", "r157", "--verbose",
    ]
    assert main(argv) in (0, 1)
    # What urllib3.connectionpool logs at DEBUG for the report download hop.
    logging.getLogger("urllib3.connectionpool").debug(
        '%s://%s:%s "%s %s %s" %s %s', "https", "reports.office.com", 443, "GET",
        "/data/download/abc?sig=SECRETPREAUTH&se=2026", "HTTP/1.1", 200, 2,
    )
    assert "SECRETPREAUTH" not in caplog.text
