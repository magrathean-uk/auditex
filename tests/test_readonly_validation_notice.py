"""An explicit read-only validation never spends a producer's log notice."""
from pathlib import Path

import pytest
from test_assessment_review import _auditex_bundle

from azure_tenant_audit import contracts, evidence_db


def _bytes(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize("read_only", [True, False])
def test_explicit_read_only_validation_never_appends_to_an_owned_bundle(tmp_path, monkeypatch, read_only):
    run = _auditex_bundle(tmp_path / "bundle")
    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda _p: False)
    before = _bytes(run)
    report = contracts.build_validation_report(run_dir=run, read_only=read_only)
    assert report["valid"] is True
    after = _bytes(run)
    if read_only:
        assert after == before
    else:
        expected = dict(before)
        expected["audit-debug.log"] += evidence_db._IN_PLACE_NOTICE + b"\n"
        assert after == expected


def test_read_only_validation_does_not_consume_the_later_producer_notice(tmp_path, monkeypatch):
    run = _auditex_bundle(tmp_path / "bundle")
    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda _p: False)
    before = _bytes(run)
    assert contracts.build_validation_report(run_dir=run, read_only=True)["valid"]
    assert _bytes(run) == before
    assert evidence_db.load_run_index_summary(run)["tenant_id"]
    once = _bytes(run)
    expected = dict(before)
    expected["audit-debug.log"] += evidence_db._IN_PLACE_NOTICE + b"\n"
    assert once == expected
    evidence_db.load_run_index_summary(run)
    assert _bytes(run) == once
