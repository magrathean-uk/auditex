"""Shareable exporters retain their published formats after D3 redaction."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from gate_support import offline_run
from test_sarif_oscal_exports import _schema_errors, oscal_validator, sarif_validator  # noqa: F401


@pytest.mark.parametrize("format_name", ["oscal", "sarif"])
def test_shareable_export_redacts_guid_and_validates_schema(
    tmp_path: Path, request: pytest.FixtureRequest, format_name: str,
) -> None:
    from auditex.exporters import run_exporter

    guid = "00000000-0000-4000-8000-123456789abc"
    run = offline_run(tmp_path, format_name)
    path = run / "reports" / "report-pack.json"
    report = json.loads(path.read_text())
    report["findings"] = [{"id": "finding-1", "rule_id": "rule-1", "severity": "high", "title": f"Fix {guid}"}]
    path.write_text(json.dumps(report))
    output = tmp_path / f"{format_name}.json"
    run_exporter(name=format_name, run_dir=str(run), output_path=str(output))
    text = output.read_text()
    assert guid not in text
    validator = request.getfixturevalue(f"{format_name}_validator")
    assert _schema_errors(validator, json.loads(text)) == []
