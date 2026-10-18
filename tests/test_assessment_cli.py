from __future__ import annotations

import json
from pathlib import Path

from auditex.cli import main


TENANT = "11111111-1111-4111-8111-111111111111"


def _maester(path: Path) -> Path:
    path.write_text(json.dumps({
        "TenantId": TENANT,
        "CurrentVersion": "2.3.0",
        "ExecutedAt": "2026-10-18T10:00:00Z",
        "Tests": [{"Id": "MT.1001", "Title": "Synthetic control", "Result": "Failed", "Severity": "High", "Tag": []}],
    }), encoding="utf-8")
    return path


def test_import_command_preserves_input_and_writes_new_output(tmp_path, capsys):
    source = _maester(tmp_path / "source.json")
    original = source.read_bytes()
    output = tmp_path / "review" / "normalized.json"
    assert main(["assessment", "import", "--source", "maester", "--input", str(source), "--output", str(output)]) == 0
    assert source.read_bytes() == original
    normalized = json.loads(output.read_text())
    assert normalized["tenant_id"] == TENANT
    assert normalized["checks"][0]["status"] == "fail"
    assert normalized["provenance"]["input_sha256"]
    assert json.loads(capsys.readouterr().out)["output"] == str(output)
    # A second import must leave the existing review artifact untouched.
    saved = output.read_bytes()
    assert main(["assessment", "import", "--source", "maester", "--input", str(source), "--output", str(output)]) == 2
    assert output.read_bytes() == saved


def test_import_cannot_write_into_finalized_run(tmp_path, capsys):
    source = _maester(tmp_path / "source.json")
    run = tmp_path / "run"
    run.mkdir()
    (run / "run-manifest.json").write_text("{}")
    output = run / "reports" / "external.json"
    assert main(["assessment", "import", "--source", "maester", "--input", str(source), "--output", str(output)]) == 2
    assert not output.exists()
    assert "outside finalized" in capsys.readouterr().err


def test_import_rejects_conflicting_tenant_without_output(tmp_path, capsys):
    source = _maester(tmp_path / "source.json")
    output = tmp_path / "normalized.json"
    assert main(["assessment", "import", "--source", "maester", "--input", str(source), "--tenant-id", "22222222-2222-4222-8222-222222222222", "--output", str(output)]) == 2
    assert not output.exists()
    assert capsys.readouterr().err


def test_source_catalogue_is_pinned_and_offline(capsys):
    assert main(["assessment", "sources"]) == 0
    catalogue = json.loads(capsys.readouterr().out)
    assert catalogue["tenant_access"] is False
    assert catalogue["external_execution"] is False
    sources = catalogue["sources"]
    assert {row["id"] for row in sources if row["import_supported"]} == {"maester", "scubagear", "monkey365"}
    assert all(len(row["revision"]) == 40 for row in sources)
