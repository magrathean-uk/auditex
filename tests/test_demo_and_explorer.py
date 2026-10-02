from __future__ import annotations

import io
import json
import re
from pathlib import Path

from azure_tenant_audit.cli import run_offline

from auditex.cli import main as auditex_main
from auditex.demo import FALLBACK_SAMPLE, DemoOptions, run_demo
from auditex.explorer import build_explorer_data, render_explorer_html, write_explorer
from auditex.reporting import verify_enterprise_handoff_pack, write_enterprise_handoff_pack

REPO_ROOT = Path(__file__).resolve().parents[1]
KNOWN_BAD = REPO_ROOT / "examples" / "sample_audit_bundle" / "known_bad_result.json"


def _known_bad_run(tmp_path: Path) -> Path:
    assert run_offline(KNOWN_BAD, tmp_path, "demo", "kb") == 0
    return tmp_path / "demo-kb"


def test_demo_walkthrough_runs_offline_end_to_end(tmp_path: Path) -> None:
    stream = io.StringIO()
    out_dir = tmp_path / "demo"

    rc = run_demo(DemoOptions(out_dir=out_dir, sample=REPO_ROOT / FALLBACK_SAMPLE, pause=False, stream=stream))

    output = stream.getvalue()
    assert rc == 0, output
    assert "No Microsoft 365 tenant is contacted" in output
    for heading in ("Plan read-only access", "Collect evidence", "Read the risk summary", "Open one finding", "attack path", "tamper-evident"):
        assert heading in output
    assert "with write access" in output and "(0 with write access)" in output
    assert "Edit one line of handoff.md, verify again: INVALID (checksum_mismatch)" in output
    assert "Restore the file, verify again: valid" in output
    assert (out_dir / "explorer.html").is_file()
    assert "\033[" not in output, "colour codes must not be written to a non-terminal stream"


def test_demo_command_is_registered(tmp_path: Path, capsys) -> None:
    rc = auditex_main(["demo", "--no-pause", "--no-html", "--sample", str(KNOWN_BAD), "--out", str(tmp_path / "d")])

    assert rc == 0
    assert "Read the risk summary" in capsys.readouterr().out


def test_explorer_is_self_contained_and_embeds_evidence(tmp_path: Path) -> None:
    run_dir = _known_bad_run(tmp_path)

    data = build_explorer_data(run_dir)
    page = render_explorer_html(data)

    assert data["contract_valid"] is True
    assert len(data["findings"]) == 13
    assert data["evidence"], "evidence records referenced by findings are embedded"
    assert data["data_handling"]["write_actions"] is False
    assert not re.search(r"""(src|href)=["']https?://""", page), "the explorer must not load remote resources"
    assert "fetch(" not in page and "XMLHttpRequest" not in page
    embedded = page.split('<script id="data" type="application/json">', 1)[1].split("</script>", 1)[0]
    assert json.loads(embedded)["runs"][0]["tenant"] == "demo"


def test_explorer_escapes_script_breakouts(tmp_path: Path) -> None:
    run_dir = _known_bad_run(tmp_path)
    data = build_explorer_data(run_dir)
    data["findings"][0]["title"] = "</script><script>alert(1)</script>"

    page = render_explorer_html(data)

    assert "</script><script>alert(1)" not in page


def test_report_explorer_command_writes_default_path(tmp_path: Path, capsys) -> None:
    run_dir = _known_bad_run(tmp_path)

    rc = auditex_main(["report", "explorer", str(run_dir)])

    assert rc == 0
    assert (run_dir / "reports" / "explorer.html").is_file()
    assert capsys.readouterr().out.strip().endswith("explorer.html")


def test_write_explorer_creates_parent_folders(tmp_path: Path) -> None:
    run_dir = _known_bad_run(tmp_path)

    path = write_explorer(run_dir, tmp_path / "nested" / "page.html")

    assert path.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_verify_pack_reports_each_tampered_file_once_with_relative_path(tmp_path: Path) -> None:
    run_dir = _known_bad_run(tmp_path)
    pack_dir = tmp_path / "pack"
    write_enterprise_handoff_pack(str(run_dir), str(pack_dir))
    (pack_dir / "handoff.md").write_text("edited\n", encoding="utf-8")

    result = verify_enterprise_handoff_pack(str(pack_dir))

    mismatches = [issue for issue in result["issues"] if issue["code"] == "checksum_mismatch"]
    assert len(mismatches) == 1
    assert mismatches[0]["path"] == "handoff.md"
    assert len(mismatches[0]["sources"]) == 2
    assert str(tmp_path) not in json.dumps(result["issues"])


def _load_generator():
    import importlib.util

    spec = importlib.util.spec_from_file_location("make_remediated_demo", REPO_ROOT / "scripts" / "make-remediated-demo.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_remediated_demo_twin_matches_its_generator() -> None:
    generator = _load_generator()
    source = json.loads(generator.SOURCE.read_text(encoding="utf-8"))
    expected, changes = generator.remediate(source)

    assert changes, "the twin applies at least one remediation"
    assert json.loads(generator.TARGET.read_text(encoding="utf-8")) == expected, "run python3 scripts/make-remediated-demo.py"


def test_remediated_twin_only_resolves_findings_and_drops_critical_grade(tmp_path: Path) -> None:
    demo_dir = REPO_ROOT / "examples" / "demo_tenant"
    assert run_offline(demo_dir / "demo_tenant.json", tmp_path, "halcyon", "before") == 0
    assert run_offline(demo_dir / "demo_tenant_remediated.json", tmp_path, "halcyon", "after") == 0

    def load(run: str, relative: str):
        return json.loads((tmp_path / f"halcyon-{run}" / relative).read_text(encoding="utf-8"))

    before_ids = {item["id"] for item in load("before", "findings/findings.json")}
    after_ids = {item["id"] for item in load("after", "findings/findings.json")}
    before_risk = load("before", "reports/report-pack.json")["summary"]["risk"]
    after_risk = load("after", "reports/report-pack.json")["summary"]["risk"]

    assert after_ids < before_ids, "remediation resolves findings without introducing new ones"
    assert load("after", "validation.json")["valid"] is True
    assert before_risk["grade"] == "critical" and after_risk["grade"] != "critical"
    assert after_risk["score"] < before_risk["score"]


def test_demo_includes_before_after_step_for_demo_tenant(tmp_path: Path) -> None:
    stream = io.StringIO()

    rc = run_demo(DemoOptions(out_dir=tmp_path / "demo", pause=False, html=False, stream=stream))

    output = stream.getvalue()
    assert rc == 0, output
    assert "Fix the worst issues, re-audit" in output
    assert "new 0" in output
    assert "Halcyon Freight Ltd" in output


def test_demo_shows_detection_baselines_and_graph_attack_path(tmp_path: Path) -> None:
    stream = io.StringIO()

    assert run_demo(DemoOptions(out_dir=tmp_path / "demo", pause=False, html=True, stream=stream)) == 0

    output = stream.getvalue()
    assert "Would anyone notice?" in output
    assert "CIS M365 v7" in output and "fail" in output
    assert "Break it: remove tom.fielding@halcyonfreight.example as owner of Payroll Export" in output
    page = (tmp_path / "demo" / "explorer.html").read_text(encoding="utf-8")
    assert 'data-view="detection"' in page and 'data-view="baselines"' in page
