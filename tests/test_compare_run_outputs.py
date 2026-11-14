from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "compare-run-outputs.py"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "contract-smoke-digests.json"

spec = importlib.util.spec_from_file_location("compare_run_outputs", SCRIPT)
cro = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cro)


def _write(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")


def _make_run(base: Path, name: str, *, stamp: str, verdict: str = "pass", line: str = "Policy met.", days: int = -436) -> Path:
    run = base / name
    run_dir = str(run.resolve())
    _write(
        run / "reports/report-pack.json",
        {
            "run_id": f"id-{stamp}",
            "run_dir": run_dir,
            "findings": [{"evidence_refs": [{"collected_at": f"2026-01-01T00:00:{stamp}.123Z", "path": f"{run_dir}/raw/x.json"}]}],
            "baseline_alignment": {"status": verdict},
            "sample": {"created": "2024-02-01T09:00:00Z"},
        },
    )
    _write(run / "reports/action-plan.json", [{"title": "Do it"}])
    _write(run / "summary.json", {"duration_seconds": float(stamp), "run_id": f"id-{stamp}", "total": 3})
    _write(
        run / "findings/findings.json",
        [
            {
                "rule_id": "a",
                "evidence_refs": [{"collected_at": f"t{stamp}"}],
                "evidence": {"expiry_state": "expired", "expiry_days_remaining": days},
                "returned_value": days,
            }
        ],
    )
    _write(run / "summary.md", f"# Summary {name}\nGenerated 2026-01-01T00:00:{stamp}.123456+00:00 in {run_dir}\nVerdict {verdict}\n")
    if name == cro.PROJECTION_RUN:
        _write(
            run / "model_assessment.json",
            {
                "generated_at": f"2026-01-01T00:00:{stamp}+00:00",
                "totals": {"rule_answered": 1},
                "policies": [{"id": "p1", "verdict": verdict, "latency_ms": int(stamp), "explainer": line}],
            },
        )
    return run


@pytest.fixture(autouse=True)
def _stub_in_memory(monkeypatch):
    def projection(run):
        data = json.loads((run / "model_assessment.json").read_text(encoding="utf-8"))
        return {"sections": {"p": data["policies"][0]["verdict"]}, "run_dir": str(run)}

    def explanations(run):
        data = json.loads((run / "model_assessment.json").read_text(encoding="utf-8"))
        return [data["policies"][0]["explainer"]]

    monkeypatch.setattr(cro, "_projection", projection)
    monkeypatch.setattr(cro, "_policy_explanations", explanations)


def _make_tree(base: Path, **kwargs) -> Path:
    for name in cro.RUNS:
        _make_run(base, name, **kwargs)
    return base


def test_volatile_fields_only_compare_equal(tmp_path):
    first = _make_tree(tmp_path / "a", stamp="11")
    second = _make_tree(tmp_path / "b" / "deeper", stamp="42")
    digests = tmp_path / "digests.json"
    assert cro.main(["--write", str(digests), str(first)]) == 0
    assert cro.main(["--digests", str(digests), str(second)]) == 0


def test_shifting_the_run_date_by_a_day_keeps_digests_equal(tmp_path):
    first = _make_tree(tmp_path / "a", stamp="11", days=-436)
    second = _make_tree(tmp_path / "b", stamp="11", days=-435)
    digests = tmp_path / "digests.json"
    assert cro.main(["--write", str(digests), str(first)]) == 0
    assert cro.main(["--digests", str(digests), str(second)]) == 0


def test_unrelated_returned_value_is_still_compared(tmp_path, capsys):
    base = _make_tree(tmp_path / "a", stamp="11")
    digests = tmp_path / "digests.json"
    cro.main(["--write", str(digests), str(base)])
    other = _make_tree(tmp_path / "b", stamp="11")
    path = other / "ci-admin-set/findings/findings.json"
    rows = json.loads(path.read_text(encoding="utf-8"))
    rows[0]["returned_value"] = 7
    path.write_text(json.dumps(rows), encoding="utf-8")
    capsys.readouterr()
    assert cro.main(["--digests", str(digests), str(other)]) == 1
    assert "ci-admin-set/findings/findings.json: differs" in capsys.readouterr().err


def test_changed_verdict_with_shifted_date_still_differs(tmp_path):
    base = _make_tree(tmp_path / "a", stamp="11", days=-436)
    digests = tmp_path / "digests.json"
    cro.main(["--write", str(digests), str(base)])
    changed = _make_tree(tmp_path / "b", stamp="11", days=-435, verdict="fail")
    assert cro.main(["--digests", str(digests), str(changed)]) == 1


def test_changed_verdict_is_named(tmp_path, capsys):
    base = _make_tree(tmp_path / "a", stamp="11")
    digests = tmp_path / "digests.json"
    cro.main(["--write", str(digests), str(base)])
    changed = _make_tree(tmp_path / "b", stamp="11", verdict="fail")
    capsys.readouterr()
    assert cro.main(["--digests", str(digests), str(changed)]) == 1
    err = capsys.readouterr().err
    assert "ci-projection-demo/model_assessment.json: differs" in err
    assert "ci-projection-demo/projection:project_run.report: differs" in err
    assert "ci-contract/reports/report-pack.json: differs" in err
    assert "ci-contract/findings/findings.json" not in err


def test_changed_explainer_line_is_named(tmp_path, capsys):
    base = _make_tree(tmp_path / "a", stamp="11")
    digests = tmp_path / "digests.json"
    cro.main(["--write", str(digests), str(base)])
    changed = _make_tree(tmp_path / "b", stamp="11")
    _make_run(changed, cro.PROJECTION_RUN, stamp="11", line="Policy not met.")
    capsys.readouterr()
    assert cro.main(["--digests", str(digests), str(changed)]) == 1
    err = capsys.readouterr().err
    assert "ci-projection-demo/explainer:policy_explanations: differs" in err
    assert "ci-contract/" not in err


def test_changed_summary_text_is_named(tmp_path, capsys):
    base = _make_tree(tmp_path / "a", stamp="11")
    digests = tmp_path / "digests.json"
    cro.main(["--write", str(digests), str(base)])
    other = _make_tree(tmp_path / "b", stamp="11")
    (other / "ci-google/summary.md").write_text("different\n", encoding="utf-8")
    capsys.readouterr()
    assert cro.main(["--digests", str(digests), str(other)]) == 1
    assert "ci-google/summary.md: differs" in capsys.readouterr().err


def test_missing_artefact_and_run_fail(tmp_path, capsys):
    base = _make_tree(tmp_path / "a", stamp="11")
    digests = tmp_path / "digests.json"
    cro.main(["--write", str(digests), str(base)])
    other = _make_tree(tmp_path / "b", stamp="11")
    (other / "ci-admin-set/reports/action-plan.json").unlink()
    shutil.rmtree(other / "ci-partial")
    capsys.readouterr()
    assert cro.main(["--digests", str(digests), str(other)]) == 1
    err = capsys.readouterr().err
    assert "ci-admin-set/reports/action-plan.json: missing or unreadable" in err
    assert "ci-partial: run directory missing" in err


def test_write_refuses_incomplete_run_tree(tmp_path):
    base = _make_tree(tmp_path / "a", stamp="11")
    (base / "ci-google/summary.md").unlink()
    target = tmp_path / "digests.json"
    assert cro.main(["--write", str(target), str(base)]) == 1
    assert not target.exists()


@pytest.mark.parametrize("content", [None, "", "not json", "{}", '{"runs": {}}', '{"runs": {"ci-contract": {}}}', "[]"])
def test_bad_digest_file_fails(tmp_path, capsys, content):
    base = _make_tree(tmp_path / "a", stamp="11")
    digests = tmp_path / "digests.json"
    if content is not None:
        digests.write_text(content, encoding="utf-8")
    assert cro.main(["--digests", str(digests), str(base)]) == 2
    assert "empty or unreadable" in capsys.readouterr().err


def test_cli_rejects_abbreviated_flags(tmp_path):
    with pytest.raises(SystemExit):
        cro.main(["--dig", str(tmp_path / "x.json"), str(tmp_path)])


def test_recorded_fixture_is_complete():
    recorded = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert recorded["schema"] == cro.SCHEMA
    assert len(recorded["commit"]) == 40
    assert set(recorded["runs"]) == set(cro.RUNS)
    for name, artefacts in recorded["runs"].items():
        for art in (*cro.JSON_ARTEFACTS, *cro.TEXT_ARTEFACTS):
            assert len(artefacts[art]) == 64, (name, art)
    projection = recorded["runs"][cro.PROJECTION_RUN]
    assert {cro.ASSESSMENT, "projection:project_run.report", "explainer:policy_explanations"} <= set(projection)


def test_expiry_state_either_side_of_an_expiry_keeps_digests_equal(tmp_path):
    before = _make_tree(tmp_path / "a", stamp="11", days=3)
    after = _make_tree(tmp_path / "b", stamp="11", days=-3)
    for tree, state in ((before, "expiring"), (after, "expired")):
        for run in tree.iterdir():
            path = run / "findings/findings.json"
            rows = json.loads(path.read_text(encoding="utf-8"))
            rows[0]["evidence"]["expiry_state"] = state
            path.write_text(json.dumps(rows), encoding="utf-8")
    digests = tmp_path / "digests.json"
    assert cro.main(["--write", str(digests), str(before)]) == 0
    assert cro.main(["--digests", str(digests), str(after)]) == 0


def test_unrelated_state_field_is_still_compared(tmp_path, capsys):
    base = _make_tree(tmp_path / "a", stamp="11")
    digests = tmp_path / "digests.json"
    cro.main(["--write", str(digests), str(base)])
    other = _make_tree(tmp_path / "b", stamp="11")
    path = other / "ci-google/findings/findings.json"
    rows = json.loads(path.read_text(encoding="utf-8"))
    rows[0]["evidence"]["compliance_state"] = "noncompliant"
    path.write_text(json.dumps(rows), encoding="utf-8")
    capsys.readouterr()
    assert cro.main(["--digests", str(digests), str(other)]) == 1
    assert "ci-google/findings/findings.json: differs" in capsys.readouterr().err


def test_docstring_does_not_point_at_the_archived_design():
    assert ".plan/work" not in (cro.__doc__ or "")
    assert ".plan/work" not in SCRIPT.read_text(encoding="utf-8")


def _recorded(tmp_path: Path, mutate) -> Path:
    base = _make_tree(tmp_path / "a", stamp="11")
    digests = tmp_path / "digests.json"
    cro.main(["--write", str(digests), str(base)])
    payload = json.loads(digests.read_text(encoding="utf-8"))
    mutate(payload["runs"])
    digests.write_text(json.dumps(payload), encoding="utf-8")
    return digests


def test_baseline_missing_a_run_fails(tmp_path, capsys):
    digests = _recorded(tmp_path, lambda runs: runs.pop("ci-partial"))
    capsys.readouterr()
    assert cro.main(["--digests", str(digests), str(tmp_path / "a")]) == 2
    assert "ci-partial: run missing from the baseline" in capsys.readouterr().err


def test_baseline_with_an_unknown_run_or_artefact_fails(tmp_path, capsys):
    def mutate(runs):
        runs["ci-extra"] = dict(runs["ci-partial"])
        runs["ci-google"]["summary.md"] = runs["ci-google"].pop("summary.md")
        runs["ci-google"]["extra.json"] = "0" * 64
        runs["ci-admin-set"].pop("summary.json")

    digests = _recorded(tmp_path, mutate)
    capsys.readouterr()
    assert cro.main(["--digests", str(digests), str(tmp_path / "a")]) == 2
    err = capsys.readouterr().err
    assert "ci-extra: run not digested by this script" in err
    assert "ci-google/extra.json: artefact not digested by this script" in err
    assert "ci-admin-set/summary.json: artefact missing from the baseline" in err
