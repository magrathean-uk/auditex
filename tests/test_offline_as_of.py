"""``--as-of`` pins the date-derived values of offline runs (DEC-005).

Two offline runs of the same sample with the same ``--as-of`` and the wall clock set either side of a
lifecycle date must give equal digests under ``scripts/compare-run-outputs.py``; without ``--as-of``
the endpoint-posture pair differs, which proves the patched clock reaches the run.
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from auditex import cli as product_cli
from auditex.google_workspace.run import run_google_offline
from azure_tenant_audit import cli as engine_cli

ROOT = Path(__file__).resolve().parents[1]
AS_OF = "2026-11-11"


def _comparator() -> Any:
    spec = importlib.util.spec_from_file_location("compare_run_outputs_for_as_of", ROOT / "scripts" / "compare-run-outputs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _frozen(instant: dt.datetime) -> type[dt.datetime]:
    class FrozenDatetime(dt.datetime):
        @classmethod
        def now(cls, tz: dt.tzinfo | None = None) -> dt.datetime:
            return instant.replace(tzinfo=None) if tz is None else instant.astimezone(tz)

    return FrozenDatetime


def _patch_wall_clock(monkeypatch: pytest.MonkeyPatch, instant: dt.datetime) -> None:
    """Point every product module's ``datetime`` at a clock that reads ``instant``."""
    frozen = _frozen(instant)
    for name, module in list(sys.modules.items()):
        if name.startswith(("azure_tenant_audit", "auditex")) and getattr(module, "datetime", None) is dt.datetime:
            monkeypatch.setattr(module, "datetime", frozen)


def _run(kind: str, out: Path, as_of: dt.datetime | None) -> Path:
    if kind == "google":
        rc = run_google_offline(
            sample_path=ROOT / "examples" / "google_workspace_sample.json",
            out=out,
            tenant_name="ci",
            run_name=kind,
            domain="example.com",
            customer_id=None,
            as_of=as_of,
        )
    else:
        sample = {
            "endpoint-posture": ROOT / "examples" / "sample_audit_bundle" / "endpoint_posture_result.json",
            "demo": ROOT / "examples" / "demo_tenant" / "demo_tenant.json",
        }[kind]
        rc = engine_cli.run_offline(sample, out, "ci", kind, as_of=as_of)
    assert rc in (0, 1), rc
    return out / f"ci-{kind}"


def _digest_pair(kind: str, before: dt.datetime, after: dt.datetime, as_of: dt.datetime | None, tmp_path: Path) -> tuple[dict, dict]:
    comparator = _comparator()
    digests = []
    for label, instant in (("before", before), ("after", after)):
        with pytest.MonkeyPatch.context() as clock:
            _patch_wall_clock(clock, instant)
            run = _run(kind, tmp_path / label, as_of)
        digests.append(comparator.digest_run(run))
    return digests[0], digests[1]


def _utc(year: int, month: int, day: int) -> dt.datetime:
    return dt.datetime(year, month, day, 12, tzinfo=dt.UTC)


# Each lifecycle date comes from the sample or the shipped table: Windows 10 22H2 (build 19045) ends support on
# 2025-10-14 (configs/os-end-of-life.json), the demo's ShipTrack Sync secret ends on 2027-03-15 and the sample
# Chromebook's auto-update expiry is 2023-06-01.
LIFECYCLE_PAIRS = {
    "endpoint-posture": (_utc(2025, 10, 1), _utc(2025, 11, 1)),
    "demo": (_utc(2027, 3, 1), _utc(2027, 4, 1)),
    "google": (_utc(2023, 5, 1), _utc(2023, 7, 1)),
}


@pytest.mark.parametrize("kind", sorted(LIFECYCLE_PAIRS))
def test_same_as_of_gives_equal_digests_either_side_of_a_lifecycle_date(kind, tmp_path) -> None:
    before, after = LIFECYCLE_PAIRS[kind]
    first, second = _digest_pair(kind, before, after, engine_cli.parse_as_of(AS_OF), tmp_path)
    assert first == second


def test_without_as_of_the_endpoint_posture_pair_differs(tmp_path) -> None:
    before, after = LIFECYCLE_PAIRS["endpoint-posture"]
    first, second = _digest_pair("endpoint-posture", before, after, None, tmp_path)
    assert first != second


def test_an_expired_waiver_stays_expired_under_an_earlier_as_of(tmp_path) -> None:
    """Waiver expiry reads the real date, so an old ``--as-of`` cannot bring an expired waiver back."""
    finding_id = "google.drive_anyone_with_link:file-1"
    waivers = tmp_path / "waivers.json"
    waivers.write_text(
        json.dumps({"waivers": [{"finding_id": finding_id, "owner": "g@example.com", "reason": "Public brochure", "expires_on": "2026-01-01"}]}),
        encoding="utf-8",
    )
    # The waiver expired before the real date and is still in force on the --as-of date.
    rc = run_google_offline(
        sample_path=ROOT / "examples" / "google_workspace_sample.json",
        out=tmp_path,
        tenant_name="ci",
        run_name="waiver",
        domain="example.com",
        customer_id=None,
        waiver_file=waivers,
        as_of=engine_cli.parse_as_of("2025-06-01"),
    )
    assert rc in (0, 1), rc
    findings = json.loads((tmp_path / "ci-waiver" / "findings" / "findings.json").read_text(encoding="utf-8"))
    finding = next(item for item in findings if item["id"] == finding_id)
    assert finding["status"] == "open"
    assert not finding.get("waiver_applied")


def test_parse_as_of_reads_a_calendar_date_as_noon_utc() -> None:
    assert engine_cli.parse_as_of("2026-11-11") == dt.datetime(2026, 11, 11, 12, tzinfo=dt.UTC)
    assert engine_cli.parse_as_of("2024-02-29") == dt.datetime(2024, 2, 29, 12, tzinfo=dt.UTC)


# The window ends and the dates just inside them.
@pytest.mark.parametrize("value", ["1970-01-01", "1970-01-02", "2999-12-30", "2999-12-31"])
def test_parse_as_of_accepts_the_window_ends(value) -> None:
    year, month, day = (int(part) for part in value.split("-"))
    assert engine_cli.parse_as_of(value) == dt.datetime(year, month, day, 12, tzinfo=dt.UTC)


INVALID_DATES = [
    "", " 2026-11-11", "2026-11-11 ", "2026-13-01", "2026-02-30", "2025-02-29", "2026-1-1", "20261111",
    "2026/11/11", "2026-11-11T00:00", "2026-11-11Z", "11-11-2026", "２０２６-11-11", "today",
    # Outside the window: the datetime extremes and the day either side of it.
    "0001-01-01", "1969-12-31", "3000-01-01", "9999-12-31",
]
OUT_OF_WINDOW = INVALID_DATES[-4:]


@pytest.mark.parametrize("value", INVALID_DATES)
def test_parse_as_of_refuses_anything_but_a_real_yyyy_mm_dd(value) -> None:
    with pytest.raises(engine_cli.argparse.ArgumentTypeError):
        engine_cli.parse_as_of(value)


def _forbid(*args, **kwargs):
    pytest.fail("this run must not start")


ENTRIES = {
    "engine": (engine_cli.main, []),
    "run": (product_cli.main, ["run"]),
    "google-run": (product_cli.main, ["google", "run", "--domain", "example.com"]),
}


def _capture_runs(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def record(*args, **kwargs):
        calls.append(kwargs)
        return 0

    monkeypatch.setattr(engine_cli, "run_offline", record)
    monkeypatch.setattr(product_cli, "run_google_offline", record)
    monkeypatch.setattr(engine_cli, "run_live", _forbid)
    monkeypatch.setattr(product_cli, "run_google_live", _forbid)
    return calls


def _exit_code(main, argv: list[str]) -> int:
    try:
        return main(argv)
    except SystemExit as exc:
        return exc.code


@pytest.mark.parametrize("entry", sorted(ENTRIES))
@pytest.mark.parametrize("value", ["2026-02-30", "2026-1-1", "20261111", "not-a-date", "0001-01-01", "9999-12-31"])
def test_an_invalid_as_of_is_a_usage_error(entry, value, monkeypatch, tmp_path, capsys) -> None:
    calls = _capture_runs(monkeypatch)
    monkeypatch.chdir(tmp_path)
    main, prefix = ENTRIES[entry]
    assert _exit_code(main, [*prefix, "--offline", "--as-of", value]) == 2
    assert calls == []
    assert value not in capsys.readouterr().err


OFFLINE_COMMANDS = {
    "engine": ["-m", "azure_tenant_audit", "--offline", "--sample", "examples/demo_tenant/demo_tenant.json"],
    "run": ["-m", "auditex", "run", "--offline", "--sample", "examples/demo_tenant/demo_tenant.json"],
    "google-run": [
        "-m", "auditex", "google", "run", "--offline", "--sample", "examples/google_workspace_sample.json", "--domain", "example.com",
    ],
}


@pytest.mark.parametrize("entry", sorted(OFFLINE_COMMANDS))
@pytest.mark.parametrize("value", OUT_OF_WINDOW)
def test_an_out_of_window_as_of_exits_2_before_any_run_folder(entry, value, tmp_path) -> None:
    """The real offline entry points stop at the parser: exit 2, no traceback and nothing written."""
    out = tmp_path / "out"
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    command = [sys.executable, *OFFLINE_COMMANDS[entry], "--tenant-name", "ci", "--out", str(out), "--as-of", value]
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 2, result.stderr
    assert "Traceback" not in result.stderr
    assert not out.exists()


@pytest.mark.parametrize("entry", sorted(ENTRIES))
def test_a_live_run_refuses_as_of(entry, monkeypatch, tmp_path, capsys) -> None:
    calls = _capture_runs(monkeypatch)
    monkeypatch.chdir(tmp_path)
    main, prefix = ENTRIES[entry]
    assert _exit_code(main, [*prefix, "--as-of", AS_OF]) == 2
    assert calls == []
    assert "--as-of applies only to offline runs" in capsys.readouterr().err


@pytest.mark.parametrize("entry", sorted(ENTRIES))
def test_offline_runs_forward_the_date_and_default_to_the_wall_clock(entry, monkeypatch, tmp_path) -> None:
    calls = _capture_runs(monkeypatch)
    monkeypatch.chdir(tmp_path)
    main, prefix = ENTRIES[entry]
    assert _exit_code(main, [*prefix, "--offline", "--as-of", AS_OF]) == 0
    assert _exit_code(main, [*prefix, "--offline"]) == 0
    assert [call["as_of"] for call in calls] == [engine_cli.parse_as_of(AS_OF), None]


def test_the_google_probe_has_no_as_of(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(product_cli, "run_google_probe", _forbid)
    monkeypatch.chdir(tmp_path)
    assert _exit_code(product_cli.main, ["google", "probe", "--offline", "--as-of", AS_OF]) == 2
