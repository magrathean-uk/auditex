from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "benchmarks" / "html_peak.py"
FIELD_TYPES = {
    "records": int,
    "profile": str,
    "workload_sha256": str,
    "peak_rss_bytes": int,
    "person_names": int,
    "unmasked_name_hits": int,
    "commit": str,
    "python": str,
}


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HARNESS), *args], capture_output=True, text=True, timeout=300, check=False
    )


@pytest.fixture(scope="module")
def shareable_result() -> dict:
    done = _run("--records", "400", "--profile", "shareable")
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_json_fields_and_types(shareable_result: dict) -> None:
    assert set(shareable_result) == set(FIELD_TYPES)
    for key, kind in FIELD_TYPES.items():
        assert isinstance(shareable_result[key], kind), key
    assert shareable_result["records"] == 400
    assert shareable_result["profile"] == "shareable"
    assert shareable_result["person_names"] == 200
    assert shareable_result["peak_rss_bytes"] > 0
    assert len(shareable_result["workload_sha256"]) == 64


def test_workload_sha256_is_stable_per_count(shareable_result: dict, tmp_path: Path) -> None:
    again = _run("--records", "400", "--profile", "local")
    assert json.loads(again.stdout)["workload_sha256"] == shareable_result["workload_sha256"]
    other = _run("--records", "404", "--profile", "local")
    assert json.loads(other.stdout)["workload_sha256"] != shareable_result["workload_sha256"]


def test_ratio_exit_codes(shareable_result: dict, tmp_path: Path) -> None:
    tiny = tmp_path / "tiny.json"
    tiny.write_text(json.dumps({**shareable_result, "peak_rss_bytes": 1}), encoding="utf-8")
    assert _run("--records", "400", "--profile", "shareable", "--baseline", str(tiny)).returncode == 1
    huge = tmp_path / "huge.json"
    huge.write_text(json.dumps({**shareable_result, "peak_rss_bytes": 10**12}), encoding="utf-8")
    assert _run("--records", "400", "--profile", "shareable", "--baseline", str(huge)).returncode == 0


def test_usage_errors(shareable_result: dict, tmp_path: Path) -> None:
    assert _run("--records", "400", "--profile", "shareable", "--max-ratio", "1.1").returncode == 2
    assert _run("--records", "401", "--profile", "shareable").returncode == 2
    assert _run("--records", "400", "--profile", "shareable", "--baseline", str(tmp_path / "no.json")).returncode == 2
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({**shareable_result, "workload_sha256": "0" * 64}), encoding="utf-8")
    done = _run("--records", "400", "--profile", "shareable", "--baseline", str(bad))
    assert done.returncode == 2
    assert "baseline workload differs" in done.stderr
    assert done.stdout == ""
    assert _run("--records", "400", "--profile", "shareable", "--max-ratio", "0", "--baseline", str(bad)).returncode == 2


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("python", 3),
        ("peak_rss_bytes", -5),
        ("peak_rss_bytes", 0),
        ("peak_rss_bytes", True),
        ("records", "400"),
        ("profile", "other"),
        ("workload_sha256", "xyz"),
        ("person_names", -1),
        ("unmasked_name_hits", 1.5),
        ("commit", ""),
    ],
)
def test_malformed_baseline_exits_2_without_json(shareable_result: dict, tmp_path: Path, key: str, value: object) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({**shareable_result, key: value}), encoding="utf-8")
    done = _run("--records", "400", "--profile", "shareable", "--baseline", str(bad))
    assert done.returncode == 2
    assert done.stdout == ""
    assert "malformed baseline" in done.stderr


def test_require_masked_fails_on_local_report() -> None:
    done = _run("--records", "400", "--profile", "local", "--require-masked")
    assert done.returncode == 3
    assert json.loads(done.stdout)["unmasked_name_hits"] > 0


def test_committed_baseline_carries_names() -> None:
    baseline = json.loads((ROOT / "benchmarks" / "html-peak-baseline.json").read_text(encoding="utf-8"))
    assert baseline["records"] == 90000
    assert baseline["profile"] == "shareable"
    assert baseline["person_names"] > 0
