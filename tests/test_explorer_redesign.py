from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import re
import shutil
import tomllib
from importlib import resources
from pathlib import Path

import pytest

from azure_tenant_audit.cli import run_offline

from auditex.cli import main as auditex_main
from auditex.demo import DemoOptions, run_demo
from auditex.explorer import (
    ExplorerCompareError,
    build_explorer_bundle,
    build_explorer_data,
    render_explorer_html,
    write_explorer,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = REPO_ROOT / "examples" / "demo_tenant"
KNOWN_BAD = REPO_ROOT / "examples" / "sample_audit_bundle" / "known_bad_result.json"
VIEWS = ("overview", "findings", "paths", "detection", "baselines", "access", "compare")
HTML_SINKS = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function")


@pytest.fixture(scope="module")
def halcyon_runs(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    root = tmp_path_factory.mktemp("halcyon")
    assert run_offline(DEMO_DIR / "demo_tenant.json", root, "halcyon", "before") == 0
    assert run_offline(DEMO_DIR / "demo_tenant_remediated.json", root, "halcyon", "after") == 0
    return root / "halcyon-before", root / "halcyon-after"


@pytest.fixture(scope="module")
def known_bad_run(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("known-bad")
    assert run_offline(KNOWN_BAD, root, "demo", "kb") == 0
    return root / "demo-kb"


def _embedded(page: str) -> dict:
    return json.loads(page.split('<script id="data" type="application/json">', 1)[1].split("</script>", 1)[0])


def _inline_script(page: str) -> str:
    match = re.search(r"<script>(.*?)</script>", page, re.S)
    assert match, "one executable inline script"
    return match.group(1)


def test_page_has_no_remote_urls_or_html_sinks(halcyon_runs: tuple[Path, Path]) -> None:
    page = render_explorer_html(build_explorer_bundle(list(halcyon_runs)))

    assert not re.search(r"https?://", page, re.I), "no http(s) URL anywhere in the page"
    assert not HTML_SINKS.search(page), "tenant strings must never reach an HTML parser"
    assert "fetch(" not in page and "XMLHttpRequest" not in page and "@import" not in page
    assert "support.js" not in page
    for source in re.findall(r"src:url\(([^)]*)\)", page):
        assert source.startswith("data:font/woff2;base64,"), "fonts are embedded, never fetched"
    assert page.count("<script") == 2, "only the JSON data block and the one inline script"


def test_csp_pins_the_inline_script_hash(halcyon_runs: tuple[Path, Path]) -> None:
    page = render_explorer_html(build_explorer_bundle(halcyon_runs[0]))
    script = _inline_script(page)
    digest = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    csp = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', page)

    assert csp, "CSP meta tag present"
    policy = csp.group(1).replace("&#x27;", "'")
    assert "default-src 'none'" in policy
    assert f"script-src 'sha256-{digest}'" in policy
    assert "style-src 'unsafe-inline'" in policy and "img-src data:" in policy
    assert 'src="data:image/png;base64,' in page, "logo is inlined as a data URI"


def test_output_is_deterministic(halcyon_runs: tuple[Path, Path], tmp_path: Path) -> None:
    first = write_explorer(list(halcyon_runs), tmp_path / "a.html").read_bytes()
    second = write_explorer(list(halcyon_runs), tmp_path / "b.html").read_bytes()

    assert first == second
    assert hashlib.sha256(first).hexdigest() == hashlib.sha256(second).hexdigest()


def test_embedded_json_round_trips(halcyon_runs: tuple[Path, Path]) -> None:
    bundle = build_explorer_bundle(list(halcyon_runs))
    page = render_explorer_html(bundle)

    assert _embedded(page) == json.loads(json.dumps(bundle, default=str))


def test_script_breakout_comment_and_url_escaping(known_bad_run: Path) -> None:
    data = build_explorer_data(known_bad_run)
    data["findings"][0]["title"] = "</script><script>alert(1)</script><!-- http://evil.example/x"
    data["meta"]["display_name"] = "</title><script>alert(2)</script> https://evil.example"

    page = render_explorer_html(data)

    assert "</script><script>alert(1)" not in page
    assert "</title><script>alert(2)" not in page
    assert "<!--" not in page.split('<script id="data"', 1)[1].split("</script>", 1)[0]
    assert not re.search(r"https?://", page)
    assert _embedded(page)["runs"][0]["findings"][0]["title"].endswith("<!-- http://evil.example/x")


def test_every_view_and_landmark_is_present(known_bad_run: Path) -> None:
    page = render_explorer_html(build_explorer_data(known_bad_run))

    for view in VIEWS:
        assert f'data-view="{view}"' in page
        assert f'id="view-{view}"' in page
    for landmark in ('<header class="ax-header">', '<nav aria-label="Explorer sections"', '<main id="ax-main" tabindex="-1"', 'class="ax-skip" href="#ax-main"'):
        assert landmark in page
    assert "prefers-reduced-motion" in page and "prefers-color-scheme: dark" in page and "@media print" in page


def test_compare_embeds_two_runs_oldest_first(halcyon_runs: tuple[Path, Path]) -> None:
    before, after = halcyon_runs
    bundle = build_explorer_bundle([after, before])

    assert [run["run_name"] for run in bundle["runs"]] == ["halcyon-before", "halcyon-after"]
    assert bundle["default_run"] == 1, "the first run passed is the run shown on open"
    compare = bundle["compare"]
    assert compare["a"]["run_name"] == "halcyon-before" and compare["b"]["run_name"] == "halcyon-after"
    assert compare["a"]["grade"] == "critical" and compare["b"]["grade"] != "critical"
    assert compare["a"]["score"] > compare["b"]["score"]
    assert len(compare["resolved"]) == compare["a"]["findings"] - compare["b"]["findings"]
    assert compare["added"] == []
    assert compare["paths_before"] > compare["paths_after"]


def test_compare_refuses_cross_tenant(halcyon_runs: tuple[Path, Path], known_bad_run: Path, tmp_path: Path, capsys) -> None:
    with pytest.raises(ExplorerCompareError):
        build_explorer_bundle([halcyon_runs[0], known_bad_run])

    rc = auditex_main(["report", "explorer", str(halcyon_runs[0]), "--compare", str(known_bad_run), "--output", str(tmp_path / "x.html")])

    assert rc == 2
    assert "different tenants" in capsys.readouterr().err
    assert not (tmp_path / "x.html").exists()


def test_cli_compare_writes_both_runs(halcyon_runs: tuple[Path, Path], tmp_path: Path) -> None:
    out = tmp_path / "page.html"

    rc = auditex_main(["report", "explorer", str(halcyon_runs[1]), "--compare", str(halcyon_runs[0]), "--output", str(out)])

    assert rc == 0
    data = _embedded(out.read_text(encoding="utf-8"))
    assert len(data["runs"]) == 2 and data["compare"] is not None


def test_demo_explorer_embeds_before_and_after(tmp_path: Path) -> None:
    assert run_demo(DemoOptions(out_dir=tmp_path / "demo", pause=False, stream=io.StringIO())) == 0

    data = _embedded((tmp_path / "demo" / "explorer.html").read_text(encoding="utf-8"))

    assert [run["run_name"] for run in data["runs"]] == ["halcyon-demo", "halcyon-after-fixes"]
    assert data["runs"][data["default_run"]]["run_name"] == "halcyon-demo"
    assert data["compare"]["a"]["grade"] == "critical"
    assert data["compare"]["a"]["score"] == 96 and data["compare"]["b"]["score"] == 63


def test_run_payload_maps_views(halcyon_runs: tuple[Path, Path]) -> None:
    run = build_explorer_data(halcyon_runs[0])

    assert run["meta"]["display_name"] == "Halcyon Freight Ltd"
    assert run["meta"]["domain"] == "halcyonfreight.example" and run["meta"]["users"]
    assert [row["n"] for row in run["findings"][:2]] == ["F-001", "F-002"]
    severities = [row["severity"] for row in run["findings"]]
    order = ["critical", "high", "medium", "low", "info"]
    assert severities == sorted(severities, key=order.index)
    path = run["attack_paths"][0]
    assert path["hops"] and path["break_index"] is not None and path["fix"]
    assert all(hop["rel"] and hop["technique_name"] for hop in path["hops"])
    hop = path["hops"][path["break_index"]]["evidence"]
    assert f"{hop['artifact']}#{hop['key']}" in run["evidence"], "break-it hop evidence is embedded"
    assert run["detection"]["signals"] and all(signal["detail"] for signal in run["detection"]["signals"])
    assert {row["status"] for row in run["detection"]["signals"]} <= {"on", "off", "unknown"}
    assert run["baselines"]["frameworks"] and run["baselines"]["secure"]["rows"]
    assert run["coverage"]["verified"] == run["coverage"]["all"] == len(run["collectors"])
    assert all(assertion["status"] == "pass" for assertion in run["assertions"])
    assert run["banners"][0]["kind"] == "synthetic"


def test_unverified_collectors_are_never_pass_or_fail(halcyon_runs: tuple[Path, Path], tmp_path: Path) -> None:
    run_dir = tmp_path / "partial"
    shutil.copytree(halcyon_runs[0], run_dir)
    ledger_path = run_dir / "normalized" / "coverage_ledger.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    for row in ledger["records"]:
        if row["collector"] == "exchange_policy":
            row["coverage_status"] = "blocked_permission"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    capability_path = run_dir / "normalized" / "capability_matrix.json"
    capability = json.loads(capability_path.read_text(encoding="utf-8"))
    for row in capability["records"]:
        if row["collector"] == "exchange_policy":
            row["blocker_kind"] = "local_tool"
    capability_path.write_text(json.dumps(capability), encoding="utf-8")

    run = build_explorer_data(run_dir)

    row = next(item for item in run["collectors"] if item["collector"] == "exchange_policy")
    assert row["status"] == "not_verified" and row["reason"] == "No Exchange Online session"
    assert run["coverage"]["not_verified"] == 1
    assert any(banner["kind"] == "partial" and "not verified" in banner["title"] for banner in run["banners"])


def test_scales_to_empty_and_large_runs(known_bad_run: Path) -> None:
    base = build_explorer_data(known_bad_run)
    empty = copy.deepcopy(base)
    empty["findings"], empty["attack_paths"], empty["evidence"] = [], [], {}
    page = render_explorer_html(empty)
    assert _embedded(page)["runs"][0]["findings"] == []

    large = copy.deepcopy(base)
    template = base["findings"][0]
    large["findings"] = [dict(template, id=f"bulk:{index}", n=f"F-{index + 1:03d}") for index in range(500)]
    path = {
        "id": "p", "severity": "high", "summary": "s", "source": "a", "target": "b", "foothold": "guest", "foothold_label": "Guest",
        "techniques": [], "hops": [], "break_index": None, "fix": "", "fix_detail": "", "also": [], "finding_id": "",
    }
    large["attack_paths"] = [dict(path, id=f"path-{index}") for index in range(50)]
    data = _embedded(render_explorer_html(large))["runs"][0]
    assert len(data["findings"]) == 500 and len(data["attack_paths"]) == 50


def test_explorer_assets_ship_as_package_data() -> None:
    assets = resources.files("auditex").joinpath("explorer_assets")
    for name in ("explorer.html", "explorer.css", "explorer.js"):
        assert assets.joinpath(name).read_text(encoding="utf-8").strip(), name
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = pyproject["tool"]["setuptools"]["package-data"]["auditex"]
    for name in ("explorer.html", "explorer.css", "explorer.js"):
        assert any(Path(name).match(Path(pattern).name) and pattern.startswith("explorer_assets/") for pattern in patterns), name


def test_barlow_fonts_are_embedded_and_allowed_only_as_data(tmp_path) -> None:  # noqa: ANN001
    from azure_tenant_audit.cli import run_offline
    from pathlib import Path as _Path

    from auditex.explorer import write_explorer

    sample = _Path(__file__).resolve().parents[1] / "examples" / "sample_audit_bundle" / "known_bad_result.json"
    assert run_offline(sample, tmp_path, "demo", "fonts") == 0
    page = write_explorer(tmp_path / "demo-fonts", tmp_path / "page.html").read_text(encoding="utf-8")

    assert page.count("@font-face") == 6
    assert "font-family:'Barlow Condensed'" in page and "font/woff2;base64," in page
    assert "font-src data:" in page
    assert "fonts.googleapis" not in page and "fonts.gstatic" not in page
