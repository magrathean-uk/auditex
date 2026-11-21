"""R064 / R134: tenant-controlled names render literally in every Markdown output (no raw HTML, links or forged rows)."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from gate_support import finding, offline_run, rehash, write_findings

HOSTILE = "<img src=x onerror=alert(1)> [Verify here](https://evil.example)\r| injected | row | # Forged heading"


def _assert_literal(text: str, where: str) -> None:
    assert "<img" not in text, where
    # A live link needs an unescaped '[' ... ']' directly followed by '('.
    assert not re.search(r"(?<!\\)\[[^\]]*(?<!\\)\]\(", text), where
    assert "\r" not in text and " " not in text, where
    for line in text.splitlines():
        assert not line.startswith("# Forged"), where
        assert not re.match(r"^\|? *injected", line), where


def test_markdown_inline_escapes_html_links_breaks_and_cells() -> None:
    from auditex.reporting import markdown_inline

    out = markdown_inline(HOSTILE)
    _assert_literal(out, "helper")
    assert "\\|" in out and "&lt;img" in out and "\\[Verify here\\]" in out
    # A backslash cannot cancel the pipe escape and reopen a table cell.
    assert markdown_inline("a\\|b") == "a\\\\\\|b"
    # Placeholders and ordinary identifiers stay readable.
    assert markdown_inline("<redacted-text> MS.AAD.1.1v1 identity:global_admin") == "<redacted-text> MS.AAD.1.1v1 identity:global_admin"


@pytest.mark.parametrize("profile", ["local", "shareable", "customer_pack"])
def test_markdown_report_renders_hostile_title_and_tenant_literally(tmp_path: Path, profile: str) -> None:
    from auditex.reporting import preview_report

    run = offline_run(tmp_path, "r064")
    row = finding("hostile-1")
    row["title"] = f"Potential privilege escalation route: {HOSTILE} -> target"
    write_findings(run, [row])
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["tenant_name"] = "contoso\n- Status: compliant\n# Auditor sign-off: all controls pass"
    manifest_path.write_text(json.dumps(manifest))
    rehash(run)

    content = preview_report(run_dir=str(run), format_name="md", profile=profile)["content"]
    _assert_literal(content, profile)
    assert not any(line.startswith(("- Status: compliant", "# Auditor sign-off")) for line in content.splitlines())


def test_customer_pack_markdown_files_render_hostile_title_literally(tmp_path: Path) -> None:
    from auditex.reporting import write_enterprise_handoff_pack

    run = offline_run(tmp_path, "r064pack")
    row = finding("hostile-1")
    row["title"] = f"Potential privilege escalation route: {HOSTILE} -> target"
    write_findings(run, [row])
    rehash(run)
    target = tmp_path / "pack"
    write_enterprise_handoff_pack(run, target)
    markdown = sorted(target.rglob("*.md"))
    assert markdown
    for path in markdown:
        _assert_literal(path.read_text(encoding="utf-8"), str(path.relative_to(target)))
