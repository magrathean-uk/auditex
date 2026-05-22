#!/usr/bin/env python3
from __future__ import annotations

import html
import posixpath
import re
import sys
from pathlib import Path


DOCS = [
    ("README.md", "Repository Overview"),
    ("RUNBOOK.md", "Runbook"),
    ("docs/README.md", "Documentation Index"),
    ("docs/PRODUCT_MANUAL.md", "Product Manual"),
    ("docs/SETUP_GUIDE.md", "Setup Guide"),
    ("docs/ADMIN_PERMISSION_GUIDE.md", "Admin Permission Guide"),
    ("docs/AI_OPERATOR_GUIDE.md", "AI Operator Guide"),
    ("docs/GITHUB_OPERATOR_GUIDE.md", "GitHub Operator Guide"),
    ("docs/CUSTOMER_HANDOFF_GUIDE.md", "Customer Handoff Guide"),
    ("docs/SECURITY_PRIVACY.md", "Security And Privacy"),
    ("docs/API_CALL_CATALOG.md", "API Call Catalog"),
    ("docs/OUTPUT_CONTRACT.md", "Output Contract"),
    ("docs/TROUBLESHOOTING.md", "Troubleshooting"),
    ("docs/SHIP_READINESS.md", "Ship Readiness"),
    ("docs/RELEASE_CHECKLIST.md", "Release Checklist"),
    ("docs/improvement/auditex-1.0-ultimate-plan.md", "Auditex 1.0 Plan"),
    ("docs/provenance/provenance.md", "Provenance"),
    ("profiles/global-reader.md", "Global Reader Profile"),
    ("profiles/security-reader.md", "Security Reader Profile"),
    ("profiles/app-readonly-full.md", "App Read-only Full Profile"),
    ("profiles/exchange-reader.md", "Exchange Reader Profile"),
    ("profiles/intune-reader.md", "Intune Reader Profile"),
    ("CHANGELOG.md", "Changelog"),
    ("RELEASE_NOTES.md", "Release Notes"),
    ("SECURITY.md", "Security Policy"),
    ("license.md", "License Summary"),
    ("THIRD_PARTY_NOTICES.md", "Third Party Notices"),
]

GITHUB_BLOB_BASE = "https://github.com/magrathean-uk/auditex/blob/main/"


STYLE = """
:root { color-scheme: light dark; --bg:#fbfbf8; --panel:#ffffff; --text:#1d2430; --muted:#5f6b7a; --line:#d9ded6; --accent:#176b5b; }
@media (prefers-color-scheme: dark) { :root { --bg:#111418; --panel:#171b20; --text:#e9edf2; --muted:#a3acb8; --line:#2b323b; --accent:#66d0b8; } }
* { box-sizing: border-box; }
body { margin:0; font:16px/1.6 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--text); }
header { border-bottom:1px solid var(--line); background:var(--panel); }
.wrap { max-width:1120px; margin:0 auto; padding:24px; }
header .wrap { display:flex; align-items:center; justify-content:space-between; gap:16px; }
a { color:var(--accent); }
nav { display:flex; flex-wrap:wrap; gap:10px; }
nav a { text-decoration:none; font-weight:600; }
.hero { padding:44px 24px 28px; }
.hero h1 { margin:0 0 8px; font-size:42px; line-height:1.08; }
.hero p { max-width:760px; color:var(--muted); font-size:18px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(260px, 1fr)); gap:14px; margin-top:24px; }
.card { border:1px solid var(--line); background:var(--panel); border-radius:8px; padding:16px; }
.card h2 { margin:0 0 8px; font-size:18px; }
main { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:26px; }
main h1:first-child { margin-top:0; }
pre { overflow:auto; padding:14px; border:1px solid var(--line); border-radius:8px; background:#0d1117; color:#e6edf3; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
:not(pre) > code { background:color-mix(in srgb, var(--line) 45%, transparent); padding:2px 5px; border-radius:4px; }
table { border-collapse:collapse; width:100%; display:block; overflow:auto; }
th, td { border:1px solid var(--line); padding:8px; text-align:left; }
footer { color:var(--muted); }
""".strip()


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    output = Path(argv[0] if argv else "site")
    output.mkdir(parents=True, exist_ok=True)
    (output / "assets").mkdir(exist_ok=True)
    (output / "assets" / "auditex.css").write_text(STYLE + "\n", encoding="utf-8")
    (output / ".nojekyll").write_text("", encoding="utf-8")

    pages = []
    for source, title in DOCS:
        path = Path(source)
        if not path.exists():
            continue
        slug = _slug(source)
        body = _markdown_to_html(path.read_text(encoding="utf-8"), path)
        (output / slug).write_text(_page(title, body), encoding="utf-8")
        pages.append((slug, title, _summary(path)))

    index_cards = "\n".join(
        f'<article class="card"><h2><a href="{href}">{html.escape(title)}</a></h2><p>{html.escape(summary)}</p></article>'
        for href, title, summary in pages
    )
    index = f"""
<section class="hero">
  <div class="wrap">
    <h1>Auditex v1 Enterprise Auditor</h1>
    <p>Audit-only Microsoft 365 and Google Workspace evidence collection, setup guidance, proof-backed reporting, and customer handoff packs.</p>
    <div class="grid">{index_cards}</div>
  </div>
</section>
""".strip()
    (output / "index.html").write_text(_page("Auditex v1 Enterprise Auditor", index, is_index=True), encoding="utf-8")
    return 0


def _slug(path: str) -> str:
    name = Path(path).with_suffix("").name.lower().replace("_", "-")
    if path == "README.md":
        return "overview.html"
    if path == "docs/README.md":
        return "documentation.html"
    if path == "docs/improvement/auditex-1.0-ultimate-plan.md":
        return "auditex-1.0-plan.html"
    if path == "docs/provenance/provenance.md":
        return "provenance.html"
    return f"{name}.html"


DOC_SLUGS = {source: _slug(source) for source, _ in DOCS}


def _summary(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text and not text.startswith("#"):
            return text[:180]
    return "Auditex documentation."


def _page(title: str, body: str, *, is_index: bool = False) -> str:
    nav = '<nav><a href="index.html">Home</a><a href="setup-guide.html">Setup</a><a href="product-manual.html">Manual</a><a href="security-privacy.html">Security</a><a href="changelog.html">Changelog</a></nav>'
    main = body if is_index else f'<div class="wrap"><main>{body}</main></div>'
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <link rel="stylesheet" href="assets/auditex.css">
</head>
<body>
  <header><div class="wrap"><strong>Auditex</strong>{nav}</div></header>
  {main}
  <footer><div class="wrap">Auditex v1. Audit-only. Evidence local by default.</div></footer>
</body>
</html>
"""


def _markdown_to_html(markdown: str, current_path: Path) -> str:
    lines = markdown.splitlines()
    out: list[str] = []
    in_code = False
    in_list = False
    in_ol = False
    in_table = False
    paragraph: list[str] = []

    def flush_paragraph() -> None:
        if paragraph:
            out.append(f"<p>{_inline(' '.join(paragraph), current_path)}</p>")
            paragraph.clear()

    def close_lists() -> None:
        nonlocal in_list, in_ol
        if in_list:
            out.append("</ul>")
            in_list = False
        if in_ol:
            out.append("</ol>")
            in_ol = False

    def close_table() -> None:
        nonlocal in_table
        if in_table:
            out.append("</tbody></table>")
            in_table = False

    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if stripped.startswith("```"):
            flush_paragraph()
            close_lists()
            close_table()
            if not in_code:
                out.append("<pre><code>")
                in_code = True
            else:
                out.append("</code></pre>")
                in_code = False
            continue
        if in_code:
            out.append(html.escape(line))
            continue
        if not stripped:
            flush_paragraph()
            close_lists()
            close_table()
            continue
        if stripped.startswith("|") and stripped.endswith("|"):
            flush_paragraph()
            close_lists()
            cells = [cell.strip() for cell in stripped.strip("|").split("|")]
            if set("".join(cells)) <= {"-", ":", " "}:
                continue
            if not in_table:
                out.append("<table><tbody>")
                in_table = True
            out.append("<tr>" + "".join(f"<td>{_inline(cell, current_path)}</td>" for cell in cells) + "</tr>")
            continue
        close_table()
        heading = re.match(r"^(#{1,4})\s+(.+)$", stripped)
        if heading:
            flush_paragraph()
            close_lists()
            level = len(heading.group(1))
            out.append(f"<h{level}>{_inline(heading.group(2), current_path)}</h{level}>")
            continue
        bullet = re.match(r"^[-*]\s+(.+)$", stripped)
        if bullet:
            flush_paragraph()
            if not in_list:
                close_lists()
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(bullet.group(1), current_path)}</li>")
            continue
        numbered = re.match(r"^\d+\.\s+(.+)$", stripped)
        if numbered:
            flush_paragraph()
            if not in_ol:
                close_lists()
                out.append("<ol>")
                in_ol = True
            out.append(f"<li>{_inline(numbered.group(1), current_path)}</li>")
            continue
        paragraph.append(stripped)

    flush_paragraph()
    close_lists()
    close_table()
    if in_code:
        out.append("</code></pre>")
    return "\n".join(out)


def _inline(text: str, current_path: Path) -> str:
    escaped = html.escape(text)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda match: _render_link(match.group(1), html.unescape(match.group(2)), current_path),
        escaped,
    )
    return escaped


def _render_link(label: str, target: str, current_path: Path) -> str:
    href = _site_link(target, current_path)
    return f'<a href="{html.escape(href, quote=True)}">{label}</a>'


def _site_link(target: str, current_path: Path) -> str:
    if target.startswith(("http://", "https://", "mailto:", "#")):
        return target
    anchor = ""
    path_part = target
    if "#" in path_part:
        path_part, anchor = path_part.split("#", 1)
        anchor = f"#{anchor}"
    candidate = (current_path.parent / path_part).as_posix()
    candidate = posixpath.normpath(candidate)
    bare = posixpath.normpath(path_part)
    if path_part.endswith(".md"):
        generated = DOC_SLUGS.get(candidate, DOC_SLUGS.get(bare))
        if generated:
            return generated + anchor
    if Path(candidate).exists():
        return GITHUB_BLOB_BASE + candidate + anchor
    if Path(bare).exists():
        return GITHUB_BLOB_BASE + bare + anchor
    return target


if __name__ == "__main__":
    raise SystemExit(main())
