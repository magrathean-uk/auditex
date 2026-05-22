#!/usr/bin/env python3
from __future__ import annotations

import html
import posixpath
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


SITE_DOMAIN = "auditex.hu"
SITE_URL = f"https://{SITE_DOMAIN}/"

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
:root {
  color-scheme: light;
  --bg:#f4f6f1;
  --ink:#101513;
  --muted:#5d6862;
  --line:#d9dfd2;
  --panel:#ffffff;
  --soft:#e9eee4;
  --dark:#101513;
  --dark-2:#18221e;
  --green:#14745f;
  --green-2:#b8eadc;
  --amber:#d6a849;
  --red:#d95c54;
  --shadow:0 22px 70px rgba(18, 32, 26, .13);
}
* { box-sizing: border-box; }
html { scroll-behavior:smooth; }
body {
  margin:0;
  font:16px/1.6 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background:var(--bg);
  color:var(--ink);
  overflow-x:hidden;
}
a { color:var(--green); }
.site-header {
  position:sticky;
  top:0;
  z-index:20;
  border-bottom:1px solid rgba(16, 21, 19, .08);
  background:rgba(244, 246, 241, .88);
  backdrop-filter:blur(18px);
}
.wrap { width:min(1160px, calc(100% - 40px)); margin:0 auto; }
.site-header .wrap { min-height:74px; display:flex; align-items:center; justify-content:space-between; gap:20px; }
.brand { display:flex; align-items:center; gap:11px; color:var(--ink); text-decoration:none; font-weight:760; letter-spacing:0; }
.brand-mark { width:31px; height:31px; display:grid; place-items:center; border:1px solid rgba(20,116,95,.28); border-radius:8px; background:#ffffff; box-shadow:0 9px 24px rgba(20,116,95,.13); }
.brand-mark svg { width:19px; height:19px; }
.nav { display:flex; align-items:center; gap:24px; }
.nav a { color:#26302b; text-decoration:none; font-size:14px; font-weight:650; }
.nav a:hover { color:var(--green); }
.header-cta { display:inline-flex; align-items:center; gap:9px; min-height:40px; padding:0 15px; border-radius:7px; color:#fff !important; background:var(--green); box-shadow:0 12px 30px rgba(20,116,95,.24); }
.header-cta svg { width:16px; height:16px; }
.hero {
  position:relative;
  overflow:hidden;
  padding:86px 0 72px;
  background:
    linear-gradient(115deg, rgba(20,116,95,.11), transparent 42%),
    radial-gradient(circle at 78% 16%, rgba(214,168,73,.18), transparent 26%),
    var(--bg);
}
.hero-grid { display:grid; grid-template-columns:minmax(0, 1.04fr) minmax(390px, .96fr); align-items:center; gap:54px; }
.hero h1 { margin:0; max-width:680px; font-size:clamp(46px, 7vw, 82px); line-height:.95; letter-spacing:0; font-weight:820; overflow-wrap:break-word; }
.hero-copy { margin:24px 0 0; max-width:610px; color:#46534c; font-size:20px; line-height:1.55; }
.actions { display:flex; flex-wrap:wrap; align-items:center; gap:13px; margin-top:32px; }
.button { display:inline-flex; align-items:center; justify-content:center; gap:9px; min-height:48px; padding:0 19px; border-radius:8px; font-weight:760; text-decoration:none; border:1px solid transparent; }
.button svg { width:17px; height:17px; }
.button.primary { background:var(--ink); color:#fff; box-shadow:0 17px 42px rgba(16,21,19,.2); }
.button.secondary { color:var(--ink); background:#fff; border-color:rgba(16,21,19,.11); }
.trust-row { display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); gap:1px; margin-top:38px; max-width:650px; border:1px solid rgba(16,21,19,.09); background:rgba(16,21,19,.09); }
.trust-row div { background:rgba(255,255,255,.65); padding:16px 18px; }
.trust-row strong { display:block; color:var(--ink); font-size:14px; }
.trust-row span { display:block; color:#5d6862; font-size:13px; margin-top:4px; }
.product-shell { min-width:0; max-width:100%; border:1px solid rgba(16,21,19,.1); background:#fff; box-shadow:var(--shadow); border-radius:14px; overflow:hidden; }
.terminal-bar { display:flex; align-items:center; justify-content:space-between; min-height:50px; padding:0 16px; border-bottom:1px solid #e4e9df; background:#fbfcf9; }
.dots { display:flex; gap:7px; }
.dots i { width:10px; height:10px; border-radius:50%; background:#d7ddd2; }
.dots i:nth-child(1) { background:var(--red); }
.dots i:nth-child(2) { background:var(--amber); }
.dots i:nth-child(3) { background:var(--green); }
.terminal-bar span { color:#68736d; font-size:12px; font-weight:720; }
.terminal { background:var(--dark); color:#e8f2ed; padding:22px; font:13px/1.65 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow:hidden; }
.terminal div { overflow-wrap:anywhere; }
.terminal .cmd { color:#b8eadc; }
.terminal .dim { color:#83928a; }
.terminal .ok { color:#86e5c9; }
.report-preview { padding:20px; display:grid; gap:13px; background:#fff; }
.risk-row { display:grid; grid-template-columns:86px 1fr auto; align-items:center; gap:13px; padding:12px; border:1px solid #e5eadf; border-radius:8px; }
.severity { font-size:12px; font-weight:800; color:#fff; text-align:center; border-radius:6px; padding:5px 7px; background:#c84d45; }
.severity.medium { background:#c28a26; }
.severity.low { background:#14745f; }
.risk-row strong { font-size:14px; }
.risk-row span { color:#657169; font-size:12px; }
.section { padding:86px 0; }
.section.dark { background:var(--dark); color:#eef5f1; }
.section h2 { margin:0; font-size:clamp(34px, 5vw, 56px); line-height:1; letter-spacing:0; }
.section-lead { max-width:690px; margin:18px 0 0; color:#5d6862; font-size:19px; }
.dark .section-lead { color:#b8c5bd; }
.split { display:grid; grid-template-columns:.88fr 1.12fr; gap:44px; align-items:start; }
.capability-grid { display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:14px; }
.capability { min-height:178px; border:1px solid var(--line); background:#fff; border-radius:8px; padding:22px; }
.capability svg { width:28px; height:28px; color:var(--green); }
.capability h3 { margin:22px 0 8px; font-size:20px; line-height:1.15; }
.capability p { margin:0; color:#657169; }
.proof-stack { display:grid; gap:13px; margin-top:28px; }
.proof-row { display:flex; justify-content:space-between; gap:18px; padding:16px 0; border-bottom:1px solid rgba(238,245,241,.16); }
.proof-row strong { font-size:18px; }
.proof-row span { color:#b8c5bd; text-align:right; }
.workflow { margin-top:36px; display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:1px; background:rgba(238,245,241,.16); border:1px solid rgba(238,245,241,.16); }
.workflow article { background:var(--dark-2); padding:24px; min-height:206px; }
.workflow span { color:var(--green-2); font-weight:800; }
.workflow h3 { margin:30px 0 9px; font-size:20px; line-height:1.15; }
.workflow p { margin:0; color:#b8c5bd; }
.docs-band { display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-top:32px; }
.doc-card { display:block; border:1px solid var(--line); background:#fff; border-radius:8px; padding:21px; color:var(--ink); text-decoration:none; }
.doc-card h3 { margin:0 0 7px; font-size:19px; }
.doc-card p { margin:0; color:#657169; }
.cta-panel { border:1px solid rgba(16,21,19,.08); border-radius:14px; background:#fff; padding:42px; box-shadow:var(--shadow); display:grid; grid-template-columns:1fr auto; align-items:center; gap:24px; }
.cta-panel h2 { font-size:42px; }
.site-footer { padding:44px 0; color:#66726b; border-top:1px solid rgba(16,21,19,.08); }
.footer-grid { display:flex; justify-content:space-between; gap:20px; flex-wrap:wrap; }
main { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:30px; margin:34px 0 70px; box-shadow:0 12px 40px rgba(18,32,26,.07); }
main h1:first-child { margin-top:0; }
pre { overflow:auto; padding:14px; border:1px solid var(--line); border-radius:8px; background:#0d1117; color:#e6edf3; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
:not(pre) > code { background:color-mix(in srgb, var(--line) 45%, transparent); padding:2px 5px; border-radius:4px; }
table { border-collapse:collapse; width:100%; display:block; overflow:auto; }
th, td { border:1px solid var(--line); padding:8px; text-align:left; }
@media (max-width: 900px) {
  .site-header .wrap { min-height:66px; }
  .nav a:not(.header-cta) { display:none; }
  .hero { padding:58px 0 54px; }
  .hero-grid, .split, .docs-band, .cta-panel { grid-template-columns:1fr; }
  .hero-grid { gap:34px; }
  .trust-row, .workflow, .capability-grid { grid-template-columns:1fr; }
  .cta-panel { padding:28px; }
}
@media (max-width: 560px) {
  .wrap { width:calc(100vw - 28px); max-width:calc(100vw - 28px); overflow:hidden; }
  .header-cta { width:42px; min-height:42px; padding:0; font-size:0; border-radius:8px; }
  .header-cta svg { width:18px; height:18px; }
  .hero h1 { font-size:34px; line-height:1.04; max-width:100%; }
  .hero-copy, .section-lead { font-size:17px; }
  .actions { flex-direction:column; align-items:stretch; }
  .button { width:100%; }
  .section { padding:62px 0; }
  .product-shell { width:100%; }
  .risk-row { grid-template-columns:1fr; }
  .terminal { font-size:12px; padding:17px; white-space:normal; }
  .terminal div { word-break:break-word; }
}
""".strip()


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    output = Path(argv[0] if argv else "site")
    output.mkdir(parents=True, exist_ok=True)
    (output / "assets").mkdir(exist_ok=True)
    (output / "assets" / "auditex.css").write_text(STYLE + "\n", encoding="utf-8")
    (output / ".nojekyll").write_text("", encoding="utf-8")
    (output / "CNAME").write_text(SITE_DOMAIN + "\n", encoding="utf-8")

    pages = []
    for source, title in DOCS:
        path = Path(source)
        if not path.exists():
            continue
        slug = _slug(source)
        body = _markdown_to_html(path.read_text(encoding="utf-8"), path)
        (output / slug).write_text(_page(title, body, canonical_path=slug), encoding="utf-8")
        pages.append((slug, title, _summary(path)))

    (output / "index.html").write_text(_landing_page(pages), encoding="utf-8")
    (output / "robots.txt").write_text("User-agent: *\nAllow: /\nSitemap: https://auditex.hu/sitemap.xml\n", encoding="utf-8")
    (output / "sitemap.xml").write_text(_sitemap([href for href, _, _ in pages]), encoding="utf-8")
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


def _page(title: str, body: str, *, is_index: bool = False, canonical_path: str = "") -> str:
    nav = '<nav class="nav"><a href="index.html#coverage">Coverage</a><a href="index.html#workflow">Workflow</a><a href="setup-guide.html">Setup</a><a href="product-manual.html">Docs</a><a class="header-cta" href="https://github.com/magrathean-uk/auditex">GitHub</a></nav>'
    main = body if is_index else f'<div class="wrap"><main>{body}</main></div>'
    canonical = f"{SITE_URL}{canonical_path}" if canonical_path else SITE_URL
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <meta name="description" content="Auditex is an audit-only Microsoft 365 and Google Workspace evidence collector with proof-backed reports.">
  <link rel="canonical" href="{canonical}">
  <link rel="stylesheet" href="assets/auditex.css">
</head>
<body>
  <header class="site-header"><div class="wrap"><a class="brand" href="index.html">{_logo()}<span>Auditex</span></a>{nav}</div></header>
  {main}
  <footer class="site-footer"><div class="wrap footer-grid"><span>Auditex v1. Audit-only. Evidence local by default.</span><span>Microsoft 365 and Google Workspace.</span></div></footer>
</body>
</html>
"""


def _landing_page(pages: list[tuple[str, str, str]]) -> str:
    doc_cards = "\n".join(
        f'<a class="doc-card" href="{href}"><h3>{html.escape(title)}</h3><p>{html.escape(summary)}</p></a>'
        for href, title, summary in pages[:8]
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Auditex | Audit-only tenant evidence for M365 and Google Workspace</title>
  <meta name="description" content="Auditex collects Microsoft 365 and Google Workspace audit evidence, validates coverage, and creates proof-backed reports without production writes.">
  <link rel="canonical" href="{SITE_URL}">
  <meta property="og:title" content="Auditex">
  <meta property="og:description" content="Audit-only tenant evidence, coverage gates, and proof-backed reports.">
  <meta property="og:url" content="{SITE_URL}">
  <meta property="og:type" content="website">
  <link rel="stylesheet" href="assets/auditex.css">
</head>
<body>
  <header class="site-header">
    <div class="wrap">
      <a class="brand" href="index.html">{_logo()}<span>Auditex</span></a>
      <nav class="nav">
        <a href="#coverage">Coverage</a>
        <a href="#workflow">Workflow</a>
        <a href="#docs">Docs</a>
        <a href="setup-guide.html">Setup</a>
        <a class="header-cta" href="https://github.com/magrathean-uk/auditex">{_icon("arrow")}GitHub</a>
      </nav>
    </div>
  </header>
  <section class="hero">
    <div class="wrap hero-grid">
      <div>
        <h1>Tenant audits with proof, not guesswork.</h1>
        <p class="hero-copy">Auditex collects read-only evidence from Microsoft 365 and Google Workspace, tells you exactly what coverage is missing, and produces board-ready reports every claim can trace back to.</p>
        <div class="actions">
          <a class="button primary" href="setup-guide.html">{_icon("terminal")}Start setup</a>
          <a class="button secondary" href="product-manual.html">{_icon("doc")}Read manual</a>
        </div>
        <div class="trust-row">
          <div><strong>Read-only</strong><span>No tenant writes or response actions.</span></div>
          <div><strong>No content reads</strong><span>No Gmail, Drive, mail, or file bodies.</span></div>
          <div><strong>Proof-backed</strong><span>Every finding links to evidence.</span></div>
        </div>
      </div>
      <div class="product-shell" aria-label="Auditex product preview">
        <div class="terminal-bar"><div class="dots"><i></i><i></i><i></i></div><span>auditex run</span></div>
        <div class="terminal">
          <div><span class="cmd">$</span> auditex setup-guide google --collector-preset everything</div>
          <div class="dim">scopes: directory, reports, alert center, gmail settings, drive metadata</div>
          <div><span class="cmd">$</span> auditex google run --probe-first --out outputs/client</div>
          <div class="ok">quality_gate: partial</div>
          <div class="ok">contract_status: valid</div>
          <div class="dim">missing: calendar ACL scope, mobile inventory API</div>
        </div>
        <div class="report-preview">
          <div class="risk-row"><span class="severity">HIGH</span><strong>Admin 2SV gap</strong><span>evidence: users:17</span></div>
          <div class="risk-row"><span class="severity medium">MED</span><strong>External forwarding</strong><span>evidence: gmail:42</span></div>
          <div class="risk-row"><span class="severity low">INFO</span><strong>Coverage limitation</strong><span>proof table ready</span></div>
        </div>
      </div>
    </div>
  </section>
  <section class="section" id="coverage">
    <div class="wrap split">
      <div>
        <h2>One audit model for both major office clouds.</h2>
        <p class="section-lead">The Microsoft 365 and Google Workspace paths share validation, evidence indexing, reporting, exports, diffing, MCP answers, and customer pack handoff.</p>
      </div>
      <div class="capability-grid">
        <article class="capability">{_icon("shield")}<h3>Identity and privilege</h3><p>Admins, roles, risky grants, MFA posture, group exposure, and stale access.</p></article>
        <article class="capability">{_icon("mail")}<h3>Mail and collaboration</h3><p>Forwarding, delegates, sharing posture, Drive metadata, SharePoint, OneDrive, and Teams.</p></article>
        <article class="capability">{_icon("pulse")}<h3>Signals and alerts</h3><p>Audit logs, sign-ins, reports, Alert Center, Defender or Secure Score where licensing allows.</p></article>
        <article class="capability">{_icon("dns")}<h3>Domain posture</h3><p>SPF, DKIM, DMARC, domain records, and provider-specific DNS expectations.</p></article>
      </div>
    </div>
  </section>
  <section class="section dark" id="workflow">
    <div class="wrap">
      <h2>Built for auditors who need to prove the work.</h2>
      <p class="section-lead">A run is useful only when it says what was checked, what was blocked, and why the report can be trusted.</p>
      <div class="proof-stack">
        <div class="proof-row"><strong>Quality gate</strong><span>complete, partial, or unusable with exact missing data reason.</span></div>
        <div class="proof-row"><strong>Evidence links</strong><span>finding rows point back to bundle artifacts and evidence database records.</span></div>
        <div class="proof-row"><strong>Client pack</strong><span>executive summary, technical appendix, limitations, proof table, and next actions.</span></div>
      </div>
      <div class="workflow">
        <article><span>01</span><h3>Plan</h3><p>Choose provider, auth mode, collector preset, and required scopes.</p></article>
        <article><span>02</span><h3>Probe</h3><p>Verify APIs, permissions, licenses, and local tooling before a live run.</p></article>
        <article><span>03</span><h3>Collect</h3><p>Gather read-only metadata and posture evidence without content reads.</p></article>
        <article><span>04</span><h3>Report</h3><p>Deliver findings with confidence, impact, remediation, and proof.</p></article>
      </div>
    </div>
  </section>
  <section class="section" id="docs">
    <div class="wrap">
      <h2>Operator docs stay close to the product.</h2>
      <p class="section-lead">Setup, permission requests, customer handoff, output contract, and release gates publish with the same build.</p>
      <div class="docs-band">{doc_cards}</div>
    </div>
  </section>
  <section class="section">
    <div class="wrap cta-panel">
      <div>
        <h2>Run the audit. Keep the proof.</h2>
        <p class="section-lead">Start with setup-guide, then probe, run, validate, and hand off only verified customer-safe output.</p>
      </div>
      <a class="button primary" href="setup-guide.html">{_icon("arrow")}Open setup guide</a>
    </div>
  </section>
  <footer class="site-footer"><div class="wrap footer-grid"><span>Auditex v1. Audit-only. Evidence local by default.</span><span>auditex.hu</span></div></footer>
</body>
</html>
"""


def _logo() -> str:
    return """<span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M12 3.2 19 6.7v5.5c0 4.3-2.8 7.3-7 8.6-4.2-1.3-7-4.3-7-8.6V6.7l7-3.5Z" stroke="currentColor" stroke-width="1.8"/><path d="M8 12.2h8M12 8.2v8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></span>"""


def _icon(name: str) -> str:
    icons = {
        "arrow": '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        "terminal": '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m7 8 4 4-4 4m6 0h4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><rect x="3" y="4" width="18" height="16" rx="3" stroke="currentColor" stroke-width="2"/></svg>',
        "doc": '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M7 3h7l4 4v14H7V3Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M14 3v5h5M9 13h6M9 17h6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
        "shield": '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3 19 6.2v5.6c0 4.4-2.8 7.5-7 9.2-4.2-1.7-7-4.8-7-9.2V6.2L12 3Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>',
        "mail": '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2.5" stroke="currentColor" stroke-width="2"/><path d="m4 7 8 6 8-6" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>',
        "pulse": '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 13h4l2-6 4 11 2-5h4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        "dns": '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="2"/><path d="M4 12h16M12 3.5c2.2 2.5 3.2 5.3 3.2 8.5s-1 6-3.2 8.5C9.8 18 8.8 15.2 8.8 12s1-6 3.2-8.5Z" stroke="currentColor" stroke-width="2"/></svg>',
    }
    return icons[name]


def _sitemap(hrefs: list[str]) -> str:
    today = datetime.now(timezone.utc).date().isoformat()
    urls = [""] + hrefs
    entries = "\n".join(
        f"  <url><loc>{SITE_URL}{html.escape(href)}</loc><lastmod>{today}</lastmod></url>" for href in urls
    )
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n{entries}\n</urlset>\n'


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
