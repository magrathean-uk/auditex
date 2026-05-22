#!/usr/bin/env python3
from __future__ import annotations

import sys
import shutil
from pathlib import Path


SITE_DOMAIN = "auditex.hu"
SITE_URL = f"https://{SITE_DOMAIN}/"


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    output = Path(argv[0] if argv else "site")
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / ".nojekyll").write_text("", encoding="utf-8")
    (output / "CNAME").write_text(f"{SITE_DOMAIN}\n", encoding="utf-8")
    (output / "index.html").write_text(_redirect_page(), encoding="utf-8")
    (output / "404.html").write_text(_redirect_page(), encoding="utf-8")
    (output / "robots.txt").write_text("User-agent: *\nDisallow: /\n", encoding="utf-8")
    return 0


def _redirect_page() -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, follow">
  <meta http-equiv="refresh" content="0; url={SITE_URL}">
  <link rel="canonical" href="{SITE_URL}">
  <title>Auditex</title>
  <script>window.location.replace("{SITE_URL}");</script>
</head>
<body>
  <p>Auditex has moved to <a href="{SITE_URL}">{SITE_DOMAIN}</a>.</p>
</body>
</html>
"""


if __name__ == "__main__":
    raise SystemExit(main())
