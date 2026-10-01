# Next release: use the magrathean.uk/solutions URLs

Release trigger (1 October 2026). Before or as part of the **next release** of
anything built from this repository, replace the former product-site URLs and
support addresses below. The former domains currently 301 to the new pages, but
those redirects end when the domains lapse (most expire in May 2027). Delete
this file once every reference is updated and released.

| Former | Current |
| --- | --- |
| `https://auditex.hu/<path>` | `https://magrathean.uk/solutions/auditex/<path>` |
| `https://codexex.eu/<path>` | `https://magrathean.uk/solutions/codexex/<path>` |
| `https://nodexapp.eu/<path>` | `https://magrathean.uk/solutions/nodex/<path>` |
| `https://termexapp.eu/<path>` | `https://magrathean.uk/solutions/termex/<path>` |
| `https://teslacam.eu/<path>` | `https://magrathean.uk/solutions/tescam/<path>` |
| `https://teslatlas.eu/<path>` | `https://magrathean.uk/solutions/teslatlas/<path>` (old `/privacy/` and `/terms/` → `/app/privacy/`, `/app/terms/`; donate → `https://magrathean.uk/donate/?product=teslatlas`) |
| `https://magrathean.uk/apps/<slug>/` | `https://magrathean.uk/solutions/<slug>/` |
| Product support e-mail | `contact+<slug>@magrathean.uk` (`auditex`, `codexex`, `nodex`, `termex`, `tescam`, `teslatlas`); `contact+teslacam@` becomes `contact+tescam@` |

Also update the App Store Connect marketing, support and privacy URLs for each
app. Historical records (release-key files, changelogs, archived plans) may keep
their original URLs when the value is part of the record.

## References found in this repository

- `.venv/lib/python3.14/site-packages/auditex-1.0.0.dist-info/METADATA:28` — `<a href="https://auditex.hu">Website</a> ·`
- `.venv/lib/python3.14/site-packages/auditex-1.0.0.dist-info/METADATA:30` — `<a href="https://auditex.hu/privacy/">Privacy</a>`
- `README.md:10` — `<a href="https://auditex.hu">Website</a> ·`
- `README.md:12` — `<a href="https://auditex.hu/privacy/">Privacy</a>`
- `scripts/build-pages-site.py:9` — `SITE_DOMAIN = "auditex.hu"`
- `src/auditex.egg-info/PKG-INFO:28` — `<a href="https://auditex.hu">Website</a> ·`
- `src/auditex.egg-info/PKG-INFO:30` — `<a href="https://auditex.hu/privacy/">Privacy</a>`
