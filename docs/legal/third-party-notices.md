# Third-party notices

The required attribution for the vendored Microsoft Skills material is in
[NOTICE](../../NOTICE). This page records the fuller inventory: every third-party
component that remains in or is declared by this repository.

## Vendored component

### Microsoft Skills

- Location: `tenant-bootstrap/vendor/microsoft-skills/`
- Upstream: `microsoft/skills`
- License: MIT
- Status: curated vendored subset retained
- Notice: the upstream MIT license is copied at `tenant-bootstrap/vendor/microsoft-skills/LICENSE`.
- Retained scope: 11 selected `SKILL.md` files plus required reference files, catalog, and manifest. The full upstream repository is not included in this package.
- Modifications: MAGRATHEAN UK LTD modified one retained file. `skills/mcp-builder/scripts/requirements.txt` raises the declared minimum versions to `anthropic>=1.8.0,<2` and `mcp>=1.30.0,<2` (upstream: `anthropic>=0.39.0`, `mcp>=1.1.0`) and carries a comment marking the change. Every other retained skill file matches upstream commit `33b598366fd91350f032be9b385389ff14876dcc`.

## Bundled run-explorer assets

These ship inside the Python package under `src/auditex/explorer_assets/` and are embedded
in every page that `auditex report explorer` writes.

### Lucide icons

- Location: SVG path data in `src/auditex/explorer_assets/explorer.js` (23 icons, some simplified)
- Upstream: `lucide-icons/lucide`
- License: ISC; icons derived from Feather are MIT (Copyright (c) 2013-present Cole Bemis)
- Notice: the upstream licence is copied at `src/auditex/explorer_assets/LICENSE-lucide.txt`,
  and the ISC and MIT notices are reproduced in the script header, so every generated page
  carries them.

### Barlow and Barlow Condensed fonts

- Location: `src/auditex/explorer_assets/fonts/` (WOFF2 latin and latin-ext subsets:
  Barlow 400 and 600, Barlow Condensed 600), embedded in generated pages as data URIs
- Upstream: Google Fonts (`google/fonts`, `ofl/barlow`), by The Barlow Project Authors
- License: SIL Open Font License 1.1
- Notice: the licence is copied at `src/auditex/explorer_assets/fonts/OFL.txt`. The font
  files are unmodified and keep their reserved name.

## Vendored test fixtures

These are used only by the test suite and live under `tests/schemas/`. They are in the public
repository but not in the wheel. They are kept byte for byte as published, so the exports are
validated against the official text. `tests/schemas/README.md` records the source URL, retrieval date
and SHA-256 of each file.

### OSCAL Assessment Results JSON Schema

- Location: `tests/schemas/oscal_assessment-results_schema-1.1.2.json` (renamed to carry the version)
- Upstream: NIST OSCAL 1.1.2 release, `oscal_assessment-results_schema.json`
- License: public domain as a work of the United States government, dedicated worldwide under CC0 1.0 Universal
- Notice: NIST asks to be acknowledged as the source; the licence is copied at `tests/schemas/LICENSE-OSCAL.md`. The file is in the public repository but not in the wheel.

### SARIF 2.1.0 JSON Schema

- Location: `tests/schemas/sarif-schema-2.1.0.json`
- Upstream: OASIS SARIF Technical Committee, SARIF Version 2.1.0 Errata 01
- License: governed by the OASIS Intellectual Property Rights Policy (RF on RAND Terms mode); the file carries no licence text of its own
- Notice: the OASIS copyright notice and Notices section that must accompany copies are reproduced word for word at `tests/schemas/LICENSE-SARIF.md`. The file is used unmodified as a test fixture, in the public repository but not in the wheel.

## Declared Python dependencies

These dependencies are declared in `pyproject.toml` / `requirements.txt`. They are not vendored in this source package.

| Package | Declared use | License recorded | Notice handling |
| --- | --- | --- | --- |
| `requests` | HTTP transport for Microsoft Graph and related endpoints | Apache-2.0 | Keep license notice when redistributing the package or bundled wheels. |
| `msal` | Microsoft identity token acquisition | MIT | Keep copyright and MIT notice when redistributing the package or bundled wheels. |
| `mcp` | Optional MCP server integration | MIT | Keep copyright and MIT notice when redistributing the optional dependency or bundled wheels. |
| `google-auth` | Optional `google` group: Google Workspace authentication | Apache-2.0 | Keep license notice when redistributing the optional dependency or bundled wheels. |
| `google-auth-oauthlib` | Optional `google` group: OAuth flow for Google Workspace | Apache-2.0 | Keep license notice when redistributing the optional dependency or bundled wheels. |
| `google-api-python-client` | Optional `google` group: Google Workspace API client | Apache-2.0 | Keep license notice when redistributing the optional dependency or bundled wheels. |
| `jsonschema` | Optional `test` group: validates the SARIF and OSCAL exports against the official schemas in tests | MIT | Development and test use only; not needed to run Auditex. |

The licences recorded are those stated in PyPI metadata for the minimum declared
versions: `requests` 2.34.2, `msal` 1.39.0, `mcp` 1.30.0, `google-auth` 2.58.1,
`google-auth-oauthlib` 1.4.1 and `google-api-python-client` 2.200.0. Check the exact
versions actually distributed.

## Research references

Projects consulted only for ideas are recorded, with their licences and our review, in
[docs/provenance](../provenance/provenance.md). No code, templates or text from them is kept
in the product.

