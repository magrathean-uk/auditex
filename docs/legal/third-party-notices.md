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

The licences recorded are those stated in PyPI metadata for the minimum declared
versions: `requests` 2.34.2, `msal` 1.39.0, `mcp` 1.30.0, `google-auth` 2.58.1,
`google-auth-oauthlib` 1.4.1 and `google-api-python-client` 2.200.0. Check the exact
versions actually distributed.

## Research references

Projects consulted only for ideas are recorded, with their licences and our review, in
[docs/provenance](../provenance/provenance.md). No code, templates or text from them is kept
in the product.

