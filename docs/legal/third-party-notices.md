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

## Declared Python dependencies

These dependencies are declared in `pyproject.toml` / `requirements.txt`. They are not vendored in this source package.

| Package | Declared use | License recorded | Notice handling |
| --- | --- | --- | --- |
| `requests` | HTTP transport for Microsoft Graph and related endpoints | Apache-2.0 | Keep license notice when redistributing the package or bundled wheels. |
| `msal` | Microsoft identity token acquisition | MIT | Keep copyright and MIT notice when redistributing the package or bundled wheels. |
| `mcp` | Optional MCP server integration | MIT | Keep copyright and MIT notice when redistributing the optional dependency or bundled wheels. |

The optional `google` dependency group in `pyproject.toml` (`google-auth`,
`google-auth-oauthlib`, `google-api-python-client`) is not yet listed in the table above.
Their licence must be confirmed from the installed package metadata before distribution;
this page does not infer it.

## Research references

Projects consulted only for ideas are recorded, with their licences and our review, in
[docs/provenance](../provenance/provenance.md). No code, templates or text from them is kept
in the product.

