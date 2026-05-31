# Third-Party Notices

This file records third-party components that remain in or are declared by this repository.

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

## External research references not retained as code/text

The following projects remain only as provenance references or idea-level prior art in `docs/provenance/provenance.csv`. No source code, templates, report text, or copied documentation from these projects is intentionally retained in the product source tree.

| Upstream | License posture | Current product action |
| --- | --- | --- |
| `ThomasKur/M365Documentation` | GPLv3+ | High-risk surfaces rewritten; competitor mirroring removed. |
| `System-Admins/m365assessment` | No visible license in reviewed local mirror / package metadata | High-risk surfaces rewritten; competitor mirroring removed. |
| `cisagov/ScubaGear` | CC0-1.0 | Idea-level influence only; no copied code/text retained. |
| `maester365/maester` | MIT | Idea-level influence only; no copied code/text retained. |
| `microsoft/EntraExporter` | MIT | Idea-level influence only; no copied code/text retained. |
| `dirkjanm/ROADtools` | MIT | Idea-level influence only; no copied code/text retained. |
| `CompliantSec/M365SAT` | MIT | Idea-level influence only; no copied code/text retained. |
