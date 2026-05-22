# Changelog

## v1 Enterprise Audit Release

Auditex v1 is the first enterprise-ready audit-only release.

### Added

- Google Workspace audit path with doctor, probe, run, offline fixture, collectors, normalization, findings, and reporting.
- Human-level audit autopilot artifacts: audit plan, quality gates, proof table, API inventory, data-handling assertions, report QA, and customer handoff packs.
- Setup-guide CLI and MCP output for Google Workspace and Microsoft 365 scopes, roles, setup steps, and verification commands.
- GitHub issue and pull request templates for safe audit setup and product review.
- GitHub Pages workflow for static product documentation.
- Release workflow that builds packages and creates a GitHub release from tags.
- Enterprise documentation: product manual, setup guide, permission guide, AI guide, GitHub guide, security/privacy, ship readiness, troubleshooting, API catalog, and customer handoff guide.

### Changed

- Report output now treats coverage gaps as explicit limitations instead of silent omissions.
- Bundle validation checks optional assurance artifacts when present.
- MCP reporting surfaces expose the same proof-backed evidence views as CLI.

### Safety

- Default audit mode is read-only.
- No Gmail body reads.
- No Drive, SharePoint, or OneDrive file-content reads.
- No production response actions in public audit mode.
- Write-capable provider scopes are recorded as scope risk and verified against observed read-only API calls.
