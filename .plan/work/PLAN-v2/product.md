# Auditex - product framing for plan v2

Orchestrator summary from AGENTS.md and G's recorded decisions, not G's own words.

Auditex is a read-only Microsoft 365 and Google Workspace tenant-audit toolkit from Magrathean
(public repo magrathean-uk/auditex, product page https://magrathean.uk/solutions/auditex/). It ships
a Python CLI (`auditex`, `azure-tenant-audit`) and a local MCP server (`auditex-mcp`) that collect
evidence, normalise it, answer the CISA SCuBA baselines with deterministic value rules, and write a
validated run bundle plus reports, exports and customer packs.

Target user (inferred, G confirms at the gate): IT administrators and consultants auditing their own
or a customer's tenant who need defensible, reproducible evidence without granting write access.

Non-negotiables (AGENTS.md Boundaries): never writes to a tenant, never reads message bodies or file
content, response features lab-only behind `AUDITEX_ENABLE_RESPONSE`, no telemetry, no credentials,
live evidence or workstation paths in git.

Release state: v1.2.4 is the latest tag. The next release is 1.3.0.

Proposed scope of 100 percent (G approves at the gate): the 1.3.0 release. Work beyond it goes to
BACKLOG next or later. G's standing decisions are in answers.md next to this file.
