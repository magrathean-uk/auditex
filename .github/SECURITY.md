# Security Policy

## Auditex scope

Auditex is an authorized Microsoft 365 and Google Workspace audit toolkit. Its
public audit plane covers audit, probe, report, export, MCP audit tools, and
customer-pack creation and verification. Those operations must not write to a
production tenant or read Gmail or Exchange message bodies, or Drive,
SharePoint, or OneDrive file content.

Treat a violation of that boundary, exposure of tenant evidence or credentials,
or a defect that changes the trustworthiness of audit evidence as a security
issue. The generated `data-handling.json` and `api-inventory.json` records are
the run-specific evidence for read-only, no-content-read, and API-call claims.
They are checks, not a substitute for reviewing an actual tenant authorization
or deployment.

## Supported versions

| Version | Security fixes |
| --- | --- |
| 1.1.x | Yes |
| Earlier than 1.1.0 | No; upgrade to the latest 1.1.x release |

Only the latest minor release is supported.

## Private Reporting

Email [contact+auditex@magrathean.uk](mailto:contact+auditex@magrathean.uk) with subject `SECURITY: Auditex`, or use **Report a vulnerability** on the repository's Security tab (GitHub private vulnerability reporting is enabled). Do not open a public issue, discussion or pull request for a suspected vulnerability.

Do not publish credentials, private keys, database dumps, signing certificates, or exploit details.

Include affected version/commit, platform, topology, reproduction steps, impact, and redacted evidence.

## Handling and disclosure

- We aim to acknowledge a report within 5 working days and to agree next steps after triage.
- We aim to release a fix, or to agree a revised date with the reporter, within 90 days of the report. Please keep details private until a fix is released or that date has passed.
- When a fix is released we publish a GitHub security advisory, request a CVE where the issue warrants one, and credit the reporter unless asked not to.
- These are targets, not guarantees. No fixed response or remediation time is promised unless a separate written agreement says so.

## Scope & Safe Harbour

Magrathean will not pursue a good-faith researcher for security disclosures that:
- Target non-production test systems or researcher-owned environments;
- Avoid persistence, destructive changes, denial of service, and access to personal or customer data;
- Report promptly and permit reasonable time for remediation;
- Do not condition non-disclosure on financial compensation.

## Excluded Conduct

No safe harbour covers phishing, credential stuffing, accessing private production infrastructure, large-scale scanning, denial of service, or unlawful conduct.

## Assessment context

Auditex runs locally and retains raw evidence in the selected output directory.
Metadata and settings can still contain personal data. Findings about raw
evidence exposure, secret handling, external telemetry, report or pack
integrity, authorization checks, unexpected mutating calls, or unexpected
content reads are material when reachable in the supported product paths.

The lab-only response plane and tenant-bootstrap helpers are outside the public
audit-only scope. Their presence does not weaken a finding that makes the
public audit plane mutate a production tenant.
