# Security Policy

Magrathean UK Ltd. takes the security of Auditex seriously. Thank you for helping keep Auditex and its operators safe.

For the product security and privacy model, including read-only guarantees, no-content-read rules, local evidence handling, and customer-pack integrity, see [docs/SECURITY_PRIVACY.md](docs/SECURITY_PRIVACY.md).

## Reporting a vulnerability

If you discover a security issue in Auditex, please **do not** open a public issue or pull request. Report it privately by email instead:

- Email: contact@magrathean.uk
- Subject: `[SECURITY] Auditex: <short description>`

Where possible, please include:

1. The version, release, or commit SHA you are reporting against.
2. A clear description of the issue and its potential impact (token leakage, scope-of-access bypass, evidence tampering, command injection, privilege escalation, etc.).
3. Reproduction steps, proof-of-concept, or test code where possible.
4. Any suggested mitigation.

## Our commitments

When you report a vulnerability in good faith, we commit to:

- Acknowledging receipt within five (5) UK working days.
- Triaging the report and providing an initial assessment within fourteen (14) days.
- Keeping you informed of remediation progress for material issues.
- Coordinated disclosure: we will agree a public-disclosure timeline with you, normally not less than ninety (90) days from acknowledgement, with a faster lane for issues affecting authentication, token handling, scope reduction, evidence integrity, or response-action gating.

## Scope

In scope:

- Source code in this repository.
- Distribution artefacts published by Magrathean UK Ltd. for Auditex.

Out of scope:

- Microsoft Graph, Entra ID, Microsoft 365 services, or any other Microsoft platform — please report those directly to Microsoft via the Microsoft Security Response Center (MSRC).
- Third-party Python packages — please report those to their respective maintainers.
- Issues caused by user-side configuration that does not match the documented setup.
- Any tenant or environment operated by a third party — that operator is responsible for its own security testing and reports.
- Best-practice or hardening recommendations that do not constitute exploitable vulnerabilities.

## Safe harbour

We will not pursue civil or criminal action against good-faith security researchers who:

- Stay within the scope above and test only against your own lab tenant or local environment.
- Make a reasonable effort to avoid privacy violations, destruction of data, and disruption of any service.
- Report findings privately to us before any public disclosure.
- Do not exploit a vulnerability beyond the minimum necessary to demonstrate the issue.
- Comply with all applicable law (including the UK Computer Misuse Act 1990 and equivalents).

This safe-harbour statement is offered as a matter of policy and does not waive the rights or remedies of any third party. **It does not authorise testing against any Microsoft 365 tenant or Google Workspace domain that you do not own or do not have explicit owner authorisation to test.**

## Contact

Magrathean UK Ltd.
16 Caledonian Court West Street, Watford, England, WD17 1RY
contact@magrathean.uk
