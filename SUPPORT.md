# Getting help

Start with the [setup guide](docs/SETUP_GUIDE.md), [troubleshooting guide](docs/TROUBLESHOOTING.md), and [runbook](RUNBOOK.md). Use `auditex doctor --json` for local readiness and the provider's probe command for live capability blockers.

For a reproducible product bug or setup question, use the repository's [issue tracker](https://github.com/magrathean-uk/auditex/issues). Include:

- Auditex version, Python version, and operating system.
- Provider, collector preset, and a sanitized command with all credentials removed.
- Expected and actual behavior, blocker classes, and a minimal synthetic reproduction if available.
- Checks already attempted and their results.

Review diagnostics before posting. Remove tenant names, domains, user identifiers, local paths, tokens, auth files, raw evidence, and customer reports. A public issue is not an evidence transfer channel.

For suspected vulnerabilities or credential exposure, follow [SECURITY.md](SECURITY.md). Do not include exploit details or confidential material in a public support issue. No response time or supported-release commitment is stated here.
