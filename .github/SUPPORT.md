# Getting help

Start with the [setup guide](../docs/guides/setup-guide.md), [troubleshooting guide](../docs/guides/troubleshooting.md), and [runbook](../docs/development/runbook.md). Use `auditex doctor --json` for local readiness and the provider's probe command for live capability blockers.

Product information is at [magrathean.uk](https://magrathean.uk/solutions/auditex/). For a reproducible product bug or setup question, use the repository's [issue tracker](https://github.com/magrathean-uk/auditex/issues). For a question that needs a private channel, email [contact+auditex@magrathean.uk](mailto:contact+auditex@magrathean.uk). Include:

- Auditex version, Python version, and operating system.
- Provider, collector preset, and a sanitized command with all credentials removed.
- Expected and actual behavior, blocker classes, and a minimal synthetic reproduction if available.
- Checks already attempted and their results.

Review diagnostics before posting or sending. Remove tenant names, domains, user identifiers, local paths, tokens, auth files, raw evidence, and customer reports. Neither a public issue nor the support address is an evidence transfer channel.

For suspected vulnerabilities or credential exposure, follow [SECURITY.md](SECURITY.md). Do not include exploit details or confidential material in a public support issue. Support is best effort with no response-time commitment; security fixes follow the supported versions listed in SECURITY.md.
