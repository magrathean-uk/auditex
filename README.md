<p align="center">
  <img src="https://raw.githubusercontent.com/magrathean-uk/auditex/main/assets/auditex-logo.svg" width="132" height="132" alt="">
</p>

<h1 align="center">Auditex</h1>

<p align="center">A read-only Microsoft 365 and Google Workspace tenant-audit toolkit, for auditors and admins.</p>

<p align="center">
  <a href="https://magrathean.uk/solutions/auditex/">Website</a> ·
  <a href="https://github.com/magrathean-uk/auditex/blob/main/docs/index.md">Documentation</a> ·
  <a href="https://magrathean.uk/solutions/auditex/privacy/">Privacy</a>
</p>

## Overview

Auditex is a Python CLI and MCP toolkit for read-only Microsoft 365 and Google Workspace tenant audits. It collects local evidence, normalizes results, and produces report, export, comparison, and customer handoff artifacts.

The public audit surface does not write to production tenants. It also does not read message bodies or file contents in audit mode. The separate `tenant-bootstrap/` kit is for lab setup and rehearsal; treat it as a writable lab tool with its own credentials, outputs, and safeguards, kept out of audit, report, export, and MCP flows. `AGENTS.md` has the rules.

## What is included

- Microsoft 365 collection through the `auditex` and `azure-tenant-audit` CLIs.
- Google Workspace collection through the optional `google` dependencies.
- Guided setup and audit flows, capability probes, and diagnostics. Microsoft 365 is audited one way: as a reader app that signs in with a certificate.
- Offline fixtures for contract checks and demonstrations.
- Report rendering, CSV/JSON and other exporters, comparison and drift gates, customer handoff packs, and a local MCP server.
- Offline imports and control-by-control review of Maester, ScubaGear and Monkey365 JSON assessments, with source hashes and strict tenant identity checks.
- Read-only privilege graph: potential routes from users, groups and applications to tier-0 control, with evidence per hop, explicit unverified prerequisites and candidate breakpoints.
- Detection coverage ("could this tenant see an attack?") and the tenant's public footprint, including MTA-STS and TLS-RPT.
- Mapping of findings to CIS Microsoft 365 Foundations v7, CISA SCuBA, Microsoft Secure Score, Zero Trust, the Microsoft cloud security benchmark, and the NCSC Cyber Essentials requirements (v3.3). A mapping shows which control a finding relates to; it is not an assessment against that framework. For Cyber Essentials, device-side requirements show as manual or assessor-tested, the ones Intune and Exchange Online evidence in part (updates, anti-malware) show as partial, and tenant-backed ones never read pass. See [framework mappings](https://github.com/magrathean-uk/auditex/blob/main/docs/reference/framework-mappings.md).
- `auditex demo`, a guided walkthrough on a fictional company, and `auditex report explorer`, a self-contained interactive HTML view of any run.

The package needs Python 3.11, 3.12, 3.13 or 3.14. Its required runtime dependencies are `requests`, `msal` and `cryptography`. Google Workspace, MCP support and the local answer are optional extras.

## Evidence, not a certificate

An Auditex report is evidence from an automated, read-only run. It is not a certificate, an assurance opinion, a penetration test or legal advice, and it does not show that a tenant is secure or that it meets Cyber Essentials, a CIS Benchmark, the CISA SCuBA baselines or any other standard. It covers only what the run could read with the access it was given; the coverage gaps are recorded in the report and are part of the result. A person still makes the judgement.

Run Auditex only against a tenant you own or have the owner's written authorisation to audit. A run folder holds personal data about the tenant's users (names, addresses, sign-in records and similar); whoever runs the audit is responsible for handling it lawfully. See [the security and privacy model](https://github.com/magrathean-uk/auditex/blob/main/docs/reference/security-privacy.md).

## Install

Auditex runs on Linux, macOS and Windows through WSL2, with Python 3.11, 3.12, 3.13 or 3.14. Native Windows is not supported;
use WSL2. Install it from PyPI with [pipx](https://pipx.pypa.io/):

```bash
pipx install auditex
auditex --version
auditex doctor
```

`auditex doctor` ends with `Core ready: yes` on a working install. Optional extras add Google Workspace audits
(`google`), the local MCP server (`mcp`) and the local model summary (`local-answer`):

```bash
pipx install --force "auditex[google,mcp]"
```

`--force` reinstalls over the base install; list every extra you want to keep, because pipx installs exactly the
extras named on its last install. On a computer without Auditex yet, `pipx install "auditex[google,mcp]"` installs
it with the extras in one step.

Upgrade with `pipx upgrade auditex`. The [install guide](https://github.com/magrathean-uk/auditex/blob/main/docs/guides/install-guide.md) walks through every step on
each system, from installing Python and pipx to a first offline run, upgrading, uninstalling and troubleshooting.

## Install from source (contributors)

To change Auditex or run its checks, install from a source checkout:

```bash
git clone https://github.com/magrathean-uk/auditex.git
cd auditex
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
auditex doctor --json
```

Run the repository commands below from inside the `auditex` folder. The activation line is for Linux and macOS.

Optional dependencies:

```bash
python -m pip install -e '.[google]'
python -m pip install -e '.[mcp]'
```

Useful repository checks are:

```bash
make lint
make test
make contract-smoke
./scripts/oss-taint-scan.sh
```

`make contract-smoke` runs an offline sample and checks the finalized bundle contract. See [the runbook](https://github.com/magrathean-uk/auditex/blob/main/docs/development/runbook.md) for the complete local and release check matrix.

## Main commands

Try the whole flow on a fictional company without touching any tenant:

```bash
auditex demo
```

`auditex demo` replays a synthetic tenant offline, then walks through access planning, findings, evidence, attack paths, and a checksum-verified customer pack, and writes an interactive HTML explorer. Use `--no-pause` for an unattended run.

Generate a provider-specific permission and scope plan before requesting access:

```bash
auditex setup-guide m365 --collector-preset full --format md
auditex setup-guide google --collector-preset everything --format md
```

Guided operator flow:

```bash
auditex guided-run
auditex guided-run --flow app-audit
```

The guided flow audits as the reader app and creates nothing in the tenant. The tenant administrator sets the app up once; every permission and setting is in [Reader app permissions](https://github.com/magrathean-uk/auditex/blob/main/docs/guides/reader-app-permissions.md).

Offline runs contact no tenant and need no credentials:

```bash
auditex run --offline --tenant-name demo --out outputs/offline
```

The run writes its own folder inside `--out`, named with the tenant and a timestamp (for example
`outputs/offline/demo-run_20261121_225532`). That folder is the `<run-dir>` the commands below take.

```bash
auditex google run --offline --sample examples/google_workspace_sample.json \
  --domain example.com --tenant-name demo --out outputs/google
```

For an authorized live Microsoft 365 audit, use the reader app with its certificate. The key file must be readable only by you; an encrypted key takes `--certificate-password-file` or `--certificate-password-env`, never the password itself:

```bash
auditex run --tenant-name CONTOSO --tenant-id contoso.onmicrosoft.com \
  --client-id <app-id> --certificate-path ~/audit-keys/auditex-reader.pem \
  --certificate-thumbprint <sha1-thumbprint> \
  --auditor-profile global-reader --out outputs/live
```

Use `auditex probe live` after permission changes to identify capability blockers before a full run, and follow the generated setup guide.

Google Workspace supports domain-wide delegation and OAuth. The full Google path requires the optional dependencies and provider credentials kept outside the repository:

```bash
auditex google doctor --json
auditex google probe --auth domain-delegation --domain example.com \
  --service-account-key /path/to/service-account.json --subject admin@example.com
```

## Read a run and prepare a handoff

External Microsoft assessment reports can also be reviewed locally with
`auditex assessment import` and `auditex assessment compare`. See
[external assessment comparison](https://github.com/magrathean-uk/auditex/blob/main/docs/guides/external-assessments.md) for
supported formats, evidence references and comparison limits.

Each finalized run contains a manifest, summary, report pack, evidence index, AI context, and validation result. The current contract version is recorded in `run-manifest.json`; required files and evidence rules are documented in [the output contract](https://github.com/magrathean-uk/auditex/blob/main/docs/reference/output-contract.md).

For an optional rule-only SCuBA assessment, `auditex assess <run-dir>` has
value rules for all 102 catalogue policies across Entra ID, Exchange Online, Power BI, Power Platform, Defender,
SharePoint and Teams. Rule availability does not guarantee a verdict: available evidence, the adapter and
permissions determine whether a policy can be assessed. A policy without a rule reports not assessed
(`rule_not_implemented`): "Not assessed: Auditex has no rule for this policy yet."
Assessment runs locally from the run bundle; no endpoint or model name is involved.
Assessments can attach deterministic template explanations to supported rule results. JSON, Markdown and HTML reports show them when present; findings are unchanged.
Each policy's status is in the run's `model_assessment.json`; see [AI assessment](https://github.com/magrathean-uk/auditex/blob/main/docs/guides/ai-assessment.md#run-and-read-the-result) for coverage and output.

For an optional plain-language answer, `auditex explain <run-dir>` (or `auditex run ... --explain`) has a local model say
what is wrong in the tenant, the most severe first, and what is right. The value rules still decide every verdict and the
order; the model only selects prepared sentences, Auditex renders every word, and a selection that fails the checks shows
fixed text. It needs the optional `local-answer` extra and downloads one pinned model file from Hugging Face on first
use, under that model's own licence, then runs offline: nothing about the run or the tenant is sent anywhere. See
[the local answer guide](https://github.com/magrathean-uk/auditex/blob/main/docs/guides/local-answer.md).

```bash
auditex report render <run-dir> --format md
auditex report api-calls <run-dir> --format md
auditex report permissions <run-dir> --format md
auditex report proof-table <run-dir> --format md
auditex report ce-plus <run-dir> --format md
auditex report customer-pack <run-dir> --output-dir customer-pack
auditex report verify-pack customer-pack
auditex report explorer <run-dir>
auditex report explorer <run-dir> --compare <previous-run-dir>
auditex compare --run-dir run-a --run-dir run-b
auditex export list
```

Start customer review with the handoff output, then inspect the API and permission ledgers, proof table, `data-handling.json`, and `validation.json`. Partial runs should be explained with their blocker and readiness artifacts rather than presented as complete coverage.

## MCP

Run the local MCP server after installing the `mcp` extra:

```bash
auditex-mcp
```

The MCP registry exposes inventory and contract inspection, offline validation, Microsoft 365 and Google Workspace audit/probe operations, run summaries and comparisons, reports and proof tables, customer-pack verification, exports, notifications, rules, and setup guides. Audit operations retain the same read-only and no-content-read boundary as the CLI. No MCP tool takes a bearer token, client secret or auth context; the Microsoft 365 tools take the reader app's client ID, certificate thumbprint and confined paths to its key and password file. Every path argument is confined to `AUDITEX_MCP_ROOT` (default: the server's working directory).

## Documentation

Use [docs/index.md](https://github.com/magrathean-uk/auditex/blob/main/docs/index.md) as the documentation index.

- [The install guide](https://github.com/magrathean-uk/auditex/blob/main/docs/guides/install-guide.md) installs Auditex from PyPI with pipx, step by step.

- [The runbook](https://github.com/magrathean-uk/auditex/blob/main/docs/development/runbook.md) covers setup, operator flows, local checks, and the separate lab bootstrap kit.
- [The product manual](https://github.com/magrathean-uk/auditex/blob/main/docs/guides/product-manual.md) explains the product workflows.
- [The setup guide](https://github.com/magrathean-uk/auditex/blob/main/docs/guides/setup-guide.md) and [the administrator permission guide](https://github.com/magrathean-uk/auditex/blob/main/docs/guides/admin-permission-guide.md) cover access planning.
- [The security and privacy model](https://github.com/magrathean-uk/auditex/blob/main/docs/reference/security-privacy.md) describes data handling and audit boundaries.
- [The customer handoff guide](https://github.com/magrathean-uk/auditex/blob/main/docs/guides/customer-handoff-guide.md) covers review packs.
- [The troubleshooting guide](https://github.com/magrathean-uk/auditex/blob/main/docs/guides/troubleshooting.md) covers common failures.
- [AGENTS.md](https://github.com/magrathean-uk/auditex/blob/main/AGENTS.md) contains repository-specific development rules.
- [.github/CONTRIBUTING.md](https://github.com/magrathean-uk/auditex/blob/main/.github/CONTRIBUTING.md) covers development setup and review expectations.
- [.github/SUPPORT.md](https://github.com/magrathean-uk/auditex/blob/main/.github/SUPPORT.md) explains how to request help and report product issues.

Keep `.venv/`, `.secrets/`, tenant evidence, and generated output directories local. Never commit tokens, OAuth caches, service-account keys, or tenant evidence. Do not add external telemetry.

## Licence

Auditex is open source under the Apache License 2.0, which provides it "as is", without warranties. See [LICENSE](https://github.com/magrathean-uk/auditex/blob/main/LICENSE) and
[NOTICE](https://github.com/magrathean-uk/auditex/blob/main/NOTICE); the fuller dependency inventory is in
[third-party notices](https://github.com/magrathean-uk/auditex/blob/main/docs/legal/third-party-notices.md). Security reporting instructions
are in [.github/SECURITY.md](https://github.com/magrathean-uk/auditex/blob/main/.github/SECURITY.md). Trademark information is in
[docs/legal/trademarks.md](https://github.com/magrathean-uk/auditex/blob/main/docs/legal/trademarks.md). Contributions: see
[CONTRIBUTING](https://github.com/magrathean-uk/auditex/blob/main/.github/CONTRIBUTING.md).

Auditex is independent. It is not affiliated with, endorsed by or supported by Microsoft, Google, CISA, the NCSC, IASME
or the Center for Internet Security. Their names are used only to say what Auditex reads or maps to.

<sub>© 2026 MAGRATHEAN UK LTD · [Legal](https://github.com/magrathean-uk/.github/blob/main/LEGAL.md)</sub>
