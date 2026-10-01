# Auditex Agent Guide

## Start here

Use `README.md` and `docs/development/runbook.md` for setup and commands. Read the
documentation for the surface you will change: `docs/reference/output-contract.md` before
changing bundle artifacts, `docs/reference/security-privacy.md` before changing data
handling, and `docs/provenance/provenance.md` before reusing third-party material.

Check `git status --short` before editing. Preserve unrelated work.

## Repository map

- `src/azure_tenant_audit/`: Microsoft 365 collection, normalization,
  findings, bundle finalization, and the core CLI.
- `src/auditex/`: product CLI, guided flows, Google Workspace collection,
  reports, exports, notifications, MCP server, and auth helpers.
- `configs/`, `profiles/`, and `schemas/`: shipped collection and contract
  data.
- `agent/` and `skills/`: shipped operator and runtime content.
- `tests/`: unit, contract, report, export, provider, and safety coverage.
- `tenant-bootstrap/`: a separate lab helper surface. Its runtime templates
  include bootstrap actions that can write tenant objects. Do not present it as
  part of the public audit-only flow.

## Safety boundaries

Public Auditex audit, probe, report, export, MCP audit tools, customer-pack
creation, and customer-pack verification must not write to production tenants.
Audit collectors must not read Gmail or Exchange message bodies, or Drive,
SharePoint, or OneDrive file content. Google Workspace remains a separate
read-only provider path.

Treat tenant evidence and credentials as confidential. Never commit tokens,
OAuth caches, service-account keys, secrets, bearer material, or tenant
evidence. Do not add external telemetry. Keep `.venv/`, `.secrets/`,
`.pytest_cache/`, `outputs/`, `audit-output/`, `src/auditex.egg-info/`,
`site/`, and tenant-bootstrap run or secret folders local.

When collector scope changes, keep collector definitions, permission maps,
setup-guide output, permission ledgers, API inventory, schemas, documentation,
tests, and contract expectations aligned. A scope that is write-capable does
not authorize a mutating operation. Record its blast radius and verify the API
inventory for the actual run.

<!-- clean-development-policy:v1 (canonical text: ~/dev/source/dev-bootstrap/snippets/clean-development-policy.md) -->
## Clean development (mandatory)

This project follows [Clean Development](https://github.com/magrathean-uk/clean-development) and the machine rule that nothing creates tool state under `~` (only the allow-listed agent homes).

- The shell environment comes from `~/.zshenv`, which loads `~/dev/env.zsh`. It routes every tool home and cache (`CARGO_HOME`, `RUSTUP_HOME`, `XDG_*`, `BUNDLE_USER_HOME`, `npm_config_cache`, `XCODE_DERIVED_DATA_PATH`, ...) and switches telemetry off. Never unset, override or bypass those variables. If a script needs a scrubbed environment, re-export them with `source ~/dev/env.zsh`.
- Run builds, tests, installs and anything else that writes caches or build output through Clean Development: `clean-development run --session session-only -- <command>`. Follow its docs and keep its receipts.
- Do not add installers or scripts that default into `~` (`~/.cargo`, `~/.rustup`, `~/.cache`, `~/.npm`, `~/.swiftpm`, `~/.gradle`, ...) and do not hardcode `$HOME` paths for caches; use the routed variables.
- Before finishing, run `dev-env-check` (must pass) and `dev-audit` (no new entries in `~`). If your work caused a violation, fix the cause in the repo and say so.

## Commands

Use Python 3.11 or newer. The repository defines these checks:

```sh
make lint
make test
make contract-smoke
./scripts/oss-taint-scan.sh
python3 scripts/build-pages-site.py /tmp/auditex-pages
auditex --help
auditex doctor --json
auditex guided-run --help
auditex-mcp --help
```

`make lint` compiles `src` and `tests`. `make test` uses
`scripts/select-python.sh`. `make contract-smoke` recreates
`outputs/ci-contract` and validates an offline bundle. Run the contract smoke
when changing collectors, reports, schemas, evidence references, API inventory,
or customer-pack behaviour. State any skipped check and its blocker.

## Working rules

Complete authorized work through its relevant checks. Make routine local
choices without repeated permission, preserve explicit owner restrictions, and
use bounded delegation for independent work when useful. Keep changes small
and follow nearby conventions. Use the stable `auditex`
product surface for normal audit work. Start an authorized tenant engagement
with setup guidance and a probe, then report blocked collectors as structured
coverage gaps. Do not expose secrets in commands, prompts, logs, or generated
documentation.

Use local auth files excluded from Git where app credentials are necessary.
Do not copy direct-secret runtime templates into operator guidance. Response
features are disabled unless `AUDITEX_ENABLE_RESPONSE` has a truthy value for
lab-only development; they are outside the public audit flow. Treat
`auditex notify send --execute` as an external send, separate from local audit
or pack verification.

Update product documentation when commands, scopes, artifacts, or operator
flows change. Keep durable repository guidance here and in maintained product
documentation rather than creating session notes or duplicate instruction
files.

## Legal

Legal files (`LICENSE`, `NOTICE`, `docs/legal/`, contributor terms, copyright and
attribution strings) are owner-controlled: change them only on the owner's explicit
instruction.

## Pending URL migration

The next release must apply [NEXT-RELEASE-URLS.md](NEXT-RELEASE-URLS.md): product sites moved to `https://magrathean.uk/solutions/<slug>/` and support addresses to `contact+<slug>@magrathean.uk`. Remove this section with that file once released.
