# Auditex Agent Guide

Auditex is a read-only Microsoft 365 and Google Workspace tenant-audit toolkit:
a Python CLI (`auditex`, `azure-tenant-audit`) and a local MCP server
(`auditex-mcp`) that collect evidence, normalize it, derive findings, and
produce a validated run bundle plus reports, exports, and customer packs.

## Start here

Use `README.md` and `docs/development/runbook.md` for setup and commands. Read the
documentation for the surface you will change: `docs/reference/output-contract.md` before
changing bundle artifacts, `docs/reference/security-privacy.md` before changing data
handling, and `docs/provenance/provenance.md` before reusing third-party material.

Check `git status --short` before editing. Preserve unrelated work.

## Commands

Use Python 3.11 or newer. There is no hosted CI; run the checks locally. Wrap anything that installs, builds,
or writes caches in Clean Development (see below), for example
`clean-development run --session session-only -- make test`.

```sh
make install                      # editable install into .venv (never system Python)
.venv/bin/python -m pip install -e '.[google,mcp]' pytest   # extras + test runner
make lint                         # compileall src and tests only; no style or type check
make test                         # pytest via scripts/select-python.sh (prefers .venv)
.venv/bin/python -m pytest tests/test_cli.py                  # one module
.venv/bin/python -m pytest tests/test_cli.py -k offline       # one test by name
make contract-smoke               # deletes and recreates outputs/ci-contract, validates bundle
./scripts/oss-taint-scan.sh
auditex --help
auditex doctor --json
auditex guided-run --help
auditex-mcp --help
```

`pytest.ini` sets `pythonpath = src`. Ruff (`E4,E7,E9,F`) and several other
pre-commit hooks are declared at the `manual` stage only; run them with
`pre-commit run <hook-id> --hook-stage manual --all-files`. Run the contract
smoke when changing collectors, normalization, findings, reports, schemas,
evidence references, API inventory, or customer-pack behaviour. State any
skipped check and its blocker.

## Architecture

Two packages under `src/`, with a one-way dependency:

- `azure_tenant_audit/` is the engine: Microsoft 365 collection, normalization,
  findings, bundle writing and finalization, probes, and the
  `azure-tenant-audit` CLI. It must not import from `auditex`
  (`tests/test_architecture_modules.py` enforces parts of this boundary).
- `auditex/` is the product layer: the `auditex` CLI, guided flows, auth
  contexts, setup guides, Google Workspace provider, reporting, exporters,
  compare and drift gates, notifications, and the MCP server. `auditex run`
  (and legacy bare flags such as `auditex --tenant-name ...`) delegate to
  `azure_tenant_audit.cli.main`.

Microsoft 365 run pipeline (`azure_tenant_audit/cli.py`, `run_live` and
`run_offline`):

1. Collectors from `collectors.REGISTRY` (each a `collectors/base.py`
   `Collector`) run through `collector_runner.CollectorRunner`. Graph calls go
   through `graph.GraphClient`; non-Graph surfaces use `adapters/` (m365 CLI,
   PowerShell Graph, M365DSC). Graph errors are classified into blocker types
   (`insufficient_permissions`, `permission_stop`, ...) rather than raised, so a
   partial run still finalizes with structured coverage gaps.
2. `output.AuditWriter` writes raw data, checkpoints, diagnostics, blockers,
   and the API call ledger into the run directory.
3. `normalize.build_normalized_snapshot` produces `normalized/*.json`;
   `findings.build_findings` derives findings using
   `configs/finding-templates.json` and `configs/control-mappings.json`.
4. `finalize.finalize_bundle_contract` writes the manifest, validation, report
   pack, AI context, and `index/evidence.sqlite`. Offline mode replays a sample
   JSON (`examples/sample_audit_bundle/`) through steps 3 and 4.

Analyses that run on the normalized snapshot at finalize time: `attack_graph.py`
(privilege-escalation paths, `attack_path.*` findings), `detection_coverage.py`
(on/off/unknown signals; unknown is never counted as off), `exposure_lookup.py`
(public footprint of the tenant's own domains; never user enumeration), and
`baselines.py` (framework alignment and Secure Score reconciliation).
Framework ids must exist in `configs/framework-catalog.json`, which records
verified sources; shipped mappings no longer emit `cis_m365_v3`. After adding
or changing a rule, run `python3 scripts/generate-rule-packs.py` (a test checks
for drift).

Google Workspace (`auditex/google_workspace/`) has its own client, collectors,
normalization, and findings, and finalizes through
`azure_tenant_audit.provider_runtime.write_provider_bundle` into the same bundle
contract. `auditex/reporting.py`, `exporters.py`, `compare.py`, and
`run_bundle.py` work from finalized run directories only, without tenant access.

Collection scope is data driven. `configs/collector-definitions.json`,
`collector-permissions.json`, and `collector-presets.json` feed
`catalog.py`, `presets.py`, and `scope_catalog.py`, which in turn drive probes,
setup-guide output, and the permission ledger. Auditor profiles live in
`profiles/`; bundle schemas in `schemas/`.

Shipped content (`configs/`, `profiles/`, `schemas/`, `docs/`, `agent/`,
`skills/`, `assets/`, `examples/`) is packaged through
`[tool.setuptools.data-files]` in `pyproject.toml` and resolved at runtime by
`azure_tenant_audit/resources.py` (repository root in a checkout, the installed
data directory otherwise, `AUDITEX_RESOURCE_ROOT` to override). Adding a
shipped file means updating both `pyproject.toml` and `shipped_content.py`; a
test asserts they match.

`examples/demo_tenant/demo_tenant.json` is the synthetic Halcyon Freight tenant
behind `auditex demo` (`src/auditex/demo.py`); only `.example` domains are
allowed in it. Its remediated twin is generated by
`scripts/make-remediated-demo.py`; rerun it after editing the fixture (a test
checks they match). `auditex report explorer` (`src/auditex/explorer.py`)
renders any run as one HTML file with no network requests.

MCP tools are declared in `auditex/mcp_registry.py` (specs and read-only
annotations) and handled in `auditex/mcp_server.py`. Response actions
(`azure_tenant_audit/response.py`) are hidden unless `auditex/features.py`
reports them enabled.

`tests/conftest.py` redirects `AUDITEX_LOCAL_AUTH_ENV`,
`AUDITEX_AUTH_CONTEXTS_PATH`, and `AUDITEX_M365_HOME` to a temporary directory
for the whole session so tests cannot overwrite real `.secrets/` credentials.
Keep new auth or secret paths behind that redirect.

## Repository map

- `configs/`, `profiles/`, and `schemas/`: shipped collection and contract
  data.
- `agent/` and `skills/`: shipped operator and runtime content.
- `scripts/`: Python selection, local auth loading, m365 home routing, taint
  scan, release smoke, and shell wrappers.
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

Response features are disabled unless `AUDITEX_ENABLE_RESPONSE` has a truthy
value for lab-only development; they are outside the public audit flow. Treat
`auditex notify send --execute` as an external send, separate from local audit
or pack verification. `auditex guided-run --flow ga-setup-app` creates or
changes an app registration and is not an audit-only step.

## Clean development (mandatory)

This project follows [Clean Development](https://github.com/magrathean-uk/clean-development) and the machine rule that nothing creates tool state under `~` (only the allow-listed agent homes).

- The shell environment comes from `~/.zshenv`, which loads `~/dev/env.zsh`. It routes every tool home and cache (`CARGO_HOME`, `RUSTUP_HOME`, `XDG_*`, `BUNDLE_USER_HOME`, `npm_config_cache`, `XCODE_DERIVED_DATA_PATH`, ...) and switches telemetry off. Never unset, override or bypass those variables. If a script needs a scrubbed environment, re-export them with `source ~/dev/env.zsh`.
- Run builds, tests, installs and anything else that writes caches or build output through Clean Development: `clean-development run --session session-only -- <command>`. Follow its docs and keep its receipts.
- Do not add installers or scripts that default into `~` (`~/.cargo`, `~/.rustup`, `~/.cache`, `~/.npm`, `~/.swiftpm`, `~/.gradle`, ...) and do not hardcode `$HOME` paths for caches; use the routed variables. The m365 CLI is run with `HOME` set to `AUDITEX_M365_HOME` or `$XDG_DATA_HOME/auditex/m365` (`azure_tenant_audit/m365_home.py`, `scripts/m365-home.sh`) for this reason.
- Before finishing, run `dev-env-check` (must pass) and `dev-audit` (no new entries in `~`). If your work caused a violation, fix the cause in the repo and say so.

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
Do not copy direct-secret runtime templates into operator guidance.

Update product documentation when commands, scopes, artifacts, or operator
flows change. Keep durable repository guidance here and in maintained product
documentation rather than creating session notes or duplicate instruction
files. `CLAUDE.md` only imports this file.

## Legal

Legal files (`LICENSE`, `NOTICE`, `docs/legal/`, contributor terms, copyright and
attribution strings) are owner-controlled: change them only on the owner's explicit
instruction.

## Pending URL migration

The next release must apply [NEXT-RELEASE-URLS.md](NEXT-RELEASE-URLS.md): product sites moved to `https://magrathean.uk/solutions/<slug>/` and support addresses to `contact+<slug>@magrathean.uk`. Remove this section with that file once released.
