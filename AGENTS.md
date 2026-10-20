# Auditex agent guide

Auditex is a read-only Microsoft 365 and Google Workspace tenant-audit toolkit: a Python
CLI (`auditex`, `azure-tenant-audit`) and a local MCP server (`auditex-mcp`) that collect
evidence, normalise it, derive findings, and produce a validated run bundle plus reports,
exports and customer packs. Remote: `magrathean-uk/auditex` (public). Python 3.11+.

## Start here

`README.md` and `docs/development/runbook.md` for setup and commands. Before changing a
surface, read its doc: `docs/reference/output-contract.md` (bundle artifacts),
`docs/reference/security-privacy.md` (data handling), `docs/provenance/provenance.md`
(third-party reuse). The architecture is documented in `docs/`; this file is the
environment, safety and command contract. Check `git status --short` before editing.

## Commands

Run commands directly; Clean Development 0.6.0 routing is loaded by `~/dev/machine/env.zsh`, e.g. `make test`.

```sh
make install                 # editable install into .venv (never system Python)
make lint                    # compileall src and tests
make test                    # pytest via scripts/select-python.sh
.venv/bin/python -m pytest tests/test_cli.py -k offline   # one test
make contract-smoke          # recreate outputs/ci-contract, validate bundle
auditex doctor --json ; auditex-mcp --help
```

`pytest.ini` sets `pythonpath = src`. Run the contract smoke when changing collectors,
normalisation, findings, reports, schemas, evidence references, API inventory or
customer-pack behaviour. After rule changes run `python3 scripts/generate-rule-packs.py`
(a test checks for drift). State any skipped check and its blocker.

## Architecture (map; detail in docs/)

Two packages under `src/` with a one-way dependency: `azure_tenant_audit/` is the M365
engine (collection, normalisation, findings, bundle finalisation, the
`azure-tenant-audit` CLI) and must not import from `auditex`; `auditex/` is the product
layer (the `auditex` CLI, guided flows, Google Workspace provider, reporting, exporters,
compare/drift, MCP server). Collection scope is data-driven from `configs/`. Shipped
content (`configs/`, `profiles/`, `schemas/`, `docs/`, `agent/`, `skills/`, `assets/`,
`examples/`) is packaged via `[tool.setuptools.data-files]` and resolved by
`azure_tenant_audit/resources.py`; adding a shipped file updates both `pyproject.toml` and
`shipped_content.py` (a test asserts they match). MCP tools: `auditex/mcp_registry.py`
(specs, read-only annotations) and `auditex/mcp_server.py`.

## Safety boundaries

Public audit, probe, report, export, MCP audit tools and customer-pack flows must not
write to production tenants and must not read message bodies or file content. Treat tenant
evidence and credentials as confidential; never commit tokens, OAuth caches, keys, secrets
or evidence; no external telemetry. Keep `.venv/`, `.secrets/`, `.pytest_cache/`,
`outputs/`, `audit-output/`, `site/` and tenant-bootstrap run/secret folders local. A
write-capable scope does not authorise a mutating operation; record its blast radius.
Response features stay disabled unless `AUDITEX_ENABLE_RESPONSE` is truthy (lab only).
`tests/conftest.py` redirects auth/secret paths to a temp dir; keep new ones behind it.

## Legal and pending migration

Legal files are owner-controlled. The next release applies `NEXT-RELEASE-URLS.md`
(product sites -> `https://magrathean.uk/solutions/<slug>/`, support ->
`contact+<slug>@magrathean.uk`), then remove it. `CLAUDE.md` only imports this file.

## Models

Claude Code (Fable/Opus 5.5 for cross-cutting work, Sonnet 5.5 for routine, Haiku 5.5 for
extraction) or Codex `gpt-6.1-sol`; `gpt-6-luna` for swarm exploration. Independent review
of collector-scope, schema and customer-pack changes.

<!-- clean-development-policy:v4 (clean-development 0.6.0; canonical: bolyki-dev/clean-development/docs/policy-snippet.md) -->
## Clean development (mandatory)

- Storage is routed for you: every zsh loads `~/dev/machine/env.zsh`; hooks pin the mode per session (`$CLEAN_DEV_MODE` is `external` when the 4TB is attached, else `internal`). Do not wrap commands, override or unset the routed variables.
- Temp files go to `$TMPDIR` (session scratch, deleted at session end), throwaway build output to `$CLEAN_DEV_BUILDS`, caches wherever their variables point. Never write caches, builds or temp files into `~`, `~/dev` or this repo outside its git-ignored build directories.
- Internal mode: before any download or build likely over 5 GB, stop and ask G (suggest waiting for the 4TB).
- This repo's `.clean-development.json` (schema v2) lists its git-ignored `buildDirs`/`depDirs`; keep it accurate when the build layout changes.
- No dot-folders in `~` or `~/dev`. `.env` files stay git-ignored; read them only when the task needs them; never commit them.
