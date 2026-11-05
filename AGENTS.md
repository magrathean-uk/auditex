# Auditex agent guide

Auditex is a read-only Microsoft 365 and Google Workspace tenant-audit toolkit: a Python CLI
(`auditex`, `azure-tenant-audit`) and a local MCP server (`auditex-mcp`) that collect evidence,
normalise it, answer the CISA SCuBA baselines with deterministic value rules, and write a validated
run bundle plus reports, exports and customer packs. Remote `magrathean-uk/auditex` (public).
Python 3.11+. Claude Code reads this file through `CLAUDE.md`; Codex reads it directly.

## Boundaries (never cross)

- Audit, probe, report, export, MCP audit tools and customer-pack flows never write to a tenant and
  never read message bodies or file content. A write-capable scope never authorises a mutating
  call; record the blast radius of any scope you add.
- Response features stay off unless `AUDITEX_ENABLE_RESPONSE` is truthy (lab only).
- Never commit credentials, tokens, OAuth caches, keys, live tenant evidence, held-out or sealed
  evaluation rows, workstation paths (`/Users/...`, `/Volumes/...`) or session URLs and trailers.
  The repo is public; everything else may go in it. No external telemetry.
- Keep local and git-ignored: `.venv/`, `.secrets/`, `outputs/`, `audit-output/`, `site/`,
  `.pytest_cache/`, tenant-bootstrap run and secret folders. Outputs holding live evidence stay on
  the encrypted internal disk.
- CLI parsers use `allow_abbrev=False`; every flag that can carry a secret is in the argv redaction
  list with a test (1.2.2 and 1.2.3 fixed a leak through abbreviated flags).
- `tests/conftest.py` redirects auth and secret paths to a temp dir; keep new ones behind it.
- Legal files are owner-controlled. Product page `https://magrathean.uk/solutions/auditex/`, support
  `contact+auditex@magrathean.uk`; do not reintroduce retired domains, `/apps/` paths or `contact@`.

## Architecture

- `src/azure_tenant_audit/` is the M365 engine (collection, normalisation, value rules, findings,
  bundle finalisation, the `azure-tenant-audit` CLI) and never imports from `auditex`.
- `src/auditex/` is the product layer (the `auditex` CLI, guided flows, Google Workspace provider,
  reporting, exporters, compare and drift, MCP server: `mcp_registry.py`, `mcp_server.py`).
- SCuBA answers come only from `src/azure_tenant_audit/value_rules/` and
  `configs/scuba-value-rules.json` (spec v3.9.1). There is no model fallback; the local model and
  the template explainer never decide a verdict.
- Collection scope is data-driven from `configs/`. Shipped content (`configs/`, `profiles/`,
  `schemas/`, `docs/`, `agent/`, `skills/`, `assets/`, `examples/`) is listed in both
  `pyproject.toml` `[tool.setuptools.data-files]` and `shipped_content.py`; a test checks they match.

## Commands

```sh
make install                          # editable install into .venv (may be a link; see Environment)
.venv/bin/python -m pytest tests/test_cli.py -k offline   # focused tests while iterating
make lint                             # compileall only, not a style check
make test                             # full suite
make contract-smoke                   # rebuild outputs/ci-contract and validate the bundle
python3 scripts/generate-rule-packs.py   # after rule changes; a test checks drift
make release-check                    # lint, test, smoke, drift, taint scan, gitleaks
gitleaks git --pre-commit --staged --redact --no-banner
```

`pytest.ini` sets `pythonpath = src`. Setup and the full command list: `docs/development/runbook.md`.

## Checks by changed surface

| Change | Required before merge |
|---|---|
| Collectors, normalisation, findings, reports, schemas, evidence refs, API inventory, customer packs | focused tests, `make contract-smoke`, independent review |
| Value rules or rule configs | focused rule and vector tests, `generate-rule-packs.py` with no drift |
| Shipped content | the shipped-content parity test |
| CLI flags or argv handling | abbreviation and redaction tests |
| Docs only | none beyond a read-through |
| Release | `make release-check` |

Merging into `main` also runs `make test` once per batch. State every skipped check and why.

## Read before changing

`docs/reference/output-contract.md` for bundle artifacts, `docs/reference/security-privacy.md` for
data handling and redaction profiles, `docs/provenance/provenance.md` for third-party reuse,
`docs/development/runbook.md` for setup and release. Read only the one your change touches.

## Parallel work

- Check `git status --short` first. One writer per worktree; worktrees live outside the repo on
  the external build volume (path in the operator plan) on branch `wt/<task>`, cut from current `main`.
- One integrator merges into `main`, one branch at a time, then pushes `main` (fast-forward,
  gitleaks over the new range; no test gate on the push itself). Nobody else pushes.
- Independent review (a fresh session, ideally the other provider) is mandatory for collector
  scope, schemas, customer packs, auth and anything touching secrets. Review a frozen commit against
  the brief, not the author's summary. Two repair rounds, then re-scope.
- Commits are signed and gitleaks-clean, one coherent change each, with plain subject lines.
- Remove the worktree and branch after merge.

## Environment and storage

Clean Development 0.6 routing is loaded by `~/dev/machine/env.zsh` in every shell; never wrap,
override or unset it. Temp files go to `$TMPDIR`, throwaway builds to `$CLEAN_DEV_BUILDS`, caches
where their variables point. Nothing is written into `~`, `~/dev` or this repo outside its
git-ignored build directories. In internal mode, stop and ask before any download or build over
5 GB. `.clean-development.json` (schema v2) lists the git-ignored `buildDirs` and `depDirs`; keep
it accurate. No dot-folders in `~` or `~/dev`; `.env` files stay ignored and unread unless needed.
`.venv` may be a link to `$DEVCACHE/venvs/auditex` on the external volume; when that volume is
away, `rm .venv` and `make install` rebuild it locally.

## Completion report

What behaviour changed; the commit or branch; each check run with its result; checks skipped and
why; remaining risks or follow-ups. Keep it short; long logs stay in files.
