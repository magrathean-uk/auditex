# Auditex agent context

<!-- clean-development-policy:v6 -->
Purpose: read-only Microsoft 365 and Google Workspace tenant-audit toolkit. A Python 3.11+ CLI (`auditex`,
`azure-tenant-audit`) and a local MCP server (`auditex-mcp`) collect evidence, normalise it, answer the CISA SCuBA
baselines with deterministic value rules, and write a validated run bundle plus reports, exports and customer packs.
Remote `magrathean-uk/auditex` (public). State of play and rulings: `.plan/STATE.md` and `.plan/DECISIONS.md`
(local, git-ignored, owner decision).

## Commands
```sh
make install                                  # editable install into .venv (may be a link to $DEVCACHE/venvs/auditex)
.venv/bin/python -m pytest tests/test_cli.py -k offline   # focused tests; pytest.ini sets pythonpath = src
make lint                                     # compileall plus pinned Ruff (E4, E7, E9, F, W, I, B, UP)
make test                                     # full suite
make contract-smoke                           # rebuild outputs/ci-contract and validate the bundle
python3 scripts/generate-rule-packs.py        # after rule changes; a test checks drift
make acceptance                               # needs AUDITEX_TEST_VALUE_RULE_VECTORS_V391
make dist                                     # reproducible wheel and sdist into dist/
make release-check                            # lint, test, smoke, drift, taint scan, gitleaks
gitleaks git --pre-commit --staged --redact --no-banner
```
Setup and the full command list: `docs/development/runbook.md`.

## Boundaries (never cross)
- Audit, probe, report, export, MCP audit tools and customer-pack flows never write to a tenant and never read
  message bodies or file content. A write-capable scope never authorises a mutating call; record the blast radius
  of any scope you add.
- Response features stay off unless `AUDITEX_ENABLE_RESPONSE` is truthy (lab only).
- Never commit credentials, tokens, OAuth caches, keys, live tenant evidence, held-out or sealed evaluation rows,
  workstation paths (`/Users/...`, `/Volumes/...`) or session URLs and trailers. The repo is public. No external
  telemetry.
- Git-ignored and local: `.venv/`, `.secrets/`, `outputs/`, `audit-output/`, `site/`, `.pytest_cache/`, `.plan/`,
  tenant-bootstrap run and secret folders. Outputs holding live evidence stay on the encrypted internal disk.
- CLI parsers use `allow_abbrev=False`; every flag that can carry a secret is in the argv redaction list with a
  test. `tests/conftest.py` redirects auth and secret paths to a temp dir; keep new ones behind it.
- Legal files are owner-controlled. Product page `https://magrathean.uk/solutions/auditex/`, support
  `contact+auditex@magrathean.uk`; do not reintroduce retired domains, `/apps/` paths or `contact@`.
- No GitHub Releases are needed (G, 25 Nov 2026); release tags are annotated `vX.Y.Z`. Plan and milestone tags
  (`M0*`, `plan-v*`, `v3-M*`, `v4-M00`) stay local, never pushed.

## Architecture
- `src/azure_tenant_audit/` is the M365 engine (collection, normalisation, value rules, findings, bundle
  finalisation, the `azure-tenant-audit` CLI) and never imports from `auditex`.
- `src/auditex/` is the product layer (CLI, guided flows, Google Workspace provider, reporting, exporters, compare
  and drift, MCP server in `mcp_registry.py` and `mcp_server.py`, the Google Workspace SCuBA projection).
- SCuBA answers come only from `src/azure_tenant_audit/value_rules/`: Microsoft 365 from
  `configs/scuba-value-rules.json` (spec v3.9.1), Google Workspace from `value_rules/gws/` with
  `configs/scuba-gws-value-rules.json` and its `scuba-gws-rules-*.json` fragments (ScubaGoggles v1.1.0 at
  `08a08ce1`). No model layer or fallback; the template explainer never decides a verdict.
- Collection scope is data-driven from `configs/`. Shipped content (`configs/`, `profiles/`, `schemas/`, `docs/`,
  `agent/`, `skills/`, `assets/`, `examples/`) is listed in both `pyproject.toml` `[tool.setuptools.data-files]`
  and `shipped_content.py`; a test checks they match.
- `tenant-bootstrap/` is lab seeding only: its scripts write to a lab tenant, so run them only against a tenant
  the owner named for lab work. Never part of audit, probe, report, export, customer-pack or MCP flows; `src/`
  never imports it. Its `azure_tenant_audit` is only the forwarder (`tests/test_tenant_bootstrap_forwarder.py`);
  do not copy engine modules back. `run-auditor.sh`, `create-lab-populator-app.py` and `auth-lab-populator.py`
  stay with the parked dummy-tenant kit (DEC-006).

## Checks by changed surface
| Change | Required before merge |
|---|---|
| Collectors, normalisation, findings, reports, schemas, evidence refs, API inventory, customer packs | focused tests, `make contract-smoke`, independent review |
| Value rules or rule configs | focused rule and vector tests, `generate-rule-packs.py` with no drift, the GWS catalogue and explainer generators with no drift |
| Shipped content | the shipped-content parity test |
| CLI flags or argv handling | abbreviation and redaction tests |
| Docs only | read-through |
| Release | `make release-check` |

Independent review (fresh session, ideally the other provider, on a frozen commit) is mandatory for collector
scope, schemas, customer packs, auth and anything touching secrets. Block a PR for: tenant writes or message/file
reads in audit paths; response features without `AUDITEX_ENABLE_RESPONSE`; a parser without `allow_abbrev=False` or
a secret flag missing from redaction; secrets, live evidence or workstation paths in the tree, outputs or logs;
schema, bundle or collector changes without a contract test; a SCuBA verdict from anything but the value rules; a
fix without a failing-then-passing test; shipped content in only one of `pyproject.toml` and `shipped_content.py`.

## Working rules
- Commits are signed, gitleaks-clean, one coherent change each. Merging into `main` runs `make test` once per
  batch; gitleaks over the new range on push. State every skipped check and why.
- Worktrees live outside the repo on branch `wt/<task>` cut from `main`; remove worktree and branch after merge.
- Cloud sessions (G, 19 Nov 2026) take only code-and-test work needing no Mac, lab tenant, Isambard-AI or secret:
  `make install`, then the checks above; push only the named `wt/<task>` branch, never `main`, a tag or a release.
- Read before changing (only the one you touch): `docs/reference/output-contract.md`,
  `docs/reference/security-privacy.md`, `docs/provenance/provenance.md`, `docs/development/runbook.md`.
- Plan Creator: you are a worker when your prompt is a brief with a task id; own only the files it names, never
  touch `.plan/` unless named, never push or merge, finish with the brief's RESULT block.
- `.clean-development.json` (schema v2) lists the git-ignored `buildDirs` and `depDirs`; keep it accurate. `.venv`
  may link to `$DEVCACHE/venvs/auditex`; if that volume is away, `rm .venv` and `make install`.

## Done when
`make lint` and the checks for the changed surface pass; `make release-check` for a release.
