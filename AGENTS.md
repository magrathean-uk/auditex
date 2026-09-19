# Auditex Agent Guide

Read `README.md`, `RUNBOOK.md`, `docs/README.md`,
`docs/OUTPUT_CONTRACT.md`, and `docs/SECURITY_PRIVACY.md` before changing the
related surface. `SECURITY.md`, `THIRD_PARTY_NOTICES.md`, and
`docs/provenance/provenance.md` hold security, legal, and provenance context.

## Repo map

- `src/azure_tenant_audit/`: Microsoft 365 audit engine, collectors,
  normalization, findings, bundle finalization, and core CLI.
- `src/auditex/`: product CLI, guided flows, Google Workspace path, reports,
  exports, notifications, MCP server, and auth/setup helpers.
- `configs/`, `profiles/`, and `schemas/`: shipped collection and contract data.
- `agent/` and `skills/`: shipped operator/runtime content.
- `tests/`: core, product, Google, contract, report, export, and safety tests.
- `tenant-bootstrap/`: portable lab helper kit; keep it aligned with root
  behavior.
- `scripts/`: setup, login, audit, taint-scan, Python selection, release smoke,
  and Pages build helpers.

## Rules

- Inspect `git status --short` first and preserve unrelated work.
- Use Python 3.11 or newer and match nearby style.
- Public Auditex is audit-only. Audit, probe, report, export, MCP audit tools,
  and customer-pack verification must not write to production tenants.
- Do not read Gmail or Exchange bodies, or Drive, SharePoint, or OneDrive file
  content in audit mode.
- Keep Google Workspace as a separate read-only provider path.
- Keep collector definitions, permission maps, setup-guide output, permission
  ledgers, and API inventories aligned when scope truth changes.
- Update schemas, docs, tests, and contract expectations together when public
  commands or bundle artifacts change.
- Never commit tenant evidence, tokens, OAuth caches, service-account keys,
  secrets, or bearer material. Do not add external telemetry.
- Treat `.venv/`, `.secrets/`, `.pytest_cache/`, `outputs/`, `audit-output/`,
  `src/auditex.egg-info/`, `site/`, and tenant-bootstrap run/secret folders as
  generated or local.

## Setup and verification

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
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

`make test` uses `scripts/select-python.sh`; `make lint` compiles `src` and
`tests`; `make contract-smoke` recreates `outputs/ci-contract` and validates an
offline bundle. No dedicated formatter or static typecheck command is
configured.

Run `make contract-smoke` when collectors, reports, schemas, evidence refs, API
inventory, or customer-pack behavior changes. Report any skipped check and its
blocker.

## Working guidance — GPT-6 Astra

Based on [OpenAI's Astra prompting guidance](https://developers.openai.com/api/docs/guides/latest-model#prompting-best-practices), reviewed 2026-09-19. These are working instructions, not a change to model or API settings.

- Complete the authorized task through implementation and relevant verification. Make routine choices yourself; ask only when a missing decision materially changes the result or requires new authority. Prepare reviewable work before requesting any necessary final approval.
- Current user instructions take precedence over repository and skill guidance within system and tool constraints. Preserve explicit exclusions and owner holds. Historical plans and session notes do not grant current authorization. If a file or skill blocks progress, identify its exact path and rule.
- Keep changes small and practical. Inspect current source and Git status, preserve unrelated work, and use existing conventions. Do not add speculative abstractions, dependencies, or unrelated cleanup. Commit, push, deploy, install, and live-service changes require authorization for that action.
- Use the reasoning effort the task needs. Follow explicit project delegation rules; otherwise use subagents only when requested, with bounded independent tasks and distinct file ownership. Batch independent reads; serialize dependent operations and conflicting edits.
- Run meaningful checks for the changed behavior and required project gates. Avoid tests that merely repeat low-impact edits. Broaden or repeat verification only after changes, failures, or unresolved concerns. Distinguish local checks from device, browser, and live-service evidence.
- Write concise, plain, outcome-first updates. State what changed, why, verification, and material gaps. Avoid filler and unnecessary formatting.
- Keep durable instructions in AGENTS.md and maintained product documentation. Do not create duplicate assistant instruction files or disposable plans, transcripts, status reports, and screenshots in source directories unless requested. Preserve source, tests, fixtures, assets, licences, and operational evidence regardless of who created them.
