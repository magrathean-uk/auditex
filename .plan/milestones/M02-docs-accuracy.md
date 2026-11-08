---
id: M02
name: docs-accuracy
weight: 20
status: planned
---
# M02 docs-accuracy
Legal files (`LICENSE`, `NOTICE`, `docs/legal/**`) are G-owned; agents draft proposals and never edit them.

## Goal
The README, guides, reference docs and runbook describe 1.3.0 exactly as the code behaves: no first-party public doc names a repository path that does not exist (checked by a test), the G-owned notice carries the correction text G approved (DEC-003), the deterministic template explainer is described as shipped and the model explainer as parked, the coverage split is current, release steps match the Makefile and the planned publication, and nothing claims SCuBA Google Workspace coverage.

## Definition of Done
- [ ] No first-party public doc (every tracked `*.md` outside `tenant-bootstrap/vendor/`, `tests/` and `.plan/`) names a repository path or relative link that does not exist, and the only exemption left in the test is the reasoned `tests/providers/m365` entry: `.venv/bin/python -m pytest tests/test_docs_paths.py && ! grep -n 'third-party-notices' tests/test_docs_paths.py`
- [ ] Review: G approved the exact text of the `docs/legal/third-party-notices.md` path correction drafted in M02-T06 (DEC-003) and M02-T07 merged it verbatim, so the notice names the tracked vendored path `grep -n 'tenant-bootstrap/vendor/microsoft-skills/skills/mcp-builder/scripts/requirements.txt' docs/legal/third-party-notices.md && ! grep -n -E '(^|[^/])skills/mcp-builder/scripts/requirements.txt' docs/legal/third-party-notices.md`
- [ ] Review: terra read-through confirms every explainer mention describes the template explainer as shipped and the model explainer as parked `git grep -n -i explainer -- README.md docs/guides docs/reference`
- [ ] Review: the README carries the current coverage split from `wt/docs-rules-and-scan-limits` (fe78ee1), reconciled with the merged behaviour, with no unsupported coverage figure `git show fe78ee1 -- README.md`
- [ ] Review: the runbook lists every `release-check` step, the `release-archive`, `dist`, `audit-deps` targets, the sdist smoke and reproducible-build check, the planned publication steps, and links the internal ScubaGear export adapter doc `grep -n -e release-archive -e audit-deps -e 'make dist' -e check-reproducible-build -e 'gh release' -e scubagear-export-adapter docs/development/runbook.md`
- [x] No doc claims SCuBA Google Workspace baseline coverage: `! git grep -q -i -E 'MS\.GWS|GWS\.[A-Z]+\.[0-9]|scuba (gws|google)' -- README.md docs` (evidence: that command passed at 3122ac5, .plan/work/PLAN-v2/evidence.md)
- [x] Review: Power BI and Power Platform collection is documented as extended scope, off by default, with the write-capable roles used read-only and their blast radius `grep -n -e 'off by default' -e 'write-capable admin role used read-only' docs/guides/admin-permission-guide.md` (evidence: docs/guides/admin-permission-guide.md:284 and :320 at 3122ac5)
- [ ] Shipped-content parity holds after the doc changes: `.venv/bin/python -m pytest tests/test_architecture_modules.py`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M02-T01 | Fix the dead admin-guide reference and stale status comments | terra | S | mechanical | todo |
| M02-T02 | Reconcile the coverage-split README branch | terra | S | - | todo |
| M02-T03 | Describe the shipped template explainer consistently | terra | M | - | todo |
| M02-T04 | Bring the runbook in line with the gates and publication | terra | S | - | todo |
| M02-T05 | Add a public-doc path test | codex | S | - | todo |
| M02-T06 | Draft the third-party notice path correction for G | terra | S | - | todo |
| M02-T07 | Apply G's approved notice text and drop its test exemption | orchestrator | S | mechanical | todo |

## Acceptance criteria
### M02-T01 Fix the dead admin-guide reference and stale status comments
- `docs/guides/admin-permission-guide.md` no longer points at `docs/prerequisites/noninteractive.md`; the Power BI tenant-setting and Power Platform prerequisites it meant are stated inline or linked to an existing section.
- The `src/azure_tenant_audit/value_rules/defender_spam.py` module comment no longer says rows are "held until P4" when `configs/scuba-value-rules.json` enables them; comment-only change, rule packs unchanged.
- The `docs/guides/model-development.md` mention of `tests/providers/m365` stays: it names an upstream sparse-checkout path, not a repository path.
- verify: `! git grep -n 'docs/prerequisites/' -- docs/guides && .venv/bin/python scripts/generate-rule-packs.py --check`
- files: `docs/guides/admin-permission-guide.md`, `src/azure_tenant_audit/value_rules/defender_spam.py`

### M02-T02 Reconcile the coverage-split README branch
- Reads the single commit fe78ee1 on `wt/docs-rules-and-scan-limits` against `main` and lands its coverage-split text in `README.md` only where it is true of the merged code (rule availability for all 102 policies kept separate from evidence actually collected).
- No historical model-answered count, kit figure or live-qualification claim appears; the internal scanner paragraph from the operator records is added only if it contains no local path or internal infrastructure name.
- The branch itself is left in place (no merge, no deletion).
- verify: `.venv/bin/python -m pytest tests/test_architecture_modules.py && ! git grep -n -E '/(Users|Volumes)/' -- README.md`
- files: `README.md`

### M02-T03 Describe the shipped template explainer consistently
- `docs/guides/ai-assessment.md` (lines 82-83, 89, 130, 181 at 82d7ca5) and `docs/guides/model-development.md` (line 120) say the deterministic template explainer ships and is wired into reports, and that the catalogued model is parked and not evaluated as an explainer; "planned and unimplemented" and "planned explainer" wording is gone.
- `docs/reference/output-contract.md` describes the explainer output as produced, if it still calls it planned.
- No text implies a model decides or rewrites a verdict.
- verify: `! git grep -n -i -e 'planned and unimplemented' -e 'planned explainer' -- docs/guides docs/reference && .venv/bin/python -m pytest tests/test_architecture_modules.py tests/test_explainer_integration.py`
- files: `docs/guides/ai-assessment.md`, `docs/guides/model-development.md`, `docs/reference/output-contract.md`

### M02-T04 Bring the runbook in line with the gates and publication
- Runs after M00-T02, M00-T03 and M00-T05 are merged.
- The runbook check table lists the `release-archive` step inside `release-check`, the `dist` target, `make audit-deps`, the wheel and sdist smoke and `scripts/check-reproducible-build.py`; the release paragraph uses `make dist` instead of an unscripted build.
- The release section names the publication G approved in DEC-001 (signed `v1.3.0` tag plus a GitHub release carrying the wheel and sdist, no PyPI), and says publication waits for G's explicit yes naming the version.
- The runbook links `docs/development/scubagear-export-adapter.md` as an internal, experimental tool.
- verify: `grep -n -e release-archive -e audit-deps -e 'make dist' -e check-reproducible-build -e 'gh release' -e scubagear-export-adapter docs/development/runbook.md`
- files: `docs/development/runbook.md`

### M02-T05 Add a public-doc path test
- Runs after M02-T01 is merged (its dead reference would fail the new test).
- `tests/test_docs_paths.py` takes its file list from `git ls-files '*.md'`, so every public first-party doc root is covered without a hand-kept list: the top-level Markdown (`README.md`, `AGENTS.md`, `CLAUDE.md`, `CHANGELOG.md`), `.github/**` (`CONTRIBUTING.md`, `SECURITY.md`, `SUPPORT.md`, `PULL_REQUEST_TEMPLATE.md`, issue templates), `docs/**` including `docs/legal/**`, `agent/**`, `skills/**`, `profiles/**` and `tenant-bootstrap/templates/docs/**`, and any Markdown added later. It scans backticked repository-rooted paths and relative links and fails on any that does not exist in the tree.
- Excluded roots, each with its reason in the test: `tenant-bootstrap/vendor/**` (upstream third-party text), `tests/**` (fixtures and schema licences, not docs), `.plan/**` (orchestration records that name files before they exist) and released `CHANGELOG.md` sections (history). The path exemption list is explicit with a reason per entry: `tests/providers/m365` (upstream sparse-checkout path, permanent) and the one `docs/legal/third-party-notices.md` line, marked `pending G-approved correction (DEC-003, M02-T07)`; M02-T07 removes that entry when the approved text lands, and no other legal-file exemption is allowed.
- verify: `.venv/bin/python -m pytest tests/test_docs_paths.py`
- files: `tests/test_docs_paths.py`

### M02-T06 Draft the third-party notice path correction for G
- `proposal.md` quotes the current `docs/legal/third-party-notices.md` line that names `skills/mcp-builder/scripts/requirements.txt`, shows that the file is tracked at `tenant-bootstrap/vendor/microsoft-skills/skills/mcp-builder/scripts/requirements.txt`, checks the stated version floors against that file, and gives the exact replacement text.
- Edits no file under `docs/legal/`; per DEC-003 the correction merges only after G approves the exact text, through M02-T07.
- verify: `test -s .plan/work/M02-T06/proposal.md && git diff --quiet -- docs/legal`
- files: `.plan/work/M02-T06/proposal.md` (read-only)

### M02-T07 Apply G's approved notice text and drop its test exemption
- Runs only after M02-T05 is merged and G has approved the exact text in `.plan/work/M02-T06/proposal.md` (DEC-003); without that approval it stays todo and M02 stays open.
- One commit replaces the notice line with G's approved text verbatim (no other change under `docs/legal/`) and removes the `docs/legal/third-party-notices.md` entry from the exemption list in `tests/test_docs_paths.py`.
- verify: `.venv/bin/python -m pytest tests/test_docs_paths.py && ! grep -n 'third-party-notices' tests/test_docs_paths.py && grep -n 'tenant-bootstrap/vendor/microsoft-skills/skills/mcp-builder/scripts/requirements.txt' docs/legal/third-party-notices.md`
- files: `docs/legal/third-party-notices.md` (G's approved text only), `tests/test_docs_paths.py` (exemption entry only)
