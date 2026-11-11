---
id: M04
name: d5-keyed-pseudonyms
weight: 18
status: planned
---
# M04 d5-keyed-pseudonyms
Track A. G approved the keyed per-run pseudonym scheme for 1.5.0 as its own milestone, with a privacy review by both providers (gate answers). That approves the bundle and `CONTRACT_VERSION` change in principle (v3 DEC-004); the design goes to G before implementation. M04-T01 may run during M00; M04-T02 onwards waits for M00.

## Goal
Pseudonyms in shareable output come from a private per-run key instead of the run-path salt, so someone holding a shared report who knows or guesses the run folder name can no longer confirm a guessed name; the salt schemes are unified or each is documented; names written with middle initials or titles, and structural mapping keys equal to a person's name, are masked or counted within the same probe budget; the bundle contract, schemas and docs change together under a new `CONTRACT_VERSION`.

## Definition of Done
- [x] Review: G approved the keyed-pseudonym design (DECISIONS.md entry "D5 keyed pseudonym design", approver G, naming one digest strategy) after both providers reviewed it: `grep -A10 '^## DEC-[0-9]* D5 keyed pseudonym design' .plan/DECISIONS.md | grep -q '^- approver: G' && grep -A10 '^## DEC-[0-9]* D5 keyed pseudonym design' .plan/DECISIONS.md | grep -qE '^- digest-strategy: (seed|normalise)$'`
- [ ] Keyed pseudonyms, the D3 profiles, the scan budget, the projection and the export pass, including the new keyed-pseudonym tests: `.venv/bin/python -m pytest tests/test_redaction_keyed_pseudonyms.py tests/test_redaction_person_names.py tests/test_redaction_profiles_d3.py tests/test_redaction_scan_budget.py tests/test_notify_redaction.py tests/test_redaction_export_schemas.py tests/test_scuba_projection.py tests/test_scubagear_export.py`
- [ ] `CONTRACT_VERSION` differs from 1.4.0's and contract smoke passes with the new schemas: `test "$(git show v1.4.0:src/azure_tenant_audit/contracts.py | grep '^CONTRACT_VERSION')" != "$(grep '^CONTRACT_VERSION' src/azure_tenant_audit/contracts.py)" && make contract-smoke`
- [ ] Middle initials, titles and name-equal mapping keys are masked or counted within the probe budget: `.venv/bin/python -m pytest tests/test_redaction_person_names.py tests/test_redaction_scan_budget.py -k 'initial or title or mapping_key or budget'`
- [ ] With the new scheme on, the shareable HTML report of the frozen 90,000-record workload contains no workload person name and its peak is within the baseline plus 15 percent: `.venv/bin/python benchmarks/html_peak.py --records 90000 --profile shareable --baseline benchmarks/html-peak-baseline.json --max-ratio 1.15 --require-masked`
- [ ] Full suite, contract smoke, the digest comparison and both acceptance suites pass at milestone close: `make test && make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract && make acceptance`
- [ ] Review: privacy reviews by both providers approve the plan v4 merges of M04-T03 and M04-T04 at the exact merged head (ARCHITECTURE.md review binding): `for T in M04-T03 M04-T04; do c=$(git log v1.4.0..HEAD --format=%H -1 --grep="^Plan-Task: $T\$") && test -n "$c" && s=$(git log -1 --format=%B "$c" | sed -n "s/^Plan-Review: REV-$T approve \([0-9a-f]\{12,40\}\)\$/\1/p") && test -n "$s" && for R in REV-$T REV-$T-privacy; do grep -qE "^[[:space:]]*(summary: )?reviewed: $s" ".plan/work/$R/result.md" && grep -qE '^[[:space:]]*(summary: )?verdict: approve' ".plan/work/$R/result.md" || exit 1; done || exit 1; done` Orchestrator check at close: the two reviews ran on launchers of different vendors, one of them the other vendor from the author's.
- [ ] Review: the privacy reference and the output contract describe the keyed scheme, every remaining salt scheme and the new masking boundary, and no longer carry the confirm-a-guess limit (terra read-through): `grep -qx 'read-through: complete' .plan/work/M04-T05/result.md`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M04-T01 | Design the keyed per-run pseudonym scheme | sol | M | - | done |
| M04-T02 | Record the pre-change HTML peak baseline and confirm the digests | codex | S | mechanical | todo |
| M04-T03 | Implement keyed per-run pseudonyms and the contract change | codex | L | cross-cutting | todo |
| M04-T04 | Mask middle initials, titles and name-equal mapping keys | codex | M | - | todo |
| M04-T05 | Document the keyed scheme and the masking boundary | terra | S | - | todo |

## Acceptance criteria
### M04-T01 Design the keyed per-run pseudonym scheme
- Read-only. Covers: key generation (random, per run), where the key lives (recommended: a non-shareable file in the run folder, excluded from reports, customer packs, exports, notifications and MCP outputs, so re-rendering and compare stay stable; the alternative, memory only, is weighed), the pseudonym function (keyed HMAC-SHA256, output length unchanged or justified), compare and drift across two runs (today the first run's salt wins), bundles from 1.4.0 and earlier, what happens when a run folder is copied or moved, and how `make contract-smoke` and the digest comparison stay deterministic under a random key (recommended: the smoke pre-seeds the key file in each run folder through the same path a re-render reads, so no test-only flag or code path exists; the alternative, normalising pseudonym values in the comparator, is weighed).
- Names exactly one digest strategy, `seed` or `normalise`, with the files it needs from the closed sets in ARCHITECTURE.md (engine to product interface); the orchestrator writes the pick as `- digest-strategy: <name>` in G's design DEC, and that line is what authorises the strategy's files in M04-T03.
- Settles the three salt schemes (`output_redaction.py` run path, `scuba_projection.py` manifest digest, `scubagear_export.py` purpose digest): unify, or keep each with a documented reason.
- Fixes the interface M04-T03 implements (function names, the `RedactionContext` change, schema const replacing `run-salted-sha256-v1`, the new `CONTRACT_VERSION`) and the test list, including a test that knowing the run path no longer reproduces a pseudonym.
- Writes the design to `.plan/work/M04-T01/design.md`; `result.md` summarises it. Then codex and sol review it (`REV-M04-T01`, `REV-M04-T01-sol`), and the orchestrator brings it to G.
- verify: `test -s .plan/work/M04-T01/result.md`
- files: `.plan/work/M04-T01/design.md`, `.plan/work/M04-T01/result.md`

### M04-T02 Record the pre-change HTML peak baseline and confirm the digests
- Precondition: M00 done (M00-T05 made the digest comparison pass). Before any M04 code change, records `benchmarks/html-peak-baseline.json` on the frozen workload with the shareable profile, on the current `main`, and confirms the contract-smoke outputs match the recorded digests without refreshing them.
- No other change; `make contract-smoke`, the digest comparison and `tests/test_html_peak_harness.py` pass.
- verify: `.venv/bin/python -m pytest tests/test_html_peak_harness.py tests/test_compare_run_outputs.py && make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract`
- files: `benchmarks/html-peak-baseline.json`

### M04-T03 Implement keyed per-run pseudonyms and the contract change
- Preconditions: G's DEC entry approves the M04-T01 design; M04-T02 merged.
- Implements the design exactly; any deviation stops the task for a design note. Knowing the run path does not reproduce any pseudonym; the key never appears in a report, pack, export, notification, MCP output or log; a 1.4.0 bundle still reads (compare and drift between a 1.4.0 and a 1.5.0 run behave as the design says).
- `CONTRACT_VERSION`, the schema const and `docs/reference/output-contract.md` change together; `tests/fixtures/contract-smoke-digests.json` is refreshed with `--write` and changes only for artefacts that carry pseudonyms, each listed in `result.md` with the reason, and the digest comparison passes on the result.
- The digest strategy in G's design DEC decides the extra files. `seed`: `Makefile` (contract-smoke target only) writes each smoke run's key file through the same path a re-render reads, and `tests/test_redaction_keyed_pseudonyms.py` proves a seeded key reproduces identical pseudonyms while a missing key yields a fresh random one. `normalise`: `scripts/compare-run-outputs.py` normalises pseudonym values only, and `tests/test_compare_run_outputs.py` proves a changed pseudonym compares equal while any other changed value still fails. The other strategy's files stay untouched (checked in verify).
- Tests that assert the current contract version move to the new one: `tests/test_contract.py:36`, `tests/test_auditex_product.py:185` and `:282`, `tests/test_assessment_review.py:202` and `tests/test_integrity_gate_followups.py:525` (line numbers at `v1.4.0`; `result.md` lists the final lines). Historical-compatibility tests that build older bundles (`2026-04-21`, `2026-10-20`, `2026-10-22`) keep their literals unchanged; no deleted line of the branch diff carries one of them.
- Tier A: codex authors; terra or sol reviews (`REV-M04-T03`) and the other vendor runs the privacy review (`REV-M04-T03-privacy`).
- verify: `s=$(grep -A10 '^## DEC-[0-9]* D5 keyed pseudonym design' .plan/DECISIONS.md | sed -n 's/^- digest-strategy: \([a-z]*\)$/\1/p' | head -1) && case "$s" in seed) x='^(scripts/compare-run-outputs\.py|tests/test_compare_run_outputs\.py)$';; normalise) x='^Makefile$';; *) false;; esac && ! git diff --name-only main...HEAD | grep -qE "$x" && .venv/bin/python -m pytest tests/test_redaction_keyed_pseudonyms.py tests/test_redaction_person_names.py tests/test_redaction_profiles_d3.py tests/test_redaction_scan_budget.py tests/test_scuba_projection.py tests/test_scubagear_export.py tests/test_contract.py tests/test_auditex_product.py tests/test_assessment_review.py tests/test_integrity_gate_followups.py tests/test_compare_run_outputs.py && make test && make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract && ! git diff main...HEAD -- tests | grep -qE '^-.*"2026-(04-21|10-20|10-22)"'`
- files: `src/azure_tenant_audit/output_redaction.py`, `src/azure_tenant_audit/contracts.py`, `src/azure_tenant_audit/run_files.py`, `src/azure_tenant_audit/bundle_integrity.py` (key-file exclusion only), `src/auditex/scuba_projection.py`, `src/auditex/scubagear_export.py`, `src/auditex/reporting.py`, `src/auditex/output_writers.py`, `src/auditex/notify.py`, `src/auditex/mcp_server.py` (only if it passes the context), `schemas/model_assessment.schema.json` and a new dated schema copy, `docs/reference/output-contract.md`, `tests/test_redaction_keyed_pseudonyms.py`, `tests/test_redaction_person_names.py`, `tests/test_scuba_projection.py`, `tests/test_scubagear_export.py`, `tests/test_contract.py`, `tests/test_auditex_product.py`, `tests/test_assessment_review.py` and `tests/test_integrity_gate_followups.py` (current-version assertions only), `tests/fixtures/contract-smoke-digests.json`; by the DEC's `digest-strategy` only: `Makefile` (contract-smoke target only) for `seed`, or `scripts/compare-run-outputs.py` and `tests/test_compare_run_outputs.py` for `normalise`

### M04-T04 Mask middle initials, titles and name-equal mapping keys
- Precondition: M04-T03 merged.
- "John A. Smith" and "Dr. Jane Doe" (and the title list the task states) are masked in free text; a structural mapping key equal to a person's name is masked or counted in the note; probes stay at most tokens x 6 and the window at most 6 (budget tests unchanged or tightened); the HTML peak check passes.
- Tier A, reviewed as M04-T03 (`REV-M04-T04`, `REV-M04-T04-privacy`).
- verify: `.venv/bin/python -m pytest tests/test_redaction_person_names.py tests/test_redaction_scan_budget.py tests/test_redaction_profiles_d3.py && .venv/bin/python benchmarks/html_peak.py --records 90000 --profile shareable --baseline benchmarks/html-peak-baseline.json --max-ratio 1.15 --require-masked`
- files: `src/azure_tenant_audit/output_redaction.py`, `tests/test_redaction_person_names.py`, `tests/test_redaction_scan_budget.py`

### M04-T05 Document the keyed scheme and the masking boundary
- Precondition: M04-T04 merged.
- `docs/reference/security-privacy.md` describes the keyed scheme, every salt scheme left after M04-T01, the masking boundary with middle initials, titles and mapping keys, and drops the confirm-a-guess limit; `docs/development/scubagear-export-adapter.md` salt lines match the code. Writes `read-through: complete` under `### Findings` after reading both against the code.
- verify: `grep -qx 'read-through: complete' .plan/work/M04-T05/result.md`
- files: `docs/reference/security-privacy.md` (D5 and salt sections), `docs/development/scubagear-export-adapter.md`
