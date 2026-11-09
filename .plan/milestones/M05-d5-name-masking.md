---
id: M05
name: d5-name-masking
weight: 20
status: planned
---
# M05 d5-name-masking
D6 (G): D5 person-name masking is a redesign from current `main`, not a merge of `wt/redact-person-names` or the `wt/d5-*` branches (reference reading only): bounded per-record matching, HTML peak within `main` plus 15 percent, privacy review by both providers. Scope (G, DEC-001): the names of everyone in the run's own directory records, wherever they appear in shareable output. M05-T03 starts after M02, M03 and M04 have merged their edits to the shared redaction, writer and privacy files.

## Goal
Shareable and customer-pack output mask the names of every person in the run's own directory records, in free text and in ids beyond the typed D3 fields, with matching cost bounded per record; an in-repo harness with a frozen, person-bearing workload and an explicit redaction profile proves the HTML report peak on the 90,000-record run stays within the recorded `main` baseline plus 15 percent while masking demonstrably runs; the docs and release notes state exactly what is and is not masked.

## Definition of Done
- [ ] Review: G approved the D5 design (DECISIONS.md entry titled "D5 design", approver G): `grep -A8 '^## DEC-[0-9]* D5 design' .plan/DECISIONS.md | grep -q '^- approver: G'`
- [x] The HTML peak harness runs on the frozen workload with an explicit profile and the baseline from `main` before D5 is committed: `.venv/bin/python -m pytest tests/test_html_peak_harness.py && test -s benchmarks/html-peak-baseline.json && grep -q '"profile": "shareable"' benchmarks/html-peak-baseline.json && grep -q '"workload_sha256"' benchmarks/html-peak-baseline.json`
- [ ] With D5 on, the shareable HTML report of the frozen 90,000-record workload contains no workload person name and its peak is within the baseline plus 15 percent: `.venv/bin/python benchmarks/html_peak.py --records 90000 --profile shareable --baseline benchmarks/html-peak-baseline.json --max-ratio 1.15 --require-masked`
- [ ] Person-name masking, the D3 profiles and the per-record scan budget pass: `.venv/bin/python -m pytest tests/test_redaction_person_names.py tests/test_redaction_profiles_d3.py tests/test_redaction_scan_budget.py tests/test_notify_redaction.py tests/test_redaction_export_schemas.py`
- [ ] Full suite and contract smoke pass: `make test && make contract-smoke`
- [ ] Both acceptance suites, the full v3.9.1 replay included, pass at milestone close: `make acceptance`
- [ ] Review: the privacy reference and the CHANGELOG `[Unreleased]` section state the D5 boundary as implemented and no longer carry the 1.3.0 D6 limit sentence (terra read-through in the plan v3 M05-T04 `result.md`)
- [ ] Review: privacy reviews by both providers approve the plan v3 merge of M05-T03 at the exact merged head (`REV-M05-T03` through the merge gate, `REV-M05-T03-privacy` from the other vendor): `c=$(git log v1.3.0..HEAD --format=%H -1 --grep='^Plan-Task: M05-T03$') && test -n "$c" && s=$(git log -1 --format=%B "$c" | sed -n 's/^Plan-Review: REV-M05-T03 approve \([0-9a-f]\{12,40\}\)$/\1/p') && test -n "$s" && for R in REV-M05-T03 REV-M05-T03-privacy; do grep -q "^reviewed: $s" ".plan/work/$R/result.md" && grep -q '^verdict: approve' ".plan/work/$R/result.md" || exit 1; done` Orchestrator check at close (ARCHITECTURE.md provider binding): the dispatch record names a launcher of the other vendor from the author's.

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M05-T01 | Design D5-v2 masking and freeze the harness interface | sol | M | hard | done |
| M05-T02 | Add the HTML peak harness and record the main baseline | codex | M | - | done |
| M05-T03 | Implement D5-v2 masking per the approved design | codex | L | cross-cutting | review |
| M05-T04 | Update the privacy reference and release notes for D5 | terra | S | - | todo |

## Acceptance criteria
### M05-T01 Design D5-v2 masking and freeze the harness interface
- Read-only; may run alongside M00. Starts from the INV3-d5 notes (main checkout `.plan/work/INV3-d5/notes.md`), `src/azure_tenant_audit/output_redaction.py` on current `main` and the backlog spec in `.plan/archive/plan-v2/BACKLOG.md`; earlier branches are read for lessons only.
- `design.md` section "Harness interface" is written first and frozen before M05-T02 starts: the synthetic workload (90,000 records, fixed seed, the count of directory people and of free-text and id occurrences of their names, its sha256 written as `workload_sha256`), the explicit profile (`--profile shareable`), the measured process and metric (peak resident memory of the child that renders the HTML report through the product path), the JSON fields (`records`, `profile`, `workload_sha256`, `peak_rss_bytes`, `person_names`, `unmasked_name_hits`, `commit`, `python`) and the flags (`--records`, `--profile`, `--baseline`, `--max-ratio`, `--require-masked`, which fails when any workload name appears in the rendered report).
- `design.md` then fixes: discovery of names and ids from the run's own directory records (everyone there, G's ruling), the per-record bounded matching rule and its budget, the key and pseudonym scheme (one helper, or both `output_redaction` and the `scuba_projection` helper documented), every `redact_output` caller that changes, the test plan, and that no bundle field or `CONTRACT_VERSION` changes (a needed change is raised to G).
- It names the false-positive guard (vocabulary, minimum length) and how a name too short or too common to match safely is reported rather than silently left.
- verify: `test -s .plan/work/M05-T01/design.md && grep -q '^## Harness interface' .plan/work/M05-T01/design.md`
- files: `.plan/work/M05-T01/design.md` (no repository file changes)

### M05-T02 Add the HTML peak harness and record the main baseline
- Precondition: the "Harness interface" section of `design.md` is frozen (sol); runs before any D5 code merges.
- `benchmarks/html_peak.py` implements that interface exactly: builds the frozen synthetic workload offline (no tenant, no network), renders the HTML report under the given profile through the product path in a child process, measures its peak resident memory and counts workload names left in the rendered report.
- `benchmarks/html-peak-baseline.json` holds the measurement on `main` before any D5 change with `--profile shareable`, the workload sha256, the commit and the Python version; on `main` `unmasked_name_hits` is above zero, proving the workload carries names.
- `tests/test_html_peak_harness.py` runs the harness at a small record count and checks the JSON fields, that the workload sha256 is stable for a seed, the ratio exit code, and that `--require-masked` fails on a report with a workload name.
- verify: `.venv/bin/python -m pytest tests/test_html_peak_harness.py && .venv/bin/python benchmarks/html_peak.py --records 90000 --profile shareable --baseline benchmarks/html-peak-baseline.json --max-ratio 1.15`
- files: `benchmarks/html_peak.py`, `benchmarks/html-peak-baseline.json`, `tests/test_html_peak_harness.py`

### M05-T03 Implement D5-v2 masking per the approved design
- Precondition: G approved `design.md`; M05-T02 merged; M02-M04 merged.
- Shareable, customer-pack and explainer profiles mask the names of everyone in the run's directory records in free text and ids; the local profile is unchanged; masking is deterministic per run salt; matching cost per record stays within the design budget, proven by `tests/test_redaction_scan_budget.py`.
- `tests/test_redaction_person_names.py` covers names in narrative text, in ids, in exports and in notify payloads, the false-positive guard and the reported unmatched case; existing D3 tests pass unchanged unless `design.md` names the change.
- The harness, unchanged, passes with `--require-masked` against the committed baseline; `benchmarks/` is not edited.
- verify: `.venv/bin/python -m pytest tests/test_redaction_person_names.py tests/test_redaction_profiles_d3.py tests/test_redaction_scan_budget.py tests/test_notify_redaction.py tests/test_redaction_export_schemas.py && make contract-smoke && .venv/bin/python benchmarks/html_peak.py --records 90000 --profile shareable --baseline benchmarks/html-peak-baseline.json --max-ratio 1.15 --require-masked`
- files: `src/azure_tenant_audit/output_redaction.py`, `src/azure_tenant_audit/output_writers.py`, `src/auditex/scuba_projection.py` (pseudonym helper only, if the design unifies it), the `redact_output` callers `design.md` names, `tests/test_redaction_person_names.py`, `tests/test_redaction_profiles_d3.py`, `tests/test_redaction_scan_budget.py`

### M05-T04 Update the privacy reference and release notes for D5
- Runs after M05-T03 merges.
- `docs/reference/security-privacy.md` states the D5 boundary as implemented (everyone in the run's directory records), cites the harness for the peak figures instead of the unreproducible numbers, and documents the pseudonym scheme; `docs/reference/output-contract.md` is unchanged unless G approved a bundle change; `CHANGELOG.md` `[Unreleased]` describes the change and drops the D6 limit for new releases. `result.md` holds the DoD read-through.
- verify: `.venv/bin/python -m pytest tests/test_docs_paths.py`
- files: `docs/reference/security-privacy.md`, `docs/reference/output-contract.md`, `CHANGELOG.md`
