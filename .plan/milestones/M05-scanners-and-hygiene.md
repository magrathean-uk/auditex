---
id: M05
name: scanners-and-hygiene
weight: 10
status: done
---
# M05 scanners-and-hygiene
Track A, after M00. M05-T01 and M05-T02 may run in parallel with each other and with M04 (disjoint files). The merge bar for both scanner tasks is set here, before any work, as v3 DEC-008 and DEC-009 did: the named limits closed for planted cases plus the fail-closed rule; any further bypass class a review finds is a named limit, not a blocker. Two repair rounds, then re-scope.

## Goal
The read-boundary and HTTP scanner limits named in v3 DEC-008 and DEC-009 are closed for planted cases under the fail-closed rule, the privacy reference lists only what stays open, the small plan v3 review follow-ups are closed, and the vendored microsoft-skills entries are settled by G's deletion-gate decision.

## Definition of Done
- [x] Both scanners pass with a planted case for every limit they close: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_http_verb_allowlist.py`
- [x] Review: an other-vendor review approves the plan v4 merges of M05-T01 and M05-T02 at the exact merged head (ARCHITECTURE.md review binding): `for T in M05-T01 M05-T02; do c=$(git log v1.4.0..HEAD --format=%H -1 --grep="^Plan-Task: $T\$") && test -n "$c" && s=$(git log -1 --format=%B "$c" | sed -n "s/^Plan-Review: REV-$T approve \([0-9a-f]\{12,40\}\)\$/\1/p") && test -n "$s" && grep -qE "^[[:space:]]*(summary: )?reviewed: $s" ".plan/work/REV-$T/result.md" && grep -qE '^[[:space:]]*(summary: )?verdict: approve' ".plan/work/REV-$T/result.md" || exit 1; done` Orchestrator check at close: the dispatch record names a launcher of the other vendor from the author's.
- [x] Review: the limits tables in the privacy reference list only limits left open, each with its planted test or the word "named limit", and scanner citations say "v2 DEC-011" (terra read-through): `grep -qx 'read-through: complete' .plan/work/M05-T03/result.md`
- [x] The plan v3 review follow-ups are closed: no "model view" wording for the projection, no dead `names` parameter on `Redactor.text`, and the follow-up tests pass: `! grep -rqi 'model view' docs src && ! grep -q 'def text(self.*names' src/azure_tenant_audit/output_redaction.py && .venv/bin/python -m pytest tests/test_compare_run_outputs.py tests/test_check_reproducible_build.py tests/test_redaction_person_names.py`
- [x] The vendored microsoft-skills entries are settled by G's deletion-gate decision, and every path it approved for removal is gone: ``d=$(sed -n 's/^## \(DEC-[0-9]*\) M05 deletion gate.*/\1/p' .plan/DECISIONS.md) && test -n "$d" && P=$(awk -F'|' -v d="$d" '{gsub(/[ `]/,"",$2); gsub(/ /,"",$5)} $5==d {print $2}' .plan/CLEANUP.md) && for p in $P; do test ! -e "$p" || exit 1; done`` (evidence: DEC-017, G on 12 Nov 2026: keep all eight; no CLEANUP.md row, command exit 0)
- [x] Full suite, contract smoke, the digest comparison and both acceptance suites pass at milestone close: `make test && make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract && make acceptance`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M05-T01 | Close the read-boundary scanner limits from v3 DEC-008 | codex | M | hard | done |
| M05-T02 | Close the HTTP scanner attribute-store limit from v3 DEC-009 | codex | M | - | done |
| M05-T03 | Update the scanner limits tables in the privacy reference | terra | S | - |done |
| M05-T04 | Close the plan v3 review follow-ups | codex | M | - | done |
| M05-T05 | Confirm the vendored microsoft-skills entries and bring the deletion gate | terra | S | - | done |

## Acceptance criteria
### M05-T01 Close the read-boundary scanner limits from v3 DEC-008
- Merge bar (set before the work): any callee name the module rebinds (def, class, assignment, import) is unresolved for the read-only hand-off and transparent-conversion shortcuts, with planted cases for the `info` and `list` shadows (today only the nearest test exists); the binding union includes import, plain `with`, `def`, `class`, `except`, `match` and comprehension-walrus bindings; class-body names resolve in the class namespace. Each closed limit has a planted test; the fail-closed proven-literal rule stays. A further class found by review is a named limit for M05-T03.
- Test citations of the scanner decision read "v2 DEC-011" (the live "DEC-011" is the 1.4.0 release).
- Tier A (security): one provider authors and the other reviews (amended by DEC-012: Opus authored, Codex reviews; the plan first named Codex as author).
- verify: `.venv/bin/python -m pytest tests/test_read_boundaries.py && make test`
- files: `tests/test_read_boundaries.py`

### M05-T02 Close the HTTP scanner attribute-store limit from v3 DEC-009
- Merge bar (set before the work): a dotted import origin is trusted only when the module makes no attribute store to it, so `pathlib.Path = factory` followed by `pathlib.Path().open(...)` is unresolved and fails the suite, with a planted case; the fail-closed rule stays; a further class found by review is a named limit for M05-T03.
- Test citations of the scanner decision read "v2 DEC-011".
- Tier A (security): one provider authors and the other reviews (amended by DEC-012: Opus authored, Codex reviews; the plan first named Codex as author).
- verify: `.venv/bin/python -m pytest tests/test_http_verb_allowlist.py && make test`
- files: `tests/test_http_verb_allowlist.py`

### M05-T03 Update the scanner limits tables in the privacy reference
- Preconditions: M05-T01, M05-T02 and M04-T05 merged (shared file).
- The read-boundary and HTTP limits tables in `docs/reference/security-privacy.md` drop closed limits, point each remaining row at its planted test or mark it "named limit", and cite "v2 DEC-011"; writes `read-through: complete` under `### Findings` after checking each row against the tests.
- verify: `grep -qx 'read-through: complete' .plan/work/M05-T03/result.md`
- files: `docs/reference/security-privacy.md` (scanner limits section only)

### M05-T04 Close the plan v3 review follow-ups
- Preconditions: M04-T04 merged (shared `output_redaction.py`), M04-T05 and M05-T03 merged (shared docs).
- `bundle_integrity.py` no longer lists `model_assessment_prompts.jsonl` as an output new runs write, while bundles that carry it still validate (test); `Redactor.text` loses the dead `names` parameter and its three call sites; `_is_privileged_user` (no caller) is removed; "model view" becomes "projection" (or "projected view") everywhere `grep -rni 'model view' docs src` finds it: four docs, the `output_writers.py` registry descriptions and the comments in `scuba_projection.py` and `value_rules/defender_targeted_users.py`.
- `scripts/compare-run-outputs.py` validates the baseline's run and artefact inventory (the date-derived `expiry_state` and the docstring pointer were fixed in M00-T05); the reproducible-build test varies only the field it means to test (REV-M01-T01); D5 test names do not cite review rounds.
- Added by DEC-050: the fixed sentence of the redaction note about vocabulary words (`unmatched_names_note` in `output_redaction.py`) says what the code does and what the privacy reference states: a person whose name is a vocabulary word is still masked in values and free text; only that sentence changes, and the test that pins it is updated with it.
- No behaviour change beyond these; the contract-smoke outputs match the recorded digests unchanged.
- verify: `! grep -rqi 'model view' docs src && .venv/bin/python -m pytest tests/test_compare_run_outputs.py tests/test_check_reproducible_build.py tests/test_redaction_person_names.py && make test && make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract`
- files: `src/azure_tenant_audit/bundle_integrity.py`, `src/azure_tenant_audit/output_redaction.py`, `src/auditex/scuba_projection.py` (comments only), `src/auditex/output_writers.py` (description strings only), `src/azure_tenant_audit/value_rules/defender_targeted_users.py` (docstring only), `scripts/compare-run-outputs.py`, `tests/test_compare_run_outputs.py`, `tests/test_check_reproducible_build.py`, `tests/test_redaction_person_names.py` (test names, and the assertion that pins the note sentence, DEC-050), the bundle-integrity test it adds or extends (named in `result.md`), `docs/reference/output-contract.md`, `docs/reference/security-privacy.md` (wording only), `docs/guides/admin-permission-guide.md`, `docs/development/scubagear-export-adapter.md` (wording only)

### M05-T05 Confirm the vendored microsoft-skills entries and bring the deletion gate
- Read-only. Confirms whether `NOTICE`, `docs/legal/third-party-notices.md` and `docs/provenance/provenance.csv` name the directory only or the entries (INV4-hygiene: directory only), whether any code, script or doc uses ALL-SKILLS-CATALOG, microsoft-foundry or entra-agent-id, and whether removing them changes any G-owned legal text.
- Writes the exact path list with a recommendation (remove or keep) for G; the orchestrator records G's answer as `## DEC-nnn M05 deletion gate` and one CLEANUP.md row per approved path. When G approves removal, the orchestrator dispatches the removal as a follow-up task with exactly those rows; legal text changes only verbatim as G approves.
- verify: `test -s .plan/work/M05-T05/result.md`
- files: `.plan/work/M05-T05/result.md`
