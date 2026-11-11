## RESULT M06-T03
status: done
summary:
verdict: ready
reviewed: 5843f0b4977c410f484502d424b6151d54d7be94
All 53 scoped DoD items are ticked and supported by evidence.
Both previous gaps are closed; artefact hashes match the candidate gate record.
changes: none
verification:
- PASS: candidate identity, clean worktree, main-only plan changes, ownership coverage, weights totalling 100, 68 cleanup rows, review bindings, re-baseline coverage and expected tags.
- PASS: retained-output comparison, all 43 digests; wheel and sdist SHA-256; archive source parity; Ruff without cache; Python syntax; rule-pack drift; gitleaks; read-only taint checks.
- PASS: release metadata, retirement predicates, acceptance refusal without a valid kit, and in-memory normalisation checks preserving verdicts and explanations.
- Recorded gates: M06-T02 passed on this candidate, including 22620 tests, dependency audit, acceptance, reproducible builds and release smoke.
- Skipped reruns: builds, pytest, acceptance, dependency audit, smoke and HTML peak require writes or heavy execution. Their recorded evidence was reviewed.
- Required storage diagnostic failed on lifecycle-lock ownership; no repair attempted. This is outside release scope.
risks: documented D5 limits; scanner blind spots; remaining validation exclusions.
questions_for_g: none

### Findings

Blocking gaps: none.

1. `scripts/compare-run-outputs.py`: the date-sensitive comparison is fixed. All 43 candidate digests match the baseline from 223fbaa; verdict and explainer changes still compare differently.
2. `.plan/work/REV-M05-T03-privacy/result.md`: the repeated review uses claude-4, separate from the author’s claude-5, and approves the same frozen SHA as Codex.

Sequencing risks: none blocking. DEC-007 records the changed integration order. Publication follows this gate and G’s approval.

Missing DoD items: none within scope. M06 items 7-10 correctly remain pending. Cleanup records and milestone tags hold.

Top 3 uncovered risks:

1. D5 leaves documented name forms readable and uses a guessable run-path salt.
2. Static scanners retain documented rebinding and indirect-call blind spots.
3. Live-provider behaviour remains outside scope; validation retains 273 skips, 34 expected failures and four known explainer mutation misses.

Candidate: 5843f0b4977c410f484502d424b6151d54d7be94

G decides:

1. Go or no-go: explicit yes naming 1.4.0 for the signed tag and GitHub release with the gated wheel and sdist, without PyPI.
2. Accept the documented residual risks and retain the exclusions for live-tenant work, Google baseline expansion and parked backlog work.
