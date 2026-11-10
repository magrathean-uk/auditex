## RESULT M06-T03
status: done
summary:
verdict: gaps
reviewed: 0589f0798f90c5a2010bf83c9d3616ae5a284f0a
All 53 scoped DoD items are ticked, but two evidence gaps block readiness.
Artifact hashes match M06-T02; main differs from the candidate only in .plan/.
changes: none
verification: PASS: candidate identity, clean worktree, ownership coverage, weights totalling 100, 68 cleanup rows, review SHA bindings, re-baseline coverage, expected tags, artifact hashes, archive source parity, Ruff, Python syntax, rule-pack drift, gitleaks and read-only taint checks. FAIL: retained-output digest comparison. Builds, pytest, acceptance, dependency audit and smoke runs were not repeated because they write files or are heavy; M06-T02 records their passes. Required storage doctor failed on lifecycle-lock ownership; no repair attempted.
risks: D5 masking limits; scanner blind spots; unverified live-provider behaviour.
questions_for_g: none

### Findings

1. `scripts/compare-run-outputs.py` and `.plan/milestones/M02-model-layer-retirement.md`: the candidate’s retained outputs fail two of 43 digest comparisons, for `ci-projection-demo/findings/findings.json` and `reports/report-pack.json`. Both match after changing only the certificate-expiry day count from -436 to -435 in memory. Fix the comparison’s clock sensitivity and rerun the baseline-to-candidate proof while preserving verdict checks.

2. `.plan/work/REV-M05-T03-privacy/result.md`: dispatch records and the ledger show that both the final author and final Claude privacy reviewer used `claude-5`, contrary to DELEGATION.md’s different-account requirement. Repeat the Claude privacy review on a different account at the frozen reviewed head and record its approval.

Sequencing risks: DEC-007 records the changed merge order; no additional sequencing gap found. Publication must follow closure of these gaps and G’s approval.

Missing DoD items: none within this gate. M06 items 7-10 correctly remain pending. Expected annotated tags match completed milestones; cleanup approvals and deletion commits hold.

Top 3 uncovered risks:

1. D5 leaves documented name forms readable and uses a guessable run-path salt.
2. Static scanners retain documented rebinding and indirect-call blind spots.
3. Live-provider behaviour remains outside scope; the recorded release suite includes 273 skips and 34 expected failures.

Candidate: 0589f0798f90c5a2010bf83c9d3616ae5a284f0a

G decides:

1. After the gaps close, go or no-go with explicit approval naming 1.4.0 for the signed tag and GitHub release, without PyPI.
2. At that decision, accept the documented residual risks and continued exclusion of live-tenant work, Google baseline expansion and parked backlog work.
