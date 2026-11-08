## RESULT M03-T04
status: done
summary:
verdict: gaps
reviewed: d9f050f1be6b4ce9c04d8a7caa7e493c22546a8c
Candidate checks and artefact hashes pass; three plan-record gaps remain.
Reviewed main’s plan at 3742f27; subsequent changes affect only .plan/.
G’s replay waiver in DEC-017 is honoured.
changes: none
verification:
- PASS: percent.py --check; integer weights total 100; all pre-publication prerequisite items ticked.
- PASS: 121 read-only pytest checks covering docs, HTTP/read boundaries, MCP and shipped-content parity; conftest and cache writes disabled.
- PASS: rule-pack drift, synthetic-example regeneration check, gitleaks, version/security checks, ownership coverage and task files/verify fields.
- PASS: both retained artefact SHA256 hashes; four cross-vendor review bindings; annotated plan-v2 and M00-M02 tags and ancestry.
- PASS: inspected candidate logs recording release-check with 23,714 passed, zero failures; acceptance with six passed and the DEC-017 skip.
- FAIL: M00-T04 branch-count verification, 45 branches versus 44 recorded rows.
- SKIPPED: full suites, builds, smoke and dependency-audit reruns because they require writes; existing evidence inspected.
risks: Full replay unverified under DEC-017; static-scanner blind spots; D3 retains some identifying text.
questions_for_g: Acceptance of DEC-011 scanner limitations for this release, as below.

### Findings

1. `.plan/STATE.md`, `.plan/master-plan.md`, `.plan/milestones/M03-release-1-3-0.md`: DEC-017 waives the full replay, but acceptance wording still claims full completion and STATE lacks its re-baseline.
   Fix: record `from 84% to 86% (DEC-017)` and describe six passes plus the approved replay skip consistently.

2. `.plan/ARCHITECTURE.md`, `.plan/master-plan.md`, `.plan/milestones/M01-boundary-proof.md`: unconditional transport, content-read and read-only-scope claims omit recorded exceptions and scanner limitations.
   Fix: incorporate DEC-006/008/010/011, distinguishing request exclusion, read-and-discard, accepted write-capable scopes and bounded scanner coverage.

3. `.plan/work/M00-T04/result.md`: branch triage omits `wt/github-build-tags-*` at `6ded82a`, whose changes introduce tagging workflows; the prescribed count check fails.
   Fix: add a reviewed disposition. Post-1.3.0 deferral matches the existing hosted-CI non-goal.

Sequencing risks:
- Publication still depends on a ready gate and G’s explicit approval naming 1.3.0; downloaded-asset verification follows publication.
- The candidate remains unchanged by main’s later plan checkpoints.

Missing DoD items:
- No success criterion lacks a milestone. M03 item 7 is this gate; items 8-11 belong to approval and publication.
- CLEANUP.md has no rows, and no tracked files were deleted since plan-v2, so no deletion approval or commit entry is missing.

Top 3 uncovered risks:
1. The full 26,898-vector replay remains unverified; G accepted this in DEC-017 and restoration is backlogged.
2. Static scanners miss documented dynamic call patterns; passing tests do not establish universal coverage.
3. D3 leaves person names in free text and some identifiers visible, as disclosed in the release notes.

Candidate: d9f050f1be6b4ce9c04d8a7caa7e493c22546a8c

G decides:
1. Go or no-go for the signed v1.3.0 tag and GitHub release carrying the verified wheel and sdist. Recommendation: no-go until the three record gaps close.
2. Whether DEC-011’s remaining scanner limitations are acceptable for 1.3.0 or require further fixes. DEC-017’s replay waiver already has approval.
