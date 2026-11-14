## RESULT M06-T03
status: done
summary:
verdict: ready
reviewed: a1c6b5e6e54e1fcc8fb224868a7e8467c723d262
All 33 in-scope DoD items have supporting evidence. No blocking release-gate gaps.
changes: none
verification: PASS read-only DoD predicates, review-binding loops, ancestry, merged-source comparisons, gitleaks, taint equivalent, shipped-content parity, ownership map and artefact hashes; saved heavy-gate logs checked.
risks: stated masking limits; whole-text withholding; thin HTML peak margin
questions_for_g: none

### Findings

1. Non-blocking: `.plan/BACKLOG.md:41` still calls the vocabulary-note sentence unfixed. Mark it closed by DEC-050 and `be9654d`; retain the deferred withholding work.
2. Non-blocking: `.plan/STATE.md:16` still lists M06-T02 as next. Update it to the completed gates and pending release decision.

Missing DoD items: none within scope. M00 is 13/13, M04 8/8, M05 6/6 and M06 items 1-6 are 6/6.

Evidence checked:

- Main HEAD `287bfa153b126afd0137cfcc660902a6db768b87` descends from the candidate; both intervening commits touch only `.plan/`. The candidate worktree is clean.
- `.plan/work/M06-T02/logs/`: all seven steps end with exit 0. Release check records 23,131 passed, 254 skipped, 7 deselected and 34 xfailed.
- Contract smoke matches all 43 digests. Acceptance passes 26,901 replay vectors, 192 contract tests and all explainer acceptance jobs, with zero skips.
- Both reproducible builds match the recorded wheel and sdist hashes. Existing artefacts independently match those hashes and all 206 candidate Python source files. Wheel and sdist release smoke passed base, Google and MCP checks.
- All eight reviewed results bind to their merge trailers; task-owned merged files equal reviewed files. Required provider separation holds.
- Version, security support and changelog claims match the candidate. The vocabulary-note correction is merged; per-unit withholding and model integration are not claimed.
- Gitleaks found no leaks. Path/session scans found no actual workstation paths or session links; remaining path examples are synthetic fixtures or system paths. Shipped-content parity covers 17 areas.
- Every recorded re-baseline has its decision and approver. Cleanup rows contain reasons, evidence and G approval; their commit fields explicitly identify external, non-repository removals. DEC-017 approves retaining the vendored files.

Write-producing suites, builds, benchmark and the original temporary-file taint script were not rerun. Saved evidence and a read-only taint equivalent were used. Progress/result files and the result-file verification predicate await the orchestrator because this sandbox cannot write them.

Sequencing: preserve the candidate and its artefact hashes; retain the documented `.venv` link for subsequent gates. A changelog date correction creates a new candidate requiring refreshed gates and approval. Missing plan-v4 milestone tags and the absent release tag are expected, not gaps.

Top 3 uncovered risks:

1. `docs/reference/security-privacy.md`: documented spellings, initial combinations, mapping keys and scanner limits remain outside coverage; masking is not comprehensive.
2. Rendered reports or pack files can become wholly `<redacted-text>` without explaining why. M04-T06 remains deferred.
3. The final executing check reports HTML peak 717,750,272 bytes against 720,352,051 allowed, approximately 1.146 against 1.15.

Outside this release: Track B, including M03 model research, and M07’s external lab kit. No model ships. Dropped M04-T06 and M07-T02 are not counted.

Candidate: a1c6b5e6e54e1fcc8fb224868a7e8467c723d262

G decides:

1. Go or no-go for 1.5.0 on the candidate above, explicitly authorising the signed tag and GitHub publication.
2. Accept the stated masking limits.
3. Accept whole-text withholding in rendered output.
4. Accept the thin HTML peak benchmark margin.
5. Choose the tag day; the changelog heading’s date must equal it.
