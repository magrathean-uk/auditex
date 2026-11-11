## RESULT VAL-v4
status: done
summary:
verdict: gaps
reviewed: 33457108edb7ef7e2c9d26ff14367ec10bcc8af6
Weights and ownership pass; dependency, evidence and verification gaps block the plan gate.
changes: none
verification:
- PASS: `percent.py --check`; integer weights total 100; 55 DoD items; all 33 tasks have files and verify fields.
- PASS: ownership scan of 845 paths found no unmatched non-test paths or overlapping globs; task verification commands pass `bash -n`.
- PASS: `git diff --quiet v1.4.0 HEAD -- . ':!.plan'`; archived release evidence read; `gitleaks dir . --no-banner --redact`; read-only taint-scan equivalent.
- FAIL: negative budget probes were accepted by all three milestone predicates.
- PASS: final `git diff --check`, index/worktree checks and unchanged HEAD.
- SKIPPED: pytest, builds, acceptance and dependency gates require writes; the exact taint script creates a temporary file.
risks: contract-change regressions; unverifiable research results; false-green budget and publication gates
questions_for_g: none

### Findings

1. `.plan/milestones/M00-foundation.md:17-24` cites `.plan/work/PLAN-v4/evidence.md` for three completed items, but that file is absent from the reviewed commit. Its main-checkout copy exists and was read.
   Fix: commit the cited evidence or move those facts into a tracked result and update the citations.

2. `.plan/milestones/M04-d5-keyed-pseudonyms.md:53` excludes four tests that hard-code the current contract version, so the required version change cannot pass the full suite within its authorised files.
   Fix: add `tests/test_contract.py`, `tests/test_auditex_product.py`, `tests/test_assessment_review.py` and `tests/test_integrity_gate_followups.py` to M04-T03, distinguishing current-version assertions from historical compatibility tests.

3. `.plan/milestones/M02-explainer-data-and-judging.md:47-60` lets M02-T03 consume checks supplied by M02-T04 without depending on it; M02-T04 has no environment prerequisite.
   Fix: require M01-T04 before M02-T04, then M02-T04 before M02-T03, and freeze the checker interface before data generation.

4. `.plan/ARCHITECTURE.md` gives airr-kit no complete runnable verification command; M01-M03 predominantly verify author-written success markers.
   Fix: specify kit commands for the trainer self-test, twin check, calibration and scoring, with artifact hashes and recorded measurements that a reviewer can independently check.

5. The GPU-hour DoD predicates in `.plan/milestones/M01-airr-bring-up.md`, `M02-explainer-data-and-judging.md` and `M03-explainer-training.md` compare usage only with the author's stated denominator. Every predicate accepts `gpu-hours: 4001 of 9999`.
   Fix: compare cumulative usage, including retries, against the approved stage caps and any explicitly approved amendments.

6. `.plan/ARCHITECTURE.md` promises unchanged verdicts and explainer text through digest comparison, but M04-M06 never execute `compare-run-outputs.py --digests`; smoke tests and comparator unit tests do not perform that comparison.
   Fix: add `.venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract` after smoke at the relevant gates; settle random-key handling in M04-T01.

7. `.plan/milestones/M06-release-1-5-0.md:20-22,51-58` checks readiness without candidate equality and remote-tag existence without remote-tag identity; publication and post-publication tasks lack explicit predecessor gates.
   Fix: bind readiness and approval to the full candidate SHA, require M06-T03 before T04 and T04 before T05, and compare the remote tag object and peeled commit with the verified local tag.

8. `.plan/STATE.md` says there are no re-baselines, although archived v3 is 100% and v4 is 4% under changed scope and weights.
   Fix: record the proposed 100%-to-4% transition against DEC-001, then confirm it on scope approval as MANUAL section 8 requires.

9. `.plan/milestones/M05-scanners-and-hygiene.md` embeds a literal backtick inside the deletion predicate's single-backtick Markdown span, breaking the rendered command.
   Fix: use a double-backtick code span. The complete underlying shell command passes syntax checking.

Sequencing risks

- Apply gap 3 before scheduling research workers.
- `.plan/master-plan.md` puts the budget look before M03, while M03-T01 omits it and M03-T02 requires it. Make those prerequisites consistent.
- Track A correctly serialises the broad Ruff change and shared redaction/documentation files; no ownership-glob collision was found.

Missing DoD items

- Actual output-to-baseline comparison, rather than comparator unit tests alone.
- Independently reproducible research checks and accounting against approved caps.
- Candidate-bound readiness and remote-tag identity verification.

Top 3 uncovered risks

1. Contract changes stall verification or weaken compatibility checks because necessary test edits are outside task ownership.
2. Research completion can be declared from success markers without reproducible evidence of calibration, isolation or scoring.
3. Budget and release predicates can report success without proving the approved limits or published identity.
