## RESULT M07-T06
status: done
summary: Repair 1 is done in kit/20261111-kit-7p/dt-r7p and frozen as kit/20261111-kit-7p/dt-r7p-ro2. Teams is no longer shared: the opener has no -Teams and 40-teams always signs in itself. The opener now owns what it opens (Exchange, S&C, and Graph when its sign-in started it). It closes everything owned on -Disconnect or on any failure, and leaves a CLOSED record. While that record or the opener's seal is in a window, 10 -Apply -Enforce, 90-verify and 99-rollback refuse to run there. In any window they also refuse a Graph context that existed before their own sign-in. A failed close is an error and the connection stays owned, so -Disconnect can retry it.
The opt-in record is accepted only with its exact shape, this process's id and the seal the opener left in the process; anything else is refused as NOT OPENED HERE. LIMITS.md says code typed by hand in the window can still forge it. A customisation refusal counts as definite only on the full signature recorded in TRIAL-FACTS. The first lookup's candidate or error is what the journal keeps. All advisories are cleared. Full write-up: kit/20261111-kit-7p/ROUND-7P.md, "Repair 1".
changes: 10 kit files changed since the review: BLUEPRINT.md, LIMITS.md, TRIAL-FACTS.md, populate/00-identity.ps1, populate/README.md, populate/_common.ps1, tools/Connect-DtShared.ps1, tools/Test-KitConstructs.ps1, tools/mock-harness/Cases-Round7p.ps1, tools/mock-harness/MockTenant.ps1. tools/shape-lint-allowlist.txt also changed (one reviewed entry); it is outside that count. New: kit/20261111-kit-7p/dt-r7p-ro2, MANIFEST-2.sha256 and old-proof-r1 (the reviewed copy plus the repaired harness). Also: ROUND-7P.md, and .plan/work/M07-T06/notes.md and evidence.md.
verification: Driver --quick on dt-r7p: pass. Log in kit/20261111-kit-7p/quick-r1-2: 7 steps, 332 tests, shape lint 0 not allowlisted, constructs 0 findings, no wildcard. Its first run failed shape lint; fixed. Round-7p cases: 45 of 45 pass (runs/r1-new-w7p-3). New cases on the pre-repair copy: 11 of 11 fail (runs/r1-old-w7p-2). Regression of at-risk existing cases: 7b 27 of 27 pass; worker files 140 of 144 pass. The 4 others stop because a helper from Cases-Round7b.ps1 is not loaded in a file-by-file run, and they stop the same way on dt-r7p-ro. dt-r7l6-ro (365) and dt-r7p-ro (367) match their manifests, dt-r7p-ro2 matches MANIFEST-2 (367), and the live kit and repository are unchanged.
risks: The live refusal text was never seen on the trial tenant; if it differs, the kit leaves the intent open (the safe side) and TRIAL-FACTS says to record it. The full mock run and Cases-Round7.ps1's top-level preflight sweep were not run by me. To mimic the README's new window for 10, 90 and 99, the mock harness reads two of the kit's variables.
questions_for_g: none
### Findings
quick-checks: pass
files-changed-since-review: 10
new-cases: 11 (plus 1 strengthened: W7p-shared-token-reused-by-30)
new-cases-fail-on-pre-repair: 11 (the strengthened token case passes there: that code already reused the token without a sign-in)
reuse-paths-removed: Teams session reuse (opener -Teams, Use-DtSharedTeams); reuse of an existing Graph context by 10 -Apply -Enforce, 90-verify and 99-rollback
frozen: kit/20261111-kit-7p/dt-r7p-ro2 c5186ecce494 367
full-suite-command: cd kit/20261111-kit-7p && bash check-suite-7l.sh --snapshot dt-r7p-ro2 --manifest MANIFEST-2.sha256 --repo <auditex checkout> dt-r7p full-r1 <OPA 1.20.2 binary> <ScubaGear 2446ad7 checkout>
codex-1 scope: clean in review, no change
codex-2 Teams reuse asserts the recorded account: closed, Teams removed from the shared set (W7p-r1-teams-never-reused)
codex-2 a planted dictionary is accepted as opt-in: closed, record bound to this process and the opener's seal (W7p-r1-record-not-opened-here); limit stated in LIMITS section 7
codex-3 a bare substring classifies the refusal: closed, full signature only (W7p-r1-dehydrated-signature-unit, W7p-r1-dehydrated-timeout-keeps-intent)
codex-3 the first lookup is overwritten: closed, one journalled observation (W7p-r1-dehydrated-failed-lookup-journals-first, W7p-r1-dehydrated-changing-lookup-journals-first)
codex-4 Agent 365: clean in review, no change
codex-5 TeamsModuleVersion: clean in review, no change
codex-6 tests: closed, the 11 new cases plus the strengthened token case
codex-7 workstation paths: closed in BLUEPRINT, TRIAL-FACTS and LIMITS; paths in make_blueprint.py, test_compare.py, Run-Mock.ps1 and MockTenant.ps1 are outside the brief and remain
codex-8 Graph not closed, so fresh callers reuse it: closed, closed record plus FRESH SIGN-IN REQUIRED (W7p-r1-disconnect-closes-graph-and-keeps-refusal, W7p-r1-fresh-caller-refuses-old-graph-context)
codex-8 opener failures leave connections nobody owns: closed, ownership recorded in finally and everything closed on failure (W7p-r1-opener-partial-failure-no-unowned)
codex-8 opener disconnects a replaced Teams session: closed, no Teams in the opener; Graph closed only when provably its own
opus-1 scope: clean in review; the stop on any refused modify is kept (now only on the signature); README explains the example config's Teams pin
opus-2a Graph not closed and fresh guard cleared: closed (same two cases as codex-8); a failed close is now an error (W7p-r1-failed-close-keeps-refusal)
opus-2b Teams reuse: closed (W7p-r1-teams-never-reused)
opus-2c Exchange and token reuse: clean in review, kept and re-proven through the opener
opus-3 no case for the failed-lookup branch: closed (W7p-r1-dehydrated-failed-lookup-journals-first)
opus-4 00-identity points to retired check 27: closed (W7p-r1-docs)
opus-5 stale "newest installed" comment: closed (W7p-r1-docs)
opus-6 token case lacks a direct no-sign-in check, version case installs two versions: closed; the tampered-record Teams case was replaced
opus-7 LIMITS workstation path: closed (W7p-r1-docs)
opus-8 LIMITS lacks the one-way hand-run enable step: closed (W7p-r1-docs)
