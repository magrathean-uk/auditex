## RESULT REV-KIT-01
status: done
summary:
verdict: changes-required
reviewed: 479195e48556
Nine original findings closed; finding 1 remains open. Three additional defects reproduced.
changes: none
verification: PASS - read-only probes, 16 twin tests, 8 trainer tests, recount and input hashes, interface/trainer hashes, syntax/import checks, AST comparison and v1.3.0 evaluator parity across 435 cases with three response variants. FAIL - four bypass cases below.
risks: Full CPU selftest and filesystem suites skipped because TMPDIR writes are denied; no GPU/Slurm execution; clean-development doctor failed on the lifecycle lock, with no repairs attempted.
questions_for_g: none
### Findings
1. open - kit/20261111-airr-v4/checks/usage.py:193 - A finished attempt hides a later RUNNING requeue with a different start time; accounting still passes. Reconcile every observed start and reject each attempt without a terminal record.
2. closed - kit/20261111-airr-v4/checks/usage.py:283 binds task identity; line 215 rejects duplicate or foreign stages, and line 248 compares each stage separately. Substitution and pooling probes fail.
3. closed - kit/20261111-airr-v4/heldout/twin_definition.py:270 enforces typed-verdict soundness. Recount confirms zero conflicting keys; weakening exact-value policies reproduces conflicts.
4. closed - kit/20261111-airr-v4/bin/kitcheck.py:295 verifies module coverage before executing verified source bytes. The unlisted-module probe fails before execution.
5. closed - kit/20261111-airr-v4/checks/score.py:201 verifies runs before reading measures; unknown kinds and missing expected runs fail. Both kind-tampering probes fail.
6. closed - kit/20261111-airr-v4/trainer/_io.py:118 restores atomic replacement. Repeated existing-record writes pass with OS calls mocked; the resume test covers existing outputs.
7. closed - kit/20261111-airr-v4/heldout/twin_definition.py:166 normalises both interfaces and requires a valid explainer verdict. Interface and missing-verdict probes pass.
8. closed - kit/20261111-airr-v4/heldout/twin_definition.py:235 drops unread sections. Adding or changing an unrelated section preserves the key.
9. closed - kit/20261111-airr-v4/heldout/notes/recount.py:23 checks soundness without requiring oracle_outcome; line 40 records input hashes. Recount completes and matches the saved figures, with its final write captured in memory.
10. closed - kit/20261111-airr-v4/trainer/model_training.py:423 fixes the four-GPU launch; lines 737 and 748 enforce ranks, allocation and visibility before loading weights. Non-writing launch tests pass.
11. new [P1] - kit/20261111-airr-v4/checks/usage.py:97 - Unknown AllocTRES silently becomes zero GPUs, allowing a zero-hours claim to pass. Validate allocation syntax and distinguish explicit CPU-only allocation from missing or unknown GPU accounting.
12. new [P2] - kit/20261111-airr-v4/bin/kitcheck.py:409 and kit/20261111-airr-v4/checks/usage.py:269 - A nonexistent results directory passes with zero checks. Require an existing readable directory before discovery.
13. new [P1] - kit/20261111-airr-v4/heldout/twin_definition.py:236 - Repeating identical evidence with a fresh reference ID changes the twin key. Both oracle rows validate and soundness accepts them, despite unchanged decisive evidence and verdict. Deduplicate projected observations before collapsing singleton containers.
