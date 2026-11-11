## RESULT REV-M04-T01-sol
status: done
summary: verdict: changes-required
  reviewed: 90866740c48d
  All 16 first-round findings are closed. Making `PseudonymKeyError` a subclass of `UnsafeRunFileError` does stop errors being swallowed: `rule_assessment.py:344` and `reporting.py:604` both re-raise it first. The hash-manifest schema gap is real.
  Three small new defects: the key-creation steps can fail or split one person's pseudonyms on some storage, one privacy-doc passage is missing from M04-T05's list, and local renders of old runs also need the key. All three are text edits; checking those edits is enough, no full re-review.
changes: .plan/work/REV-M04-T01-sol/evidence.md only (round 1 notes.md left as it was)
verification: read-only review at 6c8c3c5; sha256 of design.md checked; one scratch test of directory fsync and flock on both volumes (both work); no builds or tests run
risks: (1) Section 13's claim that it lists every test failure rests on a prototype that left out creating the key on first use and the HMAC change. Hand-built test runs now get operator-inputs/ on their first render, so a test that pins a run's files could stop M04-T03 outside that list. (2) Directory fsync on network file systems was not tried.
questions_for_g: none beyond the design's Q1 and Q2; recommendations below
### Findings
- R1-1 closed (3.5, 3.6, test 9). The answer on cli_guard.py is accepted: `_PRIVATE_NAMES` (104, 144-150) only chooses how a refusal is worded.
- R1-2 closed (3.4 step 2, 3.5, test 7)
- R1-3 closed (7; both sites re-raise `UnsafeRunFileError` before their broad handler)
- R1-4 closed (3.4 steps 3-7, 3.5, tests 5-6); remaining edge cases in N1
- R1-5 closed (3.3 option A, 12 mcp_registry, 13 M04-T05, Q2; no test pins the description)
- R1-6 closed (11, Q1 digest-exception with the label-revert proof)
- R1-7 closed (10, 13, Q1)
- R1-8 closed (1)
- R2-1 closed (3.4 steps 4, 6, 7); edge cases in N1
- R2-2 closed (7)
- R2-3 closed (13)
- R2-4 closed (3.3, 13)
- R2-5 closed (2)
- R2-6 closed (1)
- R2-7 closed (8, 10)
- R2-8 closed (a: 6; b: 4; c: 3.4 step 1; d: test 8; e: 7)
- R2-9 closed (11; the seed still holds with the replace step)
- N1, section 3.4 steps 6-7 and the fallback without flock (correctness):
  - Nothing in src fsyncs a directory today. Some file systems answer EINVAL or EBADF, and under option A that would fail every finalisation there. Fix: ignore EINVAL, EBADF and ENOTSUP from `fsync(folder_fd)`, as PostgreSQL does.
  - A reader that sees 32 bytes reads without the lock, so it can use a key that step 7 later removes after a failed fsync. The next run of the key-creation step then makes a new key, so the same person gets different pseudonyms with no warning. Fix: a reader with no registered key takes `LOCK_SH` (same 2 s limit, then `busy`) before its first read, and the key is never removed once its own fsync has succeeded.
  - Without flock, step 4 can delete another process's finished key that is already in use. Fix: remove a 0-byte key only while holding `LOCK_EX`; without flock, wait out the limit and answer `busy`.
- N2: section 13's M04-T05 list misses security-privacy.md:287-288 ("... AI context and salt, have a 32 MiB limit"). Fix: add it.
- N3: sections 3.3 and 8 and Q2 say "first shareable derivation", but `context_for_run` does not depend on the output profile:
  - `load_report_bundle` calls it even for local reports (reporting.py:589-590);
  - `redact_payload` calls it for `PROFILE_LOCAL` too (output_redaction.py:1905).
  - So a local report of a 1.4.0 run also writes the key, and such a run on read-only storage, or with a damaged key, cannot be reported even locally.
  - Fix: say so in 3.3, 8 and Q2, and add a local-report case to tests 7 and 11.
- Item 3 (files):
  - Section 13 covers the salt change: the grep finds no other test using a salt, `pseudonym(` or `_NameMatcher(`. test_mcp_guard_repair.py:31 and test_integrity_gate_followups.py:802 need nothing.
  - Nothing listed is unnecessary. Add N2's line. "M04-T04: none" is right.
- G Q1: approve `seed` once N1-N3 are in.
  - The regression gate keeps checking every output at full strength.
  - The smoke proves that rendering a run again gives identical files.
  - The only accepted digest change is the scheme's name in two demo files.
- G Q2: option A.
  - Every 1.5.0 run has its key from collection, so reports and read-only tools never write into it, and it can still be reported from read-only storage.
  - An older run gets its key once, the first time anything is rendered from it (local reports included). One on read-only storage must be copied to writable storage first.
  - Option B makes the first reader of every run write into it, and a run on read-only storage that was never reported cannot be reported.
