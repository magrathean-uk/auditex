## RESULT REV-M04-T01
status: done
summary: verdict: changes-required
  reviewed: 90866740c48d
  Three earlier findings remain open; two new publication defects and one scope gap remain.
changes: none
verification: PASS SHA-256, HMAC vector, result-file existence and clean git status; FAIL clean-development doctor (dead/unverifiable lifecycle owner), no repairs; builds and suites excluded by the read-only brief.
risks: stale admission may expose the key; failed publication may change pseudonym series; lifecycle ownership remains unverified.
questions_for_g: existing Q1 and Q2 only; recommendations below.

### Findings

- Review 1, finding 1: open, §3.6. Cached-context recovery is specified only for `pseudonym_key`. Ordinary admission after another process creates the key can retain an empty identity registry. Recheck registration before cached `bind_run` returns and before stdin admission; test cross-process creation without first calling the key reader.
- Review 1, finding 2: closed, §§3.4-3.5 and test 7. Private permissions are enforced without changing existing modes; private keys remain readable on read-only storage.
- Review 1, finding 3: closed, §7 and test 6. Subclassing `UnsafeRunFileError` reaches both existing re-raise handlers.
- Review 1, finding 4: open, §§3.4-3.5. Without `flock`, step 4 can unlink a live creator’s empty key, and an `O_EXCL` loser has no specified recovery before step 9. Refuse creation without locking, or specify equivalent serialisation; test delayed creators with locking unsupported.
- Review 1, finding 5: open, §§12-15. Legacy reads still create files while advertising `read_only_hint: true`. Documentation cannot make that annotation accurate. Mark affected tools as writing, or move legacy key preparation into an explicitly mutating operation; update registry tests.
- Review 1, finding 6: closed, §§11 and 15 Q1. The proposed DEC names precisely two label-only digest exceptions and requires a label-reversion proof.
- Review 1, finding 7: closed, §§10 and 13. The context-retention lines, additional tests and in-place schema enum choice are explicit.
- Review 1, finding 8: closed, §1. Engine diagnostics correctly retain their separate `secret_hygiene` redactor.
- Review 2, finding 1: closed, §3.4 steps 4, 6-7. Full writes, owned-file cleanup, directory fsync and empty crash leftovers are addressed; see the separate publication defect below.
- Review 2, finding 2: closed, §7 and test 6. Both swallowed-error paths now propagate the proposed exception.
- Review 2, finding 3: closed, §13. `test_redaction_scan_budget.py:320` is included.
- Review 2, finding 4: closed, §13. Both privacy-document paragraphs are explicitly in scope; the remaining annotation defect is Review 1 finding 5 above.
- Review 2, finding 5: closed, §2 and M04-T05 scope in §13. The chosen-input oracle boundary is stated.
- Review 2, finding 6: closed, §1. The diagnostic inventory and proposed behaviour are corrected.
- Review 2, finding 7: closed, §§8 and 10. Older-reader loss of explanations is explicit and assigned to the output contract.
- Review 2, finding 8: closed, §§3.4, 4, 6-7 and test 8. All five implementation clarifications are specified.
- Review 2, finding 9: closed, §11. Seeding uses the product read path and replaces each collection-created sample key.
- New [P1], §§3.4-3.5: a reader immediately accepts 32 bytes while the creator may still fail fsync and unlink that key. Outputs can therefore use a key subsequently discarded. Synchronise every read with creator completion, revalidate the named inode under the lock, and test a creator paused before a failing fsync.
- New [P2], §3.4 step 5: a failed `.gitignore` write can leave an empty file that retries accept unchanged before creating the key. Clean up an owned failed creation; validate an existing ignore rule before publication, refusing or safely completing it when absent. Test failure followed by retry.
- File scope, §§8 and 13: add `CHANGELOG.md`, which §8 promises but no task permits. Retaining legacy lazy creation also requires widening the option A registry amendment and adding `tests/test_mcp_registry.py` for corrected hints. No listed addition is unnecessary for option A; M04-T04 needs no extra files.
- G Q1 recommendation: approve `seed`, the in-place enum and the narrow digest exception after these fixes. Customers retain reproducible reports while the regression gate continues comparing complete output values.
- G Q2 recommendation: choose option A. Creating the key at collection preserves stable identities and reporting from read-only archives. If legacy runs still initialise lazily, advertise affected MCP tools as writing; retaining true read-only hints requires explicit legacy preparation first.
