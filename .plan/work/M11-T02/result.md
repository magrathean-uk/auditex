## RESULT M11-T02
status: done
summary: Repair round after REV-M11-T02: all three required changes and the non-blocking suggestion are fixed. Audit-log events now repair and count lone surrogates (collector hook, crash path, non-JSON details). Coverage rows, metadata, every file write, resumed payloads and seeded coverage count their repairs, and write_bundle repairs the summary and manifest before writing the note. A repaired key whose name is already taken gets a ~2, ~3 suffix; clean keys keep their names.
The branch was rebased onto main 0025f00 because it was behind: main's d988ecd (test-only) fixed the v3.9.1 vector constructed:MS.EXO.3.1v1:dkim_config_empty. Head ab9000c; both commits SSH-signed.
changes: src/azure_tenant_audit/output.py, src/azure_tenant_audit/collector_runner.py, src/azure_tenant_audit/cli.py, src/azure_tenant_audit/text_validity.py, tests/test_lone_surrogate_text.py, CHANGELOG.md
verification:
- make lint PASS.
- tests/test_lone_surrogate_text.py: 20 passed.
- Negative: the 8 new behavioural tests FAIL on the pre-repair src ("UnicodeEncodeError: 'utf-8' codec can't encode character '\udc00' ... surrogates not allowed", plus key-collision and count asserts); see .plan/work/M11-T02/repair/negative.txt.
- fixes-1 verify.sh on ab9000c via hostload PASS: lint, focused tests, rule packs up to date (39), contract-smoke.
- v3.9.1 replay on ab9000c: 1 passed (.plan/work/M11-T02/repair/verify-rebased.log). Before the rebase it failed on the DKIM vector above.
- 65-string pre-screen via hostload, run at 750c224 before the rebase (same src as ab9000c; .plan/work/M11-T02/repair/checks.log): fixed product 512 tenants, 0 stop, 0 intent flips, 0 controls failing. Unfixed main: 46 stop, 11 intent, 0 controls failing.
risks:
- The Google Workspace offline run (src/auditex run.py, not owned) still passes the uncleaned payload into normalisation; the write backstop repairs its files.
- A resumed run whose earlier session stopped before writing summary.json loses that session's count. Keeping it needs a new checkpoint-state field.
- The same text can be counted twice when it reaches two separate writes (for example a log line and a coverage row).
questions_for_g: none
### Findings
- R1 [P1] audit logging: fixed in AuditLogger.log and the CollectorRunner crash path; regression test_collector_log_callback_and_crash_with_lone_surrogates_finalise.
- R2 [P2] uncounted backstops and resume: fixed with counted _write_text_atomic, _write_json_atomic, write_index_records, write_bundle and _resume_carried_collectors; coverage-only, metadata-only and resume tests added.
- R3 [P2] key collisions: fixed; both insertion orders and a collision with an existing U+FFFD key are tested.
- Suggestion: direct two-code-unit surrogate-pair test added.
- fixes-1: done (pre-screen 0 stop, 0 intent, 0 controls failing; v3.9.1 replay passed). Written to .plan/work/M11-T02/result.md.

## Attack loop (rounds 2 and 3, `.plan/work/M11-T02/result-r2.md`)
Round 1 (base attacker, pre-fix 2ac9134): 260 tricks, one root (lone UTF-16 surrogate), fixed in e5143c8 plus the resume count. Rounds 2 and 3 (attacker retrained on round 1, product 9a0f301): 0 tricks each over 2,048 strings and 4 models; pre-screen 0 stop, 0 off intent. Later main commit 19198e8 changes only key-masking vocabulary and a count default, not the attacked pipeline.

## Loop status

`loop.md`:

| round | attacker | product | complete | tricks | classes | gpu-hours |
|---|---|---|---|---|---|---|
| 1 | model base | 2ac913483df2 | True | 260 | intent:surrogate, stop:surrogate | 17.70 |
| 2 | model adapter | 9a0f301374fe | True | 0 | none | 8.52 |
| 3 | model adapter | 9a0f301374fe | True | 0 | none | 8.56 |

gpu-hours: attack 34.7828
attack-loop: clean

round-3: done
