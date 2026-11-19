## RESULT REV-M11-T02
status: done
summary:
verdict: changes-required
reviewed: ab9000c32639896e84ec33afef513ba99d5d8e1b
One blocker remains: interrupted-session replacement counts disappear on resume.
Evidence: .plan/work/REV-M11-T02/notes.md.
changes: review notes only: .plan/work/REV-M11-T02/{progress,notes}.md; no product files changed
verification: PASS - PYTHONPATH=src <main-checkout>/.venv/bin/python -m pytest -q tests/test_lone_surrogate_text.py (20 tests, exit 0); git diff a463528..HEAD --check PASS; remaining verify not run (lead runs it)
risks: broader gates and 65-string replay are author-reported, not independently rerun
questions_for_g: none

### Findings
- MET - finalisation and unchanged verdicts, including not-met cases: tests/test_lone_surrogate_text.py:102-115.
- MET by inspection - valid pairs retain their character: src/azure_tenant_audit/text_validity.py:35.
- MET - M365 offline, live, logging and carried-payload admission: src/azure_tenant_audit/cli.py:315, :538; src/azure_tenant_audit/collector_runner.py:260; src/azure_tenant_audit/output.py:156.
- MET - unsafe evidence-index input and external symlinks remain refused: tests/test_lone_surrogate_text.py:146.
- MET by inspection - data-quality wording contains fixed words and a count only: src/azure_tenant_audit/text_validity.py:73.
- NOT MET - replacement-count reporting across interrupted sessions: src/azure_tenant_audit/output.py:235, :338, :960.
- MET by inspection - replaced text remains covered by answer quoting/injection regressions: tests/test_answer_digest.py:160, :173.
- UNTESTABLE independently under this dispatch - broader verification and replay: .plan/work/M11-T02/result.md:10-12.
- DoD remains open: two clean retrained attacker rounds are not claimed: .plan/milestones/M11-auditex-model.md:20.
- Scope MET - no unexplained changed paths; CHANGELOG, ingress/finalisation support, tests and fixtures match the fixes allowance.
- Security inspection: no new dependencies, credentials, unsafe deserialisation, injection or permission relaxation found.

Required changes:
1. [P2] src/azure_tenant_audit/output.py:338 - the count is restored only from summary.json. If collection repairs and checkpoints evidence before interruption, the next writer starts at zero and the already-clean evidence adds nothing; finalisation omits the required note. Persist and restore the count with resumable state, avoiding double-counting, and test repair -> checkpoint -> fresh writer -> carry -> finalise.

Prior required changes:
- 1 fixed - logging and crash recovery: src/azure_tenant_audit/output.py:156; src/azure_tenant_audit/collector_runner.py:209.
- 2 not fixed - interrupted-session counts still disappear: src/azure_tenant_audit/output.py:338.
- 3 fixed - collision-safe repaired keys: src/azure_tenant_audit/text_validity.py:49.

Prior defect classes:
- Unprotected alternate ingress and error logging: fixed, src/azure_tenant_audit/output.py:156.
- Discarded replacement counts at persistence boundaries: not fixed, src/azure_tenant_audit/output.py:338.
- Silent dictionary-key collisions during Unicode replacement: fixed, src/azure_tenant_audit/text_validity.py:49.

Non-blocking suggestions:
- Prior pair-test suggestion not fixed: tests/test_lone_surrogate_text.py:171 supplies an emoji, not two surrogate code units.
- Named pre-normalisation bypass: src/auditex/google_workspace/run.py:546 retains unclean offline payloads; persistence still uses the replacement backstop. This pre-existing Google path is outside the targeted M365 fixes.
