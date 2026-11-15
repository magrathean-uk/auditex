## RESULT REV-M03-T09
status: done
summary: verdict: approve. reviewed: 0866060e255b. Both round 1 findings are fixed. Exemplars 08 and 09 now name the Global policy, and only those four sentences changed. The new test shows that pilot-3 is refused after pilot-2 passes. Both checks passed through hostload.
changes: none to the kit or repo; round 2 notes in .plan/work/REV-M03-T09/ (notes.md, progress.md, round2-*.log)
verification: dataround tests via hostload, 76 OK, pass; new test run on its own, pass; kit-check selftest via hostload with KIT_PYTHON airr-kit-cpu, pass (trainer-selftest pass, auditex-imports 0); pilot-3 and checks manifests verified, pass
risks: none
questions_for_g: none
### Findings
- Pass: the pre-repair copy of the pilot-3 manifest hashes to 3291564774cf, the commit I reviewed in round 1. Since then only exemplars.jsonl, exemplars-provenance.md and teacher_prompt.py changed. The five pilot-2 byte copies and both judge files are still identical.
- Pass: in exemplars.jsonl, rows 01-07 are unchanged. Rows 08 and 09 change only from "In e1, X" to "In e1, the Global policy has X". Object 0 of e1 is Global and holds every value stated. In teacher_prompt.py only the EXEMPLARS line changed, by the same edit.
- Pass: the new test makes pilot-2 pass and checks the recorded result is "pass". It then expects pilot-3 to be refused with the exact DEC-098 message.
- Note: the checker now also refuses a value that differs between policies unless the sentence names the policy. Round 1 suggested this guard.
