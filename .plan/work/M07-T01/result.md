## RESULT M07-T01
status: done
summary: Froze the live kit as dt-r7l6 and a read-only twin dt-r7l6-ro (365 files) with MANIFEST.sha256; each of the 71 files that differ from dt-r7l5-ro is explained in kit/20261111-kit-7l-gate/DIFF-VS-7L5.md.
summary: The 7l6 report explains 11 of the 71 files. The other 60 trace to the protocol records; the kit was installed on 8 Nov after a passing full run (2106/538/538) and a Gate 22 SHIP from Sol and Opus with no high or medium findings.
summary: New driver kit/20261111-kit-7l-gate/check-suite-7l.sh: checks the guard's sha256, one log and one summary line per step, then a final PASS or FAIL line, and judges the mock run itself (exit code, kill signal, ASSERT FAILED, failed or filtered banner, unexpected THREW).
summary: Self-test passed 42 of 42 cases. The quick checks passed on dt-r7l6. Loopback works here (a Python listener, and an HttpListener started through the guard).
summary: Details are in .plan/work/M07-T01/notes.md.
changes: new kit/20261111-kit-7l-gate/ {dt-r7l6/, dt-r7l6-ro/, MANIFEST.sha256, DIFF-VS-7L5.md, pwsh-guarded (copy), check-suite-7l.sh, selftest-check-suite-7l.sh, selftest/, quick-1/, quick-2/, quick-2.out}; .plan/work/M07-T01/notes.md. The repository, the live kit and older folders are unchanged.
verification: diff -rq live kit vs both copies: pass (still equal at the end); shasum -c of MANIFEST: pass 365/365
verification: guard copy sha256 equals the recorded value: pass
verification: selftest-check-suite-7l.sh selftest/run-3: pass (42/42)
verification: driver's throw check on the accepted KIT54 mock log: pass (2106/538/538)
verification: check-suite-7l.sh --quick on dt-r7l6 (quick-2): pass, all 7 steps
verification: Python loopback on 127.0.0.1: pass; HttpListener through the guard: pass
risks: Once I ran `pwsh --version` without the guard (version print only; no profile, module or script). All other starts went through the guard.
risks: Some kit files hard-code paths: W12a starts its child pwsh through the original kit/20261027-ship-plan/pwsh-guarded (same sha256), and the dependency script fixes the ScubaGear and OPA paths. The driver fails the dependency step if the fixed ScubaGear path is not the one given.
risks: The full run repeats the 8 Nov accepted run on identical files. It would still be the first run through this driver.
questions_for_g: none
### Findings
snapshot: dt-r7l6-ro 109679e67da549ddc6c72bd751f1217fb146f31962a5bd5e2392c80958b1cb8c
diff-vs-7l5: 71 files, 60 unexplained
diff-vs-7l5 note: "unexplained" means not named in the 7l6 report. All 60 (10 case files, Run-Mock.ps1, 49 files under run/kit/protocol/) are explained by the protocol records.
driver-selftest: pass
quick-checks: pass
quick-checks detail: parse 88 files with 0 errors; py_compile 11; test_compare 331 OK; shape lint 270 findings, all allowlisted, 0 stale; constructs 0 findings; rego table current; hygiene clean; kit equals the snapshot; repo unchanged
loopback: yes
full-suite-command: cd kit/20261111-kit-7l-gate && run-job full-1-job -- bash check-suite-7l.sh --snapshot dt-r7l6-ro --manifest MANIFEST.sha256 --repo "$AUDITEX" dt-r7l6 full-1 "$OPA" "$SCUBAGEAR"
full-suite-command note: AUDITEX is the main checkout, OPA the pinned opa 1.20.2, SCUBAGEAR the ScubaGear checkout at 2446ad72. The absolute-path line is in notes.md. Wait on full-1-job/.done; the job's exit code and last line give the verdict.
