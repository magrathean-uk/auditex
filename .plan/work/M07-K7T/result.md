## RESULT M07-K7T
status: done
summary: The 9.1 open-intent resolution in 10 now runs before Complete-DtPreflight instead of after the CA writes. The gap MANUAL line still prints after the preflight, and nothing else changed in behaviour.
The W4 preflight sweep and all six 7t cases pass. The full suite run full-3 is OVERALL PASS on 9 steps with no failed assertions.
An earlier full-suite run, full-2, was cut off by the launching shell's time limit, so it gave no result; full-3 is the rerun.
Re-frozen: the old freeze is kept as dt-r7t-ro-1 with MANIFEST-1.sha256, and the new dt-r7t-ro has MANIFEST.sha256. The details are in .plan/work/M07-K7T/evidence-2.md.
changes: kit 20261114-kit-7t: dt-r7t/populate/10-conditional-access.ps1, ROUND-7T.md (one line; I lifted its read-only flag to add it, then restored it), dt-r7t-ro-1 and MANIFEST-1.sha256 (renamed, not changed), new dt-r7t-ro and MANIFEST.sha256; no repo file
verification: Cases-Round7t-Live 6/6 pass (runs/k7t-cases-1, host slot). Cases-Round7c-W4 run on its own: W4-preflight-sweep pass; its 18 other failures happen only because that file was loaded without the other case files, and those cases pass in the full mock step. check-suite-7l full run full-3 in the host slot: OVERALL PASS 9 steps (mock 2237 steps, 600 of 600 expected throws, 0 failed assertions; hygiene: kit equals snapshot, 370 files, repo unchanged). Both manifests check 370/370 OK.
risks: On a rerun after the live 400, the first empty read now stops 10 before it converges the other CA policies, not after. The next rerun converges them.
questions_for_g: none
### Findings
fix: populate/10-conditional-access.ps1:382
w4-sweep: pass
mock-step: pass
quick-checks: pass
changed-files: populate/10-conditional-access.ps1
frozen: kit/20261114-kit-7t/dt-r7t-ro c3285015a186 370
