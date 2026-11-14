## RESULT M08-T02
status: done
summary: The stale-set check now compares customKeyIdentifier as well, so it covers every field the PATCH sends back. New tests check a metadata-only change on both create and removal; the r1 helper fails both and the fixed helper passes. The kit is re-frozen at 4d5d1c62f086, with r1 kept as MANIFEST-2.sha256. Notes: .plan/work/M08-T02/notes.md
changes: dt-live/m08-a2 kit, outside the repo (m08a2-common.ps1, tests/mock.ps1, tests/run-tests.ps1, RECORD.md, MANIFEST.sha256, MANIFEST-2.sha256); repo: only .plan/work/M08-T02/ notes, evidence and the r1-frozen copy
verification: guarded parse of all six scripts: pass, 0 errors; harness through pwsh-guarded: pass 79/79; new tests on the r1 helper: 2/79 fail as expected; shasum -c MANIFEST.sha256: pass 7/7
risks: Graph has no conditional PATCH on applications, so a change between the re-read and the PATCH still cannot be detected (unchanged)
questions_for_g: none
### Findings
fix: dt-live/m08-a2/m08a2-common.ps1:262 (Get-A2CredSetText adds customKeyIdentifier per credential)
harness: pass 79/79
changed-files: RECORD.md 031e9544cfb0, m08a2-common.ps1 078edceede17, tests/mock.ps1 c0f94add882f, tests/run-tests.ps1 e37b475e14f7
frozen: 4d5d1c62f086
removal-step: present
out-of-kit-row: written
expected-verdicts-changed: 0
applied-from: 4d5d1c62f086
applied: complete
