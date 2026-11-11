## RESULT EXP-pim72
status: done
summary: 7.2 stays "not met" with the three extra assignments, because Global Reader and Directory Readers are outside the 8 privileged role ids.
summary: 90-verify counts any principal type holding one of the 8 roles, so service principals count there. The oracle reportedly excludes them (review note only).
changes: none
verification: rg and sed reads of the kit only; no PowerShell run; pass
risks: oracle service-principal exclusion rests on a review note, not on source in the kit; a service principal holding one of the 8 roles would diverge between 90-verify and the oracle
questions_for_g: none
### Findings
Answer, with file:line for every claim, is in the findings above (kit-ro/populate/90-verify.ps1:475-492, kit-ro/populate/_common.ps1:3160-3168, kit-ro/EXPECTED-VERDICTS.json policies["MS.AAD.7.2v1"], kit-ro/reviews/dummy-tenant-r7c-step11-design.md:51).
