## RESULT REV-M07-T18-codex
status: done
summary: verdict: ship
reviewed: 6dae564ece2c, manifest check pass
changes: none
verification: Python SHA-256 checks pass for both manifests, 369/369 each; complete snapshot diff inspected; no kit code executed
risks: runtime checks not repeated, as instructed
questions_for_g: none
### Findings
1. pass: dt-r7s-ro/populate/_common.ps1:2225 refuses non-boolean enabled in either list before preflight writes; all envelope readers retain the shared helper.
2. pass: dt-r7s-ro/tools/mock-harness/Cases-Round7s.ps1:486,493,502 cover collisions, either-list invalid values and boolean control; :479 correctly changes only the missing-value refusal reason. No case, lint rule, allowance or expected verdict weakened.
3. pass: only populate/_common.ps1:2225 and tools/mock-harness/Cases-Round7s.ps1:473 differ between snapshots; 367 files are byte-identical, none added or removed. ROUND-7S.md:339 records the permitted repair note.
