## RESULT M07-T18
status: done
summary: Get-DtTenantSettingItems now refuses a two-list reply when any `enabled` in either list is not a JSON boolean. Same throw path as a mismatch, nothing written; 60-powerbi and 90-verify both read through this helper.
3 new cases W7s-f3-r2-*; the existing "enabled missing in value" case now expects this refusal.
On fd6ad290c829 the "yes" vs 1 reply is read (9 items); the one-list case fails only by reason; the boolean control case could not run its script steps there (the old copy refuses the mock config under `-Kit`).
One host slot: 7s cases, quick steps. Re-frozen; dt-r7s-ro-3 and MANIFEST-3.sha256 kept; protected trees unchanged by hash.
changes: kit/20261111-kit-7s/dt-r7s/populate/_common.ps1; kit/20261111-kit-7s/dt-r7s/tools/mock-harness/Cases-Round7s.ps1; kit/20261111-kit-7s/ROUND-7S.md (one F3 line); kit/20261111-kit-7s/dt-r7s-ro-3 and MANIFEST-3.sha256 (renamed); kit/20261111-kit-7s/dt-r7s-ro and MANIFEST.sha256 (new, read-only); kit runs r2-old-1, r7s-all-1, slot-r2-1.sh, quick-6; evidence .plan/work/M07-T18/part5/, result.md; repository unchanged
verification: hostload slot (wait 5400) runs/slot-r2-1.sh pass; r7s-all-1 Cases-Round7s.ps1 32 of 32 pass; r2-old-1 on fd6ad290c829 rc 3, expected fails; check-suite-7l.sh --quick quick-6 7 of 7 pass; dt-r7s hash-stable across the run pass; hygiene of 44 added lines and the ROUND-7S line pass; freeze 369 of 369 OK, 0 writable pass; ro-3/ro-2/ro-1 manifests 369 of 369 OK pass; protected tree hashes before and after identical pass
risks: the boolean control case did not run its script steps on the old code (runner `-Kit` config limitation); its unit part is unaffected | full mock run not started (gate) | a reply missing `enabled` in both lists now refuses (the readers require it anyway)
questions_for_g: none
### Findings
fix: kit/20261111-kit-7s/dt-r7s-ro/populate/_common.ps1:2225
new-cases: 3 fail-on-previous 2
all-cases: pass
quick-checks: pass
changed-files: populate/_common.ps1, tools/mock-harness/Cases-Round7s.ps1
frozen: kit/20261111-kit-7s/dt-r7s-ro 6dae564ece2c 369
full-suite-command: cd 20261111-kit-7s && bash check-suite-7l.sh --mock-timeout 28800 --snapshot dt-r7s-ro --manifest MANIFEST.sha256 --repo <auditex checkout> dt-r7s full-1 <OPA 1.20.2 binary> <ScubaGear 2446ad7 checkout>
