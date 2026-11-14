## RESULT M07-T18
status: done
summary: Read DRYRUN-FAULTS.md and the 9 dry-run logs: 4 findings, 0 kit defects (F1 Fabric token scope, F2 CA preflight before 00 -Apply, O3 empty break-glass id in a dry run, O4 hidden character in a tenant SKU name).
F1: the default client's token lacks Tenant.ReadWrite.All (BLUEPRINT T7 answered no); two README rows clarified; refusal message and all PowerShell unchanged (byte-equal to the code the dry runs used).
Froze dt-r7s as dt-r7s-ro with MANIFEST.sha256; dt-r7s-cand and CANDIDATE.sha256 untouched; protected trees unchanged by hash.
Quick steps ran directly after three deferred slot attempts (not a heavy job: 2-3 min, load below cores).
changes: kit/20261111-kit-7s/dt-r7s/populate/README.md; kit/20261111-kit-7s/ROUND-7S.md (part 2b section); kit/20261111-kit-7s/dt-r7s-ro (new, read-only); kit/20261111-kit-7s/MANIFEST.sha256 (new); kit/20261111-kit-7s/quick-3, quick-3.out; evidence .plan/work/M07-T18/evidence-2b.md and part2b/; repository unchanged
verification: python3 -I -B tools/test_compare.py on dt-r7s pass (341/341); check-suite-7l.sh --quick dt-r7s quick-3 pass (OVERALL PASS, 7 steps; three hostload attempts deferred rc 75, then run directly); hygiene of 49 added lines pass; MANIFEST.sha256 369/369 OK pass; protected-tree hashes before and after identical pass; CANDIDATE.sha256 368/368 OK pass
risks: 60-powerbi cannot dry-run or apply until the owner picks an own Fabric app registration (write scope, manual tenant write) or the portal fallback | the Fabric admin role question and all writes, 403/409/429/5xx shapes and 10 after its preflight stay unproven until phase D | quick steps ran outside the host slot (judged not heavy); the gate may want them re-run in a slot
questions_for_g: F1 operator decision before phase D: own Fabric app registration with delegated Tenant.ReadWrite.All (removed by hand at the end), or the Fabric settings by hand in the portal with 60 skipped? Recommendation: the app registration, so 60, its journal and 99-rollback's Fabric restore stay in the kit.
### Findings
dry-run-findings: 4 kit-defects 0
kit-changes: kit/20261111-kit-7s/dt-r7s/populate/README.md
quick-checks: pass
frozen: kit/20261111-kit-7s/dt-r7s-ro 7433269381e1 369
full-suite-command: cd 20261111-kit-7s && bash check-suite-7l.sh --mock-timeout 28800 --snapshot dt-r7s-ro --manifest MANIFEST.sha256 --repo <auditex checkout> dt-r7s full-1 <OPA 1.20.2 binary> <ScubaGear 2446ad7 checkout>
