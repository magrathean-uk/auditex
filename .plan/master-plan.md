# Master plan - Auditex 1.4.0
<!-- Hub document, max 150 lines. sol-architect writes it, the orchestrator makes small edits, G approves scope. -->

## Vision
Auditex 1.4.0 is the release in which an IT administrator or consultant gets the same read-only, deterministic
Microsoft 365 audit as 1.3.0 from a smaller, provable product: the parked local-model layer is gone, so every
verdict and explanation visibly comes from value rules and the template; shareable output masks person names in
free text and ids, not only in typed fields, without a memory blow-up on large tenants; anyone can rebuild the
published wheel and sdist byte for byte and rerun the full 26,898-vector acceptance replay with one command; and
the boundary scanners that prove the tool never writes to a tenant or reads content have fewer blind spots, with
the rest written down. Nothing new reaches the tenant and nothing leaves the machine except to endpoints the
operator configures.

## Target user
IT administrators and consultants auditing their own or a customer's Microsoft 365 or Google Workspace tenant
who need defensible, reproducible evidence without write access (wording confirmed by G for 1.3.0).

## Success criteria
- `make lint` runs the pinned Ruff check over the whole repository with the pre-commit hook's rule set and target
  version, and `make lint`, `make test`,
  `make contract-smoke`, `make release-check` and `make audit-deps` exit 0 on the release commit.
- Two plain `make dist` builds of the release commit give a byte-identical wheel and a byte-identical sdist, and
  `scripts/check-reproducible-build.py` proves both (v2 DEC-019).
- `make acceptance` verifies all three pinned kit hashes, runs the full v3.9.1 replay (26,898 vectors) and the
  explainer acceptance suite, and passes at each milestone close from M02 and on the release commit; the replay is
  no longer waived (v2 DEC-017). The kit stays in the machine records folder, outside git; no scheduled job.
- No model module, model CLI command or flag, `model_train` extra, model script or model config remains, after G
  approved the exact removal list; a normalised digest comparison of contract smoke shows report, projection and
  explainer output unchanged, with no contract re-baseline (v2 DEC-004).
- Shareable and customer-pack output mask the names of everyone in the run's own directory records in free text
  and ids, with bounded per-record matching, an HTML peak on the frozen 90,000-record workload within the `main`
  baseline plus 15 percent while masking runs, and approving privacy reviews from both providers (D6, DEC-001).
- Every DEC-011 scanner limit is closed by a test or stated in the security and privacy reference.
- The approved dead paths and the divergent `tenant-bootstrap/azure_tenant_audit/` copies are removed through the
  deletion gate and recorded in CLEANUP.md; only the forwarder remains, a test proves it forwards to `src/`, and
  `tenant-bootstrap/` is described in AGENTS.md.
- Tier A changes (M01-T01, M02-T03, M02-T04, M04-T01, M04-T02, M05-T03, M06-T01) carry an approving other-vendor
  review of the exact merged head, checked through the merge trailer and the ledger (ARCHITECTURE.md).
- astra's release gate returns ready; the release gate compares wheel and sdist bytes; G's yes naming 1.4.0 is recorded; the signed tag `v1.4.0` and a GitHub
  release with the wheel and sdist exist and the downloaded assets match the gated hashes. No PyPI.

## Scope of 100 percent
The 1.4.0 release built from the BACKLOG Next items of plan v2, which G approved as the next scope ("ok to all,
continue dev until 100%"): a lint-enforced foundation; byte-reproducible `make dist` and a repeatable local
acceptance run with the restored replay kit; retirement of the parked model layer through the deletion gate;
the dead-code cleanup and the `tenant-bootstrap/` description and forwarder proof; the DEC-011 scanner
follow-ups; D5-v2 person-name masking; then release notes, gates and, on G's yes naming 1.4.0, publication.
100 percent means every DoD item in M00-M06 is ticked.

## Non-goals
- Live-tenant work of any kind (certificate auth live checks, presets, IPPS, Teams coverage, the day-one run,
  `-Enforce`, the SS 2.1 live wire-shape gate) and the dummy-tenant kit rounds. Never raise the tenant.
- Answering the SCuBA Google Workspace baselines; the Google provider stays an internal control map.
- Merging `wt/redact-person-names` or the `wt/d5-*` branches; D5 is a redesign from `main` (D6).
- Hosted CI; merging the Codex branch `wt/github-build-tags-20261108`; deleting `wt/*` branches or worktrees.
- PyPI or any registry upload; any release other than 1.4.0 without G's yes naming it; any tenant write path.
- Model training, base-model pulls, AIRR or Hugging Face upload (the layer is retired, not developed).
- A wider Ruff rule set than the hook's E4, E7, E9 and F; workstation tooling issues (clean-development doctor).
- A launchd or other scheduled acceptance job (G declined); acceptance runs at milestone close and the release gate.
- Edits to G-owned legal files except text G approves verbatim.

## Architecture
See ARCHITECTURE.md. Parallel work only across modules with different owners; sol agrees interfaces before any parallel dispatch.

## Milestones
<!-- milestones:begin -->
| id | name | weight | % | status |
|---|---|---|---|---|
| M00 | foundation | 10 | 100 | done |
| M01 | build-and-acceptance | 15 | 100 | done |
| M02 | model-layer-retirement | 20 | 10 | active |
| M03 | cleanup-and-bootstrap | 10 | 71 | planned |
| M04 | boundary-scanners | 10 | 17 | planned |
| M05 | d5-name-masking | 20 | 0 | planned |
| M06 | release-1-4-0 | 15 | 0 | planned |
<!-- milestones:end -->

Order: M00 first (M00-T01 alone); read-only tasks (M01-T02, M02-T01, M03-T01, M05-T01) may run alongside it.
Then, serialised on shared files: M01-T01 -> M01-T03 -> M02-T03 -> M02-T04 -> M02-T05 (`Makefile`, runbook,
model guide); M02-T02 runs after M02-T01 and before M02-T03; M05-T02 after the frozen harness section of M05-T01.
After M02-T05: M03-T02 -> M03-T03 -> M03-T04, and M04-T01, M04-T02 in parallel; M04-T03 after M03-T02 (shared
`docs/reference/security-privacy.md`); then M05-T03 -> M05-T04; then M06. Only M03-T02 deletes bootstrap files.

## Top risks
1. Ruff findings sit in 54 files across modules; M00-T01 runs alone before parallel writers, or it collides
   with every later branch.
2. The replay kit was found only by one inventory slice and the plan session could not re-locate it; if
   M01-T02 cannot find it, M01 and every milestone-close acceptance item wait on a G decision.
3. Model-layer helpers feed the shipped report, projection and value-rule paths; removing them before
   re-homing breaks 1.4.0. M02-T02 records normalised digests first; M02-T03 and M02-T04 must match them.
4. D5 is the third attempt (D6): matching cost and HTML peak are the known failure modes, hence the frozen
   harness interface, the person-bearing workload and the baseline before the change, and the design gate.
5. Two deletion gates (M02, M03 with the bootstrap copies), the D5 design and the 1.4.0 yes wait on G;
   dispatch keeps independent work moving while they wait.
6. Removing the `model` command and extra changes the CLI surface in a minor release; the notes must say so.
7. Plan v2 used the same task ids M00-M03; predicates bind to plan v3 merges, DEC ids and CLEANUP.md rows,
   never to a work path alone. The repo is public: plan files, briefs and notes carry no workstation paths, credentials, live evidence or
   sealed evaluation rows (the kit location stays outside git); gitleaks and the taint scan run before every push.

## Links
STATE.md, ARCHITECTURE.md, milestones/, BACKLOG.md, DECISIONS.md, CLEANUP.md, RETRO.md
