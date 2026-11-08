# PLAN-v2 revision 1 - orchestrator rulings

Apply every finding, sequencing risk, missing DoD item and uncovered risk in
`.plan/work/VAL-v2/result.md` (astra, verdict gaps, reviewed 3122ac5), with these rulings:

- Reconciliation is done: main contains origin/main 82d7ca5 since cd6b134, and this branch contains
  main (3122ac5). Remove the stale blocker and tick the ancestor check with that evidence (gap 7).
- DEC-001 and the scope adoption are proposed until G approves at the gate. Record the v1-to-v2
  re-baseline in STATE, linked to DEC-001 (gap 8).
- clean-development doctor and lifecycle registration are out of scope: G ruled on 5 Nov 2026 that
  clean-development issues are left alone. Remove any plan dependency on them; they are not product
  risks.
- Release (gap 1 and astra's first question): plan on a signed v1.3.0 tag plus a GitHub release
  carrying the wheel and sdist, no PyPI, inside 100 percent. Split M03 into a pre-publication gate
  subset, then G's explicit yes naming 1.3.0 (D9), then publication and close-out. G confirms or
  changes this at the gate.
- Legal notice (gap 5): `docs/legal/` is owner-controlled. Plan a task that drafts the correction to
  `docs/legal/third-party-notices.md` as a proposal; the DoD item is "G approved the exact text and
  it is merged, or G recorded an exception". Cover every other public doc path with the complete
  path review.
- The parked model layer stays parked: classify its POSTs and audit the `model_train` extra, but plan
  no model development and no removal.
- Do not run scaffold.sh. Keep the four milestones unless a finding needs another; weights still sum
  to 100. Commit with a pathspec and return the RESULT block.
