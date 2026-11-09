# Standing G decisions for plan v3

These bind plan v3 alongside every approved entry in `.plan/DECISIONS.md`; do not re-ask them.

- 9 Nov 2026 (G): "ok to all, continue dev until 100%". Plan v3 takes the BACKLOG Next items as the
  next release scope (proposed 1.4.0); the orchestrator decides routine engineering and reversible
  details.
- DEC-004 (G, 8 Nov 2026): retire the parked local-model layer after 1.3.0. Removal goes through the
  deletion gate: G approves the exact path list before any `git rm`. The shipped deterministic
  template explainer stays.
- D6 (G, 7 Nov 2026): D5 person-name masking (names in free text and ids) is a redesign from current
  main, not a merge of `wt/redact-person-names`: bounded per-record matching, HTML peak within main
  plus 15 percent, and a privacy review by both providers.
- DEC-017 (G, 8 Nov 2026): the v3.9.1 replay kit is missing. Restoring it is in scope only if it can
  be regenerated or located on this Mac without downloads, paid runs or external hosts; otherwise
  plan it as a G decision.
- DEC-019 (8 Nov 2026): making plain `make dist` byte-reproducible is in scope.
- Live-tenant work, answering the SCuBA Google Workspace baselines and the dummy-tenant kit rounds
  stay BACKLOG Later. Never raise the tenant.
- Any release other than 1.3.0 needs G's explicit yes naming the version (D9); the publication form
  stays a signed tag plus a GitHub release with wheel and sdist, no PyPI (DEC-001).
- No hosted CI: GitHub is storage only. The Codex branch `wt/github-build-tags-20261108` stays
  unmerged unless G asks for it.
- Coding runs on Codex and the claude-1..5 pool, never on G's personal account.
