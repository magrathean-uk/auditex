# Backlog
<!-- Triaged ideas and unscheduled tasks. Promotion into a milestone is a change-control event. -->

## Now
- none

## Next
- Keyed per-run pseudonym scheme for D5 masking (private per-run key, bundle change), replacing the run-path salt (DEC-004).
- A wider Ruff rule set (W, I, B, UP) than the pre-commit hook's, and a format hook (orchestrator ruling, DEC-001): about 31,800 findings on the broader probe (INV3-lint); needs its own cleanup round.
- Explainer fixtures named in `tests/test_explainer_fixtures.py:43` but absent at the top level of `tests/fixtures/explainer/` - confirm where they live or fix the test.
- Vendored `tenant-bootstrap/vendor/microsoft-skills` entries with no code reference (ALL-SKILLS-CATALOG, microsoft-foundry, entra-agent-id) - removal changes G-owned legal notices.

## Later
- Answer the SCuBA Google Workspace baselines from the Google provider (today an internal control map).
- Live-tenant work, parked until G raises it: certificate auth live acceptance (`wt/collect-certauth-1`), presets, IPPS, Teams coverage, the day-one run, `-Enforce`, and the SS 2.1 `TargetedUsersToProtect` live wire-shape gate.
- Dummy-tenant kit: 7l6 full offline suite and gate, then 7m, 7n and 7o behind it; the 7m ancestry merge stays blocked without a common base.
- Hosted CI or merging `wt/github-build-tags-20261108`, only if G asks.
