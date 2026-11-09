# Backlog
<!-- Triaged ideas and unscheduled tasks. Promotion into a milestone is a change-control event. -->

## Now
- none

## Next
- Keyed per-run pseudonym scheme for D5 masking (private per-run key, bundle change), replacing the run-path salt (DEC-004).
- A wider Ruff rule set (W, I, B, UP) than the pre-commit hook's, and a format hook (orchestrator ruling, DEC-001): about 31,800 findings on the broader probe (INV3-lint); needs its own cleanup round.
- Explainer fixtures named in `tests/test_explainer_fixtures.py:43` but absent at the top level of `tests/fixtures/explainer/` - confirm where they live or fix the test.
- Vendored `tenant-bootstrap/vendor/microsoft-skills` entries with no code reference (ALL-SKILLS-CATALOG, microsoft-foundry, entra-agent-id) - removal changes G-owned legal notices.
- `tests/test_value_rules_contract.py:266` still reads the stale `AUDITEX_TEST_VALUE_RULE_VECTORS` name and also needs `AUDITEX_TEST_VALUE_RULE_CATALOGUE`, which the v3.9.1 kit lacks, so it always skips (M01-T03); give it the kit name and a catalogue source, or retire it.
- D5 follow-up: mask names written with middle initials or titles ("John A. Smith", "Dr. Jane Doe") by letting the matcher join one separator character followed by a space (REV-M05-T03-privacy suggestion; same probe budget). In 1.4.0 they are counted unmatched and stay readable in free text, and the note says so.
- Read-boundary scanner (DEC-008 limits): treat any callee name the module rebinds (def, class, assignment, import) as unresolved for the read-only hand-off and transparent-conversion shortcuts, and include import, `with`, `def`, `class`, `except`, `match` and comprehension-walrus bindings in the binding union. Resolve class-body names in the class namespace (a launch in a class body reading a class-local name).

## Later
- Answer the SCuBA Google Workspace baselines from the Google provider (today an internal control map).
- Live-tenant work, parked until G raises it: certificate auth live acceptance (`wt/collect-certauth-1`), presets, IPPS, Teams coverage, the day-one run, `-Enforce`, and the SS 2.1 `TargetedUsersToProtect` live wire-shape gate.
- Dummy-tenant kit: 7l6 full offline suite and gate, then 7m, 7n and 7o behind it; the 7m ancestry merge stays blocked without a common base.
- Hosted CI or merging `wt/github-build-tags-20261108`, only if G asks.
