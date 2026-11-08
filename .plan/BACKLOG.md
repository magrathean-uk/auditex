# Backlog
<!-- Triaged ideas and unscheduled tasks. Promotion into a milestone is a change-control event. -->

## Now
- none

## Next
- Static boundary-scanner limits (DEC-011): the HTTP scanner misses openers passed as untyped parameters or held in containers (M01-T03 notes); the read-boundary scanner misses non-subprocess launchers, dynamic callee lookup, requests held in containers or fetched via getattr, and relies on per-module handle naming (M01-T04 notes, L1-L4). Untraceable sites fail closed only where the scanners can see them.
- Retire the parked model layer after 1.3.0 (`model-layer-parked` module, `scripts/*oracle*`, `examples/model_development/`, `configs/model-sources.json`, the `model` CLI wiring) - approved by G (DEC-004); the removal list still goes through the deletion gate; nothing changes in 1.3.0.
- D5-v2 person-name masking beyond the typed D3 fields: a new design from current `main` (not a merge of `wt/redact-person-names` 3e495d6), bounded per-record matching, 90k HTML peak within current `main` plus 15 percent, both-provider privacy review (D6).
- Dead-code candidates for a CLEANUP round after 1.3.0, each re-checked first: `benchmarks/fake_graph_benchmark.py`, `scripts/tenant-audit-flow`, `src/azure_tenant_audit/catalog.py`, `assets/auditex-logo.png`, `requirements.txt`, `tenant-bootstrap/requirements.txt`, `scripts/build-value-rule-fixture.py`.
- Repo-wide Ruff in `make lint` (today `make lint` is compileall only; Ruff runs on staged files through pre-commit).
- Describe `tenant-bootstrap/` in AGENTS.md and check its `azure_tenant_audit/` forwarders against `src/`.
- A scheduled local acceptance run (`value_rule_acceptance`, `explainer_acceptance`) so the 26,898-vector replay does not run only at release time.
- Small hygiene: `pytest.ini` `norecursedirs = !Review` is a no-op; `scripts/oss-taint-scan.sh` prunes the absent `docs/taint`.

## Later
- Answer the SCuBA Google Workspace baselines from the Google provider (today an internal control map).
- Live-tenant work, parked until G raises it: certificate auth live acceptance (`wt/collect-certauth-1`), presets, IPPS, Teams coverage, the day-one run, `-Enforce`, and the SS 2.1 `TargetedUsersToProtect` live wire-shape gate.
- Dummy-tenant kit: 7l6 full offline suite and gate, then 7m, 7n and 7o behind it; the 7m ancestry merge stays blocked without a common base.
