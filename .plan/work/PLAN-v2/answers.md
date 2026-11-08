# Standing G decisions for plan v2

From G's recorded answers and the operator decisions log (D1-D9 at the time of writing), which
lives outside the repo at `~/dev/machine/records/auditex/DECISIONS.md`; read D8 onwards there.
These bind the plan; do not re-ask them.

## Orchestrator defaults, pending G at the scope gate
Plan on these; G may change them when approving the plan.
- Scope of 100 percent is the 1.3.0 release. Everything else goes to BACKLOG next or later.
- The parked model layer stays untouched in 1.3.0 (no development, no removal). Retiring it is a
  BACKLOG next item awaiting G. Whether `examples/model_development/` holds held-out or sealed
  rows (forbidden by AGENTS.md) is a read-only check task; any removal goes through the deletion
  gate.
- The Google Workspace provider stays an internal control map in 1.3.0; docs must not claim SCuBA
  Google Workspace coverage. Answering those baselines is a BACKLOG later item.
- No hosted CI, by G's 5 Nov decision that GitHub is storage only. M00 foundation means the local
  gates run green and reproducibly: `make test`, `make contract-smoke`, rule-pack drift,
  `make release-check` (taint scan, gitleaks) and a dependency audit.
- The `wt/*` branches and leftover worktrees may hold unmerged work: plan a read-only triage for
  anything 1.3.0 needs. Deleting branches or worktrees is not in scope.

## Verdicts and model
- 5 Nov 2026: every SCuBA verdict comes from the deterministic value rules; no model fallback. The
  local model is at most an optional explainer, off by default; the shipped explainer is a
  deterministic template built from the rule cells. The model rewrite layer, base-model pull, AIRR
  training and the Hugging Face upload are parked (G: "Leave it parked"). Do not plan them.
- 5 Nov 2026 (delegated, standing): rules on by default (hidden `AUDITEX_DISABLE_VALUE_RULES`);
  uncollected evidence reads "not assessed: evidence not collected"; 250,000-user ceiling.
  Divergence rule: stricter evidence is met; missing or ambiguous is not_assessed; pinned baseline
  text beats a conflicting Rego when evidence is complete; otherwise the Rego.

## Scope
- 5 Nov 2026: Power BI (Fabric admin) and Power Platform collection ship as an opt-in extended
  scope, off by default; docs record the write-capable roles used read-only and their blast radius.
  No Sites.FullControl.All.
- 5 Nov 2026: the optional `--sensitive-users` file is approved (extended to `--partner-domains`).
- 7 Nov 2026 (D6): 1.3.0 ships the D3 masking; person-name masking beyond the typed fields (D5)
  moves to a redesign track after 1.3.0.
- 7 Nov 2026 (D7): 1.3.0 may be tagged and released once its gate is closed and `make test` plus
  `make release-check` are green. Any release other than 1.3.0 needs G.

## Live tenant
- 5 and 7 Nov 2026: no live-tenant work. The playground tenant, trials, the 1Password service
  account, passkey and break-glass stay parked until G raises them. Do not plan tasks that need
  them and do not ask about them; anything that needs a live tenant goes to BACKLOG later.

## Repository and delivery
- 5 Nov 2026: the public auditex repo is the only git (no separate kit repo). It may carry anything
  except real credentials, live tenant evidence, workstation paths and session URLs.
- 7 Nov 2026: coding runs on Codex and the claude-1..5 pool, never on G's personal account.
