# PLAN-v2 revision 2 - review residuals and G's gate answers

## Close the REV-PLAN-v2 residuals
Source: `.plan/work/REV-PLAN-v2/result.md` (Codex gpt-6.1-sol, changes-required at 55fdbfc).
- Finding 5 and the public-doc DoD item: cover every public first-party doc root (`.github/*.md`
  such as SUPPORT.md, README, `docs/`, any other shipped Markdown). The legal-notice route is now
  G's exact-text approval (below): drop the exception branch, or keep a reasoned exemption the test
  honours, so no path leaves the DoD unverifiable.
- Uncovered risk 1: the cmdlet-shaped token scan must tell trusted wrapper operations
  (`Import-Module`, `Connect-ExchangeOnline`, `Invoke-Expression` in the PowerShell adapters) apart
  from audited read commands, without widening the generic read allow-list.
- Work-record paths: no action. Tilde paths in work records are accepted (AGENTS.md itself
  publishes `~/dev` paths). Plan files stay free of absolute workstation paths.

## Record G's answers (8 Nov 2026, scope gate)
- DEC-001 approved by G on 8 Nov 2026: 100 percent = the 1.3.0 release, published as a signed
  v1.3.0 tag plus a GitHub release with wheel and sdist, no PyPI. The tag still needs G's separate
  yes naming 1.3.0 (D9). G also approved merging plan v2 and pushing main. The target-user wording
  stands.
- New decision, approver G: operator-configured notify sinks (Teams and Slack webhooks, Jira,
  GitHub issues) stay in 1.3.0 as allow-listed, opt-in, redacted outbound (class 5), never the
  tenant.
- New decision, approver G: M02-T06 drafts the legal-notice correction, and it merges only after
  G approves the exact text.
- New decision, approver G: retire the parked model layer after 1.3.0 (BACKLOG next; the removal
  list still goes through the deletion gate). Nothing about it changes in 1.3.0.
- Update STATE: pending G items become the exact legal-notice text and, later, the 1.3.0 tag yes.

Do not run scaffold.sh. Small edits only, weights unchanged, `percent.py --check`, commit with a
pathspec, return the RESULT block.
