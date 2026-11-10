## RESULT PASS-verify
status: done
summary: First-pass findings 2-6 and 8-10 resolved; finding 1 covered by the checkpoint exception; finding 7 remains unsubstantiated. Model facts, branch names, unused v4 names and five gate questions match the cited records.
changes: none
verification: PASS: source comparisons, git refs, name-collision checks, identifier scan and gitleaks on the passover; fuller gitleaks example reproduced. FAIL: quota.sh exited 3, API unreachable. Builds and suites skipped for this read-only review.
risks: Passover identifiers: github.com, magrathean-uk/auditex, claude, claude-1 through claude-5, codex, codex2, AIRR, Isambard-AI and Dawn. No credential or token values, IP addresses, or named tenants or clients found.
questions_for_g: none

### Findings

1. L203-206, first-pass finding 7: the revised 37-minute duration and exit 144 remain unsubstantiated by retained evidence. Correct to: “A previous long run died when its launching shell stopped; use run-job and wait on its .done marker.” Supported by `.plan/work/M02-T04/result.md`.

2. L9-11 and L61-64: quota figures, reset times and current eligibility could not be verified. Correct to: “These are the last reported quota figures; refresh quota.sh before dispatch. Current usage, reset times and eligibility remain unverified.”

3. L79-80 and `.plan/work/PLAN-v4/answers.md`: “each reviewed merge or checkpoint” leaves checkpoints unqualified. D2 and D9 authorise reviewed changes; D10 transfers leadership. Correct to: “Fast-forward pushes of reviewed changes to main, including reviewed checkpoints, are authorised through pushgate.sh with gitleaks over the new range. Tags, releases and new repositories remain reserved.”
