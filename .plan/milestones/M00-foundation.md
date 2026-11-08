---
id: M00
name: foundation
weight: 100
status: planned
---
# M00 foundation
No feature work before this milestone is green.

## Goal
CI, test harness, lint, secrets scan and dependency audit exist and pass on the default branch.

## Definition of Done
- [ ] CI runs on every push and is green: `<ci status command>`
- [ ] Test harness runs locally and in CI: `<test command>`
- [ ] Lint passes: `<lint command>`
- [ ] Secrets scan passes: `gitleaks detect --no-banner`
- [ ] Dependency audit has no high or critical findings: `<audit command>`
- [ ] Review: sol confirms the ARCHITECTURE.md ownership map matches the repository

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M00-T01 | <title> | terra | S | mechanical | todo |

## Acceptance criteria
### M00-T01 <title>
- <binary criterion>
- verify: `<command>`
- files: `<paths this task owns>`
