## RESULT M09-T05
status: done
summary: Version bumped to 1.6.0 and the CHANGELOG entry finished. It states the one-way change first and lists the removed ways, notes that `CONTRACT_VERSION` stays `2026-11-11`, and says the M10-T02 modules are "groundwork, not yet used". `make release-check` passed on the committed head and `make dist` built the wheel and sdist. hostload gave no slot, so release-check ran directly as the lead authorised.
changes: pyproject.toml, CHANGELOG.md, .plan/work/M09-T05/result.md (no `src/**/__init__.py` holds a version string, so none changed)
verification: `make release-check` pass (lint clean; 23514 passed, 271 skipped, 7 deselected, 34 xfailed; contract-smoke, release-archive, rule-pack drift, taint scan clean, gitleaks "no leaks found"); `make dist` pass; `grep -qx 'release-check: pass' .plan/work/M09-T05/result.md` pass; repository lint ran as part of release-check; negative cases: `auditex auth status`, `--client-secret` and `--use-azure-cli-token` refused by name, `--flow gr-audit` rejected as an invalid choice; `git status --porcelain` empty
risks: the wheel was built under umask 077, so it carries 0600 file modes (the known BACKLOG umask item), and its sha256 will differ from a build under umask 022; the wheel and sdist sha256 (1f5d94c4…6d34, 5c5df9d6…7d33) are in .plan/work/M09-T05/result.md; hostload gave no slot (a 2-hour wait, then two exits of 75), so the suite ran outside the slot on a busy host
questions_for_g: none
### Findings
release-check: pass
(lead: the RESULT block omitted the Findings section; make release-check passed on the branch head, 23,514 passed)
