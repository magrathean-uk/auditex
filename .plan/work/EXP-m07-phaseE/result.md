## RESULT EXP-m07-phaseE
status: done
summary: PHASE-E-COMMANDS.md step E7 now lists the printed lines in the script's order, including the sign-in line and the full Global Reader line. READER-APP-RECORD.md now gives the env file as `dt-live/auditex-reader-app.env`, and has a new "Stated limit" section.
changes: PHASE-E-COMMANDS.md and READER-APP-RECORD.md under the `dt-live` records folder (outside the repo; no repo files changed)
verification: compared the expected lines against the create script's printed strings (preflight, sign-in, app created, service principal, admin consent, Global Reader, secret saved, journal, done): pass. Script sha256 check: pass.
risks: none
questions_for_g: none
### Findings
- 1: E7 now reads `preflight: OK (...)`, `sign-in: a browser opens; ...`, `app created`, `service principal`, `admin consent granted`, `Global Reader ... and it holds no PIM eligibility`, `secret saved ...`, `journal: ...`, `done`. This matches READER-APP-RECORD.md L14-18 and the create script.
- 2: The "Paths that changed from r0" paragraph now names `dt-live/auditex-reader-app.secret` and `dt-live/auditex-reader-app.env`. It still mentions the old `tenant-bootstrap/.secrets/...` path once, only to say it was replaced. The "Stated limit" section is added with the wording you gave.
- 3: Edited-file sha256: PHASE-E-COMMANDS.md `125fdbe460e43e20699eec38a29be41951370a6c416026a476aaa03c269925cf`; READER-APP-RECORD.md `900e7e654aa47bdafba9c9a3eaa99ed37f30b2b5f38a292c05eb4af17b6c9122`. Both scripts are unchanged: create is `d5e9fe6249be...`, remove is `6e02c71dc066...`.
