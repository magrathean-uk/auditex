## RESULT M01-T02
status: done
summary: Fixed all 3 items from REV-M01-T02 (round 3) in the inventory; no unclassified rows; 77 rows unchanged.
- 1 fixed: section G gets a fourth exposure, exchange_policy.py:126 Get-TransportRule ApplyHtmlDisclaimerText (an admin-written body template). It is marked RETAINED: minimise_recipients only rewrites _RECIPIENT_KEYS, normalize.py:2107 keeps it in normalised output, only the SCuBA projection drops it. G intro and column header now separate retention from stripping; PrependSubject added as a related retained exposure.
- 2 fixed: A21 now shows the fixed https://oauth2.googleapis.com/token (from_authorized_user_info always overrides token_uri; confirmed in google-auth upstream source). A24, E and F split cached credentials (fixed endpoint) from flow-acquired credentials (OAuth client file token_uri, configurable).
- 3 fixed: C1 moved to auth_runtime.py:47 and C21 to command_runner.py:109. Header records that line numbers are unchanged at 462e13f (no src diff since 340552f).
changes: .plan/work/M01-T02/transport-inventory.md (work artefact, not committed; criteria say no repository file changes and .plan belongs to the orchestrator)
verification: `test -s .plan/work/M01-T02/transport-inventory.md && ! grep -n '| unclassified |' ...` from the repo root - pass; `git diff --stat 340552f 462e13f -- src` empty - pass; cited lines rechecked in source - pass; worktree `git status --porcelain` empty - pass. No module test command run: the brief is read-only and changes no code.
risks: Static inventory only; T04 must explicitly accept or remove the retained disclaimer and PrependSubject text. SessionStart hook reported that clean-development lifecycle registration failed; `clean-development doctor` was not run here (the reviewer's run also failed: routing, lifecycle-lock ownership, dot-folders); G should check it.
questions_for_g: none
