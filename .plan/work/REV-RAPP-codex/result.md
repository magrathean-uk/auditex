## RESULT REV-RAPP-codex
status: done
summary:
verdict: changes-required
C = dt-live/create-auditex-reader-app.ps1; R = dt-live/remove-auditex-reader-app.ps1; record = dt-live/READER-APP-RECORD.md.
One blocking path remains: sign-in can change the shared Graph client's consent.
changes: none; progress file skipped because the sandbox is read-only
verification: PASS: git status clean; cat/nl/sed/rg inspection, r0-to-fix diff, SHA-256 comparison with author notes. No PowerShell, sign-in or network.
risks: sign-in scope behaviour unverified offline; runtime behaviour untested
questions_for_g: none
### Findings

1. Required change 1 - fixed under DEC-057: C26-29 records the opt-in exclusions and delegated-only coverage gap; C73-78 retains the default 25 permissions.
2. Required change 2 - not fixed: C261-274 permits new shared-client consent through -AllowConsent. Process scope, scope checks and finally cleanup are present (C268-275,421).
3. Required change 3 - fixed wording: C15-24,79-81 explains Exchange capability and Global Reader restriction; C353-365 checks active directory assignments, subject to the limitation below.
4. Required change 4 - fixed statically: C114-127,214-240,368-390 creates the internal records-file privately before requesting plaintext, refuses overwrite/links and validates expiry; C59-63,414-420 suppresses diagnostics and clears secret references.
5. Required change 5 - fixed for reader-object writes: C143-153,317-390 journals intent and returned IDs around each step. Shared-client consent remains outside this protection.
6. Required change 6 - procedure supplied: R165-289 checks targets, removes and records results; record31-39 supplies both rollback rows. Actual completion must be recorded after removal.
7. Required change 7 - fixed statically: C212-255,279-297 validates prerequisites and role matches; C179-192 provides bounded reads; C260,276 checks retry configuration; C414-422 guarantees cleanup.
8. Point 2, secret - no direct plaintext path to screen, transcript, journal or another file found. C371 captures the response; C378-390 writes only through the pre-opened private handle. Runtime logging remains untested.
9. Point 2, intent - C320-390 precedes each reader-object mutation with saved intent; C262-263 can obtain shared-client consent before the first journal save at C317.
10. Point 2, partial runs - a lost create response can leave an app without journalled IDs (C321-324); R135-138 refuses automatic removal and requires manual reconciliation.
11. Point 2, sign-in - C266-276 refuses a context missing provisioning scopes before reader-object writes. Omitted -Scopes obtaining existing grants without consent is not established by the available offline evidence.
12. Point 2, role proof - C357-365 checks one response page for exactly Global Reader at tenant scope; it does not establish an exhaustive, continuing guarantee across role systems.
13. Point 3 - R165-234 checks identities and prints a plan; R243-287 journals deletion and completion. Deletion targets remain confined to the reader objects with an authentic journal, but consent can affect the kit's shared client even without -Apply.
14. Point 4 - record31 accurately lists intended reader objects, grants and undo steps; its delegated-consent delta cannot be reconstructed from C304-306, and completion claims require successful read-backs.
15. BLOCKING B1 - C262-263 and R155-156 can add or extend consent on another enterprise app before intent is recorded; removal plan mode permits this too. Remove -AllowConsent from both scripts and use an authentication path that cannot grant consent, refusing missing authority before any mutation.
16. Non-blocking suggestion - C261-271: establish the pinned SDK's omitted-scope behaviour and document a proven existing-grant authentication path.
17. Non-blocking suggestion - C346,357-362 and R200,214: follow pagination before claiming exhaustive consent or role checks; describe the role guarantee as active Entra directory assignments.
18. Non-blocking suggestion - R189-193,237-243: persist reconciled IDs at the top level before deletion; otherwise a later retry can miss a soft-deleted service principal after an interrupted removal.
19. Non-blocking suggestion - record18-24,31: update the phase E instructions and avoid copying plaintext into another env file if the single-file containment requirement continues.
