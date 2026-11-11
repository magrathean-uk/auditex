## RESULT REV-M07-populator
status: done
summary:
verdict: changes-required
reviewed: 7b20407035b2 8684a9425936 60c721533ca4
changes: none
verification: Static inspection, SHA-256 recheck and clean git status PASS; no reviewed-script execution, PowerShell, sign-in or network. Runtime checks excluded by brief.
risks: External delivery and incomplete tenant state remain possible; live API/SDK behaviour unverified; internal free space below the configured threshold.
questions_for_g: none
### Findings
1. CLOSED - populator-app.ps1:33,35,37: application deletion requires the recorded object/application IDs, tag and per-create marker.
2. OPEN (blocking) - populate-content.ps1:173,206: name/time reconciliation can adopt another creator's object, including one predating the intent. Require a persisted per-create marker and verify it before recording ownership.
3. CLOSED - populate-content.ps1:131,136,262,275,291: complete manifest-owned roster and final direct-recipient checks cover mail and event payloads. Delivery routing remains unresolved under finding 4.
4. OPEN (blocking) - populate-content.ps1:212 disables welcome mail, but delivery-preflight.ps1:15,18,19 and populate-content.ps1:266 permit an unreliable delivery clearance. Replace this gate with complete, verified checks described below.
5. CLOSED - populate-content.ps1:36,66,89 and populator-app.ps1:36,62 suppress tenant mutations and journal/secret writes during WhatIf; simulated writes return null.
6. OPEN (blocking) - populator-app.ps1:71,76,81 lack explicit per-step intents; populate-content.ps1:285 invents a sent-message ID, while :250 records the drive without the site ID. Journal each mutation separately and distinguish confirmed IDs from unresolved outcomes.
7. CLOSED - populator-app.ps1:15,50,55 resolves application roles against an exact permission set. The added mail permission is assessed below.
8. OPEN (blocking) - populator-app.ps1:84,85,88 fixes exclusive 0600 creation and verification, but :87 clears the plaintext byte buffer only after a successful write. Clear that buffer in finally alongside the credential.
9. CLOSED - populate-content.ps1:145,186,188 uses assignedLicenses and subscribedSkus, removing the unsupported application-only licenseDetails dependency.
10. OPEN (blocking) - populate-content.ps1:156,157 credits every owned user as already consuming each planned SKU, including unlicensed users. Prerequisites and provisioning errors are unchecked. Count actual assignments, validate dependencies and verify assignment outcomes.
11. OPEN (blocking) - populate-content.ps1:46 handles only delta Retry-After values; :69 leaves SDK automatic retry policy uncontrolled. Handle HTTP-date values and explicitly disable SDK retries for mutation calls before applying the wrapper's retry policy.
12. OPEN (blocking) - populate-content.ps1:86,277,283: a Sent Items lookup failure after an accepted send becomes a retryable failed operation, allowing duplicate mail. Persist acceptance before lookup and never replay that send.
13. CLOSED - populate-content.ps1:248,252 awaits the team drive and journals folder creation; :306 reports missing OneDrives as phase failures, with uploads using the drive root.
14. OPEN (blocking, new regression) - populate-content.ps1:62 returns a non-enumerated array, then :163,170,204 wrap it again: member counts become one and empty collision searches appear non-empty. Fix collection handling consistently; :58 must also reject scalar/malformed values and invalid rows.
2. Mail.ReadBasic.All - Used by populate-content.ps1:283 to read Sent Items metadata. Its unscoped blast radius covers mail metadata across tenant mailboxes, including subjects, senders and recipients; it excludes bodies and attachments.
2. Narrower alternative - No existing grant reads personal Sent Items, and sendMail returns no message ID. Dropping the lookup and honestly recording accepted-but-unconfirmed sends avoids this grant; obtaining actual Sent Items IDs requires additional read authority.
3. Preflight read-only status - delivery-preflight.ps1:7,9,12,15 contains Exchange reads only; :20 writes the local result file.
3. NEW blocking - delivery-preflight.ps1:4 depends on ambient $root and never verifies the Exchange tenant. Initialise its location explicitly and validate the connected tenant against the intended target.
3. NEW blocking - delivery-preflight.ps1:15 suppresses inbox-rule errors; :7,9 lack terminating error handling. At :18, a transport-rule name containing “informational” can suppress its blocking reason. Fail closed on read errors and use structured blocking flags.
3. NEW blocking - delivery-preflight.ps1:9,12,15 checks only the Default remote domain, omits hidden inbox rules, recipient-type/contact/group resolution and journal rules. Enumerate relevant routing configuration and require every final address to resolve uniquely to its expected owned mailbox; refuse unresolved routes. AutoForwardEnabled alone does not establish a forwarding route.
3. NEW blocking - delivery-preflight.ps1:19 accepts any non-empty roster. populate-content.ps1:266 checks neither roster nor tenant, accepts future timestamps and truthy strings, and authenticates nothing. An unchanged timestamp older than two hours fails, but partial, re-dated or hand-edited results can pass. Re-run trusted checks in-phase or authenticate an exact tenant/roster-bound report; require boolean clean and age between zero and two hours.
4. Write boundary - Beyond the listed content resources, populator-app.ps1:37,67,71,76,81 deletes/creates the temporary application and creates its service principal, grants and credential. No tenant policy, authentication-method, sharing or transport-setting writes appear.
4. NEW blocking - populate-content.ps1:213 supplies 25 initial members for the largest group, exceeding the create-group relationship limit. Create with minimal relationships and add the roster through the journalled membership loop.
4. NEW blocking - populate-content.ps1:283 accepts the first subject match without intent-time, recipient or uniqueness checks; :285 records a fabricated ID as done. Correlate a unique operation marker and require exactly one verified result; retain unresolved sends as accepted-unconfirmed.
4. NEW blocking - populate-content.ps1:212,213 adds and subscribes the operator outside the roster; :222 never rejects unexpected members, and :320 checks channel type only. Channel messages and notifications can reach those people. Remove automatic subscription and verify the explicitly authorised audience before posting.
4. NEW blocking - populator-app.ps1:39 removes the fixed secret-file path without proving this run created the current file. Partial creation or replacement can therefore cause deletion of an unowned local file. Verify recorded file creation and identity before removal.
4. NEW advisory - populator-app.ps1:18 overwrites metadata non-atomically; populate-content.ps1:31,38 has no journal lock. Use atomic metadata replacement and exclusive operation ownership to prevent lost records or concurrent duplicate writes.
5. Safe to run once - No. These revisions are not ready for the real trial tenant that cannot be reset; resolve the blocking findings and re-review first.
5. First-run watch after repairs - Run phases serially; watch absolute member counts, actual licence assignments and provisioning errors, membership/notification audiences, mailbox delivery traces and workload readiness. Stop on ambiguous outcomes without replaying writes; preserve journals and verify temporary-app removal afterwards.
