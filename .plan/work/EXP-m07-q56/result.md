## RESULT EXP-m07-q56
status: done
summary: Read-only review of the kit, the tenant records and the reader script, with no PowerShell or network use.
summary: Q1 yes. Q2 saves 2 windows with `-Products` on the rerun, or 8 by dropping the first run. Q3 costs +1 window anywhere before D, and 0 at its current slot.
summary: Four points are inferred, not stated in the files, and are marked in the findings.
changes: none (notes written to .plan/work/EXP-m07-q56/notes.md and progress.md)
verification: none (read-only; no commands that run the kit)
risks: Whether a silent Graph renewal survives ScubaGear's Process-scope connect is unobserved (kit/LIMITS.md:222).
risks: The reader script has not yet had the Auditex lead's review (dt-live/phaseE/COMMANDS.md:14).
risks: A pre-D collection can only be the variant without `--break-glass-accounts`, because the group is created by 00-identity.
questions_for_g: none
### Findings
1. yes. The kit has no apps, service principals, consent grants or object-count census. Preflight reads only each script's own objects, then Complete-DtPreflight (kit/populate/_common.ps1:152-155, kit/populate/README.md:243). A grep of kit/populate/*.ps1 finds only the Graph service principal's permission classifications (05-entra-settings.ps1:102-103, 90-verify.ps1:360), which this app does not touch. A "0 dt./DT- objects" assertion is absent (inferred from the grep). No expected verdict depends on apps, service principals, consent or credentials. AAD 5.5-5.7 use the default app-management policy (kit/BLUEPRINT.md:113-115, 05-entra-settings.ps1:167-171). AAD 7.x counts only eight roles, and Global Reader is not one (_common.ps1:3369-3378, 90-verify.ps1:475-480). Rollback deletes only journalled objects, so it neither removes nor reports the app (README.md:67, kit/LIMITS.md:177, README.md:157). "Auditex Reader (lab)" matches no kit prefix, which are `dt.` and `DT `/`DT-` (tenant.config.example.json, README.md:99). The kit text already places the app outside the kit and before step 12 (README.md:157). Conditions:
   - Use the exact name and the script unchanged, after the lead's review.
   - Allow one operator sign-in plus the permissions page.
   - Record row 8 in OUT-OF-KIT-WRITES.md straight after, and replace its "create at step 12" paragraph (dt-live/OUT-OF-KIT-WRITES.md:16-19).
   - Row 8 needs the time, app and service principal, the 25 Graph consents plus Exchange.ManageAsApp, Global Reader, the secret (expiry 31 Dec 2026) and its file path, and the undo.
   - Row 8 also needs the new delegated grants the sign-in adds: Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All and RoleManagement.ReadWrite.Directory (create-auditex-reader-app.ps1:10, same class as OUT-OF-KIT-WRITES.md:30-31).
2. 2 windows saved (alternative: 8). The two verify runs are 8 windows each: Entra, Exchange, Security and Compliance, Teams, Teams apps, SharePoint, Power BI, Power Platform (dt-live/G-SHEET.md:39, 90-verify.ps1:212,531,813,919,940,998,1026,1060).
   - **Why twice:** step 10 is the day-after baseline. Step 11 reruns with `-ScubaResults` to settle TEAMS 2.1/2.3, AAD 5.6, the SecuritySuite and Power Platform export joins, and to refreeze DNS inside compare.py's 24 h limit (90-verify.ps1:30-35,56,1214, compare.py:188,757). The Teams provisioning wait is a separate gate between the runs (dt-live/phaseE/COMMANDS.md:11).
   - **Cut A (2 windows):** run E5 with `-Products AAD,EXO,SECURITYSUITE,TEAMS,POWERPLATFORM` (parameter at 90-verify.ps1:25). `-ScubaResults` changes none of the other products' rows (90-verify.ps1:56), and compare.py needs only EXO and dnsFrozen (compare.py:757-775). This drops the SharePoint and Power BI windows. Cost: no second reading of those two products at step 11, and it departs from the README command text, not from code.
   - **Cut B (8 windows, instead of A):** skip E2 and run one full E5 after E1, E3 and E4. Cost: no pre-oracle all-MATCH baseline, so drift shows only after the 5 ScubaGear windows and inside the 24 h clock.
   - **Inferred, no change needed:** E5's Entra window is likely silent because 90-verify never disconnects (kit/LIMITS.md:222), saving 1.
   - **Not cut:** no product can be skipped for lacking an expected verdict (90-verify.ps1:1285), and the Exchange/Security and Compliance and Teams/Teams apps pairs are already one process, with separate tokens.
3. +1 window anywhere before D, and 0 at the current slot. Disconnect-MgGraph deletes the SDK record (create-auditex-reader-app.ps1:56, _common.ps1:1946-1949, kit/TRIAL-FACTS.md:8). The next kit script's Connect-DtGraph then opens a browser instead of signing in silently (_common.ps1:3155-3190, kit/LIMITS.md:222), possibly with a permissions page. Placement:
   - **Current slot (E7, after E5/E6):** no extra window. Only E8 follows, and it uses the app, so no kit Graph sign-in comes after (COMMANDS.md:14). Its own window is the counted Part 3 item (G-SHEET.md:41).
   - **Before D:** costs +1, because the next kit Graph step (Part 1 step 1, "usually silent", G-SHEET.md:13) becomes a browser sign-in.
   - **The only free slot earlier:** straight after the 9b check's own Disconnect and before `10 -Enforce`, whose Entra window is already counted (G-SHEET.md:32). That is after D, not before.
   - **Inferred alternative:** dropping the script's final Disconnect-MgGraph keeps the record for the next kit script (a one-line edit to a non-kit script).
