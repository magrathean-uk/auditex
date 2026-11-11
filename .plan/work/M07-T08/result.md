## RESULT M07-T08
status: done
summary: No verify row, EXPECTED-VERDICTS expectation, compare.py check or pinned-rule input depends on content or on counts of users, guests, groups, teams, sites, mailboxes, messages or files. A row moves only if the population changes roles, app or consent policies, domains, Exchange sharing or Teams policies, or Power BI service-principal settings.
The risks are practical: the 60-member size guard (shared and room mailboxes count towards it), the 16 free E5 seats, the kit's names and guest address, and the populator's credential lifetime.
The worst case is running the population while a kit script runs: one throttled create stops the script and blocks every later writing script until it is resolved.
Recommended order: populate everything before step 1, then run no population until step 12 is scored. Evidence is in .plan/work/M07-T08/notes.md.
changes: .plan/work/M07-T08/notes.md only; kit untouched
verification: grep, awk and Python JSON reads of kit-ro, plus one read of the repo for the Auditex user sample size; no PowerShell, sign-in, tenant contact or network
risks: (1) Not checked offline: whether a credential added before step 3 still works after the app management policy, and whether shared and room mailbox accounts read as userType Member. (2) No measurement of whether the populator's API calls can throttle the kit's. (3) Rollback never removes population objects.
questions_for_g: none
### Findings
1. Expected results
- Inputs: kit-ro/tools/rego-dependencies.json rows read only policy, setting, role, SKU, domain and environment keys (key definitions at :1095-1130,1605; full list in notes). kit-ro/populate/90-verify.ps1 reads only organisation-level objects: Entra ID :237-524, Exchange and Defender :531-910, the SharePoint tenant object :917-935, Teams policies :938-1018, Power BI and Power Platform :1021-1112. kit-ro/populate/30-sharepoint.ps1:88 confirms it reads the tenant object, not sites. No kit script lists mailboxes, sites, teams, drives or messages.
- Rows that move only if the population touches them:
  - Entra ID 7.1-7.5: any population user, group or the populator app gets one of the eight privileged roles; a group holding a role makes them UNKNOWN (90-verify.ps1:475-507; kit-ro/populate/_common.ps1:3160-3169).
  - Entra ID 5.2 and 5.5-5.7: see item 4.
  - Exchange DNS rows and security suite 1.x, 2.x and 6.x: a new accepted domain (90-verify.ps1:547-562,596-599).
  - Exchange 6.1 and 6.2: a new sharing policy (:538-541).
  - Teams 1.1, 1.2, 1.5 and 4.1: a new meeting policy or client configuration (:945-949,987-992).
  - Power BI 4.1 and 4.2: enabling the service-principal API settings (:1047-1048).
- Unaffected products: Exchange, Defender and the security suite, SharePoint and OneDrive, Teams, Power BI and Power Platform. Power Platform 2.2 is met by the kit's all-environments DLP policy before environments are read (90-verify.ps1:1089-1098; kit-ro/populate/70-powerplatform.ps1:92-96).
- Licences per user matter only as E5 seats at 00 (kit-ro/populate/00-identity.ps1:193-198) and the operator's own Power BI licence (kit-ro/compare.py:285-287). The Entra ID P2 check counts SKUs, not assignments (90-verify.ps1:237-246).
- Auditex side only: rows 7.1-7.3 reach the model through a sample of the first 100 users (kit-ro/LIMITS.md:20). Keep members, guests and mailbox accounts together under 100.
2. Guests
- The kit invites its guest once, without an invitation mail, with a display name carrying a random marker written to the journal before sending (00-identity.ps1:364-381; _common.ps1:2332-2338).
- It finds the guest only by mail equal to the configured guest address (00-identity.ps1:129,219,366-369; _common.ps1:1273). Ownership is proved by the marker name, the mail, the guest type and a server-time window (_common.ps1:2357-2393). Rollback proves it again before deleting the journalled id (kit-ro/populate/99-rollback.ps1:270-308,341-345).
- Other guests are invisible to all of this unless they use the kit's guest address. Then the pre-send check, which looks at any user and not only guests, refuses to send (_common.ps1:2339-2355). Or the invitation returns an existing id and 00 stops (00-identity.ps1:220-222,379).
- Renaming the kit's guest breaks the rollback proof, so rollback leaves it for manual removal. A failed guest create needs exactly one candidate with that mail to resolve (_common.ps1:1435-1437,1457).
- Guest-related rows read settings, not counts: Entra ID 8.1 and 8.2 (90-verify.ps1:369-370), Power BI 2.1 (:1045), SharePoint (:926-933). After step 7, SharePoint sharing is limited to the configured partner domains (30-sharepoint.ps1:49-51).
3. Guards and lookups
- Size guard: refuses -Apply in 00, 05 and 10 above 60 member users, counted in one page of up to 999 (_common.ps1:3178-3187; 00-identity.ps1:39; 05-entra-settings.ps1:31; 10-conditional-access.ps1:42). 2 existing + 18 kit + 25 = 45. Shared, room and equipment mailbox accounts count; guests do not.
- Seats: free E5 seats must cover the unlicensed kit users at 00 -Apply (00-identity.ps1:156-163,193-198). Every new trial SKU is read strictly (:140-176).
- Exact-name lookups, where a duplicate fails the run:
  - Groups DT-CA-Exclusion-BreakGlass, DT-Finance, DT-Engineering and DT-Sales (00-identity.ps1:79,92-98,204; 10-conditional-access.ps1:68; 90-verify.ps1:213-218; kit-ro/tools/New-ScubaConfig.ps1:50).
  - Users dt.<short> (_common.ps1:45,2607-2611; 99-rollback.ps1:326-333).
  - Teams custom meeting policies (kit-ro/populate/40-teams.ps1:82-87).
- Page limit is 200 Graph pages (_common.ps1:1935,1969), far beyond these numbers. No lookup scales with content, so none slows down.
- Creating teams or sites changes no SharePoint tenant field the kit writes (30-sharepoint.ps1:48-58) and no Teams setting it writes (40-teams.ps1:74-160). The kit assigns no Teams policy to users.
4. Second application
- No row reads app registrations, service principals in general, or permission and consent grants; nothing in kit-ro calls those APIs.
- 5.1 reads whether users may create apps (90-verify.ps1:348). 5.2 reads the user-consent policy and classifications on eight Microsoft service principals (:352-368). 5.3 reads the admin consent workflow setting (:372-386). Consenting the populator app moves none of them.
- 5.5-5.7: the kit's policy also covers the populator: secrets last at most 90 days, certificates at most 400 (05-entra-settings.ps1:166-172). A custom app management policy to exempt it makes 5.5-5.7 UNKNOWN (90-verify.ps1:389-396). Its service principal must hold none of the eight roles.
5. Order and concurrency
- (a) Before step 1: safe, provided the guards in item 3 hold. The 00 dry run then shows the real member count and seat figures.
- (b) Between verify and the final audit: no row moves, but compare.py refuses a DNS snapshot more than 24 h from the Auditex start (compare.py:120,953-984) and a resumed Auditex run (LIMITS.md:150-155). A setting changed after step 11 is seen by Auditex only.
- (c) After scoring: results are unaffected. Rollback removes only journalled kit objects (99-rollback.ps1:312-345); population objects stay, and teams owned only by kit users lose their owners.
- (d) During a kit script:
  - Each create is sent once (_common.ps1:1884-1923,2907-2908). A 429, 408 or 5xx answer leaves the outcome unknown (:1198-1211), stops the script and blocks every later writing script.
  - Clearing that block as "not created" needs two empty reads at least 600 s apart (:150-167,1410-1421).
  - REST reads give up when the requested wait is over 120 s (:2922-2933), which turns verify rows UNKNOWN (90-verify.ps1:187-196).
  - The kit's state-folder lock covers kit scripts only (_common.ps1:100-106).
  - After 9b, Conditional Access blocks legacy and device-code sign-in and requires MFA for every user (10-conditional-access.ps1:112,120,133-134).
- Recommended: populate fully once step 0's services answer, before the 00 dry run. Run no population from 00 -Apply until step 12's compare.py finishes; top-ups only after step 12 and before rollback. If the population runs late: content only, app-only, after the 9b after-check and finished before step 10.
Rules for the tenant session's population
- At most 60 members in total, counting shared, room and equipment mailboxes. Use no seats of the configured E5 SKU, and rerun the 00 dry run after starting any new trial.
- Never use the dt. user prefix, the DT- group names, the kit's display names (00-identity.ps1:56-77) or the kit's guest address. Never rename or reuse kit users, kit groups or the kit's guest.
- No admin roles and no role-assignable groups. No custom app management policy and no permission classifications. Populator secret at most 90 days, or a certificate at most 400 days.
- No new accepted domains, Exchange sharing policies or remote domains. No Teams policies of any kind and no custom Teams apps. No Power BI or Power Platform settings, and no Power Apps in teams.
- Use the populator's own app-only access, never the operator's account or sessions. Send internal mail only, at a moderate rate, through Graph, not SMTP AUTH.
- No test data that looks like SSN, ITIN or card numbers: the kit's DLP rule blocks access to it for everyone (50-defender.ps1:253-276).
- Nothing while any kit script, verify, ScubaGear or Auditex run is active. Remove all population objects by hand when the trial ends.
Kit source changes
- None needed.
