## RESULT M09-T01
status: done
summary: Wrote docs/guides/reader-app-permissions.md for the tenant admin: 30 API permissions (27 Microsoft Graph, Exchange.ManageAsApp on Office 365 Exchange Online and on Microsoft Exchange Online Protection, SharePoint Sites.FullControl.All), each with type, admin consent, reason, collectors and SCuBA policies; then Global Reader, certificate, Power BI setting and group, Power Platform registration, a one-command check, removal and the stolen-key risk.
Checked against lab run m08e3 and the lab app record: Graph list equals the lab token roles (27); 3 differences resolved (.plan/work/M09-T01/evidence.md in the main checkout). Linked from setup-guide.md and admin-permission-guide.md (one line each).
Shipped content criterion met by the existing docs/guides/*.md glob in pyproject.toml and shipped_content.py (adding an explicit entry would duplicate it); a test now asserts the file ships.
No review items (context.md was lead context; items 1-4 followed: plain admin steps, lab comparison recorded, certificate only, no live tenant call).
changes: docs/guides/reader-app-permissions.md, docs/guides/setup-guide.md, docs/guides/admin-permission-guide.md, tests/test_permission_docs_parity.py, tests/test_architecture_modules.py, .plan/work/M09-T01/result.md (commits 7f3018c, 3e759d8, a0fc83c on task/M09-T01-permissions-guide)
verification: verify command (test -s guide && pytest tests/test_permission_docs_parity.py tests/test_architecture_modules.py && grep -qx 'permissions-guide: exact' result.md) pass on a0fc83c, 44 passed; tests/test_docs_paths.py and tests/test_setup_guide.py pass; make lint pass; gitleaks staged clean. Negative cases fail as intended: an extra MailboxSettings.Read Graph row gives "AssertionError: assert ['extra Mailb... the 31 rows'] == []"; a missing guide file gives "AssertionError: assert 'docs/guides/reader-app-permissions.md' in [...]"; the in-suite rejection test covers extra, missing, write-capable, delegated, no-consent, wrong-API and opt-in-collector variants
risks: Exchange Online Protection consent is listed because Microsoft Learn documents it, but the lab compliance reads worked with no recorded grant; admin-centre labels follow Microsoft Learn and current portal names, not a live screen check; M09-T03 must keep the check command's auditex run certificate flags
questions_for_g: none
### Findings
permissions-guide: exact
permissions-listed: 30
lab-grant-differences: 3 resolved
difference: opt-in collector permissions (MailboxSettings.Read, IdentityRiskyUser.Read.All, ConsentRequest.Read.All, eDiscovery.Read.All) are in the code config but not the lab grant; kept out of the grant and listed under Optional collectors
difference: Exchange.ManageAsApp on Microsoft Exchange Online Protection is needed by the code and Microsoft Learn but absent from lab records although compliance reads worked; listed per Microsoft
difference: lab app holds a client secret; guide uses the certificate only (DEC-107)
