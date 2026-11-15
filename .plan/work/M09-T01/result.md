## RESULT M09-T01
status: done
summary: docs/guides/reader-app-permissions.md is the one guide for a customer's tenant admin: 30 application permissions (27 Microsoft Graph, Exchange.ManageAsApp on Office 365 Exchange Online and on Microsoft Exchange Online Protection, Sites.FullControl.All on SharePoint), each with type, admin consent, reason, collectors and SCuBA policies; then Global Reader, the certificate, the Power BI setting and group, the Power Platform registration, a one-command check, removal and the stolen-key risk. Built from collector needs and checked against lab run m08e3 and the lab app record: Graph list equals the lab token roles (27), 3 differences resolved (evidence.md in the main work folder). Linked from setup-guide.md and admin-permission-guide.md. Shipped by the existing docs/guides/*.md glob in both lists, so pyproject.toml and shipped_content.py are unchanged; a test now asserts the file is shipped.
changes: docs/guides/reader-app-permissions.md, docs/guides/setup-guide.md, docs/guides/admin-permission-guide.md, tests/test_permission_docs_parity.py, tests/test_architecture_modules.py, .plan/work/M09-T01/result.md
verification: test -s docs/guides/reader-app-permissions.md && pytest tests/test_permission_docs_parity.py tests/test_architecture_modules.py pass (44); tests/test_docs_paths.py and tests/test_setup_guide.py pass; make lint pass; gitleaks staged clean; negative cases fail as intended: an extra MailboxSettings.Read Graph row gives "AssertionError: assert ['extra Mailb... the 31 rows'] == []", and a missing guide file fails the shipped assertion
risks: Exchange Online Protection consent is listed because Microsoft documents it, but the lab compliance reads worked with no recorded grant (difference 2); the guide's admin-centre labels follow Microsoft Learn and current portal names, not a live screen check; M09-T03 must keep the check command's flags (auditex run with --certificate-path and --certificate-thumbprint)
questions_for_g: none
### Findings
permissions-guide: exact
permissions-listed: 30
lab-grant-differences: 3 resolved
difference: opt-in collector permissions (MailboxSettings.Read, IdentityRiskyUser.Read.All, ConsentRequest.Read.All, eDiscovery.Read.All) in code config, not in lab grant; kept out of the grant, listed under Optional collectors
difference: Exchange.ManageAsApp on Microsoft Exchange Online Protection needed by code and Microsoft Learn, absent from lab records although compliance reads worked; listed per Microsoft
difference: lab app holds a client secret; guide uses the certificate only (DEC-107)
