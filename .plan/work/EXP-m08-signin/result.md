## RESULT EXP-m08-signin
status: done
summary: Delegated interactive runs prompt once per run (graph.py:415-453, token_cache=None at :436). Azure CLI runs need one prior `az login` (guided.py:129). Guided runs with `--include-exchange` prompt twice (guided.py:241-300).
changes: none (notes only in .plan/work/EXP-m08-signin/)
verification: none run; read-only code and Microsoft documentation review
risks: (1) Compliance session (D) needs a second admin consent on the reader app, on a different resource from today's Exchange consent. (2) Whether Power Platform registration can reuse one account's token is unverified. (3) The audience string for the compliance token is unconfirmed.
questions_for_g: Guided delegated with Exchange (az login plus m365 login) breaks DEC-065. Recommend dropping the m365 Exchange step from that path, so Exchange stays app-only. Do you agree?
### Findings
- App secret: 0 prompts for Graph, Exchange, Power BI and Power Platform (graph.py:370, exchange_policy.py:112, power_bi.py:26, power_platform.py:40). Compliance is never opened (collection_gaps.py:55). Teams refuses a secret token (teams_policy.py:86-96), so it is not collected.
- App certificate (A1 branch): 0 prompts. One msal `ConfidentialClientApplication` mints every app token silently (`_certificate_token` in graph.py on the branch).
- Delegated interactive: 1 prompt for Graph, and it repeats every run because `token_cache=None`. Other services are dropped (selection.py:29-31) or get no token (graph.py:337), so none prompt.
- Azure CLI token: 0 prompts inside Auditex (auth_runtime.py:44-69), 1 for the prior `az login` (guided.py:129, 379, 520). Guided `--include-exchange` adds `m365 login --authType browser` (guided.py:241-300, 528), so 2.
- Default and full presets show the same counts. Neither selects `teams_policy`, `power_bi` or `power_platform` on main (profiles.py:21-80, configs/collector-presets.json).
- Q2, setup today: delegated needs 1 sign-in (admin-permission-guide.md:124). The app registration, consent, Exchange.ManageAsApp, role and certificate fit one Entra admin session (setup_guide.py:358-380). Power BI is a portal setting (guide:311-318). Power Platform needs its own `Add-PowerAppsAccount` sign-in (guide:323-327). The optional set needs at least 3 sign-ins, or 2 if Entra and the Power BI portal share a browser session.
- Q2, can it be one: only if the Power Platform registration can use a token from the same account. I found no Microsoft source for that.
- Q3, A1: keep the single certificate client. Delegated stays unchanged and Teams is skipped, not prompted, because the Teams gate requires a certificate claim and no `scp` (teams_admin_rest.py `certificate_token`).
- Q3, B: Power BI and Power Platform tokens must come from `app_token_for` and never prompt. Microsoft requires the app to hold no admin-consent Power BI application permission ([doc](https://learn.microsoft.com/en-us/power-bi/admin/read-only-apis-service-principal-authentication)). The two enablement steps are one-time customer sign-ins; the docs should state that count.
- Q3, C: reuse A1's Teams certificate token and audience, so 0 prompts.
- Q3, D: build the compliance token with the certificate client and pass it through `Connect-IPPSSession -AccessToken`, like powershell_graph.py:185-197. Microsoft supports `-AccessToken` only from module 3.8.0-Preview1, and `-CertificateThumbprint` is Windows-only ([ref](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/connect-ippssession)). App-only compliance needs Exchange.ManageAsApp on "Microsoft Exchange Online Protection" plus a role such as Global Reader ([doc](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2)). Delegated cannot open it, so it stays a named skip.
- Q3, delegated reuse: one shared in-memory MSAL cache with `acquire_token_silent` per resource would give one prompt. Teams and compliance stay blocked in delegated mode by the product's certificate gate, not by a Microsoft limit.
- Q4 (1): app-only certificate is the one no-prompt path for all six services; delegated stays Graph-only with named skips.
- Q4 (2): add acceptance tests. They check 0 interactive calls in app and certificate modes, 1 in delegated with a shared cache, and compliance via `-AccessToken` only.
- Q4 (3): add to B and D that the docs state setup sign-in counts and D's extra Exchange Online Protection consent. Also add a check that nothing in the run path calls `Connect-*` interactively or `az login`.
