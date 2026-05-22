# Auditex 1.0 Ultimate Audit Plan

## Goal

Auditex 1.0 is an audit-only autopilot for Microsoft 365 and Google Workspace. It should collect read-only evidence, prove each finding from saved artifacts, explain every limitation, and produce a client-ready report that a human auditor reviews instead of assembling by hand.

Non-goals for 1.0:

- No production fixes.
- No tenant writes from audit, probe, report, export, or MCP audit tools.
- No Gmail body reads, Drive file content reads, Exchange mailbox body reads, or SharePoint/OneDrive file content reads.
- No secrets or raw tokens in report, AI-safe, or customer handoff artifacts.

## 1.0 Release Gates

1. **Provider parity**
   - Microsoft 365 and Google Workspace both run through the same bundle finalizer.
   - Both emit `run-manifest.json`, `summary.json`, `reports/report-pack.json`, `data-handling.json`, `audit-plan.json`, `api-inventory.json`, `live-readiness.json`, `ai_context.json`, `index/evidence.sqlite`, and `validation.json`.
   - Old Microsoft 365 bundles remain readable and valid under the stable required artifact list.

2. **Read-only proof**
   - Every audit path has a data-handling declaration.
   - API inventory proves observed calls, methods, permissions, data class, read/write classification, and content-read status.
   - Contract validation fails audit-plane bundles that report writes or content reads.
   - Response/lab tooling stays hidden unless explicitly enabled for local development.

3. **Evidence gates**
   - The audit planner records selected collectors, expected collectors, required scopes, missing scopes, and pass/fail status.
   - Quality gate is one of `complete`, `partial`, or `unusable`.
   - Blockers are classified as `auth_scope`, `admin_role`, `license`, `service_absent`, `local_tool`, `tenant_policy`, `runtime`, or `unverified`.
   - Every partial or unusable run gives exact next action.

4. **Finding quality**
   - Every finding has severity, status, category, affected objects, confidence, blast radius, business impact, remediation, false-positive notes, framework mappings, and evidence refs.
   - Report QA fails unsupported claims and warns on low-confidence findings or coverage gaps.
   - The proof table maps each finding claim to exact collector, artifact path, artifact kind, record key, and optional JSON pointer or endpoint.

5. **Client-ready reporting**
   - Report pack includes executive summary, technical appendix, limitations, proof table, next actions, auditor score, attack paths, dry-run control simulator, report QA, and replay context.
   - Markdown, HTML, JSON, CSV, SARIF, OSCAL, and MCP surfaces are generated from the same bundle data.
   - Every answer from MCP must cite bundle evidence or explicitly say the evidence is missing.

6. **Drift and replay**
   - Saved bundles can be analyzed without live tenant access.
   - Drift mode shows new, resolved, and worsened findings.
   - Accepted risks have expiry and are not silent forever.
   - Notifications fire on real posture change, not ordinary rerun noise.

## Microsoft 365 1.0 Coverage

Minimum live access target: delegated read login or app-only read permissions where available. Basic tenants must still produce useful output and clear license blockers.

Required surfaces:

- Entra identity: users, admins, roles, privileged assignments, auth methods, stale or disabled privileged accounts.
- Conditional Access: policies, exclusions, emergency access coverage, MFA coverage, legacy auth posture where visible.
- Audit and sign-in logs: available log windows, failed access due to license or role limits, risky sign-in signals where licensed.
- App consent: enterprise apps, OAuth grants, risky permissions, stale app credentials, consent policy posture.
- Exchange: forwarding, mailbox delegation, transport rules, audit settings, external forwarding posture without reading mailbox bodies.
- SharePoint/OneDrive: tenant sharing posture, site sharing settings, external exposure metadata without file content reads.
- Defender/Secure Score: score and recommendations where available, with license blockers explicit.
- Intune and devices: compliance posture, device inventory metadata, policy presence where available.
- DNS/domain posture: SPF, DKIM, DMARC, MX alignment, tenant domain posture.

## Google Workspace 1.0 Coverage

Primary live path: domain-wide delegation with service account JSON and delegated super admin subject. OAuth is supported but can be partial.

Required surfaces:

- Directory: users, aliases, groups, members, org units, domains, roles, role assignments, admin status, suspended status, 2SV enrollment.
- Reports: admin, login, OAuth token, Drive, mobile, Chrome, groups, usage events where scopes and editions allow.
- Alert Center: active alerts and alert metadata.
- Gmail settings: forwarding, filters, delegates, send-as, POP/IMAP posture without body reads.
- Drive metadata and sharing: file metadata and permissions where allowed, no file content reads.
- Groups settings: external posting, external membership, public or broad exposure.
- Calendar sharing: domain and external sharing posture where available.
- Devices: mobile and ChromeOS metadata, compromise or stale sync signals.
- DNS/domain posture: SPF, DKIM, DMARC, MX alignment for Google Workspace mail.

## Deepening Opportunities

1. **Provider adapter module**
   - Problem: Microsoft 365 and Google run paths still know too much about finalization and capability rows.
   - Solution: define a small provider run interface around plan, auth, collect, normalize, find, finalize.
   - Benefit: provider-specific implementation stays local while bundle contract leverage remains shared.

2. **Evidence gate module**
   - Problem: readiness, audit plan, live readiness, and capability matrices can drift in wording.
   - Solution: keep blocker classification, gate status, and next-step text behind one module.
   - Benefit: tests target one interface and both providers inherit identical assurance language.

3. **API inventory recorder module**
   - Problem: observed call recording can become collector-specific boilerplate.
   - Solution: collectors emit call facts through one recorder that owns read-only and content-read classification.
   - Benefit: fewer missed calls, stronger customer proof, easier no-write tests.

4. **Report pack module**
   - Problem: report intelligence, rendering, and validation can drift.
   - Solution: treat report pack as the deep module for executive summary, proof table, limitations, next actions, QA, and replay.
   - Benefit: CLI, exports, and MCP get the same claims and proof rows.

5. **Scope catalog module**
   - Problem: required scopes, risk labels, and setup docs can split between CLI, collectors, docs, and tests.
   - Solution: one catalog per provider, consumed by doctor, probe, run, API inventory, and docs generation.
   - Benefit: adding a collector updates permission guidance in one place.

6. **Fixture tenant module**
   - Problem: ultimate auditor quality needs known-bad evidence for both providers.
   - Solution: keep golden Microsoft 365 and Google Workspace fixture bundles with intentionally bad posture.
   - Benefit: top risk classes stay testable without premium live tenants.

## Build Order To Finish 1.0

1. Freeze read-only enforcement and contract validation.
2. Finish report pack proof surfaces and rendered report parity.
3. Expand known-bad fixture bundles for Microsoft 365 and Google Workspace.
4. Add finding tests for every top risk class and every provider.
5. Add scope catalog tests for doctor, probe, API inventory, and docs output.
6. Add MCP evidence-citation tests.
7. Add drift acceptance-risk expiry tests.
8. Run live smoke only after doctor/probe says scopes are enough.
9. Cut release only when contract smoke, full tests, lint, and no-secret scans pass.

## Acceptance Test

Auditex 1.0 is ready when a known-bad Microsoft 365 fixture and a known-bad Google Workspace fixture both produce:

- valid contract bundle,
- complete or explicitly partial quality gate,
- correct findings for seeded risks,
- no unsupported claims,
- proof table rows for every finding,
- clear blockers for unavailable data,
- API inventory proving read-only and no content reads,
- board-ready Markdown and HTML reports,
- MCP answers that cite evidence rows.
