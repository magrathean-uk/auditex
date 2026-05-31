# Auditex Next 5 Release Roadmap

Date: 2026-05-26

## 1. Current-state diagnosis

### Product shape now

- Auditex is already a real audit-only bundle product, not just collector scripts.
- Core strengths are shared contract finalization, evidence index, API inventory, proof table, customer pack, setup guide, compare/gate, and MCP read surfaces.
- Microsoft 365 depth is broad: 32 shipped collectors plus Exchange-assisted paths.
- Google Workspace depth is much thinner: 9 shipped collectors, good contract reuse, but less surface depth and less test fixture realism.
- MCP surface is wide: 34 tools. Good artifact readers. Weak narrative evidence citation enforcement.
- Test surface is strong: `make test` passed 831 tests on 2026-05-26. `make lint` passed. `make contract-smoke` passed.

### Current release gate state

| Gate | State | Evidence |
| --- | --- | --- |
| Python packaging version | Green | `pyproject.toml` is `1.0.0` |
| Local tests | Green | `831 passed in 46.23s` |
| Local lint/compile | Green | `make lint` passed |
| Contract smoke | Green | offline bundle validated, `contract_status == valid`, `index/evidence.sqlite` present |
| Audit-only boundary in docs | Green | README, runbook, product manual, security/privacy, output contract all agree |
| Shared bundle contract | Green | both providers finish through shared finalizer |
| Evidence proof per finding | Green-ish | proof table and validation exist, but MCP citation behavior is not yet end-to-end asserted |
| Google provider parity | Yellow | contract parity exists, coverage parity does not |
| Release automation | Yellow/Red | Pages workflow exists; release workflow is deleted in current worktree |
| Commercial handoff maturity | Yellow | pack verify exists, but reviewer UX and claim-citation discipline still need hardening |

### What is done from old 1.0 plan

- Shared finalizer: done.
- Read-only / no-content-read validation: done.
- Bundle evidence index: done.
- API inventory and proof table: done.
- Customer pack and verify step: done.
- Setup guide and permission planning: done.
- Drift compare/gates: partly done.
- Accepted-risk expiry handling: only basic waiver expiration exists.
- MCP evidence citation enforcement: not done enough.
- Known-bad dual-provider fixture bundles: not done enough.
- Provider architecture cleanup: not done enough.

### Main diagnosis

Auditex is past “prototype”. It is near “trustable operator kit”. It is not yet at “boring commercial audit product” level.

Main gap is not raw code volume. Main gap is trust scaling:

- one truth for scopes and roles,
- one truth for evidence gates,
- one proof rule for MCP answers,
- better known-bad fixtures,
- deeper Google posture coverage,
- stronger release packaging and reviewer flow.

## 2. External benchmark and tool ideas

| Source | URL | Useful idea for Auditex | Keep / avoid |
| --- | --- | --- | --- |
| Microsoft Graph app-only auth | https://learn.microsoft.com/en-us/graph/auth-v2-service | Clean separation of delegated vs app-only auth story | Keep auth model clarity. Avoid widening into write workflows. |
| Microsoft Graph permissions reference | https://learn.microsoft.com/en-us/graph/permissions-reference | Stable permission naming and least-privilege review | Keep as source of truth for M365 scope catalog. |
| Exchange Online PowerShell | https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell | Explicit command-surface inventory for Exchange read posture | Keep command ledger. Avoid hidden command fallbacks. |
| Google Workspace Directory API | https://developers.google.com/workspace/admin/directory/reference/rest | Clear object families for users, groups, roles, devices, domains | Keep object taxonomy for normalized records. |
| Google Reports API auth | https://developers.google.com/workspace/admin/reports/auth | Scope-by-surface clarity for admin/login/token/drive/mobile/chrome data | Keep scope mapping and blocker explanation. |
| Google Alert Center auth | https://developers.google.com/workspace/admin/alertcenter/guides/auth | Narrow alert signal surface with explicit auth docs | Keep as separate trust surface, not blended into reports. |
| Gmail API scopes | https://developers.google.com/workspace/gmail/api/auth/scopes | Provider exposes settings behind write-capable scopes | Keep scope-risk modeling. Never blur this into content access. |
| Drive files.list | https://developers.google.com/workspace/drive/api/reference/rest/v3/files/list | Metadata-vs-content boundary is crucial | Keep metadata-only discipline and tests. |
| Calendar ACL list | https://developers.google.com/workspace/calendar/api/v3/reference/acl/list | Public/external sharing posture can be read without event content | Good parity target for Google collaboration posture. |
| CISA SCuBA project | https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project | Baseline-centric audit framing, config checks, gov-grade evidence discipline | Keep baseline mapping ideas. Avoid becoming only a benchmark runner. |
| CISA ScubaGear | https://github.com/cisagov/ScubaGear | Config baseline collection with explicit control mapping | Keep seeded known-bad examples and baseline mapping patterns. |
| CISA ScubaGoggles | https://github.com/cisagov/ScubaGoggles | Google Workspace baseline lens | Good source for Google checklist depth and expected controls. |
| CIS Benchmarks | https://www.cisecurity.org/benchmark/microsoft_365 and https://www.cisecurity.org/benchmark/google_workspace | Customer-recognized control language | Keep mapping keys and report crosswalks. Avoid over-claiming full benchmark coverage. |
| Prowler | https://github.com/prowler-cloud/prowler | Big provider/check catalog, multi-format outputs, posture-at-scale pattern | Keep catalog discipline and output consistency. Avoid sprawling into too many providers. |
| ScoutSuite | https://github.com/nccgroup/ScoutSuite | HTML drill-down and reviewer navigation patterns | Keep reviewer UX ideas. Avoid giant weakly-proven finding sets. |
| 365Inspect | https://github.com/xforcered/365inspect | Deep Microsoft 365 inspection mindset | Good inspiration for M365 depth areas and operator workflows. |

## 3. Ranked backlog

Scale:

- Value / proof / parity / testability: `1` low, `5` high.
- Effort: `1` cheap, `5` expensive.
- Legal/security risk: `1` low, `5` high.

| Rank | Item | Audit value | Customer value | Read-only proof strength | Effort | Provider parity win | Testability | Legal / sec risk | Why now |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | Scope catalog module and generated setup truth | 5 | 5 | 5 | 3 | 5 | 5 | 2 | Biggest trust multiplier. Fixes drift between collectors, setup guide, docs, MCP, and permission ledger. |
| 2 | MCP citation layer plus citation tests | 5 | 5 | 5 | 3 | 4 | 5 | 2 | Directly closes stated product rule: every MCP answer must cite evidence or say missing. |
| 3 | Known-bad dual-provider fixture bundles | 5 | 4 | 5 | 3 | 5 | 5 | 1 | Lets Auditex prove trust without live premium tenants. |
| 4 | Evidence gate module unification | 5 | 4 | 5 | 3 | 5 | 5 | 2 | Centralizes blocker kinds, next steps, and quality-gate wording. |
| 5 | Google collaboration and mail-depth expansion | 5 | 5 | 4 | 4 | 5 | 4 | 3 | Biggest functional parity gap today. |
| 6 | API inventory recorder abstraction | 4 | 4 | 5 | 3 | 4 | 5 | 2 | Makes observed-call proof less fragile as collectors grow. |
| 7 | Customer handoff pack v2 | 4 | 5 | 4 | 3 | 3 | 4 | 2 | Important for commercial review, legal, and sales engineering flow. |
| 8 | Accepted-risk expiry and drift gate | 4 | 4 | 4 | 2 | 3 | 5 | 2 | Already partly present in waivers; needs first-class lifecycle. |
| 9 | Provider adapter run interface | 4 | 3 | 4 | 4 | 5 | 4 | 2 | Needed before third provider ideas or much deeper Google growth. |
| 10 | Release packaging and publish automation restore | 3 | 4 | 3 | 2 | 2 | 4 | 2 | Current tree lacks release workflow. Needed for boring shipping. |

## 4. Explicit module evaluation

| Module / area | Call | Why |
| --- | --- | --- |
| Provider adapter module | Build in release 2 | Microsoft and Google both duplicate run/report/finalize orchestration around the shared core. |
| Evidence gate module | Build in release 1 | `capability_gate`, `live-readiness`, `audit-plan`, and reporting need one authority. |
| API inventory recorder module | Build in release 2 | Coverage rows still behave like hand-built ledger events. Better as explicit recorder API. |
| Report pack module | Refactor in release 4 | Already central, but needs typed sections, reviewer profile, citation views, and stricter pack QA. |
| Scope catalog | Build first in release 1 | Highest ROI. Too much scope truth is split now. |
| Fixture tenants | Build in release 3 and 5 | Needed for realism and seeded parity, but after trust foundation. |
| Known-bad bundles | Build in release 1 | Faster than live tenants. Immediate regression net. |
| Drift / accepted-risk expiry | Build in release 4 | Waiver expiration exists, but not surfaced in drift or operator action. |
| MCP citation tests | Build first in release 1 | Hard boundary says MCP must cite evidence. Tests must pin it. |
| Setup guides | Rebuild from scope catalog in release 1 | Setup guide already good, but truth is duplicated. |
| Customer handoff | Deepen in release 4 | Core exists. Needs stronger reviewer flow and commercial polish. |

## 5. Next five releases

### Release 1: `1.0.1` Trust Hardening

Focus: lock the truth model before adding much more breadth.

Features

- Add a provider-neutral scope catalog model.
- Generate setup-guide permission/scope output from catalog truth.
- Add MCP evidence citation helper and explicit “evidence missing” response shape.
- Add contract-valid known-bad bundles for Microsoft 365 and Google Workspace.
- Restore release/build verification workflow for package, docs, and contract smoke.

Collectors

- No major new collectors.
- Small collector metadata cleanups so each collector points to catalog IDs instead of scattered scope text.

Schemas

- Add schema for scope catalog payload if shipped as artifact or config.
- Extend MCP evidence-facing payloads with citation rows or citation summary block.
- Keep run contract backward compatible.

Tests

- New MCP citation tests: supported, unsupported, missing-evidence, partial-bundle cases.
- New known-bad fixture regression tests for top risk findings and top blocker classes.
- New setup-guide generation parity tests: collector -> setup guide -> permission ledger -> api inventory.
- Reintroduce release workflow smoke in CI.

Docs

- Setup guide rewritten from generated scope truth.
- Product manual and security/privacy docs updated with MCP citation contract.
- API call catalog updated with citation examples.

Acceptance criteria

- Same collector selection yields one permission truth across docs, setup guide, MCP, and ledgers.
- MCP tools that answer from bundle evidence always emit citations or explicit missing-evidence status.
- One known-bad M365 bundle and one known-bad Google bundle are contract-valid and stable in CI.
- Release workflow can build package, run tests, lint, contract smoke, and docs build.

Non-goals

- No major new provider surface.
- No remediation or production write features.

Rollback

- Keep old setup-guide rendering path behind fallback flag for one release.
- Keep old MCP payload shape readable while new citation field is additive.

### Release 2: `1.1.0` Provider Run Architecture

Focus: remove duplicated provider orchestration before parity growth.

Features

- Introduce provider adapter interface: plan, auth summary, collect, normalize, findings, finalize inputs.
- Centralize evidence gate assembly.
- Centralize API inventory recording through recorder hooks.
- Normalize report-pack assembly path across M365 run, M365 probe, Google run, Google probe.

Collectors

- No broad new collectors.
- Refactor collector outputs to use recorder and gate helpers.

Schemas

- No contract break.
- Optional internal metadata for provider adapter version and recorder version.

Tests

- Provider conformance tests shared across M365 and Google.
- Finalize idempotence tests for both providers through same harness.
- Gate classification snapshot tests.
- API inventory recorder tests across Graph, command, and Google endpoints.

Docs

- Architecture doc for provider interface.
- Runbook notes for provider-specific adapters and probe behavior.

Acceptance criteria

- Google and M365 run/probe paths use one finalize preparation contract.
- Blocker wording and next steps are identical for same failure kinds across providers.
- API inventory no longer depends on collector-specific row handcrafting.

Non-goals

- No third provider.
- No new commercial pack features yet.

Rollback

- Keep legacy provider orchestration wrappers for one minor release.
- Ship adapter conformance test suite before removing old path.

### Release 3: `1.2.0` Google Depth and Parity

Focus: close biggest provider-depth gap.

Features

- Deepen Google collaboration posture.
- Deepen Google mail-admin posture without body reads.
- Deepen device and role/admin posture.
- Add stronger Google framework mappings and provider scorecard logic.

Collectors

- Expand `google_groups_settings` for more risky sharing and posting rules.
- Expand `google_calendar_posture` for public, external, and domain-wide ACL risks.
- Expand `google_drive_posture` for external-domain and public-link posture quality.
- Expand `google_directory` around admin assignment, token grants, 2SV posture, stale admin logic.
- Expand `google_devices` for stale sync, unmanaged patterns, compromise posture.

Schemas

- Extend normalized Google sections with stable keys for new sharing/admin/device signals.
- Extend finding schema mappings, not required fields.

Tests

- Add known-bad Google bundles for mail, drive, calendar, groups, device, and admin risks.
- Add scope-risk regression tests for Gmail and Drive metadata-only boundaries.
- Add parity tests on provider scorecard surface coverage.

Docs

- Update admin permission guide and setup guide for deeper Google preset options.
- Customer handoff examples for Google-specific limitations and scope-risk explanation.

Acceptance criteria

- Google provider scorecard moves from “contract parity only” to “usable commercial parity” for core security and collaboration posture.
- At least one known-bad Google fixture exercises each new risk class with proof rows.
- No Gmail body or Drive content read regressions.

Non-goals

- No Google content discovery.
- No mailbox export, message read, or file read.

Rollback

- New Google collectors stay preset-gated.
- Existing `core-security` preset remains stable if deeper presets regress.

### Release 4: `1.3.0` Report, MCP, and Commercial Handoff

Focus: make reviewer and MCP trust boring.

Features

- Add typed citation views inside report pack and MCP outputs.
- Add handoff pack reviewer index with “start here / prove this / known limits”.
- Promote accepted-risk expiry into handoff and drift outputs.
- Add stronger report QA for unsupported claims and stale waivers.
- Add commercial operator flow for pre-engagement setup, live run review, handoff review, rerun cadence.

Collectors

- Mostly none. This is trust UX.

Schemas

- Extend report pack with citation summary section and reviewer index section.
- Extend handoff manifest with validation summary and stale-waiver summary.
- Optional accepted-risk expiry fields in compare/drift outputs.

Tests

- Customer-pack golden tests.
- Handoff verifier negative tests for missing source artifact, bad checksum, stale accepted risk, missing citation.
- MCP contract tests for answer-to-proof linkage.
- Drift tests for accepted-risk expiry crossing threshold.

Docs

- Customer handoff guide v2.
- Product manual reviewer flow.
- Troubleshooting for “evidence missing” and “accepted risk expired”.

Acceptance criteria

- Customer pack can answer three reviewer questions fast: what was read, what was blocked, what proves each claim.
- Expired accepted risks surface as warnings or failures in drift/handoff.
- MCP evidence-facing tools have pinned citation behavior in tests.

Non-goals

- No SIEM ingestion platform.
- No alerting SaaS.

Rollback

- Keep old handoff pack layout readable.
- Make citation summary additive before making it required.

### Release 5: `1.4.0` Scale, Drift, and Packaging

Focus: repeatable scheduled use and boring distribution.

Features

- Smarter drift compare with noise suppression and accepted-risk state changes.
- Fixture-tenant pipeline tied to `tenant-bootstrap/` for seeded regression generation.
- Packaging/publish polish: wheels, release notes generation, docs version pin, smoke matrix.
- Performance and artifact-scale work for larger tenants and more normalized sections.

Collectors

- Add depth only where drift quality needs it.
- Consider more M365 enterprise-depth collectors only after noise model is stable.

Schemas

- Extend compare/drift output for state transitions and waiver expiry.
- Add optional fixture provenance metadata for known-bad bundles.

Tests

- Large-bundle performance and report-render tests.
- Drift golden tests with accepted-risk transitions.
- Packaging tests for install extras: base, `google`, `mcp`.
- Fixture-tenant replay tests from generated seeded bundles.

Docs

- Release and packaging guide.
- Scheduled-review operator runbook.
- Fixture generation and support policy docs.

Acceptance criteria

- Repeated monthly audits produce stable compare output with low false noise.
- Fixture pipeline can regenerate known-bad bundles reproducibly.
- Publish path is automated and documented again.

Non-goals

- No managed cloud backend.
- No multi-tenant SaaS control plane.

Rollback

- Keep compare classic mode for one release.
- Treat fixture provenance metadata as optional until stable.

## 6. Release order reason

Why this order:

1. Trust truth first.
2. Then remove provider duplication.
3. Then deepen Google.
4. Then make reviewer and MCP flow hard to misuse.
5. Then optimize repeatability and packaging.

If Auditex does not do step 1 first, later depth will create scope drift, blocker drift, and weak MCP trust.

## 7. Highest ROI task

Highest ROI task is:

**Build the scope catalog module and make setup guide, permission ledger, capability gates, and provider docs generate from it.**

Why:

- It closes the most drift at lowest medium effort.
- It improves both providers at once.
- It makes customer admin setup safer.
- It makes MCP, docs, and report claims easier to verify.
- It is the cleanest prerequisite for provider parity and citation trust.

## 8. Prompt to implement highest ROI task

Use this prompt:

```text
Implement the Auditex scope catalog foundation.

Goals:
- Add a provider-neutral scope catalog module that is the single source of truth for:
  - collector required scopes / permissions
  - scope risk notes
  - minimum role hints
  - provider doc links
  - setup-guide admin steps
- Wire Microsoft 365 and Google Workspace setup-guide generation to this catalog.
- Wire permission ledger and capability/evidence gate outputs to reuse the same catalog data.
- Keep Auditex audit-only.
- Do not add tenant writes.
- Do not add Gmail body reads, Drive/SharePoint/OneDrive file-content reads, or Exchange mailbox body reads.
- Keep run contract backward compatible.

Required work:
- Add focused tests that prove one collector selection yields one consistent truth across:
  - setup-guide JSON
  - setup-guide Markdown
  - permission ledger
  - capability gate output
  - api-inventory declared collector rows
- Add Google scope-risk regression tests for Gmail settings and Drive metadata scopes.
- Update product docs to state the catalog is the authority for access planning.

Definition of done:
- `make test`, `make lint`, and `make contract-smoke` pass.
- No existing CLI or MCP command loses backward compatibility.
- New tests fail if scope truth drifts across modules.
```
