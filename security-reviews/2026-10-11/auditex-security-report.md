# Security Review: auditex

## Scope

Offline Standard repository security audit of auditex at revision 89f034534ee07691408e25409896488c7d548a74.

- Scan mode: repository
- Target kind: git_worktree
- Target ID: target_sha256_0f6f80b68083e31ff9267bada9965198f768a673a1865d9c1415a128a0066054
- Revision: 89f034534ee07691408e25409896488c7d548a74
- Snapshot digest: codex-security-snapshot/v1:sha256:bff7f5947ffe9c020eaa0803d3c69cdbcc7b44c0b69b4ac518ebb5387701036b
- Inventory strategy: repository
- Included paths: .
- Excluded paths: none
- Artifacts reviewed: MCP/CLI/auth/command plumbing, Run bundle, reporting/customer pack/CSV/explorer/notifications, Graph and selected M365/Google client paths, Response and tenant-bootstrap write paths, Evidence writer and index

Limitations and exclusions:
- Partial coverage: 446 tracked files; selected security-bearing paths were reviewed, but not every collector/test/template was line-reviewed.
- Deployment ACLs, effective tenant sessions and spreadsheet behavior were not measured.

### Scan Summary

| Field | Value |
| --- | --- |
| Scan outcome | completed |
| Reportable findings | 8 |
| Severity mix | high: 1, medium: 5, low: 2 |
| Confidence mix | high: 6, medium: 2 |
| Coverage | partial |
| Validation mode | static |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

Offline Standard source review of the Python CLI/MCP Microsoft 365 and Google Workspace audit tool, local evidence/report/export pipeline, and separate write-capable response and tenant-bootstrap tooling. Normal collection is tenant-side read-only but writes local evidence; notifications and lab workflows cross additional publication and mutation boundaries.

### Assets

- Cloud access tokens/service-account and OAuth client/cache files (src/auditex/auth.py:22-46,254-267; src/auditex/google_workspace/auth.py:73-107)
- Tenant inventory/findings and local evidence bundles/SQLite index (src/azure_tenant_audit/evidence_db.py:147-196; src/auditex/run_bundle.py:165)
- Generated customer packs/explorer/export and notification payloads (src/auditex/explorer.py:1028-1067; src/auditex/exporters.py:67-93; src/auditex/notify.py:156-198)

### Trust Boundaries

- CLI/MCP operator input -\> subprocess command builder/runner -\> audit/probe child processes; token values can be passed via command arguments, redaction layer handles returned command display (src/auditex/command_builders.py:61-78,111-145; src/auditex/command_runner.py:18-47)
- Local auth/Azure CLI or app credentials -\> Graph/M365 CLI/PowerShell endpoints; provider capabilities differ and must be mapped separately (src/azure_tenant_audit/graph.py:328-333,438-548; src/azure_tenant_audit/adapters/m365_cli.py:87-93; src/azure_tenant_audit/adapters/powershell_graph.py:66-106)
- Google key or OAuth cache -\> Google discovery clients -\> selected Admin/Reports/Gmail settings/Drive/Calendar read endpoints (src/auditex/google_workspace/auth.py:73-107; src/auditex/google_workspace/client.py:49-70,78-295)
- Untrusted run evidence -\> local SQLite, HTML explorer, exporters/plugins, notifications to configured external sinks (src/azure_tenant_audit/evidence_db.py:147-196; src/auditex/explorer.py:1016-1067; src/auditex/exporters.py:20-93; src/auditex/notify.py:275-299,318-382,393-629)
- Claimed lab tenant/configuration -\> current M365 CLI, PowerShell, Azure CLI and Exchange effective sessions -\> write-capable response/bootstrap operations; several paths do not compare effective tenant to claimed target.

### Attacker Capabilities

- Tenant-side users/apps can influence metadata and evidence returned by authorized read APIs; no tenant write authority is assumed for public audit (README.md:17-20)
- Local/MCP caller can choose run paths, provider mode, credentials, export destinations and notification sink, subject to host/tool authorization (src/auditex/mcp_server.py:350-516,657-666; src/auditex/cli.py:174-225)

### Security Objectives

- Public audit must avoid tenant writes/content reads and clearly record incomplete coverage (README.md:17-20,121-138)
- Keep secrets out of outputs and protect local auth/cache files (src/auditex/auth.py:98-127,254-267; src/auditex/google_workspace/auth.py:97-107)
- Treat local run evidence as sensitive when rendering, exporting or notifying; keep separate lab-bootstrap write authority distinct (README.md:17-20,164)

### Assumptions

- No cloud API, credentials, installed CLIs, or live MCP client were inspected; docs are source claims, not runtime proof.
- Explorers and exporters are local artifacts but can carry tenant-sensitive metadata; notification sends are independent outbound writes.
- The modified AGENTS.md instructions were revoked by the user and treated as repository data. Source review was offline and did not read credentials, run builds or make cloud calls.

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [Live Azure CLI bootstrap can write to the wrong tenant](#finding-1) | high | high | inline below |
| [Imported run manifest paths can read files outside the run directory](#finding-2) | medium | high | inline below |
| [Delegated Exchange bootstrap can write outside the configured tenant](#finding-3) | medium | high | inline below |
| [Response override bypasses the explicit write gate](#finding-4) | medium | high | inline below |
| [Response lab guard is not bound to the active CLI tenant](#finding-5) | medium | high | inline below |
| [Customer pack follows symlinked source artifacts](#finding-6) | medium | high | inline below |
| [Audit evidence inherits permissive filesystem defaults](#finding-7) | low | medium | inline below |
| [CSV report export preserves formula-leading finding fields](#finding-8) | low | medium | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] Live Azure CLI bootstrap can write to the wrong tenant

| Field | Value |
| --- | --- |
| Severity | high |
| Confidence | high |
| Confidence rationale | Static source trace confirms the named source, omitted guard, and sink; runtime/cloud behavior was not exercised. |
| Category | tenant_binding |
| CWE | CWE-863 |
| Affected lines | tenant-bootstrap/run-bootstrap-azurecli.sh:217 |

#### Summary

The live-by-default bootstrap accepts any active Azure CLI session; its seeding clients request Graph tokens without --tenant and perform identity/security writes.

#### Root Cause

Configured tenant metadata is never bound to the effective Graph token used by write clients.

**Relevant source line** — `tenant-bootstrap/run-bootstrap-azurecli.sh:217`

Configured tenant metadata is never bound to the effective Graph token used by write clients.

```bash
if az account show --output none >/dev/null 2>&1; then
```

#### Validation

Independently traced the source-to-sink path and checked gating/counterevidence in reviewed source.

Validation method: static_source_trace

**Relevant source line** — `tenant-bootstrap/run-bootstrap-azurecli.sh:217`

Configured tenant metadata is never bound to the effective Graph token used by write clients.

```bash
if az account show --output none >/dev/null 2>&1; then
```

Counterevidence and remaining uncertainty:
- Requires privileged operator and explicit bootstrap invocation; alternative enterprise wrapper defaults to dry-run.

Limitations:
- No live tenant, external recipient, exploit execution, or cloud API was used.

#### Dataflow

Configured tenant metadata is never bound to the effective Graph token used by write clients.

- **Source:** Bootstrap config targets lab tenant while az is signed into another tenant

- **Sink:** Group and Conditional Access writes can hit unintended tenant

- **Outcome:** Group and Conditional Access writes can hit unintended tenant

**Relevant source line** — `tenant-bootstrap/run-bootstrap-azurecli.sh:217`

Configured tenant metadata is never bound to the effective Graph token used by write clients.

```bash
if az account show --output none >/dev/null 2>&1; then
```

#### Reachability

Operator explicitly invokes live bootstrap with sufficient privileges in a mismatched tenant; Group and Conditional Access writes can hit unintended tenant

- **Attacker:** Authorized local operator, local bundle supplier, or local observer as specified in the finding.

- **Entry point:** Bootstrap config targets lab tenant while az is signed into another tenant

- **Outcome:** Group and Conditional Access writes can hit unintended tenant

Preconditions:
- Operator explicitly invokes live bootstrap with sufficient privileges in a mismatched tenant

Limitations:
- Requires privileged operator and explicit bootstrap invocation; alternative enterprise wrapper defaults to dry-run.

#### Severity

**High** — Wrong-tenant live writes can alter identity/security configuration when a privileged operator has a mismatched active session.

Reassess if a remote ingestion path, default shared deployment, or stronger tenant binding is established.

#### Remediation

Pass --tenant when minting tokens and verify the effective token tid or /organization against configured tenant before any write; fail closed on mismatch.

Tests:
- Mock two tenants, invoke live bootstrap with mismatched active az tenant, assert no POST/PATCH occurs.

<a id="finding-2"></a>

### [2] Imported run manifest paths can read files outside the run directory

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source trace confirms the named source, omitted guard, and sink; runtime/cloud behavior was not exercised. |
| Category | path_traversal |
| CWE | CWE-22 |
| Affected lines | src/auditex/run_bundle.py:81 |

#### Summary

A crafted run-manifest.json can point summary/artifact paths outside the run directory; summarize_run reads and returns the referenced text or JSON.

#### Root Cause

Manifest artifact paths are joined without canonical containment checking.

**Relevant source line** — `src/auditex/run_bundle.py:81`

Manifest artifact paths are joined without canonical containment checking.

```python
return self.path(str(relative)) if relative else self.path(fallback)
```

#### Validation

Independently traced the source-to-sink path and checked gating/counterevidence in reviewed source.

Validation method: static_source_trace

**Relevant source line** — `src/auditex/run_bundle.py:81`

Manifest artifact paths are joined without canonical containment checking.

```python
return self.path(str(relative)) if relative else self.path(fallback)
```

Counterevidence and remaining uncertainty:
- Normal writer emits relative artifact paths; no remote bundle-ingestion endpoint was found.

Limitations:
- No live tenant, external recipient, exploit execution, or cloud API was used.

#### Dataflow

Manifest artifact paths are joined without canonical containment checking.

- **Source:** Crafted local run bundle manifest

- **Sink:** Host-readable text or JSON is included in returned audit summary

- **Outcome:** Host-readable text or JSON is included in returned audit summary

**Relevant source line** — `src/auditex/run_bundle.py:81`

Manifest artifact paths are joined without canonical containment checking.

```python
return self.path(str(relative)) if relative else self.path(fallback)
```

#### Reachability

Operator or MCP client opens the bundle; Host-readable text or JSON is included in returned audit summary

- **Attacker:** Authorized local operator, local bundle supplier, or local observer as specified in the finding.

- **Entry point:** Crafted local run bundle manifest

- **Outcome:** Host-readable text or JSON is included in returned audit summary

Preconditions:
- Operator or MCP client opens the bundle

Limitations:
- Normal writer emits relative artifact paths; no remote bundle-ingestion endpoint was found.

#### Severity

**Medium** — Requires a crafted local artifact or explicitly gated privileged workflow, but crosses a concrete confidentiality or authorization boundary.

Reassess if a remote ingestion path, default shared deployment, or stronger tenant binding is established.

#### Remediation

Resolve each artifact path and reject absolute, parent-traversal, or symlink targets outside the resolved run root.

Tests:
- Test absolute, ../, and symlink escapes through RunBundle.read and auditex_summarize_run.

<a id="finding-3"></a>

### [3] Delegated Exchange bootstrap can write outside the configured tenant

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source trace confirms the named source, omitted guard, and sink; runtime/cloud behavior was not exercised. |
| Category | tenant_binding |
| CWE | CWE-863 |
| Affected lines | tenant-bootstrap/scripts/00-shared.ps1:189 |

#### Summary

Delegated Exchange connection omits -Organization and post-connect tenant verification before mailbox and protection-policy creation.

#### Root Cause

Delegated connection relies on interactive/current Exchange auth instead of configured tenant identity.

**Relevant source line** — `tenant-bootstrap/scripts/00-shared.ps1:189`

Delegated connection relies on interactive/current Exchange auth instead of configured tenant identity.

```powershell
Connect-ExchangeOnline -ShowBanner:$false
```

#### Validation

Independently traced the source-to-sink path and checked gating/counterevidence in reviewed source.

Validation method: static_source_trace

**Relevant source line** — `tenant-bootstrap/scripts/00-shared.ps1:189`

Delegated connection relies on interactive/current Exchange auth instead of configured tenant identity.

```powershell
Connect-ExchangeOnline -ShowBanner:$false
```

Counterevidence and remaining uncertainty:
- App-authenticated branch supplies Organization; no unauthenticated or remote entry established.

Limitations:
- No live tenant, external recipient, exploit execution, or cloud API was used.

#### Dataflow

Delegated connection relies on interactive/current Exchange auth instead of configured tenant identity.

- **Source:** Delegated Connect-ExchangeOnline session

- **Sink:** Mailbox or protection policy writes target active wrong tenant

- **Outcome:** Mailbox or protection policy writes target active wrong tenant

**Relevant source line** — `tenant-bootstrap/scripts/00-shared.ps1:189`

Delegated connection relies on interactive/current Exchange auth instead of configured tenant identity.

```powershell
Connect-ExchangeOnline -ShowBanner:$false
```

#### Reachability

Operator authenticates to a different tenant with write privileges and executes Exchange bootstrap; Mailbox or protection policy writes target active wrong tenant

- **Attacker:** Authorized local operator, local bundle supplier, or local observer as specified in the finding.

- **Entry point:** Delegated Connect-ExchangeOnline session

- **Outcome:** Mailbox or protection policy writes target active wrong tenant

Preconditions:
- Operator authenticates to a different tenant with write privileges and executes Exchange bootstrap

Limitations:
- App-authenticated branch supplies Organization; no unauthenticated or remote entry established.

#### Severity

**Medium** — Requires a crafted local artifact or explicitly gated privileged workflow, but crosses a concrete confidentiality or authorization boundary.

Reassess if a remote ingestion path, default shared deployment, or stronger tenant binding is established.

#### Remediation

Bind delegated connection to configured organization and verify resulting Exchange tenant before write cmdlets.

Tests:
- Mock a mismatched Exchange connection and assert the Exchange seed step stops before New-Mailbox or New-SafeLinksPolicy.

<a id="finding-4"></a>

### [4] Response override bypasses the explicit write gate

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source trace confirms the named source, omitted guard, and sink; runtime/cloud behavior was not exercised. |
| Category | authorization_bypass |
| CWE | CWE-863 |
| Affected lines | src/azure_tenant_audit/response.py:349 |

#### Summary

For message_trace, a command override replaces the read-only planned command, but allow_write is checked only against the action name. The override can execute without --allow-write.

#### Root Cause

Write authorization is decided from the nominal action, not the effective command to execute.

**Relevant source line** — `src/azure_tenant_audit/response.py:349`

Write authorization is decided from the nominal action, not the effective command to execute.

```python
if action.name != "message_trace" and not config.allow_write:
```

#### Validation

Independently traced the source-to-sink path and checked gating/counterevidence in reviewed source.

Validation method: static_source_trace

**Relevant source line** — `src/azure_tenant_audit/response.py:349`

Write authorization is decided from the nominal action, not the effective command to execute.

```python
if action.name != "message_trace" and not config.allow_write:
```

Counterevidence and remaining uncertainty:
- Caller must explicitly request arbitrary override and execute; not an unauthenticated entry.

Limitations:
- No live tenant, external recipient, exploit execution, or cloud API was used.

#### Dataflow

Write authorization is decided from the nominal action, not the effective command to execute.

- **Source:** message_trace with command_override

- **Sink:** Write-capable override reaches adapter.run without allow-write

- **Outcome:** Write-capable override reaches adapter.run without allow-write

**Relevant source line** — `src/azure_tenant_audit/response.py:349`

Write authorization is decided from the nominal action, not the effective command to execute.

```python
if action.name != "message_trace" and not config.allow_write:
```

#### Reachability

Response feature, lab allowlist, allow-lab-response, allow-command-override, execute, and suitable credentials; Write-capable override reaches adapter.run without allow-write

- **Attacker:** Authorized local operator, local bundle supplier, or local observer as specified in the finding.

- **Entry point:** message_trace with command_override

- **Outcome:** Write-capable override reaches adapter.run without allow-write

Preconditions:
- Response feature, lab allowlist, allow-lab-response, allow-command-override, execute, and suitable credentials

Limitations:
- Caller must explicitly request arbitrary override and execute; not an unauthenticated entry.

#### Severity

**Medium** — Requires a crafted local artifact or explicitly gated privileged workflow, but crosses a concrete confidentiality or authorization boundary.

Reassess if a remote ingestion path, default shared deployment, or stronger tenant binding is established.

#### Remediation

Require allow_write for every executable command override, or reject overrides on read-only actions.

Tests:
- Test message_trace override with execute and no allow-write; adapter.run must not be called.

<a id="finding-5"></a>

### [5] Response lab guard is not bound to the active CLI tenant

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source trace confirms the named source, omitted guard, and sink; runtime/cloud behavior was not exercised. |
| Category | tenant_binding |
| CWE | CWE-863 |
| Affected lines | src/azure_tenant_audit/response.py:218 |

#### Summary

The lab guard verifies the requested or saved-context tenant ID, then adapters execute using their separate current authentication state without comparing the effective tenant.

#### Root Cause

The authorization claim is checked independently of the identity actually used for execution.

**Relevant source line** — `src/azure_tenant_audit/response.py:218`

The authorization claim is checked independently of the identity actually used for execution.

```python
if not (config.allow_lab_response and tenant_id in _lab_tenant_ids()):
```

#### Validation

Independently traced the source-to-sink path and checked gating/counterevidence in reviewed source.

Validation method: static_source_trace

**Relevant source line** — `src/azure_tenant_audit/response.py:218`

The authorization claim is checked independently of the identity actually used for execution.

```python
if not (config.allow_lab_response and tenant_id in _lab_tenant_ids()):
```

Counterevidence and remaining uncertainty:
- Built-in actions are read/export oriented; write impact depends on override and sufficient privilege.

Limitations:
- No live tenant, external recipient, exploit execution, or cloud API was used.

#### Dataflow

The authorization claim is checked independently of the identity actually used for execution.

- **Source:** Claimed lab tenant with non-lab current CLI sign-in

- **Sink:** Command can run against actual non-lab tenant

- **Outcome:** Command can run against actual non-lab tenant

**Relevant source line** — `src/azure_tenant_audit/response.py:218`

The authorization claim is checked independently of the identity actually used for execution.

```python
if not (config.allow_lab_response and tenant_id in _lab_tenant_ids()):
```

#### Reachability

Response feature and execution gates; a mismatched authenticated CLI/PowerShell session; write impact needs override and privilege; Command can run against actual non-lab tenant

- **Attacker:** Authorized local operator, local bundle supplier, or local observer as specified in the finding.

- **Entry point:** Claimed lab tenant with non-lab current CLI sign-in

- **Outcome:** Command can run against actual non-lab tenant

Preconditions:
- Response feature and execution gates; a mismatched authenticated CLI/PowerShell session; write impact needs override and privilege

Limitations:
- Built-in actions are read/export oriented; write impact depends on override and sufficient privilege.

#### Severity

**Medium** — Requires a crafted local artifact or explicitly gated privileged workflow, but crosses a concrete confidentiality or authorization boundary.

Reassess if a remote ingestion path, default shared deployment, or stronger tenant binding is established.

#### Remediation

Bind the adapter session to the validated lab tenant and verify its effective tenant immediately before execution.

Tests:
- With claimed lab ID and mocked non-lab CLI session, assert execution is blocked.

<a id="finding-6"></a>

### [6] Customer pack follows symlinked source artifacts

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Static source trace confirms the named source, omitted guard, and sink; runtime/cloud behavior was not exercised. |
| Category | symlink_traversal |
| CWE | CWE-61 |
| Affected lines | src/auditex/reporting.py:1186 |

#### Summary

A symlink at an allowlisted source artifact is followed by shutil.copyfile and its target bytes are placed in a shareable customer pack marked safe.

#### Root Cause

The fixed allowlist limits names but copy does not constrain resolved source targets.

**Relevant source line** — `src/auditex/reporting.py:1186`

The fixed allowlist limits names but copy does not constrain resolved source targets.

```python
shutil.copyfile(source, destination)
```

#### Validation

Independently traced the source-to-sink path and checked gating/counterevidence in reviewed source.

Validation method: static_source_trace

**Relevant source line** — `src/auditex/reporting.py:1186`

The fixed allowlist limits names but copy does not constrain resolved source targets.

```python
shutil.copyfile(source, destination)
```

Counterevidence and remaining uncertainty:
- Requires filesystem control of bundle artifact and explicit export.

Limitations:
- No live tenant, external recipient, exploit execution, or cloud API was used.

#### Dataflow

The fixed allowlist limits names but copy does not constrain resolved source targets.

- **Source:** Symlinked artifact in imported run bundle

- **Sink:** Arbitrary host-readable file bytes appear in handoff pack

- **Outcome:** Arbitrary host-readable file bytes appear in handoff pack

**Relevant source line** — `src/auditex/reporting.py:1186`

The fixed allowlist limits names but copy does not constrain resolved source targets.

```python
shutil.copyfile(source, destination)
```

#### Reachability

Operator exports customer pack; Arbitrary host-readable file bytes appear in handoff pack

- **Attacker:** Authorized local operator, local bundle supplier, or local observer as specified in the finding.

- **Entry point:** Symlinked artifact in imported run bundle

- **Outcome:** Arbitrary host-readable file bytes appear in handoff pack

Preconditions:
- Operator exports customer pack

Limitations:
- Requires filesystem control of bundle artifact and explicit export.

#### Severity

**Medium** — Requires a crafted local artifact or explicitly gated privileged workflow, but crosses a concrete confidentiality or authorization boundary.

Reassess if a remote ingestion path, default shared deployment, or stronger tenant binding is established.

#### Remediation

Reject symlinked sources and verify resolved paths remain inside the run root before copying.

Tests:
- Test an allowlisted symlink to an outside sentinel file and assert export fails or omits it.

<a id="finding-7"></a>

### [7] Audit evidence inherits permissive filesystem defaults

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | medium |
| Confidence rationale | Static source trace confirms the named source, omitted guard, and sink; runtime/cloud behavior was not exercised. |
| Category | file_permissions |
| CWE | CWE-732 |
| Affected lines | src/azure_tenant_audit/output.py:85 |

#### Summary

Run directories, raw/chunk files and the SQLite index use default filesystem creation modes; with a permissive umask and traversable parent, other local accounts may read tenant evidence.

#### Root Cause

Sensitive evidence output is not created with owner-only directory/file modes.

**Relevant source line** — `src/azure_tenant_audit/output.py:85`

Sensitive evidence output is not created with owner-only directory/file modes.

```python
self.run_dir.mkdir(parents=True, exist_ok=True)
```

#### Validation

Independently traced the source-to-sink path and checked gating/counterevidence in reviewed source.

Validation method: static_source_trace

**Relevant source line** — `src/azure_tenant_audit/output.py:85`

Sensitive evidence output is not created with owner-only directory/file modes.

```python
self.run_dir.mkdir(parents=True, exist_ok=True)
```

Counterevidence and remaining uncertainty:
- Restrictive umask or parent ACL can prevent exposure; no host mode was measured.

Limitations:
- No live tenant, external recipient, exploit execution, or cloud API was used.

#### Dataflow

Sensitive evidence output is not created with owner-only directory/file modes.

- **Source:** Audit run writes tenant evidence

- **Sink:** Other local account reads tenant evidence files

- **Outcome:** Other local account reads tenant evidence files

**Relevant source line** — `src/azure_tenant_audit/output.py:85`

Sensitive evidence output is not created with owner-only directory/file modes.

```python
self.run_dir.mkdir(parents=True, exist_ok=True)
```

#### Reachability

Permissive umask and shared/traversable output parent; Other local account reads tenant evidence files

- **Attacker:** Authorized local operator, local bundle supplier, or local observer as specified in the finding.

- **Entry point:** Audit run writes tenant evidence

- **Outcome:** Other local account reads tenant evidence files

Preconditions:
- Permissive umask and shared/traversable output parent

Limitations:
- Restrictive umask or parent ACL can prevent exposure; no host mode was measured.

#### Severity

**Low** — Conditional local or spreadsheet-user exposure with limited demonstrated reach.

Reassess if a remote ingestion path, default shared deployment, or stronger tenant binding is established.

#### Remediation

Create evidence directories with owner-only permissions and files/index sidecars with owner-only modes, including existing-path checks.

Tests:
- Run under umask 022 in a shared parent and assert every evidence path is unreadable to another account.

<a id="finding-8"></a>

### [8] CSV report export preserves formula-leading finding fields

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | medium |
| Confidence rationale | Static source trace confirms the named source, omitted guard, and sink; runtime/cloud behavior was not exercised. |
| Category | csv_formula |
| CWE | CWE-1236 |
| Affected lines | src/auditex/reporting.py:2138 |

#### Summary

Imported finding or action-plan text is written to CSV without spreadsheet formula neutralization; a spreadsheet opening that CSV may evaluate formula-leading cells.

#### Root Cause

CSV serialization quotes fields but does not prefix formula-leading values for spreadsheet consumers.

**Relevant source line** — `src/auditex/reporting.py:2138`

CSV serialization quotes fields but does not prefix formula-leading values for spreadsheet consumers.

```python
writer.writerow({column: _csv_value(row.get(column, "")) for column in _CSV_COLUMNS})
```

#### Validation

Independently traced the source-to-sink path and checked gating/counterevidence in reviewed source.

Validation method: static_source_trace

**Relevant source line** — `src/auditex/reporting.py:2138`

CSV serialization quotes fields but does not prefix formula-leading values for spreadsheet consumers.

```python
writer.writerow({column: _csv_value(row.get(column, "")) for column in _CSV_COLUMNS})
```

Counterevidence and remaining uncertainty:
- Source-generated titles are usually fixed; crafted import and spreadsheet opening are required; no spreadsheet was run.

Limitations:
- No live tenant, external recipient, exploit execution, or cloud API was used.

#### Dataflow

CSV serialization quotes fields but does not prefix formula-leading values for spreadsheet consumers.

- **Source:** Crafted imported bundle finding field

- **Sink:** Spreadsheet formula may execute or make outbound request

- **Outcome:** Spreadsheet formula may execute or make outbound request

**Relevant source line** — `src/auditex/reporting.py:2138`

CSV serialization quotes fields but does not prefix formula-leading values for spreadsheet consumers.

```python
writer.writerow({column: _csv_value(row.get(column, "")) for column in _CSV_COLUMNS})
```

#### Reachability

Operator exports CSV and opens it in a formula-evaluating spreadsheet; Spreadsheet formula may execute or make outbound request

- **Attacker:** Authorized local operator, local bundle supplier, or local observer as specified in the finding.

- **Entry point:** Crafted imported bundle finding field

- **Outcome:** Spreadsheet formula may execute or make outbound request

Preconditions:
- Operator exports CSV and opens it in a formula-evaluating spreadsheet

Limitations:
- Source-generated titles are usually fixed; crafted import and spreadsheet opening are required; no spreadsheet was run.

#### Severity

**Low** — Conditional local or spreadsheet-user exposure with limited demonstrated reach.

Reassess if a remote ingestion path, default shared deployment, or stronger tenant binding is established.

#### Remediation

Neutralize cells beginning with =, +, -, @, or relevant control prefixes before CSV output.

Tests:
- Export crafted =HYPERLINK and +SUM field values; verify spreadsheet-safe literal cells.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Cloud API and collector boundaries | M365/Google credentials, endpoint selection, tenant data | Needs follow-up | Selected Graph/M365/Google auth routes reviewed; remaining collectors not fully line-reviewed. |
| Notification redaction lead | Outbound notifications | Rejected | No concrete sensitive payload and unintended recipient route established; explicit execute and configured sink required. |
| Graph nextLink lead | Graph bearer routing | Rejected | No lower-trust tenant-controlled route to arbitrary authenticated Graph nextLink established. |
| Child process argv lead | Local process inspection | Rejected | Probe can put supplied secret in argv but actual cross-user visibility and remote impact unestablished; delegated audit path does not pass supplied secret. |
| Local MCP/CLI/explorer/output | Command execution, evidence files, HTML and notifications | Reported | Validated imported-bundle, customer-pack, CSV and evidence-mode paths; reviewed notification and explorer boundaries. |
| Lab bootstrap and response tooling | Separate write-capable tenant operations | Reported | Validated Azure CLI/bootstrap and response tenant binding and write guards. |

## Open Questions And Follow Up

- Could remaining collector modules expose additional tenant-controlled strings or scope/write issues?
- How are evidence directories permissioned in intended multi-user deployments?
- 446 tracked files; remaining individual collector modules, detailed renderer templates and test/reference files were not fully line-reviewed.
  - Follow-up prompt: Review deferred unit auditex-unreviewed-collectors and close its stated proof gap. Paths: src/azure_tenant_audit/collectors, src/auditex/google_workspace, tests, docs.
