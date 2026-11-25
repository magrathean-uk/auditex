# Internal SCuBA parity check

`scripts/scuba-parity.py` compares the verdicts of CISA's own SCuBA tools (ScubaGear for Microsoft 365, ScubaGoggles
for Google Workspace) with Auditex's SCuBA answers, policy by policy, and puts every difference in a named category.
It is internal: absent from the public `auditex` CLI, MCP, shipped content and customer documentation. It never
signs in, calls a tenant or runs either CISA tool; it reads files that already exist.

## What it does

Inputs:

- a CISA result file: ScubaGear `ScubaResults_<uuid>.json` or ScubaGoggles `ScubaResults*.json`. The tool is
  detected from the policy ids (`MS.*` or `GWS.*`, never both) and checked against `MetaData.Tool` when present.
  The file must be strict JSON of at most 64 MiB, with no duplicate keys or NaN, and the `Results` layout of both
  tools (product, then groups, then `Controls` rows with `Control ID` and `Result`). The one exception is the
  export adapter's repair of PowerShell's empty-array defect (`"key": ,`) inside `Raw`; the report then says
  `cisa_input_repaired: true`, and a repair inside `Results` is refused.
- an Auditex run folder (its `model_assessment.json`) or the assessment file itself. Only value-rule answers count
  as decided; a row from the retired model layer reads `not_assessed` with reason `not_a_rule_answer`.
- or, for Microsoft 365, `--same-input`: the script runs the internal ScubaGear export adapter
  (`docs/development/scubagear-export-adapter.md`) on the `Raw` export inside the same ScubaResults file and compares
  ScubaGear's verdicts with Auditex's answers on that identical input. Every difference is then a rule or adapter
  difference, not a collection difference. The adapter's own assessment lands in `<out>/auditex-same-input/`.

Outputs, in a new or empty `--out` directory (created mode 0700, files mode 0600): `scuba-parity.json` and
`scuba-parity.md`, one row per policy id in either input with the CISA `Result` literal, the CISA verdict class, the
Auditex verdict and reason code, the category and any divergence ids. Neither file copies tenant names, ids,
domains, `Details` text, the report UUID or paths. Stdout gets one JSON line of counts. In same-input mode
`<out>/auditex-same-input/` also holds the adapter's own `model_assessment.json` and sidecar; like the ScubaResults
file, they are live evidence (the adapter leaves domains and the tenant id unmasked) and stay on the encrypted
internal disk.

Exit codes: 0 compared; 1 compared with `--strict` and at least one `disagreement`; 2 unusable input, with one
fixed message on stderr that never contains a path or input text.

```sh
.venv/bin/python scripts/scuba-parity.py ScubaResults_x.json --same-input --out <new-dir>
.venv/bin/python scripts/scuba-parity.py ScubaResults_x.json <auditex-run-dir> --out <new-dir> [--strict]
```

### Verdict vocabularies

| CISA `Result` | class | decided |
|---|---|---|
| `Pass` | pass | yes |
| `Fail` | fail | yes |
| `Warning` (SHOULD or MAY not met) | fail | yes |
| `N/A` (3rd Party or Not-Implemented: a manual check) | manual | no |
| `No events found` (ScubaGoggles) | no_events | no |
| `Error`, `Error - Test results missing` | error | no |
| `-` (ScubaGear: deleted control) | deleted | no |
| `Omitted`, `Incorrect result` | the class of `OriginalResult` or `OmittedEvaluationResult`; `omitted` or `annotated_incorrect` when neither is present | as that class |

Any other `Result` string, or an original-result field outside the table, is refused (exit 2). The shared
literals match the export adapter's `VERDICT_MAP` (a test pins it). One deliberate difference: the adapter's
baseline treats an `Omitted` row as not assessed, while parity compares the tool's own verdict behind the overlay. Two ScubaGoggles
rows for one control with different classes become `conflicting_rows` (not decided).

Auditex verdicts come from the `requirement_met` claim exactly as `value_rule_verdict` derives them: `met`,
`not_met`, `not_applicable` (inferred true with `policy_not_applicable`) and `not_assessed`. The reason code is the
rule precheck's `reason_code`, else its class (`absent_section` and so on), else `rule_not_implemented`,
`policy_not_in_catalogue` or `not_a_rule_answer`. A code that no shipped rule config (`configs/*.json`) or divergence entry names is
reported as `unlisted_reason_code`, so free text in an assessment never reaches the report. The assessment is
checked structurally, not against its schema version, so older assessments still load.

### Categories

| category | meaning |
|---|---|
| `agree` | pass with met or not_applicable, or fail with not_met |
| `documented_divergence` | a non-agreement that matches a documented D row (named in the row) |
| `auditex_not_assessed` | the CISA tool decided and Auditex did not: unknown is not safe, but find out why |
| `auditex_decided` | the CISA tool could not decide and Auditex did |
| `disagreement` | both decided, opposite answers, nothing documented: needs a look |
| `neither_decided` | neither side decided |
| `cisa_only`, `auditex_only` | the policy id is in one input only (product subset, version suffix or catalogue gap) |

Order: `agree` first, then `neither_decided` (so a D row never applies when neither side decided), then
`documented_divergence`, then the rest.

### Divergence map

`scripts/scuba-parity-divergences.json` maps a policy id to a D id. Each entry names the CISA classes (`pass`,
`fail`, `not_decided`) and Auditex verdicts it covers, optionally the Auditex reason codes, and cites its source
row:

- `gws-design 8.3 Dn` and `gws-design 8.3a Dn`: the M13 design's divergences from ScubaGoggles v1.1.0, rows D1 to
  D10 and the 25 Nov 2026 addendum rows D11 to D22, with a one-line summary of each under `rows`. Policy scope
  comes from the design's per-policy table (rule kind and not_assessed reasons). D10 (Error against
  `section_not_collected`) has no entries: both sides are undecided, so it is `neither_decided` by construction.
- `m365-spec Dn`: the value-rules spec v3.9.1 divergences from the pinned ScubaGear Rego. These are derived from
  the spec's replay vectors whose disagreement reads `expected: Dn` (vectors sha256 recorded in the file),
  grouped by policy and D id, with the Rego gold mapped to a CISA class and the rule's verdict and reason codes
  kept. Gold `not_applicable` maps to both `pass` and `not_decided` because the vectors do not say which ScubaGear
  shows.

The file is generated from the owner's records, not by hand; regenerate it when a design D row or the spec
changes. Limits: a pattern matches the verdict pair and reason code, not the evidence, so a real fault that lands on
a documented pair with the same reason code is labelled documented. The reason-code scoping keeps that narrow.
Spec rows relabelled after v3.9.1 (the replay test's review relabels) may leave an entry that no longer matches
anything, which is harmless.

### Version pinning

Auditex pins ScubaGear v1.8.0 baselines (spec v3.9.1) and ScubaGoggles v1.1.0. The report records the CISA tool
version and `version_matches`; a different release is still compared, and its id suffix changes show up as
`cisa_only` and `auditex_only`. ScubaGear's latest release at the time of writing is v2.0.0 (October 2026), so the
real run must install v1.8.0 explicitly.

## Plan for the real runs (not run yet)

Neither tool has been run. Both runs read live tenant data: the CISA output files and the Auditex runs are live
evidence and stay on the encrypted internal disk, never in the repo, `outputs/` of a shared checkout or a log.

### (a) ScubaGear against the Microsoft 365 lab tenant, on the Windows host

ScubaGear runs only on Windows PowerShell 5.1, so it runs on the internal Windows host through the maintainer's
`win-run` helper, against the lab tenant the owner named for lab work, read-only.

Non-interactive sign-in (ScubaGear's non-interactive prerequisites page, noninteractive.md): a certificate-based service principal,
`Invoke-SCuBA -AppID <app-id> -CertificateThumbprint <thumbprint> -Organization <lab-tenant>.onmicrosoft.com`.
All three go together; client secrets are not supported; the certificate must be in `Cert:\CurrentUser\My` of the
account that runs ScubaGear (a Power Platform requirement).

What the lab tenant needs for that service principal (`serviceprincipal-workflows.md`):

| product | grant | blast radius |
|---|---|---|
| Entra ID | Graph application: Directory.Read.All, Policy.Read.All, PrivilegedAccess.Read.AzureADGroup, PrivilegedEligibilitySchedule.Read.AzureADGroup, RoleManagement.Read.Directory, RoleManagementPolicy.Read.AzureADGroup, User.Read.All | read only |
| Exchange Online, Security Suite | Exchange.ManageAsApp plus the Global Reader role | Global Reader is read only |
| SharePoint | Sites.FullControl.All (SharePoint API) | write-capable on every site; ScubaGear only reads, but the grant itself can write: lab tenant only, removed after the run, or run without `sharepoint` |
| Teams | Global Reader role | read only |
| Power BI | admin portal setting "Service principals can access read-only admin APIs", scoped to a security group holding the principal; no API permission | read only |
| Power Platform | one-off `Add-PowerAppsAccount` then `New-PowerAppManagementApp -ApplicationId <app-id>` | registers the app as a Power Platform management app |

Needs the owner at a keyboard (interactive admin sign-ins that no script can do):

1. Create the service principal. `New-ScubaGearServicePrincipal` creates the app, permissions, roles and
   certificate and returns the app id and thumbprint; it needs Application Administrator (or Global, Security or
   Cloud App Administrator) and prompts for delegated consent. Doing it on the Windows host puts the certificate
   straight into the right store.
2. Power Platform registration: an interactive Power Platform Administrator or Global Administrator sign-in.
3. Power BI admin portal setting and the security group.

Then the run, from the Mac through `win-run` (outside 23:00 to 07:30 UK):
`Install-Module ScubaGear -RequiredVersion 1.8.0 -Scope CurrentUser`, `Initialize-SCuBA` (installs dependencies and
OPA), `Invoke-SCuBA -ProductNames * <sign-in parameters> -OutPath <work-dir> -Quiet`, fetch `ScubaResults_*.json`
back with `--get` to the encrypted internal disk, `win-run clean`. Then on the Mac:

1. `scuba-parity.py <ScubaResults> --same-input --out <dir>`: rule and adapter parity on identical input.
2. An Auditex run of the same tenant within the hour, then `scuba-parity.py <ScubaResults> <run> --out <dir>`:
   end-to-end parity including collection.
3. Triage every `disagreement` and `auditex_not_assessed`; a new deliberate difference gets a D row first, then a
   regenerated map.

### (b) ScubaGoggles against the Google Workspace tenant, on the Mac, after M13

Wait until M13 lands: Auditex must write GWS rows to `model_assessment.json` before there is anything to compare.
ScubaGoggles v1.1.0 is untrusted code: install it (`pip install scubagoggles==1.1.0`) in its own virtual
environment outside the Auditex checkout, fetch OPA with `scubagoggles getopa`, and run
`scubagoggles gws --credentials <key.json> --subjectemail <super-admin> --outputpath <dir> --quiet`. The key comes
from 1Password into a private temporary file that is removed after the run. There is no same-input mode for Google
Workspace: ScubaGoggles' `Raw` is its own provider shape, not Auditex evidence.

Scopes, both under domain-wide delegation of the same service account client id:

| scope | ScubaGoggles | Auditex core |
|---|---|---|
| admin.reports.audit.readonly | yes | yes |
| admin.directory.domain.readonly | yes | yes |
| admin.directory.orgunit.readonly | yes | yes |
| admin.directory.user.readonly | yes | yes |
| admin.directory.rolemanagement.readonly | yes | yes |
| admin.directory.group.readonly | yes | yes |
| cloud-identity.policies.readonly | yes | yes |
| admin.directory.customer.readonly | yes | no |
| cloud-identity.inboundsso.readonly | yes | no (M13 design adds it for the live check) |
| admin.directory.user.security, admin.reports.usage.readonly, apps.alerts, gmail.settings.basic, admin.directory.device.mobile.readonly, admin.directory.device.chromeos.readonly | no | yes |
| apps.groups.settings, apps.licensing | delegated-admin service account (no domain-wide delegation): the Groups Reader role and a custom License Read role assigned to the service account | apps.groups.settings in the everything preset only |

Needs the owner at a keyboard (Admin console and Cloud console):

1. Add `admin.directory.customer.readonly` and `cloud-identity.inboundsso.readonly` to the existing domain-wide
   delegation entry. Both are read only.
2. Assign the Groups Reader role and a custom License Read role to the service account, and enable the Groups
   Settings and Enterprise License Manager APIs. Without them ScubaGoggles cannot read group settings or
   licences, and the rows that depend on them do not decide (or run without the `groups` baseline).
3. Name the super admin to use as `--subjectemail`.

Then the Auditex run of the same tenant within the hour (`auditex google run`, `auditex assess`) and
`scuba-parity.py <ScubaResults> <run> --out <dir>`. Expect `neither_decided` for `No events found` rows and
`documented_divergence` for the D rows; triage the rest as in (a).
