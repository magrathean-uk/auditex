# Auditex Security and Privacy Model

Auditex is for authorized tenant auditing. The public product surface is
audit-only.

## Authorization and audit boundaries

Use Auditex only against tenants you own or for which the tenant owner has
given explicit written authorization. The operator remains responsible for the
applicable Microsoft, Google, legal, regulatory, and data-protection
requirements.

The audit plane must not write to production tenants. This covers Microsoft
365 and Google Workspace audit runs, probes, reports, exports, MCP audit tools,
customer-pack creation, and customer-pack verification. Lab-only response
features require `AUDITEX_ENABLE_RESPONSE` to have a truthy value (`1`,
`true`, `yes`, or `on`) and are outside the public audit flow.

## Data collected

The Teams policy reader adds `api.interfaces.records.teams.microsoft.com` for five allowlisted HTTPS GET paths in commercial and GCC, with a certificate-authenticated Teams admin token and Global Reader on the service principal; redirects are not followed and tokens are never logged or stored in bundles.

Audit collectors must not read Gmail or Exchange message bodies, or Drive,
SharePoint, or OneDrive file content. Metadata and settings can still contain
personal data, including user names, email addresses, group membership, device
metadata, OAuth grant metadata, sharing metadata, and audit-event metadata.
Treat every bundle as confidential.
Value-rule records carry policy, cell, code, section names and controlled reason
text, not tenant evidence values. Serving rules read a separate in-memory view
on both the run-bundle and internal ScubaGear export paths after source, ledger,
collector-error, qualifier and scan checks, before pruning and the model view's
shape, size and redaction gates. The rule view retains unredacted
e-mail addresses and display names so rules can distinguish users; it is never
serialised into prompts, assessment files, sidecars or logs. This includes
Defender ATP preset-rule recipient and exclusion lists (`SentTo`,
`SentToMemberOf`, `RecipientDomainIs` and their `ExceptIf*` counterparts),
DNS resolver `log` entries and the Security Suite unsuccessful-command ledger.
The model layer is parked: neither assessment route calls an endpoint. Dry-run exports only the
gated, redacted model view locally. Legacy model flags and `AUDITEX_DISABLE_VALUE_RULES` are ignored
with one warning per invocation, without values; redaction remains enabled. Each view uses its own per-policy `scuba_config` synthesis outcome: an unprojected
view receives the not-collected marker. The private rule view can retain recognised
government environments while the model view remains withheld.
Conditional Access policy display names in `scope_post_check` are retained as
tenant configuration metadata, with e-mail local parts masked, as specified in
the output contract. Administrators can put personal names in those labels;
assessment bundles containing them remain confidential.
The identity collector's user inventory selects `onPremisesImmutableId`, so raw
`identity.users` chunks hold it for every returned user, up to the 250,000-user
safety ceiling. Previously only the hybrid collector's first 100 sampled users
carried it. Normalised user records, the evidence index and customer packs do
not carry it. Model projection keeps only effective administrators and
pseudonymises non-null values in local prompt exports; legacy `--no-redaction` is ignored.

The PIM role policy reads of the directory roles (`identity_governance`) collect the
notification recipients of each policy rule: these are e-mail addresses, collected as
evidence like the other directory identifiers (they sit in `raw/` and in
`normalized/governance_objects.json` and `normalized/privileged_roles.json`, which stay local). The
projection masks their e-mail local parts in local prompt exports. Assessment calls no model endpoint;
legacy `--no-redaction` cannot disable masking.
The approvers' names and ids of an approval rule are not stored. Nothing else of these reads
leaves the machine, and the reads are GET-only.

Defender for Office 365 / EOP rule scope lists (`SentTo`, `SentToMemberOf`,
`ExceptIfSentTo`, `ExceptIfSentToMemberOf`) are stored as same-length lists of
`"recipient"` placeholders in the collector payload. Non-empty strings become
`"recipient"`, non-empty dictionaries become `["recipient"]`, and nulls and empty
values stay unchanged. Domain scopes are retained for comparison with accepted
domains. For rule errors, payload `stdout` is replaced with its length in
`stdout_bytes`; `stderr` is retained.
`TargetedUsersToProtect` is not collected. The adapter records the audit log's
`stdout_sample` before this payload minimisation; the shared diagnostic boundary
masks e-mail/UPN local parts and dashed GUIDs and clips the sample to 500 characters,
as described below. Treat that log as confidential tenant evidence too.

`data-handling.json` describes a run's declared plane, scope risk, read-only
status, content-read status, and write actions; it is a declaration.
`api-inventory.json` records declared collectors, the collectors' own call
rows, permissions, call classification, and safety counts, and (Microsoft 365)
an `observed_ledger` read back from the run's own `audit-log.jsonl`: the
methods and endpoints the transport actually sent, the commands the adapters
actually ran, and the calls refused. Final audit-plane validation rejects
bundles that report tenant writes or body or file content reads. These
artifacts support review of a run; they do not authorize access or replace an
operator's obligations.

## What is enforced where

Read-only and data minimisation are enforced in code at the layer that makes the
call, and the audit log records both what ran and what was refused.

| Control | Enforced in | What it does | Where it shows |
| --- | --- | --- | --- |
| Microsoft Graph methods | `GraphClient._request` (`graph.py`) | Allows `GET`, and `POST` only to the Graph `/$batch` endpoint when every inner request is a relative `GET` without a body. Anything else raises `GraphError` (`ReadOnlyViolation`) before a token is requested or the network is touched. Every request must be HTTPS to `graph.microsoft.com` (also for `get_json(..., full_url=True)`), so the bearer token cannot go to another host, and `X-HTTP-Method-Override`, `X-HTTP-Method` and `X-Method-Override` headers are refused, on the request and on each `$batch` inner request. A redirect is never followed by the HTTP library: `GraphClient` follows it by hand (at most three hops), keeps the bearer token only for a hop on Graph, and fetches any other hop without the token, over HTTPS and only on a Microsoft download host (`.office.com`, `.office.net`, `.office365.com`, `.microsoft.com`, `.microsoftonline.com`, `.sharepoint.com`, `.azureedge.net`, `.windows.net`); anything else is refused (`RedirectRefused`, event `graph.request.redirect_refused`). The usage-report functions answer 302 to a pre-authenticated download URL, so each hop is logged as `graph.request.redirect` with host and path only, never the query (it is a credential), and an error after a redirect names the host and path without the query. The OAuth token endpoint is the only other call the client makes. | `graph.request.refused` event; `observed_ledger.graph.refused` |
| Command adapters | `adapters/read_guard.py`, called by the m365 CLI, PowerShell and Microsoft365DSC adapters before any process starts | Both languages are checked as plain ASCII: any non-ASCII or control character (other than tab, LF, CR) is refused, because the parsers treat Unicode quotes, dashes and line breaks differently from this check; a CR ends a statement like an LF. m365: the executable must be `m365`, the command must end in `list`, `get` or `status` (or be an `outlook report <name>` usage report), and after the command words every token must be a known option (`--output`/`-o`, `--period`, `--top`, `--help`/`-h`, `--verbose`, `--debug`) or that option's value, so a later bare word or `--` cannot extend the command inside the CLI parser. PowerShell: only `Get-*`, a few read-shaping pipeline cmdlets and `Search-UnifiedAuditLog`; comments, backticks, redirection, here-strings, `::`, a call operator on anything but a script block, subexpressions in double-quoted strings, dynamic member access (`.` followed by a quote or `$`) and method calls other than a few string helpers are refused. Microsoft365DSC also allows `Export-M365DSCConfiguration`, which reads the tenant and writes only local files. The lab response plane runs through the same adapters, so `--command-override` is held to the same allowlist. It is a syntactic allowlist that fails closed, not a PowerShell parser; the read-only role and scopes remain the authoritative boundary. Refusal reasons are redacted and clipped before they are logged. | `command.refused` event; `observed_ledger.commands.refused` |
| API ledger | `api_inventory.py`, attached by `AuditWriter.write_json_artifact` to every `api-inventory.json` it writes | `safety.read_only` and `safety.no_content_reads` are re-derived from the audit log. A write method, a non-read command, any refused call, a `$batch` whose inner calls or methods were not all recorded, a malformed or unreadable log line, a body-reading endpoint (message, attachment and content endpoints, calendar events and `calendarView`, group threads, conversations and posts, chat messages, SharePoint list items, To Do tasks), a `$select` of a body field or an `$expand` of a content collection (also when it sits in a next-page URL or a `$batch` inner URL) makes them false, whatever the collectors declared. Logged command words are cross-checked against the logged command text. `teams_admin_rest.request` records method, host, path, status and duration without headers or tokens; `observed_ledger.teams_admin_rest` counts attempts and endpoints, and non-GET or missing methods feed `safety.observed_write_calls`. Observed calls outside the declared set are listed (including `outside_declared.teams_admin_rest`), and redirect hops under `observed_ledger.graph.redirects`. Endpoint templates replace only identifiers with `{id}`, so a long resource name such as `deviceCompliancePolicies` stays visible. The handoff, `api-calls.md`, the pack README and `report.md` print the observation basis next to `read_only` and `no_content_reads` and render the ledger; a declaration is never printed as an observed fact. | `api-inventory.json` `observed_ledger`, `safety.observation_basis` |
| Bundle files | `output.py` (`AuditWriter`, `harden_bundle`), `evidence_db.py` | Run directories and every directory under them are `0700`; every file is `0600`; the audit log, evidence database and temporary files are created that way, whatever the caller's umask. A final sweep covers files other code wrote into the bundle. Files the tooling writes later are private on creation too, through one writer (`private_io.py`): rendered reports (`report render`, the exporters, the guided `--report-format`), the explorer page (default `reports/explorer.html`), report payloads sent to `--output`, and customer packs are `0600` in `0700` directories whatever the umask. Directories that already exist are not changed; a pack directory is tightened. A file is replaced through a temporary file, never written through a symbolic link. The sweep leaves symbolic links alone, and a symbolic link anywhere in a run makes the bundle fail its integrity check. | `ls -l` of the bundle |
| User-authored text | `data_minimisation.py`, used by `google_workspace/client.py`, `google_workspace/collectors.py`, `collectors/mailbox_forwarding.py`, both normalizers, `AuditWriter` and the offline replay copy in `cli.py` | Gmail vacation-responder subject and body (plain and HTML), Gmail send-as signatures, Graph automatic-reply message bodies, the words an inbox rule matches (`subjectContains`, `bodyContains`, `bodyOrSubjectContains`, `headerContains`, `senderContains`, `recipientContains`, each kept as `<field>Count` and `has<Field>`) and the Gmail filter `query`, `negatedQuery` and `subject` (kept as `<field>Length` and `has<Field>`; address lists and actions are kept, and a responder who needs the keywords of a suspect rule goes back to the tenant) are dropped before `raw/`, `normalized/`, `ai_safe/`, chunk files or any report, on live collection and on offline replay of a fixture. The booleans (`enableAutoReply`, `restrictToDomain`, `status`, `externalAudience`) and a `<field>Length` and `has<Field>` pair per dropped field stay. | `raw/`, `normalized/` |
| MCP tools | `mcp_registry.py`, `mcp_paths.py`, `mcp_server.py` | No tool takes a bearer token or client secret: auth comes from the local auth context and the server's environment (`AZURE_CLIENT_SECRET`). Every filesystem argument is resolved against the MCP root and refused when it contains `..`, starts with `~`, or lands outside the root (including through a symbolic link). Tenant and run names (which become part of a run directory name) are refused when they contain `/`, `\`, `..` or a control character; `AuditWriter` enforces the same rule. The server refuses to start, and every path argument is refused, when the root is `/`, or the home directory with `AUDITEX_MCP_ROOT` unset. Read-only annotations are unchanged. | `McpPathError` from the tool |

The MCP root is `AUDITEX_MCP_ROOT` when set, otherwise the server's working
directory. Run outputs, run directories, credential file paths and imported
assessment files must sit under it. The shipped defaults for `config_path`,
`schema_dir` and `sample_path` pass unchanged; any other value is confined. The
`auditex_setup_guide` path arguments are rendered into guide text and are never
opened.

Not enforced by these layers: Google Workspace SDK calls are not routed through
a method check and write no per-call audit events, so Google bundles say
`observation_basis: "coverage_ledger_only"` and rely on read-only scopes and the
collectors' use of list and get methods; the `dns_posture`, exposure, `power_platform`
and `power_bi` lookups use their own GET-only sessions rather than `GraphClient`, and the
`probe` toolchain checks that start `pwsh` or `az` directly are outside the
adapters.

The optional Power BI / Power Platform collectors are extended scope, off by default
and absent from `full` and all default presets. In commercial-cloud app mode they
obtain their own tokens through `app_token_for` for
`https://service.powerapps.com//.default` and
`https://analysis.windows.net/powerbi/api/.default`. Delegated runs have no token
path. The customer deliberately selects the `power-platform` preset after setting
up the management-app registration and the Power BI security-group tenant setting;
see the [one-time setup steps](../guides/admin-permission-guide.md#power-platform-and-power-bi-optional).
Fabric Administrator and Power Platform Administrator are write-capable admin roles
used read-only, with tenant-wide administrative blast radius in their services.
Power Platform management-app registration includes write privileges; the blast
radius is UNKNOWN beyond that statement. The Power BI service-principal setting
permits tenant-wide read-only admin metadata access for the selected group.
Auditex performs no registration, role assignment, tenant-setting change or other
tenant write and adds no Graph application permission. `Tenant.Read.All` must not
be granted. `listTenantSettings` is a read pinned to GET (`2023-06-01`);
POST is only a possible later fallback if GET is refused, to be decided after a
playground check, and is not enabled. Environment display names are discarded
because developer and trial environments can be named after people; DLP policy
display names remain because the rules read them. No bodies or file content are read.

Command-output diagnostics mask credentials (including JSON-keyed secrets), e-mail
and UPN local parts, and dashed GUIDs. This applies to `command.completed` samples,
adapter error dictionaries (`stdout`, `stderr`, `output`, `error`), doctor/auth errors
and toolchain probe details, including the `capability_matrix`. Each diagnostic is
clipped to 500 characters after masking. Matching inspects at most the requested
sample plus 2,048 characters: 320 covers an ordinary address, while the larger margin
also covers a 64-character local part represented by JSON `\uXXXX` escapes and a
253-character domain, or a percent-encoded GUID straddling the cut. If the input
exceeds that window, its trailing non-delimiter run is dropped after masking so
shrinking earlier matches cannot expose a partial identifier at the scan edge.
An unterminated delimiter-free window can therefore yield an empty sample.
E-mail local parts, including quoted ones, are bounded to 64 characters for matching.
Common encoded separators (`%40`, `\u0040`, `&#64;`, fullwidth `＠`, `%7B`/`%7D`,
`%2D`) are decoded once for masking; credentials are masked both before and after
decoding, and the decoded forms are emitted, including in MCP responses. URL schemes, hosts and paths are
retained around masked local parts; numeric npm versions, Git SSH addresses with
user `git` and hosts starting with `git` or `ssh.`, undashed hashes and labelled
`Trace ID:`/`Correlation ID:` values remain usable for support. Graph `request-id`
and `client-request-id` labels remain visible; their values follow the ordinary
dashed-GUID masking rule.
Known limitations include double-encoded or unsupported separator forms (`%2540`,
double-escaped `\\u0040`, `&#x40;`, `&#064;`, `&commat;`, `\x40`, `%u0040`), GUIDs
immediately followed by a hexadecimal character, IP-literal or numeric e-mail
domains, local parts or preceding glued local-part runs exceeding 64 characters,
and partial local parts at the scan edge when a quote is treated as a delimiter
(for example, `o'` from `o'brien` or `"john ` from `"john smith"`).

Live MCP command-response streams are masked without clipping. Values explicitly
supplied through `--tenant-name`, `--tenant-id`, `--out`, `--run-name`, `--target`,
`--subject`, `--domain` and `--run-dir`, including resolved output/run paths, are
preserved for tool chaining only where not preceded by an e-mail local-part
character; an operator address does not exempt a suffix of another address.
Credentials are redacted before those exemptions.
Collected evidence and raw inputs to parsers and error classifiers retain their
original values. This is a boundary for command diagnostics, not a guarantee that
all other exception messages or API logs are anonymised.

Customer packs contain no absolute path of the operator's machine and no file their manifest does not list
(`verify-pack` reports `unexpected_file`); a symbolic link, or an unlisted file where the product reads, is an
integrity mismatch and the pack is refused. The effective boundary against a mistake in any of these is the
read-only role and scopes granted to the auditor.

## External lookups

Live Microsoft 365 runs with the `dns_posture` collector make unauthenticated,
read-only requests about the audited tenant's domains:

- DNS-over-HTTPS queries (default resolver `cloudflare-dns.com`) for SPF,
  DMARC and DKIM TXT records cover the tenant's Exchange accepted domains,
  excluding coexistence domains, when complete same-run `acceptedDomains`
  evidence is available. Otherwise they cover Graph-verified domains with the
  Email service (a missing or non-list `supportedServices` field is kept).
  The separate posture checks, including MTA-STS, TLS-RPT and BIMI, cover
  Graph-verified domains only.
- An HTTPS GET of `https://mta-sts.<domain>/.well-known/mta-sts.txt`, only when
  the `_mta-sts` TXT record exists. Redirects are not followed.
- An HTTPS GET of the public Entra OpenID discovery document,
  `https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration`.
  Only tenant-level facts (tenant ID, region scope, cloud instance) are kept,
  as the informational `public_footprint` report section.

These requests reveal the audited domain names to the DNS resolver, the
domain's web host, and Microsoft. No usernames, mailboxes, or accounts are
probed, and no user enumeration endpoint is called. The HTTPS reads (MTA-STS
and OpenID discovery) stay limited to Graph-verified tenant domains. The TXT
record universe can also include tenant Exchange accepted domains absent from
that verified list. Offline runs make no external lookups; embedded callers
can pass `public_lookups: False` in the collector
context to skip the HTTPS reads.

The opt-in `identity_protection` collector stores only aggregate risky-user
counts, never user names or UPNs. The `exchange_policy` mailbox audit bypass
check stores only a count of bypassed accounts.

## Evidence and customer packs

`operator_inputs.sensitive_users.supplied` is a boolean; when true,
`operator_inputs.sensitive_users.count` is the positive integer count of unique
normalised addresses and `operator_inputs.sensitive_users.hmac_sha256` records
HMAC-SHA256 of the sorted, normalised list joined by newlines without a final
newline. Each run with a list
generates 32 random bytes using `secrets.token_bytes(32)` and stores them as raw
bytes only in `operator-inputs/sensitive-users.key` (0600, directory 0700).
The list is stored only in `operator-inputs/sensitive-users.txt`, also 0600.
The list and key are excluded from customer packs, exports, the evidence index,
AI context, logs and run-copy helpers. `bundle-hashes.json` records only their
paths and exclusion reason, never hashes or byte lengths. The key never leaves
the private area or appears in the manifest.

This lets the operator who holds the run directory prove which list was used;
a holder of only a customer pack cannot test guesses without the key. The count
and HMAC may be shared. This is a consistency check, not an authenticity
guarantee against someone able to rewrite all three inputs. Support can call
`azure_tenant_audit.sensitive_users.verify_sensitive_users(run_dir)`, which uses
`hmac.compare_digest`. Resume retains one key while replacing the list, removes
both when no list is supplied, and refuses to replace a missing or invalid key
for an existing HMAC.

Evidence is written locally under the selected output directory. Auditex does
not send raw evidence to an external service. Customer handoff packs copy
selected artifacts and include checksums. Selected artifacts can still contain
customer-sensitive metadata. Create each pack in a fresh review directory,
inspect its contents and intended recipients before transfer, then store it
under the customer's retention rules and delete stale bundles when that period
ends.

Before handoff, verify the pack:

```sh
auditex report verify-pack <customer-pack-dir>
```

If verification fails, regenerate the pack from the original run directory.

Notification preview is local by default. `auditex notify send --execute`
sends the chosen notification to an external sink. Review the recipient and
payload separately from pack verification before using `--execute`.

## Output redaction boundary

Run directories hold tenant evidence and are private working files: 0600 files in 0700 directories, for the
operator, not redacted, because the operator and the rules need the real values. The outputs listed in the
inventory below that can leave the machine pass one function, `redact_output` in
`azure_tenant_audit/output_redaction.py`, at the last step before the bytes are written, printed, sent or
returned. `auditex/output_writers.py` holds three machine-readable inventories and
`tests/test_output_redaction.py` checks them against the source (see "What the structural test enforces").

### What is guaranteed, and what is not

- **Guaranteed by the code and tested:** the classes in "What each profile redacts", in the representations
  listed there, in the outputs marked routed in the inventory; determinism; idempotence for those forms (a
  second pass changes nothing, generated pseudonyms are never re-read as names, ids or addresses); structure
  preservation (mappings keep their keys, apart from identifier keys, which are rewritten, never dropped; lists
  keep their order; embedded JSON is parsed, redacted and written back as valid JSON); a controlled failure
  (`RedactionDepthError`, a `ValueError`) for a value nested more than 100 levels or referring to itself, so a
  deep value is refused, never returned half redacted; an unknown profile name raises `KeyError`.
- **Not guaranteed:** that no identifier survives. This is a pattern and structure redactor. A privileged
  user's name that appears only in free text, with no structured record anywhere in the run's `normalized/`
  files, is not known to it; names under four characters are not replaced in free text; a name that is also
  report vocabulary (a role, a status word, a key of the structure) keeps that word in free text (the user's
  structured `display_name` is still pseudonymised); e-mail addresses are matched in plain, `%40`, `@`,
  `&#64;` and full-width forms only (not double-encoded); domains, group names, role names and free-text fields
  are kept by default (decisions below).
- **Not covered at all:** customer-pack source artifacts other than `run-manifest.json` (below), the
  `report_pack` profile, anything in the operator-only rows, and writers, prints, sends and return values the
  structural test cannot see.

### Inventory

| Output | Writer | Audience | Handling | Can leave the machine |
| --- | --- | --- | --- | --- |
| Run bundle: `raw/`, `normalized/`, `findings/`, `blockers/`, `index/evidence.sqlite`, `audit-log.jsonl`, `coverage.json`, `summary.json`, `summary.md`, manifests, `validation.json`, `bundle-hashes.json` | `AuditWriter` (`output.py`), `evidence_db.py`, `run_offline` | Operator | Private working files. Not redacted. Diagnostics inside them are masked by the command-output boundary above; user-authored text is minimised at collection | Only by operator action (copying, a customer pack) |
| `reports/report-pack.json`, `reports/action-plan.json` | `AuditWriter.write_report_pack` | Operator; copied verbatim into customer packs | `report_pack` profile: secrets only. **E-mails, GUIDs, names and paths are retained exactly** because finding ids, proof-table rows and evidence references embed the keys of the records they cite and the validator resolves them (an e-mail masked here gives `unresolved_report_proof_table_ref`) | Yes, inside a customer pack (see below) |
| Reports: HTML, Markdown, JSON, CSV, SARIF, OSCAL; exports (`auditex export run`, built-in exporters call `render_report`) | `render_report`, `preview_report` (`reporting.py`) | Customer, reviewers, CI tools | `shareable` profile on the sections before rendering, then on the rendered text (not on JSON, SARIF or OSCAL text) | Yes |
| Report preview returned to the CLI and the MCP tool `auditex_report_preview` | `preview_report` | Local client, AI client | `shareable`, including the citations (re-derived after masking) | Yes |
| `report api-calls`, `permissions`, `proof-table`, `handoff` and `analyze`, to a file or stdout | `_emit_report_payload` (`cli.py`) | Customer, reviewers | `shareable`: the payload is redacted as structure first, then rendered (Markdown gets a markup-safe pass over the already redacted text) | Yes |
| MCP tools `auditex_summarize_run`, `auditex_probe_summarize`, `auditex_diff_runs`, `auditex_compare_runs`, `auditex_normalize_external_assessment`, `auditex_compare_external_assessments`, `auditex_list_blockers`, `auditex_report_analyze`, `auditex_api_inventory`, `auditex_permissions_ledger`, `auditex_proof_table`, `auditex_enterprise_handoff`, `auditex_verify_customer_pack` | `mcp_server.py` functions of the same names | An AI client or any MCP caller | `shareable` over the complete returned payload, with the context of every run it was built from (a comparison uses the first run's salt); citation summaries re-derived. A pack-verification result also scrubs the pack's own path | Yes |
| Setup guide (`setup-guide`) | `_emit_setup_guide` (`cli.py`) | Operator | Not redacted: it renders the operator's own parameters (for example `--subject`) and commands, and holds no tenant evidence | Yes, but carries no evidence |
| Customer pack: `handoff`, `report.md`, `api-calls`, `permissions`, `proof-table`, `README.md`, `checksums.sha256`, `pack-manifest.json` and the copy of `run-manifest.json` | `write_enterprise_handoff_pack`, `_write_text_artifact`, `_copy_source_artifact` | The tenant owner and whoever they pass it to | `customer_pack` profile, with the run salt; the manifest digests are those of the redacted files | Yes |
| Customer pack `source-artifacts/` other than `run-manifest.json`: `summary.json`, `data-handling.json`, `api-inventory.json`, `audit-plan.json`, `live-readiness.json`, `reports/report-pack.json`, `validation.json`, `ai_context.json`, `bundle-hashes.json` | `_copy_source_artifact` | As above | **Verbatim, integrity-bound copies, not redacted** (`verify-pack` ties them to `bundle-hashes.json`) | Yes |
| Notifications: Slack, Teams, SMTP, Jira, GitHub | `send_notification` (`notify.py`) | Third-party services | `shareable` over the whole envelope (payload, citations, service responses) before any sink and before the return; the run identity used for ticket de-duplication is computed first, from the real run directory, and carried as a one-way digest (`run_fingerprint`); the webhook walker (`_redact_value`) stays as a second layer | Yes |
| Explorer page | `write_explorer` (`explorer.py`) | Operator's browser | Private working view; it exists to inspect real values. Not redacted. Decision pending product if it is to be shared | Only by operator action |
| Model assessment files, prompts, adapter sidecar | `assess_run`, `assess_scubagear_export` (`model_serving.py`) | Operator; the model endpoint (loopback unless the operator says otherwise) | The model view is redacted by the projection (input side); the files are private. The explainer's text passes `redact_output(..., profile="explainer", context=context_for_run(run))`, wired by the explainer job, not by these writers | Prompts only to the configured endpoint |
| Logs: `audit-log.jsonl`, command samples, doctor and auth errors | Adapters, `secret_hygiene.redact_output` | Operator, support | Diagnostics boundary above: credentials, e-mail local parts, dashed GUIDs; clipped to 500 characters | Only by operator action |
| Operator terminal output of read-only commands: `auditex summarize`, `blockers`, `diff`, `compare`, `probe summarize`, `verify-pack`, `customer-pack` results (the pack path), `rules`, `auth` and model commands | `cli.py` `main`, `summarize_run_raw`, `list_blockers_raw` | Operator | Not redacted, deliberately: they print the operator's own run (the whole point of `summarize` is the real values) to the operator's terminal. If the operator redirects them to a file and sends it, that is operator action | No (the operator's terminal) |
| MCP tools that run a command (`auditex_run_*`, `auditex_probe_live`, `auditex_google_*`) | `command_runner` | The MCP caller | The command-output boundary (diagnostic masking), not `redact_output` | Yes, masked |
| MCP tools `auditex_auth_status`, `auditex_auth_list`, `auditex_auth_capability`, `auditex_auth_use` | `mcp_server.py` | The MCP caller | Saved connection names and tenant metadata of the operator; not run evidence; not redacted. Open item for product | Yes |
| MCP catalogue tools (profiles, collectors, adapters, rules, exporters, schemas, setup guide) | `mcp_server.py` | The MCP caller | Shipped catalogues, no tenant data | Yes |

### What the structural test enforces

`tests/test_output_redaction.py` scans every module under `src/` (an AST scan) for functions that open a file for
writing, call `Path.write_text`/`write_bytes`, `write_private_*`, `copy_private_file`, `secure_write_*`, a `shutil`
copy, `.write()`, `json.dump`, `print()` of a non-literal value, or send through `requests`, a session, an opener,
`smtplib` or `urlopen`. Every function found must have an entry in `SINK_INVENTORY`
(`auditex/output_writers.py`) classified `routed` or `private` with a reason; an unknown function fails the test,
and so does an entry that matches nothing. A `routed` function is checked to call the redaction (or to be called
only from a function that does). Every MCP tool must be in `MCP_TOOL_INVENTORY`, and every `routed` one must call
`redact_payload`. A self-test checks that the scan recognises each shape it claims to.

Limits of that test, stated in `SCAN_LIMITS`: it reads source text by call name and receiver name, so it does not
see a write through an alias or a stored callable, `os.write` on a raw descriptor, sqlite writes, subprocess
commands that write, logging handlers, non-Python files or third-party code; and it does not follow data, so it
proves that a routed function reaches the redaction, not that every value it writes has passed it. The
guarantee of this section is therefore: outputs of the shapes above are classified, and the ones classified
routed call the redaction. Nothing stronger is claimed.

### What each profile redacts

| Class | `report_pack` | `shareable`, `customer_pack`, `explainer` |
| --- | --- | --- |
| Secrets: Bearer values, JWTs, `key=value` and JSON-keyed credentials (`secret_hygiene.INLINE_SECRET_RE`, quoted values with escaped quotes included), and the whole value, of any type, under an exact credential key (`client_secret`, `password`, `access_token`, `refresh_token`, `api_key` and the like, spelled `snake_case`, `kebab-case` or `camelCase`) | Yes | Yes |
| E-mail local parts, masked `***@domain` exactly as the model projection masks them, also when the at sign is written `%40`, `@`, `&#64;` or full-width | No | Yes |
| Privileged-user display names (a record with an immutable id, M365 role holders, Google users flagged `is_admin`, `is_delegated_admin` or `is_privileged`) and `onPremisesImmutableId`, pseudonymised as the projection does (`User <16 hex>`, `Id <16 hex>`; `sha256(salt NUL value)`, the salt being the SHA-256 of the canonical `run-manifest.json`), so a name matches across the model view and every output of one run. The names and ids come from every `normalized/` record of the run, so an output that selects only some sections still protects them | No | Yes |
| Dashed GUIDs (tenant, object, application and policy ids): replaced by a valid GUID `00000000-0000-4000-8000-<12 hex>` derived from the run salt, so references inside one output stay consistent and OSCAL still validates | No | Yes (pending product, below) |
| The operator's run paths, every occurrence: run-relative when the text starts with the path, otherwise `<run-dir>` | No | Yes |
| JSON embedded in a string | As the profile | Parsed, redacted as structure and written back in its own layout, so escapes and quotes stay valid |

Deliberately not redacted, in every profile: policy ids, finding ids and rule ids, reason codes, verdicts and
statuses, section names, setting names and enum values, role names, numbers and booleans, and the public
baseline text. These public values are allow-listed exactly: the addresses `reports@dmarc.cyber.dhs.gov`,
`cyberliaison@cisa.dhs.gov`, `reports@example.com` and `username@somedomain.com` (`PUBLIC_ADDRESSES`); the
all-zero GUID, Microsoft first-party resource application ids and the Microsoft role template ids the product
ships (`PUBLIC_GUIDS`, kept equal to the GUID literals under `src/` by a test); and values labelled
`Trace ID:` or `Correlation ID:`, which stay usable for support as in the diagnostics boundary. A mapping key is
rewritten only when its text holds an identifier (an e-mail address or a GUID), never by name substitution;
values under structural keys (`status`, `severity`, `verdict`, `reason_code`, role keys and the like) and names that
equal report vocabulary are protected from name substitution. If two keys become equal the later one gets a `#n`
suffix; no value is lost. Redaction is deterministic and leaves numbers, booleans, `None` and bytes alone.

### The customer pack's verbatim files

A customer pack redacts what the product generates (`handoff.json`, `report.md`, the ledgers, `README.md`,
`checksums.sha256`, `pack-manifest.json`) and the copy of `run-manifest.json`. It does **not** redact nine
source artifacts, which are integrity-bound byte copies of the run's files: `summary.json`,
`data-handling.json`, `api-inventory.json`, `audit-plan.json`, `live-readiness.json`, `reports/report-pack.json`,
`validation.json`, `ai_context.json` and `bundle-hashes.json`. They can carry e-mail addresses, GUIDs and
privileged names exactly as the run recorded them (the report pack in particular, per the `report_pack` row
above). A pack therefore cannot be described as "all identifiers redacted", and the test deliberately skips
those files. The confidentiality of the pack depends on who receives it.

### Decisions pending product

These classes are not settled by the documents. Each default is conservative but usable and is a field of the
single constant `PENDING_PRODUCT_POLICY`; changing the field changes every writer.

| Class | Default | Why | Flip |
| --- | --- | --- | --- |
| GUIDs | Redacted (pseudonymised) | Tenant and object ids identify the tenant; consistent pseudonyms keep cross-references readable | `redact_guids=False` |
| Domain names | Kept | DNS, mail-flow and accepted-domain findings are unreadable without them; the e-mail mask keeps the domain by contract | `redact_domains=True` replaces every domain seen in an e-mail address (and `RedactionContext.domains`) with `domain-<12 hex>.invalid` |
| Group display names | Kept | The group is what an administrator acts on | `redact_group_names=True` pseudonymises records whose `principal_type` is `group` (`Group <16 hex>`) |
| Free text (`owner`, `justification`, `comment`, `comments`, `notes` values, whatever their type) | Kept | Accountability fields of waivers; `reason` is not in the list because it carries reason codes | `redact_free_text=True` |
| Role names | Kept; **no flip exists** (the earlier `redact_role_names` field was inert and has been removed) | Built-in names are public Microsoft vocabulary, custom names are tenant text, and the output alone cannot tell them apart | Needs a product definition first |
| Customer-pack source artifacts (the nine above) | Verbatim | `verify-pack` checks them against `bundle-hashes.json`; a redacted copy needs a `transformed` row like the manifest has, and a recipient who is the tenant owner may need the real values | Product to decide whether the pack carries redacted derivatives |
| `report-pack.json` in the run bundle | Secrets only | Its ids are references; see the inventory | Redact at hand-over only (the current design) |
| Explorer page | Not redacted | Operator working view | Add a shareable variant |
| MCP auth tools | Not redacted | Operator's saved connection metadata | Decide whether tenant ids and names in them are shared with an AI client |

Limits worth knowing: after masking, two users of one domain are indistinguishable in a shared report (the
projection's mask has the same property); a pseudonymised GUID cannot be looked up in the portal, so the operator
reads the private run directory for that; the notification fingerprint is the same value as before the boundary
existed (a hash of tenant name and run directory), computed before redaction, so existing Jira and GitHub tickets
still match and two runs of one tenant do not collide.

## Credentials and local files

Never commit or ship Azure app authentication values, Google service-account
files, OAuth client files, OAuth caches, bearer or refresh material, raw
credential dumps, or customer signing keys. Keep them in `.secrets/` or another
local Git-excluded path. Do not place those paths in repository defaults.

Bearer tokens are imported and inspected only through the local CLI
(`auditex auth ...`); the MCP server has no tool that accepts one.

Use AI and MCP only with bundle artifacts intended for reasoning, such as
`summary.json`, `summary.md`, `data-handling.json`, `audit-plan.json`,
`api-inventory.json`, report-pack data, proof-table rows, `ai_context.json`,
and `validation.json`. If evidence is missing, say so rather than inferring a
fact. Do not add external crash telemetry or analytics.

## Suspected exposure

If sensitive auth material is found in a bundle or pack, stop handoff, remove
the pack from its transfer channel, rotate the exposed material, regenerate the
run or pack after correcting the source, verify the pack again, and record the
incident through the customer's process.
