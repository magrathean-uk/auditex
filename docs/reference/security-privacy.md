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
For `Get-AntiPhishPolicy`, `TargetedUsersToProtect` is read only transiently and
replaced inside the adapter with a count/HMAC-bound `TargetedUsersCoverage`
summary. No literal target list, stdout, stderr or sample text leaves that
operation's adapter boundary, including successful warnings and errors. Raw
offline samples are sanitised before they are saved or used by collectors.
Other operations record the audit log's `stdout_sample` before payload
minimisation; their shared diagnostic boundary
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
| MCP tools | `mcp_registry.py`, `mcp_paths.py`, `mcp_server.py` | No tool takes a bearer token or client secret value: Microsoft auth comes from the local auth context and the server's environment (`AZURE_CLIENT_SECRET`), and the Google tools take confined paths to credential files (`service_account_key`, `oauth_client`, `token_cache`), never secret values. Every filesystem argument is resolved against the MCP root and refused when it contains `..`, starts with `~`, or lands outside the root (including through a symbolic link). Tenant and run names (which become part of a run directory name) are refused when they contain `/`, `\`, `..` or a control character; `AuditWriter` enforces the same rule. The server refuses to start, and every path argument is refused, when the root is `/`, or the home directory with `AUDITEX_MCP_ROOT` unset. Tools whose `read_only_hint` is false are listed below. | `McpPathError` from the tool |

MCP tools with `read_only_hint` false (a test compares this list with the registry).
None of them writes to a tenant; the hint is false because they write local files
or local auth state, or, for the response tool, because it is a gated response action:

- `auditex_auth_use`: switches the active saved m365 connection (local auth state).
- `auditex_run_offline_validation`: writes an offline sample run bundle locally.
- `auditex_run_delegated_audit`: writes a run bundle locally; the audit itself is read-only.
- `auditex_google_probe`: writes probe output locally; the probe is read-only.
- `auditex_run_google_workspace_audit`: writes a run bundle locally; the audit itself is read-only.
- `auditex_probe_live`: writes probe artifacts locally; the probe is read-only.
- `auditex_run_response_action`: gated response tool, listed only when `AUDITEX_ENABLE_RESPONSE` is truthy (lab only).

The MCP root is `AUDITEX_MCP_ROOT` when set, otherwise the server's working
directory. Run outputs, run directories, credential file paths and imported
assessment files must sit under it. The shipped defaults for `config_path`,
`schema_dir` and `sample_path` pass unchanged; any other value is confined. The
`auditex_setup_guide` path arguments are rendered into guide text and are never
opened.

The MCP offline validation tool removes all `AUDITEX_*` variables from its
sample-run process, retains other environment variables unchanged, and closes
the child's standard input. It also drops the registered operator-input CLI
flags. Real-audit tools retain their environment; direct CLI offline replay can
still use operator inputs deliberately.

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
Syntax errors in the product CLIs (`azure-tenant-audit`, `auditex`, `auditex-mcp`
and the vendored `tenant-bootstrap` package copy) print usage and a fixed error
message without echoing supplied argument values. The lab scripts under
`tenant-bootstrap/scripts` and `benchmarks` are outside this guarantee.
Operator-input validation can also show a line number and a fixed reason,
without the source value or path. Use `--help` to inspect options.
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

## Guarded run and pack reads

`azure_tenant_audit.run_files.read_run_file` reads a file beneath a run or pack
directory through a guarded descriptor. `UnsafeRunFileError`, an `OSError`,
has a path-free message and a `.reason` attribute; `outside`, `oversize`,
`hardlink` and `type` identify those specific refusals. Missing files still
raise `FileNotFoundError`.

Control files, including manifests, summaries, validation, AI context and
salt, have a 32 MiB limit (`MAX_RUN_FILE_BYTES`). Evidence and other data
files have a 256 MiB limit (`MAX_RUN_DATA_BYTES`). Hashing and copies use
guarded streams. Guarded reads during writer finalisation have no size cap.
Bundle hash manifest generation and verification stream without a size cap;
they still reject unsafe file types and links. Identity discovery has its own
limits, described below.

The guard rejects paths outside the root, symbolic links, non-regular files,
files owned by another user, and files with more than one hard link. A run and
its `operator-inputs` directory must be owned by the effective user and must not
be group- or world-writable. It refuses where descriptor-relative, no-follow
opens or the required identity and permission checks are unavailable.

The context for an operation verifies a run's sensitive-user and partner-domain
pairs against its manifest and keeps their file identities open while admitting inputs. A
missing, partial or invalid claimed pair is refused. Independently copied runs
are verified and registered separately. Discovery starts at the selected file's
parent even when a caller supplies a nested root. `operator-inputs` and any
directory below it cannot be run roots, and a manifest there cannot hide an
enclosing pair. A standalone copy without a run marker
and with an unseen file identity cannot be recognised as a private pair. There
is no global registry of private files.

The guard does not contain a writer running as the same user, an earlier rename,
replacement or writable ancestors, ACL grants, privilege, or restored modes.
Shipped resources, including `AUDITEX_RESOURCE_ROOT` and import-time rule
configuration, remain outside it. So do token files, OAuth and service-account
files, token caches, `AUDITEX_LOCAL_AUTH_ENV`, `AUDITEX_AUTH_CONTEXTS_PATH`,
and inherited descriptors other than standard input. Child processes using `AUDITEX_M365_HOME` or
`XDG_DATA_HOME`, external exporters given run paths, and delegated
Transformers/Datasets reads are trusted code and are outside this boundary.

Hard-linked backup bundles, including those made with `rsync --link-dest`, are
refused; the original run is also refused while its files have those extra
links. Recover with an independent `cp` copy owned by the operator, not hard
links, and restore safe directory permissions. Each copy's private pair is
verified on admission.

Index inspection admits the main index file and every sidecar beside it by guarded
descriptor (no-follow walk, regular file, single link, owner and private-pair identity);
any failure is the fixed refusal. Only the admitted main file is ever copied, into a
private `0700` temporary directory (files `0600`) under an operator-owned parent that
is not group- or world-writable, never under the run's parent directory, and only after
that directory is proved to be on encrypted internal storage. The proof is implemented
for macOS Data volumes. No evidence is copied to unproved temporary storage. Every
SQLite open uses `mode=ro&immutable=1`, on the copy or in place. A missing proof, a
failed copy or an SQLite error is never an admission refusal: the read falls back to
the admitted path in place, or the index is reported as invalid.

Sidecars are never copied or replayed, so the verdict does not depend on the host.
A hashed index is authoritative as hashed; the hash check reports any sidecar. An
unhashed legacy index with a non-empty `-wal` or `-journal` is untrusted: its summary
is empty, consumers use the manifest and report metadata, and validation records
`invalid_evidence_sqlite`. An empty `-wal` or any `-shm` is ignored. This is
deliberately conservative, even when the WAL frames were already checkpointed.

The held main descriptor is checked again after SQLite inspection and before
fallback from a failed SQLite open. A change refuses the read, including when a
query fails. Read-only consumers never create, append to or
change anything in a bundle they inspect. A process that is producing a run appends
one constant info line (no path or value, never the console) to that run's debug log
the first time it reads the index in place, when the existing guarded log accepts an
append without creating a log or changing its permissions; an unwritable or unsafe log gets no line and the read still succeeds. A resume
is a new producing invocation and logs its own line. A writer running as the same user
can still alter or exchange the file around these checks. Index copies have no size
cap, so copy time and available temporary space matter.
A killed or interrupted index build can leave a private staging directory beside the index.

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

Assessment verifies the private list and key against the manifest before
supplying bare lower-case addresses to SS 2.1's in-memory rule configuration.
This configuration bypasses the model shape gate and model budgets, never the
loader's byte/entry bounds. Addresses never enter public projection views,
prompts, assessment records, sidecars, logs, AI context, reports, exports or
packs. Absent input stays not collected; a present but invalid private pair is
refused during run admission. SS 2.3 consumes its separate verified
PartnerDomains input in a private rule view, independently of SensitiveUsers.
The collector's bounded, transient target-list comparison produces only
`TargetedUsersCoverage`. A verified binding and usable policy evidence can
establish membership without retaining target strings. The full summary stays
local in raw evidence, normalised records and SQLite; its private binding stays
in the rule view. Shareable, customer-pack and explainer outputs drop both
whole subtrees, including embedded JSON. Offline copies use the same
verification and private view; the ScubaGear export path keeps its literal
comparison and ignores reserved run-summary fields.

This lets the operator who holds the run directory prove which list was used;
a holder of only a customer pack cannot test guesses without the key. The count
and HMAC stay local; redacted manifest derivatives retain at most boolean
`supplied`. This is a consistency check, not an authenticity
guarantee against someone able to rewrite all three inputs. Support can call
`azure_tenant_audit.sensitive_users.verify_sensitive_users(run_dir)`, which uses
`hmac.compare_digest`. Resume retains one key while replacing the list, removes
both when no list is supplied, and refuses to replace a missing or invalid key
for an existing HMAC.

Target-list limits are 10,000 raw entries and 262,144 compact-JSON UTF-8 bytes
per policy, measured before filtering or de-duplication. A streamed 64 MiB
stdout bound terminates and reaps an over-limit child. Unknown shapes, malformed
fields and failed transforms never persist the original target material.
Retained policy settings accept only scalars or flat bounded lists; a nested
structure drops that setting alone. Replay reduces unsupported Exchange
operations and components that name the target field, including JSON-escaped
text, to safe settings and closed diagnostic classes. Unknown diagnostic text
is discarded or replaced with a fixed error class.
Fresh offline replay cannot reuse an old summary without fresh literals;
resume cannot reuse known membership after the verified input binding changes.
If the resulting selected Exchange re-run fails, its failed status and coverage
remain authoritative while safe earlier settings survive without membership
proof. Healthy fresh operations replace their earlier settings.
Live Exchange wire-shape validation remains unverified; unexpected shapes are
unusable evidence.

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

### Partner domains: customer-confidential operator input

Partner domains are not personal data, but are customer-confidential. Microsoft
365 audit commands, guided flows and offline replay accept `--partner-domains FILE`
or `AUDITEX_PARTNER_DOMAINS_FILE` (flag wins). Local regular files only, read once
before collection, capped at 256 KiB and 10,000 entries; parser errors show a
fixed message, while direct validation can name a physical line and fixed reason.
Neither exposes source content or its path. UTF-8/BOM text or a JSON string array is
normalised into bare sorted unique ASCII domains, lower-case with one trailing
dot removed and a final label that is neither all digits nor `0x` followed by
zero or more hexadecimal digits. No comments, e-mail
addresses, URLs, wildcards or non-ASCII input; ASCII punycode is accepted.
SS 2.3 v3.9.1 uses exact domain matching, including explicit subdomains, without
IDNA conversion or subdomain expansion.

The sole persisted list is `operator-inputs/partner-domains.txt` (0600, directory
0700). `operator_inputs.partner_domains` records only `supplied`, and when true
`count` and `hmac_sha256`, covering the normalised newline-joined UTF-8 list
without its final newline. A separate random 32-byte key per input per run is
stored only at `operator-inputs/partner-domains.key` (raw bytes, 0600). It is never
shared with sensitive users. Both paths are marked `redacted_artifacts`, excluded
from evidence and its index, AI context, logs, reports, exports and customer packs.
Bundle hashes list exact-path `redacted_operator_input` exclusions without hashes
or byte lengths, including the shared `.gitignore`; the directory is not blanket
excluded. Source paths are redacted in command arguments. Nothing is uploaded;
assessment reads the verified snapshot only into SS 2.3's in-memory private
rule configuration. Ordinary absence of SensitiveUsers does not disable this
input, or vice versa; malformed private material still refuses run admission.
Demos never resolve this input.

Resume retains a valid key while replacing the list; clearing removes this input
and key, preserving the sibling input and shared ignore file when needed. An
existing HMAC with an unusable key is an error. The local helper
`azure_tenant_audit.partner_domains.verify_partner_domains(run_dir)` verifies count
and HMAC consistency; it cannot establish authenticity against someone able to
replace the manifest and both private files. Treat the list and key as private
run material. The manifest schema defines this field; see the output contract for
its constraints. The model projection and shape gate never receive either list.

## Output redaction boundary

The local rendered report retains the original values. Shareable reports and
built-in exports, MCP report payloads, customer packs, notifications and the
explainer profile redact dashed GUIDs and strings under `owner`, `justification`,
`comment`, `comments` and `notes`, including strings used as keys in nested containers. Domains, group
names and role names remain. The redactor also masks e-mail local parts, known
privileged-user display names and immutable IDs, credentials and run-directory
paths. Public baseline example addresses are kept. A run-specific pseudonym uses
the resolved run path as its salt input. GUIDs become `Guid` plus a digest,
which is stable on another pass without reserving a range of real GUIDs.

The report structure is redacted before rendering, so free-text keys work in
Markdown and HTML as well as JSON. Customer-pack source JSON is a redacted
derivative: the pack records the original and derivative hashes separately.
The original hash manifest is copied only when redaction leaves it unchanged.
The run bundle and its working report pack stay local and retain their values.
The original hash identifies the source; it does not prove how a derivative was
produced. A derivative is bound to the pack checksums, so detecting an edit
followed by recomputing those checksums requires a separately recorded digest
passed to `verify-pack --expect-checksums-sha256`.

Before sharing, identity discovery reads all `normalized/**/*.json` files. It
refuses malformed, unreadable or non-regular entries, symbolic and hard links, changes
during discovery and scans exceeding 5,000 files, 64 MiB per file, 256 MiB
in total per run or 32 directory levels. A subsequent snapshot also refuses scan
problems or changed fingerprints. These checks cover shareable reports, exports,
customer packs, notifications and MCP tools. A size-limit refusal reports the
supported sizes without naming files; other refusals identify the reason using
safe file labels. Repair the evidence before retrying.

The limits are on bytes scanned, not a resident-memory ceiling. A synthetic
25,000-user run had 54 normalised files totalling 23.6 MiB; a 90,000-user run
had 54 files totalling 84.1 MiB, with a largest file of 44.1 MiB. On the test
machine, their shareable HTML previews peaked at about 0.5 GiB and 1.5 GiB of
resident memory respectively. The 2 GiB ceiling used for these tests is not
enforced by the scanner; memory use also depends on the evidence and output.

On adversarial JSON, worst-case scanner memory is about 64 times the file size, up to about 4 GiB at the 64 MiB per-file cap. This is an upper bound that ordinary evidence does not reach; the tested sizes remain as listed above.

These are pattern and structure rules, not a guarantee that every personal
value in arbitrary prose is recognised. URL userinfo passwords are matched
for schemes of 1 to 32 characters and scheme-relative URLs. Known immutable
IDs are matched in narrative only at word-character boundaries and when at
least four characters long; a structured immutable-ID field is redacted even
when shorter. Narrative name matching has the same minimum length and word
boundaries, and preserves recognised structural, group and role vocabulary.
Names not discovered in the run or output can remain in prose.

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

## Deterministic explainer boundary

The template explainer uses only the rule's cited, already redacted sections.
Null citations resolve to the fixed policy read set, never all supplied
sections. Evidence ids retain positions in the supplied full section order.
Each observed section is capped at 6,000 canonical JSON characters after the
existing projection redaction; oversize values become `{not_shown: "size"}`.
Only `M365Environment` and `collection_status` survive in `scuba_config`;
null is preserved and other shapes become `{not_shown: "shape"}`.

Pass the redacted view as is, without extra pseudonymisation. The existing
idempotent email-local-part guard remains on section values and reason text.
Projection already pseudonymises privileged-user DisplayName and non-null
OnPremisesImmutableId with the run salt. Internal rule views, detail, labels,
tenant/run identifiers, paths, timestamps, credentials and uncited records are
not explainer inputs. Public baseline Instructions retain their example
addresses until final output redaction.

Every returned explanation, step and reference must pass through the D3
`explainer` output profile before serialisation or display. As described in
[Output redaction boundary](#output-redaction-boundary), this profile redacts
GUIDs and strings under the free-text keys `owner`, `justification`, `comment`,
`comments` and `notes`, as well as the other values listed there. Domains,
group names and role names remain. This is not full anonymisation.

Serving passes the public rule answer and redacted model-case sections to the
explainer, never the private rule view. It redacts the complete result with the
`explainer` profile before attaching it. For run bundles the context contains
the run salt, paths and discovered identities; incomplete discovery or any
rendering or redaction exception suppresses the explanation without changing
the verdict. Logs contain only the policy id and exception class. An internal
ScubaGear export has no run context, so its explainer uses an empty context:
pseudonyms are unsalted and run paths and undiscovered names are not known to
that context. The same profile still masks recognised identifiers and secrets.

Reports guard and validate the assessment before reading explanations and apply
the explainer profile again, including for local reports, so modified
assessment text does not bypass that boundary. If the context or assessment is
unusable, explanations are omitted. The support address in the fixed fault
step currently has its local part masked by this profile.
It has no inference dependency, endpoint or model fallback. Model use is parked;
if separately authorised later, it must be loopback only, with this same input
and output boundary and no `--no-redaction` path.

Explainer test material follows the public-repository fixture rule: stored fixtures hold only constructed rows and
model-pack train and validation rows, each with a vector id and an origin; held-out test rows (pack or pilot), sealed
pilot rows, diagnostic rows, machine paths and files over 1 MB are refused by `tests/test_explainer_fixtures.py`, and the
expanded test set, pairs and mutants are generated in memory from the allowed fixtures rather than stored.
