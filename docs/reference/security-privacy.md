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
The model layer is removed: assessment makes no network request and no model endpoint is a permitted outbound destination. `auditex assess` rejects the removed model, endpoint, dry-run and
redaction options (exit 2) and reads no `AUDITEX_MODEL_*` or `AUDITEX_DISABLE_VALUE_RULES` setting;
redaction is always on. Each view uses its own per-policy `scuba_config` synthesis outcome: an unprojected
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
pseudonymises non-null values in the local projection with the run's pseudonym key
(see [Pseudonym key](#pseudonym-key)).

The PIM role policy reads of the directory roles (`identity_governance`) collect the
notification recipients of each policy rule: these are e-mail addresses, collected as
evidence like the other directory identifiers (they sit in `raw/` and in
`normalized/governance_objects.json` and `normalized/privileged_roles.json`, which stay local). The
projection masks their e-mail local parts. Assessment calls no endpoint, and no option disables masking.
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
| Bundle files | `output.py` (`AuditWriter`, `harden_bundle`), `evidence_db.py` | Run directories and every directory under them are `0700`; every file is `0600`; the audit log, evidence database and temporary files are created that way, whatever the caller's umask. A final sweep covers files other code wrote into the bundle. Files the tooling writes later are private on creation too, through one writer (`private_io.py`): rendered reports (`report render`, the exporters, the guided `--report-format`), the explorer page (default `reports/explorer.html`), report payloads sent to `--output`, and customer packs are `0600` in `0700` directories whatever the umask. Directories that already exist are not changed; a pack directory is tightened. A file is replaced through a temporary file, never written through a symbolic link. The sweep leaves symbolic links alone, and a symbolic link anywhere in a run makes the bundle fail its integrity check. The private key `operator-inputs/pseudonym.key` is `0600` in an `operator-inputs/` folder of `0700`; a key or folder with any group or other bit is refused, never tightened. | `ls -l` of the bundle |
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

No tool whose `read_only_hint` is true ever writes a run. Tools that derive pseudonyms from a run
(summaries, diffs, comparisons, previews, notifications, the inventory and handoff tools) only read its key;
they never create one. A keyless run (made by 1.4.0 or earlier, copied without `operator-inputs/`, or sealed on
storage without locking) is masked with a temporary key held in memory, and the result says so. The command
`auditex report prepare-key RUN_DIR` creates the run's key; it is a CLI command and is not offered over MCP. This
paragraph makes no claim about when an MCP client asks for approval of a tool.

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
and the `tenant-bootstrap` forwarder to the engine) print usage and a fixed error
message without echoing supplied argument values. The lab scripts under
`tenant-bootstrap/scripts` are outside this guarantee.
Operator-input validation can also show a line number and a fixed reason,
without the source value or path. Use `--help` to inspect options.
Collected evidence and raw inputs to parsers and error classifiers retain their
original values. This is a boundary for command diagnostics, not a guarantee that
all other exception messages or API logs are anonymised.

Customer packs contain no absolute path of the operator's machine and no file their manifest does not list
(`verify-pack` reports `unexpected_file`); a symbolic link, or an unlisted file where the product reads, is an
integrity mismatch and the pack is refused. The effective boundary against a mistake in any of these is the
read-only role and scopes granted to the auditor.

## Boundary scanner limits

Two static scanners guard the source tree against an accidental write or content read:
`tests/test_read_boundaries.py` (process launches, command text and Google Workspace requests) and
`tests/test_http_verb_allowlist.py` (HTTP verbs and openers). They check our own code and are not a defence against
code written to defeat them; review covers deliberate obfuscation. The runtime layer behind them is the adapter guard
(`adapters/read_guard.py`), which refuses any non-read command sent through the adapters before a process starts. The
read-only role and scopes granted to the auditor remain the authoritative boundary.

Both scanners fail closed on a value they cannot prove: a launcher argument, importer name, callee lookup, standard
input or HTTP receiver that is not provably literal or a known non-opener is reported and fails the suite. Over-reporting
is therefore possible (for example a flow-insensitive mutation mark, an f-string with a field, or a parameter that shares
a receiver's name in another scope); it is a false positive, not a gap. The limits below hide a call and are known to
be open, each a "named limit" (v2 DEC-011): no test asserts the limit itself, and it is reviewed by hand. They are the
limits found in the scanners and their reviews so far; a static scan can have others. Planted tests in
`tests/test_read_boundaries.py` close shadowing by a module binding only: when the module itself binds a read-only
hand-off or transparent-conversion name such as `info` or `list` (`def`, `class`, assignment, import or parameter),
that shortcut no longer applies. They also close the import, `with`, `def`, `class`, `except`, `match` and
comprehension-walrus bindings after a literal, and class-body names. The same name called on another object, a call
matched to a module function by name, the `zip` and `enumerate` unpacking and a store on `builtins` stay open and are
listed. In `tests/test_http_verb_allowlist.py` the opener attribute store (`pathlib.Path = factory`) is closed the same
way.

Read-boundary scanner:

| Limit | Status |
| --- | --- |
| A script passed by file (`-File`) or encoded (`-EncodedCommand`); the launch is found, the script text is not read | named limit (v2 DEC-011) |
| A script written to a process's standard input after it starts (`communicate`, `stdin.write`); `input=` is read | named limit (v2 DEC-011) |
| Launchers outside the named set (`ctypes` or `cffi` calls into libc, `multiprocessing`, third-party process libraries) | named limit (v2 DEC-011) |
| `getattr(obj, name)` with a computed name on a runtime object that is not a launcher module | named limit (v2 DEC-011) |
| A module-level container changed from another module (`helpers.ARGV.append(x)`) is not seen in the module that binds it | named limit (v2 DEC-011) |
| A Google service read straight from the builder cache outside the builder methods | named limit (v2 DEC-011) |
| A shortcut name called on another module or object that this module does not bind (`helpers.info(argv)`, `obj.list(ARGV)`) is taken as the read-only builtin or conversion | named limit (v2 DEC-011) |
| A call matched by name to a function the module defines, even where the call site binds the name otherwise (a parameter or a local assignment); that function's parameters and returns are read instead | named limit (v2 DEC-011) |
| A rebound `zip` or `enumerate` in loop unpacking, even one the module defines itself: the unpacked names are read from its arguments. The other name-matched shortcuts (string methods, `.get`, `append`, `insert`, `extend`) also ignore what the receiver is, but their result is proved only when the receiver is itself a proved literal, so no gap is known there | named limit (v2 DEC-011) |
| A store on the `builtins` module (`builtins.list = f`, `setattr(builtins, "list", f)`) is not a binding the shortcuts check | named limit (v2 DEC-011) |

HTTP verb scanner:

| Limit | Status |
| --- | --- |
| Cross-module writes through `__dict__`, `vars(obj)` or `sys.modules` | named limit (v2 DEC-011) |
| A parameter annotation is trusted, so an argument that contradicts it is not seen | named limit (v2 DEC-011) |
| Send methods of clients the source does not use (such as an `httpx` `stream`), a verb chosen by `getattr` with a computed name, and `googleapiclient` request chains | named limit (v2 DEC-011) |

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

Control files, including manifests, summaries, validation and AI context,
have a 32 MiB limit (`MAX_RUN_FILE_BYTES`). The pseudonym key is read with an
exact 32-byte bound instead: any other size is `damaged`. Evidence and other data
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
change anything in a bundle they inspect; that includes the pseudonym key, which
only collection and `auditex report prepare-key` create. A process that is producing a run appends
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
names and role names remain. The redactor also masks e-mail local parts, the names of
every person in the run's directory records (see
[Person names](#person-names)), immutable IDs, credentials and run-directory
paths. Public baseline example addresses are kept. A pseudonym is keyed with the
run's private key (see [Pseudonym key](#pseudonym-key)). GUIDs become `Guid` plus a digest,
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

### Person names

Who is masked: every person in the run's directory records, not only privileged
users. A record is a directory person when its normalised kind is `user` or
`google_user`, its raw type is `#microsoft.graph.user` or `admin#directory#user`,
it is a privileged-user record, or it carries a principal address and a display
name (a user reference such as an audit-event initiator, which also finds people
seen only in events). A principal type that is not a user (service principal,
group, device and similar) is not a person.

Where: the shareable, customer-pack and explainer profiles, in every string the
redactor visits: values, values under controlled keys, group and role display
names (a group named after a person's full name is masked; a group or role name
equal to a person's name protects that name instead), JSON embedded in strings,
and mapping keys, except a whole key that is a structural identifier such as
`policy_id`. The local profile is unchanged. JSON, CSV, SARIF, OSCAL, MCP and
notification payloads keep their shape.

What is matched, case-insensitively and Unicode-folded, over whole words only:
the display name, given plus family name, the family name first, a
`Family, Given` name, the joined form (`alicesmith`, for two or three words),
the local part of an address when it has two or more words (`alice.smith`), and
the whole address read as words, which finds OneDrive-style segments
(`alice_smith_contoso_com`). Between words the matcher follows white space or
exactly one of `.` `_` `-` `'`. A possessive such as `Smith's` matches. At most six
words and 64 characters per word form a name. A person keeps at most 16 such
keys, required forms first; keys past 16 are reported, not dropped silently.
`Malice Smithers` and `alice_smithers` do not match `Alice Smith`. Matching is
one linear pass with a bounded window and at most six dictionary probes per
word, so its cost does not depend on the number of people.

Replacement forms: prose becomes `User <16 hex>`. An identifier keeps its shape
and becomes `user-<16 hex>` (for example `/personal/user-<hex>_contoso_com`).
In a directory-person record `displayName` and `fullName` become
`User <digest>` whole and `givenName`, `surname` and `familyName` become
`<redacted-text>`. The pass is idempotent: a pseudonym is never matched again.
Final markup passes over rendered HTML leave tags and character references
alone and skip single-word keys, so the renderers' own markup is never
rewritten; multi-word keys still apply.

Pseudonym scheme: the pseudonym is keyed (see [Pseudonym key](#pseudonym-key)), over
the person's canonical name in UTF-8 (the display name, else the address). It is
deterministic for a key, so the prose form equals the structured `displayName`
form. Two people with the same display name share a pseudonym. Multi-run contexts
(compare and drift) mask the names of every run with the first-listed run's key.

The unmatched note: a person whose names cannot all be followed safely is
counted, never named. When any such person exists, shareable HTML and Markdown
reports (and so a customer pack's Markdown report) end with one line,
`Name masking: N directory people have names that cannot be matched safely in
free text (reason count, ...); their name fields are pseudonymised, the same
words elsewhere are left as written.` People are counted once each (by object
id, else principal name), under the first applicable reason:

| Reason | Meaning |
|---|---|
| `too_short` | fewer than four letters and digits |
| `no_letters` | no letter at all (a numeric name must not rewrite numbers) |
| `too_many_tokens` | more than six words or a word over 64 characters |
| `vocabulary` | equal to product, role or group vocabulary found in the run, a pseudonym word, or a product field name (only the mapping key stays; see the limits below) |
| `common_word` | only common words such as `admin`, `support` or `meeting room` |
| `structural` | a structural code such as a policy id or snake-case name |
| `separator` | a separator the matcher does not follow (for example `/` or `+`); the spellings it does follow are still masked |
| `limit` | more than 16 keys for the person |

Limits, as implemented. A name left as written is not reported unless it is in
the table above.

- People who are not in the run's directory records and never appear as a user
  reference are not discovered.
- Only recorded spellings match. Nicknames, transliterations, dropped
  diacritics and a family name on its own are not masked. Spellings that differ
  only in Unicode form (composed or decomposed letters, combining marks of any
  script) match. A user record that carries only a given name and a family name
  is discovered and masked.
- Middle initials and titles are handled only in part. A recorded name also
  matches without its leading titles and without its middle initials, and in the
  text a middle initial between two parts of a name, and a capitalised run of the
  listed titles directly before a name, are masked with it. The listed titles are
  `Mr`, `Mrs`, `Ms`, `Miss`, `Mx`, `Dr`, `Prof`, `Professor`, `Sir`, `Dame`,
  `Lord`, `Lady`, `Rev` and `Revd`, with or without a full stop. A name with
  middle initials or a title that cannot be resolved inside the scan budget is
  withheld: the whole string becomes the text placeholder `<redacted-text>`, never
  left readable. These limits stand, and each name left as written is not reported unless the table above
  lists it:
  - a leading initial for the given name (`A. Smith`) and post-nominals (`Jr`,
    `PhD`);
  - titles outside the list: with `Capt. Jane Doe` recorded, a bare `Jane Doe`
    in text stays readable, and the unmatched note does not count it;
  - a title before a sentence stop is joined to the next name (`Contact the
    Lord. Jane Doe` gives `Contact the User <hex>`), and a capitalised `Miss`,
    `Rev` or `MS` used as an ordinary word before a name is absorbed (`We Miss
    Jane Doe`); a comma never joins a title to a name, and a lower-case `miss` is
    kept;
  - some records with a title or initial after the family name (`Smith, Dr.
    John`, `Smith, John A.`);
  - a name written with a zero-width space or a fullwidth full stop;
  - a name with several middle initials where the walk has taken them on another
    key's path is not left readable: with a recorded `John A. B. C. D. Jones`
    sign-in path, `John A. B. C. D. Smith` is withheld as `<redacted-text>`, or
    masked as one name when that full name is recorded.
- A name URL-encoded (`Alice%20Smith`), joined by `+` or `/`, or inside an HTML
  tag or attribute of already rendered text, is left as written.
- A mapping key that is a person written as an identifier (`priya_kovalenko`,
  `PriyaKovalenko`) is masked only when the whole key is that person's name
  (`user-<hex>` for the snake form, `User <hex>` for the camel form). A key whose
  plain form, after its titles and initials are stripped, is a person
  (`dr_priya_kovalenko`, `priya_x_kovalenko`) is withheld as `<redacted-text>`
  (`#n` is added on a collision and the value is kept). Other parts of a key
  (`priya_kovalenko_mailbox`) stay as written. A mapping key that is a product field name (a property in
  `schemas/`, a key in `configs/`, or an identifier-shaped literal written as a
  key or constant under `src/`, kept as `_D5_FIELD_NAMES` in
  `output_redaction.py`) is never renamed, whoever has that name: a person
  called `Break Glass` keeps the key `break_glass`, is counted as `vocabulary`,
  and is still masked in values and free text. A key that exists only in
  collected data and in no schema, config or source literal (a Graph property
  passed through), and a field name the generator misses (a key passed as a call
  keyword, for example in `google_workspace/normalize.py`), is not exempt, so a
  person with that name has the key renamed. A new product key under `src/`,
  `schemas/` or `configs/` fails the drift test until `_D5_FIELD_NAMES` is
  edited by hand; the failure lists the missing names.
- Stated limits of the merged matcher (DEC-044 stop rule: limits, not defects to
  fix here). Examples are invented.
  - Withholding reaches the whole string (a field, list item or key), and in the
    final pass over rendered output the whole file. The placeholder does not say
    why. This happens when a name start is followed by more initials than the
    six-word window resolves (`First A B C D E Last`).
  - With one user known only as `Neral` and another as `Neral Vosk Taren`,
    `Vosk Taren` stays readable in `Neral A B C D Vosk Taren`: the window ends on
    a non-initial.
  - A name whose last letter carries an extra combining mark the recorded
    spelling lacks (`Orin Pasḱ`) stays readable, and so does the accent-dropped
    form of a name recorded in decomposed form (`Zoe Vosk` for `Zoë Vosk`).
    Before this change the matcher masked that name when the mark was written
    as a separate character after the last letter, leaving the mark after the
    pseudonym.
  - A name with an invisible character inside it (zero-width joiner, soft hyphen,
    combining grapheme joiner, variation selector) or a combining mark after a
    space stays readable.
  - Mapping keys that stay readable: camel-joined with a title or initial
    (`DrNeralVosk`, `NeralAVosk`), suffixed (`neral_vosk_adm`), reversed
    (`vosk_neral`), with an edge initial (`a_neral_vosk`), with middle names as
    initials (`orin_t_m_pask`), over six tokens, or with a token over 64
    characters.
  - Parts-only records: the given and family fields are withheld, but `N. Vosk`
    and either part on its own stay readable, and parts with stray spaces or a
    different case take their own pseudonym.
- Scripts written without spaces (CJK) match only where spaces or punctuation
  delimit the name.
- Single-word local parts (`asmith`) are masked inside addresses and full-address
  forms only.
- Names counted in the note are not left out of free-text matching: only the
  spellings the index does not support can stay readable (for `separator` and
  `limit`, every other accepted spelling is still masked), and the name fields
  are pseudonymised.
- The note's fixed wording ("the same words elsewhere are left as written") is
  generic. For a person counted as `vocabulary` only the mapping key stays
  readable; the name is still masked in values and free text, as above.
- Over-masking: an ordinary word equal to a person's name and outside the
  common-word and vocabulary lists is masked too.
- Immutable-ID matching is unchanged and is one alternation over every
  discovered ID.
- The explainer context of an internal ScubaGear export has no run, so it uses a
  fresh random key for that one context and knows no run paths or undiscovered
  names.

Before sharing, identity discovery reads all `normalized/**/*.json` files. It
refuses malformed, unreadable or non-regular entries, symbolic and hard links, changes
during discovery and scans exceeding 5,000 files, 64 MiB per file, 256 MiB
in total per run or 32 directory levels. A subsequent snapshot also refuses scan
problems or changed fingerprints. These checks cover shareable reports, exports,
customer packs, notifications and MCP tools. A size-limit refusal reports the
supported sizes without naming files; other refusals identify the reason using
safe file labels. Repair the evidence before retrying.

The limits are on bytes scanned, not a resident-memory ceiling. Peak
resident memory of a shareable HTML render is measured by
`benchmarks/html_peak.py` against `benchmarks/html-peak-baseline.json`, which
fails above a ratio of 1.15 of the baseline and, with `--require-masked`, when a
workload name survives in the output. Run the harness for current figures
instead of relying on numbers quoted here. The harness measures the child
process's resident memory and compares it with the baseline times the ratio;
memory use also depends on the evidence and output.

On adversarial JSON, worst-case scanner memory is about 64 times the file size, up to about 4 GiB at the 64 MiB per-file cap. This is an upper bound that ordinary evidence does not reach.

These are pattern and structure rules, not a guarantee that every personal
value in arbitrary prose is recognised. URL userinfo passwords are matched
for schemes of 1 to 32 characters and scheme-relative URLs. Known immutable
IDs are matched in narrative only at word-character boundaries and when at
least four characters long; a structured immutable-ID field is redacted even
when shorter. Person-name matching follows [Person names](#person-names), which lists its limits.

### Pseudonym key

Every pseudonym is the first 16 lower-case hex digits of HMAC-SHA256 under a 32-byte
key, keeping its prefix (`User `, `Id `, `Guid `, `user-`); the strategy label is
`keyed-hmac-sha256-v1`. The 1.4.0 label `run-salted-sha256-v1` still validates in an
older `model_assessment.json`; writers emit only the new one. There is no salt and
no unkeyed pseudonym. Pseudonyms of 1.4.0 and earlier came from the run path and do
not match those of 1.5.0; they stay confirmable by a holder who knows the path.

Key sources:

- Run key: collection creates `operator-inputs/pseudonym.key` when it seals a run
  (`secrets.token_bytes(32)`, exactly 32 raw bytes, the file `0600` in an
  `operator-inputs/` folder of `0700`, beside `operator-inputs/.gitignore` holding
  `*`). `bundle-hashes.json` names it under `excluded` by path and reason only. It is
  never in a report, preview, customer pack, export, notification, MCP output, log or
  error message, and a customer pack never copies `operator-inputs/`. Auditex never
  removes, shortens or replaces a published key, and never changes the modes of an
  existing one. The guard refuses the key as an ordinary input by name, case alias,
  link, standard input or output destination.
- Modes: a key or its folder with any group or other bit is refused (`permissions`),
  and a key of any size but 32 bytes is refused (`damaged`). Either refusal stops
  every derivation of that run, local reports with policy explanations included,
  until the operator restores or restricts it (`0600`, `0700`) or removes it;
  removing it starts a new pseudonym series. The refusal message is fixed and names
  neither a path nor key bytes.
- Memory key per context: output with no run (no run folder in the call, the
  explainer context of an internal ScubaGear export) uses a fresh random key for
  that one context. Names are consistent within the output and cannot be recomputed.
- Session (temporary) key for a keyless run: a keyless run is one made by 1.4.0 or
  earlier, one copied without `operator-inputs/`, or one sealed on storage without
  locking. Reads never write into it. It is masked with a random key held in memory,
  one per run (folder and the manifest's `run_id`) per process, so the files of one
  customer pack and the calls of one MCP server session agree. That holds only when
  the manifest's `run_id` is usable: when it is missing, null, not a string or empty,
  the key lives for the current context only and no other run or call shares it. Output made with it
  says so in a fixed line, and its pseudonyms are not stable across sessions: another
  command or a restarted server gives different ones. `auditex report prepare-key
  RUN_DIR` creates the key once (it prints `created`, or `present`), after which the
  pseudonyms are stable. The command is not offered over MCP, and a context keeps the
  first key it resolved for each run.
- Export-derived key: an internal ScubaGear export has no run folder, so
  `redaction_key` derives its key in memory from the whole export (SHA-256 over a
  purpose string, the privileged entries, their object IDs and a digest of the whole
  parsed export); it orders the numbered users with the same function and is never
  written. Only a holder of the whole export, who already holds every name, can
  derive it.
- Several runs (compare, drift, diff) mask every run's names with the first-listed
  run's key, so a person lines up with their pseudonym in that run's own reports;
  the other order uses the other key. `project_run` reads the run's key (or the
  temporary key) only when redaction is on, and never creates one.

Boundary: the key protects people who hold outputs, not people who can run Auditex
against the run folder. Anyone who can call a tool on the run can obtain the
run-key pseudonym of a name of their choosing: `auditex_compare_external_assessments`
with `run_dir` masks names from a file the caller supplies with that run's key, and
`auditex_diff_runs` and `auditex_compare_runs` mask a second run's names with the
first run's key (an MCP client can build such a run with
`auditex_run_offline_validation`). That caller can already read the run's evidence
through the same host. This is pseudonymisation, not anonymisation, and one key
protects a name only as long as the key is private.

Limits of key creation:

- Storage without locking never gets a key. Every lock error except would-block,
  try-again and interrupted counts as no locking, raised before anything is written
  (Linux network storage answers this way). Collection seals such a run keyless and
  logs `pseudonym_key.unavailable` with reason `nolock` in `audit-log.jsonl`;
  `prepare-key` refuses there until the run is copied to local storage; a keyless
  run renders with a temporary key meanwhile.
- Locks between machines on network storage depend on the server's lock service.
  Two machines creating a key in one keyless run at the same moment, on storage
  whose locks do not span hosts, could both publish, and the output of the first
  would not match.
- Durability: the run folder is flushed after `operator-inputs/` is created and
  `operator-inputs/` after the key is published, where the storage supports it.
  Where a folder cannot be flushed (storage that cannot flush a folder, a flush that
  fails after the key was published, the moment between publication and the flush,
  and macOS, where a flush does not empty the disk's own cache), a power loss soon
  after creation can lose the key's folder entry. Output made before the loss then
  does not match the key created next.
- Output made with a temporary key is not stable across sessions until
  `auditex report prepare-key RUN_DIR` is run.
- A 1.4.0 reader of a 1.5.0 run ignores the key and masks with its own run-path
  salt, and it rejects the 1.5.0 `model_assessment.json`, so its render of that run
  loses the policy explanations.

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
OnPremisesImmutableId with the run's pseudonym key (or the temporary key of a
keyless run). Internal rule views, detail, labels,
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
the run's pseudonym key (a temporary key for a keyless run), paths and discovered identities; incomplete discovery or any
rendering or redaction exception suppresses the explanation without changing
the verdict. Logs contain only the policy id and exception class. An internal
ScubaGear export has no run context, so its explainer uses an empty context
with a fresh random key: its pseudonyms are not stable across assessments, and run
paths and undiscovered names are not known to that context. The same profile still masks recognised identifiers and secrets.

Reports guard and validate the assessment before reading explanations and apply
the explainer profile again, including for local reports, so modified
assessment text does not bypass that boundary. If the context or assessment is
unusable, explanations are omitted. The support address in the fixed fault
step currently has its local part masked by this profile.
It has no inference dependency, endpoint or model fallback. Reintroducing any model use would need
explicit authorisation, the same input and output boundary and no redaction opt-out.

Explainer test material follows the public-repository fixture rule: stored fixtures hold only constructed rows and
model-pack train and validation rows, each with a vector id and an origin; held-out test rows (pack or pilot), sealed
pilot rows, diagnostic rows, machine paths and files over 1 MB are refused by `tests/test_explainer_fixtures.py`, and the
expanded test set, pairs and mutants are generated in memory from the allowed fixtures rather than stored.
