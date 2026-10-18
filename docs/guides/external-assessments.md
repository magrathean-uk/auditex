# Compare Microsoft assessment tools

Auditex can normalize existing Maester, CISA ScubaGear and Monkey365 JSON
reports for offline review. This workflow reads local files. It does not run
the external tools, authenticate to a tenant, execute report content, or call
an inference provider.

## Import reports

Use the tools' structured JSON exports, rather than HTML, Excel or screenshots.
Keep the original reports beside the review material: normalized checks refer
to their original JSON pointers and SHA-256 hashes.

```sh
auditex assessment sources
auditex assessment import --source maester --input /path/to/maester.json --output outputs/review/maester.json
auditex assessment import --source scubagear --input /path/to/ScubaResults.json --output outputs/review/scuba.json
auditex assessment import --source monkey365 --input /path/to/monkey365.json --tenant-id 11111111-1111-4111-8111-111111111111 --output outputs/review/monkey.json
```

`--tenant-id` binds an export that omits tenant metadata to an operator-supplied
identity. It cannot override a conflicting identity in the report. Display
names are not tenant identities. The normalized report records whether its
identity came from the source or the operator; an unbound report cannot be
compared.

For an offline rehearsal, use the three fictional exports in
`examples/sample_audit_bundle/external_maester.json`,
`external_scubagear.json` and `external_monkey365.json`. They use tenant ID
`11111111-1111-4111-8111-111111111111` and each includes a pass, a fail and an
unknown result. Use those paths as `--input` in the commands above. Their
unmapped controls intentionally demonstrate comparison limitations.

Output files must be new and outside finalized Auditex run directories.
Omit `--output` to print JSON. Treat both original and normalized reports as
customer-sensitive local evidence. Normalization selects assessment fields;
it is not a general-purpose anonymizer.

## Review agreements and gaps

```sh
auditex assessment compare --assessment outputs/review/maester.json --assessment outputs/review/scuba.json --tenant-id 11111111-1111-4111-8111-111111111111
auditex assessment compare --assessment outputs/review/scuba.json --run-dir outputs/customer-run
```

Only exact control identifiers are compared. Different control versions,
untagged checks, unavailable workloads, errors and unknown results remain
visible as limitations. The comparison requires matching tenant identities.
An optional Auditex run must be finalized and valid. Existing bundles are
never changed by import or comparison.

ScubaGear's versioned policy IDs can match Auditex's CISA baseline rows.
Maester's unversioned CISA test IDs remain distinct, and Monkey365's OCSF
JSON does not contain a benchmark control mapping. Those checks are available
for manual review; this release does not invent a crosswalk between them.

Agreement is corroboration, not independent proof of correctness. Collection
times, scopes, licences and object populations can differ. Investigate a
disagreement using the original source records before accepting either answer.
Imported conclusions do not become Auditex's native findings or training gold.

The read-only MCP tools `auditex_normalize_external_assessment` and
`auditex_compare_external_assessments` expose the same review functions in
memory. They do not persist imports or comparisons.

## Reference versions and maintenance

`configs/assessment-sources.json` records the inspected repository revisions,
selected paths and integration roles. Source checkouts are development
references, not runtime dependencies. The product never downloads or imports
their Python, PowerShell or Go code when processing a report.

Maester and ScubaGear supply independent assessment comparators; Monkey365
supplies another structured findings format. EntraExporter informs coverage
review, Cartography informs graph semantics and fixtures, and Prowler/CIPP
inform typed review interfaces. The two Entra AI prototypes inform evidence
selection and the separation of conclusions from collection gaps.

Microsoft365DSC compatibility must be checked separately. Its October 2026
major release changes resource implementation, property names and runtime
requirements. A module being installed does not establish that an export
command is compatible. The Auditex adapter reports runtime/module readiness
before export execution.

## Empty-tenant pilot

Start with the tenant's empty baseline and existing licences. Review the
separate `tenant-bootstrap/` helpers before introducing a small collection of
fictional identities, groups, applications and policy scenarios. Seeding is a
lab operation; it is separate from Auditex's collection and review commands.

Capture baseline/change/reset snapshots and compare overlapping controls with
the external tools. Include report-only versus enabled policies, eligible
versus active roles, expired credentials, permission-blocked collection and
unknown authentication evidence. Independently reviewed expectations, rather
than an external tool's unreviewed output, define evaluation answers.
