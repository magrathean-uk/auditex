## Change

Describe the operator problem and the resulting behavior.

## Validation

List the checks run, their results, and any skipped check with a reason.
For bundle, collector, report, schema, evidence-reference, or customer-pack changes, include `make contract-smoke`.

## Review

- [ ] Audit and probe operations keep the production tenant read-only boundary.
- [ ] No mail body or file content collection was added to audit mode.
- [ ] No credentials, local auth files, or tenant evidence are included.
- [ ] Related command, permission, artifact, and operator documentation is current.
- [ ] Third-party code and data retain their license and attribution.
