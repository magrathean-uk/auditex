# exchange-reader

Focused delegated audit for Exchange Online configuration and mail flow evidence.

- Role hints in the runtime: Exchange Reader, Global Reader
- Default collectors: `exchange`, `exchange_policy`, `security`, `identity`.
- Audit planes: inventory, full, export.

These are profile defaults from `src/azure_tenant_audit/profiles.py`, not a guarantee of tenant visibility. Explicit collector selections, presets, exclusions, installed adapters, licenses, and permissions affect the run. Generate `auditex setup-guide m365 --auditor-profile exchange-reader --format md`, then probe the selected surface before collection.

Review the generated permission plan rather than granting every profile hint. Some hints carry write capability even though audit calls are read-only. Never use an audit profile as authorization for tenant changes. See the [administrator permission guide](../docs/ADMIN_PERMISSION_GUIDE.md).
