# intune-reader

Focused delegated audit for Intune devices, compliance, and configuration.

- Role hints in the runtime: Intune Reader, Global Reader
- Default collectors: `intune`, `intune_depth`.
- Audit planes: inventory, full.

These are profile defaults from `src/azure_tenant_audit/profiles.py`, not a guarantee of tenant visibility. Explicit collector selections, presets, exclusions, installed adapters, licenses, and permissions affect the run. Generate `auditex setup-guide m365 --auditor-profile intune-reader --format md`, then probe the selected surface before collection.

Review the generated permission plan rather than granting every profile hint. Some hints carry write capability even though audit calls are read-only. Never use an audit profile as authorization for tenant changes. See the [administrator permission guide](../docs/guides/admin-permission-guide.md).
