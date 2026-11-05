# AAD and SharePoint projection vectors

Synthetic configuration data only; auditex-data-not-confidential. Rows derive from CC0 1.0 ScubaGear fixtures or are constructed. Evidence values are not relabelled. Only rows with reversible raw contracts are included; malformed containers, unavailable markers, non-singletons, missing join ids, inconsistent fan-outs and unsafe synthetic naming are excluded. Up to six vectors per policy and rule cell, after origin filtering.

Fixture meta: **constructed rows and pack train and validation rows from v3.9.1; held-out test and pilot rows excluded**. Every row records its vector_id, origin, source_kind, source_file and split.

Source manifest: `vectors-manifest.json` from the model stream's `value-rules-v391` directory (v3.9.1). This manifest does not list a hash for the final vectors.jsonl; both the manifest and the actual vector bytes are hashed below.

```json
{
  "by_policy": {
    "MS.AAD.1.1v1": 22,
    "MS.AAD.2.1v1": 20,
    "MS.AAD.2.3v1": 20,
    "MS.AAD.3.1v1": 18,
    "MS.AAD.3.2v2": 20,
    "MS.AAD.3.3v2": 1,
    "MS.AAD.3.4v1": 6,
    "MS.AAD.3.5v2": 1,
    "MS.AAD.3.6v1": 18,
    "MS.AAD.3.7v1": 23,
    "MS.AAD.3.8v1": 23,
    "MS.AAD.3.9v1": 24,
    "MS.AAD.5.2v1": 37,
    "MS.AAD.5.3v1": 26,
    "MS.AAD.5.5v1": 23,
    "MS.AAD.5.6v1": 36,
    "MS.AAD.5.7v1": 24,
    "MS.AAD.6.1v1": 1,
    "MS.AAD.9.1v1": 63,
    "MS.SHAREPOINT.1.1v1": 12,
    "MS.SHAREPOINT.1.2v1": 14,
    "MS.SHAREPOINT.1.3v1": 23,
    "MS.SHAREPOINT.2.1v1": 22,
    "MS.SHAREPOINT.2.2v1": 22,
    "MS.SHAREPOINT.3.1v1": 26,
    "MS.SHAREPOINT.3.2v1": 31,
    "MS.SHAREPOINT.3.3v2": 32
  },
  "by_source_kind": {
    "constructed": 344,
    "pack-train": 190,
    "pack-validation": 54
  },
  "fixture_sha256": "fcaa5d941df1f97e78206df5e74078b34da7ad1dbd06ce231e4190814933db2b",
  "manifest_sha256": "6acfe2a82e45b7f50c295559b47496e09bf0d911b3a46b1b87c6a29696a0d7fd",
  "rejected": {
    "domain names or ids outside synthetic raw contract": 122,
    "not round-trippable": 522,
    "synthetic naming filter": 520
  },
  "rows": 588,
  "selection": "constructed rows and pack train and validation rows from v3.9.1; held-out test and pilot rows excluded",
  "source": "the v3.9.1 vectors.jsonl from the model stream's value-rules-v391 directory",
  "source_sha256": "3515b6facbac73091ef43bfa51b746e9265ac508909103ffcc016a5dab92cf4e"
}
```

Stage B CA rows retain populated restrictions. SharePoint rows round-trip the fields a Graph-only payload can carry. No held-out, pilot or sealed AAD v2.1 freeze row is included. The selection script lives in session scratch and is not shipped.

Pack-only fields dropped by section are listed in PACK_ONLY_DROPPED in tests/test_scuba_adapters_aad.py. D2: Users.IncludeGroups, IncludeGuestsOrExternalUsers, SessionControls, CustomAuthenticationFactors and TermsOfUse are deliberately dropped. The v3.9.1 reference and pinned AAD Rego do not read them. AAD 3.3v2 reads Authenticator context only (D94); it no longer reads Conditional Access. v3.9.1 adds no new field names over v3.9, but treats unreadable AuthenticationStrength under OR and non-object AuthenticationFlows as unknown.

Integration limitation: the approved PD-1 hook retries incomplete_shape only. A missing normalised SharePoint artifact still reports missing_artifact and does not trigger a retry; the raw variant itself needs no normalised artifact. The universal SP invariant also excludes legacy success through normalised-only capability synthesis: the variant requires a raw SharingCapability and never invents ODBSharingCapability.

Legacy policy-only bundles preserve authentication_method_policy and omit the unknown authentication_method_feature_settings key, rather than inventing an empty configurations inventory. Populated unknown location/platform leaves stay withheld because the v3.9.1 rule reads them as restrictions. Domain rows with ids outside .invalid are excluded without relabelling, so the selected domain vector is the empty-inventory case; hand-built cases cover populated domains, null and missing validity. No live collector or playground execution was used.
