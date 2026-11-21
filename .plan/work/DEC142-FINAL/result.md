## RESULT DEC142-FINAL
status: done
summary: Final read-only app-only certificate collection m08e4 on main d1abee4 (1.8.0 code), 21 Nov 2026. The 1.8.0 live path works on the lab tenant: certificate-only sign-in for Graph, Power BI, Power Platform, Exchange and Security & Compliance; every collector that was ok in m08e3 is ok, except power_platform, whose management-app registration was removed on 15 Nov after m08e3 (tenant cause). AAD 7.5 moved from met to not met as DEC-096 predicted.
verification: comparison worker DEC142-COMPARE (claude-3 Sonnet) over model_assessment, manifest, summary, blockers and debug log of both runs; run and comparison kept in the records folder (phaseE/runs/dummy-tenant-m08e4, jobs/dec142-compare-20261121T124307Z).
risks: kit compare not rerun (kit-7s compare.py refuses schema 2026-11-05); the 8 Power Platform rows were not re-scored live.
### Findings
run-mode: app-only certificate
live-path: works
rows-changed: 9 of 64 (AAD 7.5 intended; 8 Power Platform rows to not assessed, tenant cause)
aad-7-5: m08e3 met, m08e4 not met
gaps: m08e3 4, m08e4 5 (new: defender alerts service not provisioned on the trial; secure score now collected)
regressions: 0
