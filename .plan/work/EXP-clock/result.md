## RESULT EXP-clock
status: done
summary: Lifecycle and stale-sync findings take the date from `now`/`as_of`, falling back to the wall clock (`findings.py:3348`, `normalize.py:1613`); the `azure_tenant_audit` CLI never passes `as_of` (`cli.py:1175`).
summary: Smallest fix: a `--as-of` flag passed into `run_offline`, used on every offline smoke call in the Makefile, digests re-recorded once. The demo already pins its date this way (`demo.py:430`).
summary: Which of the 8 digested runs depend on the date, and the Google run, are unconfirmed because I ran no builds.
changes: none
verification: rg and sed reads only; did not run make contract-smoke or tests
risks: Google run (`auditex google run`) is outside `azure_tenant_audit`, so a flag there is a separate change; other wall-clock reads in `findings.py` and `waivers.py` are not covered by `as_of`
questions_for_g: none
