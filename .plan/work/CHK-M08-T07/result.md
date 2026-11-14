## RESULT CHK-M08-T07
status: done
summary:
check: pass
checked: 64b3172dd4d585e2f4d587020020ee36a4f5fc08
Verify exit 0 (179 tests passed, `make lint` clean, `make contract-smoke` ok). All 21 negative cases failed as they must.
changes: none
verification:
- Verify command as written in the acceptance block: exit 0, pass
- Second interactive sign-in after the cache stops serving Graph (`src/azure_tenant_audit/graph.py`): exit 0, pass. It raised `GraphError` and the sign-in count stayed 1.
- Delegated Exchange token before any sign-in: exit 0, pass. It returned None with no prompt.
- Delegated Exchange token when silent refresh is refused: exit 0, pass. It returned None, no second prompt.
- Delegated Exchange token when silent refresh raises: exit 0, pass. It returned None.
- Graph silent refresh raises: exit 0, pass. `GraphError("Silent token refresh failed.")` carried none of the message text, and no second prompt opened.
- `delegated_token_for` in static-access-token mode: exit 0, pass. It returned None.
- `delegated_token_for` in app mode: exit 0, pass. It returned None.
- `_session_prelude` with a UPN containing `'; Remove-Mailbox`: exit 0, pass. No connect, empty environment.
- `_session_prelude` with no token: exit 0, pass. No connect.
- `_session_prelude` with a bad organisation: exit 0, pass. No connect.
- `_session_prelude` with no organisation and no UPN: exit 0, pass. No connect.
- `_session_prelude` with a non-Exchange session kind: exit 0, pass. No connect.
- `_exchange_session` with no delegated token: exit 0, pass. `{"kind": "none"}`.
- `_exchange_session` with a token but no signed-in user: exit 0, pass. `{"kind": "none"}`.
- Static `Connect-*` without `-AccessToken` checker on a planted string: exit 0, pass. Both planted lines flagged.
- Static `az login` checker on planted code: exit 0, pass. Both planted functions flagged.
- Shipped static tests against a copy of `src` with a planted `az login` and `Connect-ExchangeOnline` without a token: exit 0, pass. Both tests failed.
- Guided delegated run with no sign-in app id and no Azure CLI sign-in (`src/auditex/guided.py`): exit 0, pass. rc 2, no run started.
- Guided delegated `--include-exchange` with no sign-in app id: exit 0, pass. rc 2, no run started.
- `_delegated_exchange_selection("identity, exchange ,exchange,identity")`: exit 0, pass. It returned `identity,exchange_policy`.
risks: none. Evidence is in `.plan/work/CHK-M08-T07/evidence.md`.
questions_for_g: none

### Findings
- Second prompt refused: msal fake whose cache stops serving Graph, expected `GraphError` with 1 interactive call, actual the same.
- Exchange token before sign-in, refused silently, or raising: expected None with no new prompt, actual the same for all three.
- Graph silent refresh raising: expected a generic `GraphError` and no second prompt, actual the same.
- Static-token and app modes: expected `delegated_token_for` to return None, actual the same.
- `_session_prelude` bad UPN, no token, bad organisation, neither organisation nor UPN, wrong kind: expected an empty prelude and no token in the environment, actual the same for all five.
- `_exchange_session` with no token, or a token without a user: expected `{"kind": "none"}`, actual the same.
- Static checkers: expected the planted `Connect-*` and `az login` sites flagged, and both shipped tests to fail on a planted `src` copy, actual the same.
- Guided no sign-in and Exchange without an app id: expected rc 2 and no run, actual the same.
- Explicit collector list containing `exchange`: expected it swapped for `exchange_policy` with no duplicates, actual `identity,exchange_policy`.
