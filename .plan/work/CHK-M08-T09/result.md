## RESULT CHK-M08-T09
status: done
summary:
check: pass
checked: 9bda88058e39f94c3237f5bc1c32b125274afeea
Verify exited 0: 175 tests passed, `make lint` clean, `make contract-smoke` clean. All 36 negative cases failed as they must; none was accepted.
changes: none
verification:
- `.venv/bin/python -m pytest tests/test_graph_batch_retry.py tests/test_graph.py tests/test_graph_read_only.py tests/test_graph_streaming.py tests/test_privileged_roles.py && make lint && make contract-smoke` - exit 0, pass
- `.venv/bin/python -I $TMPDIR/chk/neg.py` (scratch script, faked sessions and clock, no network) - exit 0, every case failed as it must, pass
risks:
- `.venv` was linked from the main checkout for the run and removed afterwards; `git status --porcelain` is empty, so the verify changed no tracked path.
- The negative cases use fakes, as the task's tests do; no live Graph throttling was exercised.
questions_for_g: none
### Findings
- Attempt bound: always-429 item with `Retry-After: 1`. Expected a gap after the bound; got 4 POSTs (`rate_limit_retries`+1), status 429, `retry_exhausted` set, `graph.batch.retry_exhausted` emitted. Held.
- Wait bound: `Retry-After: 9999`. Expected no sleep; got waits `[]`, one POST, `retry_exhausted`. Held.
- No retry of other 4xx: statuses 400, 401, 403, 404, 408 and 409 each got one POST, no wait and no `retry_exhausted`. Held.
- 503 bound: always-503 item stopped at `server_error_retries`+1 (3 POSTs) with `retry_exhausted`. Held.
- GET-only batch: POST, DELETE and PATCH items were refused with `GraphError` before any send. Held.
- Missing path: an empty or absent path was refused with `GraphError`. Held.
- Bad `Retry-After` values (`nan`, `inf`, `-inf`, an HTTP date, empty, `-5`): each fell back to the policy back-off (1.5s), never a non-finite or negative wait. Held.
- Failed re-send: the settled 200 stayed, the pending item got `retry_exhausted` and "Retry request failed: boom", and `graph.batch.retry_failed` was emitted. Held.
- Failure on the first send: raised to the caller, no partial result. Held.
- Top-level 400 on the `$batch` POST: raised `GraphError` with status 400, one POST, no retry. Held.
- Transport `Retry-After: 500` on a re-send: not slept (total wait stayed within the safe policy's bound), item left as a gap, `graph.request.retry_budget_exhausted` emitted. Held.
- Read-only guard: `_request` refused DELETE, PATCH, PUT and POST to a non-`$batch` URL. Held.
- Endpoint reader pacing: `batch_size=5` over 12 endpoints made calls of 5, 5 and 2; exhausted 429 items read as failed, not OK, with no fallback re-read. Held.
- `batch_size` of 0 or -3: one call of 12, nothing dropped. Held.
- Chunking: 45 items with a 429 on the first send went as chunks of 20, 20 and 5, then re-sends of 20, 20 and 5; every item ended 200 and order was kept. Held.
