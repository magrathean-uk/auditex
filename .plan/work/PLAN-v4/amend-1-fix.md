# Plan v4 amendment 1, repair of the check's three defects

The check of amendment 1 (changes-required at 8749be5) is at .plan/work/REV-PLAN-v4/result-3.md. Fix exactly its three defects and nothing else. As before, do not edit .plan/STATE.md or .plan/DECISIONS.md, and do not run percent.py with --write.

1. M04-T03 files line: remove the conditional mcp_server.py allowance (the approved design's section 12 leaves that file unchanged); MCP notices travel through redact_payload.
2. M00-T06 files line: let src/auditex/cli.py carry the dispatch, validation and forwarding edits the Google offline run needs for the as-of date, not only parser edits.
3. M00-T06 verify and the new M00 DoD item: a predicate that accepts a date computed at run time defeats the point. Require one shared literal date on the actual offline invocations of the contract smoke, and probe the predicate with a computed date (must fail) and a literal one (must pass).
