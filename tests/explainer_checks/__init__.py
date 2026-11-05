"""Hard-check suite for the explainer (plan section 3): checkers S, a, b, c, d, e, e2, e3, a driver and shared helpers.

Pure Python standard library; no model, no network, no randomness. Each checker is a function
    check_X(ctx, out) -> {"pass": bool, "klass": "exact"|"heuristic", "failures": [ {code, klass, text, detail} ], "notes": [...]}
where ctx is explchk.context.Context (built from one prompt record) and out is explchk.chk_s.Output (the parsed candidate).
"""
CHECKS = ("S", "a", "b", "c", "d", "e", "e2", "e3")
