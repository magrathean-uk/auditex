"""Eight independent hard checks, using only explicitly supplied resources."""

from . import CHECKS
from .chk_a import check_a
from .chk_b import check_b
from .chk_c import check_c
from .chk_d import check_d
from .chk_e import check_e
from .chk_e2 import check_e2
from .chk_e3 import check_e3
from .chk_s import Output, check_s

FUNCS = {"S": check_s, "a": check_a, "b": check_b, "c": check_c,
         "d": check_d, "e": check_e, "e2": check_e2, "e3": check_e3}


def run_pair(pair, resources, *, canary=None):
    """Return {check: Result}; invalid raw JSON fails S and explicitly skips others.

    Resources may never be inferred from a workstation, network or runtime.
    Raw output_text takes precedence when both candidate forms are supplied.
    """
    ctx = resources.context_for(pair)
    out = Output(text=pair.get("output_text"), obj=pair.get("output"))
    results = {}
    for check in CHECKS:
        if check != "S" and not out.ok:
            results[check] = {"pass": None, "klass": None, "failures": [],
                              "notes": ["skipped: candidate is not strict JSON"]}
        elif check == "d":
            results[check] = check_d(ctx, out, canary if canary is not None else pair.get("canary"))
        else:
            results[check] = FUNCS[check](ctx, out)
    return results


def failing(results):
    return sorted(check for check, result in results.items() if result["pass"] is False)
