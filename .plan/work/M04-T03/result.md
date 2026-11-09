## RESULT M04-T03
status: done
summary: No repository change. The doc was approved at 4329812. The DoD read-through is written below as one line per DEC-011 limit. Every test name was checked against `grep -n "def test_"`. `tests/test_docs_paths.py` passes.
changes: none
verification: `PYTHONPATH="$PWD/src" .venv/bin/python -m pytest tests/test_docs_paths.py` passed; `git status --short` is empty.
risks: none
questions_for_g: none

### Findings
- HTTP-1, opener passed as an untyped parameter: closed by `test_an_opener_passed_as_an_untyped_parameter_fails` and `test_a_type_parameter_or_alias_leaves_the_receiver_unresolved`. A trusted annotation that an argument contradicts remains, stated at `docs/reference/security-privacy.md:244`.
- HTTP-2, opener held in a container: closed by `test_an_opener_held_in_a_container_fails` and `test_a_binding_the_scan_cannot_prove_leaves_the_receiver_unresolved`. Cross-module writes via `__dict__`, `vars` or `sys.modules` remain, stated at `docs/reference/security-privacy.md:243`.
- L1, non-subprocess launchers: closed by `test_launches_outside_plain_subprocess_calls_are_found`, `test_non_subprocess_launch_with_unseen_input_is_reported` and `test_untraceable_launch_forms_are_reported`. Launchers outside the named set (`ctypes`, `cffi`, `multiprocessing`, third-party) remain, stated at `docs/reference/security-privacy.md:233`.
- L2, dynamic callee lookup: closed by `test_launchers_reached_through_dynamic_access_are_reported` and `test_launches_through_unpacking_rebinding_and_lookups_are_judged`. `getattr` with a computed name on a non-launcher runtime object remains, stated at `docs/reference/security-privacy.md:234`.
- L3, requests held in containers or fetched through getattr: closed by `test_google_calls_held_or_fetched_indirectly_fail_closed` and `test_a_request_value_the_scan_cannot_prove_is_not_get`. A service read straight from the builder cache (`docs/reference/security-privacy.md:236`) and a verb chosen by `getattr` with a computed name (`:245`) remain.
- L4, reliance on per-module handle naming: closed by `test_google_handles_are_classified_per_scope`, `test_google_handles_resolve_through_nested_scopes`, `test_google_handles_outside_their_function_scope_fail_closed` and `test_a_google_handle_declared_global_is_a_module_handle`. The cross-module container change remains, stated at `docs/reference/security-privacy.md:235`.
- Every one of the six DEC-011 limits is either closed by an existing named test or has its remainder stated and bounded in the scanner limits section.
