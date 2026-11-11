## RESULT ASSESS-v4
status: done
summary: All 11 slice results were read (INV4-bases, d5, delta, explainer, hygiene, kit-chains, kit-data, scanners, trainer, PASS-model, PASS-airr); all had status done. The merged assessment is 105 lines with the nine sections in order. 13 claims were spot-checked and all held; two wording corrections are applied in the body.
changes: .plan/work/assessment-v4.md
verification: wc -l assessment-v4.md gives 105 (pass, limit 150); a section-header grep shows the nine sections in order (pass); 13 spot-checks by rg, targeted sed and a read-only python3 -I count (pass; no builds or tests run); read the 11 slice result.md files (pass)
risks: 1) Web-sourced AIRR and base-model claims are undated and single-source, and Isambard compute-node internet and aarch64 PEFT/bitsandbytes support are unknown. 2) No slice ran lint or tests, so "works" rests on reads and counts. 3) The twin-count figures disagree (137 versus 318, and 298 twin-free) and are unreconciled.
questions_for_g: Should `_is_privileged_user` be deleted and `AGENTS.md:59` corrected, given `make lint` also runs ruff? Should model retraining get a defined role and acceptance bar before GPU time, and should it live outside the product repo? Should `clean-development doctor` be authorised for diagnosis only?
### Findings
Five facts a plan must respect:
1. 1.4.0 has no model layer. The model layer was removed in c97539d (67 deleted paths since v1.3.0), the kit's `train_lora.py` shims import the removed `auditex.model_training`, and a retrain needs a v1.3.0 pin or a standalone trainer.
2. Rules answer all 102 policies and a template explainer covers them (1,084 cells, reports only, no MCP tool). The model was parked on 5 Nov, so a retrain role must be set first.
3. BACKLOG premises are stale: the 14 `.gz` explainer fixtures exist, the 31,800 ruff figure is now 899, and the contract test skips on an env-name mismatch (`_V391`).
4. The test-v7 held-out set is twinned with train (137 by the project's count, 318 by a luna heuristic, 39 percent one policy). No test-v8 exists, so any new score needs a new held-out set.
5. Isambard-AI is aarch64 GH200 with 24 h `workq`, a 32-GPU cap and Apptainer. Compute-node internet, package pins and egress are unknown, and the kit's chains need porting off the former cluster's site-specific parts.
Corrections applied: 2 (the `make lint` description now includes compileall, and the `.venv` absence is scoped to the slice worktree; the main checkout has one).
Open questions: the 7 unreferenced baseline keys; customer-pack use of `policy_explanations`; the Google Workspace value-rule path; whether the D5 suite and `make lint` pass at HEAD; the 37 versus 38 DEC-005 removal list; the DEC-011 ID collision.
