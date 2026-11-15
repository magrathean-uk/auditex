## RESULT ASTRA-trackB
status: done
summary: The evidence argues against further training for the two existing jobs. A bounded tenant-prioritisation pilot is the strongest remaining opportunity, with a separate evaluation of usefulness.
changes: none
verification: none; assessment uses the supplied facts and existing knowledge, with no system access
risks: Judge preference may mismeasure usefulness; tenant plans introduce recommendation errors beyond factual checks; pilot cost and benefit remain uncertain
questions_for_g: none
### Findings
1. Could another training approach change the outcome?
Possibly, but there is no demonstrated target worth distilling yet. Convergence on teacher outputs that themselves lose to the template makes target quality the immediate bottleneck. More epochs or more examples of the same kind will not resolve it.
Domain-adaptive pre-training could improve domain knowledge, but these jobs already supply the relevant values and verdicts. It does not directly teach useful explanation or ordering. Retrieval helps when evidence is missing; it has little reason to beat a baseline already given the gold references.
DPO needs reliable, substantively better positive examples. Using this judge's sparse wins risks teaching stylistic preferences or exploiting its weaknesses. A bigger writer is not ruled out: attempt 4 improved results, but remained far below the bar despite extra sampling.
Keeping the first passing candidate tests a particular selection method, not the writer's maximum capability. Better selection might help, but the observed gap does not justify another training campaign. Require a writer to demonstrate useful improvement on untouched data before training a student.

2. Is the comparison or bar part of the problem?
Yes. A strong template is the right comparator for these jobs, but both-order wins measure stable judge preference, which is not necessarily operator benefit. Requiring consistency reduces order bias while turning some genuine but modest improvements into ties. The calibration establishes defect sensitivity more convincingly than usefulness sensitivity.
The denominator matters: 38 wins produces 0.571 when scored across all 267 rows, not just the 190 headroom rows. With everything else worth half, preference equals 0.5 + 0.5 × wins/N. The stated requirement of about 139 headroom wins appears consistent with seeking a lower confidence bound above 0.729 across all 267; the precise requirement depends on the interval method.
Do not retrospectively declare these pilots successful. For a separately registered usefulness study, retain the safety floors, flag ceiling and owner review. Compare against the template and mechanical-fuller control using blinded operator judgements and task accuracy; measure completion effort where relevant.
A fair proposed preference criterion is a lower 95% confidence bound above 50%, plus a predeclared practically meaningful advantage, for example at least ten percentage points above chance. Count losses as losses, randomise presentation, and account for shared tenants when estimating uncertainty. The practical threshold requires justification from the operator task, not the existing judge's calibration.
Report raw generation failures and fallback frequency separately from delivered-output safety. Repeated validation experiments are development evidence; a final claim needs an untouched hold-out set. Existing deterministic checks also cannot establish the correctness of new remediation advice.

3. Single next step, cost and effort
Run one inference-only pilot of a prioritised tenant fix plan. This offers a plausible new benefit: selecting and sequencing actions across findings, explaining dependencies and stating trade-offs. It remains unproven, but addresses work the current per-check template does not perform.
Give the writer validated findings and a vetted action catalogue with prerequisites. Require evidence-linked selections, explicit uncertainty and no invented tenant facts. Compare with a credible deterministic plan ordered by severity, exposure and known dependencies.
Use a small development set and at least 24 untouched tenant scenarios for owner review, separated by tenant where possible. Have independent domain reviewers assess unsupported actions, dependency mistakes and practical usefulness. Preserve at least the 99% hard-check floor; reject materially unsafe recommendations regardless of preference.
Budget ceiling: 100 GH200 GPU-hours for generation and judging, with no training. This is a proposed spending cap, not a measured runtime estimate. Effort centres on curating scenarios, validating the action catalogue, defining plan checks and reviewing paired outputs. A small pilot establishes whether further evaluation is worthwhile, not deployment readiness.
Recommendation: Stop explanation and run-question training; spend at most 100 GPU-hours on this tenant-plan pilot, and stop model work if it cannot show clear operator benefit over the deterministic plan.
