## RESULT M01-T05b
status: done
summary: Corrected the section 10 "Queue and reservation" bullet. Run 1's training is now the only one on the interactive reservation (826 s on 4 GPUs, 0.918 reservation GPU-hours). Run 2's training and both later trainings are stated as normal queue. Nothing else in section 10 or the usage notes depended on two reservation trainings.
changes: runbook/README.md in the kit (outside the repository); no repository files touched
verification: re-read lines 478-482 of runbook/README.md, pass. Searched section 10 and runs/usage/M01-T05 for reservation or billed figures: none found. The only GPU-hours figures there are the raw 12.465 total and the 0.95 per-training lesson, and neither depends on the reservation.
risks: none
questions_for_g: none
### Findings
corrected: 1 sentence(s), section 10, lines 480-482 (added the 0.918 reservation GPU-hours figure on line 481)
checksum-line: none (no SHA256SUMS in the kit lists runbook/README.md)
