## RESULT EXP-phaseD-signins
status: done
summary: Run phase D as is, plus exported REST tokens for the sitting (already supported). One small change first: a longer group member read-back wait in 00-identity.
changes: none
verification: none (read-only reads of the kit, M07 and DECISIONS only)
risks: member read-back is about 20 s (_common.ps1:32-33), the m08-b failure; rollback then re-apply may meet same-name groups in deleted items; a shared opener is what DEC-010 removed
questions_for_g: none
### Findings
See the Findings section above the block.
