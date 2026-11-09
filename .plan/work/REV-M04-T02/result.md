## RESULT REV-M04-T02
status: done
summary:
verdict: changes-required
reviewed: 6e866b331a91d7f1c9537a95abc75c0827eaef9b
One fail-open path outside DEC-008 confirmed.
changes: none
verification: Three production scanner assertions PASS with the virtual planted module; fake-runner replay confirms the writing command reaches the launcher; worktree clean.
Required pytest command BLOCKED before collection because the sandbox denies temporary-file writes.
risks: clean-development doctor failed on a dead/unverifiable lifecycle-lock owner; no repairs attempted.
questions_for_g: none
### Findings
P1 - `tests/test_read_boundaries.py:462`: `_bind` ignores `global` declarations, so replacement argv is recorded under the function rather than the module. The launcher resolves only the original read-only value.
Planted example:
    import subprocess
    ARGV = ["pwsh", "-Command", "Get-Date"]
    def choose_command():
        global ARGV
        ARGV = ["pwsh", "-Command", "Set-Mailbox -Identity x -HiddenFromAddressListsEnabled $true"]
    def audit():
        choose_command()
        subprocess.run(ARGV)
Calling `audit()` hands `Set-Mailbox` to the fake runner. Scanner violations, unresolved inputs and untraceable launches are all empty; all three corresponding suite assertions pass with this virtual source included.
This needs neither callee-name shadowing nor an import after a literal assignment, so DEC-008 does not exclude it.
