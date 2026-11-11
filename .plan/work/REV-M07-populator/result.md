## RESULT REV-M07-populator
status: done
summary:
verdict: approve
reviewed: d2f0d07e31aa f0209cf2a65f
changes: none
verification: shasum PASS (all three prefixes); diff PASS (one replacement); static filesystem review PASS; no PowerShell or network
risks: static confirmation only; approval covers PowerShell 7.4 on macOS; BSD stat syntax is incompatible with Linux
questions_for_g: none
### Findings
diff: 1 lines changed, populator-app.ps1:79; only the hidden-folder lookup, adding -Force -LiteralPath (one deletion, one addition)
link-refusal: holds - Force exposes the hidden directory; LiteralPath prevents wildcard expansion; LinkType is truthy for a symbolic link and empty for a plain directory, including under StrictMode 3
app:77 Test-Path $secDir - before first tenant write (88); hidden directory works without Force; advisory
app:77 New-Item directory - before first tenant write; explicit dot-directory creation needs no Force; advisory
app:77 chmod - before first tenant write; explicit hidden path works on macOS/Linux; advisory
app:80 Stat directory via 29 - before first tenant write; BSD stat works on macOS; Linux fails here before any tenant write; advisory
app:81 Test-Path secret file - before first tenant write; hidden ancestor needs no Force; advisory
app:110-111 FileStream creation, Write, Flush and Dispose - after first tenant write; .NET supports hidden ancestors and UnixCreateMode on macOS/Linux; no platform blocker
app:112 Stat secret file via 29 - after first tenant write; works on macOS; incompatible on Linux and blocking if reached there
content:161 File.ReadAllText - before that script's first tenant write, after app creation; .NET reads through hidden ancestors without Force; advisory
