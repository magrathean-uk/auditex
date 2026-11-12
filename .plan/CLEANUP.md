# Cleanup ledger
<!-- Deletions are outright (git rm) from a G-approved list. Git history is the archive. -->
| path | reason | evidence nothing references it | approved | commit |
|---|---|---|---|---|
| the system's project store, hub cache of the teacher model: `blobs/50f010b63185...69d057da.incomplete` (46,462,402,560 bytes) | stale partial download from the fetch M02-T03 dropped | a `.incomplete` blob is referenced by no snapshot; no job queued and no download process running at 15:14 GMT on 12 Nov 2026 | G, 12 Nov 2026 ("Del it") | not in the repository (removed on the system at 15:15 GMT) |
| the system's project store, hub cache of the teacher model: `blobs/166755c02c0c...a9074df0.incomplete` (3,575,644,160 bytes) | stale partial download from the same fetch | as above | G, 12 Nov 2026 ("Del it") | not in the repository (removed on the system at 15:15 GMT) |
| the system's project store, hub cache of the Ministral 3 8B base: eight `.incomplete` blobs of 11 Nov 2026 (1,895,639,166 bytes in all; four file hashes, two partials each) | stale partial downloads from an interrupted fetch on 11 Nov | `.incomplete` blobs are referenced by no snapshot; no job queued at 15:20 GMT on 12 Nov 2026; no `.incomplete` file is left anywhere on the project store | G, 12 Nov 2026 ("Yes") | not in the repository (removed on the system at 15:20 GMT) |
