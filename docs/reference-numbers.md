# Reference numbers

What the build this toolkit was developed against produced, so a reader can tell at
a glance whether their own numbers look sane. **These are one program's numbers, not
a promise**: a different build legitimately differs, and the tests assert invariants
and lower bounds rather than these totals.

| Stage | Result |
|---|---|
| object table | 834 objects, 34,415 methods, 0.4 s |
| literals from the image | 167,564 in 4.6 s (6,171 with a SQL verb) |
| literals from a listing | 441,607 in 12,480 procedures |
| statements | 10,691 starts → 8,745 closed in 4,109 procedures, 494 tables |
| `.frm` design | 369 forms, 30,000 controls, 126 forms with control arrays |
| form blobs | 801 blobs, 24,967/24,967 controls (100 %), 367/369 forms |
| DataReports | 437 layouts (413 in report DLLs + 24 embedded in the executable) |
| dossier | 34,159 procedures in 52 s (4,416 of them carrying CLOSED SQL) |
| edges | 4 m 47 s single pass: 34,159/34,159 ranges end on `ret` inside their own bounds; 1,897,375 calls named via imports + 9,980 via import thunks; 27,033 edges attributed to listed procedures; 1,791,902 late-bound; 79 hits still unnamed |
| outline | 1,882,740 of 1,907,355 runtime hits (98.7 %) land in a runtime-table category, in 2 s, engine-free |

A different program legitimately gives different numbers. The tests assert
invariants and lower bounds, not these totals. The `stitch` row was measured before
0.3.0 fixed the `STUCK` classification of one-literal statements, so it understates
`closed` — see `docs/pipeline.md` §3.
