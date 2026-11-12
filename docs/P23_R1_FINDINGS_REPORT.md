# P23-R1 findings

| id | builds | stability | CWE | attribution |
|---|---|---|---|---|
| FND-t0-0001 | 12.6.68 crashes, 12.6.77 refuses | stable, 4 flag sets | CWE-125 candidate | none (CVE-2024-0124 candidate) |
| FND-t0-0002 | both 12.6.68 and 12.6.77 crash | 1 run | UNKNOWN | none (0123/0125 candidates, neither matches) |

FND-t0-0001 independently rediscovers the P22 anomaly with a different construction (a legal
-rdc cubin, one Rela r_offset = 0x7fffffff, file length and section headers untouched), plus a
masking control showing r_offset = section_size + 1 does not crash 12.6.68. It is reproduction
evidence for the historical finding, not a second vulnerability.

FND-t0-0002 is new: an out-of-range relocation symbol index crashes the version shipped as the
12.6 fix as well. 12.8/13.0 were not tested because the run's index query hit a quoting bug.
