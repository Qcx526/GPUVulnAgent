# P23 CVE reproduction matrix

| CVE | component | affected | fixed | downloaded | PoC generated | runs | crash | differential | status | open issues |
|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2024-0124 | nvdisasm (CWE-416 UAF) | <= 12.6U1 | 12.6U2 (=12.6.77) | yes: 12.6.68, 12.6.77, 12.8.55, 12.8.90, 13.0.85 via signed APT debs | no new Track A PoC this round | 6 inputs x 2 primary builds in P22, unchanged | none on 12.6.68/12.6.77 | none for the UAF question | **not reproduced** | no lifetime evidence; inputs never reach a free/use sequence |

Reading this table correctly: "downloaded" and "tool executed" are not progress toward
reproduction. The only line that matters is `status`, and it says not reproduced.
