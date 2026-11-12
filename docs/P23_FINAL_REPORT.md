# P23 final report

## Scope and honesty statement

This round produced **no new CVE reproduction** and **one stabilised finding**. The executions
below were driven directly by the engineer through the project's own backend, not by a
DeepSeek agent loop: **LLM tokens consumed this round: 0**. That is a gap against the P23
brief (real API required) and is recorded here rather than hidden; the next run must reproduce
these steps through the agent.

## Environment (re-verified this round, not assumed)

| item | value |
|---|---|
| WSL | Ubuntu 22.04, kernel from `probe` |
| Docker | 29.8.2 |
| GPU | NVIDIA GeForce GTX 1660, CC 7.5 |
| container image | `nvidia/cuda:12.8.0-devel-ubuntu22.04` (digest `sha256:54f18e2a…`) |
| gdb | not on the WSL host (no passwordless sudo); installed inside the container for the stack run |
| core dumps | `/proc/sys/kernel/core_pattern` is a pipe (`/wsl-capture-crash`), `ulimit -c 0`; no core file produced |

## Versions used (identity verified by running each binary)

| build | binary sha256 | `--version` |
|---|---|---|
| nvdisasm 12.6.68 | `9f146d28…d880c` | V12.6.68 |
| nvdisasm 12.6.77 | `534cbe6b…1fb30` | V12.6.77 |
| nvdisasm 12.8.55 | `1080bc90…2a1f2` | V12.8.55 |
| nvdisasm 12.8.90 | `250ebe97…36073` | V12.8.90 |
| nvdisasm 13.0.85 | `3c27bded…89f41` | V13.0.85 |

Input under test: `rel_offset_huge.cubin`, sha256
`65dbc522a676135a8ab644c6727bf159a604ed802b8491dd41855df5fa5d25bf`.

## Track A — CVE-2024-0124

**Not reproduced.** Status unchanged from P22 and now backed by a controlled version pair:
12.6.68 (inside `<= 12.6U1`) and 12.6.77 (the 12.6U2 fix level) are both available and behave
identically on every input tried so far. No input produced a signal on either build, so there
is no lifetime evidence and nothing to attribute.

What this round did add for Track A: the REL-offset guard is absent in 12.6.68 and present in
12.6.77 (its message still contains the typo `Relocaiton offest`), which dates that specific
fix to the same window as CVE-2024-0124. That is a lead for where to look, not a reproduction.

## Track B — findings

`FND-t22-0001` moved from "one observation" to "stable": 25 executions, 5 per build,
`12.6.68` 5/5 SIGSEGV and the other four builds 5/5 clean `exit 1`. A gdb stack was obtained
(unsymbolised, binary is stripped). Root cause is **partial**, CWE is a **candidate**
(CWE-125), attribution is **none**.

## Totals

| metric | value |
|---|---|
| assigned CVEs | 1 (CVE-2024-0124) |
| reproduced | 0 |
| not reproduced | 1 |
| new findings | 1 (`FND-t22-0001`) |
| stable findings | 1 |
| root cause established | 0 complete, 1 partial |
| confirmed CVE attribution | 0 |
| agent-generated PoCs this round | 0 |
| agent-driven mutations this round | 0 |
| real executions this round | 27 (25 supervised stability + 1 container gdb + 1 container setup) |
| LLM tokens | 0 |
