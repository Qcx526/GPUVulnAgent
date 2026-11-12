# P23 findings report

## FND-t22-0001 — nvdisasm 12.6.68 SIGSEGV on a relocation offset outside every section

**Status:** stable, root cause partial, attribution none.

| field | value |
|---|---|
| component | nvdisasm |
| affected | 12.6.68 only (12.6.77, 12.8.55, 12.8.90, 13.0.85 refuse cleanly) |
| input | `research_archive/experiments/P22/rel_offset_huge.cubin` |
| input sha256 | `65dbc522a676135a8ab644c6727bf159a604ed802b8491dd41855df5fa5d25bf` |
| mutation | first `r_offset` in the REL section set to `0xFFFFFFFFFFFF0000` |
| crash | SIGSEGV, signal 11, supervisor-verified |
| stability | 5/5 per build, 25 runs total, deterministic |
| CWE | candidate CWE-125; **not** UAF (no free observed, no reuse observed) |
| candidates | CVE-2024-0124, CVE-2025-23308, CVE-2024-53876, CVE-2025-23338 |
| confirmed | none |

### Observed

```
0x000000000040b6be in ?? ()      <- and (%rdx,%rdi,8),%rax   with rdi=0
#1 0x44f7c7  #2 0x45a333  #3 0x420592  #4 0x45a9cd  #5 0x4202c2  #6 0x45d836  #7 main
```

The binary is stripped, so these are addresses, not function names. The faulting instruction
reads memory through `rdx + rdi*8` with `rdi = 0`.

### Version behaviour

| build | result | message |
|---|---|---|
| 12.6.68 | SIGSEGV (5/5) | none |
| 12.6.77 | exit 1 (5/5) | `fatal : Relocaiton offest outside section size` (typo original) |
| 12.8.55 / 12.8.90 / 13.0.85 | exit 1 (5/5) | `fatal : Relocation offset outside section size` |

The guard's introduction in 12.6.77, with its spelling fixed by 12.8.55, dates the fix to the
12.6.68 → 12.6.77 window.

### Why it is not attributed

The fix window coincides with CVE-2024-0124's, which makes the overlap tempting and wrong to
act on: the assigned CVE is a use-after-free, this is an invalid read at a computed address,
and there is no symbol or lifetime evidence. Every bulletin in the candidate list also covers
12.6.68. The honest position is `related_cves` (candidate) with `confirmed_attribution` empty.

### Open questions

1. Which function contains `0x40b6be`? Needs a non-stripped build or a byte-diff of 12.6.68 vs
   12.6.77 around the guard.
2. Is the bad pointer derived from `r_offset`, from the section index, or from a table lookup
   that returns null?
3. Would ASAN report the same access as an OOB read, or something else?
4. Which advisory specifically introduced the 12.6.77 guard?
