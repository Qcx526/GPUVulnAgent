# P22 — first CUDA Toolkit campaign result

## What was run

36 supervised executions: 6 inputs x 4 nvdisasm builds (12.6.68, 12.8.55, 12.8.90, 13.0.85)
plus 6 inputs x 2 cuobjdump builds (12.8.55, 13.0.85). Every process was started through the
static supervisor, so `exited 139` and `killed by SIGSEGV` stay distinguishable.

Versions were obtained as signed APT packages, not docker images:

| build | deb sha256 | binary sha256 |
|---|---|---|
| nvdisasm 12.6.68 | `34848a95…` | `9f146d28…` |
| nvdisasm 12.8.55 | `ad094254…` | `1080bc90…` |
| nvdisasm 12.8.90 | `0c4b84ce…` | `250ebe97…` |
| nvdisasm 13.0.85 | `a0edae45…` | `3c27bded…` |
| cuobjdump 12.8.55 | `4daf0632…` | `ad1d0f06…` |
| cuobjdump 13.0.85 | `c175036d…` | `1763b536…` |

## Inputs

Baseline `vector_add.cubin` (sm_75) and five REL-section mutations derived from it, aimed at
the parsing stage CVE-2025-23308 describes rather than at the early size checks:

| input | change | hypothesis |
|---|---|---|
| `rel_entsize1` | `sh_entsize = 1` | entry count becomes size/1, parser walks past the section |
| `rel_entsize0` | `sh_entsize = 0` | division by zero / unbounded loop |
| `rel_size_plus1` | `sh_size + 16` | one entry read past the section end |
| `rel_info_huge` | first `r_info` symbol index = 0xFFFFFFF0 | symbol lookup outside `.symtab` |
| `rel_offset_huge` | first `r_offset` = 0xFFFFFFFFFFFF0000 | relocation target outside every section |

## Result

One crash, and it is a real one:

| build | `rel_offset_huge` |
|---|---|
| nvdisasm 12.6.68 | **exit 139, supervisor reports SIGSEGV** |
| nvdisasm 12.8.55 | exit 1, `fatal : Relocation offset outside section` |
| nvdisasm 12.8.90 | exit 1, same fatal |
| nvdisasm 13.0.85 | exit 1, warning only |

The other four mutations were rejected or ignored by every build (for example `sh_entsize=1`
gives `warning : Invalid Entry size` on 13.0.85 and `error : Unknown relocator type` on the
12.x builds). cuobjdump parsed all six inputs, including the crashing one, without a crash.

## Verdict ladder

| level | state | basis |
|---|---|---|
| TOOL_EXECUTED | yes | 36 runs, six binaries with recorded hashes |
| INPUT_ACCEPTED | yes | baseline disassembles on all four; the crashing input was parsed far enough to reach relocation handling |
| TARGET_PATH_REACHED | yes | the fault is inside relocation processing, the stage the bulletin describes |
| CRASH_OBSERVED | yes | one SIGSEGV, supervisor-verified on 12.6.68 |
| DIFFERENTIAL_SUPPORTED | yes | same bytes: 12.6.68 crashes, 12.8.55/12.8.90/13.0.85 refuse cleanly |
| MECHANISM_SUPPORTED | **no** | no dump, no stack, no allocator evidence |
| CVE_ATTRIBUTED | **no** | 12.6.68 sits in several bulletins' ranges; versions alone cannot pick one |

## What this does and does not claim

It is a reproducible, version-differential crash in nvdisasm's relocation handling that
disappears in later 12.8 builds. It is **not** yet a CVE reproduction: the bulletin ranges
overlap, there is no stack, and the crash has been seen once. Claiming UAF or heap overflow
from one SIGSEGV would be exactly the confusion the P22 rules forbid.

## Next, in order

1. Repeat `rel_offset_huge` five times per build to establish stability.
2. Get a stack: `cuda-gdb`/`gdb` on the Linux binary, or a core dump via `ulimit -c` in the
   container; map the faulting frame to relocation handling.
3. Only then compare against CVE-2025-23308 (heap overflow, REL parsing) versus the CWE-125
   read family, and record which one the stack supports.
4. Run the same input against cuobjdump 12.6.x, which was not fetched for this round.
