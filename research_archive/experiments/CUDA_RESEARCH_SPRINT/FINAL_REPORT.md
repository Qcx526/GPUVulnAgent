# CUDA Vulnerability Research Sprint - report 1

## Status

One sprint run, 30 decisions, 647,091 tokens. The agent read a first-hand Talos report and a
NVIDIA bulletin, built a legal baseline cubin, and wrote a structure-aware mutator - then ran
out of decision budget before executing the mutant. Nothing was reproduced.

| item | value |
|---|---|
| CVEs researched | 2 (CVE-2025-23339 cuobjdump; nvJPEG family 23273/23274/23275 scoped) |
| components covered | cuobjdump, nvJPEG (scoped only) |
| PoC written by the agent | 1 baseline (`base.cu` -> `base.cubin`) + 1 mutator (`mutate.py`) |
| PoCs actually executed against a target | 0 mutants (baseline parsed by cuobjdump) |
| crashes observed | 0 |
| differentials | 0 |
| findings registered | 0 |
| status | BEHAVIOR not reproduced; BLOCKED by budget, not by environment |

## What is real

- CVE-2025-23339: CWE-121, affected cuobjdump 12.8.55, fixed 13.0.85, trigger `--dump-elf` on a
  crafted `.debug_abbrev`; stack layout from Talos TALOS-2025-2155 (return address at rsp+0x8b8,
  write via `[rbp+r14*8-8]`, ~0x108 iterations, no count limit).
- Baseline: `nvcc -arch=sm_75 -G -cubin` produced `base.cubin`
  sha256 `e95ed268d3614323ea14ed440ad74b910dc7e0a3095be829f18e927c52d5e19a`, 10216 bytes, and
  `cuobjdump --dump-elf` parses its `.debug_abbrev`, so the target path is reachable.
- Mutator: appends a body at EOF with 0x260 `0x41` LEB128 values and rewrites only that
  section's `sh_offset`/`sh_size`, plus a paired control. Script archived here.

## What is not real

No mutant was ever executed, so there is no exit code, no signal, no supervisor record and no
cross-version comparison. This is hypothesis plus prepared apparatus, not a result.

## Environment friction worth fixing

The agent burned a third of its turns discovering that `container_exec` stages only flat files
into `/work` (not `inputs/`), and that `fs_write` output lands in the workspace where the
container cannot see it. That is a usability defect, not a research failure: the tool
description says "the trail directory is mounted at /work" and the agent reasonably read that as
including subdirectories.
