# legacy_pipeline — pointer, not a copy

The pre-agent research pipeline stays where it is: in `cuda_poc_generator`.

| item | value |
|---|---|
| repository | https://github.com/Qcx526/cuda_poc_generator |
| branch | `archive/pre-agent-runtime-2026-11-11` |
| commit | `0a119a0dc017141fc7478f0317c39d89fe149f01` |
| status | untouched by this migration |

This directory deliberately contains **no pipeline source**. Copying it into
`GPUVulnAgent` would create a second, diverging copy of 150+ modules and would make the
new project a wrapper around the old one, which is exactly what P18 was meant to end.

What is here instead:

* `PIPELINE_INVENTORY.md` - what the archived pipeline contains, so a future reader knows
  what to fetch and from which commit.
* `README.md` - this file.

If a capability from the pipeline is needed later, the rule is to re-implement it as a
project tool with its own tests (as `adapters/jpeg` and `adapters/elf_cubin` do), not to
import it.
