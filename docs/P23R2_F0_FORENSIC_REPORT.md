# P23-R2-F0 forensic report

## Candidates (4, all parsed, none modified)

| file | sha256 | nsyms | rel/rela sections | out-of-range sym entries |
|---|---|---|---|---|
| plain.cubin.reloc_sym_oob.bin | `0daec10b...(full in finding history)` | 7 | 1 | 0 |
| reloc.cubin.reloc_sym_oob.bin | `8b23036c...(full in finding)` | 11 | 5 | 1: sym=0x0FFFFFFF type=57 |
| relocobj.o.reloc_sym_oob.bin | `43f1a2bc...` | 39 | 4 | 0 |
| smem.cubin.reloc_sym_oob.bin | `7afbf719...` | 10 | 2 | 0 |

ELF64 little-endian throughout; r_info decoded as sym=r_info>>32, type=r_info&0xffffffff.

## Execution mapping

- #81: `/work/bin-nvdisasm-12.6.68-1 /work/mut/reloc.cubin.reloc_sym_oob.bin` -> exit 139
- #83: `/work/bin-nvdisasm-12.6.77-1 /work/mut/reloc.cubin.reloc_sym_oob.bin` -> exit 139
- Both were launched inside `campaign1.py` (exec08), not as supervised processes, so `supervision.signaled` is absent for both.

## Corrections

1. The previously recorded input (plain.cubin...) was the wrong file; it has no out-of-range symbol index. Corrected to reloc.cubin...
2. `0x0FFFFFFF` is verified as a symbol index in a real file, not a narrative artefact.
3. FND-t0-0002 is downgraded to UNVERIFIED: the two executions share identical bytes and identical exit 139, but there is no supervisor signal record, so SIGSEGV is inferred from 139 - exactly what the project rules forbid treating as proof.

## Missing evidence

- no signal-verified run of this input on any version;
- no stack, valgrind or register evidence;
- 12.8.55 / 12.8.90 / 13.0.85 were never run against this input.
