# P21-R2 acceptance report

Real run: `gpuvulnagent run --sessions-dir runs --turns 10 --case P21R2-CUDA`.

| item | value |
|---|---|
| trial | `runs/trial2` |
| artifacts | 20 (source=2, binary=4, log=7, script=1, file=6) |
| registry verify | ok |
| evidence chain | `runs/trial2/evidence/evidence.jsonl`, verified |
| report | `runs/trial2/report/final_report.md` |

The agent wrote `vector_scale_v1.cu` with a bash heredoc in the container, derived
`vector_scale_v2.cu` with `sed` (COEFF 2.0 to 3.0, two-line diff), compiled each with
`nvcc -arch=sm_75` to a cubin and an executable, and ran both on the GTX 1660.

|  | v1 | v2 |
|---|---|---|
| source sha256 | `9ad8f9366455fdfa...` | `93e6a435b47a05e7...` |
| cubin sha256 | `00906277ef55a35e...` | `5e16d8846507cf50...` |
| exit / MISMATCHES | 0 / 0 | 0 / 0 |
| SAMPLE | 2.000000 | 3.000000 |

SASS differs in one instruction (`FADD R7, R2, R2` vs `FMUL R7, R2, 3`), confirming v2 was
derived from v1, and both cubins are valid ELF64/EM_CUDA.

Gaps the run itself reported: the `container_exec` evidence id was cut off by observation
truncation (artifacts were still registered by the harvest), and `memory_note` was rejected
because one cited id had been guessed.
