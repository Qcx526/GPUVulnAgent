# Archived pipeline inventory

Fetched metadata only - `git ls-tree` against the archived commit. No pipeline file is
copied into this workspace.

| field | value |
|---|---|
| branch | `archive/pre-agent-runtime-2026-11-11` |
| commit | `0a119a0dc017141fc7478f0317c39d89fe149f01` |
| files | 1468 |
| python modules under `src/` | 163 |
| top-level entries | `src/`, `tools/`, `tests/`, `docs/`, `data/`, `config/`, `constraints/`, `specs/`, `main.py`, `pyproject.toml`, `requirements.txt` |

How to retrieve it, read-only, without touching the archive:

```
git clone https://github.com/Qcx526/cuda_poc_generator.git cuda_poc_generator
cd cuda_poc_generator
git checkout --detach 0a119a0dc017141fc7478f0317c39d89fe149f01
```

Why it is not copied here: the pipeline is ~150 modules with an internal import graph that
reaches into `src/` everywhere. Copying it would recreate the coupling this project exists
to remove, and would let two copies drift.

Which parts of it were re-implemented as project tools instead:

| pipeline capability | new location | reason |
|---|---|---|
| JPEG input adapter (`src/jpeg_adapter.py`) | `gpuvulnagent/adapters/jpeg/` | self-contained, no `src` imports, discoverable via the catalog |
| nvJPEG / CUBIN inspection helpers | `gpuvulnagent/adapters/elf_cubin/` | reads structure directly, drives manifest binaries |
| agent loop, evidence, memory | `gpuvulnagent/runtime`, `gpuvulnagent/evidence`, `gpuvulnagent/memory` | rewritten as an independent package |
