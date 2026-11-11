# GPUVulnAgent

An autonomous NVIDIA GPU vulnerability research agent. It plans, calls real tools, records
what actually happened as hash-chained evidence, and refuses to call a guess a finding.

This is a new project, not a wrapper around `cuda_poc_generator`: the agent core was
extracted from that repository at a fixed commit, then rebuilt as an independent package
with its own toolchain, research archive and tests. The legacy pipeline stays where it is.

## What it does

- **Open-ended loop.** No stage list. Each decision the model may call one or more tools;
  results return to the conversation as tool messages.
- **Native tool calling first.** DeepSeek `tool_calls` is the primary channel; a JSON
  action in the text is a recorded fallback, and the channel used is stored per turn.
- **Typed tools.** Every parameter has a JSON-Schema type, validated before dispatch.
- **Evidence, not prose.** Append-only JSONL with a hash chain, content-addressed
  artifacts, per-process termination classification.
- **Three memory scopes.** Run memory dies with the run; case memory and global research
  memory persist, including refuted directions.
- **Capability catalog.** Tools, adapters and toolchain binaries are searchable by purpose,
  file format and dependency - including the ones that cannot run here, with the reason.
- **Toolchain manifest.** No hardcoded drive letters; binaries live under `toolchains/`
  with version, SHA256 and provenance.
- **Benchmark runner.** Unique run ids, explicit case/mode identity, disjoint metrics, a
  wall clock that is actually enforced, and a cumulative result index.

## Layout

```
gpuvulnagent/
  runtime/      agent loop, run state, workspace guard
  providers/    DeepSeek (native tool calling), Tavily
  registry/     typed tool specs, validation, dispatch
  tools/        builtin tools, assembly
  discovery/    capability catalog, toolchain manifest
  evidence/     hash chain, artifacts, process runner, termination classes
  memory/       run / case / global research memory
  context/      prompt assembly, observation rendering
  adapters/     elf_cubin, jpeg
  benchmarks/   runner, metrics, crash classification, summary index
  config/       .env + YAML loader with explicit precedence
```

```
tests/            pytest suite (no network, no credentials)
scripts/          setup_toolchain.py, archive_p18.py, acceptance.py
configs/          default.yaml
data/             cases, benchmarks, knowledge
toolchains/       cuda, binary_tools, compilers, debuggers, installers, manifests
research_archive/ legacy_pipeline (pointer only), p17, p18, migration, memory
.local/           runs, artifacts, logs, cache, tmp, migration_source   (not tracked)
```

## Quickstart

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[dev,search,jpeg,elf]"

copy .env.example .env      # then fill in DEEPSEEK_API_KEY / TAVILY_API_KEY

.venv/Scripts/python.exe -m gpuvulnagent doctor --verify-toolchain
.venv/Scripts/python.exe -m gpuvulnagent tools --search jpeg
.venv/Scripts/python.exe -m gpuvulnagent run --goal "探测本机 GPU 研究条件" --turns 6
.venv/Scripts/python.exe -m gpuvulnagent verify --run .local/runs/<run-id>
```

Credentials come from the project root `.env`; an exported environment variable always
wins. Nothing key-shaped is written to evidence, logs or reports - the runtime redacts
before it writes.

## Tests

```bash
.venv/Scripts/python.exe -m pytest
```

The suite is offline: providers are scripted, and no test needs a key. Real-endpoint
acceptance is a separate, explicit step:

```bash
.venv/Scripts/python.exe scripts/acceptance.py --turns 8
```

It writes `.local/logs/acceptance.json` and prints one line per check.

## Independence

- No import of `cuda_poc_generator`, no `sys.path` injection, no symlink into it.
- The old repository is read once, read-only, into `.local/migration_source/` at a pinned
  commit; that directory is git-ignored.
- Every path the runtime needs is resolved from the project root or from configuration.

See `docs/GPUVULNAGENT_MIGRATION_FINAL_REPORT.md` for the migration record and
`research_archive/migration/SOURCE_AUDIT.md` for what was wrong in the previous
implementation.
