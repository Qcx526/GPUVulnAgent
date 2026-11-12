# P19-R1 — GPU Execution Backend Evidence Correctness

Branch: `fix/p19-evidence-correctness`
Base: `feat/linux-gpu-execution-backend` @ `cd6823c`
Date: 2026-11-12

This stage does not redesign the backend. It fixes seven places where the backend produced
evidence that was true-looking but not true, and one place where a configuration value was
never wired to anything.

| # | defect | fix |
|---|---|---|
| 1 | a second execution overwrote the first one's artifacts | every execution owns `execs/execNN/` with its own snapshot |
| 2 | the artifact collector followed symlinks | `lstat` + `O_NOFOLLOW` + `fstat` + root-boundary check, symlinks recorded and skipped |
| 3 | `exit(139)` was read as SIGSEGV | an independent supervisor reports wait status; no evidence means `unverified_signal`, never a crash |
| 4 | a collection error could leave a container running | cleanup runs in `finally`; a cleanup failure is recorded, not swallowed |
| 5 | `GPU_BACKEND_ENABLED` / `WSL_*` / `GPU_IMAGE` were unused, `WSL_CALL_TIMEOUT` was dead | wired through CLI → `WslConfig.from_settings` → worker; call timeout is the default transport timeout |
| 6 | image pulling was implicit | `pull_policy` (`missing` default, `always`, `never`), recorded with the resolved digest |
| 7 | docs implied the option allowlist was a sandbox | README and this document state the actual boundary |

---

## 1. Execution artifact snapshots

The trail still owns one persistent work directory, so a compile step and a run step share
the same `/work`. What changed is where results land:

```
trails/trail0/
  inputs/poc.cu                    staged by the agent
  execs/exec00/                   execution 0
    result.json                    classified result, image digest, cleanup, supervision
    snapshot.json                  created / changed / deleted / unchanged, before/after hashes
    outputs/poc.cu, outputs/poc    files this execution produced
    logs/docker_run.stdout, .stderr
  execs/exec01/                   execution 1, same names, different bytes
```

* The snapshot holds **only files this execution created or modified**, plus a full
  before/after hash listing so "it did not change" is provable too.
* An execution never writes into another execution's directory, and `Trail.add_file` still
  refuses to overwrite a path inside a trail.
* Evidence records for one execution link only that execution's artifacts
  (`execs/exec00/...`), which the Windows side verifies by re-hashing every file.

Measured (acceptance C): the same `poc.cu` and the same binary name written twice.

| version | source sha256 | binary sha256 |
|---|---|---|
| v1 (exec00) | `462d42aee6fc15e7018670ed3a5f8635f7cbb3a97c7de724435d554ee9f45165` | `df326fb76467d3baf99ed8dd5ae9fd46ca7815bcaa9d68a8e2ed52871897e9a0` |
| v2 (exec01) | `6368ebc8e902c1b66a0ab3114a990d43a90fd0ed5da5f735419538a79228291e` | `8d…` (different) |

Both are readable afterwards (`trail_read("execs/exec00/outputs/poc.cu")` and the same for
`exec01`), and a bare `trail_read("poc.cu")` resolves to the newest execution.

## 2. Symlink-safe collection

The collector no longer trusts the tree it walks:

* `os.walk(..., followlinks=False)` and symlinked directories are pruned and recorded;
* every file is `lstat`-ed first; anything that is not a regular file is skipped and listed
  in `snapshot.skipped_symlinks` / `snapshot.special` with the link target and a reason;
* the open uses `O_NOFOLLOW`, and the `fstat` result is compared with the `lstat` result so
  a path swapped between check and open is rejected;
* the real path must stay inside the work root (and the copy destination inside the
  artifact root);
* the Windows side repeats the check: a copied file that is a symlink is refused, and every
  file is re-hashed.

Measured (acceptance D): a container created `ln -s /etc/passwd /work/leak-passwd.txt` and
`ln -s /home/pocdev /work/leak-home`.

```
skipped: ["leak-home", "leak-passwd.txt"]   leaked_files: []
real_output_collected: true
```

No archived artifact contains `root:x:`.

## 3. Linux crash classification

An exit status cannot distinguish `return 139` from SIGSEGV, and Docker reports 139 for
both. The backend now ships a small supervisor (`gpuvulnagent/backends/worker/
gpuvuln_supervise.c`, built once on the WSL host with `gcc -O2 -static`) and starts the
experiment as its child. It writes the wait status — exited vs signalled, with the signal
number — to a status file opened with `O_NOFOLLOW`.

Classification order:

1. timeout / OOM / docker runtime error → `timeout` / `oom_killed` / `container_error`,
   never a crash, regardless of exit code;
2. supervisor readable and `signaled` → signal kind (`sigsegv`, `sigabrt`, `sigbus`,
   `sigill`, `sigfpe`), crash only for a target signal;
3. supervisor readable and `exited` → `success` or `error_exit`, **including exit 139**;
4. no supervisor evidence and an exit code in the signal range → `unverified_signal`
   (`crash=false`, `signal_verified=false`) — conservative by construction.

Measured (acceptance E), all three run directly in the same image:

| program | container exit | kind | crash | signal_verified |
|---|---|---|---|---|
| `int main(void){return 139;}` | 139 | `error_exit` | false | true |
| `int main(){int *p=0;*p=1;}` | 139 | `sigsegv` | **true** | true |
| segfault behind `bash -lc` | 139 | `sigsegv` | true | true |

The third row is a property of bash: it re-raises the child's signal, so the supervisor
still sees a signal. A program that *returns* 139 does not become one.

## 4. Container lifecycle

Cleanup is in a `finally` block, and its result is evidence:

```
"cleanup": {"attempted": true, "target": "...", "exit": 0, "detail": "removed"},
"cleanup_ok": true
```

* If snapshotting or the host copy raises, the error is recorded in the result and the
  container is still removed (tested with an injected `RuntimeError`).
* If `docker rm` fails, `cleanup_ok` is false and the reason is stored; the tool observation
  says so instead of reporting success.
* A timeout kills the container before removal; `gpu_cleanup(run_id)` finds leftovers by
  label. Acceptance F: `leftovers: {"removed": []}`.

## 5. Configuration integration

`GPU_BACKEND_ENABLED`, `WSL_DISTRO`, `WSL_USER`, `WSL_WORKER_ROOT`, `GPU_IMAGE`,
`WSL_CALL_TIMEOUT` and `GPU_PULL_POLICY` are read from `.env` and forwarded:

```
CLI run/bench/tools  ->  settings.backend  ->  WslConfig.from_settings()  ->  backend  ->  worker
```

* `gpuvulnagent run --no-gpu-backend` (and `GPU_BACKEND_ENABLED=0`) unregisters the GPU
  tools for that run; `tools --search gpu` then finds nothing, which the CLI test asserts.
* `WSL_CALL_TIMEOUT` is now the default timeout for every worker round trip.
* An invalid `GPU_PULL_POLICY` is a configuration error, not a silent default.

Measured (acceptance G): with `.env` set to distro `Ubuntu-22.04`, user `pocdev`, image
`nvidia/cuda:12.8.0-base-ubuntu22.04`, timeout 120, pull policy `never`:

```
distro_applied, user_applied, image_applied, call_timeout_applied, pull_policy_applied: true
default_image_used: true          (the run used the configured base image)
missing_image_refused: true       (pull_policy=never + absent image -> container_error)
bad_user_is_reported: true        (getpwnam(no-such-user-r1) surfaced in the error)
```

## 6. Docker image pull

`container_exec(pull_policy=...)` with `missing` (default), `always`, `never`. The worker
inspects the image first, pulls only when the policy says so, and records:

```
"image_pull": {"policy": "missing", "present_before": true, "pulled": false,
               "ok": true, "duration_ms": 0, "error": ""}
```

`network=none` is a property of the **container**, not of the engine: the daemon can still
pull. That is stated in the tool schema and in the note the worker returns.

## 7. Documented boundary

The README now says, in the backend section and in "Scope and limits":

* the `shell` tool runs **on the Windows host** and can start any host command the user can;
  it is not sandboxed;
* the docker option allowlist (no `--privileged`, one mount, no docker socket, network none
  by default) limits blast radius; it is **not** a security sandbox;
* containers share the WSL2 kernel and use the Windows NVIDIA driver, so kernel-mode and
  physical GPU driver research is out of scope for this backend;
* what the backend is for: Linux user-space CUDA PoC, GPU kernels, user-mode driver
  interfaces, with evidence.

---

## A. Offline regression

```
$ python -m pytest -o addopts="" -q
191 passed, 7 skipped in 8.34s
```

7 skipped = the live WSL/Docker/GPU tests, which need `GPUVULNAGENT_LIVE=1`.

New offline coverage for this stage: snapshot create/change/delete, two versions of one
name, symlink file and symlink directory, timeout kill, cleanup on collection error,
cleanup failure recorded, pull policy matrix, supervisor wrapping, exit139 vs signalled vs
unverified, config from environment, CLI toggle, tool schema/summary.

## B–H. Real environment (WSL2 / Docker 29.8.2 / GTX 1660)

```
$ python scripts/p19r1_acceptance.py --turns 12
[supervisor]                 OK  sha256 bf398336… static=True
[C_snapshot_two_versions]    OK
[D_symlink_escape]           OK
[E_exit139_vs_sigsegv]       OK
[F_timeout_cleanup]          OK
[G_config_effect]            OK
[H_agent_end_to_end]         OK
```

| check | evidence |
|---|---|
| B real execution | containers on `nvidia/cuda:12.8.0-devel-ubuntu22.04`, digest `nvidia/cuda@sha256:54f18e2a…`, GPU `NVIDIA GeForce GTX 1660` (CC 7.5), CUDA 12.8.93 |
| C two versions | see §1; both source and binary recoverable |
| D symlink | see §2; two links skipped, nothing leaked |
| E signals | see §3; three cases distinguished |
| F timeout | `timed_out=true`, `kind=timeout`, `cleanup_ok=true`, no leftovers |
| G config | see §5; nine checks true |
| H agent | `run-20261112T025246Z-491b2a`: 12 decisions, 21 executions, 4 container executions, 2 trails, 47 evidence records, chain verified, 201 741 tokens, 94.4 s |

Real GPU test suite:

```
$ GPUVULNAGENT_LIVE=1 python -m pytest tests/test_live_gpu_backend.py -q
7 passed in 18.90s
```

## Evidence bundle

`research_archive/experiments/P19/` — 51 files, 2.3 MB:

```
environment.json            probe at archive time (distro, docker, GPU, CC, CUDA, tools)
acceptance.json             the acceptance results
bundle_manifest.json        every archived file with sha256, host facts, check statuses
SHA256SUMS.txt              sha256sum -c compatible
evidence/C_.../trail0/…     manifests, result.json, snapshot.json, stdout/stderr, small artifacts
evidence/D_... …/E_... …/F_... …
agent/result.json           the agent's final answer
agent/evidence.jsonl        the hash-chained log of the run
agent/trails/*/manifest.json
```

Excluded on purpose: the toolchain, container filesystems, the full WSL work directories,
and anything credential-shaped. `scripts/archive_p19.py` scans each file for key patterns
and refuses to copy one that matches.

## Not fixed in this stage

1. **Signal evidence inside a shell is the shell's.** `bash -lc './poc'` reports the signal
   because bash re-raises it; `sh -c 'poc; echo $?'` may not. Direct argv is the reliable
   form.
2. **No core dump / symbolized stack.** A `sigsegv` is proven by wait status plus stdout and
   stderr, not by a backtrace.
3. **Snapshot is a delta, not a full copy.** Unchanged files are recorded by hash but not
   copied again. A full-tree copy per execution would be simpler to read and much more
   expensive; the before/after listing is the compromise.
4. **Deleted files are recorded, not preserved.** If an execution deletes a file, the
   snapshot says so; the bytes from the earlier execution are still in the earlier
   execution's directory, not in this one.
5. **Still one GPU host.** Multi-host scheduling remains out of scope.
6. **Not a security boundary.** See §7.
