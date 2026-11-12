# P19 — Linux GPU Execution Backend

Branch: `feat/linux-gpu-execution-backend`
Baseline: `main` @ `ff207df`
Date: 2026-11-12

The agent runs on Windows. Until now it could only execute Windows processes, which made
CUDA/Linux user-space work impossible. This stage adds one capability and nothing else: a
way to run an arbitrary argv on a real Linux GPU machine, and get back evidence that can be
checked.

It is deliberately **not** a CUDA pipeline. There is no list of steps, no fixed source
template, no "compile then run then grade" flow. The agent picks the image, the command,
the inputs and the order; the backend reports what happened.

---

## A. Git state

| item | value |
|---|---|
| starting branch | `main` |
| starting HEAD | `ff207df1d41d8b4bdb2696f6716da217b5d02fea` |
| remote at start | `origin/main` = `ff207df` (0 ahead / 0 behind) |
| working branch | `feat/linux-gpu-execution-backend` |
| merge into main | **not done**, by instruction |

Files added:

```
gpuvulnagent/backends/__init__.py
gpuvulnagent/backends/base.py              backend contract, result dataclasses
gpuvulnagent/backends/trails.py            trail allocation + manifests
gpuvulnagent/backends/wsl_docker.py        Windows -> WSL launcher, docker orchestration
gpuvulnagent/backends/worker/__init__.py
gpuvulnagent/backends/worker/gpu_worker.py the in-WSL worker (stdlib only)
gpuvulnagent/evidence/container_outcome.py docker exit -> termination kind
gpuvulnagent/tools/gpu.py                  9 tools registered with the agent
scripts/p19_acceptance.py                  A-D acceptance run
tests/test_container_outcome.py            11 offline tests
tests/test_trails.py                       13 offline tests
tests/test_worker.py                       12 offline tests
tests/test_wsl_backend.py                  11 offline tests
tests/test_gpu_tools.py                    10 offline tests
tests/test_live_gpu_backend.py             4 real tests (env-gated)
data/cases/cuda_smoke/vector_add.cu        the sample kernel used by acceptance B
docs/P19_LINUX_GPU_BACKEND.md              this document
```

Files modified: `gpuvulnagent/config/loader.py` (backend settings),
`gpuvulnagent/tools/build.py` (registration), `gpuvulnagent/runtime/loop.py`
(two pass-through parameters), `gpuvulnagent/registry/registry.py` (failure status is
preserved instead of flattened), `gpuvulnagent/context/observation.py` (empty artifact refs
no longer crash the prompt), `gpuvulnagent/benchmarks/metrics.py` (container records count
as target executions), `.env.example`, `README.md`, `pyproject.toml`.

`configs/default.yaml` was left untouched: it carries an uncommitted local edit by the
user (a proxy `base_url`), and committing it would change the project default.

---

## B. Architecture

```
Agent (Windows, Python 3.13)
  │  tool call: container_exec(trail, image, argv, gpu, timeout_s, ...)
  ▼
gpuvulnagent/tools/gpu.py        arguments -> backend call -> evidence record
  ▼
gpuvulnagent/backends/wsl_docker.py
  │  one JSON request on stdin, one JSON response on stdout
  │  wsl.exe -d Ubuntu-22.04 -u pocdev -- /usr/bin/python3 <worker.py>
  ▼
WSL2 Ubuntu 22.04 (kernel 6.6.87.2-microsoft-standard-WSL2)
  │  gpu_worker.py: allow-lists docker options, starts the container, reads its state,
  │  kills it on timeout, copies artifacts back, hashes everything
  ▼
Docker Engine 29.8.2  →  nvidia/cuda:12.8.0-devel-ubuntu22.04  →  GTX 1660
```

**Why a worker instead of `wsl.exe docker ...` from Windows.** A command string would be
re-parsed by bash on the Linux side, so an argv element containing a space, quote or `;`
would become a second command. The worker takes a JSON object and a string array, so
nothing is re-interpreted. It is also where the security decisions live:

* docker options are built from named fields (`image`, `gpu`, `gpus`, `network`, `memory`,
  `cpus`, `env`, `as_root`); there is no "extra docker args" hole, so `--privileged`,
  host mounts and the docker socket are unreachable from the agent;
* exactly one mount: the trail's work directory at `/work`;
* `--network none` by default; `bridge`/`host` must be requested and are recorded;
* environment variables whose names look like secrets (`*API_KEY*`, `*TOKEN*`,
  `*SECRET*`, `*PASSWORD*`) are refused before the container starts;
* `--security-opt no-new-privileges`, and the container runs as the WSL uid/gid by default
  so it cannot leave root-owned files that the trail owner can no longer manage;
* the container carries `gpuvulnagent.run_id` / `gpuvulnagent.trail` labels, which is how
  leftover containers are found and removed.

**How files move.** Windows writes inputs into `<run>/trails/trailN/inputs/`. The worker
copies them from `/mnt/f/...` into `/home/pocdev/gpuvulnagent-worker/runs/<run_id>/<trail>/work`,
which is the only thing mounted. Compilation and execution happen on the WSL ext4
filesystem, not on `/mnt`. Afterwards the worker copies results back to
`<run>/trails/trailN/outputs/` and `logs/`, and the Windows side re-hashes every file and
refuses the run if a hash disagrees with what the worker reported.

**How evidence comes back.** `container_exec` writes one `exec` record into the existing
hash-chained log (`evidence/log.py`), with the fields the stage required: `run_id`,
`backend`, `image`, `image_digest`, `container_id`, `argv`, `cwd`, `gpu_name`, `cuda`,
`started_at`, `finished_at`, `duration_ms`, `exit`, `timed_out`, `oom_killed`,
`termination`, `stdout_artifact`, `stderr_artifact`, `artifact_hashes`, `trail`. The full
stdout/stderr also go into the run's artifact store, so `artifact_read` keeps working.

**How trails work.** `trail0`, `trail1`, … are allocated with `mkdir(exist_ok=False)`,
which is atomic, so two concurrent callers cannot receive the same number; a test runs 12
threads to prove it. Each trail has `inputs/`, `outputs/`, `logs/`, `manifest.json` with
per-file SHA256/size/source and a `parent_trail` link. A trail is append-only: writing the
same name twice is an error, and a second experiment gets the next trail.

---

## C. What the backend can actually do

| question | answer |
|---|---|
| run arbitrary commands | yes — any argv, any image present on the host |
| compile CUDA | yes — `nvcc 12.8.93` inside `nvidia/cuda:12.8.0-devel-ubuntu22.04` |
| use the real GPU | yes — GTX 1660, CC 7.5, verified inside the container |
| choose tools itself | yes — 9 tools in the catalog; the agent searched, chose and sequenced them |
| capture errors | yes — `not_found` 127, `not_runnable` 126, `container_error` 125/hook failure, `error_exit`, `timeout`, `oom_killed`, and signals 132/134/135/136/139 |
| collect artifacts | yes — everything under `/work` plus `collect_paths` via `docker cp`, hashed on both sides |
| keep history | yes — trails are append-only, one execution log per trail |
| limit resources | `--memory`, `--cpus`, `timeout_s` (the container is killed at the deadline) |

Distinct classifications, all verified on the real machine:

| situation | kind | crash |
|---|---|---|
| normal exit | `success` | no |
| missing binary in image | `not_found` (127) | no |
| compile failure | `error_exit` (2) | no |
| ordinary non-zero exit | `error_exit` (3) | no |
| harness timeout (killed) | `timeout` (137 + timed_out) | no |
| bad GPU spec / runtime hook failure | `container_error` | no |
| OOM killed | `oom_killed` | no |
| target segfault | `sigsegv` (139) | **yes** |

---

## D. Real experiment record

### D.1 Environment (acceptance A)

| field | measured |
|---|---|
| distro | Ubuntu 22.04.5 LTS (22.04) |
| kernel | 6.6.87.2-microsoft-standard-WSL2 |
| Docker | 29.8.2 (reachable as `pocdev`, no sudo) |
| GPU | NVIDIA GeForce GTX 1660, 6144 MiB |
| Compute capability | 7.5 |
| Driver / KMD | 610.47 (from the Windows host, via WSL) |
| CUDA toolkit | 12.8.93 (`nvcc`, `nvdisasm`, `cuobjdump` all execute) |
| GPU inside container | ok — `nvidia-smi` from inside the container sees the device |

### D.2 vector_add through the tool layer (acceptance B)

| field | value |
|---|---|
| run | `run-20261112T020759Z-42ac03` |
| trail | `trail0` |
| image | `nvidia/cuda:12.8.0-devel-ubuntu22.04` |
| image digest | `nvidia/cuda@sha256:54f18e2a8e1b3d03f77b9a6dc905533da46ac93a5513f10e8ba8e560db9fa5ab` |
| container | `e1bed94ae854` |
| argv | `bash -lc "nvcc -O2 -arch=sm_75 vector_add.cu -o vector_add && ./vector_add"` |
| exit | 0 (`success`), 2.0 s |
| evidence | `run-20261112T020759Z-42ac03#3` |
| source sha256 | `53c08235dc76dac4606f07c86fd5c0a8dd3f72bd8a15a69a3d96912d45856f1a` |
| binary | `trails/trail0/outputs/vector_add`, 1 007 080 B, sha256 `34763cd30aeb34bb8b6658f748a986c8a88b190e4094246b8df6e7ba54b858cd` |
| stdout artifact | `trails/trail0/logs/stdout.txt`, 620 B, sha256 `1870526d82210774152b5ca05fd754e461cb205820bf0aa7f530deea24f3bf25` |
| evidence log | `.local/runs/p19-acceptance-run-20261112T020759Z-42ac03/evidence.jsonl` |

Program output (as captured, licence banner trimmed):

```
GPU: NVIDIA GeForce GTX 1660
Compute Capability: 7.5
CUDA_KERNEL=PASS
ELEMENTS=1048576
RESULT=30
```

### D.3 Failure matrix (acceptance C)

| case | exit | kind | crash | leftover container |
|---|---|---|---|---|
| missing binary | 127 | `not_found` | no | none |
| ordinary non-zero | 3 | `error_exit` | no | none |
| compile failure | 2 | `error_exit` | no | none |
| timeout (3 s, `sleep 60`) | 137 | `timeout` | no | none |
| bad GPU spec (`device=99`) | 128 | `container_error` | no | none |

`gpu_cleanup` after the matrix reported `{"removed": []}` — nothing was left running.

### D.4 Autonomous run (acceptance D)

Goal given to the agent, with no tool instructions:

> 请检查当前 GPU 环境，并使用现有工具完成一次 CUDA 向量加法实验。验证计算结果，保存完整实验产物，并给出结论。

| field | value |
|---|---|
| run | `run-20261112T020810Z-207e0a` |
| decisions / executions | 10 / 20 |
| container executions | 4 |
| trails | `trail0`, `trail1`, `trail2` |
| tools it chose | `gpu_environment_probe`, `env_probe`, `fs_list`, `fs_read`, `trail_new`, `trail_write`, `container_exec`, `memory_search`, `memory_note` |
| evidence | 45 records, chain verified |
| tokens | 233 138 |
| wall clock | 151 s |

What it did, from the transcript and evidence:

1. probed the environment (host and inside a container) before touching the GPU;
2. read the staged sample, then wrote **its own** verification kernel (multiple kernels,
   host-side reference comparison, negative control, timing) rather than only running the
   sample;
3. built with `nvcc -O2 -arch=sm_75`, ran in a container, wrote per-step exit files and
   artifacts;
4. when an early attempt failed on a wrong path assumption, it inspected `/work` with
   `ls`/`find`, corrected itself, and recorded the lesson in case memory;
5. produced a conclusion that cites evidence ids and separates "tool output" from
   "inference".

Its own summary of the first failure is the useful part: the container said
`cc1plus: fatal error: inputs/vector_add_probe.cu: No such file or directory`, and the
agent diagnosed its own wrong assumption instead of blaming the backend.

---

## E. Tests

Separated as required: offline first, real environment second.

| group | command | result |
|---|---|---|
| unit + regression (offline) | `pytest -q` | **164 passed, 4 skipped** in 7.5 s |
| new P19 offline tests | `pytest tests/test_trails.py tests/test_worker.py tests/test_wsl_backend.py tests/test_gpu_tools.py tests/test_container_outcome.py -q` | 57 passed |
| real WSL/Docker/GPU | `GPUVULNAGENT_LIVE=1 pytest tests/test_live_gpu_backend.py -q` | **4 passed** in 12.0 s |
| real CUDA kernel | inside the above | `CUDA_KERNEL=PASS`, `RESULT=30` |
| autonomy | `python scripts/p19_acceptance.py --turns 10` | A/B/C/D all ok |
| compileall | `python -m compileall -q gpuvulnagent tests scripts` | clean |
| whitespace | `git diff --check` | clean |

The 4 skipped tests are the live ones, skipped by design when `GPUVULNAGENT_LIVE` is unset.
No mock is used to claim GPU support: the GPU claim rests on
`tests/test_live_gpu_backend.py` and acceptance B/D, which start real containers.

---

## F. Not implemented

1. **No kernel/GPU-driver isolation.** Containers share the WSL2 kernel and use the Windows
   NVIDIA driver. This backend is for Linux user-space tools, CUDA programs and GPU kernels.
   It cannot be used to claim isolation for kernel-mode or physical GPU driver bugs.
2. **No privileged mode, by design.** Experiments that genuinely need it are out of scope
   here and would need a VM or a dedicated machine.
3. **Single GPU host.** The backend talks to one WSL distro on one machine; `gpus` selects
   devices within it, but there is no scheduler across hosts.
4. **No image build/pull management.** The agent must use an image that already exists;
   `docker pull` is not exposed (network is `none` by default). Pulling is an operator task.
5. **No differential oracle.** The backend records paired runs and their artifacts, but
   "candidate vs control" verdicts are still the agent's/method's job, not automatic.
6. **Crash evidence stops at the exit status.** No core dumps, no `cuda-memcheck`, no WER;
   a segfault is recorded as `sigsegv` with stdout/stderr, not as a symbolized stack.
7. **`/mnt` is used for transfer, not for work.** Inputs and artifacts cross the 9p
   boundary; compile and run happen on ext4. Large-file streaming is chunked reads, not a
   sparse file protocol.
8. **Trail concurrency is per-run.** Two processes may append to the same trail only if the
   caller serialises them; the manifest write is not locked across processes.
