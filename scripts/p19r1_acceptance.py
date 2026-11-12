# -*- coding: utf-8 -*-
"""P19-R1 acceptance: evidence correctness on the real WSL/Docker/GTX 1660 machine.

    python scripts/p19r1_acceptance.py [--turns 12] [--skip-agent]

A. offline regression is a separate command (pytest); this script does the real parts.
C. two executions modify the same file name in one trail - both versions must survive.
D. a container plants a symlink to a host file - it must not enter the evidence.
E. exit(139) and a real SIGSEGV must be told apart, with and without the supervisor.
F. a timeout must be classified as a timeout and leave no container behind.
G. .env settings (distro, user, image, call timeout, pull policy) must actually take effect.
H. one real DeepSeek agent run that performs a CUDA experiment end to end.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gpuvulnagent.backends.trails import TrailStore  # noqa: E402
from gpuvulnagent.backends.wsl_docker import WslConfig, WslDockerBackend  # noqa: E402
from gpuvulnagent.config import ConfigLoader  # noqa: E402
from gpuvulnagent.evidence import ArtifactStore, EvidenceLog, Runner, verify_chain  # noqa: E402
from gpuvulnagent.memory.store import LayeredMemory  # noqa: E402
from gpuvulnagent.providers.deepseek import DeepSeekProvider  # noqa: E402
from gpuvulnagent.runtime.loop import AgentRuntime  # noqa: E402
from gpuvulnagent.runtime.state import new_run_id  # noqa: E402
from gpuvulnagent.runtime.workspace import Workspace  # noqa: E402
from gpuvulnagent.tools.build import build_assembly  # noqa: E402

IMAGE = "nvidia/cuda:12.8.0-devel-ubuntu22.04"
BASE_IMAGE = "nvidia/cuda:12.8.0-base-ubuntu22.04"
RESULTS: dict = {}

V1 = "#include <cstdio>\nint main(){puts(\"poc v1\");return 0;}\n"
V2 = "#include <cstdio>\nint main(){puts(\"poc v2 (mutated)\");return 0;}\n"
RETURNS_139 = "int main(void){return 139;}\n"
SEGFAULTS = "int main(){int *p=0;*p=1;return 0;}\n"


def record(name: str, payload: dict) -> None:
    RESULTS[name] = payload
    print("[%-28s] %-6s %s" % (name, payload.get("status", "?").upper(),
                               json.dumps({k: v for k, v in payload.items()
                                           if k not in ("status", "stdout", "stderr")},
                                          ensure_ascii=False)[:340]))


def backend(**overrides) -> WslDockerBackend:
    settings = ConfigLoader()
    config = WslConfig.from_settings(settings)
    for key, value in overrides.items():
        setattr(config, key, value)
    return WslDockerBackend(config)


def check_supervisor(backend_obj) -> None:
    try:
        state = backend_obj.supervisor()
    except Exception as exc:  # noqa: BLE001
        record("supervisor", {"status": "failed", "error": str(exc)})
        return
    record("supervisor", {"status": "ok" if state.get("ok") else "failed",
                          "sha256": state.get("sha256"), "static": state.get("static"),
                          "built": state.get("built")})


def check_c_snapshot(backend_obj, root: Path) -> None:
    """One trail, two executions, the same two file names written twice."""
    run_id = "run-p19r1-snapshot-" + new_run_id()
    trails = TrailStore(root / "trails", run_id)
    trail = trails.allocate(purpose="same file name, two mutations")
    command = ["bash", "-lc",
               "printf '%s' \"$SRC\" > /work/poc.cu && "
               "nvcc -O2 /work/poc.cu -o /work/poc && ./poc"]
    first = backend_obj.exec(trail, image=IMAGE, timeout_s=300, argv=command,
                             env={"SRC": V1})
    second = backend_obj.exec(trail, image=IMAGE, timeout_s=300, argv=command,
                              env={"SRC": V2})

    exec0 = trail.root / "execs" / "exec00" / "outputs"
    exec1 = trail.root / "execs" / "exec01" / "outputs"
    checks = {
        "exec00_dir": exec0.is_dir(),
        "exec01_dir": exec1.is_dir(),
        "v1_source_kept": (exec0 / "poc.cu").is_file(),
        "v2_source_kept": (exec1 / "poc.cu").is_file(),
        "sources_differ": (exec0 / "poc.cu").read_bytes() != (exec1 / "poc.cu").read_bytes(),
        "v1_is_the_original": (exec0 / "poc.cu").read_text() == V1,
        "v2_is_the_mutation": (exec1 / "poc.cu").read_text() == V2,
        "v1_binary_kept": (exec0 / "poc").is_file(),
        "v2_binary_kept": (exec1 / "poc").is_file(),
        "binaries_differ": (exec0 / "poc").read_bytes() != (exec1 / "poc").read_bytes(),
        "first_created": "poc.cu" in (first.snapshot.get("created") or []),
        "second_changed": "poc.cu" in (second.snapshot.get("changed") or []),
        "evidence_links_own_dir": all(item.name.startswith("execs/exec00/")
                                      for item in first.artifacts),
    }
    record("C_snapshot_two_versions", {
        "status": "ok" if all(checks.values()) else "failed",
        "trail": trail.trail_id,
        "exec_dirs": [first.exec_dir, second.exec_dir],
        "v1_sha256": sha(exec0 / "poc.cu") if (exec0 / "poc.cu").is_file() else "",
        "v2_sha256": sha(exec1 / "poc.cu") if (exec1 / "poc.cu").is_file() else "",
        "binary_v1_sha256": sha(exec0 / "poc") if (exec0 / "poc").is_file() else "",
        "binary_v2_sha256": sha(exec1 / "poc") if (exec1 / "poc").is_file() else "",
        "checks": checks,
        "stdout": (second.stdout or "")[-160:]})


def check_d_symlink(backend_obj, root: Path) -> None:
    run_id = "run-p19r1-symlink-" + new_run_id()
    trails = TrailStore(root / "trails", run_id)
    trail = trails.allocate(purpose="symlink escape attempt")
    result = backend_obj.exec(
        trail, image=IMAGE, timeout_s=300, argv=[
            "bash", "-lc",
            "ln -s /etc/passwd /work/leak-passwd.txt; "
            "ln -s /home/pocdev /work/leak-home; "
            "echo real-output > /work/real.txt; ls -l /work"],
        env={})
    artifacts = trail.root / "execs" / "exec00" / "outputs"
    leaked = []
    for path in artifacts.rglob("*"):
        if path.is_file() and b"root:x:" in path.read_bytes():
            leaked.append(str(path))
    skipped = {item["name"]: item for item in
               (result.snapshot.get("skipped_symlinks") or [])}
    checks = {
        "leak_file_skipped": "leak-passwd.txt" in skipped,
        "leak_dir_skipped": "leak-home" in skipped,
        "no_leak_in_artifacts": not leaked,
        "real_output_collected": (artifacts / "real.txt").is_file(),
        "skipped_reason_recorded": "symlink" in
                                   str(skipped.get("leak-passwd.txt", {}).get("reason", "")),
    }
    record("D_symlink_escape", {
        "status": "ok" if all(checks.values()) else "failed",
        "trail": trail.trail_id, "checks": checks,
        "skipped": list(skipped), "leaked_files": leaked})


def check_e_exit139_vs_sigsegv(backend_obj, root: Path) -> None:
    run_id = "run-p19r1-signals-" + new_run_id()
    trails = TrailStore(root / "trails", run_id)
    trail = trails.allocate(purpose="exit(139) vs SIGSEGV")
    trail.add_file("returns139.c", RETURNS_139)
    trail.add_file("segfaults.c", SEGFAULTS)

    build = backend_obj.exec(
        trail, image=IMAGE, timeout_s=300, argv=[
            "bash", "-lc",
            "gcc -O0 returns139.c -o returns139 && gcc -O0 segfaults.c -o segfaults && echo built"])
    normal = backend_obj.exec(trail, image=IMAGE, timeout_s=120,
                              argv=["./returns139"])
    crashed = backend_obj.exec(trail, image=IMAGE, timeout_s=120,
                               argv=["./segfaults"])
    # The old, wrong inference: a shell reports the child's signal as exit 139 too.
    wrapped = backend_obj.exec(trail, image=IMAGE, timeout_s=120,
                               argv=["bash", "-lc", "./segfaults"])

    checks = {
        "build_ok": build.exit_code == 0,
        "exit139_is_not_a_crash": (normal.exit_code == 139
                                   and normal.termination["kind"] == "error_exit"
                                   and normal.termination["crash"] is False
                                   and normal.signal_verified is True),
        "sigsegv_is_a_crash": (crashed.termination["kind"] == "sigsegv"
                               and crashed.termination["crash"] is True
                               and crashed.signal_verified is True
                               and crashed.signaled is True),
        # bash re-raises the child's signal when the foreground job dies of one, so the
        # supervisor still sees a signal; a program that calls exit(139) is different.
        "shell_propagates_signal": (wrapped.termination["crash"] is True
                                    and wrapped.signal_verified is True),
    }
    record("E_exit139_vs_sigsegv", {
        "status": "ok" if all(checks.values()) else "failed",
        "trail": trail.trail_id, "checks": checks,
        "exit139": {"exit": normal.exit_code, "kind": normal.termination["kind"],
                    "crash": normal.termination["crash"],
                    "supervision": normal.supervision},
        "sigsegv": {"exit": crashed.exit_code, "kind": crashed.termination["kind"],
                    "crash": crashed.termination["crash"],
                    "signal": crashed.signal_name,
                    "supervision": crashed.supervision},
        "via_shell": {"exit": wrapped.exit_code, "kind": wrapped.termination["kind"],
                      "crash": wrapped.termination["crash"]}})


def check_f_timeout(backend_obj, root: Path) -> None:
    run_id = "run-p19r1-timeout-" + new_run_id()
    trails = TrailStore(root / "trails", run_id)
    trail = trails.allocate(purpose="timeout cleanup")
    result = backend_obj.exec(trail, image=IMAGE, timeout_s=3, argv=[
        "bash", "-lc", "echo started; sleep 120; echo finished"])
    leftovers = backend_obj.cleanup(run_id)
    checks = {
        "timed_out": result.timed_out is True,
        "kind_timeout": result.termination["kind"] == "timeout",
        "not_a_crash": result.termination["crash"] is False,
        "cleanup_ok": result.cleanup_ok is True,
        "no_leftovers": leftovers.get("removed") == [],
        "stdout_kept": "started" in (result.stdout or ""),
    }
    record("F_timeout_cleanup", {
        "status": "ok" if all(checks.values()) else "failed",
        "trail": trail.trail_id, "checks": checks, "cleanup": result.cleanup,
        "leftovers": leftovers})


def check_g_config(root: Path) -> None:
    keys = ("WSL_DISTRO", "WSL_USER", "GPU_IMAGE", "WSL_CALL_TIMEOUT", "GPU_PULL_POLICY")
    saved = {key: os.environ.get(key) for key in keys}
    try:
        _check_g_config(root)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _check_g_config(root: Path) -> None:
    os.environ["WSL_DISTRO"] = "Ubuntu-22.04"
    os.environ["WSL_USER"] = "pocdev"
    os.environ["GPU_IMAGE"] = BASE_IMAGE
    os.environ["WSL_CALL_TIMEOUT"] = "120"
    os.environ["GPU_PULL_POLICY"] = "never"
    settings = ConfigLoader()
    configured = WslConfig.from_settings(settings)
    active = WslDockerBackend(configured)
    run_id = "run-p19r1-config-" + new_run_id()
    trails = TrailStore(root / "trails", run_id)
    trail = trails.allocate(purpose="config effect")
    used = active.exec(trail, timeout_s=120, argv=["nvidia-smi", "-L"])
    missing = active.exec(trail, timeout_s=60,
                          argv=["true"], image="nvidia/cuda:12.8.0-devel-ubuntu22.04-r1missing",
                          pull_policy="never")

    os.environ["WSL_USER"] = "no-such-user-r1"
    broken = WslConfig.from_settings(ConfigLoader())
    broken_backend = WslDockerBackend(broken)
    broken_error = ""
    try:
        broken_backend.probe(force=True)
    except Exception as exc:  # noqa: BLE001
        broken_error = "%s: %s" % (type(exc).__name__, exc)
    os.environ["WSL_USER"] = "pocdev"

    checks = {
        "distro_applied": configured.distro == "Ubuntu-22.04",
        "user_applied": configured.user == "pocdev",
        "image_applied": configured.image == BASE_IMAGE,
        "call_timeout_applied": configured.call_timeout == 120,
        "pull_policy_applied": configured.pull_policy == "never",
        "default_image_used": used.image == BASE_IMAGE,
        "pull_policy_recorded": used.pull_policy == "never",
        "missing_image_refused": (missing.ok is False
                                  and missing.termination["kind"] == "container_error"),
        "bad_user_is_reported": "no-such-user-r1" in broken_error,
    }
    record("G_config_effect", {
        "status": "ok" if all(checks.values()) else "failed",
        "checks": checks, "image_used": used.image,
        "missing_image": {"kind": missing.termination["kind"],
                          "error": used.error or missing.to_dict().get("error", "")},
        "broken_user_error": broken_error[:200]})


def check_h_agent(settings: ConfigLoader, turns: int) -> None:
    run_dir = ROOT / ".local" / "runs" / ("p19r1-autonomy-" + new_run_id())
    goal = (
        "请检查当前 GPU 环境，并使用现有工具完成一次 CUDA 向量加法实验。"
        "验证计算结果，保存完整实验产物，并给出结论。\n"
        "要求：至少做两次执行（例如先编译再运行，或先跑基线再跑变异），"
        "确认第二次执行没有覆盖第一次的产物；结论必须引用真实 evidence id；"
        "区分「工具输出显示」与「推测」；把实验记录写入 case 记忆（scope=case）。"
        "工作区 samples/ 里有一个参考程序。"
    )
    provider = DeepSeekProvider(api_key=settings.llm.api_key, model=settings.llm.model,
                                base_url=settings.llm.base_url, timeout=settings.llm.timeout,
                                max_attempts=settings.llm.max_attempts,
                                temperature=settings.llm.temperature,
                                max_tokens=settings.llm.max_tokens)
    runtime = AgentRuntime(goal=goal, root=run_dir, provider=provider, max_turns=turns,
                           run_timeout=1800, shell_timeout=120, case_id="P19R1-AUTONOMY",
                           research_root=ROOT / "research_archive",
                           toolchain_root=ROOT / "toolchains",
                           enable_search=bool(settings.tavily_api_key),
                           backend_config=WslConfig.from_settings(settings))
    runtime.workspace.write("samples/vector_add.cu",
                            (ROOT / "data" / "cases" / "cuda_smoke" /
                             "vector_add.cu").read_text(encoding="utf-8"))
    started = time.time()
    result = runtime.run()
    check = verify_chain(run_dir / "evidence.jsonl")
    execs, trails, container_execs = 0, set(), 0
    for line in (run_dir / "evidence.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("kind") == "exec":
            execs += 1
            if rec.get("backend"):
                container_execs += 1
        if rec.get("trail"):
            trails.add(rec["trail"])
    record("H_agent_end_to_end", {
        "status": "ok" if container_execs and check["ok"] and len(result.final or "") > 200
                  else "failed",
        "run_id": result.run_id, "run_dir": str(run_dir), "stopped": result.stopped,
        "decisions": result.decisions, "executions": len(result.turns),
        "container_execs": container_execs, "execs_records": execs,
        "trails": sorted(trails), "evidence_records": check["records"],
        "evidence_ok": check["ok"], "usage": result.usage.to_dict(),
        "seconds": round(time.time() - started, 1),
        "tools_used": sorted({turn.tool for turn in result.turns}),
        "final_head": result.final[:600]})


def sha(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--turns", type=int, default=12)
    parser.add_argument("--skip-agent", action="store_true")
    parser.add_argument("--only", default="all")
    args = parser.parse_args()

    settings = ConfigLoader()
    root = ROOT / ".local" / "runs" / ("p19r1-acceptance-" + new_run_id())
    root.mkdir(parents=True, exist_ok=True)
    active = WslDockerBackend(WslConfig.from_settings(settings))
    record("backend", {"status": "ok", "run_dir": str(root),
                       "config": active.describe()})

    only = args.only
    if only in ("all", "s"):
        check_supervisor(active)
    if only in ("all", "c"):
        check_c_snapshot(active, root)
    if only in ("all", "d"):
        check_d_symlink(active, root)
    if only in ("all", "e"):
        check_e_exit139_vs_sigsegv(active, root)
    if only in ("all", "f"):
        check_f_timeout(active, root)
    if only in ("all", "g"):
        check_g_config(root)
    if only in ("all", "h") and not args.skip_agent:
        check_h_agent(settings, args.turns)

    out = ROOT / ".local" / "logs" / "p19r1_acceptance.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(RESULTS, ensure_ascii=False, indent=1), encoding="utf-8")
    print("\nwritten: %s" % out)
    failures = [name for name, item in RESULTS.items() if item.get("status") == "failed"]
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
