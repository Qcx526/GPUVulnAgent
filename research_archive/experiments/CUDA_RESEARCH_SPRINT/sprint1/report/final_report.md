# trial0 — final report

**Goal.** # Sprint: 自主研究多个 CUDA Toolkit CVE

起点：docs/P22_CUDA_TOOLKIT_CVE_INVENTORY.md 里的 26 条 CVE。
不要只做 nvdisasm；优先覆盖 cuobjdump 与 nvJPEG，nvdisasm 最多一个。

自己排序、自己选 2-3 个做，每个 CVE 一个 trail。对每个 CVE：
1. 读官方公告/NVD，写清 CWE、受影响版本、修复版本、触发条件。
2. 取受影响与修复版本（优先 NVIDIA 签名 APT 的独立 deb；nvJPEG 可用容器内 libnvjpeg）。
3. 用 nvcc 造合法基线，再按你提出的假设做结构感知变异；每轮记录假设、偏移、旧值、新值、脚本、SHA256。
4. 真实执行：受影响 vs 修复，同字节；用监督器判信号，不要用 139 推断。
5. 分层结论：执行过 / 输入被接受 / 到达目标路径 / 崩溃 / 差分 / 机制 / 归因。

执行纪律（很重要）：
- 前 3 个决策内必须有一次真实 container_exec。参数只用 argv、network、as_root、timeout_s。
- 工具报 bad arguments 时读 accepted parameters，立刻改，不要连续两轮讨论同一个错误。
- 每个 CVE 预算约 12 个决策；没进展就记录 INCONCLUSIVE 并换下一个，不要死磕。
- 发现与所选 CVE 无关的异常，用 finding_new 单独登记。

环境：WSL2 + Docker，镜像 nvidia/cuda:12.8.0-devel-ubuntu22.04；容器内可 apt（network=bridge, as_root=true）。
历史版本 nvdisasm/cuobjdump 在 WSL `/home/pocdev/gpuvulnagent-worker/refs/` 下，用前先 ls 确认。
nvidia/cuda:12.8 devel 镜像内含 libnvjpeg.so.12.3.5.57 与头文件。
不改 Windows 驱动。总预算 600k token。

**Status.** stopped=token_budget, artifacts=12 (binary=4, file=6, log=1, script=1), evidence records=87

## Artifacts

| id | type | v | origin | sha256 | path |
|---|---|---|---|---|---|
| `art-6c1f783d8461` | script | 1 | generated | `954608866e7fde9d` | `session/run/workspace/stage_refs.sh` |
| `art-3a67f093ee2e` | binary | 1 | generated | `ad1d0f0699f46603` | `session/run/workspace/refs/cuobjdump-12-8-12.8.55-1/usr/local/cuda-12.8/bin/cuobjdump` |
| `art-6b258e9c835e` | file | 1 | generated | `5844f4087a5d4273` | `session/run/workspace/refs/cuobjdump-12-8-12.8.55-1/usr/share/doc/cuda-cuobjdump-12-8/changelog.Debian.gz` |
| `art-0d2948fdb820` | file | 1 | generated | `e2c71babfd18a8e6` | `session/run/workspace/refs/cuobjdump-12-8-12.8.55-1/usr/share/doc/cuda-cuobjdump-12-8/copyright` |
| `art-ba7d0d991e58` | binary | 1 | generated | `1763b5367167e739` | `session/run/workspace/refs/cuobjdump-13-0-13.0.85-1/usr/local/cuda-13.0/bin/cuobjdump` |
| `art-2571305fba65` | file | 1 | generated | `d80dd517304ce2c5` | `session/run/workspace/refs/cuobjdump-13-0-13.0.85-1/usr/share/doc/cuda-cuobjdump-13-0/changelog.Debian.gz` |
| `art-30f485f66764` | file | 1 | generated | `f176e5fd245a4ff1` | `session/run/workspace/refs/cuobjdump-13-0-13.0.85-1/usr/share/doc/cuda-cuobjdump-13-0/copyright` |
| `art-4a4c5fa87f1c` | binary | 1 | generated | `3c27bded09bd8778` | `session/run/workspace/refs/nvdisasm-13-0-13.0.85-1/usr/local/cuda-13.0/bin/nvdisasm` |
| `art-81369aecb230` | file | 1 | generated | `567e4d0f58aee172` | `session/run/workspace/refs/nvdisasm-13-0-13.0.85-1/usr/share/doc/cuda-nvdisasm-13-0/changelog.Debian.gz` |
| `art-01ab1adbbf9f` | file | 1 | generated | `f176e5fd245a4ff1` | `session/run/workspace/refs/nvdisasm-13-0-13.0.85-1/usr/share/doc/cuda-nvdisasm-13-0/copyright` |
| `art-58a9632b218a` | log | 1 | generated | `a4e53f38f338ccfb` | `session/run/workspace/marker.txt` |
| `art-dd5fba689aa6` | binary | 1 | generated | `e95ed268d3614323` | `evidence/trails/trail1/execs/exec03/outputs/base.cubin` |

## Conclusions

# CUDA-SPRINT-1 阶段结论（决策预算耗尽，未完成的 CVE 尚未验证）

## 1. 实际做了什么

**环境与素材定位**
- 工作区初始为空，`fs_read docs/P22_CUDA_TOOLKIT_CVE_INVENTORY.md` 返回 null；实际文件在 `F:\qcx\code\GPUVulnAgent\docs\P22_CUDA_TOOLKIT_CVE_INVENTORY.md`（运行 #22 读到了前 25 行，表头为 `CVE | Component | CWE | Affected | Fixed | Bulletin | Source status`，26 条里每条都标 "search result only"）。
- WSL refs 目录用 `ls` 确认存在（运行 `run-20261112T130644Z-47466b#50`）：`cuobjdump-12-8-12.8.55-1`、`cuobjdump-13-0-13.0.85-1`、`nvdisasm-12-8-12.8.90-1`、`nvdisasm-13-0-13.0.85-1`。**受影响版本与修复版本的 cuobjdump 都在手上**。
- 容器实测（#36，镜像 `nvidia/cuda:12.8.0-devel-ubuntu22.04`，digest `sha256:54f18e2a…`）：系统 `nvcc 12.8.61`、`cuobjdump 12.8.55`、`nvdisasm 12.8.55`，`libnvjpeg.so.12.3.5.57`（7.8 MB）+ `nvjpeg_static.a`；容器内 `/home/pocdev/...` 不可见（NO_REFS），WSL 侧 refs 必须由我显式搬入。
- 摸索出 `container_exec` 的 staging 规则（多次试错，#60 #78 #73）：`/work` 是 **trail 目录**，且只 stage **平铺文件**，不映射 `inputs/` 子目录，`/work/refs/` 不会出现。`fs_write` 写的内容落在 workspace，容器里看不到（marker.txt 未出现，#78 的 `find` 只找到 `/work/base.cu`）。

**来源核实（CVE-2025-23339）**
- `web_search`（#31）+ `web_extract` Talos 报告 TALOS-2025-2155（#41、#47 续读）取得完整机制：CWE-121，受影响 **cuobjdump 12.8.55**，修复在 CUDA 13.0.85（NVIDIA bulletin a_id/5661，CVSS 7.8，公告文本明确写 "stack-based buffer overflow … malicious ELF file"）。Talos 给出精确栈布局：`push` 6×8 + `sub rsp,0x888` ⇒ 返回地址在 `rsp+0x8b8`，`rbp = rsp+0x80`，store 用 `[rbp+r14*8-8]`/`[rbp+r14*8-4]`，故 **约 `0x108` 次迭代 / `0x210` 个 LEB128 值**即可踩到返回地址；循环退出条件只取决于解出的 DW_FORM 是否为 0，**没有任何计数上限**。
- 同批还确认了 nvJPEG 三个 CVE 的公告口径（#33）：CVE-2025-23273 CWE-369 除零 / CVE-2025-23274 CWE-125 OOB read / CVE-2025-23275 CWE-787 GPU OOB write，均为 "all versions prior to nvJPEG 13.0.0"，修复 13.0.0。

**基线构造（已执行成功）**
- `trail1/inputs/base.cu` 写好（含模板、struct、`__global__` kernel，SHA256 记录在 #64）；`nvcc -arch=sm_75 -G -cubin` 在容器内编译成功（#86）：`base.cubin` 10216 字节，SHA256 `e95ed268d3614323ea14ed440ad74b910dc7e0a3095be829f18e927c52d5e19a`，并确认 `cuobjdump --dump-elf` 能识别 `.debug_abbrev`（偏移 `0x1875`，大小 `0x77`）并逐条打印 DW_AT/DW_FORM 对 —— 即目标解析路径在基线上是**真实可达**的。
- 结构感知变异器 `trail1/inputs/mutate.py` 已写好（#83，SHA256 `a68e8a2401…`）：通过真实 section header table + 真实 `.shstrtab` 定位 `.debug_abbrev`，在 **EOF 追加**新 body（`01 11 01` 前导 + 0x260 个 `0x41` LEB128 + 终止 0），只改该 section 的 `sh_offset`/`sh_size`，其余字节不动；同时生成 **paired control**（原 body + 原 offset/size），用于证明 old==new 时字节完全一致。记录字段包含 shdr 偏移、old/new sh_offset、old/new sh_size、old/new body SHA256、pattern、nvalues、src/dst SHA256。

## 2. 有证据的结论

- 工具链事实全部有证据：#36（容器内版本 + libnvjpeg 版本）、#50（refs 里 12.8.55 与 13.0.85 两套 cuobjdump/nvdisasm 完备）、#86（基线 cubin 编译成功、`.debug_abbrev` 存在且被 cuobjdump 解析）。
- CVE-2025-23339 的 CWE/受影响/修复/触发条件来自一手公告与 Talos 报告：#41/#47（CWE-121、12.8.55 确认受影响、`--dump-elf` + `.debug_abbrev` 触发、无界循环写栈、0x210 个 LEB128 值到返回地址）。
- nvJPEG 三个 CVE 的公告口径有证据：#33。

**没有任何"崩溃/差分/机制"级别的 finding。** 我没有执行过一次受影响 vs 修复的同字节对比：变异器写完后没有来得及在容器里跑 `python3 mutate.py base.cubin` + 两个 cuobjdump 的执行，因此 `mut.cubin` / `control.cubin` 的 SHA256、退出信号、监督器判定全部不存在。按证据规则，cuobjdump 这条 CVE 目前只能算 **hypothesis + 已备好实验器材**，不能写成 finding。

## 3. 仍是推测的部分

- **推测**：给定上述无界循环与栈写入布局，0x260 个 `0x41` 值（约 0x130 次迭代 > 0x108）应能覆盖 12.8.55 的返回地址并在 `--dump-elf` 下崩溃。这是从 Talos 的偏移算式推出来的，**我自己没有观测到崩溃**。
- **推测**：13.0.85 在同一输入上不会崩（修复应加入计数/边界检查），但该仓库树的 `sub rsp,0x888` 类栈帧也可能变化，未验证。
- **未验证**：`0x41` 是否被 cuobjdump 的 LEB128 解码器接受为合法 DW_AT（0x41 落在 DW_AT 空间内，但不是有效的 DW_FORM），若解析器提前 bail 则需换成 Talos 用的递增模式。
- nvJPEG 三条（23273/23274/23275）我**完全没有**开始：既没有写 PoC 解码器，也没有取容器内 12.3.5.57 与 13.0 的 libnvjpeg 做同字节对比。任何关于它们的实现层结论都是空白。

## 4. 还缺什么条件

1. 至少 2–3 个决策：把 `mutate.py`、`base.cu` 平铺进 trail，容器内 `nvcc -G -cubin` → `python3 mutate.py` → 分别用 `/work/cuobjdump-12.8.55` 和 `/work/cuobjdump-13.0.85` 跑 `--dump-elf mut.cubin`，用 `gpuvuln_supervise`（已在 `/work/.gpuvulnagent/gpuvuln_supervise`，#78 见到）判信号，而不是靠退出码 139 推断；同时必须跑 `control.cubin` 作为同字节差分基线。
2. nvJPEG 需要：一个最小 C 程序链接 `libnvjpeg`，用 `jpeg_inspect`/`jpeg_mutate_dimensions` 造尺寸异常的合法 JPEG（对应 23275 的 "certain image dimensions"、23273 的除零），并取得 nvJPEG 13.0 的 `libnvjpeg.so.13`（容器内无，需从 APT/容器外取）才能做受影响/修复同字节对比。
3. staging 限制要绕开：只能用平铺文件名（如 `cuobjdump-12.8.55`、`base.cu`、`mutate.py`），不能在 `/work` 下建目录；`fs_write` 的产物不会进容器，路径要通过 WSL 侧 `cp` 放进各 trail 的 `inputs/`。

一句话：本轮把 **CVE-2025-23339 的读料、双版本二进制定位、合法 DWARF 基线、结构感知变异器与 paired control 全部落地并留下证据**，但真实执行与差分尚未发生；nvJPEG 一条都没启动。全部结论停留在"输入被接受"之前的准备阶段。
