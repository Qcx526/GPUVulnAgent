# GPUVulnAgent 迁移与独立工程初始化 — 最终报告

**日期**：2026-11-11
**工作区**：`F:\qcx\code\GPUVulnAgent`
**结论**：新工程已独立建立、可独立启动、可独立验收；旧仓库未被修改；历史证据未被改写；未发现密钥泄露。

---

## 1. 迁移来源及精确 Commit

| 角色 | 引用 | Commit | 校验方式 |
|---|---|---|---|
| 旧仓库 | https://github.com/Qcx526/cuda_poc_generator | — | 新工作区内只读克隆 `.local/migration_source/repo` |
| main | `origin/main` | `0e299aff954e797b94d3b48bec666ca5d92df423` | 克隆内 `cat-file` 存在 |
| 原始 Pipeline 归档分支 | `archive/pre-agent-runtime-2026-11-11` | `0a119a0dc017141fc7478f0317c39d89fe149f01` | 同上；分支仍保留在旧仓库 |
| **Agent 源码基线（本次迁移基线）** | `research/autonomous-agent-completion` | **`c80efe18fcb60a1986f7d3dc570268356866d73c`** | worktree `git rev-parse HEAD` 与 `archive_p18.py` 内断言一致 |

迁移方式：`git clone --no-checkout` → `git worktree add --detach c80efe18…` 到
`.local/migration_source/tree`，**只读**读取。整个过程未在旧仓库执行任何写操作（无 commit、
无 push、无分支删除、无 reset）。

> 说明：克隆期间 GitHub 连接一度不稳定，最终完整克隆成功（`.git` 7.7 MB，277 个提交）。
> 归档脚本会再次断言 `HEAD == c80efe18` 才允许复制，防止在错误基线上归档。

---

## 2. 迁移的 Agent 模块

旧 `agent/` 包被拆解重写为 `gpuvulnagent` 包，逐文件对应关系：

| 旧文件 | 新位置 | 处理方式 |
|---|---|---|
| `agent/runtime.py`（18.9 KB） | `runtime/loop.py`、`runtime/protocol.py`、`runtime/state.py`、`context/prompts.py`、`context/observation.py` | 保留开放式循环、resume 语义、观察渲染；新增原生 tool_calls 主路径、多调用、墙钟预算、收尾回合 |
| `agent/evidence.py`（10.0 KB） | `evidence/log.py`、`evidence/artifacts.py`、`evidence/runner.py`、`evidence/outcome.py`、`evidence/redact.py` | 保留 hash chain 与 artifact store；终止原因独立分类；`evidence_id` 落盘可追溯 |
| `agent/workspace.py`（1.9 KB） | `runtime/workspace.py` | 路径保护逻辑保留，补 `workspace` 只读/写入语义 |
| `agent/registry.py`（9.1 KB） | `registry/spec.py`、`registry/registry.py` | 删除"扫描 `src/` 发现工具"；参数改为 JSON-Schema 类型；冲突显式记录 |
| `agent/memory.py`（3.6 KB） | `memory/models.py`、`memory/store.py` | 从"每 run 一个文件"扩展为 run/case/global 三层，finding 的 evidence 需真实可解析 |
| `agent/tools_builtin.py`（10.7 KB） | `tools/builtin.py` | 保留 shell/fs/http/artifact/env/memory；新增 `run_program`、`tool_search`、`tool_describe`、`toolchain_lookup`、`memory_search`、`memory_refute` |
| `agent/tavily_provider.py`（8.0 KB） | `providers/tavily.py` | 保留"未配置是正常状态"的设计，改为返回 `ToolSpec` |
| `agent/native_tools.py`（2.4 KB） | 融入 `providers/base.py` + `runtime/loop.py` | 不再是一个没人调用的适配器：原生调用成为 Runtime 主路径 |
| `agent/cli.py`（2.0 KB） | `cli.py` | 新增 `run/tools/doctor/memory/bench/verify` 六个子命令，去掉对 `src.*` 的导入 |

**保留的原有正确设计（逐条）**：开放式 Agent Loop、Tool Registry、ToolExecutionRecord、
Evidence Hash Chain、Artifact Store、Workspace 路径保护、Research Memory、Resume、DeepSeek
Provider、Tavily Provider、Token Usage、按工具类型组织 Observation。

**没有保留的部分**：`build_registry(legacy=True)` 的 `src/` 扫描、`fn_signature` 全字符串参数、
`to_openai_tools` 仅用于测试的适配器、per-run 单一 memory 文件。

---

## 3. 被重写的配置与 Provider

| 旧 | 行数/依赖 | 新 | 说明 |
|---|---|---|---|
| `src/config_loader.py` | 278 行，依赖 `PyYAML` + `src.utils` | `gpuvulnagent/config/loader.py` | 项目根 `.env`（自带解析器，无 `python-dotenv` 依赖）；优先级 **进程环境 > `.env` > `configs/default.yaml` > 默认值**；路径相对项目根解析；数字非法即报错不静默取默认 |
| `src/llm_client.py` | 550 行，依赖 `langchain-openai` + `langchain-core` + `httpx` | `gpuvulnagent/providers/deepseek.py`（约 220 行，仅 `urllib`） | OpenAI 兼容 `/chat/completions`；原生 `tools`/`tool_choice=auto`；`response_format=json_object` 可选；408/409/425/429/5xx 有界退避重试，400/401/403/404 立即失败；usage 真实记录（无则不估算）；超时可被 Runtime 按剩余预算收窄 |

`providers/base.py` 定义 `Message/ToolCall/Usage/ProviderResponse/Provider/ProviderError`，
Provider 抽象保留，换模型只需实现 `chat()`。

---

## 4. 新工程完整目录树

```
GPUVulnAgent/
├── gpuvulnagent/
│   ├── adapters/{elf_cubin,jpeg}/
│   ├── benchmarks/{crash,metrics,runner,summary}.py
│   ├── config/loader.py
│   ├── context/{observation,prompts}.py
│   ├── discovery/{catalog,manifest}.py
│   ├── evidence/{artifacts,hashing,log,outcome,redact,runner}.py
│   ├── memory/{models,store}.py
│   ├── providers/{base,deepseek,tavily}.py
│   ├── registry/{spec,registry}.py
│   ├── runtime/{loop,protocol,state,workspace}.py
│   ├── tools/{build,builtin}.py
│   └── cli.py, __main__.py
├── tests/                 13 个测试文件 + conftest + support
├── scripts/               setup_toolchain.py, archive_p18.py, acceptance.py
├── configs/default.yaml
├── data/{cases,benchmarks,knowledge}/
├── docs/                  本报告
├── toolchains/
│   ├── binary_tools/cuda-{11.2,12.4,13.4}/bin/{cuobjdump,nvdisasm}.exe
│   ├── compilers/cuda-12.4/{bin,nvvm}/
│   ├── cuda/nvjpeg/{11.2,12.4,13.2.2}/
│   ├── debuggers/README.md, installers/README.md
│   └── manifests/toolchain_manifest.json
├── research_archive/
│   ├── legacy_pipeline/{README,PIPELINE_INVENTORY}.md      （指针，不含源码）
│   ├── p17/{runs,r2_acceptance,16 份 P17 文档}
│   ├── p18/{original,goals,P18 最终报告}
│   ├── migration/{SHA256SUMS.txt,migration_manifest.json,SOURCE_AUDIT.md}
│   └── memory/{global,cases}/
├── .local/{runs,artifacts,logs,cache,tmp,migration_source}/   （不入 Git）
├── .env.example, .env（本地凭证，已忽略）, .gitignore
├── pyproject.toml, README.md
```

包名 `gpuvulnagent`，48 个 `.py` 源文件，757 KB。

---

## 5. 工具发现机制

P18 的根因是"未注册即不可见"。新机制的三个层次：

1. **ToolRegistry**（显式注册）：内建工具 + 适配器 + 可选 Provider 工具，冲突记录不覆盖。
2. **CapabilityCatalog**（独立索引，`discovery/catalog.py`）：在适配器**导入前**登记其用途、
   位置、支持格式、依赖、可运行性与原因；同时索引 manifest 里的二进制。
   - `tool_search(query, formats, requires, available_only)`：按名称/用途/**文件格式**/**依赖**搜索
   - `tool_describe(name)`：参数、用法、位置、能否运行、不能运行的原因、未注册的说明
   - `toolchain_lookup(name)`：manifest 中的版本、SHA256、路径、可运行性
3. **Manifest**（`discovery/manifest.py`）：运行时只认 manifest，不硬编码 `C:\`/`D:\`。

实测（真实结果，非 mock）：

```
$ gpuvulnagent tools --search jpeg
jpeg_inspect            adapter  ok   Read a JPEG's marker structure: SOI/APP/DQT/DHT/SOF/SOS/EOI...
jpeg_mutate_dimensions  adapter  ok   Write one plan: set the SOF frame width/height...
nvjpeg64_12.dll-12.4    binary   no   nvJPEG from CUDA 12.4
                                     reason: nvjpeg64_12.dll is a library, not an executable
{"total": 33, "available": 28,
 "by_kind": {"binary": 12, "tool": 16, "adapter": 5},
 "unavailable": ["nvjpeg.h-13.2.2", "nvjpeg.lib-13.2.2", "nvjpeg64_11.dll-11.2",
                 "nvjpeg64_12.dll-12.4", "nvjpeg64_13.dll-13.2.2"]}
```

5 个不可运行项都是库/头文件（原因如实标注），不是缺失的适配器。

`adapters.ADAPTERS` 中任一适配器导入失败时，`catalog.add_unavailable()` 会保留条目并写明
`requires`/`reason`——"没有该能力"与"有该能力但缺依赖"不再混为一谈。

**写入边界**：项目源码目录只读（`Workspace.resolve` 拒绝逃逸）；Agent 自建文件只进
`<run>/workspace/`。

---

## 6. Native Tool Calling 验收

真实端点：`deepseek-v4.1-flash-1017`（`.env` 中配置的 OpenAI 兼容端点）。

| 项 | 结果 |
|---|---|
| 纯文本往返 | 返回「收到」，`usage={prompt:35, completion:16, total:51}`，延迟 1172 ms |
| 原生 `tool_calls` | `mode=native`、`finish_reason=tool_calls`、`call_id=call_8ba4cd…`、`arguments={}` 正确解析 |
| 多工具单响应 | 单测 `test_one_response_may_contain_several_tool_calls` 覆盖，2 个 `tool_call_id` 均落证据 |
| 工具结果回灌 | 每条工具结果以 `role=tool` + 原 `tool_call_id` 进入下一请求；`test_native_tool_call_records_id_and_feeds_result_back` 断言 |
| JSON fallback | `mode=json_fallback` 时 `via=json_fallback` 落证据，结果以 user 回合回灌 |
| 参数错误 | 未派发即 `status=dispatch_error`，不产生"操作失败"的假象 |
| Token Usage | `run.usage` 累加真实 usage；provider 不返回时为 null，不估算 |

---

## 7. 跨 Run Memory 验收

三层物理隔离（`research_archive/memory/`）：

| Scope | 位置 | 生命周期 |
|---|---|---|
| run | `<run>/memory.jsonl` | 随 run 目录 |
| case | `research_archive/memory/cases/<case_id>.jsonl` | 跨 run |
| global | `research_archive/memory/global/memory.jsonl` | 跨 case |

规则执行情况（均有测试）：
- 稳定 id：`sha256(scope|case|run|type|normalized_text)[:16]`，重复写不产生重复条目；
- 记录 `run_id` / `case_id` / `evidence[]` / `source` / `created_at`；
- 五类语义 `attempt / finding / hypothesis / failed / open`，仅 `finding` 可当事实；
- `finding` 的 evidence 由 `EvidenceResolver` 真实解析（按 `run-xxx#seq` 或 `sha256:`），
  解析不到直接拒绝（`MemoryError_`）；
- 否证不覆盖：`refute()` 追加 `failed` 条目并用 `refutes` 指向原 id，原条目保持可读；
- `search()` 优先返回 `failed`/已否证方向，`digest()` 在 prompt 中标注 `(REFUTES xxx)`；
- 跨 run 检索已验证：真实 smoke run 写入 case 记忆后，另一个新 run 的 `LayeredMemory` 能读到
  （`memory_id=7328e3314ab2bc5c`，evidence=`run-20261111T094340Z-43ec1e#3`）。

---

## 8. Toolchain 版本及 SHA256

全部位于 `F:\qcx\code\GPUVulnAgent\toolchains`（245.5 MB；二进制不入 Git，manifest 入 Git）。
**复制而非移动**，系统 CUDA 安装与 NVIDIA 驱动未被改动。

| 名称 | 版本 | 相对路径 | SHA256 | 状态 | 来源 |
|---|---|---|---|---|---|
| `cuobjdump-11.2` | 11.2 | `binary_tools/cuda-11.2/bin/cuobjdump.exe` | `da9f5983bd9c003d6b468b4ba66c6f496fa9e340ccf6051331c2102e8a198e6b` | verified | CUDA v11.2 |
| `cuobjdump-12.4` | 12.4 | `binary_tools/cuda-12.4/bin/cuobjdump.exe` | `fb25802b2a8b39d63edefe0cdbc1f4b44939bcf8916ffbc33e03e4d5c4b197c5` | verified | CUDA v12.4 |
| `cuobjdump-13.4` | 13.4 | `binary_tools/cuda-13.4/bin/cuobjdump.exe` | `db89b939a19ba2910cb639116bd71d01f42173d8e6479fd988395effe2e40df5` | verified | CUDA v13.4 |
| `nvdisasm-11.2` | 11.2 | `binary_tools/cuda-11.2/bin/nvdisasm.exe` | `8154c5d61b5f8a71a524f62f6321f6976f941c68b3e624d8cccba036fe649c07` | verified | CUDA v11.2 |
| `nvdisasm-12.4` | 12.4 | `binary_tools/cuda-12.4/bin/nvdisasm.exe` | `1dbfb4a8eef8d3e5043d08093e4a2678e6c1963b4cc54ea05233dedc44461c20` | verified | CUDA v12.4 |
| `nvdisasm-13.4` | 13.4 | `binary_tools/cuda-13.4/bin/nvdisasm.exe` | `71c5c94eecde05c2fa7c9bfe2a96bb1ef2627bc631c4193143ffca9ca2ff9a6c` | verified | CUDA v13.4 |
| `nvcc-12.4` | 12.4 | `compilers/cuda-12.4/bin/nvcc.exe` | `9fd6d38221c524b536c181c5eeb10b3c3e4363059e221601c7e29abca17dcb2a` | verified | CUDA v12.4（含 cicc/ptxas/nvlink/fatbinary/cudafe++/nvvm 依赖） |
| `nvjpeg64_11.dll-11.2` | 11.2 | `cuda/nvjpeg/11.2/x64/nvjpeg64_11.dll` | `f53e8d5d1940e6caf9dbdc617afb05b60d30556671eb2cec50dd9b0575902e00` | present | CUDA v11.2 |
| `nvjpeg64_12.dll-12.4` | 12.4 | `cuda/nvjpeg/12.4/x64/nvjpeg64_12.dll` | `07876623d1f6d992bd0c31428dee93c489968b24870d536657e6d50a615acc3f` | present | CUDA v12.4 |
| `nvjpeg64_13.dll-13.2.2` | 13.2.2 | `cuda/nvjpeg/13.2.2/x64/nvjpeg64_13.dll` | `957bb73818e62883ac4bfc0aa15204bba5e341a8f7964a11b0289742df4e0da2` | present | CUDA 13.4 安装包提取 |
| `nvjpeg.lib-13.2.2` | 13.2.2 | `cuda/nvjpeg/13.2.2/dev/lib/x64/nvjpeg.lib` | `90ede3e2b85cc5e4cd05bca72dc17bba6e7f52b98d8b1a6605935ed68402f269` | present | 同上 |
| `nvjpeg.h-13.2.2` | 13.2.2 | `cuda/nvjpeg/13.2.2/dev/include/nvjpeg.h` | `46982c4b4a34070a219668719d3d75797abfba5860ec6042a89ffdb4c0890570` | present | 同上 |

`verified` = 复制后真实执行 `--version` 且退出码为 0；`present` = 库文件，只校验 SHA256。
`gpuvulnagent doctor --verify-toolchain` 返回 `ok: true`（12/12 无缺失、无漂移）。

主机事实：`NVIDIA GeForce GTX 1660 / 驱动 610.47`；系统 CUDA 工具包检测到 v11.2、v12.4、v13.4。
`cuda-gdb` 在 Windows 上不可用，已如实记入 manifest 的 `absent` 字段与 `debuggers/README.md`。

---

## 9. P17/P18 历史数据迁移情况

| 来源 | 目标 | 文件数 |
|---|---|---|
| `data/agent/archive/`（p17_case1/2） | `research_archive/p17/runs/` | 35 |
| `data/agent/r2_acceptance/` | `research_archive/p17/r2_acceptance/` | 6 |
| `data/agent/benchmarks/p18/`（6 CVE + JPEG_EXPLORATORY + 3 份 summary） | `research_archive/p18/original/` | 276 |
| `data/agent/goal_nvjpeg*.md` | `research_archive/p18/goals/` | 2 |
| `docs/P18_AUTONOMOUS_AGENT_FINAL_REPORT.md` | `research_archive/p18/` | 1 |
| `docs/P17_*.md`（13 份，含 R1/R2 交付与 LEGACY_AUDIT） | `research_archive/p17/` | 13 |
| **合计** | | **333 个文件 / 2.0 MB** |

- 复制后逐文件比对源/目标 SHA256，不一致立即失败；
- **未修改**任何原始 Verdict / Evidence / Artifact / 报告（`case`、`mode`、`crash_observed` 等字段保持原值）；
- 旧 Pipeline **没有**复制进来：`research_archive/legacy_pipeline/` 只有 README 与
  `PIPELINE_INVENTORY.md`（1468 文件 / 163 个 `src` 模块的清单与取回命令）。

独立审计文档：`research_archive/migration/SOURCE_AUDIT.md`（含 file:line 与 `git blame` 结论）。

---

## 10. 每个归档文件的 SHA256 校验

- 清单：`research_archive/migration/SHA256SUMS.txt`（333 行，`sha256sum -c` 兼容格式）
- 机器可读：`research_archive/migration/migration_manifest.json`（源 commit、源路径、目标路径、
  SHA256、字节数、总计与策略）
- 本次校验结果：**`files: 333  bad: 0`**（缺失 0，不一致 0）
- Toolchain 校验：`manifest.verify()` → `ok: true`，12/12 `verified`/`present`

---

## 11. 旧仓库保护状态

| 检查 | 结果 |
|---|---|
| 修改 main | 未发生（旧仓库工作树 `git log -1` 仍为 `a63160e`，无我们产生的 commit） |
| 修改 archive 分支 | 未发生（仅 `git cat-file`/`ls-tree` 读取） |
| 删除分支 / 历史 | 未发生 |
| 向旧仓库 push | 未执行任何 push 命令 |
| 迁移来源污染 | 克隆独立存放于 `.local/migration_source`，已 git 忽略 |
| 符号链接 / 目录联接 | 未创建 |
| `sys.path` 引用旧仓库 | 无（`gpuvulnagent` 内不存在指向旧路径的 import/path） |

旧仓库工作树存在 2 个**与本轮无关的既存未跟踪文件**（`docs/P3_D_EXECUTION.md`、
`docs/P3_D_REAL_VALIDATION.md`，mtime 2026-10-16/17），非本次操作产生，未清理。

---

## 12. 独立 Python 环境

```
F:\qcx\code\GPUVulnAgent\.venv\Scripts\python.exe
Python 3.13.14 (main, Jun 11 2026) [MSC v.1944 64-bit]
```

从零创建（`python -m venv .venv`）并 `pip install -e ".[dev,search,jpeg,elf]"`：

```
gpuvulnagent 0.1.0  PyYAML 6.0.3  pytest 9.2.0  Pillow 13.0.0
tavily-python 0.8.5  pyelftools 0.33  httpx 0.28.1  requests 2.34.2
```

运行期必需依赖只有 `PyYAML`；DeepSeek Provider 仅用标准库 `urllib`，不依赖 LangChain。

---

## 13. 真实 API 验收

`python scripts/acceptance.py --turns 8`（真实网络、真实进程；原始记录 `.local/logs/acceptance.json`）

| 检查 | 结果 | 关键数据 |
|---|---|---|
| 凭证 | ok | model=`deepseek-v4.1-flash-1017`；DEEPSEEK/TAVILY 均在位（不在本报告与任何文件中出现） |
| Provider 往返 | ok | total_tokens=51，1172 ms |
| 原生工具调用 | ok | `mode=native`，`finish_reason=tool_calls`，id 与参数解析正确 |
| Tavily 搜索 + 抽取 | ok | 3 条结果，首条 `access.redhat.com/security/cve/cve-2024-0124`，抽取 5193 字符 |
| Agent Smoke Run | ok | run `run-20261111T094340Z-43ec1e`：7 决策 / 14 次执行 / 6 类工具 / 37 条证据 / 18 个 artifact / `stopped=final` / evidence chain `ok`；usage 80 958 tokens |
| 跨 Run Memory | ok | case 记忆写入后由新 run 读到，evidence 真实解析 |
| Benchmark 不覆盖 | ok | 两次同 case 生成不同 run_id，summary index 同时保留 |

Smoke Run 结论摘录（模型自述，未验证）：
> 已停止探索，共使用 4 轮探测（6 次工具调用）…… 先 `env_probe`+`toolchain_lookup`+`fs_list` 并行探测；
> 再用 `run_program` 调 cuobjdump/nvdisasm、用 `shell` 统计；随后用 python glob 定位 6 个 exe 并逐个
> `--version`；最后把结论写入 case 记忆。

本轮**未**重跑六个 CVE（按要求不消耗大量 token）。

---

## 14. 全量测试结果

```
$ .venv/Scripts/python.exe -m pytest -o addopts="" -q
106 passed in 5.23s
```

覆盖：config / registry / evidence / outcome / runtime / catalog / memory / benchmark /
adapters / provider / cli / toolchain（13 个文件，全部离线，无凭证、无网络）。

补充校验：

```
$ python -m compileall -q gpuvulnagent tests scripts     → exit 0
$ git diff --check                                        → clean
```

关键判据测试（对应任务书 A–F）：

| 判据 | 测试 |
|---|---|
| A 不覆盖实验 | `test_runs_never_overwrite_each_other`、`test_existing_directory_is_refused`、`test_run_directory_is_never_overwritten` |
| B 案例身份 | `test_case_identity_is_recorded_as_separate_fields` |
| C 崩溃识别 | `test_timeout_and_missing_binary_are_not_crashes`、`test_outcome.py` 全量矩阵 |
| D 指标拆分 | `test_metrics_are_disjoint_and_target_scoped` |
| E 墙钟预算 | `test_wall_clock_really_stops_the_run`、`test_wall_clock_budget_is_enforced` |
| F 汇总累积 | `test_summary_can_be_rebuilt_from_verdicts` |

---

## 15. Git 提交和远程状态

```
分支：main（新建，未推送）
提交：4a062fc  feat: initialize GPUVulnAgent from the P18 agent baseline
             （+ 本报告所在提交 docs: add migration final report）
跟踪文件：414（不含 .env / .venv / .local / 工具链二进制 / *.dll,*.exe,*.lib）
忽略规则要点：.env、.local/、.venv/、toolchains 下二进制、*.dll/*.exe/*.lib/*.zip...
```

**远程**：未配置 remote，未向 `cuda_poc_generator` 推送任何内容。若后续要发布，建议先建**私有**
仓库再 `git remote add`，避免在未明确可见性的情况下创建公开仓库。

大型二进制与 `.local` 均不入 Git，但**物理存在于工作区**（toolchains 245.5 MB、
`.local/migration_source` 只读克隆）。

---

## 16. 尚未实现 / 已知边界

1. **没有新的 CVE 结论**：本轮不开展研究，P18 的 `CRASH_OBSERVED=0/6`、
   `DIFFERENTIAL/MECHANISM/CVE_ATTRIBUTED = NOT_ESTABLISHED` 原样保留。
2. **差值判据未自动化**：`DIFFERENTIAL_SUPPORTED` 仍恒为 `NOT_ESTABLISHED`；新 Runner 会记录
   paired control 所需的证据 id，但"自动建立差值"尚未实现。
3. **目标工具识别是启发式**：`metrics.target_program()` 依据 `via` 字段与 `argv[0]` 基名匹配
   `cuobjdump/nvdisasm/nvcc/nvjpeg`；用户自建、名字不含这些词的 PoC 需要显式声明为 target。
4. **崩溃分类不含 dump/WER 采集**：只按退出码/信号分类，没有 `MiniDumpWriteDump`、
   `GetExitCodeProcess` 之外的系统级证据（如 ETW、WER 报告）。
5. **Memory 提升（promote）是显式的**：run→case 需要 agent 调用 `scope=case` 或 `promote()`，
   没有"自动把 finding 提升"的策略。
6. **Resume 不重放中断动作**：故意保守（`INTERRUPTED / EXECUTION_STATE_UNKNOWN`），中断的工具
   需要重新决定。
7. **无 CUDA 调试器**：Windows 无 `cuda-gdb`，`toolchains/debuggers/` 只有说明；SASS 级调试依赖
   nvdisasm 静态分析。
8. **Catalog 不索引 manifest 之外的可执行文件**：项目外的二进制需先写入 manifest 才可发现。
9. **无多智能体/分布式**：单进程、单 agent；benchmark 串行执行 cases。
10. **无 GUI/服务化**：只有 CLI；`.local/runs` 目录可被外部工具读取，但没有可视化前端。

---

## 最终确认

| 要求 | 状态 |
|---|---|
| 新工程不依赖旧仓库 | ✅ `gpuvulnagent/` 内没有指向旧仓库的 import 或路径（仅 `__init__.py` 一句说明性 docstring 提到名字）；`scripts/archive_p18.py` 只保存来源 URL 作为溯源；无 sys.path 注入；`.local/migration_source` 仅供一次性读取 |
| 新工程可独立启动 | ✅ 全新 venv + `pip install -e .` + `python -m gpuvulnagent doctor/run/tools` 均验证通过 |
| 所有工具链位于新工作区 | ✅ 245.5 MB，12 项 manifest 全部通过 SHA256 与可运行性校验 |
| 所有研究归档位于新工作区 | ✅ 333 文件 / 2.0 MB，SHA256 全量校验 0 差异 |
| 旧 Pipeline 完整保留 | ✅ 仍在 `cuda_poc_generator` 的 `archive/pre-agent-runtime-2026-11-11`（`0a119a0`），未复制进新工程 |
| 历史证据未被修改 | ✅ 归档逐字节比对；新判据只用于新运行，历史审计另存 `SOURCE_AUDIT.md` |
| 没有密钥泄露 | ✅ `.env` 未入 Git；evidence/log/report 中无 `sk-`/`tvly-` 值；`redact()` 覆盖并在测试中断言 |
