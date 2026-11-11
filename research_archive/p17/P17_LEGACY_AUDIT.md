# P17-1：旧工程只读审计

审计对象：`0a119a0`（`main` 与 `archive/pre-agent-runtime-2026-11-11` 同一提交）。
审计方式：读取真实源码、AST 统计模块耦合、统计测试与硬编码路径，不依据 README 或历史总结。

## 一、分支现状（与任务描述有出入）

| 项 | 任务描述 | 实际 |
|---|---|---|
| 归档分支名 | `archive/pre-autonomous-agent-2026-11-11` | **`archive/pre-agent-runtime-2026-11-11`** |

两者指向同一提交 `0a119a0`。按实际存在的分支执行只读约定，未另建重名分支。
`main` 与归档分支当前同指一个提交，后续 `main` 前进不影响归档基线。

## 二、规模

| 指标 | 数量 |
|---|---|
| `src/` 模块 | **139** 个，37,712 行 |
| `tools/cuda/` 脚本 | 14 个，8,838 行 |
| `tests/` | 135 个文件，22,282 行，1,973 用例通过 |
| 硬编码绝对路径 | **37** 处（`C:/Program Files`、`D:/Windows Kits`、`F://qcx/...` 等） |

## 三、按域审计

### 3.1 Agent 与 LLM

| 事实 | 证据 |
|---|---|
| Provider 抽象只支持 OpenAI 兼容端点，DeepSeek 通过 `base_url` 伪装接入 | `llm_client.py`（525 行），`ConfigLoader` 读环境变量 |
| **无 usage 返回**，token 统计不可得（F16-R2 已因此只能记字符数） | `llm_client.chat()` 只返回字符串 |
| 无 Agent，只有"阶段编排"：`generate→execute→grade→feedback` 固定四段 | `loop_runner.py:53`、`loop_stages.py`（732 行） |
| 多轮反馈是"诊断码 + 指令"单向注入，模型不能选择下一步动作 | `failure_taxonomy.py` 的 `Diagnosis.directive` |
| 上下文管理 = 拼接 prompt，无检索、无记忆、无压缩 | `code_generator.py`（664 行）规则 1–22 全量内联 |
| 任务状态 = 一个 `LoopState` dataclass，随进程结束丢失 | `closed_loop.py` |

**结论**：旧工程没有 Agent。它是"固定流水线 + LLM 填空"。这是架构转型的核心原因。

### 3.2 PoC 生成能力

| 能力 | 实现 | 形态 |
|---|---|---|
| ELF/cubin 字段变异 | `elf_fields.py`、`mutation_campaign.py`（592 行） | 内置算子表，非工具 |
| Python 候选生成 | `code_generator.py` + `llm_mutation.py`（628 行） | 固定提示词 + 固定输出契约 |
| C/CUDA 程序生成 | `cuda_api_backend.py`、`cuda_transport.py` | nvcc 调用封装，路径硬编码 |
| JPEG 输入构造 | `jpeg_adapter.py` / `jpeg_parser.py` / `jpeg_bundle.py` | **已工程化**，15+13+8 项测试 |
| API 序列 | `staged_fixture.py`、`execution_bridge.py` | 与固定场景绑定 |

**结论**：生成能力是真的，但**入口是固定的**——每个漏洞类型对应一条硬编码分支，
Agent 无法自行决定用哪种表示、哪种工具。

### 3.3 工具与执行环境

| 事实 | 证据 |
|---|---|
| 工具路径写死在源码 | 37 处绝对路径，含 CUDA/MSVC/SDK/工作目录 |
| Docker 执行封装存在但不可替换 | `execution_worker.py`、`cuda_process.py` |
| nvJPEG 探针是专用二进制 | `data/driver/f15/nvjpeg_probe.exe` + `.cpp` |
| 无工具注册/发现机制 | 工具以 `import` 形式被直接调用 |
| 无版本管理 | 版本信息散落在各调用点字符串里 |

**结论**：环境能力够用，**但不是"可被 Agent 发现的工具"**，而是"被代码写死的依赖"。

### 3.4 证据与实验管理（旧工程最强的一块）

| 能力 | 实现 | 质量 |
|---|---|---|
| 可信执行记录 | `trusted_grading.py`、`exec_evidence.py` | 好：拒绝无记录时回退候选自述 |
| Artifact manifest | `jpeg_bundle.py`（canonical JSON + 离线核验） | 好：可离线复核，测试覆盖篡改 |
| Provenance | `plan.json` / `manifest.json` / journal 逆序恢复 | 好 |
| Crash 分类 | 0xC0000000 阈值、137 单独计 | 好（经历三次修正） |
| 版本差分 | 三版本 DLL + argv 矩阵重放 | 好，但口径曾出错，已修 |
| 原始日志 | `data/loop/*/iteration_*_{observation,trusted}.json` | 好，但只在固定流水线里产生 |

**结论**：证据模型值得保留并抽象成服务；它目前**与流水线耦合**，无法被 Agent 用于任意实验。

### 3.5 工程质量

| 项 | 观察 |
|---|---|
| 测试 | 1,973 通过，覆盖可信判定、JPEG、循环、CLI；但大量测试依赖固定流水线结构 |
| 依赖 | `pyproject.toml` 有 extras（rag/search/dev/jpeg），Pillow 刚补 |
| 耦合 | `pipeline.py` 504 行串联 20+ 模块；`lifecycle_*` 四模块互相引用 |
| 模块边界 | 生成、执行、判定、证据四层尚可辨认，但边界靠约定不靠接口 |
| 硬编码 | 37 处绝对路径，跨机器不可用 |
| 可复现 | 干净克隆可跑测试与 JPEG 适配器；**完整实验不可复现**（依赖本机 DLL 与 Docker） |

## 四、旧资产分类

| 模块 | 分类 | 理由 |
|---|---|---|
| `jpeg_parser.py` / `jpeg_adapter.py` / `jpeg_bundle.py` | **TOOL**（保留为可调用工具） | 契约清晰、有测试、与流水线无关；应变成 Agent 可选择调用的工具，而非必经流程 |
| `trusted_grading.py` / `exec_evidence.py` | **ADAPT** | 证据语义正确，需从"循环内判定"抽象为"任意命令的证据记录" |
| `artifacts_manifest.py` / manifest 逻辑 | **KEEP→ADAPT** | canonical 哈希与离线核验直接可用，需泛化到非 JPEG 产物 |
| `llm_client.py` | **ADAPT** | 补 usage、补 tool-calling，其余保留 |
| `config_loader.py` | **KEEP** | 环境变量加载，简单可靠 |
| `case_v2.py` / `case_projection.py` | **ADAPT** | 漏洞案例模型可作为 Agent 的"任务卡"，但不再是生成入口 |
| `code_generator.py` / `loop_stages.py` / `loop_runner.py` / `closed_loop.py` | **REWRITE** | 固定四段流水线与 22 条内联规则，是本次要替代的核心 |
| `pipeline.py` / `lifecycle_*` / `batch_loop.py` | **RETIRE**（归档保留） | 批量固定流程，与新架构冲突 |
| `mutation_campaign.py` / `elf_fields.py` | **TOOL** | 变异算子可作为工具暴露 |
| `cuda_api_backend.py` / `cuda_transport.py` | **ADAPT** | 编译/执行逻辑有价值，但需去掉硬编码路径，改为可配置 |
| `driver_*`（13 个模块） | **UNKNOWN / RETIRE** | 面向内核驱动实验，与本轮用户态范围无交集；保留历史 |
| `failure_taxonomy.py` | **TOOL** | 诊断码可作为 Agent 的一个工具，而非自动注入的指令 |
| `env_probe.py` / `platform_probe.py` | **TOOL** | 环境探测适合让 Agent 自己调用 |
| 37 处硬编码路径 | **REWRITE** | 改为配置或由 Agent 探测 |

## 五、迁移边界（本轮）

- **迁**：证据记录、manifest/离线核验、JPEG 三件套、LLM 客户端、配置加载、环境探测。
- **不迁**：`pipeline`、`lifecycle`、`batch_loop`、`driver_*`、固定 `code_generator` 规则。
- **不改**：归档分支与历史实验数据；`data/` 下全部原始证据只读保留。

## 六、无法确认的部分

1. DeepSeek 专用 provider 是否存在——代码中只有 OpenAI 兼容客户端，未找到独立实现；
2. token 统计是否曾实现——`llm_client` 无 usage 字段，历史报告中的 token 数无来源；
3. `research/full` 分支的用途——未审计，不在本轮范围；
4. 驱动类实验的真实性——需要硬件与内核环境，本轮不评估。
