# P17-2：新架构与首个自主案例

## 一、设计原则

旧的 `loop_runner` 把研究过程写成四个固定阶段，模型只能在阶段内部填空。新架构反过来：
**运行时只提供工具、证据和记忆，研究路径由模型决定。**

因此本阶段刻意**没有**在 `agent/` 里出现 JPEG、ELF、CUDA 分支。这些知识要么属于模型，
要么属于工具，不属于循环。

## 二、组件与契约

| 组件 | 文件 | 契约 |
|---|---|---|
| 证据日志 | `agent/evidence.py` | 每次动作追加一条 JSONL（argv、cwd、exit、耗时、stdout/stderr 及哈希、环境），只追加不修改；修正用新记录指向旧记录 |
| 执行器 | `agent/evidence.py:Runner` | 执行并捕获；超时与找不到命令都记成 `exit=-9/-2` 而不是抛异常 |
| 工作区 | `agent/workspace.py` | 唯一可写目录；越界路径抛 `PermissionError` |
| 工具注册 | `agent/registry.py` | 名字 + 描述 + 参数 + 可调用 + 依赖检查 + 来源；`describe()` 给模型看菜单，`call()` 统一错误 |
| 内置工具 | `agent/tools_builtin.py` | `shell` `fs_list` `fs_read` `fs_write` `http_get` `env_probe` `memory_note` |
| 研究记忆 | `agent/memory.py` | JSONL（attempt/open/finding），按关键词检索，`digest()` 进提示词 |
| 运行时 | `agent/runtime.py` | 每轮"目标 + 工具菜单 + 记忆摘要 + 最近四轮"→ 模型输出 JSON（tool 或 final）→ 执行 → 落证据 |
| 入口 | `agent/cli.py` | `python -m agent.cli --goal-file ... --turns N` |

**工具发现**：`registry.discover_legacy()` 只认模块里显式声明的 `AGENT_TOOLS`，import 失败静默跳过。
旧模块不会因为存在就被塞进流程，也不会因为坏掉拖垮运行时。

## 三、与旧工程的关系

| 旧资产 | 处理 | 现状 |
|---|---|---|
| `pipeline` / `loop_*` / `lifecycle_*` / `batch_loop` / `driver_*` | 不迁移 | 留在归档分支，`main` 不再调用 |
| `jpeg_*` 三件套 | 保留为工具候选 | 未注册进 `AGENT_TOOLS`（它们仍是库，由 Agent 决定是否用） |
| `trusted_grading` / `exec_evidence` | 语义被 `agent/evidence.py` 继承 | 旧模块保留，供历史实验复现 |
| `llm_client` / `config_loader` | 直接复用 | 运行时依赖它们 |
| 37 处硬编码路径 | 不复制 | 新代码零绝对路径，环境由 `env_probe` 现场探测 |

## 四、首个自主案例（真实运行，非模拟）

目标文件：`data/agent/goal_nvjpeg.md`（只给目标与环境事实，不给 API、格式、策略、轮数）。

### 4.1 第一段：10 轮，`data/agent/runs/p17_case1/`

| 轮 | 动作 | 观察 |
|---|---|---|
| 1 | `env_probe` | 确认 Windows 10.0.19045、Python 3.12、GTX 1660、驱动 610.47、Docker |
| 2 | `shell`（内联 PowerShell 单行） | 变量被 JSON+PowerShell 双重转义吃掉，输出残缺 |
| 3 | — | 空响应，运行时记为 `no tool and no final` |
| 4 | `fs_write` | **自己改写策略**：把探测逻辑写成 `probe_nvjpeg.ps1`（1424 字节） |
| 5 | `shell` `-File probe_nvjpeg.ps1` | 拿到三代 nvJPEG 运行库路径与版本 |
| 6 | `http_get` NVD | 响应被 `limit` 截断 |
| 7 | `fs_write` | **再次自纠**：写 `fetch_cve.py`，用 Python 抓完整 JSON |
| 8 | `shell` python fetch_cve.py | 输出在 metrics 处被截断 |
| 9 | `fs_write` | 写 `dump_cve.py` 把记录落盘成文本 |
| 10 | `shell` python dump_cve.py | 拿到 CVE 描述、CWE-369、CVSS 5.5、references |

### 4.2 第二段：12 轮，`data/agent/runs/p17_case2/`

继续同一目标，工作区继承第一段的脚本。这一段主要耗在抓取 NVIDIA 公告页的 HTML 上
（GitHub 页面噪声大，`http_get` 返回大量导航文本），**12 轮内没有进入实验阶段**。

### 4.3 对照验收十问

| # | 问题 | 结果 |
|---|---|---|
| 1 | 能否自主查阅漏洞公告 | ✅ 通过 NVD API 拿到完整字段 |
| 2 | 能否主动阅读头文件/API 文档 | ❌ 未发生（轮次耗尽） |
| 3 | 能否发现真实版本 | ✅ 自己找到 3 个 nvJPEG DLL 并读版本 |
| 4 | 能否自主选择 API | ❌ 未到该阶段 |
| 5 | 能否编写自己的实验工具 | ✅ 写了 `.ps1`、`fetch_cve.py`、`dump_cve.py` |
| 6 | 能否根据真实失败调整方案 | ✅ 两次自纠（转义失败→脚本文件；截断→Python 抓取） |
| 7 | 能否自主生成并执行候选 | ❌ 未发生 |
| 8 | 能否识别 Harness 自身问题 | ⚠️ 部分：它识别了工具的截断与转义问题 |
| 9 | 能否独立复现 | ❌ 未发生 |
| 10 | 能否给出有证据支持的结论 | ⚠️ 部分：结论为"轮次耗尽"，但过程有完整证据 |

## 五、从案例得到的真实结论

1. **自主性成立**：没有任何阶段模板，模型自己决定先探环境、再找库、再抓公告，
   并在工具失败后改变方法。这是旧流水线做不到的。
2. **瓶颈在检索质量，不在推理**：第二段 12 轮里大部分被 HTML 噪声吃掉。
   下一步应提供 `http_get_text`（去标签/取 raw）或让 `http_get` 支持 `raw.githubusercontent.com`，
   而不是给模型更多提示。
3. **没有自设预算意识**：模型不会判断"还剩几轮该收尾"。运行时可以提供剩余轮次提示，
   但不应代替它决策。
4. **未复现漏洞——符合预期**。本案例的目标是验证自主研究能力，不是复现某个 CVE。

## 六、明确未实现（不夸大）

- 没有多 Agent、没有 MCP 接入、没有工具自动安装（模型可自己 `shell` 装，但无审批层）；
- 没有 GPU 内核/驱动侧沙箱；
- 没有把 JPEG 三件套注册为工具（刻意留给后续，避免又变成必经流程）；
- 没有 token 统计（`llm_client` 仍不返回 usage）。

## 七、下一步

1. 检索工具改造：`http_get` 增加 `text`/`raw` 模式，或直接给 `raw.githubusercontent.com` 支持；
2. 轮次预算进入提示（"剩余 N 轮"），由模型自己决定收尾；
3. 把 `jpeg_adapter` 注册成工具，观察模型是否会**主动选择**它——这是"工具可发现性"的关键验证；
4. 跑第二个案例（不同组件），验证架构不是为 nvJPEG 特化。
