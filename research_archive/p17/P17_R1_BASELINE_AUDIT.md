# P17-R1 基线审计（只读）

## Git 状态

| 项 | 值 |
|---|---|
| 起始 HEAD | `0e299af`（= 远程 main） |
| 工作区 | 干净（仅历史未跟踪的 `data/driver/binary/*` 与 `.pytest-tmp*`） |
| 归档分支 | `archive/pre-agent-runtime-2026-11-11` → `0a119a0`（未动） |
| 新分支 | `research/p17-r1-runtime-hardening` |
| 远程 | `origin` = Qcx526/cuda_poc_generator |

## 逐项核查（审计要求 A–G）

**A. Shell timeout 未生效**
`agent/tools_builtin.py` 的 `shell(command, timeout=300)` 把 `timeout` 吞掉了，
`Runner.run()` 完全没有该参数，命令一律按 300 秒执行。→ 属实，已修（`agent/evidence.py:Runner.run` 增加 `timeout` 形参与 `clamp_timeout`）。

**B. Registry 初始化**
`agent/cli.py` 只在 `discover_legacy()` 返回非空时才传入 registry，否则传 `None` 让
`AgentRuntime` 自建 → 只要有一个 legacy 工具，七个 builtin 就都不在菜单里。→ 属实，已改为 `build_registry()`：builtin 无条件注册，legacy 增量。

**C. 工具证据不完整**
`AgentRuntime.run()` 对工具只记 `{tool, args, ok}`，完整输出没入日志；只有 `shell` 经
`Runner` 落了一份 stdout。→ 属实，已统一为 `ToolExecutionRecord`（见 P17_R1_EVIDENCE_DESIGN.md）。

**D. Transcript 被清空**
`__init__` 里 `transcript_path.write_text("")`，每次启动都截断。→ 属实，已改为追加；resume 时读回。

**E. HTTP 截断**
`http_get` 读 800KB、返回前 6000 字符，但**不标记截断**，也没有 status/content-type/final URL。→ 属实，已加 `mode`/`truncated`/`http_status`/`final_url`/`sha256`。

**F. Research Memory**
`memory_note` 只往 EvidenceLog 写 `note`，从未进 `ResearchMemory`；`digest()` 也未按目标检索。→ 属实，已改为写入 memory（带类型校验），`digest(goal)` 走 `search(goal)`。

**G. 证据完整性**
`record_sha256` 是单条哈希，无前序关联，删一条、换顺序都发现不了。→ 属实，已加 hash chain + 序号 + `verify_chain()`，并在 `run.json` 存 `evidence_head` 锚点检测尾部截断。

## 额外发现（未被要求但影响可靠性）

1. `EvidenceLog` 的 `status` 字段会被 payload 里同名字段覆盖（HTTP 的 `status=None` 会把
   记录状态抹成 null）。已改为保留字段优先，HTTP 状态改名 `http_status`。
2. `Runner` 的 workspace 与 `Workspace` 的 root 可以不一致，导致 shell 在错误的目录执行。
   测试里已显式对齐；运行时统一用 `workspace.root`。
