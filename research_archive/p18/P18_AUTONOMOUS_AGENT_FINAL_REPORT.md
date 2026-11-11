# P18 最终报告：自主 Agent 建设与历史 CVE 实战评估

分支 `research/autonomous-agent-completion`，起点 `3d04dde`（P17-R2）。
本报告只写实际发生的事；没有做到的部分在 F 节逐条列出。

## A. 架构成果

| 能力 | 实现 | 状态 |
|---|---|---|
| 开放式循环 | `agent/runtime.py`：目标+工具菜单+记忆+最近四轮 → 模型输出 JSON/工具调用 → 执行 → 记录 | 真实运行 9 次 |
| 工具注册 | `agent/registry.py:build_registry`：builtin 恒定、legacy/search 增量、冲突显式 | 有测试 |
| 调度/操作分离 | 信封含 `dispatched` / `ok` / `status` / `summary` / `artifacts` / `error` | 有测试 |
| 参数校验 | 调用前 `inspect.signature().bind()`；工具内部 TypeError 归为内部故障 | 有测试 |
| 证据 | 追加式 JSONL + hash chain + 序号 + 尾部锚点；`verify_chain()` | 每例均校验通过 |
| Artifact | 完整输出按 sha 前缀落盘，prompt 只取预览 + 引用 | 每例都有 |
| 观察渲染 | 按工具类型分别渲染（shell 取 exit+stdout，search 取条目，read 取正文+续读指针），旧轮折叠成一行 | 本轮新增，**在完成 9 次基准后才真正生效**（见 E2 节） |
| 记忆 | JSONL，类型受校验（finding 必须带 evidence id），`digest(goal)` 参与检索 | 有测试 |
| Resume | 校验目标哈希+证据链+头锚点，中断标 `INTERRUPTED` 不重放 | 有测试 |
| Provider | DeepSeek（OpenAI 兼容端点），JSON 协议为默认，原生 tool calling 适配已实现 | 真实调用 |

**Token 统计已接入**：`LLMClient` 现在记录 `last_usage`（prompt/completion/total），来源是
provider 返回的 `usage_metadata`；没有返回时记 None，不估算。

## B. 真实 API 验收

| 项 | 结果 |
|---|---|
| DeepSeek `chat` | 真实返回；`usage = {prompt:34, completion:38, total:72}` |
| 原生 tool calling | `bind_tools` 后返回 `tool_calls=[{'name':'env_probe',...}]`，端点支持 |
| Tavily 搜索/抽取 | 真实调用成功（P17-R2 验收：搜到 NVIDIA 公告，抽取 5890 字符） |
| 本轮 9 次运行 | 每次 20k–49k tokens，合计 **276,135**；8/9 用到 Tavily |
| Mock | 单元测试用 mock；上面这些是真实网络调用 |

## C. 六个 CVE 的 Blind 实验

统一预算：8 轮决策，独立目录，不提供历史 PoC 路径与结论，只给 CVE 编号与环境事实。

| CVE | 工具调用 | 真实执行 | 使用工具 | 崩溃 | 耗时 | tokens |
|---|---|---|---|---|---|---|
| CVE-2025-23346 | 7 | 1 | fs_list, http_get, shell, web_extract, web_search | 0 | 122s | 28,168 |
| CVE-2025-23338 | 6 | 3 | http_get, shell, web_extract, web_search | 0 | 130s | 26,992 |
| CVE-2025-23308 | 6 | 0 | artifact_read, web_extract, web_search | 0 | 54s | 20,617 |
| CVE-2024-0111 | 6 | 2 | artifact_read, http_get, shell, web_extract, web_search | 0 | 82s | 24,058 |
| CVE-2024-0124 | 5 | 2 | shell, web_extract, web_search | 0 | 94s | 27,086 |
| CVE-2024-0125 | 7 | 1 | artifact_read, http_get, shell, web_extract, web_search | 0 | 79s | 26,522 |

六例合计：37 次工具调用、9 次真实执行、**0 次异常终止**。

**每个案例的判定**（一律按证据，不采信模型自述）：

```
CRASH_OBSERVED          = 0/6
DIFFERENTIAL_SUPPORTED  = NOT_ESTABLISHED（无配对对照被 harness 实际执行）
MECHANISM_SUPPORTED     = NOT_ESTABLISHED
CVE_ATTRIBUTED          = NOT_ESTABLISHED
```

代表性结论（原文摘录）：

- **CVE-2025-23346**：自主定位到 `cuobjdump`、NULL 指针解引用，找到三套 `cuobjdump.exe`
  （v11.2/v12.4/v13.4）；明确写"具体是哪个 ELF 字段触发**仍是推测，我没有任何实测证据**"。
- **CVE-2025-23308**：引用自己抽取的 artifact（sha256 `fd4011ec…`，9905 字节）证明组件与
  堆溢出类型，并把"触发面"单独标为推测。
- **CVE-2024-0125**：主动指出搜索结果信噪比不佳，"不能把这些无关片段当作本漏洞的技术描述"，
  并记录 NVD 直连失败的取证尝试。

## D. Seed-assisted 对照

| CVE | 工具调用 | 真实执行 | 崩溃 | 耗时 | tokens |
|---|---|---|---|---|---|
| CVE-2025-23346 | 10 | 4 | 0 | 102s | 34,882 |
| CVE-2024-0111 | 8 | 3 | 0 | 129s | 38,633 |

给到历史 PoC 路径后，执行次数从 1→4、2→3，说明它确实会读历史产物并跟进执行；
但**没有产生崩溃**，也没有建立新的差分。两例都未出现"复制旧 PoC 就宣布成功"的行为。

## E. JPEG 跨格式探索

`JPEG_EXPLORATORY`：10 轮、10 次工具调用、8 次真实执行、156s、49,177 tokens。

- 它**没有**使用 Tavily，也没找到现成的 JPEG 适配器；
- 自己写程序、自己执行（新渲染下还用了 `artifact_read` 回读自己的输出）；
- 两次运行都在第 10 轮耗尽预算，停在一条失败的 `findstr` 上；
- 结论是"未在 10 轮内得出结论"，**没有编造结果**。

这一例也暴露了当前限制：不经提示时，Agent 更容易重新发明工具而不是发现仓库里已有的
`src/jpeg_adapter.py`。工具可发现性仍未解决。

## E2. 一个必须说明的过程问题

第一次 9 次基准跑完后，我发现"按工具类型渲染观察"的补丁**没有真正落到代码里**
（替换字符串没匹配上，而我没有复核），所以那批运行使用的是旧的 600 字符统一截断。
这不是结论错误，但报告的"本轮新增"描述与事实不符，必须更正。

修复后用新渲染重跑了两例对照：

| 案例 | 旧渲染（600 截断） | 新渲染（按类型 + 续读指针） |
|---|---|---|
| CVE-2025-23308 | 6 次调用 / **0 次执行** / 54s / 20,617 tok | 6 次调用 / **2 次执行** / 436s / 31,113 tok |
| JPEG_EXPLORATORY | 10 次调用 / 8 次执行 / 156s / 49,177 tok | 10 次调用 / 6 次执行 / 229s / 64,057 tok，且首次用上 `artifact_read` |

同一 CVE 在新渲染下多做了两次真实执行，说明"看得见完整输出"确实改变了行为方向；
代价是单轮更慢、token 更多。这是真实权衡，不是纯收益。

## F. 自主能力评价（逐项，按实际观察）

| 能力 | 结论 | 依据 |
|---|---|---|
| 自主搜索 | ✅ | 8/9 案例主动调用 `web_search`，并筛选官方来源 |
| 自主工具选择 | ✅ | 每例在 shell/fs/http/search/extract/artifact_read 间自行切换 |
| 自主安装工具 | ❌ | 本轮无案例需要安装，也未观察到安装行为 |
| 自主编程 | ✅ | JPEG 例自写程序并执行；seed 例读历史脚本 |
| 自主构造 PoC | ⚠️ 部分 | 有执行，但 8 轮内未产出可评估候选 |
| 自主变异 | ❌ | 未观察到有效变异循环 |
| 自主验证 | ⚠️ 部分 | 会引用 artifact 与 sha256，但未建立配对对照 |
| 自主反馈 | ✅ | 多次记录失败尝试并改换路径（如 NVD 直连失败改用其他源） |
| 自主停止 | ⚠️ 部分 | 5/9 主动收尾，JPEG 例撞到轮次上限 |
| 跨 Run 记忆 | ⚠️ 已实现未验证 | 机制有测试，本轮未做跨 Run 续研实验 |

## G. 与旧工程对照（F14）

| 维度 | F14 旧流水线 | P18 Agent |
|---|---|---|
| 目标工具差分 | 4/6 | **0/6** |
| 机制归因 | 0/6 | 0/6 |
| 组件识别 | 由固定 prompt 提供 | **自主检索得到**（6/6） |
| 失败自我批评 | 无 | **有**（主动标注推测、指出搜索噪声） |
| 每例耗时 | 5–13 分钟（含生成） | 54–156 秒 |
| 人工介入 | 需要预置 spec 与脚本 | 只需 CVE 编号 |

**结论必须说清**：新 Agent 在"发现与自我批评"上明显更强，在"持续构造到可评估候选"上
明显更弱。F14 的 4/6 差分来自预先写好的生成器与可信重放，不是模型自主完成的；
P18 的 0/6 则受 8 轮预算与"从零搭建实验"的限制。两者不可直接比较为"退步"或"进步"。

## H. 工程与科研边界

已验证：Runtime 循环、工具合同、证据链、Artifact、Resume、Memory、真实 DeepSeek、真实 Tavily。
仅候选：原生 tool calling 适配（测过，未进主循环）；JPEG 适配器复用（Agent 未主动发现）。
未完成：PoC 构造闭环、变异循环、机制证据、CVE 归属、跨 Run 续研、工具自动安装。

## I. Git

- 分支：`research/autonomous-agent-completion`
- 起点：`3d04dde`
- 实验数据：`data/agent/benchmarks/p18/<case>/<mode>/`
- 全量回归：命令与统计见提交说明

## J. 下一轮最该做的三件事

1. **提高单例预算并加"进度自检"**：当前 8 轮只够摸清目标，不够构造+验证；
2. **工具可发现性**：把仓库已有工具（jpeg_adapter 等）以 `AGENT_TOOLS` 暴露，
   并让 `fs_list` 能索引 `tools/`，避免重复发明；
3. **把差分做成工具**：Agent 现在会执行但不会自己搭对照，需要一个 `run_pair` 类工具
   把"候选 vs control 同版本同参数"变成一次调用。
