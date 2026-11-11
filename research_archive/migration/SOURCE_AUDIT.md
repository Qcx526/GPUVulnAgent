# 迁移源码审计（P18 Legacy Audit）

**审计对象**：`https://github.com/Qcx526/cuda_poc_generator`
分支 `research/autonomous-agent-completion`，commit `c80efe18fcb60a1986f7d3dc570268356866d73c`
**审计方式**：只读 worktree（`.local/migration_source/tree`），逐文件阅读 + `git blame` + 归档数据交叉核对。
**审计原则**：本文只记录"旧实现哪里不对"，不改写任何历史 Verdict / Evidence / Artifact。

---

## 1. 架构层面的问题

### 1.1 Agent 不是独立的包

`agent/cli.py:13-14`、`tools/p18_bench.py:29-30` 直接 `from src.config_loader import ConfigLoader`
与 `from src.llm_client import LLMClient`。`agent` 依赖旧 Pipeline 的 `src/` 包，因此
"把 agent 目录拷走"并不能得到一个可运行的 Agent。

**新工程处置**：`gpuvulnagent.config` 与 `gpuvulnagent.providers` 独立实现，Provider 走
OpenAI 兼容 Chat Completions 的裸 HTTP（`urllib`），不引入 LangChain，也不依赖 `src/`。
见 `gpuvulnagent/config/loader.py`、`gpuvulnagent/providers/deepseek.py`。

### 1.2 原生 Tool Calling 只写了适配器，没有接进 Runtime

`agent/native_tools.py` 定义了 `NativeActionModel`，但全仓库除测试外没有任何引用：

```
$ grep -rn "NativeActionModel" --include=*.py .
./tests/test_agent_tools.py:149,165,171,186
```

`agent/runtime.py` 的主循环只调用 `parse_action(raw, ...)` 解析文本 JSON。也就是说 P18 报告里
"原生 tool calling 适配已实现"是真的，但"Agent 用上了"不是。

**新工程处置**：`providers/base.py` 定义 `ToolCall`/`ProviderResponse`，`runtime/loop.py` 优先消费
`tool_calls`，多调用一次响应全部执行，tool call id 写入 Evidence 并以 `role=tool` 消息回灌；
文本 JSON 仅作 fallback，且每条 turn 记录 `mode=native|json_fallback|prose`。

### 1.3 所有工具参数都被声明成字符串

`agent/registry.py:210-211`：

```python
def fn_signature(fn):
    return {name: "str" for name, _ in inspect.signature(fn).parameters.items()}
```

`agent/native_tools.py:21-28` 据此生成 `{"type": "string"}`。整数、布尔、数组参数在协议层就丢了类型。

**新工程处置**：`registry/spec.py` 的 `ParamSpec` 支持 string/integer/number/boolean/array/object，
生成真正的 JSON Schema，调用前校验并只在无歧义时做类型转换（转换会记录在 `coercions`）。

### 1.4 Tool Registry 靠扫描 `src/` 目录发现工具

`agent/registry.py:195`：`module_path = Path("src")`，只扫描当前工作目录下的 `src/`，并要求模块
暴露 `AGENT_TOOLS`。实际检查：`src/` 下没有任何模块定义 `AGENT_TOOLS`

```
$ grep -rl "AGENT_TOOLS" src/ tools/ agent/
agent/registry.py
```

所以 `--legacy` 是空操作，`src/jpeg_adapter.py` 这类能力对 Agent 完全不可见——这正是 P18
"Agent 不知道 `jpeg_adapter.py` 存在"的直接原因。

**新工程处置**：`discovery/catalog.py` 建立能力目录，适配器在**导入前**就登记（含依赖、位置、
可运行性）。不可运行的适配器依然可见，并给出原因。

---

## 2. Benchmark Runner 的六处判据缺陷（对应任务书 A–F）

文件：`tools/p18_bench.py`（`git blame` 显示全部由 `c80efe18` 引入）

| # | 位置 | 旧行为 | 后果 |
|---|---|---|---|
| A | `:156-158` | `if case_dir.exists(): shutil.rmtree(case_dir)` | 默认删除上一次实验，重跑即覆盖 |
| B | `:134` | `"case": run_dir.name`，而 `run_dir = case_dir/"run"` | 只要用提交版脚本重跑，verdict 的 `case` 会是字符串 `run`；Case / Mode / Run 没有分别记录 |
| C | `:110-122` | `code < 0 or code >= 0xC0000000` 即算 crash | `-2`（找不到程序）、`-9`（超时被杀）被计入 CRASH_OBSERVED |
| D | `:133-141` | 一个 `executions` 数混合了工具调用与进程启动 | 无法回答"目标工具是否运行过、是否崩溃" |
| E | `:165` | `wall_clock_s` 只写进 `case.json` | 没有代码读取它，预算不约束任何执行 |
| F | `:235` | `summary_<mode>.json` 每次覆盖写 | 同一 mode 跑两次，前一次结果消失 |

补充事实：归档的 11 份 verdict（`research_archive/p18/original/**/verdict.json`）里 `case` 字段是
正确的，说明这九次实验由提交前的工作版本产生；**缺陷存在于被提交的脚本中**，任何用该脚本重跑
都会丢失 Case 身份。因此历史结论不需要改写，需要修的是 Runner——新 Runner 已按 A–F 重写
（`gpuvulnagent/benchmarks/`）。

---

## 3. Memory 只有 Run 级别

`agent/runtime.py:153`：`ResearchMemory(self.root / "memory.jsonl", self.run_id)`。
记忆随 run 目录存亡；新 run 从零开始，会重复已失败的方向。类型校验（finding 必须带 evidence id）
是有效的，但只校验"非空"，不校验 evidence 是否真的存在。

**新工程处置**：`memory/store.py` 三个物理隔离的 scope（run / case / global），稳定 id，
记录来源 run 与 case，finding 的 evidence 通过 `EvidenceResolver` 真实解析，否证用新条目
（`refutes`）而不是覆盖原条目。

---

## 4. 其它代码级问题

| 位置 | 问题 |
|---|---|
| `agent/runtime.py:101-104` | `Turn` 数据类重复声明 `dispatched` / `operation_ok` 各两次——可运行但说明该文件在提交前被机械编辑过，缺少一次完整回归 |
| `src/jpeg_adapter.py:30,32` | 同一 `from .jpeg_parser import ...` 连写两次，并在其后重新赋值 `SOF_BASELINE/SOF_EXTENDED`，遮蔽了导入符号 |
| `agent/registry.py:104-111` | 工具返回值与异常混在同一个 `ok` 里（P18 已部分修正为 dispatched/ok 分离，但 evidence 的 `status` 仍写 `rejected`，与"调度失败"语义不一致） |
| `agent/evidence.py:191` | `FileNotFoundError` 被压成 `exit_code=-2` 的普通记录，缺少"程序未能启动"这一独立事实 |
| 全仓 | 未发现密钥写入 Evidence；`redact()` 覆盖 `sk-` / `tvly-` / Bearer，这一点旧实现是正确的，新工程沿用并扩展（`evidence/redact.py`） |

---

## 5. 审计结论

旧 Agent 的**设计意图**多数是对的：开放式循环、dispatched/ok 分离、hash chain、artifact store、
workspace 路径保护、resume 的保守语义、finding 必须带 evidence。这些在新工程中原样保留并加强。

真正需要推翻的是四件事，且都已在新工程重做：

1. 包依赖旧 `src/` → 独立包 + 独立 Provider；
2. 原生工具调用没接入 → Runtime 一等公民；
3. 工具发现靠扫目录 → 能力目录 + 显式注册；
4. Benchmark 判据（A–F）系统性失真 → 重写 Runner 与 metrics。

历史实验数据保持不变，重新审计的差异另存于本文件与新 Runner 的 `compare_legacy()` 审计视图中，
不写回历史 Verdict。
