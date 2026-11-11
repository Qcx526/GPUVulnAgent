# P17-R1 实现记录

## 一、修复项（逐条对应审计）

| 问题 | 原位置 | 修改 | 新位置 | 测试 |
|---|---|---|---|---|
| A Shell timeout 不生效 | `agent/tools_builtin.py:shell` | `Runner.run(timeout=...)` + `clamp_timeout`（1..3600，非法回退默认），记录 `timed_out`/`timeout_seconds`/`status=timeout` | `agent/evidence.py:Runner.run` | `test_shell_timeout_reaches_runner`、`test_shell_timeout_is_validated`、`test_timeout_is_clamped_and_applied` |
| B Registry 只加载 legacy | `agent/cli.py` | `build_registry()`：builtin 无条件注册，legacy 只增不改，同名冲突显式返回 | `agent/registry.py:build_registry` | `test_registry_always_has_builtins`、`test_legacy_tools_add_without_replacing_builtins` |
| C 工具证据缺正文 | `agent/runtime.py:run` | 统一 `log.append("tool", {tool_name, arguments, result_summary, artifacts}, status)` | `agent/runtime.py:run` | `test_agent_calls_tool_then_finishes`、`test_full_output_becomes_an_artifact_with_hash` |
| D Transcript 被清空 | `agent/runtime.py:__init__` | 改为追加；resume 时 `_load_turns()` 读回 | `agent/runtime.py` | `test_resume_appends_and_keeps_evidence` |
| E HTTP 无截断标记 | `agent/tools_builtin.py:http_get` | `mode=text/json/raw`，返回 `http_status/content_type/final_url/bytes/sha256/truncated`，原始 body 存 artifact | 同上 | `test_http_records_source_and_truncation`、`test_http_json_mode_pretty_prints`、`test_http_failure_is_recorded_not_raised` |
| F memory_note 不入记忆 | `agent/tools_builtin.py` | 写入 `ResearchMemory`，类型受校验（`finding` 必须带 evidence id） | `agent/tools_builtin.py` + `agent/memory.py` | `test_memory_note_requires_evidence_for_findings`、`test_memory_is_visible_in_later_prompt` |
| G 无完整性校验 | `agent/evidence.py` | hash chain（`previous_record_sha256`）+ 连续序号 + `verify_chain()` + `run.json:evidence_head` 锚点 | `agent/evidence.py` | `test_chain_*` 四例、`test_resume_with_broken_chain_is_refused` |

## 二、新增能力

### 2.1 统一 ToolExecutionRecord

所有七个工具（含以后注册的）都走同一个落盘路径：
`sequence / kind / status / tool_name / arguments / result_summary / artifacts / previous_record_sha256 / record_sha256`。
状态取值：`success` `failed` `rejected` `timeout`。

### 2.2 Artifact 管理

```
run/
├── evidence.jsonl
├── transcript.jsonl
├── memory.jsonl
├── run.json
├── result.json
├── artifacts/{stdout,stderr,http,files}/<sha12>-<name>
└── workspace/
```
完整 stdout/stderr 全文入 artifact，prompt 里只放预览（`stdout_preview` 2000 字符）并标 `truncated`。

### 2.3 断点恢复

- `run.json` 记录 `run_id`、`goal_sha256`、状态、`evidence_head`；
- `--resume` 校验目标哈希与证据链，不符直接拒绝；
- 若最后一条是未完成的工具记录 → `INTERRUPTED / EXECUTION_STATE_UNKNOWN`，不自动重放。

### 2.4 原生 tool calling 适配

`agent/native_tools.py`：`to_openai_tools()` 把 registry 转成 OpenAI schema，
`NativeActionModel.act()` 优先取 `tool_calls`，否者回退 JSON 解析，并返回使用的模式。

## 三、接口变更（兼容性）

| 变更 | 影响 |
|---|---|
| `ToolRegistry.register()` 同名默认抛错 | 旧代码若重复注册需显式 `allow_override=True` |
| `env_probe`/`http_get` 返回 `{ok, summary, artifacts}` | 观测结构变了，旧测试已按新契约更新 |
| `ResearchMemory.add()` 校验类型 | `finding` 不带 evidence 会被拒 |
| `AgentRuntime(root=...)` 已存在 `run.json` 时抛错 | 必须用 `--resume` |

JSON action 协议保持兼容：`{"thought","tool","args"}` / `{"thought","final"}` 不变，只是校验变严。
