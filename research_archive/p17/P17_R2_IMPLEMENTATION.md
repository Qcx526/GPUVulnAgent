# P17-R2 实现记录

| 项 | 位置 | 说明 | 测试 |
|---|---|---|---|
| 派发/操作分离 | `agent/registry.py:envelope` + `call()` | 新增 `dispatched`，`ok` 取自工具自述 | `test_shell_nonzero_exit_is_a_failure`、`test_http_500_is_a_failure_with_body_kept`、`test_tavily_401_is_a_failure` |
| Runtime 消费 | `agent/runtime.py:run` | Turn 增加 `dispatched`/`operation_ok`；evidence 记 `dispatched`/`operation_ok`/`error`/`artifacts` | 同上（三层同断言） |
| 搜索正文 | `agent/tavily_provider.py:web_search` | 每条结果含 `content`（上限 600 字符）+ `content_truncated`，并注明"这是搜索引擎摘要，不是网页正文" | `test_tavily_search_success_carries_content` |
| 参数校验 | 同上 | `max_results` 1..20、`search_depth` ∈ {basic, advanced}，越界直接 rejected 并留证据 | `test_search_argument_validation` |
| 空结果 | 同上 | 0 命中 → `status="empty"`（请求成功、无数据），不算失败也不算命中 | `test_tavily_empty_results_is_not_a_hit` |
| 抽取语义 | `agent/tavily_provider.py:web_extract` | 无 results / raw_content 为空 → `ok=false`；`failed_results` 非空 → `status="partial"` | `test_extract_empty_body_is_a_failure`、`test_extract_partial_when_some_urls_fail` |
| Artifact 分块读 | `agent/tools_builtin.py:artifact_read` | 按引用读取，支持 offset/limit，返回 total/read/next/has_more；路径必须落在本次 run 的 artifacts 根内 | `test_artifact_read_chunks_and_stays_inside_the_run` |
| Legacy 兼容 | `agent/registry.py:envelope` | 普通 dict 视为成功，原样放进 `result` | `test_legacy_tool_returning_plain_object_is_success` |

## 未改动的部分

- 七个 builtin 的返回结构不变（仍是 `{ok, summary, artifacts, status?}`）；
- JSON action 协议不变；
- Tavily 仍未进入 Runtime 核心，只通过 `build_registry(search=True)` 注入。
