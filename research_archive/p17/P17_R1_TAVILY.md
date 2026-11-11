# Tavily 检索接入

## 复用既有机制（不新增配置体系）

| 项 | 复用 |
|---|---|
| 凭据 | 根目录 `.env` 的 `TAVILY_API_KEY`，由 `ConfigLoader._load_project_dotenv()` 经 python-dotenv 加载（`src/config_loader.py:130`） |
| 依赖 | `pyproject.toml` 的 `search` extra（`tavily-python`），实测安装版本 **0.8.5** |
| 说明 | `.env.example` 中的占位符与注释保持原样 |
| 忽略 | `.gitignore` 已忽略真实 `.env`，未改动 |

没有第二个 key 文件，不需要在终端临时设环境变量。

## 解耦方式

`agent/tavily_provider.py` 只做三件事：

1. `status()` 报告可用性（SDK 是否装、key 是否存在、原因）；
2. `build_tools(log)` 在可用时返回 `web_search` / `web_extract` 两个工具 spec；
3. 工具内部自己调用 SDK 并写证据。

`AgentRuntime` 不 import Tavily，只通过 `build_registry(search=True)` 拿到 spec 列表。
未配置时 `build_tools` 返回空列表，Agent 正常启动。

## 未配置时的行为

```
[provider] tavily available=False (TAVILY_API_KEY is not set)
```

七个 builtin 工具照常在菜单里，`web_search` / `web_extract` 不出现，`start` 记录里带
`providers` 字段说明原因。启动不报错、不阻塞。

## 证据

| 事件 | 记录 |
|---|---|
| 搜索成功 | `kind=search`：query、结果数、payload SHA256、artifact 引用 |
| 抽取成功 | `kind=extract`：URL、字符数、payload SHA256、artifact 引用 |
| 调用失败（401/网络） | `kind=search|extract`，`status=failed`，错误已脱敏 |

原始 JSON payload 存 `artifacts/http/`，prompt 只拿到前 10 条标题/URL 或前 4000 字符正文，
并带 `truncated` 标记。

**Key 安全**：key 只在 SDK 构造时使用；`tvly-*` 与 `sk-*` 一样在写盘前被 `redact()` 替换。
实测（`test_key_never_appears_in_evidence`）确认日志里不会出现真实值。

## 开关

`python -m agent.cli --no-search` 可在已配置的情况下也不注册检索工具。

## 测试（7 项）

| 场景 | 用例 |
|---|---|
| `.env` 加载 | `test_dotenv_supplies_the_key`（临时项目根 + 真实 ConfigLoader） |
| 缺 key | `test_missing_key_leaves_agent_usable` |
| 缺 SDK | `test_status_reports_missing_sdk` |
| 错误 key | `test_wrong_key_is_an_observation` |
| 正常搜索 | `test_search_records_payload_and_artifact` |
| 正文抽取 | `test_extract_truncates_preview_but_keeps_full_body` |
| 不泄露 key | `test_key_never_appears_in_evidence` |

SDK 在测试中全部 mock；没有发起真实网络请求。
