# P17-R1 验证记录

## 全量回归

```
python -m pytest -q
2010 passed, 67 skipped, 1 warning in 202.59s
```

环境：Windows 10.0.19045、Python 3.12.13、pytest 8.4、venv 位于项目 `.venv`。

## 专项测试

| 文件 | 用例数 | 覆盖 |
|---|---|---|
| `tests/test_agent_runtime.py` | 10 | 循环、schema 校验、工具派发、记忆注入、路径逃逸、拒绝覆盖 |
| `tests/test_agent_evidence.py` | 9 | hash chain（删中间/改内容/换序）、artifact、超时、脱敏、超时参数校验 |
| `tests/test_agent_resume.py` | 6 | 新建、恢复、目标不一致、链损坏、尾部截断、中断标记 |
| `tests/test_agent_tools.py` | 12 | HTTP 截断/来源/JSON/失败、shell 超时、memory 类型约束、registry 组合、原生 tool call 适配 |
| **合计** | **37** | — |

## Mock 使用情况（必须如实）

| 对象 | 是否 Mock | 说明 |
|---|---|---|
| LLM | **是** | `ScriptedClient` / `FakeModel`，运行时测试不访问真实 API |
| HTTP | **是** | monkeypatch `urllib.request.urlopen`，离线可复现 |
| Pillow 解码 | 未涉及 | 这些测试不产生 JPEG 判定 |
| 时间/目录 | 真实 | 用 `tmp_path` |

## 真实调用（非测试）

| 项 | 结果 |
|---|---|
| 原生 tool calling 探测 | `bind_tools` 后 `invoke()` 返回 `tool_calls=[{'name':'env_probe','args':{},...}]`，**该端点确实支持** |
| 模型 | 项目配置的 OpenAI 兼容端点（`ConfigLoader`），未记录凭据 |

## 命令

```
python -m compileall -q agent src     → 通过
git diff --check                      → 通过（无空白错误）
```

## 未验证 / 未执行

- 未用真实 LLM 重跑自主研究案例（本轮只做运行时加固，案例数据见归档）；
- 未在干净克隆里安装依赖后复跑 37 项专项（本地 venv 已验证；克隆验证留待下一轮）；
- 未做 GPU 相关实验。
