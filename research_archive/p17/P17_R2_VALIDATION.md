# P17-R2 验证记录

## 全量回归

`python -m pytest -q` → **2029 passed, 67 skipped, 0 failed**（220.28s，退出码 0）

## 专项测试（新增 13 项）

`tests/test_agent_tool_contract.py`：

| 用例 | 断言层次 |
|---|---|
| shell exit=1 | Registry envelope + Runtime Turn + Evidence 记录 |
| HTTP 500 | envelope `summary.http_status`、evidence status=failed |
| Tavily 401 | 同上，错误含 401 |
| Tavily 正常搜索 | items 含 content/score/truncated |
| Tavily 空结果 | status=empty，不是 success |
| 参数越界 | 三种非法输入均 ok=false |
| extract 空正文 | ok=false，artifact 仍保留 |
| extract 部分失败 | status=partial + failed_results |
| 未知工具 | dispatched=false，status=dispatch_error |
| 参数错误 | dispatched=false |
| Legacy 普通 dict | ok=true，result 原样 |
| artifact_read 分块 | offset/limit/has_more + 目录逃逸拒绝 |

`tests/test_agent_tavily.py` 原有 7 项继续通过。

## 真实 Tavily 验收

工具：`tools/agent_tavily_acceptance.py`，产物：`data/agent/r2_acceptance/`。

```
search: success results: 5
  - 0.9016528 https://github.com/NVIDIA/product-security/blob/main/2026/5910/5910.md
  - 0.8591094 https://www.sentinelone.com/vulnerability-database/cve-2025-23275
  - 0.8500835 https://nvidia.custhelp.com/…security-bulletin…
chosen: https://github.com/NVIDIA/product-security/blob/main/2026/5910/5910.md
extract: success chars: 5890
artifact_read: success read: 2352 has_more: False
negative controls: failed failed
verdict: ACCEPTED | evidence ok: True
```

Artifact：

```
http/ef8e90a9906f-tavily-search.json   7926 bytes
http/a4dc9d86adce-tavily-extract.json  6352 bytes  sha256 a4dc9d86adce1596…
http/bfd4f2891e15-tavily-extract.json   193 bytes   （无效 URL 的原始响应）
```

Evidence（3 条 + 拒绝记录，链校验通过）：

```
#1 search    success  NVIDIA CUDA security bulletin nvJPEG
#2 extract   success  https://github.com/NVIDIA/product-security/…
#3 extract   failed   https://invalid.invalid/nothing-here
```

**这不是漏洞复现**，只验证检索工具可用性与状态语义，不计入任何 PoC 成功率。

## Mock 使用

单元测试中 LLM 与 Tavily SDK 均 mock；**上面的验收是真实 API 调用**（真实网络、真实 key）。
