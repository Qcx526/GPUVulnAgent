# 证据模型设计

## 记录格式

```json
{
  "schema": "agent-tool-execution/v1",
  "run_id": "run-xxxxxxxxxxxx",
  "sequence": 4,
  "kind": "tool",
  "status": "success",
  "at": "2026-11-11T12:00:00",
  "previous_record_sha256": "…",
  "record_sha256": "…",
  "tool_name": "shell",
  "arguments": {"command": "python probe.py", "timeout": 30},
  "result_summary": {"exit": 0, "stdout": "…"},
  "artifacts": [{"artifact": "stdout/ab12cd34ef56-shell.out", "sha256": "…", "bytes": 4096}]
}
```

`status` 是保留字段，payload 无法覆盖（HTTP 的状态另存为 `http_status`）。

## 完整性

- 每条记录带 `sequence`（从 1 连续）与 `previous_record_sha256`；
- `record_sha256` 覆盖除自身外的全部字段（canonical JSON：`sort_keys` + `ensure_ascii=False`）；
- `verify_chain()` 校验序号连续、前序哈希、自身哈希，可检出**删除中间记录、改内容、换顺序**；
- 删除**尾部**记录不会被链本身发现，因此 `run.json` 存 `evidence_head`（最后一条哈希），resume 时比对。

## 安全边界（必须准确表述）

Hash chain 提供的是**篡改可发现性**，不是不可篡改：
拥有写权限的人可以重写整份日志并重建一条自洽的链。它能发现误删、误改和随手编辑，
不能抵抗有意伪造。真正要求不可否认时需要外部锚（签名、时间戳服务、异地副本），本轮未做。

## 证据与推理的分离

| 类别 | 存放 | 是否可作为结论依据 |
|---|---|---|
| 模型推理（thought） | `transcript.jsonl` | 否 |
| 工具观测 | `evidence.jsonl`（`kind=tool/exec/http`） | 是，作为"调用发生了什么" |
| 执行证据 | `artifacts/` 原始字节 + sha256 | 是，且可离线复核 |
| 研究假设 | `memory.jsonl`（`hypothesis`） | 否 |
| 已支持发现 | `memory.jsonl`（`finding`，必须引用 evidence id） | 有条件：仅指"证据支持" |
| 已验证结果 | 不在本轮范围内自动产生 | — |

`ResearchMemory.add("finding", …)` 在没有 evidence id 时直接抛错，防止把模型判断写成结论。
