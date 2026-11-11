# P17-R2 工具合同设计

## 问题

`ToolRegistry.call()` 把所有返回值统一包成 `{"ok": True, "result": ...}`。
而 builtin 工具本身返回 `{"ok": false, "summary": ...}`。于是：

- `shell` 退出码 1 → 外层 ok=True → Runtime 记 success；
- `http_get` 收到 500 → 同样是 success；
- Tavily 401 → 同样。

受影响的不只是 Tavily：**所有走 Registry 的工具**，因为问题在派发层而不是某个 provider。

## 新合同

```
{
  "dispatched": bool,   # 工具存在、依赖就绪、参数被接受，函数确实跑了
  "ok": bool,           # 操作成功与否，取自工具自述的 ok（普通返回值视为成功）
  "status": "success" | "failed" | "rejected" | "dispatch_error" | "partial" | "empty" | "timeout"
  "result": <原始返回值>,
  "summary": <工具自述摘要>,
  "artifacts": [...],
  "error": str | None
}
```

| 情形 | dispatched | ok | status |
|---|---|---|---|
| 未知工具 | False | False | dispatch_error |
| 依赖缺失 | False | False | dispatch_error |
| 参数类型错误（TypeError） | False | False | dispatch_error |
| 工具抛异常 | True | False | failed |
| 工具返回 `{"ok": false}` | True | False | failed |
| 工具返回 `{"ok": true}` | True | True | success（或工具自述 status） |
| 工具返回普通对象（legacy） | True | True | success |

Runtime 用 `dispatched` 决定"是否算拒绝"，用 `ok` 决定"操作是否成功"，
并把两者都写进 Turn、evidence、result.json；失败时的 artifacts 照样保留。
