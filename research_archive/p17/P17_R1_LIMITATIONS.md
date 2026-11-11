# P17-R1 局限与未完成项

## 一、本轮明确未做

1. 多 Agent、Coordinator；
2. MCP 生态接入；
3. 向量库 / 知识图谱；
4. 新的 PoC 生成器或 CUDA 专用工具；
5. GPU 内核/驱动侧沙箱；
6. 修改任何历史 CVE 判据或统计口径。

## 二、能力的真实边界

### 2.1 Shell ≠ 沙箱

`shell` 以当前用户身份执行**宿主机**命令。`Workspace` 只约束 `fs_*` 工具的写入路径，
**不构成文件系统隔离**：`shell("del /s ...")` 完全可能越过工作区。

Agent 能做的事等于运行它的用户能做的事。本轮没有降权、没有容器化、没有审批层。
需要真正的隔离时，应把 Agent 整体放进受限账户或容器，而不是指望路径检查。

### 2.2 Hash chain 是篡改可发现，不是防篡改

有写权限的人可以重写整份 `evidence.jsonl` 并重建自洽链。它能发现误删、误改、换序，
不能抵抗有意伪造。要更强保证需要外部锚（签名/时间戳/异地副本），本轮未实现。

### 2.3 Resume 的重复执行风险

若进程在工具执行中途死亡，运行时无法判断该工具是否完成。当前策略是标记
`INTERRUPTED / EXECUTION_STATE_UNKNOWN` 并**不自动重放**，但没有幂等性判断，
也没有"人工确认后继续"的交互通道——需要调用者自己看 `run.json` 决定。

### 2.4 原生 tool calling 未接入主循环

`NativeActionModel` 已实现并通过单元测试，provider 也实测支持，但 `AgentRuntime`
默认仍走 JSON 协议。没有在真实案例上对比两种模式的稳定性。

### 2.5 Token 统计仍缺失

`LLMClient.chat()` 不返回 usage，运行时无法记录 token 消耗。本轮未改 `src/llm_client.py`。

### 2.6 证据与"已验证结论"之间没有自动闸门

`memory.add("finding", ...)` 强制要求 evidence id，但**不校验该 id 是否真的存在**，
也不判断证据是否足以支撑结论。这是刻意的：判断强度仍是人的责任。

## 三、已知工程债

| 项 | 影响 |
|---|---|
| `agent/evidence.py` 与 `src/exec_evidence.py` 职责重叠 | 两套证据模型并存，旧模块仅服务历史实验 |
| `Runner` 与 `Workspace` 的根目录可以不一致 | 已在运行时对齐，但接口允许误用 |
| `_load_turns()` 只恢复工具轮，不恢复 thought | resume 后 prompt 里上一轮的想法缺失 |
| 归档目录 `data/agent/archive/` 未进 `.gitignore` | 会随提交进入仓库（本轮有意如此，便于审计） |
