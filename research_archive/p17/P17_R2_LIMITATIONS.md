# P17-R2 局限

1. **`artifact_read` 只能读本次 run 的 artifacts**，不能跨 run 检索；历史归档里的文件要用
   `fs_read`（受 workspace 约束）或自行复制。
2. **搜索摘要不是网页正文**：`web_search` 的 `content` 字段是搜索引擎给出的片段（≤600 字符），
   判断正文必须 `web_extract`，两者在 summary 里已有明确区分，但模型仍可能混用。
3. **部分失败判定粗粒度**：`failed_results` 非空即 `partial`，不区分"部分成功"与"全部失败但
   返回了空壳结果"。
4. **状态语义尚未进入评分**：Runtime 现在如实记录 `dispatched/ok/status`，但没有任何下游逻辑
   据此拒绝"把失败当成功"的结论——那仍然是人的判断。
5. **真实验收只覆盖一条查询**：NVIDIA 官方公告检索成功，不代表检索质量在任意主题上稳定。
6. **未验证**：Tavily 限流/超时下的重试策略（当前无重试，一次失败即记录并返回）。
7. **未改动**：token 统计仍缺；`src/llm_client.py` 未修改。
