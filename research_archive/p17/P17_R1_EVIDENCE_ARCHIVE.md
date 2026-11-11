# 历史实验材料归档

## 现状核查

| 项 | 结果 |
|---|---|
| 本地 `data/agent/runs/p17_case1` | **存在**，16 个文件 |
| 本地 `data/agent/runs/p17_case2` | **存在**，17 个文件 |
| 远程 Git Tree | **不存在**（只提交了 `data/agent/goal_*.md` 两个文件） |
| 原因 | `.gitignore:64` 的 `runs/` 规则把整棵运行目录排除，`git add data/agent` 静默跳过 |
| 完整性 | 两段的 `transcript.jsonl`、`evidence.jsonl`、`memory.jsonl`、`result.json`、`workspace/*` 齐全 |

轮次核对：case1 transcript 10 条模型动作（与 P17 报告一致），case2 12 条，一致。

## 归档方式

复制到 `data/agent/archive/<case>/`（不在 `runs/` 规则下），由 `tools/agent_archive.py` 处理：

- 逐文件计算原始 SHA256；
- 扫 `sk-*`、`api_key=`、`Authorization: Bearer`、`C:\Users\<name>` 并脱敏；
- 记录脱敏命中数与归档后 SHA256；
- 生成 `archive.json` 作为清单。

## 结果

| 用例 | 文件数 | 需要脱敏 | 清单 |
|---|---|---|---|
| p17_case1 | 16 | 0 | `data/agent/archive/p17_case1/archive.json` |
| p17_case2 | 17 | 0 | `data/agent/archive/p17_case2/archive.json` |

**原始目录未修改**：`data/agent/runs/` 保持原样，归档是副本；每个文件的
`sha256_original` 与 `sha256_archived` 都写在 `archive.json` 里，本次两者相同（无脱敏）。

## 未做

- 没有为缺失的历史材料补造数据；
- 没有把新实验冒充为旧实验；
- 没有取消 `runs/` 忽略规则（归档放在独立路径，规则保持原样）。
