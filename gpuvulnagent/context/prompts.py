# -*- coding: utf-8 -*-
"""Prompt assembly: system contract, initial user message, resume recap.

The system prompt states what counts as a conclusion and what does not. It deliberately
does not prescribe steps: the agent chooses the method, the runtime only insists that a
claim is backed by something it can point at.

Tool schemas travel in the API request (native function calling), so the prompt carries a
short menu for orientation plus an explicit reminder that ``tool_search`` exists - an agent
cannot discover an unregistered capability by guessing its name.
"""

from __future__ import annotations

from typing import List

SYSTEM = """你是一个自主的 NVIDIA GPU 漏洞研究 Agent，在 Windows 主机上工作。

你的任务：用真实可执行的工具把研究目标推进到"有证据的结论"。没有人给你规定步骤，
也不要求你复现某个已知漏洞。

工作方式：
- 你有原生工具调用能力。需要外部信息或需要执行时就调用工具，不要凭记忆断言环境事实。
- 一轮可以调用多个工具；工具结果会带着 exit/termination 和 artifact 引用回到你这里。
- 不知道有什么工具可用时，先调用 tool_search（可按用途、文件格式、依赖搜索），
  再用 tool_describe 看参数、位置和能否运行。项目里的适配器即使依赖缺失也会出现在目录中。
- 大输出被截断时用 artifact_read 按 offset 续读，不要重复执行同一命令。

证据规则（重要）：
- 区分「推测」「工具输出显示」「已复现」三种强度，并用词准确。
- 只有你实际执行并留下可核验记录的结果才能写成 finding；finding 必须引用 evidence id
  （形如 run-xxxx#12，见工具结果里的 evidence_id）。没有证据就写 hypothesis。
- 工具报错时先读错误内容，再决定换工具、换参数还是换方法；不要把报错当成目标行为。
- 记忆里有失败过的方向，先看 memory_search 的结果，避免重复。

边界：
- 只写工作区内的文件；不要修改系统驱动、不要安装需要管理员权限的组件。
- 不要试图读取或输出密钥。

结束时（不再调用工具）用自然语言给出最终结论，包含：
做了什么、实际观测到什么、哪些有证据、哪些仍是推测、还缺什么条件。
"""

JSON_FALLBACK_HINT = """
如果一个工具需要调用，你也可以只输出一个 JSON 对象：
{"thought": "...", "tool": "<工具名>", "args": {...}}
结束则输出 {"thought": "...", "final": "..."}。
"""


def initial_message(*, goal: str, workspace: str, digest: str, menu: List[str],
                    remaining: int, case_id: str = "", evidence_path: str = "") -> str:
    lines = ["# 研究目标", "", goal.strip(), ""]
    if case_id:
        lines += ["# 案例", "", "case_id: %s" % case_id, ""]
    lines += ["# 工作区", "",
              "所有写入都在这里：%s" % workspace,
              "证据日志：%s（每条工具结果自动追加，含 hash chain）" % evidence_path, ""]
    if digest:
        lines += ["# 记忆（跨 run 共享，含已否证方向）", "", digest, ""]
    lines += ["# 可直接调用的工具", ""]
    lines += menu[:60] if menu else ["(无)"]
    lines += ["", "以上只是摘要；tool_search / tool_describe 可以查全部能力、参数与可运行性。", "",
              "剩余决策轮次：%d" % remaining]
    return "\n".join(lines)


def resume_section(turns: List[dict], limit: int = 10) -> str:
    """Prior turns rendered as text: a resumed run must not fake tool protocol ids."""
    if not turns:
        return ""
    lines = ["# 恢复：本 run 之前已完成的工作", ""]
    for turn in turns[-limit:]:
        lines.append("- 第%s步 %s -> %s" % (turn.get("step"), turn.get("tool"),
                                            turn.get("status")))
        if turn.get("observation"):
            lines.append("  观测: %s" % str(turn["observation"])[:300])
    lines += ["", "完整记录见 evidence.jsonl。"]
    return "\n".join(lines)


def budget_note(remaining: int) -> str:
    return "剩余决策轮次：%d。请优先收敛到可核验的结论。" % remaining
