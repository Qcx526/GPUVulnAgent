# Harness evaluation: what actually degrades long agent runs

## Method

Every number below comes from a run's `result.json` (decisions, usage, turns) and its
`tool_calls.jsonl`. A tool call counts as failed when its recorded status is not `success`.

| run | decisions | tokens | failed / total tool calls | tokens per decision |
|---|---|---|---|---|
| P19 autonomy run A | 12 | 220,292 | 0 / 17 | 18k |
| P19 autonomy run B | 10 | 195,987 | 0 / 15 | 19k |
| P19 autonomy run C | 10 | 233,138 | 0 / 20 | 23k |
| P23-R1 blind CVE | 30 | 1,286,497 | 7 / 43 | 42k |
| SPRINT R1 | 25 | 647,091 | 8 / 34 | 25k |
| R1 retry | 14 | 220,530 | 8 / 22 | 15k |
| R2 (budget unwired) | 12 | 164,696 | 6 / 19 | 13k |
| R2 retry | 9 | 109,671 | 4 / 13 | 12k |
| R4 | 8 | 121,423 | 0 / 12 | 15k |
| R5 | 8 | 118,208 | 3 / 12 | 14k |

## What the data says

1. **The model does not "think instead of acting".** In every run, including R4/R5/R6, the first
   tool call lands on decision 1. No run spent turns only analysing. The hypothesis that opened
   this task is not supported by the transcripts.
2. **The failure rate separates the runs that produced something from the ones that did not.**
   P19's three autonomy runs failed 0 of 17, 0 of 15 and 0 of 20 calls, and finished. P23-R1 -
   the only run that produced a real crash differential - failed 7 of 43. The sprint runs that
   never executed a target sat at 24-36%: 8/34, 8/22, 6/19, 4/13.
3. **Context per decision is 1.5-2.5x higher where it mattered least.** P19 averages ~18k tokens
   per decision, P23-R1 ~43k, the sprint runs ~26k while doing less. A 100k cap buys about four
   decisions there, two of which go to recovering from a rejected call.
4. **Failures compound.** A rejected call still costs a full prompt, and the model then re-reads
   material it already had, inflating the next prompt. R4 spent 8 decisions and 121k tokens with
   zero executions, after two `repo:` paths that did not exist.
5. **The budget was enforced one request too late.** R6 spent 118,208 against a 100,000 cap
   because the check ran after the response. Fixed: the runtime now reserves the next prompt and
   stops before sending a request that would not fit.

## Framework evaluation

| option | fit here | verdict |
|---|---|---|
| LangChain `create_agent` | thin loop, no durable state, tool errors still passed back verbatim | not enough alone |
| LangGraph `StateGraph` + checkpointer | durable state, interrupt/resume, per-step context control | adopt the checkpointer idea |
| Deep Agents SDK | subagents, summarisation, file-backed memory, but its own filesystem and tool layers would duplicate Trail / Artifact / Evidence | not adopted now |
| LangChain `ChatDeepSeek` | would replace a provider that already handles reasoning_content and usage | not adopted |

Recommendation: keep `AgentRuntime`, `ToolRegistry`, `Evidence`, `Artifact` and `Trial`, and take
three mechanisms rather than a framework:

1. **Resumable state per trial.** `run.json` already holds the state; add an explicit checkpoint
   after every tool call so a killed run can continue instead of starting over.
2. **Context compaction with a size rule.** Tool results above N bytes are offloaded to the
   artifact store and replaced by a reference plus hash. Tool output is what makes prompts 43k,
   so this is the largest single lever.
3. **Schema-tight rejections.** Already partly done: a rejected call now lists the accepted
   parameters, which is what lets a model repair itself in one step.

## Honest status

This recommendation is a design decision, not a verified result: **no LangGraph or deepagents
prototype has been run against the real API.** A spike on `experiment/deepagents-harness-spike`
would have to show three things before any migration: the P19 Golden Task still passes, tokens
per decision drop, and a killed run resumes from its checkpoint. Until then, the measurable fixes
above are the ones worth keeping.
