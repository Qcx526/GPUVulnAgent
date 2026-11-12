# Trial directory spec

`runs/trial0`, `trial1`, ... allocated by `mkdir` (atomic, never reused).

| section | content |
|---|---|
| `session/task.json` | goal, case id, created_at |
| `session/transcript.jsonl` | one line per decision (thought, tool, args, status, evidence id) |
| `session/decisions.jsonl` | decision summary + usage |
| `session/tool_calls.jsonl` | tool, arguments, tool_call_id, via/mode, observation |
| `session/run/` | runtime state: run.json, workspace/, trails/ |
| `poc/manifests/<id>.json`, `poc/INDEX.md` | per-artifact provenance and a human table |
| `evidence/evidence.jsonl` | the hash chain (single authoritative log) |
| `evidence/artifact_index.{json,jsonl}` | registry view + journal |
| `report/final_report.md` | goal, status, artifact table, conclusion |

The run lives inside `session/run` so the trial owns the evidence chain while the runtime
keeps its workspace and trails. Nothing in a trial directory is overwritten.
