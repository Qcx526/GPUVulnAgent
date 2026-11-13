# -*- coding: utf-8 -*-
"""Run a LangGraph campaign. `--resume` continues the same thread from the checkpoint."""
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gpuvulnagent.agents.langgraph_agent import run_campaign
from gpuvulnagent.backends.wsl_docker import WslConfig, WslDockerBackend
from gpuvulnagent.config import ConfigLoader
from gpuvulnagent.evidence import ArtifactStore, EvidenceLog, Runner
from gpuvulnagent.memory.store import LayeredMemory
from gpuvulnagent.runtime.workspace import Workspace
from gpuvulnagent.tools.build import build_assembly

ap = argparse.ArgumentParser()
ap.add_argument("--campaign", required=True)
ap.add_argument("--goal", default="")
ap.add_argument("--goal-file", default="")
ap.add_argument("--case", default="")
ap.add_argument("--tokens", type=int, default=300000)
ap.add_argument("--steps", type=int, default=40)
ap.add_argument("--resume", action="store_true")
a = ap.parse_args()

settings = ConfigLoader()
root = Path(a.campaign)
goal = Path(a.goal_file).read_text(encoding="utf-8") if a.goal_file else a.goal
log = EvidenceLog(root / "evidence" / "evidence.jsonl",
                  root.name, ArtifactStore(root / "artifacts"))
ws = Workspace(root / "workspace")
asm = build_assembly(workspace=ws, runner=Runner(ws.root, log, 180), log=log,
                     memory=LayeredMemory(run_dir=root, research_root=root.parent / "memory",
                                          run_id=root.name, case_id=a.case),
                     toolchain_root=settings.paths.toolchain_root,
                     tavily_api_key=settings.tavily_api_key,
                     backend_config=WslConfig.from_settings(settings))
out = run_campaign(registry=asm.registry, log=log, campaign_dir=root, goal=goal,
                   campaign_id=root.name, model=settings.llm.model,
                   base_url=settings.llm.base_url, api_key=settings.llm.api_key,
                   max_tokens=a.tokens, max_steps=a.steps, resume=a.resume)
final = ""
for m in reversed(out["messages"]):
    if getattr(m, "content", "") and not getattr(m, "tool_calls", None):
        final = m.content if isinstance(m.content, str) else str(m.content)
        break
print(json.dumps({"campaign": out["campaign"]["campaign_id"], "resumed": out["resumed"],
                  "steps": out["steps"], "tokens": out["spent_tokens"],
                  "facts": out["campaign"]["facts"][-8:]}, ensure_ascii=False))
print("\nFINAL:\n" + final[:1500])
