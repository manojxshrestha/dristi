#!/usr/bin/env bash
# =============================================================================
# dispatch_hunt.sh — Generate Phase 6 agent dispatch list + coverage matrix
#
# Reads agents/registry.yaml, filters by target tech stack (optional),
# and produces two files for the AI to consume:
#   1. $OUT_DIR/hunt/dispatch_list.json   — ordered list of agents to dispatch
#   2. $OUT_DIR/hunt/coverage_matrix.csv  — track dispatch status per agent
#
# The AI agent MUST then dispatch EVERY agent in dispatch_list.json by
# calling task(subagent_type="<id>", ...) for each one.
#
# Usage:
#   bash scripts/dispatch_hunt.sh <domain> [--tech tech1,tech2,...]
#
# Examples:
#   bash scripts/dispatch_hunt.sh target.com
#       -> dispatches ALL mandatory + tech-stack agents
#
#   bash scripts/dispatch_hunt.sh target.com --tech nextjs,aws,rails
#       -> dispatches mandatory + tech-stack agents matching nextjs/aws/rails
#
#   bash scripts/dispatch_hunt.sh target.com --tech-only nextjs,aws
#       -> dispatches ONLY agents matching these tech stacks (no mandatory)
# =============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"
source "$TOOLS_DIR/_env.sh"

TARGET="${1:?Usage: $0 <domain> [--tech a,b,c] [--tech-only a,b,c]}"
shift

TECH_FILTER=""
FILTER_MODE="add"
while [ $# -gt 0 ]; do
  case "$1" in
    --tech)
      TECH_FILTER="$2"
      FILTER_MODE="add"
      shift 2
      ;;
    --tech-only)
      TECH_FILTER="$2"
      FILTER_MODE="only"
      shift 2
      ;;
    *)
      log_err "Unknown option: $1"
      exit 1
      ;;
  esac
done

# -- Paths --
REGISTRY="$DRISTI_ROOT/agents/registry.yaml"
OUT_DIR="${RECON_BASE}/${TARGET}"
HUNT_DIR="$OUT_DIR/hunt"
DISPATCH_FILE="$HUNT_DIR/dispatch_list.json"
COVERAGE_FILE="$HUNT_DIR/coverage_matrix.csv"
mkdir -p "$HUNT_DIR"

if [ ! -f "$REGISTRY" ]; then
  log_err "Registry not found: $REGISTRY"
  exit 1
fi

# -- Parse registry.yaml and generate dispatch files --
python3 << PYEOF
import json, sys, os, re
from datetime import datetime, timezone

registry_path = "$REGISTRY"
tech_filter_str = "$TECH_FILTER"
filter_mode = "$FILTER_MODE"
target = "$TARGET"
dispatch_file = "$DISPATCH_FILE"
coverage_file = "$COVERAGE_FILE"

tech_filter = [t.strip().lower() for t in tech_filter_str.split(",") if t.strip()] if tech_filter_str else []

def parse_registry(path):
    with open(path) as f:
        lines = f.readlines()
    agents = []
    current = None
    in_agents = False
    for line in lines:
        s = line.rstrip()
        if s.startswith("agents:"):
            in_agents = True
            continue
        if s.startswith("#") and "mapping" in s.lower():
            in_agents = False
        if not in_agents:
            continue
        stripped_line = s.strip()
        if stripped_line.startswith("- id:"):
            if current:
                agents.append(current)
            current = {"id": stripped_line.split(":",1)[1].strip(), "category": "", "priority": "", "description": "", "tech_stack": []}
        elif current:
            m = re.match(r"^\s+(\w+):\s*(.*)", s)
            if m:
                k, v = m.group(1), m.group(2).strip()
                if k == "tech_stack":
                    v = v.strip("[]")
                    current["tech_stack"] = [x.strip().strip("'\"") for x in v.split(",") if x.strip()]
                elif k in ("id","category","priority","description"):
                    current[k] = v.strip("'\"")
    if current:
        agents.append(current)
    return agents

agents = parse_registry(registry_path)

mandatory = [a for a in agents if a.get("priority") == "mandatory"]
tech_match = [a for a in agents if a.get("priority") == "tech-stack-match"]
recommended = [a for a in agents if a.get("priority") == "recommended"]

if tech_filter:
    if filter_mode == "only":
        selected = [a for a in tech_match if any(t in tech_filter for t in a.get("tech_stack", []))]
        filtered_agents = selected
    else:
        matched_tech = [a for a in tech_match if any(t in tech_filter for t in a.get("tech_stack", []))]
        filtered_agents = mandatory + matched_tech + recommended
else:
    filtered_agents = mandatory + tech_match + recommended

dispatch = {
    "domain": target,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "tech_stack_filter": tech_filter if tech_filter else ["all"],
    "summary": {
        "mandatory": len(mandatory),
        "tech_stack_match": len(tech_match),
        "recommended": len(recommended),
        "total": len(filtered_agents),
        "tech_filter_applied": bool(tech_filter),
        "tech_filter_values": tech_filter or [],
    },
    "agents": filtered_agents
}

with open(dispatch_file, "w") as f:
    json.dump(dispatch, f, indent=2)

csv_lines = ["agent,category,priority,dispatched,findings,status"]
for a in filtered_agents:
    csv_lines.append(f"{a['id']},{a['category']},{a['priority']},,,pending")
with open(coverage_file, "w") as f:
    f.write("\n".join(csv_lines) + "\n")

agent_ids = "\n    ".join([a["id"] for a in filtered_agents])
tech_info = ", ".join(tech_filter) if tech_filter else "ALL (no filter)"

summary = f"""
[DISPATCH SUMMARY]
  Target:        {target}
  Tech filter:   {tech_info}
  Mandatory:     {len(mandatory)} agents
  Tech-match:    {len(tech_match)} agents
  Recommended:   {len(recommended)} agents
  Total:         {len(filtered_agents)} agents to dispatch
  Dispatch list: {dispatch_file}
  Coverage:      {coverage_file}

  [DISPATCH INSTRUCTIONS]
  You MUST dispatch EVERY agent in the dispatch list.
  Do NOT skip any agent. Dispatch ALL of them.

  Agents to dispatch:
    {agent_ids}

  For each agent, call the task() tool:
    task(description="Phase 6: ID on TARGET", subagent_type="ID")
    where ID = agent id from the list and TARGET = {target}

  After each agent completes, run:
    1. Update coverage at {coverage_file}:
       - Change status from 'pending' to 'complete'
       - Record findings count in the findings column
    2. Call WSTG tracking:
       bash scripts/wstg_track_from_agent.sh <engagement_id> "{target}" "ID" "completed"
       (where ID = agent id, engagement_id = target identifier like "intercom")

  When ALL agents show 'complete' status, the Phase 6 gate will pass.
"""
print(summary.strip())
PYEOF

log_ok "Dispatch list generated: $DISPATCH_FILE"
log_ok "Coverage matrix generated: $COVERAGE_FILE"
