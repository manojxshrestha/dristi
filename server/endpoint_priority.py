"""Endpoint Prioritization for risk-weighted test ordering.

Scores endpoints by attack surface characteristics and sorts them
so that highest-risk endpoints are tested first. This avoids spending
time on low-value static endpoints when high-value API endpoints exist.

Inspired by Dristi-DRL's CVSS-weighted reward signals.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

# These get set by server.py after import
PRIORITY_QUEUE_DIR: Path = Path(".")
_atomic_write_json = None
_append_event = None


def configure(priority_queue_dir: Path, atomic_write_fn, append_event_fn):
    """Called by server.py to inject shared dependencies."""
    global PRIORITY_QUEUE_DIR, _atomic_write_json, _append_event
    PRIORITY_QUEUE_DIR = priority_queue_dir
    _atomic_write_json = atomic_write_fn
    _append_event = append_event_fn


# ── Scoring Algorithm ─────────────────────────────────────────────

TECH_RISK_SCORES = {
    "php": 5,
    "asp": 5,
    "asp.net": 5,
    "jsp": 4,
    "java": 3,
    "spring": 3,
    "node": 3,
    "express": 3,
    "next": 2,
    "python": 2,
    "flask": 2,
    "django": 2,
    "fastapi": 2,
    "ruby": 3,
    "rails": 3,
    "go": 1,
    "golang": 1,
    "rust": 1,
    "static": 0,
    "cdn": 0,
}

METHOD_SCORES = {
    "POST": 3,
    "PUT": 3,
    "PATCH": 2,
    "DELETE": 2,
    "GET": 1,
    "HEAD": 0,
    "OPTIONS": 0,
}


def _score_endpoint(ep: dict) -> float:
    """Score an endpoint based on attack surface characteristics.

    Scoring factors:
    - Parameter count: more params = more attack surface (max 10)
    - Technology risk: PHP/ASP > Java/Node > Python > Go/static
    - Taint chain: source code analysis found a confirmed sink
    - Tool convergence: multiple recon tools found this endpoint
    - User input: endpoint accepts user-controlled input
    - Auth: unauthenticated endpoints = quick wins, test first
    - HTTP method: state-changing methods (POST/PUT) > GET
    """
    score = 0.0

    # Parameter count (more params = more attack surface, cap at 10)
    params = ep.get("parameters", [])
    param_count = len(params) if isinstance(params, list) else 0
    score += min(param_count * 2, 10)

    # Technology risk score
    tech = ep.get("tech_stack", "").lower()
    tech_score = 0
    for tech_key, tech_val in TECH_RISK_SCORES.items():
        if tech_key in tech:
            tech_score = max(tech_score, tech_val)
    if tech_score == 0 and tech:
        tech_score = 2  # Unknown tech defaults to medium
    score += tech_score

    # Source code taint chain identified
    if ep.get("has_taint_chain"):
        score += 5

    # Multiple tools discovered this endpoint (convergence signal)
    tool_count = ep.get("tool_count", 1)
    score += min(tool_count, 3)

    # Accepts user input
    if params:
        score += 2

    # Authentication not required (test first for quick wins)
    if not ep.get("auth_required", True):
        score += 3

    # HTTP method (state-changing = higher priority)
    method = ep.get("method", "GET").upper()
    score += METHOD_SCORES.get(method, 1)

    # Bonus: endpoint has specific high-value indicators
    path = ep.get("path", "").lower()
    if any(indicator in path for indicator in ["/api/", "/admin/", "/upload", "/import", "/exec", "/eval", "/search"]):
        score += 2
    if any(indicator in path for indicator in ["/login", "/auth", "/token", "/password", "/reset"]):
        score += 1

    # Bonus: parameter names suggest injectable contexts
    param_names = []
    if isinstance(params, list):
        for p in params:
            if isinstance(p, dict):
                param_names.append(p.get("name", "").lower())
            elif isinstance(p, str):
                param_names.append(p.lower())

    injectable_params = {"id", "user", "name", "query", "search", "q", "url", "file", "path", "page", "redirect", "callback", "cmd", "exec", "template", "email", "sort", "order", "filter"}
    param_bonus = sum(1 for p in param_names if p in injectable_params)
    score += min(param_bonus * 1.5, 6)

    return round(score, 1)


def _format_endpoint_line(ep: dict, rank: int) -> str:
    """Format a single endpoint as a markdown line."""
    method = ep.get("method", "GET")
    path = ep.get("path", "?")
    score = ep.get("_score", 0)
    params = ep.get("parameters", [])

    # Build tags
    tags = []
    if ep.get("has_taint_chain"):
        tags.append("TAINT")
    if not ep.get("auth_required", True):
        tags.append("NOAUTH")
    if ep.get("tool_count", 1) > 1:
        tags.append(f"{ep['tool_count']}tools")

    param_str = ""
    if params:
        if isinstance(params[0], dict):
            param_str = ", ".join(p.get("name", "?") for p in params[:5])
        else:
            param_str = ", ".join(str(p) for p in params[:5])
        if len(params) > 5:
            param_str += f", +{len(params) - 5} more"

    tag_str = f" [{', '.join(tags)}]" if tags else ""
    param_display = f" — params: {param_str}" if param_str else ""

    return f"{rank}. **{method} {path}** (score: {score}){tag_str}{param_display}"


# ── MCP Tool Functions ───────────────────────────────────────────


def prioritize_endpoints(engagement_id: str, endpoints_json: str) -> str:
    """Score and sort endpoints by risk for prioritized testing.
    Higher scores = higher attack surface = test first.

    Args:
        engagement_id: The engagement identifier
        endpoints_json: JSON array of endpoint objects. Each object should have:
            method (str), path (str), parameters (list), auth_required (bool),
            tech_stack (str), has_taint_chain (bool), tool_count (int)
    """
    try:
        endpoints = json.loads(endpoints_json)
    except json.JSONDecodeError as e:
        return f"Invalid JSON: {e}"

    if not isinstance(endpoints, list):
        return "endpoints_json must be a JSON array of endpoint objects."

    if not endpoints:
        return "No endpoints provided."

    # Score each endpoint
    for ep in endpoints:
        ep["_score"] = _score_endpoint(ep)

    # Sort by score descending
    endpoints.sort(key=lambda x: x["_score"], reverse=True)

    # Save to queue
    queue_data = {
        "engagement_id": engagement_id,
        "endpoint_count": len(endpoints),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "endpoints": endpoints,
    }

    PRIORITY_QUEUE_DIR.mkdir(parents=True, exist_ok=True)
    queue_file = PRIORITY_QUEUE_DIR / f"{engagement_id}.json"
    _atomic_write_json(queue_file, queue_data)

    if _append_event:
        _append_event(
            engagement_id,
            {
                "tool": "prioritize_endpoints",
                "args": {"endpoint_count": len(endpoints)},
                "result": f"Scored and sorted {len(endpoints)} endpoints",
            },
        )

    # Format output
    lines = [f"# Endpoint Priority Queue: {engagement_id}\n"]
    lines.append(f"**Total endpoints**: {len(endpoints)}")
    max_score = endpoints[0]["_score"] if endpoints else 0
    min_score = endpoints[-1]["_score"] if endpoints else 0
    lines.append(f"**Score range**: {min_score} — {max_score}\n")

    # Show top 20
    lines.append("## Top Priority Endpoints\n")
    for i, ep in enumerate(endpoints[:20], 1):
        lines.append(_format_endpoint_line(ep, i))

    if len(endpoints) > 20:
        lines.append(f"\n_...and {len(endpoints) - 20} more. Use get_priority_queue() to see all._")

    return "\n".join(lines)


def get_priority_queue(engagement_id: str, limit: int = 0) -> str:
    """Retrieve the saved endpoint priority queue.

    Args:
        engagement_id: The engagement identifier
        limit: Maximum number of endpoints to return. 0 = all endpoints.
    """
    queue_file = PRIORITY_QUEUE_DIR / f"{engagement_id}.json"
    if not queue_file.exists():
        return f"No priority queue found for {engagement_id}. Call prioritize_endpoints() first."

    data = json.loads(queue_file.read_text(encoding="utf-8"))
    endpoints = data.get("endpoints", [])
    created = data.get("created_at", "?")

    lines = [f"# Priority Queue: {engagement_id}\n"]
    lines.append(f"**Created**: {created}")
    lines.append(f"**Total endpoints**: {len(endpoints)}\n")

    display = endpoints[:limit] if limit > 0 else endpoints

    for i, ep in enumerate(display, 1):
        lines.append(_format_endpoint_line(ep, i))

    if limit > 0 and len(endpoints) > limit:
        lines.append(f"\n_Showing {limit}/{len(endpoints)}. Use limit=0 for all._")

    return "\n".join(lines)
