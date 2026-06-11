"""Hierarchical Task Tree for pentest engagement planning.

Provides a persistent tree structure where phases are branches and tests/endpoints
are leaves. Replaces flat todo tracking with strategic, hierarchical state that
survives context loss across subagents.

Inspired by PentestGPT's Pentesting Task Tree (PTT) — USENIX Security 2024.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# These get set by server.py after import
TASK_TREE_DIR: Path = Path(".")
_atomic_write_json = None
_append_event = None


def configure(task_tree_dir: Path, atomic_write_fn, append_event_fn):
    """Called by server.py to inject shared dependencies."""
    global TASK_TREE_DIR, _atomic_write_json, _append_event
    TASK_TREE_DIR = task_tree_dir
    _atomic_write_json = atomic_write_fn
    _append_event = append_event_fn


# ── Data Helpers ──────────────────────────────────────────────────


def _load_tree(engagement_id: str) -> dict | None:
    """Load tree from disk. Returns None if not found."""
    tree_file = TASK_TREE_DIR / f"{engagement_id}.json"
    if not tree_file.exists():
        return None
    return json.loads(tree_file.read_text(encoding="utf-8"))


def _save_tree(engagement_id: str, tree: dict) -> None:
    """Save tree to disk using atomic write."""
    TASK_TREE_DIR.mkdir(parents=True, exist_ok=True)
    tree_file = TASK_TREE_DIR / f"{engagement_id}.json"
    _atomic_write_json(tree_file, tree)


def _slugify(label: str) -> str:
    """Convert label to a URL-safe slug for node IDs."""
    slug = label.lower().strip()
    slug = re.sub(r"[^a-z0-9\s-]", "", slug)
    slug = re.sub(r"[\s]+", "-", slug)
    slug = re.sub(r"-+", "-", slug)
    return slug[:50].strip("-")


def _make_node(
    node_id: str,
    parent_id: str | None,
    label: str,
    priority: str = "medium",
    notes: str = "",
) -> dict:
    """Create a new tree node."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": node_id,
        "parent_id": parent_id,
        "label": label,
        "status": "pending",
        "priority": priority,
        "notes": notes,
        "findings_count": 0,
        "children": [],
        "created_at": now,
        "updated_at": now,
    }


def _unique_id(tree: dict, base_slug: str) -> str:
    """Generate a unique node ID from a slug, appending counter if needed."""
    nodes = tree["nodes"]
    if base_slug not in nodes:
        return base_slug
    counter = 2
    while f"{base_slug}-{counter}" in nodes:
        counter += 1
    return f"{base_slug}-{counter}"


def _compute_completion(tree: dict, node_id: str) -> float:
    """Compute completion percentage for a node based on its children."""
    node = tree["nodes"].get(node_id)
    if not node:
        return 0.0
    children = node.get("children", [])
    if not children:
        # Leaf node — completed/skipped = 100%, else 0%
        return 100.0 if node["status"] in ("completed", "skipped") else 0.0
    completed = sum(1 for cid in children if tree["nodes"].get(cid, {}).get("status") in ("completed", "skipped"))
    return round((completed / len(children)) * 100, 1) if children else 0.0


def _status_icon(status: str) -> str:
    """Get a text icon for a status."""
    icons = {
        "completed": "[x]",
        "skipped": "[-]",
        "in_progress": "[>]",
        "blocked": "[!]",
        "pending": "[ ]",
    }
    return icons.get(status, "[ ]")


def _render_tree(tree: dict, node_id: str, depth: int, max_depth: int, indent: int = 0) -> list[str]:
    """Recursively render tree as markdown lines."""
    node = tree["nodes"].get(node_id)
    if not node:
        return []
    if depth > max_depth:
        return []

    icon = _status_icon(node["status"])
    children = node.get("children", [])
    prefix = "  " * indent

    if children:
        pct = _compute_completion(tree, node_id)
        findings = node.get("findings_count", 0)
        findings_tag = f" ({findings} findings)" if findings > 0 else ""
        line = f"{prefix}{icon} **{node['label']}** ({pct:.0f}%){findings_tag}"
    else:
        findings = node.get("findings_count", 0)
        findings_tag = f" [{findings}F]" if findings > 0 else ""
        line = f"{prefix}{icon} {node['label']}{findings_tag}"

    lines = [line]
    if node.get("notes") and depth < max_depth:
        lines.append(f"{prefix}   _Note: {node['notes'][:80]}_")

    for child_id in children:
        lines.extend(_render_tree(tree, child_id, depth + 1, max_depth, indent + 1))

    return lines


def _auto_propagate(tree: dict, node_id: str) -> None:
    """If all children are completed/skipped, mark parent as completed."""
    node = tree["nodes"].get(node_id)
    if not node or not node.get("parent_id"):
        return

    parent = tree["nodes"].get(node["parent_id"])
    if not parent or not parent.get("children"):
        return

    all_done = all(tree["nodes"].get(cid, {}).get("status") in ("completed", "skipped") for cid in parent["children"])
    if all_done and parent["status"] != "completed":
        parent["status"] = "completed"
        parent["updated_at"] = datetime.now(timezone.utc).isoformat()
        # Recurse up
        _auto_propagate(tree, parent["id"])


# ── Default Phase Template ────────────────────────────────────────

DEFAULT_PHASES = [
    ("phase--1", "Phase -1: Source Code Analysis", "low"),
    ("phase-0", "Phase 0: Discovery & Mapping", "critical"),
    ("phase-1", "Phase 1: Information Gathering", "high"),
    ("phase-2", "Phase 2: Configuration Testing", "high"),
    ("phase-3", "Phase 3: Auth/Authz/Session", "critical"),
    ("phase-4", "Phase 4: Input Validation", "critical"),
    ("phase-5", "Phase 5: Error/Crypto/Business/Client/API", "high"),
    ("phase-6", "Phase 6: Reporting", "medium"),
    ("phase-7", "Phase 7: Final Judge Review", "medium"),
]


# ── MCP Tool Functions ───────────────────────────────────────────


def create_task_tree(engagement_id: str) -> str:
    """Create a hierarchical task tree for a pentest engagement.
    Initializes with the standard phase structure. Idempotent.

    Args:
        engagement_id: The engagement identifier
    """
    existing = _load_tree(engagement_id)
    if existing:
        node_count = len(existing["nodes"])
        return f"Task tree already exists for {engagement_id} " f"({node_count} nodes). Use get_task_tree() to view it."

    root_id = "pentest-root"
    tree: dict[str, Any] = {
        "root": root_id,
        "nodes": {},
    }

    # Create root
    tree["nodes"][root_id] = _make_node(root_id, None, f"Pentest: {engagement_id}", "critical")

    # Create phase nodes
    for phase_id, phase_label, priority in DEFAULT_PHASES:
        tree["nodes"][phase_id] = _make_node(phase_id, root_id, phase_label, priority)
        tree["nodes"][root_id]["children"].append(phase_id)

    _save_tree(engagement_id, tree)

    if _append_event:
        _append_event(
            engagement_id,
            {
                "tool": "create_task_tree",
                "args": {"engagement_id": engagement_id},
                "result": f"Created tree with {len(tree['nodes'])} nodes",
            },
        )

    return f"Task tree created for {engagement_id} with {len(DEFAULT_PHASES)} phases.\n" f"Use add_task_node() to add sub-tasks under any phase.\n" f"Use get_task_tree() to view the full tree."


def add_task_node(
    engagement_id: str,
    parent_id: str,
    label: str,
    priority: str = "medium",
    notes: str = "",
) -> str:
    """Add a task node to the engagement task tree.

    Args:
        engagement_id: The engagement identifier
        parent_id: ID of the parent node (e.g., 'phase-0', 'phase-4')
        label: Human-readable task description
        priority: One of: critical, high, medium, low
        notes: Optional notes about the task
    """
    valid_priorities = {"critical", "high", "medium", "low"}
    if priority not in valid_priorities:
        return f"Invalid priority '{priority}'. Must be one of: {', '.join(sorted(valid_priorities))}"

    tree = _load_tree(engagement_id)
    if not tree:
        return f"No task tree found for {engagement_id}. Call create_task_tree() first."

    if parent_id not in tree["nodes"]:
        valid_ids = ", ".join(sorted(tree["nodes"].keys())[:20])
        return f"Parent node '{parent_id}' not found. Available nodes: {valid_ids}"

    base_slug = _slugify(label)
    if not base_slug:
        base_slug = "task"
    node_id = _unique_id(tree, base_slug)

    node = _make_node(node_id, parent_id, label, priority, notes)
    tree["nodes"][node_id] = node
    tree["nodes"][parent_id]["children"].append(node_id)
    tree["nodes"][parent_id]["updated_at"] = datetime.now(timezone.utc).isoformat()

    # If parent was pending and now has children being worked on, mark in_progress
    if tree["nodes"][parent_id]["status"] == "pending":
        tree["nodes"][parent_id]["status"] = "in_progress"

    _save_tree(engagement_id, tree)

    if _append_event:
        _append_event(
            engagement_id,
            {
                "tool": "add_task_node",
                "args": {"parent_id": parent_id, "label": label},
                "result": f"Added node {node_id}",
            },
        )

    return f"Task node added: {node_id} (under {parent_id})"


def update_task_node(
    engagement_id: str,
    node_id: str,
    status: str = "",
    notes: str = "",
    findings_count: int = -1,
) -> str:
    """Update a task node's status, notes, or findings count.

    Args:
        engagement_id: The engagement identifier
        node_id: The node ID to update
        status: New status (pending, in_progress, completed, skipped, blocked). Empty = no change.
        notes: Updated notes. Empty = no change.
        findings_count: Updated findings count. -1 = no change.
    """
    valid_statuses = {"pending", "in_progress", "completed", "skipped", "blocked"}
    if status and status not in valid_statuses:
        return f"Invalid status '{status}'. Must be one of: {', '.join(sorted(valid_statuses))}"

    tree = _load_tree(engagement_id)
    if not tree:
        return f"No task tree found for {engagement_id}. Call create_task_tree() first."

    if node_id not in tree["nodes"]:
        return f"Node '{node_id}' not found in task tree."

    node = tree["nodes"][node_id]
    changes = []

    if status:
        old = node["status"]
        node["status"] = status
        changes.append(f"status: {old} -> {status}")

    if notes:
        node["notes"] = notes
        changes.append("notes updated")

    if findings_count >= 0:
        node["findings_count"] = findings_count
        changes.append(f"findings: {findings_count}")

    if not changes:
        return "No changes specified."

    node["updated_at"] = datetime.now(timezone.utc).isoformat()

    # Auto-propagate completion up the tree
    if status in ("completed", "skipped"):
        _auto_propagate(tree, node_id)

    _save_tree(engagement_id, tree)

    if _append_event:
        _append_event(
            engagement_id,
            {
                "tool": "update_task_node",
                "args": {"node_id": node_id, "changes": changes},
                "result": f"Updated {node_id}",
            },
        )

    return f"Node updated: {node_id} — {', '.join(changes)}"


def get_task_tree(engagement_id: str, max_depth: int = 3) -> str:
    """Get the full task tree as formatted markdown.

    Args:
        engagement_id: The engagement identifier
        max_depth: Maximum depth to render (default 3). Use higher for more detail.
    """
    tree = _load_tree(engagement_id)
    if not tree:
        return f"No task tree found for {engagement_id}. Call create_task_tree() first."

    lines = [f"# Task Tree: {engagement_id}\n"]

    # Summary stats
    nodes = tree["nodes"]
    total = len(nodes) - 1  # exclude root
    completed = sum(1 for n in nodes.values() if n["status"] in ("completed", "skipped") and n["id"] != tree["root"])
    in_progress = sum(1 for n in nodes.values() if n["status"] == "in_progress")
    blocked = sum(1 for n in nodes.values() if n["status"] == "blocked")
    total_findings = sum(n.get("findings_count", 0) for n in nodes.values())

    lines.append(f"**Progress**: {completed}/{total} tasks done | {in_progress} in progress | {blocked} blocked | {total_findings} findings\n")

    # Render tree
    lines.extend(_render_tree(tree, tree["root"], 0, max_depth))

    return "\n".join(lines)


def get_subtree(engagement_id: str, node_id: str) -> str:
    """Get a specific subtree for subagent context injection.
    Returns the node and all its descendants.

    Args:
        engagement_id: The engagement identifier
        node_id: The root node of the subtree to retrieve
    """
    tree = _load_tree(engagement_id)
    if not tree:
        return f"No task tree found for {engagement_id}."

    if node_id not in tree["nodes"]:
        return f"Node '{node_id}' not found."

    lines = [f"# Subtree: {tree['nodes'][node_id]['label']}\n"]
    lines.extend(_render_tree(tree, node_id, 0, 10))  # unlimited depth for subtrees

    return "\n".join(lines)


def get_task_summary(engagement_id: str) -> str:
    """Get a high-level summary of task tree progress.
    One line per phase with completion %, findings, and pending items.

    Args:
        engagement_id: The engagement identifier
    """
    tree = _load_tree(engagement_id)
    if not tree:
        return f"No task tree found for {engagement_id}. Call create_task_tree() first."

    root = tree["nodes"].get(tree["root"])
    if not root:
        return "Tree has no root node."

    lines = [f"# Task Summary: {engagement_id}\n"]
    lines.append("| Phase | Status | Progress | Findings | Pending |")
    lines.append("|-------|--------|----------|----------|---------|")

    for child_id in root.get("children", []):
        child = tree["nodes"].get(child_id)
        if not child:
            continue

        pct = _compute_completion(tree, child_id)
        findings = child.get("findings_count", 0)
        # Also sum child findings
        for desc_id in child.get("children", []):
            desc = tree["nodes"].get(desc_id)
            if desc:
                findings += desc.get("findings_count", 0)

        pending = sum(1 for cid in child.get("children", []) if tree["nodes"].get(cid, {}).get("status") == "pending")
        total_children = len(child.get("children", []))
        pending_str = f"{pending}/{total_children}" if total_children > 0 else "-"

        icon = _status_icon(child["status"])
        lines.append(f"| {icon} {child['label']} | {child['status']} | {pct:.0f}% | {findings} | {pending_str} |")

    return "\n".join(lines)
