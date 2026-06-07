"""Cross-Phase Knowledge Graph for automated vulnerability chaining.

Builds an in-memory graph during testing where nodes represent entities
(endpoints, parameters, technologies, findings, users) and edges represent
relationships (authenticates-to, reflects-in, redirects-to, trusts-origin).

Enables automated chaining queries: "find all paths from unauthenticated
input to admin functionality."

Inspired by Dristi-DRL's graph-based attack modeling.

Roadmap Tier 2.4.
"""

import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

# Injected by server.py
GRAPH_DIR: Path = Path(".")
_atomic_write_json = None
_append_event = None


def configure(graph_dir: Path, atomic_write_fn, append_event_fn):
    """Called by server.py to inject shared dependencies."""
    global GRAPH_DIR, _atomic_write_json, _append_event
    GRAPH_DIR = graph_dir
    _atomic_write_json = atomic_write_fn
    _append_event = append_event_fn


# ── Node & Edge Types ─────────────────────────────────────────────

VALID_NODE_TYPES = {
    "endpoint",  # API/page endpoint (e.g., POST /api/users)
    "parameter",  # Input parameter (e.g., id, query, url)
    "technology",  # Tech component (e.g., PHP 8.1, MySQL 8, Keycloak)
    "finding",  # A discovered vulnerability (links to FINDING-XXX)
    "user_role",  # Application role (e.g., admin, user, guest)
    "cookie",  # Session cookie or token
    "domain",  # A domain in scope
    "header",  # HTTP header used as input vector
    "file",  # A file on the server
    "secret",  # Exposed secret/credential
}

VALID_EDGE_TYPES = {
    "authenticates_to",  # user_role -> endpoint (this role can access)
    "has_parameter",  # endpoint -> parameter
    "reflects_in",  # parameter -> endpoint (input reflected in response)
    "redirects_to",  # endpoint -> endpoint
    "trusts_origin",  # domain -> domain (CORS trust)
    "shares_session",  # domain -> domain (same session cookie)
    "uses_technology",  # endpoint/domain -> technology
    "has_finding",  # endpoint/parameter -> finding
    "bypasses",  # finding -> endpoint/user_role (auth bypass)
    "chains_to",  # finding -> finding (vuln A enables vuln B)
    "sends_to",  # endpoint -> domain (SSRF, redirect target)
    "reads_file",  # parameter -> file (path traversal)
    "exposes",  # endpoint -> secret
    "includes",  # endpoint -> file (LFI/RFI)
    "manages",  # user_role -> user_role (role hierarchy)
    "owned_by",  # cookie -> domain
    "injects_into",  # parameter -> technology (e.g., SQL injection)
}

# ── Predefined chaining patterns ──────────────────────────────────

CHAIN_PATTERNS = {
    "xss_to_session_theft": {
        "description": "XSS + weak cookie attributes = session hijacking",
        "source_type": "finding",
        "target_type": "cookie",
        "via_edges": ["has_finding", "owned_by"],
        "conditions": {
            "source_finding_class": ["xss_reflected", "xss_stored", "xss_dom"],
            "target_missing_flags": ["httponly"],
        },
        "severity_upgrade": "One level up (XSS alone is High, with session theft is Critical)",
    },
    "xss_no_csp": {
        "description": "XSS + missing/weak CSP = no browser mitigation",
        "source_type": "finding",
        "target_type": "finding",
        "via_edges": ["chains_to"],
        "conditions": {
            "source_finding_class": ["xss_reflected", "xss_stored", "xss_dom"],
            "target_finding_class": ["missing_csp", "weak_csp"],
        },
        "severity_upgrade": "XSS severity stays but add note about increased exploitability",
    },
    "open_redirect_to_oauth_theft": {
        "description": "Open redirect + OAuth = authorization code theft",
        "source_type": "finding",
        "target_type": "endpoint",
        "via_edges": ["redirects_to"],
        "conditions": {
            "source_finding_class": ["open_redirect"],
            "target_has_tag": ["oauth", "callback", "redirect_uri"],
        },
        "severity_upgrade": "Open redirect upgrades from Medium to High",
    },
    "idor_to_admin": {
        "description": "IDOR + privilege escalation = admin access",
        "source_type": "finding",
        "target_type": "user_role",
        "via_edges": ["bypasses"],
        "conditions": {
            "source_finding_class": ["idor"],
            "target_role": ["admin", "superadmin"],
        },
        "severity_upgrade": "IDOR upgrades to Critical",
    },
    "ssrf_to_cloud_metadata": {
        "description": "SSRF + cloud metadata endpoint = credential theft",
        "source_type": "finding",
        "target_type": "endpoint",
        "via_edges": ["sends_to"],
        "conditions": {
            "source_finding_class": ["ssrf"],
            "target_endpoint": ["169.254.169.254", "metadata.google", "metadata.azure"],
        },
        "severity_upgrade": "SSRF upgrades to Critical",
    },
    "auth_bypass_chain": {
        "description": "No lockout + no MFA = credential attack chain",
        "source_type": "finding",
        "target_type": "finding",
        "via_edges": ["chains_to"],
        "conditions": {
            "source_finding_class": ["no_lockout", "brute_force"],
            "target_finding_class": ["no_mfa", "weak_password_policy"],
        },
        "severity_upgrade": "Both findings upgrade one level",
    },
    "cors_to_data_theft": {
        "description": "CORS misconfiguration + sensitive endpoint = data theft",
        "source_type": "finding",
        "target_type": "endpoint",
        "via_edges": ["trusts_origin", "has_finding"],
        "conditions": {
            "source_finding_class": ["cors_misconfiguration"],
            "target_has_tag": ["api", "sensitive", "user_data"],
        },
        "severity_upgrade": "CORS upgrades from Medium to High",
    },
}


# ── Data Helpers ──────────────────────────────────────────────────


def _load_graph(engagement_id: str) -> dict | None:
    """Load graph from disk."""
    graph_file = GRAPH_DIR / f"{engagement_id}.json"
    if not graph_file.exists():
        return None
    return json.loads(graph_file.read_text(encoding="utf-8"))


def _save_graph(engagement_id: str, graph: dict) -> None:
    """Save graph to disk."""
    GRAPH_DIR.mkdir(parents=True, exist_ok=True)
    graph_file = GRAPH_DIR / f"{engagement_id}.json"
    _atomic_write_json(graph_file, graph)


def _new_graph(engagement_id: str) -> dict:
    """Create a new empty graph."""
    return {
        "engagement_id": engagement_id,
        "nodes": {},
        "edges": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── MCP Tool Functions ───────────────────────────────────────────


def add_graph_node(
    engagement_id: str,
    node_id: str,
    node_type: str,
    label: str,
    properties: str = "{}",
) -> str:
    """Add a node to the engagement knowledge graph.

    Nodes represent entities discovered during testing: endpoints, parameters,
    technologies, findings, user roles, cookies, domains, headers, files, secrets.

    Args:
        engagement_id: The engagement identifier
        node_id: Unique node identifier (e.g., 'ep-post-api-users', 'param-id', 'finding-001')
        node_type: One of: endpoint, parameter, technology, finding, user_role,
            cookie, domain, header, file, secret
        label: Human-readable label (e.g., 'POST /api/users', 'id parameter', 'admin role')
        properties: JSON string of additional properties (e.g., '{"method": "POST", "auth_required": true}')
    """
    if node_type not in VALID_NODE_TYPES:
        return f"Invalid node_type '{node_type}'. Must be one of: {', '.join(sorted(VALID_NODE_TYPES))}"

    try:
        props = json.loads(properties)
    except json.JSONDecodeError:
        return f"Invalid JSON in properties: {properties}"

    graph = _load_graph(engagement_id)
    if not graph:
        graph = _new_graph(engagement_id)

    if node_id in graph["nodes"]:
        # Update existing node
        graph["nodes"][node_id].update(
            {
                "label": label,
                "properties": {**graph["nodes"][node_id].get("properties", {}), **props},
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        _save_graph(engagement_id, graph)
        return f"Node updated: {node_id} ({node_type})"

    graph["nodes"][node_id] = {
        "id": node_id,
        "type": node_type,
        "label": label,
        "properties": props,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    graph["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save_graph(engagement_id, graph)

    if _append_event:
        _append_event(
            engagement_id,
            {
                "tool": "add_graph_node",
                "args": {"node_id": node_id, "node_type": node_type},
                "result": f"Added node {node_id}",
            },
        )

    return f"Node added: {node_id} ({node_type}: {label})"


def add_graph_edge(
    engagement_id: str,
    source_id: str,
    target_id: str,
    edge_type: str,
    properties: str = "{}",
) -> str:
    """Add a directed edge between two nodes in the knowledge graph.

    Edges represent relationships: authenticates_to, has_parameter, reflects_in,
    redirects_to, trusts_origin, shares_session, uses_technology, has_finding,
    bypasses, chains_to, sends_to, reads_file, exposes, includes, manages,
    owned_by, injects_into.

    Args:
        engagement_id: The engagement identifier
        source_id: Source node ID
        target_id: Target node ID
        edge_type: One of the valid edge types (see description)
        properties: JSON string of additional properties (e.g., '{"confidence": "high"}')
    """
    if edge_type not in VALID_EDGE_TYPES:
        return f"Invalid edge_type '{edge_type}'. Must be one of: {', '.join(sorted(VALID_EDGE_TYPES))}"

    try:
        props = json.loads(properties)
    except json.JSONDecodeError:
        return f"Invalid JSON in properties: {properties}"

    graph = _load_graph(engagement_id)
    if not graph:
        return f"No graph found for {engagement_id}. Call add_graph_node() first to create the graph."

    if source_id not in graph["nodes"]:
        return f"Source node '{source_id}' not found in graph."
    if target_id not in graph["nodes"]:
        return f"Target node '{target_id}' not found in graph."

    # Check for duplicate edge
    for edge in graph["edges"]:
        if edge["source"] == source_id and edge["target"] == target_id and edge["type"] == edge_type:
            # Update existing edge
            edge["properties"] = {**edge.get("properties", {}), **props}
            edge["updated_at"] = datetime.now(timezone.utc).isoformat()
            _save_graph(engagement_id, graph)
            return f"Edge updated: {source_id} --[{edge_type}]--> {target_id}"

    edge = {
        "source": source_id,
        "target": target_id,
        "type": edge_type,
        "properties": props,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    graph["edges"].append(edge)
    graph["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save_graph(engagement_id, graph)

    if _append_event:
        _append_event(
            engagement_id,
            {
                "tool": "add_graph_edge",
                "args": {"source": source_id, "target": target_id, "type": edge_type},
                "result": "Added edge",
            },
        )

    return f"Edge added: {source_id} --[{edge_type}]--> {target_id}"


def query_graph(
    engagement_id: str,
    node_type: str = "",
    edge_type: str = "",
    node_id: str = "",
    property_filter: str = "{}",
) -> str:
    """Query the knowledge graph for nodes and their connections.

    Filter by node type, edge type, specific node, or properties.
    Returns matching nodes with their edges.

    Args:
        engagement_id: The engagement identifier
        node_type: Filter by node type (e.g., 'endpoint', 'finding'). Empty = all.
        edge_type: Filter edges by type (e.g., 'has_finding'). Empty = all.
        node_id: Get a specific node and all its connections. Empty = query all.
        property_filter: JSON filter for node properties (e.g., '{"auth_required": false}')
    """
    graph = _load_graph(engagement_id)
    if not graph:
        return f"No knowledge graph found for {engagement_id}. Use add_graph_node() to start building one."

    try:
        prop_filter = json.loads(property_filter)
    except json.JSONDecodeError:
        return f"Invalid JSON in property_filter: {property_filter}"

    nodes = graph["nodes"]
    edges = graph["edges"]

    # Filter nodes
    if node_id:
        if node_id not in nodes:
            return f"Node '{node_id}' not found."
        matching_nodes = {node_id: nodes[node_id]}
    elif node_type:
        matching_nodes = {nid: n for nid, n in nodes.items() if n["type"] == node_type}
    else:
        matching_nodes = dict(nodes)

    # Apply property filter
    if prop_filter:
        filtered = {}
        for nid, n in matching_nodes.items():
            props = n.get("properties", {})
            match = all(props.get(k) == v for k, v in prop_filter.items())
            if match:
                filtered[nid] = n
        matching_nodes = filtered

    if not matching_nodes:
        return "No matching nodes found."

    # Filter edges
    matching_edges = []
    node_ids = set(matching_nodes.keys())
    for edge in edges:
        if edge_type and edge["type"] != edge_type:
            continue
        if edge["source"] in node_ids or edge["target"] in node_ids:
            matching_edges.append(edge)

    # Format output
    lines = [f"# Graph Query Results: {engagement_id}\n"]
    lines.append(f"**Matching nodes**: {len(matching_nodes)}")
    lines.append(f"**Related edges**: {len(matching_edges)}\n")

    lines.append("## Nodes\n")
    for nid, n in matching_nodes.items():
        props = n.get("properties", {})
        props_str = ", ".join(f"{k}={v}" for k, v in props.items()) if props else ""
        props_display = f" ({props_str})" if props_str else ""
        lines.append(f"- **{nid}** [{n['type']}] {n['label']}{props_display}")

    if matching_edges:
        lines.append("\n## Edges\n")
        for edge in matching_edges:
            src_label = nodes.get(edge["source"], {}).get("label", edge["source"])
            tgt_label = nodes.get(edge["target"], {}).get("label", edge["target"])
            lines.append(f"- {src_label} --[{edge['type']}]--> {tgt_label}")

    return "\n".join(lines)


def find_chains(
    engagement_id: str,
    source_id: str = "",
    target_id: str = "",
    max_depth: int = 4,
) -> str:
    """Find vulnerability chains and attack paths in the knowledge graph.

    Uses BFS to discover multi-hop paths between nodes. Also checks
    predefined chaining patterns (XSS+no CSP, SSRF+cloud metadata, etc.)
    and suggests severity upgrades.

    Args:
        engagement_id: The engagement identifier
        source_id: Starting node for path search (empty = check all findings)
        target_id: Destination node (empty = find all reachable sensitive targets)
        max_depth: Maximum path length to search (default 4)
    """
    graph = _load_graph(engagement_id)
    if not graph:
        return f"No knowledge graph found for {engagement_id}."

    nodes = graph["nodes"]
    edges = graph["edges"]

    # Build adjacency list
    adj = defaultdict(list)
    for edge in edges:
        adj[edge["source"]].append((edge["target"], edge["type"]))

    lines = ["# Vulnerability Chain Analysis\n"]

    # ── Part 1: BFS path search ──

    if source_id and target_id:
        # Find specific path
        paths = _bfs_paths(adj, source_id, target_id, max_depth)
        if paths:
            lines.append(f"## Paths: {source_id} -> {target_id}\n")
            for i, path in enumerate(paths, 1):
                path_str = _format_path(path, nodes)
                lines.append(f"### Chain {i} (depth {len(path)-1})\n{path_str}\n")
        else:
            lines.append(f"No paths found from {source_id} to {target_id} within depth {max_depth}.\n")

    elif source_id:
        # Find all reachable from source
        reachable = _bfs_reachable(adj, source_id, max_depth)
        interesting = [(nid, depth) for nid, depth in reachable.items() if nodes.get(nid, {}).get("type") in ("finding", "secret", "user_role") and nid != source_id]
        if interesting:
            lines.append(f"## Reachable from {source_id}\n")
            for nid, depth in sorted(interesting, key=lambda x: x[1]):
                node = nodes.get(nid, {})
                lines.append(f"- **{nid}** [{node.get('type')}] {node.get('label', '?')} (depth {depth})")
        else:
            lines.append(f"No interesting targets reachable from {source_id}.\n")

    # ── Part 2: Predefined chain pattern matching ──

    findings = {nid: n for nid, n in nodes.items() if n["type"] == "finding"}

    if findings:
        chains_found = []

        for pattern_name, pattern in CHAIN_PATTERNS.items():
            for fid, finding in findings.items():
                finding_class = finding.get("properties", {}).get("vuln_class", "")
                conditions = pattern.get("conditions", {})

                # Check if this finding matches the source condition
                source_classes = conditions.get("source_finding_class", [])
                if source_classes and finding_class not in source_classes:
                    continue

                # Check target conditions
                target_classes = conditions.get("target_finding_class", [])
                if target_classes:
                    # Look for matching target finding
                    for other_fid, other_finding in findings.items():
                        if other_fid == fid:
                            continue
                        other_class = other_finding.get("properties", {}).get("vuln_class", "")
                        if other_class in target_classes:
                            chains_found.append(
                                {
                                    "pattern": pattern_name,
                                    "description": pattern["description"],
                                    "source": fid,
                                    "target": other_fid,
                                    "upgrade": pattern["severity_upgrade"],
                                }
                            )

                # Check edge-based targets
                for _, (target, edge_type) in [(s, t) for s in [fid] for t in adj.get(s, [])]:
                    target_node = nodes.get(target, {})
                    target_tags = target_node.get("properties", {}).get("tags", [])

                    target_has_tag = conditions.get("target_has_tag", [])
                    if target_has_tag and any(t in target_tags for t in target_has_tag):
                        chains_found.append(
                            {
                                "pattern": pattern_name,
                                "description": pattern["description"],
                                "source": fid,
                                "target": target,
                                "upgrade": pattern["severity_upgrade"],
                            }
                        )

                    target_role = conditions.get("target_role", [])
                    if target_role:
                        role_name = target_node.get("properties", {}).get("role", "")
                        if role_name in target_role:
                            chains_found.append(
                                {
                                    "pattern": pattern_name,
                                    "description": pattern["description"],
                                    "source": fid,
                                    "target": target,
                                    "upgrade": pattern["severity_upgrade"],
                                }
                            )

        if chains_found:
            lines.append(f"\n## Detected Vulnerability Chains ({len(chains_found)})\n")
            for i, chain in enumerate(chains_found, 1):
                src = nodes.get(chain["source"], {})
                tgt = nodes.get(chain["target"], {})
                lines.append(f"### Chain {i}: {chain['pattern']}")
                lines.append(f"**{chain['description']}**")
                lines.append(f"- Source: {src.get('label', chain['source'])}")
                lines.append(f"- Target: {tgt.get('label', chain['target'])}")
                lines.append(f"- Severity impact: {chain['upgrade']}")
                lines.append("")
        else:
            lines.append("\n## No predefined vulnerability chains detected.\n")
            lines.append("This could mean: (1) findings are isolated, or (2) graph needs more edges.")
            lines.append("Add edges between findings with `add_graph_edge()` using `chains_to` type.")
    else:
        lines.append("\nNo findings in graph yet. Add findings as nodes to enable chain analysis.")

    # ── Part 3: Graph statistics ──

    lines.append("\n## Graph Statistics\n")
    type_counts = defaultdict(int)
    for n in nodes.values():
        type_counts[n["type"]] += 1
    for ntype, count in sorted(type_counts.items()):
        lines.append(f"- **{ntype}**: {count} nodes")

    edge_type_counts = defaultdict(int)
    for e in edges:
        edge_type_counts[e["type"]] += 1
    if edge_type_counts:
        lines.append("")
        for etype, count in sorted(edge_type_counts.items()):
            lines.append(f"- **{etype}**: {count} edges")

    return "\n".join(lines)


def get_graph_summary(engagement_id: str) -> str:
    """Get a high-level summary of the knowledge graph.

    Returns node/edge counts, type distribution, and isolated
    nodes (not connected to any edge).

    Args:
        engagement_id: The engagement identifier
    """
    graph = _load_graph(engagement_id)
    if not graph:
        return f"No knowledge graph found for {engagement_id}."

    nodes = graph["nodes"]
    edges = graph["edges"]

    # Node type counts
    type_counts = defaultdict(int)
    for n in nodes.values():
        type_counts[n["type"]] += 1

    # Edge type counts
    edge_type_counts = defaultdict(int)
    for e in edges:
        edge_type_counts[e["type"]] += 1

    # Find connected and isolated nodes
    connected = set()
    for e in edges:
        connected.add(e["source"])
        connected.add(e["target"])
    isolated = [nid for nid in nodes if nid not in connected]

    lines = [f"# Knowledge Graph: {engagement_id}\n"]
    lines.append(f"**Total nodes**: {len(nodes)}")
    lines.append(f"**Total edges**: {len(edges)}")
    lines.append(f"**Isolated nodes**: {len(isolated)}")
    lines.append(f"**Connected nodes**: {len(connected)}\n")

    lines.append("## Node Types\n")
    lines.append("| Type | Count |")
    lines.append("|------|-------|")
    for ntype, count in sorted(type_counts.items()):
        lines.append(f"| {ntype} | {count} |")

    if edge_type_counts:
        lines.append("\n## Edge Types\n")
        lines.append("| Type | Count |")
        lines.append("|------|-------|")
        for etype, count in sorted(edge_type_counts.items()):
            lines.append(f"| {etype} | {count} |")

    if isolated:
        lines.append(f"\n## Isolated Nodes ({len(isolated)})\n")
        lines.append("These nodes have no edges. Consider adding relationships:\n")
        for nid in isolated[:20]:
            n = nodes[nid]
            lines.append(f"- **{nid}** [{n['type']}] {n['label']}")
        if len(isolated) > 20:
            lines.append(f"- _...and {len(isolated) - 20} more_")

    return "\n".join(lines)


# ── BFS Helpers ───────────────────────────────────────────────────


def _bfs_paths(adj: dict, source: str, target: str, max_depth: int) -> list:
    """Find all paths from source to target using BFS (up to max_depth)."""
    queue = deque([(source, [source])])
    found = []
    visited_paths = set()

    while queue:
        current, path = queue.popleft()
        if len(path) > max_depth + 1:
            continue

        if current == target and len(path) > 1:
            path_key = tuple(path)
            if path_key not in visited_paths:
                visited_paths.add(path_key)
                found.append(path)
            continue

        for neighbor, edge_type in adj.get(current, []):
            if neighbor not in path:  # Prevent cycles
                queue.append((neighbor, path + [neighbor]))

    return found[:10]  # Cap at 10 paths


def _bfs_reachable(adj: dict, source: str, max_depth: int) -> dict:
    """Find all nodes reachable from source with their minimum depth."""
    visited = {source: 0}
    queue = deque([(source, 0)])

    while queue:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue

        for neighbor, _ in adj.get(current, []):
            if neighbor not in visited:
                visited[neighbor] = depth + 1
                queue.append((neighbor, depth + 1))

    return visited


def _format_path(path: list, nodes: dict) -> str:
    """Format a path as a readable chain."""
    parts = []
    for nid in path:
        node = nodes.get(nid, {})
        label = node.get("label", nid)
        ntype = node.get("type", "?")
        parts.append(f"[{ntype}] {label}")
    return " -> ".join(parts)
