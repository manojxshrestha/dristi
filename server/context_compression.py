"""Progressive Context Compression for pentest engagements.

Generates compressed phase summaries to combat context window degradation
during long pentests. Reverses the linear decline in LLM success rate
documented by AI-Pentest-Benchmark (Isozaki et al., UMAP 2025).

Summary injection improved exploitation success from 50% to 100% on Funbox.
"""

import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Module State ─────────────────────────────────────────────────

_data_dir: Path | None = None
_atomic_write: Callable | None = None
_append_event: Callable | None = None


def configure(
    data_dir: Path,
    atomic_write_fn: Callable,
    append_event_fn: Callable,
) -> None:
    """Configure module with shared infrastructure."""
    global _data_dir, _atomic_write, _append_event
    _data_dir = data_dir
    _atomic_write = atomic_write_fn
    _append_event = append_event_fn


# ── Phase-to-Category Mapping ────────────────────────────────────

PHASE_CATEGORIES = {
    0: [],  # No WSTG tests — tool/discovery-only phase
    1: ["INFO"],
    2: ["CONF"],
    3: ["IDNT", "ATHN", "ATHZ", "SESS"],
    4: ["INPV"],
    5: ["ERRH", "CRYP", "BUSL", "CLNT", "APIT"],
}

PHASE_NAMES = {
    0: "Application Discovery & Mapping",
    1: "Information Gathering & Reconnaissance",
    2: "Configuration & Deployment Testing",
    3: "Identity, Authentication, Authorization & Session Testing",
    4: "Input Validation Testing",
    5: "Error Handling, Cryptography, Business Logic, Client-Side & API Testing",
}

# Phase-to-tool mapping for filtering tool tracking
PHASE_TOOLS = {
    0: {"nmap", "katana", "ffuf", "httpx", "nuclei", "whatweb", "gau", "nikto", "feroxbuster", "wapiti", "subfinder", "arjun"},
    2: {"corscanner", "dnsreaper"},
    3: {"hydra", "jwt_tool"},
    4: {"sqlmap", "dalfox", "commix", "sstimap", "ssrfmap", "nosqli", "crlfuzz", "smuggler"},
    5: {"testssl", "testssl.sh", "graphql-cop", "websocat"},
}


# ── Helper Functions ─────────────────────────────────────────────


def _safe_read_json(filepath: Path, default: Any = None) -> Any:
    """Read JSON file safely."""
    if not filepath.exists():
        return default
    try:
        return json.loads(filepath.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def _test_matches_phase(test_id: str, phase: int) -> bool:
    """Check if a WSTG test ID belongs to a phase's categories."""
    categories = PHASE_CATEGORIES.get(phase, [])
    if not categories:
        return False
    # Extract category code from test ID: WSTG-INFO-01 -> INFO
    parts = test_id.split("-")
    if len(parts) >= 2:
        code = parts[1]
        return code in categories
    return False


def _tool_matches_phase(tool_name: str, phase: int) -> bool:
    """Check if a tool belongs to a phase."""
    tools = PHASE_TOOLS.get(phase, set())
    return tool_name.lower() in tools


def _get_phase_time_range(engagement_id: str, phase: int) -> tuple[str, str]:
    """Get the timestamp range for a phase from gate tracking.

    Returns (start_ts, end_ts) as ISO strings.
    Start = previous phase gate timestamp (or epoch for phase 0).
    End = this phase gate timestamp (or now if not yet gated).
    """
    gate_file = _data_dir / "gate-tracking" / f"{engagement_id}.json"
    gates = _safe_read_json(gate_file, [])

    start_ts = "1970-01-01T00:00:00"
    end_ts = datetime.now(timezone.utc).isoformat()

    for gate in gates:
        gate_phase = gate.get("phase", -1)
        if gate_phase == phase - 1:
            start_ts = gate.get("timestamp", start_ts)
        if gate_phase == phase:
            end_ts = gate.get("timestamp", end_ts)

    return start_ts, end_ts


def _summarize_finding(finding: dict) -> str:
    """One-line summary of a finding."""
    fid = finding.get("id", "?")
    title = finding.get("title", "Unknown")
    severity = finding.get("severity", "?")
    url = finding.get("url", "")
    return f"- **{fid}**: {title} ({severity}) — `{url}`"


# ── Main Compression Functions ────────────────────────────────────


def compress_phase_context(engagement_id: str, phase: int) -> str:
    """Generate a compressed summary of all engagement activity for a phase.

    Reads tracking, findings, tools, deliverables, and gate results.
    Saves as deliverable type 'phase_N_summary'.

    Args:
        engagement_id: The engagement identifier
        phase: The phase number to summarize (0-5)
    """
    if phase not in range(6):
        return f"Invalid phase: {phase}. Must be 0-5."

    phase_name = PHASE_NAMES.get(phase, f"Phase {phase}")
    start_ts, end_ts = _get_phase_time_range(engagement_id, phase)

    # ── Load data ────────────────────────────────────────────
    tracking_file = _data_dir / "tracking" / f"{engagement_id}.json"
    all_tests = _safe_read_json(tracking_file, [])

    tool_file = _data_dir / "tool-tracking" / f"{engagement_id}.json"
    all_tools = _safe_read_json(tool_file, [])

    findings_file = _data_dir / "findings" / f"{engagement_id}.json"
    all_findings = _safe_read_json(findings_file, [])

    gate_file = _data_dir / "gate-tracking" / f"{engagement_id}.json"
    gates = _safe_read_json(gate_file, [])

    scope_file = _data_dir / "scope" / f"{engagement_id}.json"
    scope = _safe_read_json(scope_file, [])

    # ── Filter data for this phase ───────────────────────────
    phase_tests = [t for t in all_tests if _test_matches_phase(t.get("test_id", ""), phase)]
    phase_tools = [t for t in all_tools if _tool_matches_phase(t.get("tool_name", ""), phase)]

    # Findings in this phase's time window
    phase_findings = [f for f in all_findings if start_ts <= f.get("timestamp", "") <= end_ts]

    # Gate result for this phase
    phase_gate = None
    for gate in gates:
        if gate.get("phase") == phase:
            phase_gate = gate
            break

    # ── Build summary sections ───────────────────────────────
    sections = [f"# Phase {phase} Summary: {phase_name}\n"]

    # Key Findings
    if phase_findings:
        sections.append(f"## Key Findings ({len(phase_findings)})\n")
        # Sort by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        sorted_findings = sorted(phase_findings, key=lambda f: severity_order.get(f.get("severity", ""), 5))
        for f in sorted_findings:
            sections.append(_summarize_finding(f))
        sections.append("")
    else:
        sections.append("## Key Findings\nNo findings logged during this phase.\n")

    # Test Coverage
    if phase_tests:
        completed = [t for t in phase_tests if t.get("status") == "completed"]
        skipped = [t for t in phase_tests if t.get("status") == "skipped"]
        na = [t for t in phase_tests if t.get("status") == "not_applicable"]
        in_progress = [t for t in phase_tests if t.get("status") == "in_progress"]
        total = len(phase_tests)
        pct = round(len(completed) / total * 100) if total > 0 else 0

        sections.append("## Test Coverage\n")
        sections.append(f"- **Completed**: {len(completed)}/{total} ({pct}%)")
        if skipped:
            sections.append(f"- **Skipped** ({len(skipped)}):")
            for t in skipped[:5]:  # Limit to 5 for brevity
                sections.append(f"  - {t['test_id']}: {t.get('notes', 'no reason')[:80]}")
        if na:
            sections.append(f"- **N/A** ({len(na)}):")
            for t in na[:5]:
                sections.append(f"  - {t['test_id']}: {t.get('notes', 'no reason')[:80]}")
        if in_progress:
            sections.append(f"- **In Progress** ({len(in_progress)}): {', '.join(t['test_id'] for t in in_progress)}")
        sections.append("")
    elif phase == 0:
        sections.append("## Test Coverage\nPhase 0 is discovery-only (no WSTG tests).\n")
    else:
        sections.append("## Test Coverage\nNo tests tracked for this phase.\n")

    # Tool Results
    if phase_tools:
        sections.append("## Tool Results\n")
        for t in phase_tools:
            tool = t.get("tool_name", "?")
            status = t.get("status", "?")
            notes = t.get("notes", "")[:100]
            fc = t.get("findings_count", 0)
            finding_note = f" ({fc} findings)" if fc > 0 else ""
            sections.append(f"- **{tool}**: {status}{finding_note} — {notes}")
        sections.append("")
    else:
        sections.append("## Tool Results\nNo tools tracked for this phase.\n")

    # Attack Surface (Phase 0 specific)
    if phase == 0 and scope:
        sections.append("## Scope / Domains\n")
        for s in scope:
            domain = s.get("domain", "?")
            dtype = s.get("domain_type", "?")
            notes = s.get("notes", "")[:80]
            sections.append(f"- **{domain}** ({dtype}): {notes}")
        sections.append("")

    # WAF Intelligence
    waf_file = _data_dir / "waf-data" / f"{engagement_id}.json"
    if waf_file.exists() and phase >= 4:
        waf_data = _safe_read_json(waf_file, {})
        if waf_data:
            vendor = waf_data.get("vendor", "unknown")
            confidence = waf_data.get("confidence", "?")
            sections.append("## WAF/Defense Intelligence\n")
            sections.append(f"- **Vendor**: {vendor} (confidence: {confidence})")
            sections.append("")

    # Gate Result
    if phase_gate:
        result = phase_gate.get("result", "?")
        blockers = phase_gate.get("blockers_count", 0)
        warnings = phase_gate.get("warnings_count", 0)
        sections.append("## Phase Gate Result\n")
        sections.append(f"- **Result**: {result}")
        if blockers:
            sections.append(f"- **Blockers**: {blockers}")
        if warnings:
            sections.append(f"- **Warnings**: {warnings}")
        sections.append("")

    # Unresolved Issues
    unresolved = []
    for t in phase_tests:
        if t.get("status") == "skipped":
            reason = t.get("notes", "")
            if "auth" in reason.lower() or "unavailable" in reason.lower():
                unresolved.append(f"- {t['test_id']}: {reason[:100]}")
    if unresolved:
        sections.append("## Unresolved Issues\n")
        sections.extend(unresolved[:5])
        sections.append("")

    summary_text = "\n".join(sections)

    # ── Save as deliverable ──────────────────────────────────
    deliverable_type = f"phase_{phase}_summary"
    deliverable_dir = _data_dir / "deliverables"
    deliverable_dir.mkdir(parents=True, exist_ok=True)
    deliverable_file = deliverable_dir / f"{engagement_id}_{deliverable_type}.json"

    word_count = len(summary_text.split())
    deliverable_data = {
        "engagement_id": engagement_id,
        "deliverable_type": deliverable_type,
        "producer_agent": "context-compression",
        "content": summary_text,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "word_count": word_count,
    }
    _atomic_write(deliverable_file, deliverable_data)

    _append_event(
        engagement_id,
        {
            "tool": "compress_phase_context",
            "args": {"phase": phase},
            "result": f"Saved {deliverable_type} ({word_count} words)",
        },
    )

    return (
        f"Phase {phase} context compressed and saved as `{deliverable_type}` "
        f"({word_count} words).\n\n"
        f"Subagents in Phase {phase + 1}+ can retrieve with:\n"
        f"  `get_deliverable('{engagement_id}', '{deliverable_type}')`\n\n"
        f"---\n\n{summary_text}"
    )


def get_engagement_summary(engagement_id: str) -> str:
    """Get a compressed summary of all phases completed so far.

    Combines individual phase summaries into an engagement-wide overview.
    Useful for injecting into subagent prompts to provide full context
    without raw historical data.

    Args:
        engagement_id: The engagement identifier
    """
    deliverable_dir = _data_dir / "deliverables"
    sections = [f"# Engagement Summary: {engagement_id}\n"]

    # Collect phase summaries
    found_phases = []
    for phase in range(6):
        deliverable_file = deliverable_dir / f"{engagement_id}_phase_{phase}_summary.json"
        if deliverable_file.exists():
            data = _safe_read_json(deliverable_file, {})
            content = data.get("content", "")
            if content:
                found_phases.append(phase)
                sections.append(content)
                sections.append("\n---\n")

    if not found_phases:
        # No phase summaries exist — generate a quick status overview
        sections.append("No phase summaries available yet.\n")

        # Try to provide basic stats from tracking data
        tracking_file = _data_dir / "tracking" / f"{engagement_id}.json"
        all_tests = _safe_read_json(tracking_file, [])
        findings_file = _data_dir / "findings" / f"{engagement_id}.json"
        all_findings = _safe_read_json(findings_file, [])

        if all_tests or all_findings:
            completed = len([t for t in all_tests if t.get("status") == "completed"])
            sections.append(f"**Quick Stats**: {completed} tests completed, {len(all_findings)} findings logged.\n")
            sections.append("Run `compress_phase_context()` for each completed phase to generate summaries.")
    else:
        sections.insert(1, f"Phases summarized: {', '.join(str(p) for p in found_phases)}\n")

    # Add overall finding stats
    findings_file = _data_dir / "findings" / f"{engagement_id}.json"
    all_findings = _safe_read_json(findings_file, [])
    if all_findings:
        severity_counts = {}
        for f in all_findings:
            sev = f.get("severity", "Unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        sections.append("## Overall Finding Summary\n")
        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                sections.append(f"- **{sev}**: {count}")
        sections.append(f"- **Total**: {len(all_findings)}")

    _append_event(
        engagement_id,
        {
            "tool": "get_engagement_summary",
            "args": {},
            "result": f"Generated summary covering phases {found_phases}",
        },
    )

    return "\n".join(sections)
