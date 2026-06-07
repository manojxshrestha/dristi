"""Results Verification & Auto-Correction Loop for CLI security tools.

Verifies CLI tool output quality and suggests corrected commands when output
is empty, incomplete, or suspicious. Reduces false-negative tool results by
97.7% (per Dristier, Ginige et al. 2025).

Inspired by Dristier's Results Verifier module.
"""

import re
from collections.abc import Callable
from pathlib import Path

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


# ── Per-Tool Validation Rules ────────────────────────────────────


def _check_nmap(command: str, raw: str) -> tuple[bool, list[str], list[str]]:
    """Validate nmap output."""
    issues = []
    corrections = []
    lines = raw.strip().split("\n") if raw.strip() else []

    if not lines:
        issues.append("Empty output — nmap produced no results")
        corrections.append(_suggest_fix(command, add_flags="-Pn -sS", reason="Host may be blocking ping probes"))
        return False, issues, corrections

    has_host_up = any("Host is up" in l for l in lines)
    has_open_port = any("open" in l and ("tcp" in l or "udp" in l) for l in lines)
    host_down = any("host seems down" in l.lower() for l in lines)

    if host_down:
        issues.append("Host reported as down — firewall may be blocking ping probes")
        corrections.append(_suggest_fix(command, add_flags="-Pn", reason="Skip host discovery"))
        return False, issues, corrections

    if not has_host_up and not has_open_port:
        issues.append("No 'Host is up' or open ports detected — results may be incomplete")
        corrections.append(_suggest_fix(command, add_flags="-Pn -sS", reason="Force scan without ping"))
        return False, issues, corrections

    if has_host_up and not has_open_port:
        issues.append("Host is up but no open ports found — may need broader port range")
        if "-p " not in command and "--top-ports" not in command:
            corrections.append(_suggest_fix(command, add_flags="-p-", reason="Scan all 65535 ports"))
        return False, issues, corrections

    return True, [], []


def _check_nuclei(command: str, raw: str) -> tuple[bool, list[str], list[str]]:
    """Validate nuclei output."""
    issues = []
    corrections = []
    lines = raw.strip().split("\n") if raw.strip() else []

    if not lines:
        issues.append("Empty output — nuclei produced no results")
        corrections.append(_suggest_fix(command, add_flags="-severity critical,high,medium", reason="Broaden severity filter"))
        return False, issues, corrections

    has_match = any("[" in l and "]" in l for l in lines)
    has_completed = any("completed" in l.lower() or "finished" in l.lower() for l in lines)

    if not has_match and not has_completed:
        issues.append("No template matches and no completion indicator — scan may have failed")
        corrections.append(_suggest_fix(command, remove_proxy=True, reason="Proxy may be interfering"))
        return False, issues, corrections

    if not has_match and has_completed:
        # Legitimate — no vulnerabilities found
        return True, [], []

    return True, [], []


def _check_sqlmap(command: str, raw: str) -> tuple[bool, list[str], list[str]]:
    """Validate sqlmap output."""
    issues = []
    corrections = []
    lines = raw.strip().split("\n") if raw.strip() else []

    if not lines:
        issues.append("Empty output — sqlmap produced no results")
        corrections.append(_suggest_fix(command, add_flags="--level 5 --risk 3", reason="Increase test depth"))
        return False, issues, corrections

    has_connection_error = any("connection error" in l.lower() or "connection timed out" in l.lower() for l in lines)
    has_not_injectable = any("does not seem to be injectable" in l.lower() or "not injectable" in l.lower() for l in lines)
    has_injectable = any("is vulnerable" in l.lower() or "injectable" in l.lower() for l in lines)
    has_testing = any("[INFO] testing" in l for l in lines)
    has_separator = any("---" in l for l in lines)

    if has_connection_error:
        issues.append("Connection errors detected — target may be unreachable or blocking requests")
        corrections.append(_suggest_fix(command, remove_proxy=True, reason="Remove proxy"))
        corrections.append(_suggest_fix(command, add_flags="--timeout=30", reason="Increase timeout"))
        return False, issues, corrections

    if has_testing and not has_separator and not has_injectable and not has_not_injectable:
        issues.append("sqlmap started testing but did not complete — may have been interrupted")
        corrections.append(_suggest_fix(command, add_flags="--batch --flush-session", reason="Force fresh session"))
        return False, issues, corrections

    if has_not_injectable and "--level" not in command:
        issues.append("Target reported not injectable at default level — try deeper testing")
        corrections.append(_suggest_fix(command, add_flags="--level 5 --risk 3", reason="Test with higher intensity"))
        return False, issues, corrections

    return True, [], []


def _check_ffuf(command: str, raw: str) -> tuple[bool, list[str], list[str]]:
    """Validate ffuf output."""
    issues = []
    corrections = []

    if not raw.strip():
        issues.append("Empty output — ffuf produced no results")
        corrections.append(_suggest_fix(command, add_flags="-mc all -fc 404", reason="Accept all status codes except 404"))
        return False, issues, corrections

    # Try JSON parse
    try:
        import json

        data = json.loads(raw)
        results = data.get("results", [])
        if len(results) == 0:
            issues.append("ffuf found 0 results — wordlist may not match target technology")
            corrections.append(_suggest_fix(command, reason="Try a different wordlist matching the target technology"))
            return False, issues, corrections
    except (json.JSONDecodeError, ValueError):
        # Text output
        if "0 results" in raw.lower() or not any(line.strip() for line in raw.split("\n") if "Status:" in line or "200" in line):
            issues.append("ffuf found 0 results — wordlist or filters may need adjustment")
            return False, issues, corrections

    return True, [], []


def _check_feroxbuster(command: str, raw: str) -> tuple[bool, list[str], list[str]]:
    """Validate feroxbuster output."""
    issues = []
    corrections = []

    if not raw.strip():
        issues.append("Empty output — feroxbuster produced no results")
        corrections.append(_suggest_fix(command, add_flags="--insecure", reason="Allow insecure TLS"))
        return False, issues, corrections

    error_lines = [l for l in raw.split("\n") if "error" in l.lower() and "0 errors" not in l.lower()]
    if error_lines and len(error_lines) > 3:
        issues.append(f"Multiple errors detected ({len(error_lines)} error lines)")
        corrections.append(_suggest_fix(command, remove_proxy=True, reason="Proxy may be causing connection issues"))
        return False, issues, corrections

    return True, [], []


def _check_testssl(command: str, raw: str) -> tuple[bool, list[str], list[str]]:
    """Validate testssl output."""
    issues = []
    corrections = []

    if not raw.strip():
        issues.append("Empty output — testssl produced no results")
        corrections.append(_suggest_fix(command, remove_proxy=True, reason="testssl may not work through proxy"))
        return False, issues, corrections

    has_connection_fail = any(p in raw.lower() for p in ["couldn't connect", "fatal error", "connection refused"])
    if has_connection_fail:
        issues.append("Connection failure — testssl could not reach the target")
        corrections.append(_suggest_fix(command, remove_proxy=True, reason="Remove proxy for direct TLS testing"))
        return False, issues, corrections

    has_results = any(p in raw for p in ["Testing protocols", "Testing cipher", "Overall Grade", "Rating"])
    if not has_results:
        issues.append("No TLS analysis sections found — scan may have failed silently")
        return False, issues, corrections

    return True, [], []


def _check_dalfox(command: str, raw: str) -> tuple[bool, list[str], list[str]]:
    """Validate dalfox output."""
    issues = []
    corrections = []

    if not raw.strip():
        issues.append("Empty output — dalfox produced no results")
        corrections.append(_suggest_fix(command, add_flags="--WAF-evasion", reason="Enable WAF evasion mode"))
        return False, issues, corrections

    any("Reflected" in l or "found" in l.lower() for l in raw.split("\n"))
    all_not_reflected = all("not reflected" in l.lower() for l in raw.split("\n") if l.strip())

    if all_not_reflected:
        issues.append("All parameters reported as 'not reflected' — check if URL/parameters are correct")
        corrections.append(_suggest_fix(command, add_flags="--blind <callback-url>", reason="Try blind XSS with callback"))
        return False, issues, corrections

    return True, [], []


def _check_wapiti(command: str, raw: str) -> tuple[bool, list[str], list[str]]:
    """Validate wapiti output."""
    issues = []
    corrections = []

    if not raw.strip():
        issues.append("Empty output — wapiti produced no results")
        corrections.append(_suggest_fix(command, add_flags="--scope page", reason="Limit scope to reduce timeout risk"))
        return False, issues, corrections

    "anomalies" in raw.lower() or "vulnerabilities" in raw.lower()
    error_count = sum(1 for l in raw.split("\n") if "error" in l.lower())

    if error_count > 5:
        issues.append(f"High error count ({error_count}) — wapiti encountered problems during scan")
        corrections.append(_suggest_fix(command, remove_proxy=True, reason="Proxy may be interfering"))
        return False, issues, corrections

    return True, [], []


def _check_katana(command: str, raw: str) -> tuple[bool, list[str], list[str]]:
    """Validate katana output."""
    issues = []
    corrections = []

    if not raw.strip():
        issues.append("Empty output — katana discovered no URLs")
        corrections.append(_suggest_fix(command, add_flags="-jc -d 3", reason="Enable JS crawling and increase depth"))
        return False, issues, corrections

    urls = [l.strip() for l in raw.split("\n") if l.strip() and ("http" in l or "/" in l)]
    if len(urls) < 3:
        issues.append(f"Only {len(urls)} URLs discovered — crawl depth may be too shallow")
        if "-d " not in command:
            corrections.append(_suggest_fix(command, add_flags="-d 3", reason="Increase crawl depth"))
        if "-jc" not in command:
            corrections.append(_suggest_fix(command, add_flags="-jc", reason="Enable JavaScript crawling"))
        return False, issues, corrections

    return True, [], []


def _check_httpx(command: str, raw: str) -> tuple[bool, list[str], list[str]]:
    """Validate httpx output."""
    issues = []
    corrections = []

    if not raw.strip():
        issues.append("Empty output — httpx produced no results")
        corrections.append(_suggest_fix(command, remove_proxy=True, reason="Proxy may be blocking connections"))
        return False, issues, corrections

    lines = raw.strip().split("\n")
    fail_indicators = ["failed", "timeout", "error", "refused"]
    fail_count = sum(1 for l in lines if any(f in l.lower() for f in fail_indicators))

    if fail_count > len(lines) * 0.8:
        issues.append(f"High failure rate ({fail_count}/{len(lines)} lines contain errors)")
        corrections.append(_suggest_fix(command, remove_proxy=True, reason="Remove proxy for direct probing"))
        return False, issues, corrections

    return True, [], []


# ── Generic Checks (all tools) ───────────────────────────────────


def _check_generic_issues(command: str, raw: str) -> tuple[list[str], list[str]]:
    """Check for cross-tool issues like proxy errors, permission denied, timeouts."""
    issues = []
    corrections = []
    raw_lower = raw.lower() if raw else ""

    # Proxy errors
    proxy_patterns = [
        "proxy connect",
        "proxy error",
        "502 bad gateway",
        "connect tunnel failed",
        "proxy authentication required",
    ]
    if any(p in raw_lower for p in proxy_patterns):
        issues.append("Proxy-related errors detected — tool may not work through Burp proxy")
        corrections.append(_suggest_fix(command, remove_proxy=True, reason="Remove HTTP_PROXY/HTTPS_PROXY"))

    # Permission denied
    if "permission denied" in raw_lower or "access denied" in raw_lower:
        issues.append("Permission denied — may need different credentials or flags")

    # Timeout
    if "timed out" in raw_lower or "deadline exceeded" in raw_lower:
        issues.append("Timeout detected — tool could not complete within time limit")
        corrections.append(_suggest_fix(command, add_flags="--timeout 60", reason="Increase timeout"))

    return issues, corrections


# ── Command Suggestion Helpers ────────────────────────────────────


def _suggest_fix(
    command: str,
    add_flags: str = "",
    remove_proxy: bool = False,
    reason: str = "",
) -> str:
    """Generate a corrected command suggestion."""
    parts = []

    if remove_proxy:
        command = command.replace("--proxy http://", "--proxy-disabled ")
        parts.append("Remove proxy environment variables")

    if add_flags:
        # Insert flags before the URL (heuristic: before http:// or https://)
        url_match = re.search(r"(https?://\S+)", command)
        if url_match:
            insert_pos = url_match.start()
            command = command[:insert_pos] + add_flags + " " + command[insert_pos:]
        else:
            command = command + " " + add_flags
        parts.append(f"Add: `{add_flags}`")

    suggestion = f"**Suggested fix** ({reason}):\n```\n{command}\n```"
    return suggestion


# ── Verification Rules Registry ───────────────────────────────────

_VERIFICATION_RULES = {
    "nmap": _check_nmap,
    "nuclei": _check_nuclei,
    "sqlmap": _check_sqlmap,
    "ffuf": _check_ffuf,
    "feroxbuster": _check_feroxbuster,
    "testssl": _check_testssl,
    "testssl.sh": _check_testssl,
    "dalfox": _check_dalfox,
    "wapiti": _check_wapiti,
    "katana": _check_katana,
    "httpx": _check_httpx,
}


# ── Main Verification Function ────────────────────────────────────


def verify_tool_result(tool_name: str, command: str, raw_output: str) -> str:
    """Verify CLI tool output quality and suggest corrections.

    Returns a markdown report with status (valid/suspicious/empty),
    issues found, and corrected command suggestions.

    Args:
        tool_name: The tool name (e.g., nmap, nuclei, sqlmap, ffuf)
        command: The exact command that was run
        raw_output: The raw output text from the tool
    """
    tool_lower = tool_name.lower().strip()

    # Empty output — universal check
    if not raw_output or not raw_output.strip():
        lines = [
            f"## Tool Verification: {tool_name}\n",
            "**Status**: EMPTY\n",
            "The tool produced no output at all. This usually indicates:\n",
            "1. The tool failed to start (wrong path, missing dependency)",
            "2. Network/proxy issues prevented connectivity",
            "3. The tool requires different permissions\n",
        ]

        # Try tool-specific empty-output suggestions
        checker = _VERIFICATION_RULES.get(tool_lower)
        if checker:
            _, _, corrections = checker(command, "")
            if corrections:
                lines.append("### Suggested Corrections\n")
                for c in corrections:
                    lines.append(c + "\n")
        else:
            lines.append("### Generic Suggestion\n" "Try running without proxy:\n" "```\n" "```\n")

        return "\n".join(lines)

    # Tool-specific validation
    checker = _VERIFICATION_RULES.get(tool_lower)
    if checker:
        valid, tool_issues, tool_corrections = checker(command, raw_output)
    else:
        valid, tool_issues, tool_corrections = True, [], []

    # Cross-tool generic checks
    generic_issues, generic_corrections = _check_generic_issues(command, raw_output)

    all_issues = tool_issues + generic_issues
    all_corrections = tool_corrections + generic_corrections

    if not all_issues:
        status = "VALID"
    elif valid and generic_issues:
        status = "VALID (with warnings)"
    else:
        status = "SUSPICIOUS"

    lines = [
        f"## Tool Verification: {tool_name}\n",
        f"**Status**: {status}\n",
    ]

    if all_issues:
        lines.append("### Issues Found\n")
        for issue in all_issues:
            lines.append(f"- {issue}")
        lines.append("")

    if all_corrections:
        lines.append("### Suggested Corrections\n")
        for correction in all_corrections:
            lines.append(correction + "\n")

    if not all_issues:
        output_lines = len(raw_output.strip().split("\n"))
        lines.append(f"Tool output appears valid ({output_lines} lines). No corrections needed.")

    return "\n".join(lines)
