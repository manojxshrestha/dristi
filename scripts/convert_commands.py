#!/usr/bin/env python3
"""Convert BH commands to OpenCode commands for Dristi."""

from pathlib import Path

HOME = Path.home()
BH_COMMANDS = HOME / "dristi/.opencode/commands-bughunt"
OC_COMMANDS = HOME / "dristi/.opencode/commands"

# Each command: (filename, description, agent, subtask)
COMMANDS = [
    ("hunt", "Active vulnerability hunting dispatcher. Routes to correct agent based on target and mode (red team / WAPT / bug bounty). Usage: /hunt target.com", "hunt-dispatcher", True),
    ("recon", "Full recon pipeline: subdomain enum, live host discovery, URL crawl, gf classification, secret detection, subdomain takeover. Usage: /recon target.com", "web2-recon", True),
    ("triage", "Quick 7-Question Gate triage — kill N/A findings before writing a report. Faster than /validate. Usage: /triage <describe finding>", "triage-validation", True),
    ("validate", "Full 4-gate validation: Reproduction, Scope, Impact, Severity. PASS/KILL/DOWNGRADE/CHAIN-REQUIRED verdicts. Usage: /validate", "triage-validation", True),
    ("report", "Generate HackerOne/Bugcrowd/Intigriti/Immunefi-ready report. Usage: /report", "report-writing", True),
    ("chain", "Build attack chains from individual findings. A→B→C path composition, MITRE ATT&CK mapping, severity upgrades. Usage: /chain", None, False),
    ("intel", "Gather threat intelligence on a target: breach data, social media, tech stack, infrastructure. Usage: /intel target.com", "offensive-osint", True),
    ("pickup", "Load and resume a previous session from handoff markdown. Usage: /pickup <handoff-file.md>", None, False),
    ("remember", "Save session state silently — engagement notes, progress, pending items. No user prompt. Usage: /remember", None, False),
    ("surface", "Surface P1/P2 attack paths from recon data. Kill chain prioritization. Usage: /surface", None, False),
    ("memory-gc", "Compact session context — summarize, prune, consolidate. Frees tokens. Usage: /memory-gc", None, False),
    ("token-scan", "Scan for hardcoded tokens, secrets, API keys in source code / JS files. Usage: /token-scan <path|url>", "hunt-source-leak", True),
    ("autopilot", "Autonomous hunting mode. Loops through attack classes, reports findings. Usage: /autopilot target.com [--vuln-class X]", None, False),
    ("web3-audit", "Web3/DeFi smart contract audit. Reentrancy, flash loans, oracle manipulation, MEV. Usage: /web3-audit <contract-address|repo>", "web3-audit", True),
]


def convert_command(name: str, description: str, agent: str | None, subtask: bool) -> str:
    src = BH_COMMANDS / f"{name}.md"
    if not src.exists():
        alt = src
        if not alt.exists():
            print(f"  [SKIP] {name}: source not found")
            return ""
    
    content = src.read_text(encoding="utf-8")

    # Parse frontmatter
    parts = content.split("---", 2)
    if len(parts) < 3:
        body = content.strip()
    else:
        body = parts[2].strip()

    # Rewrite cross-references
    body = _rewrite_refs(body)
    body = _fix_tool_refs(body)

    # Build OpenCode frontmatter
    fm = f"---\ndescription: {description}\n"
    if agent:
        fm += f"agent: {agent}\n"
    if subtask:
        fm += "subtask: true\n"
    fm += "---\n\n"

    agent_content = fm + body

    dst = OC_COMMANDS / f"{name}.md"
    dst.write_text(agent_content, encoding="utf-8")
    lines = len(agent_content.splitlines())
    print(f"  [OK] {name}.md ({lines} lines)")
    return name


BH_TO_DRISTI = {  # same as in convert_skills.py
    "hunt-xss": "xss-hunter", "hunt-sqli": "sqli-hunter",
    "hunt-ssrf": "ssrf-hunter", "hunt-ssti": "ssti-hunter",
    "hunt-lfi": "lfi-hunter", "hunt-xxe": "xxe-hunter",
    "hunt-idor": "idor-hunter", "hunt-csrf": "csrf-hunter",
    "hunt-cors": "cors-hunter", "hunt-oauth": "oauth-hunter",
    "hunt-graphql": "graphql-hunter", "hunt-file-upload": "file-upload-hunter",
    "hunt-host-header": "host-header-hunter", "hunt-http-smuggling": "http-smuggler",
    "hunt-open-redirect": "open-redirect-hunter", "hunt-brute-force": "brute-force-hunter",
    "hunt-session": "session-hunter", "hunt-auth-bypass": "auth-bypass-hunter",
    "hunt-ato": "ato-hunter", "hunt-subdomain": "subdomain-hunter",
    "hunt-api-misconfig": "api-misconfig-hunter", "hunt-mfa-bypass": "mfa-bypass-hunter",
    "hunt-race-condition": "race-condition-hunter", "hunt-cache-poison": "cache-poison-hunter",
    "hunt-deserialization": "deserialization-hunter", "hunt-dom": "dom-hunter",
    "hunt-websocket": "websocket-hunter", "hunt-llm-ai": "llm-hunter",
    "hunt-rce": "rce-hunter", "hunt-k8s": "k8s-hunter", "hunt-cicd": "cicd-hunter",
    "hunt-cloud-misconfig": "cloud-misconfig-hunter", "hunt-nosqli": "nosqli-hunter",
    "hunt-saml": "saml-hunter", "hunt-ldap": "ldap-hunter",
    "hunt-source-leak": "source-leak-hunter", "hunt-business-logic": "bizlogic-hunter",
    "hunt-misc": "misc-hunter", "hunt-sharepoint": "sharepoint-hunter",
    "hunt-ntlm-info": "ntlm-hunter", "hunt-aspnet": "aspnet-hunter",
    "hunt-springboot": "springboot-hunter", "hunt-laravel": "laravel-hunter",
    "hunt-nextjs": "nextjs-hunter", "hunt-nodejs": "nodejs-hunter",
    "hunt-tls-network": "tls-hunter",
    "hunt-dispatch": "hunt-dispatcher", "triage-validator": "triage-validation",
    "report-writer": "report-writing", "evidence-hygiene": "evidence-hygiene",
    "osint-gatherer": "offensive-osint", "web-recon": "web2-recon",
    "osint-methodology": "osint-methodology", "bb-methodology": "bb-methodology",
    "bug-bounty": "bug-bounty", "bugcrowd-reporting": "bugcrowd-reporter",
    "redteam-mindset": "redteam-mindset",
    "mid-engagement-ir-detection": "ir-detector",
    "redteam-report-template": "redteam-reporter",
}


def _rewrite_refs(body: str) -> str:
    for old_ref, new_ref in sorted(BH_TO_DRISTI.items(), key=lambda x: -len(x[0])):
        body = body.replace(f"`{old_ref}`", f"`@{new_ref}`")
        body = body.replace(f"`{old_ref}", f"`@{new_ref}")
        body = body.replace(f"{old_ref}`", f"{new_ref}`")
        body = body.replace(f"skill: {old_ref}", f"agent: {new_ref}")
        body = body.replace(f"skill:`{old_ref}`", f"agent:`@{new_ref}`")
    body = body.replace("`triage-validation`", "`@triage-validator`")
    body = body.replace("`hunt-dispatch`", "`@hunt-dispatcher`")
    body = body.replace("`report-writing`", "`@report-writer`")
    body = body.replace("Claude-BugHunter", "Dristi")
    return body


def _fix_tool_refs(body: str) -> str:
    body = body.replace("`claude`", "`opencode`")
    body = body.replace("Claude Code", "OpenCode")
    return body


def main():
    OC_COMMANDS.mkdir(parents=True, exist_ok=True)
    print(f"\n{'='*50}")
    print("Converting BH commands → OpenCode commands")
    print(f"{'='*50}")
    converted = 0
    for name, desc, agent, subtask in COMMANDS:
        result = convert_command(name, desc, agent, subtask)
        if result:
            converted += 1
    print(f"\nTotal: {converted}/{len(COMMANDS)} commands created in {OC_COMMANDS}")


if __name__ == "__main__":
    main()
