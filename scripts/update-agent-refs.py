#!/usr/bin/env python3
"""Update all hunt agents with proper fetch-and-reference disclosed reports sections."""

import os
import re

AGENTS_DIR = "/home/pwn/.config/opencode/agents"
H1_REPORTS_DIR = os.path.expanduser("~/dristi/docs/reports/hackerone-reports")
FB_REPORTS_DIR = os.path.expanduser("~/dristi/docs/reports/facebook-reports")
DISCLOSED_DIR = os.path.expanduser("~/dristi/docs/reports/disclosed-reports")

# Agent classes that have corresponding HackerOne report files
H1_CLASSES = {
    "xss": "Cross-Site Scripting (XSS)",
    "sqli": "SQL Injection",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "ssti": "Server-Side Template Injection (SSTI)",
    "rce": "Remote Code Execution (RCE)",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "csrf": "Cross-Site Request Forgery (CSRF)",
    "xxe": "XML External Entities (XXE)",
    "open-redirect": "Open Redirect",
    "file-upload": "File Upload",
    "lfi": "Local File Inclusion / Path Traversal",
    "business-logic": "Business Logic",
    "ato": "Account Takeover (ATO)",
    "clickjacking": "Clickjacking / UI Redressing",
    "mfa-bypass": "MFA / 2FA Bypass",
    "oauth": "OAuth / OpenID Connect",
    "race-condition": "Race Condition",
    "cache-poison": "Web Cache Poisoning",
    "http-smuggling": "HTTP Request Smuggling",
    "subdomain": "Subdomain Takeover",
    "graphql": "GraphQL",
    "auth-bypass": "Authentication / Authorization Bypass",
    "api-misconfig": "API Misconfiguration",
    "misc": "Information Disclosure / Misc",
}

def get_top_reports(agent_class, n=5):
    """Get the top N report links from the H1 report file."""
    fp = os.path.join(H1_REPORTS_DIR, f"{agent_class}.md")
    if not os.path.exists(fp):
        return []
    
    reports = []
    with open(fp, 'r', encoding='utf-8') as f:
        for line in f:
            m = re.match(r'## Report (\d+):\s*(.+)$', line.strip())
            if m:
                rid = m.group(1)
                title = m.group(2).strip()
                reports.append({'id': rid, 'title': title})
                if len(reports) >= n:
                    break
    return reports

def get_report_count(agent_class):
    """Get the number of reports in a class file."""
    fp = os.path.join(H1_REPORTS_DIR, f"{agent_class}.md")
    if not os.path.exists(fp):
        return 0
    with open(fp, 'r', encoding='utf-8') as f:
        content = f.read()
    return content.count("## Report ")

def has_pattern_library(agent_class):
    """Check if a pattern library exists."""
    fp = os.path.join(DISCLOSED_DIR, f"hunt-{agent_class}.md")
    return os.path.exists(fp)

def has_facebook_writeups():
    """Check if facebook writeups file exists."""
    fp = os.path.join(FB_REPORTS_DIR, "facebook-writeups.md")
    if not os.path.exists(fp):
        return False
    with open(fp, 'r', encoding='utf-8') as f:
        content = f.read()
    m = re.search(r'(\d+)\s+public', content)
    return m.group(1) if m else "0"

def generate_class_section(agent_class):
    """Generate the Disclosed Reports Reference section for a class with H1 data."""
    class_name = H1_CLASSES.get(agent_class, agent_class.replace('-', ' ').title())
    report_count = get_report_count(agent_class)
    top_reports = get_top_reports(agent_class, 5)
    has_pat = has_pattern_library(agent_class)
    
    lines = []
    lines.append(f"\n## Disclosed Reports Reference\n")
    lines.append(f"When hunting **{class_name}**, use these resources BEFORE and DURING testing:\n")
    lines.append(f"### Before You Start\n")
    lines.append(f"1. **Read the report index:** `docs/hackerone-reports/{agent_class}.md` — scan top-upvoted reports for real-world payloads, bypass techniques, and bounty benchmarks")
    if has_pat:
        lines.append(f"2. **Study the pattern library:** `~/dristi/docs/disclosed-reports/hunt-{agent_class}.md` — curated techniques with HTTP request/response examples and detection methods")
    lines.append(f"3. **Check writeups (Meta/Facebook):** `docs/facebook-reports/facebook-writeups.md` if testing Meta-owned surfaces")
    lines.append(f"")
    lines.append(f"### During Testing\n")
    lines.append(f"- **Fetch a report when stuck:** If a test shows promise but you need a payload/bypass idea, use `webfetch` to pull the full HackerOne disclosure:")
    if top_reports:
        lines.append(f"  ```")
        lines.append(f"  webfetch https://hackerone.com/reports/{top_reports[0]['id']}")
        lines.append(f"  ```")
    lines.append(f"- **Study the technique** from the fetched report, then apply it to your current target")
    lines.append(f"- **Cross-reference impact:** After confirming a bug, check similar HackerOne reports to validate your severity classification")
    lines.append(f"")
    lines.append(f"### Top {min(5, len(top_reports))} Most-Upvoted {class_name} Reports\n")
    lines.append(f"| # | Report ID | Title |")
    lines.append(f"|---|-----------|-------|")
    for i, r in enumerate(top_reports, 1):
        title_short = r['title'][:70] + '...' if len(r['title']) > 70 else r['title']
        lines.append(f"| {i} | [#{r['id']}] | [{title_short}](https://hackerone.com/reports/{r['id']}) |")
    lines.append(f"")
    lines.append(f"**Full list:** `docs/hackerone-reports/{agent_class}.md` ({report_count} reports)\n")
    lines.append(f"### Quick Fetch Commands\n")
    lines.append(f"```bash")
    for r in top_reports[:3]:
        lines.append(f"webfetch https://hackerone.com/reports/{r['id']}")
    lines.append(f"```\n")
    lines.append(f"### External Repositories\n")
    lines.append(f"- **HackerOne Reports:** `docs/hackerone-reports/{agent_class}.md` — per-class disclosed reports")
    lines.append(f"- **HackerOne Master Index:** `docs/hackerone-reports/INDEX.md` — all classes")
    lines.append(f"- **Pattern Library:** `~/dristi/docs/disclosed-reports/hunt-{agent_class}.md`{' (exists)' if has_pat else ' (not available)'}")
    
    return '\n'.join(lines)

def generate_generic_section(agent_class):
    """Generate a generic reference section for agents without H1 data."""
    has_pat = has_pattern_library(agent_class)
    class_name = agent_class.replace('-', ' ').title()
    
    lines = []
    lines.append(f"\n## Disclosed Reports Reference\n")
    lines.append(f"When hunting **{class_name}**, use these resources:\n")
    lines.append(f"### Before You Start\n")
    lines.append(f"1. **Browse the master index:** `docs/hackerone-reports/INDEX.md` — find reports relevant to your class")
    if has_pat:
        lines.append(f"2. **Study the pattern library:** `~/dristi/docs/disclosed-reports/hunt-{agent_class}.md` — curated techniques with HTTP request/response examples")
    lines.append(f"3. **Check Facebook writeups:** `docs/facebook-reports/facebook-writeups.md` if testing Meta/Meta-owned surfaces")
    lines.append(f"")
    lines.append(f"### During Testing\n")
    lines.append(f"- When you find a potential vulnerability, search the HackerOne disclosed reports index for similar findings to:")
    lines.append(f"  - Discover payload/bypass techniques from real reports")
    lines.append(f"  - Validate your impact assessment against paid bounties")
    lines.append(f"  - Cross-check severity classification")
    lines.append(f"- Use `webfetch` to read a relevant HackerOne report when you need technique guidance")
    lines.append(f"")
    lines.append(f"### External Repositories\n")
    lines.append(f"- **HackerOne Reports (Master):** `docs/hackerone-reports/INDEX.md` — 14,682+ structured disclosed reports")
    lines.append(f"- **HackerOne TOP by Class:** `docs/hackerone-reports/` — per-class report files (24 classes)")
    lines.append(f"- **Facebook Writeups:** `docs/facebook-reports/facebook-writeups.md` — Meta bug bounty writeups")
    if has_pat:
        lines.append(f"- **Pattern Library:** `~/dristi/docs/disclosed-reports/hunt-{agent_class}.md`")
    
    return '\n'.join(lines)

def update_agent(agent_file):
    """Update a single agent file with the proper reference section."""
    basename = os.path.basename(agent_file).replace('.md', '')
    agent_class = basename.replace('hunt-', '')
    
    with open(agent_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Remove old Disclosed Reports Reference section (from "## Disclosed Reports Reference" to EOF)
    section_start = "## Disclosed Reports Reference"
    if section_start in content:
        content = content[:content.index(section_start)].rstrip()
    
    # Generate new section
    if agent_class in H1_CLASSES:
        new_section = generate_class_section(agent_class)
    else:
        new_section = generate_generic_section(agent_class)
    
    # Append
    content += new_section + '\n'
    
    with open(agent_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    return agent_class

def main():
    print("=== Updating hunt agents with fetch-and-reference sections ===\n")
    
    agent_files = sorted([f for f in os.listdir(AGENTS_DIR) 
                         if f.startswith('hunt-') and f.endswith('.md')])
    
    updated = 0
    for fname in agent_files:
        fpath = os.path.join(AGENTS_DIR, fname)
        agent_class = update_agent(fpath)
        cls_type = "H1" if agent_class in H1_CLASSES else "generic"
        print(f"  {fname} ({cls_type})")
        updated += 1
    
    print(f"\n  Updated {updated} agents")
    
    # Also update hunt-dispatch if it exists (pipeline agent)
    dispatch_fp = os.path.join(AGENTS_DIR, "hunt-dispatch.md")
    if os.path.exists(dispatch_fp):
        # Just skip - dispatch is a router, not a hunter
        print("  Skipped hunt-dispatch (pipeline router)")

if __name__ == '__main__':
    main()
