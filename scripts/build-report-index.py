#!/usr/bin/env python3
"""Build comprehensive report index from hackerone-reports data.csv and TOP files."""

import csv
import os
import sys
import re
from collections import defaultdict, OrderedDict

DATA_CSV = os.path.expanduser("~/dristi/docs/hackerone-reports/data.csv")
TOPS_DIR = os.path.expanduser("~/dristi/docs/hackerone-reports/tops_by_bug_type")
DISCLOSED_DIR = os.path.expanduser("~/dristi/docs/reports/disclosed-reports")
OUTPUT_DIR = os.path.expanduser("~/dristi/docs/report-index")

# Map HackerOne vuln_type -> hunt agent name
VULN_MAP = {
    "Cross-site Scripting (XSS) - Generic": "xss",
    "Cross-site Scripting (XSS) - Reflected": "xss",
    "Cross-site Scripting (XSS) - Stored": "xss",
    "Cross-site Scripting (XSS) - DOM": "xss",
    "SQL Injection": "sqli",
    "Server-Side Request Forgery (SSRF)": "ssrf",
    "Insecure Direct Object Reference (IDOR)": "idor",
    "Cross-Site Request Forgery (CSRF)": "csrf",
    "XML External Entities (XXE)": "xxe",
    "Open Redirect": "open-redirect",
    "Code Injection": "rce",
    "Command Injection - Generic": "rce",
    "OS Command Injection": "rce",
    "Path Traversal": "lfi",
    "Business Logic Errors": "business-logic",
    "Authentication Bypass": "auth-bypass",
    "Improper Authentication - Generic": "auth-bypass",
    "Improper Authorization": "auth-bypass",
    "Privilege Escalation": "auth-bypass",
    "Insufficient Session Expiration": "session",
    "UI Redressing (Clickjacking)": "clickjacking",
    "HTTP Request Smuggling": "http-smuggling",
    "CRLF Injection": "crlf",
    "Deserialization of Untrusted Data": "deserialization",
    "Improper Access Control - Generic": "idor",
    "Violation of Secure Design Principles": "business-logic",
    "Information Disclosure": "misc",
    "Uncontrolled Resource Consumption": "misc",
    "Memory Corruption - Generic": "rce",
    "Cryptographic Issues - Generic": "misc",
    "Misconfiguration": "misc",
    "Privacy Violation": "misc",
    "Cleartext Storage of Sensitive Information": "misc",
    "Improper Input Validation": "misc",
    "Use After Free": "rce",
    "Classic Buffer Overflow": "rce",
    "Buffer Over-read": "rce",
    "Heap Overflow": "rce",
    "NULL Pointer Dereference": "misc",
    "Insecure Storage of Sensitive Information": "misc",
    "Phishing": "misc",
    "Insufficiently Protected Credentials": "misc",
    "Information Exposure Through an Error Message": "misc",
    "Information Exposure Through Directory Listing": "misc",
    "Information Exposure Through Debug Information": "misc",
    "Cleartext Transmission of Sensitive Information": "misc",
    "Improper Certificate Validation": "misc",
    "Improper Restriction of Authentication Attempts": "brute-force",
    "Out-of-bounds Read": "rce",
}

# Map TOP file name -> hunt agent name
TOP_MAP = {
    "TOPXSS.md": "xss",
    "TOPSQLI.md": "sqli",
    "TOPSSRF.md": "ssrf",
    "TOPSSTI.md": "ssti",
    "TOPRCE.md": "rce",
    "TOPIDOR.md": "idor",
    "TOPCSRF.md": "csrf",
    "TOPXXE.md": "xxe",
    "TOPOPENREDIRECT.md": "open-redirect",
    "TOPUPLOAD.md": "file-upload",
    "TOPFILEREADING.md": "lfi",
    "TOPBUSINESSLOGIC.md": "business-logic",
    "TOPACCOUNTTAKEOVER.md": "ato",
    "TOPCLICKJACKING.md": "clickjacking",
    "TOPMFA.md": "mfa-bypass",
    "TOPOAUTH.md": "oauth",
    "TOPRACECONDITION.md": "race-condition",
    "TOPWEBCACHE.md": "cache-poison",
    "TOPREQUESTSMUGGLING.md": "http-smuggling",
    "TOPSUBDOMAINTAKEOVER.md": "subdomain",
    "TOPGRAPHQL.md": "graphql",
    "TOPAUTH.md": "auth-bypass",
    "TOPAUTHORIZATION.md": "auth-bypass",
    "TOPINFODISCLOSURE.md": "misc",
    "TOPDOS.md": "misc",
    "TOPAPI.md": "api-misconfig",
    "TOPMOBILE.md": "misc",
    "TOPOPENID.md": "oauth",
}

def parse_data_csv():
    """Parse data.csv into per-class report lists."""
    class_reports = defaultdict(list)
    total = 0
    errors = 0
    
    with open(DATA_CSV, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.reader(f)
        header = next(reader)
        
        for row in reader:
            total += 1
            try:
                if len(row) < 6:
                    continue
                program, title, link, upvotes, bounty, vuln_type = row[:6]
                upvotes = int(upvotes) if upvotes.strip().isdigit() else 0
                try:
                    bounty_val = float(bounty) if bounty.strip() else 0.0
                except ValueError:
                    bounty_val = 0.0
                
                agent_class = VULN_MAP.get(vuln_type.strip(), "misc")
                # Skip empty titles
                if not title.strip():
                    continue
                    
                class_reports[agent_class].append({
                    'program': program,
                    'title': title.strip(),
                    'link': link.strip(),
                    'upvotes': upvotes,
                    'bounty': bounty_val,
                    'vuln_type': vuln_type.strip(),
                })
            except Exception as e:
                errors += 1
                continue
    
    # Sort each class by upvotes descending
    for cls in class_reports:
        class_reports[cls].sort(key=lambda x: x['upvotes'], reverse=True)
    
    print(f"Parsed {total} reports, {errors} errors")
    for cls, reports in sorted(class_reports.items()):
        print(f"  {cls}: {len(reports)} reports")
    
    return class_reports

def parse_top_file(filepath):
    """Parse a TOP file and extract report entries."""
    reports = []
    pattern = re.compile(r'^\d+\.\s+\[(.+?)\]\((https://hackerone\.com/reports/\d+)\)\s+to\s+(.+?)\s+-\s+(\d+)\s+upvotes,\s+\$?([\d,]+|0)')
    
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            m = pattern.match(line.strip())
            if m:
                title = m.group(1)
                link = m.group(2)
                program = m.group(3).strip()
                upvotes = int(m.group(4))
                bounty_str = m.group(5).replace(',', '')
                bounty = float(bounty_str) if bounty_str.replace('.', '', 1).isdigit() else 0
                reports.append({
                    'title': title,
                    'link': link,
                    'program': program,
                    'upvotes': upvotes,
                    'bounty': bounty,
                })
    return reports

def format_bounty(bounty):
    if bounty >= 10000:
        return f"${bounty/1000:.0f}K"
    elif bounty > 0:
        return f"${bounty:,.0f}"
    return "—"

def generate_class_report(agent_class, csv_reports, top_reports, top_limit=50):
    """Generate a structured markdown report for one vulnerability class."""
    lines = []
    class_name = agent_class.replace('-', ' ').title()
    lines.append(f"# {class_name} — Disclosed HackerOne Reports\n")
    lines.append(f"> Comprehensive index of disclosed HackerOne reports relevant to `hunt-{agent_class}`.\n")
    
    # TOP reports section
    if top_reports:
        lines.append(f"## Top {class_name} Reports\n")
        lines.append(f"These are the highest-upvoted {class_name} reports from HackerOne's TOP list.\n")
        lines.append("| # | Title | Program | Upvotes | Bounty | Link |")
        lines.append("|---|-------|---------|---------|--------|------|")
        
        for i, r in enumerate(top_reports[:top_limit], 1):
            bounty_str = format_bounty(r['bounty'])
            # Truncate title if too long
            title = r['title'][:80] + '...' if len(r['title']) > 80 else r['title']
            link_num = r['link'].split('/')[-1]
            link = f"https://hackerone.com/reports/{link_num}"
            lines.append(f"| {i} | {title} | {r['program']} | {r['upvotes']} | {bounty_str} | [#{link_num}]({link}) |")
        lines.append("")
    
    # Summary stats
    if csv_reports:
        total_bounty = sum(r['bounty'] for r in csv_reports)
        avg_bounty = total_bounty / len(csv_reports) if csv_reports else 0
        total_upvotes = sum(r['upvotes'] for r in csv_reports)
        
        lines.append(f"## Statistics\n")
        lines.append(f"- **Total reports:** {len(csv_reports)}")
        lines.append(f"- **Total bounty:** ${total_bounty:,.0f}")
        lines.append(f"- **Average bounty:** ${avg_bounty:,.0f}")
        lines.append(f"- **Total upvotes:** {total_upvotes:,}")
        lines.append(f"- **Average upvotes:** {total_upvotes/len(csv_reports):.0f}" if csv_reports else "")
        lines.append("")
    
    # CSV reports sorted by bounty
    if csv_reports:
        csv_sorted = sorted(csv_reports, key=lambda x: x['bounty'], reverse=True)
        lines.append(f"## All Disclosed Reports ({len(csv_sorted)})\n")
        lines.append("| # | Title | Program | Upvotes | Bounty | Vuln Type |")
        lines.append("|---|-------|---------|---------|--------|-----------|")
        
        for i, r in enumerate(csv_sorted[:200], 1):
            title = r['title'][:80] + '...' if len(r['title']) > 80 else r['title']
            link_num = r['link'].split('/')[-1] if '/' in r['link'] else r['link']
            link = f"https://hackerone.com/reports/{link_num}" if not r['link'].startswith('http') else r['link']
            bounty_str = format_bounty(r['bounty'])
            vtype = r['vuln_type'][:40] + '...' if len(r['vuln_type']) > 40 else r['vuln_type']
            lines.append(f"| {i} | [{title}]({link}) | {r['program']} | {r['upvotes']} | {bounty_str} | {vtype} |")
        
        if len(csv_sorted) > 200:
            lines.append(f"\n*Showing top 200 by bounty. Full list: {len(csv_sorted)} reports.*\n")
    
    return '\n'.join(lines)

def update_disclosed_pattern_library(agent_class, top_reports):
    """Add a 'HackerOne References' section to the disclosed-reports pattern library."""
    filepath = os.path.join(DISCLOSED_DIR, f"hunt-{agent_class}.md")
    if not os.path.exists(filepath):
        print(f"  WARNING: {filepath} not found, skipping")
        return
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if already has HackerOne section
    if "## HackerOne References" in content:
        print(f"  Already has HackerOne References section, skipping")
        return
    
    # Build references section
    ref_lines = []
    ref_lines.append("\n\n## HackerOne References\n")
    ref_lines.append("> Concrete disclosed HackerOne report links for the patterns above. ")
    ref_lines.append("These are real paid reports that demonstrate each pattern in the wild.\n")
    
    for i, r in enumerate(top_reports[:15], 1):
        link_num = r['link'].split('/')[-1]
        bounty_str = format_bounty(r['bounty'])
        ref_lines.append(f"{i}. **{r['title'][:100]}** — [{r['program']}](https://hackerone.com/reports/{link_num}) — {r['upvotes']} upvotes, {bounty_str}")
    
    ref_lines.append("\n")
    ref_lines.append(f"*Full reference: `docs/hackerone-reports/tops_by_bug_type/TOP{class_name_to_top(agent_class)}.md`*\n")
    
    content += '\n'.join(ref_lines)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"  Updated {filepath}")

def class_name_to_top(agent_class):
    """Map agent class to TOP file name."""
    rev_map = {v: k for k, v in TOP_MAP.items()}
    # Special cases
    overrides = {
        'xss': 'TOPXSS',
        'sqli': 'TOPSQLI',
        'ssrf': 'TOPSSRF',
        'ssti': 'TOPSSTI',
        'rce': 'TOPRCE',
        'idor': 'TOPIDOR',
        'csrf': 'TOPCSRF',
        'xxe': 'TOPXXE',
        'open-redirect': 'TOPOPENREDIRECT',
        'file-upload': 'TOPUPLOAD',
        'lfi': 'TOPFILEREADING',
        'business-logic': 'TOPBUSINESSLOGIC',
        'ato': 'TOPACCOUNTTAKEOVER',
        'clickjacking': 'TOPCLICKJACKING',
        'mfa-bypass': 'TOPMFA',
        'oauth': 'TOPOAUTH',
        'race-condition': 'TOPRACECONDITION',
        'cache-poison': 'TOPWEBCACHE',
        'http-smuggling': 'TOPREQUESTSMUGGLING',
        'subdomain': 'TOPSUBDOMAINTAKEOVER',
        'graphql': 'TOPGRAPHQL',
        'auth-bypass': 'TOPAUTH',
        'api-misconfig': 'TOPAPI',
    }
    return overrides.get(agent_class, f"TOP{agent_class.upper()}")

def generate_hunt_agent_ref_section(agent_class, csv_count, top_count, top_reports):
    """Generate the reference section text to add to a hunt agent."""
    class_name = agent_class.replace('-', ' ').title()
    top_name = class_name_to_top(agent_class)
    
    lines = []
    lines.append(f"\n## Disclosed Reports Reference\n")
    lines.append(f"### Pattern Library\n")
    lines.append(f"- **`docs/disclosed-reports/hunt-{agent_class}.md`** — Curated attack patterns and techniques with real-world context")
    lines.append(f"")
    lines.append(f"### HackerOne TOP Reports\n")
    lines.append(f"- **`docs/hackerone-reports/tops_by_bug_type/{top_name}.md`** — Top {class_name} reports by upvotes ({top_count} entries)")
    lines.append(f"")
    
    if top_reports:
        lines.append(f"**Top {min(5, len(top_reports))} most-upvoted {class_name} reports:**")
        for r in top_reports[:5]:
            link_num = r['link'].split('/')[-1]
            lines.append(f"- [[#{link_num}](https://hackerone.com/reports/{link_num})] **{r['title'][:100]}** — {r['program']} — {r['upvotes']} upvotes, {format_bounty(r['bounty'])}")
        lines.append(f"")
    
    lines.append(f"### Data.csv Stats\n")
    lines.append(f"- **Total entries:** {csv_count}")
    lines.append(f"- **Source:** `docs/hackerone-reports/data.csv` ({csv_count:,} total disclosed reports across all classes)")
    lines.append(f"")
    lines.append(f"### External Repositories\n")
    lines.append(f"- **HackerOne Reports:** `docs/hackerone-reports/` — 14,683+ structured disclosed reports")
    lines.append(f"- **Facebook Writeups:** `docs/facebook-writeups/` — Meta/Facebook/Instagram bug bounty writeups (2020-2026)")
    
    return '\n'.join(lines)

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Parse data.csv
    print("=== Parsing data.csv ===")
    class_reports = parse_data_csv()
    
    # Parse TOP files
    print("\n=== Parsing TOP files ===")
    top_reports_map = {}
    for top_file, agent_class in sorted(TOP_MAP.items()):
        filepath = os.path.join(TOPS_DIR, top_file)
        if os.path.exists(filepath):
            reports = parse_top_file(filepath)
            top_reports_map[agent_class] = reports
            print(f"  {top_file} -> {agent_class}: {len(reports)} reports")
    
    # Generate per-class report files
    print("\n=== Generating per-class reports ===")
    for agent_class in sorted(set(list(class_reports.keys()) + list(top_reports_map.keys()))):
        csv_r = class_reports.get(agent_class, [])
        top_r = top_reports_map.get(agent_class, [])
        
        if not csv_r and not top_r:
            continue
            
        report = generate_class_report(agent_class, csv_r, top_r)
        outpath = os.path.join(OUTPUT_DIR, f"{agent_class}.md")
        with open(outpath, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"  Generated {outpath} ({len(csv_r)} csv + {len(top_r)} top reports)")
    
    # Update disclosed-reports pattern libraries
    print("\n=== Updating disclosed-reports pattern libraries ===")
    for agent_class, top_r in top_reports_map.items():
        if top_r:
            update_disclosed_pattern_library(agent_class, top_r)
    
    # Generate hunt agent reference sections
    print("\n=== Generating hunt agent reference sections ===")
    for agent_class in sorted(set(list(class_reports.keys()) + list(top_reports_map.keys()))):
        csv_r = class_reports.get(agent_class, [])
        top_r = top_reports_map.get(agent_class, [])
        
        if not csv_r and not top_r:
            continue
        
        ref = generate_hunt_agent_ref_section(agent_class, len(csv_r), len(top_r), top_r[:5])
        outpath = os.path.join(OUTPUT_DIR, f"ref-{agent_class}.md")
        with open(outpath, 'w', encoding='utf-8') as f:
            f.write(ref)
        print(f"  Generated reference section for {agent_class}")
    
    # Generate master index
    print("\n=== Generating master index ===")
    index_lines = []
    index_lines.append("# HackerOne Disclosed Reports — Master Index\n")
    index_lines.append(f"> Complete index of {sum(len(v) for v in class_reports.values()):,} disclosed reports from data.csv, ")
    index_lines.append("organized by vulnerability class and cross-referenced to hunt agents and pattern libraries.\n")
    index_lines.append("## Quick Navigation\n")
    index_lines.append("| Class | Hunt Agent | Pattern Library | Reports | TOP File |")
    index_lines.append("|-------|------------|-----------------|---------|----------|")
    
    for agent_class in sorted(set(list(class_reports.keys()) + list(top_reports_map.keys()))):
        class_name = agent_class.replace('-', ' ').title()
        csv_count = len(class_reports.get(agent_class, []))
        top_name = class_name_to_top(agent_class)
        top_r = top_reports_map.get(agent_class, [])
        top_count = len(top_r)
        
        hunt_link = f"`hunt-{agent_class}`"
        pat_link = f"[Pattern Lib](docs/disclosed-reports/hunt-{agent_class}.md)" if os.path.exists(os.path.join(DISCLOSED_DIR, f"hunt-{agent_class}.md")) else "—"
        top_link = f"[TOP](docs/hackerone-reports/tops_by_bug_type/{top_name}.md)" if top_r else "—"
        csv_display = f"{csv_count}" if csv_count else "—"
        
        index_lines.append(f"| {class_name} | {hunt_link} | {pat_link} | {csv_display} | {top_link} |")
    
    index_lines.append("")
    index_lines.append(f"## Summary\n")
    index_lines.append(f"- **Total CSV reports:** {sum(len(v) for v in class_reports.values()):,}")
    index_lines.append(f"- **Vulnerability classes:** {len(class_reports)}")
    index_lines.append(f"- **TOP file entries:** {sum(len(v) for v in top_reports_map.values()):,}")
    index_lines.append(f"- **TOP files:** {len(top_reports_map)}")
    index_lines.append(f"- **Pattern libraries:** {len([f for f in os.listdir(DISCLOSED_DIR) if f.endswith('.md')])}")
    index_lines.append(f"- **Facebook writeups:** 269 entries")
    index_lines.append(f"")
    index_lines.append(f"## Sources\n")
    index_lines.append(f"- [HackerOne Disclosed Reports (data.csv)](docs/hackerone-reports/data.csv) — 14,683 structured entries")
    index_lines.append(f"- [HackerOne TOP Reports (by bug type)](docs/hackerone-reports/tops_by_bug_type/) — 28 files, 8,456 entries")
    index_lines.append(f"- [HackerOne TOP Reports (by program)](docs/hackerone-reports/tops_by_program/) — 52 files")
    index_lines.append(f"- [Facebook Writeups](docs/facebook-writeups/README.md) — 269 entries (2020-2026)")
    index_lines.append(f"- [Pattern Libraries](docs/disclosed-reports/) — 24 curated technique guides")
    
    index_path = os.path.join(OUTPUT_DIR, "INDEX.md")
    with open(index_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(index_lines))
    print(f"  Generated {index_path}")
    
    # Remove .git from cloned repos
    for repo in ['hackerone-reports', 'facebook-writeups']:
        git_dir = os.path.expanduser(f"~/dristi/docs/{repo}/.git")
        if os.path.exists(git_dir):
            import shutil
            shutil.rmtree(git_dir)
            print(f"  Removed .git from {repo}")

if __name__ == '__main__':
    main()
