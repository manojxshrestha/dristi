#!/usr/bin/env python3
"""Generate per-class disclosed report files in docs/hackerone-reports/ and docs/facebook-reports/."""

import csv
import os
import re
import sys
from collections import defaultdict, OrderedDict

SOURCE_DIR = os.path.expanduser("~/dristi/docs")
DATA_CSV = os.path.join(SOURCE_DIR, "hackerone-reports", "data.csv")
TOPS_DIR = os.path.join(SOURCE_DIR, "hackerone-reports", "tops_by_bug_type")
FB_README = os.path.join(SOURCE_DIR, "facebook-writeups", "README.md")
DOCS_DIR = os.path.expanduser("~/dristi/docs/reports")
H1_OUT = os.path.join(DOCS_DIR, "hackerone-reports")
FB_OUT = os.path.join(DOCS_DIR, "facebook-reports")

os.makedirs(H1_OUT, exist_ok=True)
os.makedirs(FB_OUT, exist_ok=True)

# Map TOP file names to class names (multiple TOPs can map to same class)
TOP_FILE_CLASS = OrderedDict([
    ("TOPXSS.md", "xss"),
    ("TOPSQLI.md", "sqli"),
    ("TOPSSRF.md", "ssrf"),
    ("TOPSSTI.md", "ssti"),
    ("TOPRCE.md", "rce"),
    ("TOPIDOR.md", "idor"),
    ("TOPCSRF.md", "csrf"),
    ("TOPXXE.md", "xxe"),
    ("TOPOPENREDIRECT.md", "open-redirect"),
    ("TOPUPLOAD.md", "file-upload"),
    ("TOPFILEREADING.md", "lfi"),
    ("TOPBUSINESSLOGIC.md", "business-logic"),
    ("TOPACCOUNTTAKEOVER.md", "ato"),
    ("TOPCLICKJACKING.md", "clickjacking"),
    ("TOPMFA.md", "mfa-bypass"),
    ("TOPOAUTH.md", "oauth"),
    ("TOPRACECONDITION.md", "race-condition"),
    ("TOPWEBCACHE.md", "cache-poison"),
    ("TOPREQUESTSMUGGLING.md", "http-smuggling"),
    ("TOPSUBDOMAINTAKEOVER.md", "subdomain"),
    ("TOPGRAPHQL.md", "graphql"),
    ("TOPAUTH.md", "auth-bypass"),
    ("TOPAUTHORIZATION.md", "auth-bypass"),
    ("TOPAPI.md", "api-misconfig"),
    ("TOPINFODISCLOSURE.md", "misc"),
    ("TOPDOS.md", "misc"),
    ("TOPMOBILE.md", "misc"),
    ("TOPOPENID.md", "oauth"),
])

TOP_PRETTY = {
    "xss": "Cross-Site Scripting (XSS)",
    "sqli": "SQL Injection",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "ssti": "Server-Side Template Injection (SSTI)",
    "rce": "Remote Code Execution (RCE)",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "csrf": "Cross-Site Request Forgery (CSRF)",
    "xxe": "XML External Entities (XXE)",
    "open-redirect": "Open Redirect",
    "file-upload": "File Upload Vulnerabilities",
    "lfi": "Local File Inclusion / Path Traversal",
    "business-logic": "Business Logic Errors",
    "ato": "Account Takeover (ATO)",
    "clickjacking": "Clickjacking / UI Redressing",
    "mfa-bypass": "MFA / 2FA Bypass",
    "oauth": "OAuth / OpenID Connect",
    "race-condition": "Race Conditions",
    "cache-poison": "Web Cache Poisoning",
    "http-smuggling": "HTTP Request Smuggling",
    "subdomain": "Subdomain Takeover",
    "graphql": "GraphQL API",
    "auth-bypass": "Authentication / Authorization Bypass",
    "api-misconfig": "API Misconfiguration",
    "misc": "Information Disclosure / Miscellaneous",
}

def format_bounty(bounty):
    if bounty >= 10000:
        s = f"${bounty/1000:.1f}K".replace('.0K', 'K')
        return s
    elif bounty > 0:
        if bounty == int(bounty):
            return f"${int(bounty):,}"
        return f"${bounty:,.2f}"
    return "—"

def parse_top_file(filepath):
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
                try:
                    bounty = float(bounty_str) if bounty_str.replace('.', '', 1).isdigit() else 0
                except:
                    bounty = 0
                report_id = link.split('/')[-1]
                reports.append({
                    'id': report_id,
                    'title': title,
                    'link': link,
                    'program': program,
                    'upvotes': upvotes,
                    'bounty': bounty,
                })
    return reports

def get_top_source_name(top_file):
    """Get the human-readable name of a TOP file."""
    return top_file.replace('.md', '')

def generate_hackerone_class_file(agent_class, all_reports, source_top_files):
    """Generate a single per-class report file combining multiple TOP file sources."""
    class_name = TOP_PRETTY.get(agent_class, agent_class.replace('-', ' ').title())
    filename = f"{agent_class}.md"
    filepath = os.path.join(H1_OUT, filename)
    
    # Sort by upvotes descending
    all_reports.sort(key=lambda x: x['upvotes'], reverse=True)
    
    lines = []
    lines.append(f"# Disclosed Reports — {class_name}\n")
    lines.append(f"Pattern library built from {len(all_reports)} public HackerOne bug bounty reports.\n")
    
    if len(source_top_files) > 1:
        src_str = ", ".join(source_top_files)
        lines.append(f"**Sources:** {src_str}\n")
    
    lines.append(f"---\n")
    
    for i, r in enumerate(all_reports, 1):
        bounty_str = format_bounty(r['bounty'])
        lines.append(f"\n## Report {r['id']}: {r['title']}\n")
        lines.append(f"**Program:** {r['program']}  \n")
        lines.append(f"**Link:** {r['link']}  \n")
        lines.append(f"**Upvotes:** {r['upvotes']:,} | **Bounty:** {bounty_str}  \n")
        lines.append(f"\n---\n")
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(''.join(lines))
    
    return len(all_reports)

def generate_hackerone_reports():
    """Generate all per-class report files, combining multiple TOP files per class."""
    print("=== Generating HackerOne report files ===")
    
    # Group TOP files by class
    class_to_files = defaultdict(list)
    for top_file, agent_class in TOP_FILE_CLASS.items():
        class_to_files[agent_class].append(top_file)
    
    total = 0
    for agent_class, top_files in sorted(class_to_files.items()):
        all_reports = []
        source_names = []
        seen_ids = set()
        
        for top_file in top_files:
            filepath = os.path.join(TOPS_DIR, top_file)
            if not os.path.exists(filepath):
                continue
            reports = parse_top_file(filepath)
            source_names.append(get_top_source_name(top_file))
            for r in reports:
                if r['id'] not in seen_ids:
                    seen_ids.add(r['id'])
                    all_reports.append(r)
        
        if all_reports:
            count = generate_hackerone_class_file(agent_class, all_reports, source_names)
            total += count
            src = ", ".join(source_names)
            print(f"  {agent_class}.md ({count} reports from {src})")
    
    # Generate master INDEX.md
    index_lines = []
    index_lines.append("# HackerOne Disclosed Reports — Index\n\n")
    index_lines.append("Per-class disclosed report files for agent reference during hunts.\n\n")
    index_lines.append("| Class | File | Reports | Source |\n")
    index_lines.append("|-------|------|---------|--------|\n")
    
    for agent_class in sorted(class_to_files.keys()):
        fp = os.path.join(H1_OUT, f"{agent_class}.md")
        if not os.path.exists(fp):
            continue
        class_name = TOP_PRETTY.get(agent_class, agent_class.replace('-', ' ').title())
        top_files = class_to_files[agent_class]
        src = ", ".join(get_top_source_name(f) for f in top_files)
        with open(fp, 'r') as f:
            content = f.read()
        report_count = content.count("## Report ")
        index_lines.append(f"| {class_name} | [{agent_class}.md]({agent_class}.md) | {report_count} | {src} |\n")
    
    with open(os.path.join(H1_OUT, "INDEX.md"), 'w', encoding='utf-8') as f:
        f.writelines(index_lines)
    print(f"  INDEX.md generated")
    
    print(f"  Total: {total} reports across {len(class_to_files)} classes\n")
    return total, class_to_files

def generate_facebook_reports():
    """Generate facebook writeups report file."""
    print("=== Generating Facebook writeups report ===")
    
    outpath = os.path.join(FB_OUT, "facebook-writeups.md")
    
    if not os.path.exists(FB_README):
        print(f"  WARNING: {FB_README} not found")
        return 0
    
    with open(FB_README, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Extract writeup entries - match lines starting with - **[something]
    raw_lines = []
    for line in content.split('\n'):
        stripped = line.strip()
        if stripped.startswith('- **[') and '](' in stripped:
            raw_lines.append(stripped)
    
    # Parse entries
    writeups = []
    for line in raw_lines:
        try:
            # Pattern: - **[<date> - $<bounty>]** [<title>](<url>) by [<author>](<author_url>)
            m = re.match(r'-\s+\*\*\[(.+?)\]\*\*\s+\[(.+?)\]\((.+?)\)\s+by\s+\[(.+?)\]\((.+?)\)', line)
            if m:
                date_bounty = m.group(1).strip()
                title = m.group(2).strip()
                url = m.group(3).strip()
                author = m.group(4).strip()
                author_url = m.group(5).strip()
                
                # Parse bounty from date_bounty
                bounty_match = re.search(r'\$([0-9,]+|\?\?\?)', date_bounty)
                bounty = f"${bounty_match.group(1)}" if bounty_match else '$???'
                
                # Parse date
                date = date_bounty
                bounty_part = re.search(r'\s*-\s*\$[0-9,?]+\s*', date_bounty)
                if bounty_part:
                    date = date_bounty[:bounty_part.start()].strip()
                
                writeups.append({
                    'date': date,
                    'title': title,
                    'url': url,
                    'author': author,
                    'author_url': author_url,
                    'bounty': bounty,
                })
            else:
                # Try alternative: - **[<date> - $<bounty>]** [TITLE](URL)
                m2 = re.match(r'-\s+\*\*\[(.+?)\s*-\s*\$?(.+?)\]\*\*\s+\[(.+?)\]\((.+?)\)(?:\s+by\s+\[(.+?)\]\((.+?)\))?', line)
                if m2:
                    date = m2.group(1).strip()
                    bounty_str = m2.group(2).strip()
                    title = m2.group(3).strip()
                    url = m2.group(4).strip()
                    author = m2.group(5).strip() if m2.group(5) else 'Unknown'
                    author_url = m2.group(6).strip() if m2.group(6) else ''
                    bounty = f"${bounty_str}" if bounty_str != '?' else '$???'
                    writeups.append({
                        'date': date,
                        'title': title,
                        'url': url,
                        'author': author,
                        'author_url': author_url,
                        'bounty': bounty,
                    })
        except Exception as e:
            continue
    
    wc = len(writeups)
    with open(outpath, 'w', encoding='utf-8') as f:
        f.write(f"# Disclosed Reports — Facebook / Meta Bug Bounty\n\n")
        f.write(f"Pattern library built from {wc} public Facebook/Meta/Instagram/WhatsApp bug bounty writeups.\n\n")
        f.write(f"**Source:** `~/dristi/docs/facebook-writeups/README.md`\n\n")
        f.write(f"---\n")
        
        for i, w in enumerate(writeups, 1):
            f.write(f"\n## Report {i}: {w['title']}\n")
            f.write(f"**Date:** {w['date']}  \n")
            f.write(f"**Bounty:** {w['bounty']}  \n")
            f.write(f"**Link:** {w['url']}  \n")
            f.write(f"**Author:** [{w['author']}]({w['author_url']})  \n" if w['author_url'] else f"**Author:** {w['author']}  \n")
            f.write(f"\n---\n")
    
    print(f"  Generated facebook-writeups.md ({wc} writeups)\n")
    return wc

if __name__ == '__main__':
    h1_total, classes = generate_hackerone_reports()
    fb_total = generate_facebook_reports()
    
    print(f"=== DONE ===")
    print(f"  docs/hackerone-reports/: {h1_total} reports across {len(classes)} classes")
    print(f"  docs/facebook-reports/: {fb_total} writeups")
    print(f"  Total: {h1_total + fb_total} entries")
